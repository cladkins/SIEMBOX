/**
 * Pure parts of endpoint performance: sample validation, the threshold
 * breach / recovery rules, and the policy's performance settings.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  cleanSample,
  cleanSnapshot,
  cleanTimestamp,
  diskPct,
  hourOf,
  isBreach,
  isRecovered,
  parseRange,
  recoveryLevel,
  seriesFrom,
  type SeriesPoint,
} from './edrPerformance';
import { BUILTIN_DEFAULT_PERFORMANCE, agentPerformanceConfig, normalizePerformance, storedPerformance } from './perfConfig';

const NOW = new Date('2026-10-27T12:00:30Z');

function sample(over: Record<string, unknown> = {}) {
  return {
    ts: '2026-10-27T12:00:00Z',
    cpu_pct: 12.345,
    cpu_count: 4,
    mem_total: 8e9,
    mem_used: 2e9,
    swap_total: 1e9,
    swap_used: 0,
    load1: 0.5,
    load5: 0.4,
    load15: 0.3,
    uptime_seconds: 3600,
    disks: [{ mount: '/', fs: 'ext4', total: 100, used: 45, free: 50 }],
    net: [{ iface: 'eth0', rx_bps: 1000, tx_bps: 200 }],
    ...over,
  };
}

test('cleanSample keeps a valid sample, computes the df-style disk share, rounds', () => {
  const s = cleanSample(sample(), NOW)!;
  assert.equal(s.ts, '2026-10-27T12:00:00.000Z');
  assert.equal(s.cpu_pct, 12.35);
  assert.deepEqual(s.disks, [{ mount: '/', fs: 'ext4', total: 100, used: 45, free: 50, pct: 47.4 }]);
  assert.deepEqual(s.net, [{ iface: 'eth0', rx: 1000, tx: 200 }]);
  assert.equal(diskPct(0, 0), 0);
});

test('cleanSample refuses what it cannot store and bounds the rest', () => {
  assert.equal(cleanSample(null, NOW), null);
  assert.equal(cleanSample(sample({ mem_total: 0 }), NOW), null, 'no memory total');
  assert.equal(cleanSample(sample({ ts: 'yesterday' }), NOW), null, 'bad time');
  assert.equal(cleanSample(sample({ ts: '2026-10-27T12:10:00Z' }), NOW), null, '10 minutes in the future');
  assert.equal(cleanSample(sample({ ts: '2026-10-19T12:00:00Z' }), NOW), null, 'older than raw retention');
  assert.ok(cleanTimestamp('2026-10-27T12:04:00Z', NOW), 'small clock skew is fine');

  const s = cleanSample(
    sample({
      cpu_pct: 250,
      mem_used: 9e9, // more than the total
      load1: -1,
      load5: 'x',
      disks: [
        ...Array.from({ length: 50 }, (_, i) => ({ mount: `/m${i}`, total: 10, used: 1, free: 9 })),
        { mount: '/', total: 10, used: 1, free: 9 },
      ],
      net: [{ iface: 'eth0', rx_bps: -5, tx_bps: Infinity }, { iface: 'eth0', rx_bps: 1, tx_bps: 1 }, { iface: '' }],
    }),
    NOW
  )!;
  assert.equal(s.cpu_pct, 100);
  assert.equal(s.mem_used, 8e9);
  assert.equal(s.load1, null);
  assert.equal(s.load5, null);
  assert.equal(s.disks.length, 32);
  assert.deepEqual(s.net, [{ iface: 'eth0', rx: 0, tx: 0 }], 'one entry per interface, bad numbers zeroed');
  const ctl = cleanSample(sample({ disks: [{ mount: '/a\u0000b\nc', total: 1, used: 0, free: 1 }] }), NOW)!;
  assert.equal(ctl.disks[0].mount, '/abc');
});

test('cleanSnapshot keeps named processes only, at most 25 per list', () => {
  const snap = cleanSnapshot(
    {
      ts: '2026-10-27T12:00:00Z',
      by_cpu: [{ pid: 1, name: 'init', cpu_pct: 1, mem_rss: 10, mem_pct: 0.1 }, { pid: 2 }, ...Array.from({ length: 40 }, (_, i) => ({ pid: i + 10, name: 'p' }))],
      by_mem: [],
    },
    NOW
  )!;
  assert.equal(snap.by_cpu.length, 24); // 25 kept, the nameless one dropped
  assert.equal(snap.by_cpu[0].user, null);
  assert.equal(cleanSnapshot({ ts: '2026-10-27T12:00:00Z', by_cpu: [], by_mem: [] }, NOW), null);
});

test('hourOf truncates to the UTC hour', () => {
  assert.equal(hourOf('2026-10-27T12:59:59.000Z'), '2026-10-27T12:00:00.000Z');
});

const minutes = (values: number[], start = Date.parse('2026-10-27T12:00:00Z')): SeriesPoint[] =>
  // newest first, one a minute
  values.map((v, i) => ({ t: start - i * 60_000, v }));

test('isBreach: newest value for 0/1-minute thresholds; sustained ones need the whole span covered', () => {
  assert.equal(isBreach(minutes([91]), { percent: 90, minutes: 0 }), true);
  assert.equal(isBreach(minutes([90]), { percent: 90, minutes: 0 }), false, 'above, not at');
  assert.equal(isBreach([], { percent: 90, minutes: 0 }), false);

  const ten = { percent: 95, minutes: 10 };
  assert.equal(isBreach(minutes(Array(10).fill(99)), ten), true);
  assert.equal(isBreach(minutes([...Array(9).fill(99), 50]), ten), false, 'one dip in the window');
  assert.equal(isBreach(minutes(Array(3).fill(99)), ten), false, 'only three minutes of data');
  // 8 of 10 samples (two missed minutes) spanning the window still count.
  const gappy = minutes(Array(10).fill(99)).filter((_, i) => i !== 3 && i !== 6);
  assert.equal(isBreach(gappy, ten), true);
  // Older values beyond the window don't matter.
  assert.equal(isBreach(minutes([...Array(10).fill(99), 10, 10]), ten), true);
});

test('isRecovered: below the threshold less the margin for up to 5 minutes', () => {
  assert.equal(recoveryLevel(90), 87);
  assert.equal(recoveryLevel(4), 3);
  const disk = { percent: 90, minutes: 0 };
  assert.equal(isRecovered(minutes([88]), disk), false, 'inside the margin');
  assert.equal(isRecovered(minutes([86.9]), disk), true);
  const cpu = { percent: 95, minutes: 10 };
  assert.equal(isRecovered(minutes([10, 10, 10, 10]), cpu), true, 'the data there is, within 5 minutes');
  assert.equal(isRecovered(minutes([10, 10, 10, 10, 99]), cpu), false, 'a high value within 5 minutes');
  assert.equal(isRecovered(minutes([10, 10, 10, 10, 10, 99]), cpu), true, 'the 6th minute is outside');
});

test('seriesFrom: cpu, memory and each disk mount', () => {
  const s = seriesFrom([
    { ts: new Date('2026-10-27T12:01:00Z'), cpu_pct: 5, mem_used: '50', mem_total: '100', disks: [{ mount: '/', pct: 91 } as never] },
    { ts: new Date('2026-10-27T12:00:00Z'), cpu_pct: 6, mem_used: 25, mem_total: 100, disks: [] },
  ]);
  assert.deepEqual(s.get('memory\u0000')!.map((p) => p.v), [50, 25]);
  assert.deepEqual(s.get('disk\u0000/')!.map((p) => p.v), [91]);
  assert.equal(s.get('cpu\u0000')!.length, 2);
});

test('parseRange', () => {
  assert.equal(parseRange(undefined), '24h');
  assert.equal(parseRange('7d'), '7d');
  assert.throws(() => parseRange('2y'), /range must be one of/);
  assert.throws(() => parseRange(['1h']), /range must be one of/);
});

test('performance settings: validation, stored fallback, agent config', () => {
  const ok = normalizePerformance(BUILTIN_DEFAULT_PERFORMANCE);
  assert.deepEqual(ok, BUILTIN_DEFAULT_PERFORMANCE);
  const bad = (patch: unknown, re: RegExp) => assert.throws(() => normalizePerformance(patch), re);
  bad(null, /must be an object/);
  bad({ ...BUILTIN_DEFAULT_PERFORMANCE, metrics: 'yes' }, /metrics must be a boolean/);
  bad({ ...BUILTIN_DEFAULT_PERFORMANCE, thresholds: { ...BUILTIN_DEFAULT_PERFORMANCE.thresholds, swap: {} } }, /unknown metric/);
  bad({ ...BUILTIN_DEFAULT_PERFORMANCE, thresholds: { cpu: BUILTIN_DEFAULT_PERFORMANCE.thresholds.cpu } }, /memory is required/);
  const th = (t: Record<string, unknown>) => ({
    ...BUILTIN_DEFAULT_PERFORMANCE,
    thresholds: { ...BUILTIN_DEFAULT_PERFORMANCE.thresholds, disk: { ...BUILTIN_DEFAULT_PERFORMANCE.thresholds.disk, ...t } },
  });
  bad(th({ percent: 100 }), /percent must be a number from 1 to 99.9/);
  bad(th({ percent: 0 }), /percent/);
  bad(th({ minutes: 1.5 }), /minutes must be an integer from 0 to 240/);
  bad(th({ minutes: 241 }), /minutes/);
  bad(th({ severity: 'info' }), /severity must be one of/);
  assert.equal(normalizePerformance(th({ percent: 85.55 })).thresholds.disk.percent, 85.6);

  assert.deepEqual(storedPerformance(null), BUILTIN_DEFAULT_PERFORMANCE);
  assert.deepEqual(storedPerformance({ metrics: 1 }), BUILTIN_DEFAULT_PERFORMANCE);

  const off = agentPerformanceConfig({ ...BUILTIN_DEFAULT_PERFORMANCE, metrics: false });
  assert.equal(off.enabled, false);
  assert.equal(off.processes, false, 'no processes without metrics');
  assert.deepEqual(agentPerformanceConfig(BUILTIN_DEFAULT_PERFORMANCE), {
    enabled: true,
    processes: true,
    sample_interval_seconds: 60,
    send_interval_seconds: 60,
    process_interval_seconds: 300,
    top_processes: 10,
  });
});
