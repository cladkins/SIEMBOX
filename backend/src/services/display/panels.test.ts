/**
 * The Big Display's pure folds (services/display/panels.ts): zero-filled
 * buckets, severity order, the ingest state's thresholds with and without the
 * rollup, the silent / quiet / active / unknown rule (including the bursty
 * source and the counter's overflow row), the UDP drop window, and what each
 * privacy level leaves out.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  classifySource,
  createDropTracker,
  foldIngest,
  foldOpenAlerts,
  foldPulse,
  foldRecentAlerts,
  foldShippers,
  foldSources,
  foldThreatMap,
  foldTopRules,
  foldTopSources,
  foldVulnerabilities,
  ingestState,
  severitiesFrom,
  type IngestRaw,
  type SourceRaw,
} from './panels';

const MIN = 60_000;
// A fixed "now", 20 s into a minute.
const AT = Date.UTC(2026, 9, 16, 12, 0, 20);
const NOW_MINUTE = Math.floor(AT / MIN);
const minuteIso = (minutesAgo: number) => new Date((NOW_MINUTE - minutesAgo) * MIN).toISOString();

test('open alerts: every severity present, unknown severities ignored, total summed', () => {
  const data = foldOpenAlerts([
    { severity: 'high', open: 3, untouched: 1, oldest_at: new Date(AT - 3600_000) },
    { severity: 'critical', open: '2', untouched: '2', oldest_at: new Date(AT - 60_000) },
    { severity: 'info', open: 9, untouched: 9, oldest_at: null },
  ]);
  assert.deepEqual(Object.keys(data.by_severity), ['critical', 'high', 'medium', 'low'], 'severity order');
  assert.equal(data.total, 5);
  assert.deepEqual(data.by_severity.critical, { open: 2, untouched: 2, oldest_at: new Date(AT - 60_000).toISOString() });
  assert.deepEqual(data.by_severity.low, { open: 0, untouched: 0, oldest_at: null });
});

test('alert pulse: always 24 hourly buckets, oldest first, padded at the front', () => {
  const data = foldPulse([{ total: 4, critical: 1 }, { total: 2, critical: 0 }], { total_24h: 6, prev_24h: 3, last_hour: 2, critical: 1, high: 5 });
  assert.equal(data.hourly.length, 24);
  assert.deepEqual(data.hourly.slice(-2), [{ total: 4, critical: 1 }, { total: 2, critical: 0 }]);
  assert.deepEqual(data.hourly[0], { total: 0, critical: 0 });
  assert.deepEqual(data.by_severity_24h, { critical: 1, high: 5, medium: 0, low: 0 });
  assert.equal(foldPulse([], undefined).total_24h, 0, 'no totals row');
});

test('recent alerts: rule names in operations, category labels only in public, 6 shown and the 7th sets more', () => {
  assert.deepEqual(severitiesFrom('high'), ['critical', 'high']);
  assert.deepEqual(severitiesFrom('medium'), ['critical', 'high', 'medium']);
  const rows = [
    { severity: 'critical', status: 'new', created_at: new Date(AT), source: null, rule_name: 'SSH brute force' },
    { severity: 'high', status: 'investigating', created_at: new Date(AT - 1000), source: 'leaked-creds', rule_name: null },
    { severity: 'high', status: 'new', created_at: new Date(AT - 2000), source: null, rule_name: null },
    { severity: 'high', status: 'new', created_at: new Date(AT - 3000), source: 'siembox-auth', rule_name: null },
    { severity: 'high', status: 'new', created_at: new Date(AT - 4000), source: 'domain-monitor', rule_name: null },
    { severity: 'high', status: 'new', created_at: new Date(AT - 5000), source: 'edr', rule_name: null },
    { severity: 'high', status: 'new', created_at: new Date(AT - 6000), source: 'something-new', rule_name: null },
  ];
  const ops = foldRecentAlerts(rows, 'high', 'operations');
  assert.equal(ops.more, true);
  assert.deepEqual(
    ops.items.map((i) => [i.category, i.label]),
    [
      ['rule', 'SSH brute force'],
      ['leaked_credentials', 'Leaked credentials'],
      ['rule', 'Detection rule'],
      ['sign_in', 'Sign-in protection'],
      ['domain_monitoring', 'Domain monitoring'],
      ['endpoint', 'Endpoint detection'],
    ]
  );
  const pub = foldRecentAlerts(rows, 'high', 'public');
  assert.equal(pub.items[0].label, 'Detection rule');
  const email = foldRecentAlerts([{ ...rows[0], rule_name: 'Notify ops@example.com' }], 'high', 'operations');
  assert.equal(email.items[0].label, 'Detection rule', 'a name holding an email address is not shown');
  assert.equal(foldRecentAlerts([rows[0]], 'critical', 'operations').more, false);
});

test('top rules: worst severity by rank; public mode merges rules under one label', () => {
  const rows = [
    { rule_id: 1, rule_name: 'A', source: null, n: 5, worst: 2 },
    { rule_id: 2, rule_name: 'B', source: null, n: 4, worst: 4 },
    { rule_id: null, rule_name: null, source: 'edr', n: 3, worst: 3 },
  ];
  const ops = foldTopRules(rows, 12, 24, 'operations');
  assert.deepEqual(ops.items.map((i) => [i.label, i.worst_severity, i.count]), [['A', 'medium', 5], ['B', 'critical', 4], ['Endpoint detection', 'high', 3]]);
  const pub = foldTopRules(rows, 12, 1, 'public');
  assert.deepEqual(pub.items.map((i) => [i.label, i.worst_severity, i.count]), [['Detection rule', 'critical', 9], ['Endpoint detection', 'high', 3]]);
  assert.equal(pub.window_hours, 1);
});

test('ingest state: idle, stalled, slow (only with a baseline of 20/min and under 25 %), flowing', () => {
  const base = { at: AT, stallMinutes: 15, rate15: null, baseline: null };
  assert.equal(ingestState({ ...base, lastLogAt: null }), 'idle');
  assert.equal(ingestState({ ...base, lastLogAt: AT - 25 * 3600_000 }), 'idle');
  assert.equal(ingestState({ ...base, lastLogAt: AT - 15 * MIN }), 'stalled');
  assert.equal(ingestState({ ...base, lastLogAt: AT - 14 * MIN }), 'flowing');
  assert.equal(ingestState({ ...base, lastLogAt: AT, rate15: 4, baseline: 20 }), 'slow');
  assert.equal(ingestState({ ...base, lastLogAt: AT, rate15: 5, baseline: 20 }), 'flowing', '25 % is not below 25 %');
  assert.equal(ingestState({ ...base, lastLogAt: AT, rate15: 0, baseline: 19 }), 'flowing', 'a baseline under 20 never reads slow');
  assert.equal(ingestState({ ...base, lastLogAt: AT, rate15: 0, baseline: null }), 'flowing', 'without the rollup');
});

function ingestRaw(overrides: Partial<IngestRaw> = {}): IngestRaw {
  return {
    lastLogAt: new Date(AT - 5000).toISOString(),
    rollupSince: null,
    minutes: [],
    rawLastMinute: 42,
    hourly: [{ total: 100, unparsed: 25 }],
    stallMinutes: 15,
    udpDropped15m: null,
    ...overrides,
  };
}

test('ingest without the rollup: the raw_logs minute count, no per-minute bars, no slow state', () => {
  const data = foldIngest(ingestRaw(), AT);
  assert.equal(data.per_minute, null);
  assert.equal(data.logs_last_minute, 42);
  assert.equal(data.rate_15m_per_minute, null);
  assert.equal(data.baseline_per_minute, null);
  assert.equal(data.state, 'flowing');
  assert.equal(data.hourly.length, 24, 'hourly padded to 24');
  assert.equal(data.parsed_pct_24h, 75);
  // A rollup only a minute old still counts as "without".
  assert.equal(foldIngest(ingestRaw({ rollupSince: minuteIso(1) }), AT).per_minute, null);
});

test('ingest with the rollup: 60 zero-filled minutes ending with the current one, the 15-minute rate and the 24 h median', () => {
  // 3 hours of 100/min, except the last 15 complete minutes at 10/min; nothing yet this minute.
  const minutes: Array<[string, number]> = [];
  for (let ago = 180; ago >= 1; ago--) if (ago !== 30) minutes.push([minuteIso(ago), ago <= 15 ? 10 : 100]);
  const data = foldIngest(ingestRaw({ rollupSince: minuteIso(180), minutes }), AT);
  assert.equal(data.per_minute!.length, 60);
  assert.equal(data.per_minute![59], 0, 'the current, partial minute');
  assert.equal(data.per_minute![58], 10, 'the last complete minute');
  assert.equal(data.per_minute![29], 0, 'a minute with no row is zero');
  assert.equal(data.logs_last_minute, 10);
  assert.equal(data.rate_15m_per_minute, 10);
  assert.equal(data.baseline_per_minute, 100);
  assert.equal(data.state, 'slow');
  assert.equal(data.rollup_since, minuteIso(180));
  // Under an hour of rollup: no baseline, so never slow.
  const young = foldIngest(ingestRaw({ rollupSince: minuteIso(30), minutes: minutes.filter(([m]) => m >= minuteIso(30)) }), AT);
  assert.equal(young.baseline_per_minute, null);
  assert.equal(young.state, 'flowing');
  assert.equal(foldIngest(ingestRaw({ hourly: [] }), AT).parsed_pct_24h, null, 'no logs parsed: no percentage');
});

test('UDP drops: the counter now minus the oldest sample within 15 minutes; null without a syslog server', () => {
  let dropped = 0;
  let running = true;
  const tracker = createDropTracker(() => (running ? { dropped } : null));
  assert.equal(tracker.dropped15m(AT), 0);
  dropped = 5;
  assert.equal(tracker.dropped15m(AT + MIN), 5);
  dropped = 9;
  assert.equal(tracker.dropped15m(AT + 10 * MIN), 9);
  assert.equal(tracker.dropped15m(AT + 17 * MIN), 4, 'counted from the newest sample at least 15 minutes old');
  dropped = 2;
  assert.equal(tracker.dropped15m(AT + 18 * MIN), 0, 'a restarted server counts from 0 again');
  running = false;
  assert.equal(tracker.dropped15m(AT + 19 * MIN), null);
});

const steady = { lastEstablished: null, activeMinutes: 1440, logs24h: 1440 * 5 };
const ctx = { at: AT, silentAfter: 15, observedMinutes: 1440, overflowMinutes: [] as number[] };

test('sources: active within the threshold, silent after it, quiet when low-volume or bursty', () => {
  assert.equal(classifySource({ ...steady, lastMinute: minuteIso(1) }, ctx).state, 'active');
  assert.equal(classifySource({ ...steady, lastMinute: minuteIso(15) }, ctx).state, 'active', '14 full minutes without logs');
  const silent = classifySource({ ...steady, lastMinute: minuteIso(16) }, ctx);
  assert.deepEqual(silent, { state: 'silent', silentMinutes: 15 });
  // An hourly NAS: under a log a minute on average.
  assert.equal(classifySource({ lastMinute: minuteIso(40), lastEstablished: null, activeMinutes: 24, logs24h: 500 }, ctx).state, 'quiet');
  // The bursty exemption: plenty of logs, but in a few big batches.
  assert.equal(classifySource({ lastMinute: minuteIso(40), lastEstablished: null, activeMinutes: 48, logs24h: 50_000 }, ctx).state, 'quiet');
  assert.equal(classifySource({ lastMinute: minuteIso(40), lastEstablished: null, activeMinutes: 720, logs24h: 50_000 }, ctx).state, 'silent', 'half the minutes is steady');
  // Under an hour of rollup nothing is called silent yet.
  assert.equal(classifySource({ ...steady, lastMinute: minuteIso(20) }, { ...ctx, observedMinutes: 59 }).state, 'quiet');
  // Within a partial window the thresholds scale: 120 minutes observed, logging in 100 of them.
  assert.equal(classifySource({ lastMinute: minuteIso(20), lastEstablished: null, activeMinutes: 100, logs24h: 200 }, { ...ctx, observedMinutes: 120 }).state, 'silent');
});

test("sources: overflow after a source's last row makes it unknown, unless it was still an established source", () => {
  const source = { ...steady, lastMinute: minuteIso(30) };
  const overflowAgo = (ago: number) => [NOW_MINUTE - ago];
  assert.equal(classifySource(source, { ...ctx, overflowMinutes: overflowAgo(40) }).state, 'silent', 'overflow before its last row');
  assert.equal(classifySource(source, { ...ctx, overflowMinutes: overflowAgo(10) }).state, 'unknown', 'it could have logged into overflow');
  // Established at its last row: it keeps its own row for 60 minutes, so its absence is real.
  const established = { ...source, lastEstablished: minuteIso(30) };
  assert.equal(classifySource(established, { ...ctx, overflowMinutes: overflowAgo(10) }).state, 'silent');
  // ...but not past those 60 minutes.
  const longGone = { ...steady, lastMinute: minuteIso(90), lastEstablished: minuteIso(90) };
  assert.equal(classifySource(longGone, { ...ctx, silentAfter: 60, overflowMinutes: overflowAgo(20) }).state, 'unknown');
  assert.equal(classifySource(longGone, { ...ctx, silentAfter: 60, overflowMinutes: overflowAgo(85) }).state, 'silent');
});

function source(overrides: Partial<SourceRaw>): SourceRaw {
  return { kind: 'direct', key: '192.0.2.1', lastMinute: minuteIso(1), lastEstablished: minuteIso(1), activeMinutes: 1440, logs15m: 150, logs24h: 14_400, label: '192.0.2.1', ghost: false, ...overrides };
}

test('sources panel: silent first, then unknown, then the busiest; counts; ghosts; collecting; public mode lists nothing', () => {
  const raw = {
    rollupSince: minuteIso(2000),
    overflowMinutes: [minuteIso(5)],
    sources: [
      source({ key: 'a', label: 'fw-1', logs15m: 30 }),
      source({ key: 'b', label: 'fw-2', logs15m: 300 }),
      source({ key: 'c', label: 'nas', lastMinute: minuteIso(50), activeMinutes: 20, logs24h: 300 }),
      source({ kind: 'shipper', key: 'deadbeef', label: null, ghost: true, lastMinute: minuteIso(40), lastEstablished: null }),
      source({ kind: 'shipper', key: 'cafebabe', label: 'web shipper', lastMinute: minuteIso(30), lastEstablished: minuteIso(30) }),
    ],
  };
  const data = foldSources(raw, 15, 'operations', AT);
  assert.deepEqual(
    { active: data.active, silent: data.silent, quiet: data.quiet, unknown: data.unknown, ghosts: data.unknown_shippers, since: data.since, more: data.more_active },
    { active: 2, silent: 1, quiet: 1, unknown: 1, ghosts: 1, since: null, more: 0 }
  );
  assert.deepEqual(data.rows.map((r) => [r.label, r.state, r.silent_minutes]), [
    ['web shipper', 'silent', 29],
    [null, 'unknown', 39],
    ['fw-2', 'active', null],
    ['fw-1', 'active', null],
  ]);
  assert.equal(data.rows[2].logs_per_minute, 20);
  const pub = foldSources(raw, 15, 'public', AT);
  assert.deepEqual(pub.rows, []);
  assert.equal(pub.silent, 1);
  const young = foldSources({ ...raw, rollupSince: minuteIso(600) }, 15, 'operations', AT);
  assert.equal(young.since, minuteIso(600), 'collecting since');
  const many = foldSources({ ...raw, sources: Array.from({ length: 12 }, (_, i) => source({ key: `k${i}`, logs15m: i })) }, 15, 'operations', AT);
  assert.equal(many.rows.length, 8);
  assert.equal(many.more_active, 4);
});

test('shippers: statuses as the Shippers page works them out; offline names longest first, none in public', () => {
  const rows = [
    { id: 1, name: 'web', status: 'online', last_seen: new Date(AT - 30_000) },
    { id: 2, name: 'db', status: 'online', last_seen: new Date(AT - 10 * MIN) },
    { id: 3, name: 'old', status: 'online', last_seen: new Date(AT - 60 * MIN) },
    { id: 4, name: 'new', status: 'pending', last_seen: null },
    { id: 5, name: 'bad', status: 'error', last_seen: new Date(AT - 30_000) },
    { id: 6, name: '\u0007', status: 'online', last_seen: new Date(AT - 9 * MIN) },
  ];
  const data = foldShippers(rows, 2, 'operations', AT);
  assert.deepEqual({ ...data, offline_list: undefined }, { total: 6, online: 1, offline: 3, pending: 1, error: 1, unknown_shippers_24h: 2, offline_list: undefined });
  assert.deepEqual(data.offline_list.map((s) => s.name), ['old', 'db', 'Shipper 6']);
  assert.deepEqual(foldShippers(rows, null, 'public', AT).offline_list, []);
});

test('threat map and top sources: valid codes and addresses only; no addresses in public', () => {
  const map = foldThreatMap([{ code: 'DE', n: 5 }, { code: 'xx', n: 3 }, { code: 'US', n: 2 }], 20, 7);
  assert.deepEqual(map, { window_days: 7, located: 7, total_in_window: 20, countries: [{ code: 'DE', count: 5 }, { code: 'US', count: 2 }] });
  const rows = [
    { ip: 'not-an-ip', cc: 'DE', n: 9, worst: 4, last_at: new Date(AT) },
    { ip: '203.0.113.9', cc: 'Germany', n: 5, worst: 3, last_at: new Date(AT) },
    { ip: '2001:db8::1', cc: 'FR', n: 2, worst: 1, last_at: new Date(AT) },
  ];
  const ops = foldTopSources(rows, 'operations');
  assert.deepEqual(ops.items.map((i) => [i.ip, i.country_code, i.worst_severity]), [['203.0.113.9', null, 'high'], ['2001:db8::1', 'FR', 'low']]);
  assert.deepEqual(foldTopSources(rows, 'public').items, []);
});

test('vulnerabilities: scanned once a scan ran or a finding exists', () => {
  assert.equal(foldVulnerabilities({ total: 0 }, false).scanned, false);
  assert.equal(foldVulnerabilities({ total: 0 }, true).scanned, true);
  assert.deepEqual(foldVulnerabilities({ total: 3, critical: 1, high: 2, affected_assets: 1 }, false), {
    scanned: true,
    open_by_severity: { critical: 1, high: 2, medium: 0, low: 0 },
    affected_assets: 1,
  });
});
