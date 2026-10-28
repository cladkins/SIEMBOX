import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  defaultPerformance,
  describePerformance,
  describeThreshold,
  formatBytes,
  formatPct,
  formatRate,
  formatUptime,
  hasLoad,
  isFresh,
  levelOf,
  performanceForm,
  performanceProblem,
  supportsPerfMetrics,
  swapPct,
  tickStep,
  toXY,
  type PerfPoint,
} from './endpointPerformance.ts';

describe('endpointPerformance', () => {
  it('formats bytes, rates, percentages and uptime', () => {
    assert.equal(formatBytes(512), '512 B');
    assert.equal(formatBytes(1536), '1.5 KB');
    assert.equal(formatBytes(8 * 1024 ** 3), '8.0 GB');
    assert.equal(formatBytes(null), '—');
    assert.equal(formatRate(125_000), '1.0 Mbit/s');
    assert.equal(formatRate(10), '80 bit/s');
    assert.equal(formatRate(undefined), '—');
    assert.equal(formatPct(41.26, 1), '41.3%');
    assert.equal(formatPct(null), '—');
    assert.equal(formatUptime(90_061), '1d 1h');
    assert.equal(formatUptime(3_660), '1h 1m');
    assert.equal(formatUptime(59), '0m');
    assert.equal(formatUptime(-1), '—');
  });

  it('levels: crit at the threshold, warn within 15 points', () => {
    assert.equal(levelOf(91, 90), 'crit');
    assert.equal(levelOf(80, 90), 'warn');
    assert.equal(levelOf(74, 90), 'ok');
    assert.equal(levelOf(76), 'warn', 'default threshold 90');
    assert.equal(levelOf(null), 'ok');
  });

  it('freshness and capability', () => {
    const now = Date.parse('2026-10-27T12:00:00Z');
    assert.equal(isFresh('2026-10-27T11:58:30Z', now), true);
    assert.equal(isFresh('2026-10-27T11:50:00Z', now), false);
    assert.equal(isFresh(null, now), false);
    assert.equal(supportsPerfMetrics({ capabilities: ['adhoc_scans', 'perf_metrics'] }), true);
    assert.equal(supportsPerfMetrics({ capabilities: null }), false);
    assert.equal(supportsPerfMetrics(null), false);
  });

  it('policy settings: form, validation, descriptions', () => {
    const f = performanceForm(undefined);
    assert.deepEqual(f, defaultPerformance());
    f.thresholds.cpu.percent = 0;
    assert.match(performanceProblem(f)!, /CPU: the threshold/);
    f.thresholds.cpu.enabled = false;
    assert.equal(performanceProblem(f), null, 'a disabled threshold is not checked');
    f.thresholds.disk.minutes = 1.5;
    assert.match(performanceProblem(f)!, /Disk: "for"/);

    // The form is a copy: editing it leaves the policy row alone.
    const row = defaultPerformance();
    const edit = performanceForm(row);
    edit.thresholds.disk.percent = 80;
    assert.equal(row.thresholds.disk.percent, 90);

    assert.equal(describeThreshold(defaultPerformance().thresholds.cpu), '> 95% for 10 min (medium)');
    assert.equal(describeThreshold(defaultPerformance().thresholds.disk), '> 90% (high)');
    assert.equal(describeThreshold({ ...defaultPerformance().thresholds.disk, enabled: false }), 'off');
    assert.equal(describePerformance(defaultPerformance()), 'on, processes; alerts: cpu, memory, disk');
    assert.equal(describePerformance({ ...defaultPerformance(), metrics: false }), 'off');
  });

  it('chart points: gaps break the line, swap share, load presence', () => {
    const pts = [
      { t: '2026-10-27T12:00:00Z', v: 1 },
      { t: '2026-10-27T12:01:00Z', v: 2 },
      { t: '2026-10-27T12:10:00Z', v: 3 }, // the agent was off for 9 minutes
    ];
    const xy = toXY(pts, (p) => p.v, 60);
    assert.deepEqual(
      xy.map((p) => p.y),
      [1, 2, null, 3]
    );
    assert.equal(xy[2].x, Date.parse('2026-10-27T12:02:00Z'));
    assert.equal(swapPct({ swap_used: 1, swap_total: 4 }), 25);
    assert.equal(swapPct({ swap_used: 0, swap_total: 0 }), null);
    const p = { load1: null } as PerfPoint;
    assert.equal(hasLoad([p]), false);
    assert.equal(hasLoad([p, { ...p, load1: 0.2 }]), true);
  });

  it('time axis ticks fall on round steps, at most 7 per range', () => {
    const min = 60_000;
    assert.equal(tickStep(60 * min), 10 * min);
    assert.equal(tickStep(6 * 60 * min), 60 * min);
    assert.equal(tickStep(24 * 60 * min), 240 * min);
    assert.equal(tickStep(7 * 1440 * min), 1440 * min);
    assert.equal(tickStep(30 * 1440 * min), 7 * 1440 * min);
    assert.equal(tickStep(90 * 1440 * min), 14 * 1440 * min);
  });
});
