/**
 * Endpoint scan policies, the pure parts: validating entries, policies and
 * overrides; time windows; when a scan is due (planPolicyRun) and the next
 * runs shown for it. The DB side is scanPolicies.db.test.ts.
 * Run with `npm test`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeScanSpec,
  normalizePolicyScans,
  normalizeOverrides,
  inWindow,
  applyWindow,
  nextAfter,
  planPolicyRun,
  projectRuns,
  previewRuns,
  resolveEffective,
  specKey,
  supportsPolicyScans,
  BUILTIN_DEFAULT_SCANS,
  type ScanSpec,
  type PolicyRunState,
} from './scanPolicies';

const at = (iso: string) => new Date(iso);
const iso = (d: Date | null) => (d ? d.toISOString() : null);

const hourly: ScanSpec = { enabled: true, schedule: null, interval_minutes: 60, window: null };
const daily0200: ScanSpec = {
  enabled: true,
  schedule: { frequency: 'daily', time: '02:00', timezone: 'UTC' },
  interval_minutes: null,
  window: null,
};

// ---- Validation ------------------------------------------------------------------

test('normalizeScanSpec: interval entry, calendar entry, fixed key order', () => {
  assert.deepEqual(normalizeScanSpec({ interval_minutes: 60, enabled: true }), hourly);
  const cal = normalizeScanSpec({
    window: { timezone: 'America/Chicago', end: '06:00', start: '22:00' },
    schedule: { timezone: 'UTC', time: '02:00', frequency: 'daily', days: [1] },
    enabled: false,
  });
  assert.deepEqual(cal, {
    enabled: false,
    schedule: { frequency: 'daily', timezone: 'UTC', time: '02:00' },
    interval_minutes: null,
    window: { start: '22:00', end: '06:00', timezone: 'America/Chicago' },
  });
  assert.deepEqual(Object.keys(cal), ['enabled', 'schedule', 'interval_minutes', 'window']);
});

test('normalizeScanSpec: rejects what the editor must not save', () => {
  const bad: Array<[unknown, RegExp]> = [
    [null, /must be an object/],
    [{ interval_minutes: 60 }, /enabled must be a boolean/],
    [{ enabled: true }, /interval_minutes must be an integer from 15/],
    [{ enabled: true, interval_minutes: 5 }, /from 15 to 43200/],
    [{ enabled: true, interval_minutes: 60.5 }, /integer/],
    [{ enabled: true, interval_minutes: 60, schedule: daily0200.schedule }, /not both/],
    [{ enabled: true, schedule: { frequency: 'yearly', timezone: 'UTC' } }, /schedule.frequency/],
    [{ enabled: true, interval_minutes: 60, window: { start: '25:00', end: '06:00', timezone: 'UTC' } }, /window.start/],
    [{ enabled: true, interval_minutes: 60, window: { start: '01:00', end: '1:00', timezone: 'UTC' } }, /window.end/],
    [{ enabled: true, interval_minutes: 60, window: { start: '01:00', end: '01:00', timezone: 'UTC' } }, /must differ/],
    [{ enabled: true, interval_minutes: 60, window: { start: '01:00', end: '02:00', timezone: '+05:00' } }, /timezone/],
    [{ enabled: true, interval_minutes: 60, window: 'nights' }, /window must be an object/],
  ];
  for (const [input, msg] of bad) assert.throws(() => normalizeScanSpec(input, 'scan'), msg, JSON.stringify(input));
});

test('normalizePolicyScans: every scan type, nothing else', () => {
  assert.deepEqual(normalizePolicyScans(BUILTIN_DEFAULT_SCANS), BUILTIN_DEFAULT_SCANS);
  const missing: Partial<typeof BUILTIN_DEFAULT_SCANS> = { ...BUILTIN_DEFAULT_SCANS };
  delete missing.yara;
  assert.throws(() => normalizePolicyScans(missing), /scans.yara is required/);
  assert.throws(() => normalizePolicyScans({ ...BUILTIN_DEFAULT_SCANS, nmap: hourly }), /unknown scan type "nmap"/);
  assert.throws(() => normalizePolicyScans({ ...BUILTIN_DEFAULT_SCANS, vuln: { enabled: 'yes' } }), /scans.vuln.enabled/);
  assert.throws(() => normalizePolicyScans([]), /must be an object/);
});

test('normalizeOverrides: some types, null entries drop, empty is null', () => {
  assert.equal(normalizeOverrides(null), null);
  assert.equal(normalizeOverrides({}), null);
  assert.equal(normalizeOverrides({ vuln: null }), null);
  assert.deepEqual(normalizeOverrides({ yara: daily0200, vuln: hourly, packages: null }), { vuln: hourly, yara: daily0200 });
  assert.deepEqual(Object.keys(normalizeOverrides({ yara: daily0200, vuln: hourly })!), ['vuln', 'yara']);
  assert.throws(() => normalizeOverrides({ ssh: hourly }), /unknown scan type/);
  assert.throws(() => normalizeOverrides([hourly]), /overrides must be an object/);
});

test('resolveEffective: an override replaces only its own type', () => {
  const eff = resolveEffective(BUILTIN_DEFAULT_SCANS, { vuln: daily0200 });
  assert.deepEqual(eff.map((e) => [e.scan_type, e.source]), [
    ['vuln', 'override'], ['yara', 'policy'], ['packages', 'policy'], ['inventory', 'policy'],
  ]);
  assert.deepEqual(eff[0].spec, daily0200);
  assert.deepEqual(eff[3].spec, BUILTIN_DEFAULT_SCANS.inventory);
});

test('supportsPolicyScans', () => {
  assert.equal(supportsPolicyScans({ capabilities: ['adhoc_scans', 'policy_scans'] }), true);
  assert.equal(supportsPolicyScans({ capabilities: ['adhoc_scans'] }), false);
  assert.equal(supportsPolicyScans({ capabilities: null }), false);
  assert.equal(supportsPolicyScans(null), false);
});

// ---- Windows ---------------------------------------------------------------------

test('inWindow: same-day and past-midnight windows, start inclusive, end exclusive', () => {
  const day = { start: '09:00', end: '17:00', timezone: 'UTC' };
  assert.equal(inWindow(at('2026-03-02T09:00:00Z').getTime(), day), true);
  assert.equal(inWindow(at('2026-03-02T16:59:00Z').getTime(), day), true);
  assert.equal(inWindow(at('2026-03-02T17:00:00Z').getTime(), day), false);
  assert.equal(inWindow(at('2026-03-02T08:59:00Z').getTime(), day), false);
  const night = { start: '22:00', end: '06:00', timezone: 'UTC' };
  assert.equal(inWindow(at('2026-03-02T23:30:00Z').getTime(), night), true);
  assert.equal(inWindow(at('2026-03-02T05:59:00Z').getTime(), night), true);
  assert.equal(inWindow(at('2026-03-02T06:00:00Z').getTime(), night), false);
  assert.equal(inWindow(at('2026-03-02T12:00:00Z').getTime(), night), false);
  // In the window's own zone: 22:00 Chicago (CST, UTC-6) is 04:00 UTC.
  const chicago = { start: '22:00', end: '23:00', timezone: 'America/Chicago' };
  assert.equal(inWindow(at('2026-01-15T04:30:00Z').getTime(), chicago), true);
  assert.equal(inWindow(at('2026-01-15T22:30:00Z').getTime(), chicago), false);
});

test('applyWindow: inside stays, outside moves to the next opening', () => {
  const night = { start: '22:00', end: '06:00', timezone: 'UTC' };
  const inside = at('2026-03-02T23:00:00Z').getTime();
  assert.equal(applyWindow(inside, night), inside);
  assert.equal(applyWindow(inside, null), inside);
  assert.equal(iso(new Date(applyWindow(at('2026-03-02T10:00:00Z').getTime(), night))), '2026-03-02T22:00:00.000Z');
  assert.equal(iso(new Date(applyWindow(at('2026-03-02T06:00:00Z').getTime(), night))), '2026-03-02T22:00:00.000Z');
  // DST: 02:30 does not exist in New York on 2026-03-08; the window opens when the clock jumps (03:00 EDT).
  const ny = { start: '02:30', end: '04:00', timezone: 'America/New_York' };
  assert.equal(iso(new Date(applyWindow(at('2026-03-08T05:00:00Z').getTime(), ny))), '2026-03-08T07:00:00.000Z');
});

test('nextAfter: calendar occurrence, or the interval later', () => {
  assert.equal(iso(new Date(nextAfter(daily0200, at('2026-03-02T02:00:00Z').getTime()))), '2026-03-03T02:00:00.000Z');
  assert.equal(iso(new Date(nextAfter(hourly, at('2026-03-02T02:10:00Z').getTime()))), '2026-03-02T03:10:00.000Z');
});

// ---- When a scan is due ----------------------------------------------------------------

const now = at('2026-03-02T12:00:00Z');
const state = (spec: ScanSpec, next: string | null, last: string | null): PolicyRunState => ({
  spec_key: specKey(spec),
  next_due_at: next ? at(next) : null,
  last_issued_at: last ? at(last) : null,
});

test('planPolicyRun: a new endpoint runs its baseline now, then on schedule', () => {
  const p = planPolicyRun(daily0200, null, now, false);
  assert.equal(p.issue, true);
  assert.equal(p.changed, true);
  assert.equal(iso(p.last_issued_at), now.toISOString());
  assert.equal(iso(p.next_due_at), '2026-03-03T02:00:00.000Z');
  const h = planPolicyRun(hourly, null, now, false);
  assert.equal(iso(h.next_due_at), '2026-03-02T13:00:00.000Z');
});

test('planPolicyRun: not due yet changes nothing', () => {
  const s = state(hourly, '2026-03-02T12:30:00Z', '2026-03-02T11:30:00Z');
  const p = planPolicyRun(hourly, s, now, false);
  assert.equal(p.issue, false);
  assert.equal(p.changed, false);
  assert.equal(p.waiting, null);
  assert.equal(iso(p.next_due_at), '2026-03-02T12:30:00.000Z');
});

test('planPolicyRun: an endpoint back after missing runs catches up once', () => {
  // Due daily at 02:00 and last issued five days ago: one run now, next 02:00 tomorrow.
  const s = state(daily0200, '2026-02-26T02:00:00Z', '2026-02-25T02:00:00Z');
  const p = planPolicyRun(daily0200, s, now, false);
  assert.equal(p.issue, true);
  assert.equal(iso(p.next_due_at), '2026-03-03T02:00:00.000Z');
  // The next heartbeat a minute later issues nothing more.
  const again = planPolicyRun(daily0200, p, at('2026-03-02T12:01:00Z'), true);
  assert.equal(again.issue, false);
  assert.equal(again.changed, false);
});

test('planPolicyRun: a due run outside its window waits for it, then runs', () => {
  const spec = { ...hourly, window: { start: '22:00', end: '06:00', timezone: 'UTC' } };
  const s = state(spec, '2026-03-02T09:00:00Z', '2026-03-02T05:30:00Z');
  const p = planPolicyRun(spec, s, now, false);
  assert.equal(p.issue, false);
  assert.equal(p.waiting, 'window');
  assert.equal(p.changed, false);
  const later = planPolicyRun(spec, s, at('2026-03-02T22:00:00Z'), false);
  assert.equal(later.issue, true);
  assert.equal(iso(later.next_due_at), '2026-03-02T23:00:00.000Z');
  // Next runs: the opening, then hourly inside the window.
  assert.deepEqual(projectRuns(spec, p, now, 3).map(iso), [
    '2026-03-02T22:00:00.000Z', '2026-03-02T23:00:00.000Z', '2026-03-03T00:00:00.000Z',
  ]);
});

test('planPolicyRun: a due run while the last one is outstanding is skipped', () => {
  const s = state(hourly, '2026-03-02T11:59:00Z', '2026-03-02T10:59:00Z');
  const p = planPolicyRun(hourly, s, now, true);
  assert.equal(p.issue, false);
  assert.equal(p.waiting, 'outstanding');
  assert.equal(iso(p.next_due_at), '2026-03-02T13:00:00.000Z');
  assert.equal(iso(p.last_issued_at), '2026-03-02T10:59:00.000Z');
});

test('planPolicyRun: disabled means nothing due; re-enabling resumes', () => {
  const off = { ...hourly, enabled: false };
  const s = state(hourly, '2026-03-02T11:00:00Z', '2026-03-02T10:00:00Z');
  const p = planPolicyRun(off, s, now, false);
  assert.equal(p.issue, false);
  assert.equal(p.next_due_at, null);
  assert.equal(p.changed, true);
  assert.deepEqual(projectRuns(off, p, now, 3), []);
  // Back on: an interval entry is due an interval after its last run (already passed: now).
  const on = planPolicyRun(hourly, p, now, false);
  assert.equal(on.issue, true);
});

test('planPolicyRun: changing the timing recomputes the next due time without running now', () => {
  const s = state(hourly, '2026-03-02T12:30:00Z', '2026-03-02T11:30:00Z');
  const toDaily = planPolicyRun(daily0200, s, now, false);
  assert.equal(toDaily.issue, false);
  assert.equal(toDaily.changed, true);
  assert.equal(iso(toDaily.next_due_at), '2026-03-03T02:00:00.000Z');
  // Interval -> a longer interval: counted from the last run.
  const sixHours = { ...hourly, interval_minutes: 360 };
  const p = planPolicyRun(sixHours, s, now, false);
  assert.equal(iso(p.next_due_at), '2026-03-02T17:30:00.000Z');
  assert.equal(p.issue, false);
  // -> a shorter interval whose time has already passed: due now.
  const s2 = state(sixHours, '2026-03-02T17:30:00Z', '2026-03-02T11:30:00Z');
  assert.equal(planPolicyRun({ ...hourly, interval_minutes: 15 }, s2, now, false).issue, true);
});

test('projectRuns and previewRuns', () => {
  const p = planPolicyRun(daily0200, null, now, false);
  assert.deepEqual(projectRuns(daily0200, p, now, 3).map(iso), [
    now.toISOString(), '2026-03-03T02:00:00.000Z', '2026-03-04T02:00:00.000Z',
  ]);
  assert.deepEqual(previewRuns(daily0200, now, 2).map(iso), ['2026-03-03T02:00:00.000Z', '2026-03-04T02:00:00.000Z']);
  assert.deepEqual(previewRuns(hourly, now, 2).map(iso), ['2026-03-02T13:00:00.000Z', '2026-03-02T14:00:00.000Z']);
  const weekend = { ...daily0200, window: { start: '00:00', end: '01:00', timezone: 'UTC' } };
  // Daily at 02:00 but only between 00:00 and 01:00: each run waits for the next midnight.
  assert.deepEqual(previewRuns(weekend, now, 2).map(iso), ['2026-03-04T00:00:00.000Z', '2026-03-05T00:00:00.000Z']);
});
