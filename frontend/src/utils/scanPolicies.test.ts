import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  canEditPolicies,
  defaultPolicyScans,
  describeLocalIntervals,
  describeSpec,
  describeWindow,
  enabledCount,
  newSpecForm,
  policyRunLabel,
  specFormFromSpec,
  specFormProblem,
  specFromForm,
  supportsPolicyScans,
  timeInWindow,
  windowMissesSchedule,
  type ScanSpec,
} from './scanPolicies.ts';

const daily: ScanSpec = {
  enabled: true,
  schedule: { frequency: 'daily', time: '02:00', timezone: 'UTC' },
  interval_minutes: null,
  window: null,
};

describe('scan policies', () => {
  it('round-trips an interval entry and a calendar entry with a window', () => {
    const interval: ScanSpec = { enabled: false, schedule: null, interval_minutes: 360, window: null };
    assert.deepEqual(specFromForm(specFormFromSpec(interval, 'UTC')), interval);
    const windowed: ScanSpec = {
      enabled: true,
      schedule: { frequency: 'weekly', time: '01:30', days: [0, 6], timezone: 'Europe/London' },
      interval_minutes: null,
      window: { start: '22:00', end: '06:00', timezone: 'Europe/London' },
    };
    assert.deepEqual(specFromForm(specFormFromSpec(windowed, 'UTC')), windowed);
    // Turning the window off drops it; the form keeps its times for turning it back on.
    const form = specFormFromSpec(windowed, 'UTC');
    form.useWindow = false;
    assert.equal(specFromForm(form).window, null);
    assert.equal(form.window.start, '22:00');
  });

  it('a new form is daily at 02:00 in the given zone, with a default overnight window ready', () => {
    const f = newSpecForm('America/Chicago');
    assert.deepEqual(specFromForm(f), {
      enabled: true,
      schedule: { frequency: 'daily', time: '02:00', timezone: 'America/Chicago' },
      interval_minutes: null,
      window: null,
    });
    assert.deepEqual(f.window, { start: '22:00', end: '06:00', timezone: 'America/Chicago' });
  });

  it('flags what the server would refuse', () => {
    const f = specFormFromSpec({ enabled: true, schedule: null, interval_minutes: 10, window: null }, 'UTC');
    assert.match(specFormProblem(f) ?? '', /at least|15 minutes/);
    f.timing.interval_minutes = 60;
    assert.equal(specFormProblem(f), null);
    f.useWindow = true;
    f.window = { start: '01:00', end: '01:00', timezone: 'UTC' };
    assert.match(specFormProblem(f) ?? '', /must differ/);
    f.window.end = '';
    assert.match(specFormProblem(f) ?? '', /start and end/);
    const w = specFormFromSpec({ ...daily, schedule: { frequency: 'weekly', time: '02:00', days: [1], timezone: 'UTC' } }, 'UTC');
    w.timing.days = [];
    assert.match(specFormProblem(w) ?? '', /day of the week/);
  });

  it('windows: same-day and overnight; a calendar time outside its window is flagged', () => {
    assert.equal(timeInWindow('09:00', { start: '09:00', end: '17:00' }), true);
    assert.equal(timeInWindow('17:00', { start: '09:00', end: '17:00' }), false);
    assert.equal(timeInWindow('23:15', { start: '22:00', end: '06:00' }), true);
    assert.equal(timeInWindow('05:59', { start: '22:00', end: '06:00' }), true);
    assert.equal(timeInWindow('12:00', { start: '22:00', end: '06:00' }), false);
    const night = { start: '22:00', end: '06:00', timezone: 'UTC' };
    assert.equal(windowMissesSchedule({ ...daily, window: night }), false);
    assert.equal(windowMissesSchedule({ ...daily, schedule: { ...daily.schedule!, time: '12:00' }, window: night }), true);
    assert.equal(windowMissesSchedule({ ...daily, schedule: { ...daily.schedule!, time: '12:00' }, window: { ...night, timezone: 'Asia/Tokyo' } }), false, 'different zones are not compared');
    const hourly: ScanSpec = { ...daily, schedule: { frequency: 'hourly', minute: 30, every_hours: 6, timezone: 'UTC' }, window: { start: '01:00', end: '05:00', timezone: 'UTC' } };
    assert.equal(windowMissesSchedule(hourly), true, '00:30, 06:30, 12:30, 18:30 all miss 01:00-05:00');
    assert.equal(windowMissesSchedule({ ...hourly, window: { start: '00:00', end: '01:00', timezone: 'UTC' } }), false);
    assert.equal(windowMissesSchedule({ enabled: true, schedule: null, interval_minutes: 60, window: night }), false);
  });

  it('describes entries and windows', () => {
    assert.equal(describeSpec(daily), 'Daily at 02:00 (UTC)');
    assert.equal(describeSpec({ ...daily, enabled: false }), 'Off');
    assert.equal(describeSpec({ enabled: true, schedule: null, interval_minutes: 1440, window: null }), 'Every 24 hours');
    assert.equal(
      describeSpec({ ...daily, window: { start: '22:00', end: '06:00', timezone: 'UTC' } }),
      'Daily at 02:00 (UTC), only 22:00–06:00 (overnight) (UTC)'
    );
    assert.equal(describeWindow({ start: '09:00', end: '17:00', timezone: 'UTC' }), 'only 09:00–17:00 (UTC)');
    assert.equal(describeWindow(null), '');
    assert.equal(describeSpec(null), '-');
  });

  it('the default policy, enabled counts', () => {
    const d = defaultPolicyScans();
    assert.deepEqual(Object.keys(d), ['vuln', 'yara', 'packages', 'inventory']);
    assert.equal(d.inventory.interval_minutes, 60);
    assert.equal(enabledCount(d), 4);
    d.yara.enabled = false;
    assert.equal(enabledCount(d), 3);
  });

  it('roles, capability, history labels, local intervals', () => {
    assert.equal(canEditPolicies('admin'), true);
    assert.equal(canEditPolicies('operator'), true);
    assert.equal(canEditPolicies('analyst'), false);
    assert.equal(canEditPolicies(undefined), false);
    assert.equal(supportsPolicyScans({ capabilities: ['adhoc_scans', 'policy_scans'] }), true);
    assert.equal(supportsPolicyScans({ capabilities: ['adhoc_scans'] }), false);
    assert.equal(supportsPolicyScans(null), false);
    assert.equal(policyRunLabel({ trigger: 'policy', policy_name: 'Servers', policy_source: 'policy' }), 'policy · Servers');
    assert.equal(policyRunLabel({ trigger: 'policy', policy_name: 'Default', policy_source: 'override' }), 'endpoint override · Default');
    assert.equal(policyRunLabel({ trigger: 'console' }), '');
    assert.equal(
      describeLocalIntervals({ inventory_seconds: 3600, vuln_seconds: 86400, packages_seconds: 21600, yara: 'changed files every minute' }),
      'system inventory hourly, vulnerabilities daily, packages every 6 hours (its own defaults), YARA changed files every minute'
    );
    assert.equal(describeLocalIntervals(null), '');
  });
});
