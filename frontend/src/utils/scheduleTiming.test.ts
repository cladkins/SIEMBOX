import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  defaultTimingForm,
  describeDays,
  describeSchedule,
  formatInZone,
  formatInterval,
  ordinal,
  scheduleFromForm,
  timeZoneOptions,
  timingFormFromRow,
  timingFormProblem,
  timingPayload,
} from './scheduleTiming.ts';

const CHI = 'America/Chicago';

describe('schedule summaries', () => {
  it('describes calendar schedules', () => {
    assert.equal(describeSchedule({ schedule: { frequency: 'weekly', time: '02:30', days: [1, 2, 3, 4, 5], timezone: CHI } }), 'Weekdays at 02:30 (America/Chicago)');
    assert.equal(describeSchedule({ schedule: { frequency: 'weekly', time: '04:00', days: [6, 0], timezone: 'UTC' } }), 'Weekends at 04:00 (UTC)');
    assert.equal(describeSchedule({ schedule: { frequency: 'weekly', time: '04:00', days: [1], timezone: 'UTC' } }), 'Mondays at 04:00 (UTC)');
    assert.equal(describeSchedule({ schedule: { frequency: 'weekly', time: '04:00', days: [5, 1, 3], timezone: 'UTC' } }), 'Mon, Wed, Fri at 04:00 (UTC)');
    assert.equal(describeSchedule({ schedule: { frequency: 'weekly', time: '04:00', days: [0, 6], timezone: 'UTC' } }), 'Weekends at 04:00 (UTC)');
    assert.equal(describeSchedule({ schedule: { frequency: 'daily', time: '02:00', timezone: CHI } }), 'Daily at 02:00 (America/Chicago)');
    assert.equal(describeSchedule({ schedule: { frequency: 'hourly', minute: 5, every_hours: 1, timezone: 'UTC' } }), 'Hourly at :05 (UTC)');
    assert.equal(describeSchedule({ schedule: { frequency: 'hourly', minute: 30, every_hours: 6, timezone: 'UTC' } }), 'Every 6 hours at :30 (UTC)');
    assert.equal(describeSchedule({ schedule: { frequency: 'monthly', time: '03:00', day_of_month: 15, timezone: 'Europe/London' } }), 'Monthly on the 15th at 03:00 (Europe/London)');
    assert.equal(describeSchedule({ schedule: { frequency: 'monthly', time: '03:00', day_of_month: 31, timezone: 'UTC' } }), 'Monthly on the 31st (or the last day) at 03:00 (UTC)');
  });
  it('describes fixed intervals as before', () => {
    assert.equal(describeSchedule({ schedule: null, interval_minutes: 1440 }), 'Every 24 hours');
    assert.equal(describeSchedule({ interval_minutes: 60 }), 'Every hour');
    assert.equal(describeSchedule({ interval_minutes: 90 }), 'Every 90 min');
    assert.equal(describeSchedule({}), '-');
    assert.equal(formatInterval(180), 'Every 3 hours');
    assert.equal(formatInterval(2880), 'Every 2 days');
  });
  it('words days and ordinals', () => {
    assert.equal(describeDays([0, 1, 2, 3, 4, 5, 6]), 'Every day');
    assert.equal(describeDays([0, 2]), 'Tue, Sun');
    assert.deepEqual([1, 2, 3, 4, 11, 12, 13, 21, 22, 23, 31].map(ordinal), ['1st', '2nd', '3rd', '4th', '11th', '12th', '13th', '21st', '22nd', '23rd', '31st']);
  });
});

describe('timing form', () => {
  it('defaults to daily at 02:00 in the given zone', () => {
    const f = defaultTimingForm(CHI);
    assert.equal(f.frequency, 'daily');
    assert.equal(f.time, '02:00');
    assert.equal(f.timezone, CHI);
    assert.deepEqual(timingPayload(f), { schedule: { frequency: 'daily', timezone: CHI, time: '02:00' } });
  });
  it('builds each frequency with only its fields', () => {
    const f = { ...defaultTimingForm('UTC'), minute: 15, every_hours: 3, days: [5, 1, 1], day_of_month: 31, time: '23:45' };
    assert.deepEqual(scheduleFromForm({ ...f, frequency: 'hourly' }), { frequency: 'hourly', timezone: 'UTC', minute: 15, every_hours: 3 });
    assert.deepEqual(scheduleFromForm({ ...f, frequency: 'weekly' }), { frequency: 'weekly', timezone: 'UTC', time: '23:45', days: [1, 5] });
    assert.deepEqual(scheduleFromForm({ ...f, frequency: 'monthly' }), { frequency: 'monthly', timezone: 'UTC', time: '23:45', day_of_month: 31 });
    assert.equal(scheduleFromForm({ ...f, frequency: 'interval' }), null);
    assert.deepEqual(timingPayload({ ...f, frequency: 'interval', interval_minutes: 360 }), { schedule: null, interval_minutes: 360 });
  });
  it('round-trips an existing schedule', () => {
    const schedule = { frequency: 'weekly' as const, time: '02:30', days: [1, 3], timezone: CHI };
    const form = timingFormFromRow({ schedule }, 'UTC');
    assert.equal(form.timezone, CHI);
    assert.deepEqual(scheduleFromForm(form), schedule);
    const legacy = timingFormFromRow({ schedule: null, interval_minutes: 720 }, 'Europe/London');
    assert.equal(legacy.frequency, 'interval');
    assert.equal(legacy.interval_minutes, 720);
    assert.equal(legacy.timezone, 'Europe/London', 'switching a legacy schedule to calendar starts in the viewer zone');
  });
  it('flags problems before saving', () => {
    const f = defaultTimingForm('UTC');
    assert.equal(timingFormProblem(f), null);
    assert.match(timingFormProblem({ ...f, frequency: 'weekly', days: [] })!, /day of the week/);
    assert.match(timingFormProblem({ ...f, time: '' })!, /time of day/);
    assert.match(timingFormProblem({ ...f, timezone: '' })!, /time zone/);
    assert.match(timingFormProblem({ ...f, frequency: 'hourly', every_hours: 13 })!, /1-12/);
    assert.match(timingFormProblem({ ...f, frequency: 'hourly', minute: 60 })!, /0-59/);
    assert.match(timingFormProblem({ ...f, frequency: 'monthly', day_of_month: 0 })!, /1-31/);
    assert.match(timingFormProblem({ ...f, frequency: 'interval', interval_minutes: 4 })!, /at least 5/);
  });
});

describe('time zones', () => {
  it('lists UTC first and includes extra zones', () => {
    const zones = timeZoneOptions('Asia/Calcutta', null, undefined);
    assert.equal(zones[0], 'UTC');
    assert.ok(zones.includes('America/New_York'));
    assert.ok(zones.includes('Asia/Calcutta'));
    assert.equal(new Set(zones).size, zones.length);
  });
  it('formats a run in a zone', () => {
    assert.equal(formatInZone('2026-03-09T07:30:00Z', CHI), 'Mon, Mar 9, 02:30 CDT');
    assert.equal(formatInZone('2026-01-09T08:30:00Z', CHI), 'Fri, Jan 9, 02:30 CST');
    assert.equal(formatInZone('2026-01-09T08:30:00Z', 'Not/AZone'), '2026-01-09T08:30:00Z');
  });
});
