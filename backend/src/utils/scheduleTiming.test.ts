import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  computeNextRun,
  isValidTimeZone,
  nextRuns,
  normalizeCalendarSchedule,
  zonedTimeToInstant,
  type CalendarSchedule,
} from './scheduleTiming';

const NY = 'America/New_York';
const LONDON = 'Europe/London';
const CHICAGO = 'America/Chicago';

const iso = (d: Date) => d.toISOString();
const next = (s: CalendarSchedule, after: string) => iso(computeNextRun(s, new Date(after)));
const seq = (s: CalendarSchedule, after: string, n: number) => nextRuns(s, new Date(after), n).map(iso);

describe('time zone validation', () => {
  it('accepts canonical names, UTC and links', () => {
    for (const z of ['America/New_York', 'Europe/London', 'Asia/Kolkata', 'UTC', 'Etc/UTC', 'Asia/Calcutta', 'America/Argentina/Buenos_Aires']) {
      assert.equal(isValidTimeZone(z), true, z);
    }
  });
  it('rejects unknown names, offsets and non-strings', () => {
    for (const z of ['Mars/Olympus', '+05:00', '-0800', 'GMT+5:00', '', 'America/New York', 'x'.repeat(65), 5, null, undefined, {}]) {
      assert.equal(isValidTimeZone(z), false, String(z));
    }
  });
});

describe('zonedTimeToInstant', () => {
  it('converts ordinary wall times', () => {
    assert.equal(new Date(zonedTimeToInstant(2026, 1, 15, 2, 30, NY)).toISOString(), '2026-01-15T07:30:00.000Z');
    assert.equal(new Date(zonedTimeToInstant(2026, 7, 15, 2, 30, NY)).toISOString(), '2026-07-15T06:30:00.000Z');
    assert.equal(new Date(zonedTimeToInstant(2026, 7, 15, 2, 30, 'UTC')).toISOString(), '2026-07-15T02:30:00.000Z');
    assert.equal(new Date(zonedTimeToInstant(2026, 7, 15, 2, 30, 'Asia/Kolkata')).toISOString(), '2026-07-14T21:00:00.000Z');
  });
  it('moves a time inside a spring-forward gap to the instant the clock jumps', () => {
    // New York, 2026-03-08: 02:00 EST -> 03:00 EDT (07:00Z)
    assert.equal(new Date(zonedTimeToInstant(2026, 3, 8, 2, 30, NY)).toISOString(), '2026-03-08T07:00:00.000Z');
    assert.equal(new Date(zonedTimeToInstant(2026, 3, 8, 2, 0, NY)).toISOString(), '2026-03-08T07:00:00.000Z');
    // London, 2026-03-29: 01:00 GMT -> 02:00 BST (01:00Z)
    assert.equal(new Date(zonedTimeToInstant(2026, 3, 29, 1, 30, LONDON)).toISOString(), '2026-03-29T01:00:00.000Z');
  });
  it('resolves a repeated fall-back time to its first occurrence', () => {
    // New York, 2026-11-01: 01:30 happens at 05:30Z (EDT) and 06:30Z (EST)
    assert.equal(new Date(zonedTimeToInstant(2026, 11, 1, 1, 30, NY)).toISOString(), '2026-11-01T05:30:00.000Z');
    // London, 2026-10-25: 01:30 happens at 00:30Z (BST) and 01:30Z (GMT)
    assert.equal(new Date(zonedTimeToInstant(2026, 10, 25, 1, 30, LONDON)).toISOString(), '2026-10-25T00:30:00.000Z');
  });
});

describe('computeNextRun: daily', () => {
  const daily: CalendarSchedule = { frequency: 'daily', time: '02:00', timezone: CHICAGO };
  it('runs later today when the time is still ahead', () => {
    assert.equal(next(daily, '2026-06-10T05:00:00Z'), '2026-06-10T07:00:00.000Z'); // 00:00 CDT -> 02:00 CDT
  });
  it('runs tomorrow when the time has passed', () => {
    assert.equal(next(daily, '2026-06-10T08:00:00Z'), '2026-06-11T07:00:00.000Z');
  });
  it('after == an occurrence returns the following one', () => {
    assert.equal(next(daily, '2026-06-10T07:00:00Z'), '2026-06-11T07:00:00.000Z');
    assert.equal(next(daily, '2026-06-10T06:59:59.999Z'), '2026-06-10T07:00:00.000Z');
  });
  it('keeps wall-clock time across a zone boundary in UTC terms', () => {
    // 02:00 Chicago is 08:00Z in winter and 07:00Z in summer.
    assert.deepEqual(seq(daily, '2026-03-07T12:00:00Z', 3), [
      '2026-03-08T08:00:00.000Z', // spring-forward day: 02:00 doesn't exist -> 03:00 CDT
      '2026-03-09T07:00:00.000Z',
      '2026-03-10T07:00:00.000Z',
    ]);
  });
  it('handles a date the local zone is already a day ahead of UTC', () => {
    const tokyo: CalendarSchedule = { frequency: 'daily', time: '08:00', timezone: 'Asia/Tokyo' };
    // 2026-06-10T22:00Z is 07:00 on the 11th in Tokyo.
    assert.equal(next(tokyo, '2026-06-10T22:00:00Z'), '2026-06-10T23:00:00.000Z');
    const kiritimati: CalendarSchedule = { frequency: 'daily', time: '00:00', timezone: 'Pacific/Kiritimati' }; // UTC+14
    assert.equal(next(kiritimati, '2026-06-10T09:59:00Z'), '2026-06-10T10:00:00.000Z');
    const pagoPago: CalendarSchedule = { frequency: 'daily', time: '23:59', timezone: 'Pacific/Pago_Pago' }; // UTC-11
    // 10:00Z is 23:00 on the 9th there: tonight's 23:59 is 10:59Z.
    assert.equal(next(pagoPago, '2026-06-10T10:00:00Z'), '2026-06-10T10:59:00.000Z');
    assert.equal(next(pagoPago, '2026-06-10T10:59:00Z'), '2026-06-11T10:59:00.000Z');
  });
});

describe('computeNextRun: DST', () => {
  it('America/New_York spring-forward: 02:30 runs at the next valid instant (03:00 EDT)', () => {
    const s: CalendarSchedule = { frequency: 'daily', time: '02:30', timezone: NY };
    assert.deepEqual(seq(s, '2026-03-07T00:00:00Z', 3), [
      '2026-03-07T07:30:00.000Z', // 02:30 EST
      '2026-03-08T07:00:00.000Z', // gap -> 03:00 EDT
      '2026-03-09T06:30:00.000Z', // 02:30 EDT
    ]);
  });
  it('America/New_York fall-back: 01:30 runs once', () => {
    const s: CalendarSchedule = { frequency: 'daily', time: '01:30', timezone: NY };
    const runs = seq(s, '2026-10-31T00:00:00Z', 3);
    assert.deepEqual(runs, [
      '2026-10-31T05:30:00.000Z', // 01:30 EDT
      '2026-11-01T05:30:00.000Z', // first 01:30 (EDT); the EST repeat is skipped
      '2026-11-02T06:30:00.000Z', // 01:30 EST
    ]);
    // Computing from just after the first run (as the scheduler does) skips the repeat.
    assert.equal(next(s, '2026-11-01T05:30:20Z'), '2026-11-02T06:30:00.000Z');
  });
  it('Europe/London spring-forward and fall-back', () => {
    const spring: CalendarSchedule = { frequency: 'daily', time: '01:15', timezone: LONDON };
    assert.deepEqual(seq(spring, '2026-03-28T00:00:00Z', 3), [
      '2026-03-28T01:15:00.000Z', // GMT
      '2026-03-29T01:00:00.000Z', // gap -> 02:00 BST
      '2026-03-30T00:15:00.000Z', // BST
    ]);
    const fall: CalendarSchedule = { frequency: 'daily', time: '01:15', timezone: LONDON };
    assert.deepEqual(seq(fall, '2026-10-24T00:00:00Z', 3), [
      '2026-10-24T00:15:00.000Z', // BST
      '2026-10-25T00:15:00.000Z', // first 01:15 (BST) only
      '2026-10-26T01:15:00.000Z', // GMT
    ]);
  });
  it('a time outside the transition is unaffected on a DST day', () => {
    const s: CalendarSchedule = { frequency: 'daily', time: '12:00', timezone: NY };
    assert.equal(next(s, '2026-03-08T00:00:00Z'), '2026-03-08T16:00:00.000Z');
    assert.equal(next(s, '2026-11-01T00:00:00Z'), '2026-11-01T17:00:00.000Z');
  });
  it('hourly across New York spring-forward and fall-back', () => {
    const s: CalendarSchedule = { frequency: 'hourly', minute: 30, every_hours: 1, timezone: NY };
    assert.deepEqual(seq(s, '2026-03-08T05:45:00Z', 4), [
      '2026-03-08T06:30:00.000Z', // 01:30 EST
      '2026-03-08T07:00:00.000Z', // 02:30 doesn't exist -> 03:00 EDT
      '2026-03-08T07:30:00.000Z', // 03:30 EDT
      '2026-03-08T08:30:00.000Z',
    ]);
    const onTheHour: CalendarSchedule = { frequency: 'hourly', minute: 0, every_hours: 1, timezone: NY };
    // 02:00 doesn't exist and lands on 03:00, the same instant as the 03:00 run: one run.
    assert.deepEqual(seq(onTheHour, '2026-03-08T06:30:00Z', 2), ['2026-03-08T07:00:00.000Z', '2026-03-08T08:00:00.000Z']);
    assert.deepEqual(seq(s, '2026-11-01T04:45:00Z', 3), [
      '2026-11-01T05:30:00.000Z', // 01:30 EDT (once)
      '2026-11-01T07:30:00.000Z', // 02:30 EST
      '2026-11-01T08:30:00.000Z',
    ]);
  });
});

describe('computeNextRun: hourly', () => {
  it('runs at the minute past each hour', () => {
    const s: CalendarSchedule = { frequency: 'hourly', minute: 15, timezone: 'UTC' };
    assert.equal(next(s, '2026-06-10T10:14:00Z'), '2026-06-10T10:15:00.000Z');
    assert.equal(next(s, '2026-06-10T10:15:00Z'), '2026-06-10T11:15:00.000Z');
    assert.equal(next(s, '2026-06-10T23:20:00Z'), '2026-06-11T00:15:00.000Z');
  });
  it('every N hours counts from local midnight', () => {
    const s: CalendarSchedule = { frequency: 'hourly', minute: 0, every_hours: 6, timezone: CHICAGO };
    // 00, 06, 12, 18 Chicago (CDT = UTC-5)
    assert.deepEqual(seq(s, '2026-06-10T05:00:00Z', 5), [
      '2026-06-10T11:00:00.000Z',
      '2026-06-10T17:00:00.000Z',
      '2026-06-10T23:00:00.000Z',
      '2026-06-11T05:00:00.000Z',
      '2026-06-11T11:00:00.000Z',
    ]);
    const five: CalendarSchedule = { frequency: 'hourly', minute: 5, every_hours: 5, timezone: 'UTC' };
    assert.deepEqual(seq(five, '2026-06-10T19:00:00Z', 3), ['2026-06-10T20:05:00.000Z', '2026-06-11T00:05:00.000Z', '2026-06-11T05:05:00.000Z']);
  });
  it('a half-hour-offset zone keeps local minutes', () => {
    const s: CalendarSchedule = { frequency: 'hourly', minute: 0, every_hours: 12, timezone: 'Asia/Kolkata' };
    assert.deepEqual(seq(s, '2026-06-10T00:00:00Z', 2), ['2026-06-10T06:30:00.000Z', '2026-06-10T18:30:00.000Z']);
  });
});

describe('computeNextRun: weekly', () => {
  const weekdays: CalendarSchedule = { frequency: 'weekly', time: '02:30', days: [1, 2, 3, 4, 5], timezone: CHICAGO };
  it('skips the weekend', () => {
    // 2026-06-12 is a Friday.
    assert.deepEqual(seq(weekdays, '2026-06-12T08:00:00Z', 3), [
      '2026-06-15T07:30:00.000Z', // Monday
      '2026-06-16T07:30:00.000Z',
      '2026-06-17T07:30:00.000Z',
    ]);
  });
  it('runs on the chosen days only', () => {
    const s: CalendarSchedule = { frequency: 'weekly', time: '23:00', days: [0, 3], timezone: 'UTC' };
    // 2026-06-10 is a Wednesday.
    assert.deepEqual(seq(s, '2026-06-10T00:00:00Z', 4), [
      '2026-06-10T23:00:00.000Z', // Wed
      '2026-06-14T23:00:00.000Z', // Sun
      '2026-06-17T23:00:00.000Z', // Wed
      '2026-06-21T23:00:00.000Z',
    ]);
  });
  it('uses the weekday in the schedule zone, not in UTC', () => {
    // Monday 01:00 in Tokyo is Sunday 16:00Z.
    const s: CalendarSchedule = { frequency: 'weekly', time: '01:00', days: [1], timezone: 'Asia/Tokyo' };
    assert.equal(next(s, '2026-06-13T00:00:00Z'), '2026-06-14T16:00:00.000Z');
    const la: CalendarSchedule = { frequency: 'weekly', time: '22:00', days: [6], timezone: 'America/Los_Angeles' };
    // Saturday 22:00 PDT is Sunday 05:00Z.
    assert.equal(next(la, '2026-06-13T00:00:00Z'), '2026-06-14T05:00:00.000Z');
  });
  it('a single day a week', () => {
    const s: CalendarSchedule = { frequency: 'weekly', time: '02:00', days: [0], timezone: 'UTC' };
    assert.equal(next(s, '2026-06-14T02:00:00Z'), '2026-06-21T02:00:00.000Z');
  });
});

describe('computeNextRun: monthly', () => {
  it('runs on the day of the month', () => {
    const s: CalendarSchedule = { frequency: 'monthly', time: '03:00', day_of_month: 15, timezone: 'UTC' };
    assert.equal(next(s, '2026-06-10T00:00:00Z'), '2026-06-15T03:00:00.000Z');
    assert.equal(next(s, '2026-06-15T03:00:00Z'), '2026-07-15T03:00:00.000Z');
  });
  it('a month without that day runs on its last day', () => {
    const s: CalendarSchedule = { frequency: 'monthly', time: '02:00', day_of_month: 31, timezone: 'UTC' };
    assert.deepEqual(seq(s, '2026-01-01T00:00:00Z', 6), [
      '2026-01-31T02:00:00.000Z',
      '2026-02-28T02:00:00.000Z',
      '2026-03-31T02:00:00.000Z',
      '2026-04-30T02:00:00.000Z',
      '2026-05-31T02:00:00.000Z',
      '2026-06-30T02:00:00.000Z',
    ]);
    const leap: CalendarSchedule = { frequency: 'monthly', time: '02:00', day_of_month: 30, timezone: 'UTC' };
    assert.equal(next(leap, '2028-02-01T00:00:00Z'), '2028-02-29T02:00:00.000Z');
    assert.equal(next(leap, '2028-02-29T02:00:00Z'), '2028-03-30T02:00:00.000Z');
  });
  it('month boundaries follow the schedule zone', () => {
    // 1st of the month at 00:30 New York is 04:30Z (EDT) / 05:30Z (EST).
    const s: CalendarSchedule = { frequency: 'monthly', time: '00:30', day_of_month: 1, timezone: NY };
    assert.deepEqual(seq(s, '2026-10-15T00:00:00Z', 2), ['2026-11-01T04:30:00.000Z', '2026-12-01T05:30:00.000Z']);
  });
  it('a year boundary', () => {
    const s: CalendarSchedule = { frequency: 'monthly', time: '00:00', day_of_month: 1, timezone: LONDON };
    assert.equal(next(s, '2026-12-15T00:00:00Z'), '2027-01-01T00:00:00.000Z');
  });
});

describe('computeNextRun: input', () => {
  it('rejects an invalid date', () => {
    assert.throws(() => computeNextRun({ frequency: 'daily', time: '02:00', timezone: 'UTC' }, new Date('nope')));
  });
});

describe('normalizeCalendarSchedule', () => {
  it('keeps only the fields the frequency uses', () => {
    assert.deepEqual(
      normalizeCalendarSchedule({ mode: 'calendar', frequency: 'daily', time: '02:00', timezone: 'UTC', days: [1], minute: 4 }),
      { frequency: 'daily', timezone: 'UTC', time: '02:00' }
    );
    assert.deepEqual(normalizeCalendarSchedule({ frequency: 'hourly', minute: 0, timezone: 'UTC' }), {
      frequency: 'hourly',
      timezone: 'UTC',
      minute: 0,
      every_hours: 1,
    });
    assert.deepEqual(normalizeCalendarSchedule({ frequency: 'weekly', time: '02:30', days: [5, 1, 3, 1], timezone: CHICAGO }), {
      frequency: 'weekly',
      timezone: CHICAGO,
      time: '02:30',
      days: [1, 3, 5],
    });
    assert.deepEqual(normalizeCalendarSchedule({ frequency: 'monthly', time: '02:30', day_of_month: 31, timezone: CHICAGO }), {
      frequency: 'monthly',
      timezone: CHICAGO,
      time: '02:30',
      day_of_month: 31,
    });
  });
  it('names the problem', () => {
    const bad: Array<[unknown, RegExp]> = [
      [null, /must be an object/],
      [[], /must be an object/],
      [{ mode: 'interval', frequency: 'daily', time: '02:00', timezone: 'UTC' }, /mode/],
      [{ frequency: 'yearly', time: '02:00', timezone: 'UTC' }, /frequency/],
      [{ frequency: 'daily', time: '02:00' }, /timezone/],
      [{ frequency: 'daily', time: '02:00', timezone: 'Nowhere/Land' }, /timezone/],
      [{ frequency: 'daily', time: '2:00', timezone: 'UTC' }, /time must be HH:MM/],
      [{ frequency: 'daily', time: '24:00', timezone: 'UTC' }, /time must be HH:MM/],
      [{ frequency: 'daily', time: '12:60', timezone: 'UTC' }, /time must be HH:MM/],
      [{ frequency: 'hourly', timezone: 'UTC' }, /minute/],
      [{ frequency: 'hourly', minute: 60, timezone: 'UTC' }, /minute/],
      [{ frequency: 'hourly', minute: 1.5, timezone: 'UTC' }, /minute/],
      [{ frequency: 'hourly', minute: 0, every_hours: 0, timezone: 'UTC' }, /every_hours/],
      [{ frequency: 'hourly', minute: 0, every_hours: 13, timezone: 'UTC' }, /every_hours/],
      [{ frequency: 'weekly', time: '02:00', timezone: 'UTC' }, /days/],
      [{ frequency: 'weekly', time: '02:00', days: [], timezone: 'UTC' }, /days/],
      [{ frequency: 'weekly', time: '02:00', days: [7], timezone: 'UTC' }, /days/],
      [{ frequency: 'weekly', time: '02:00', days: ['1'], timezone: 'UTC' }, /days/],
      [{ frequency: 'monthly', time: '02:00', timezone: 'UTC' }, /day_of_month/],
      [{ frequency: 'monthly', time: '02:00', day_of_month: 0, timezone: 'UTC' }, /day_of_month/],
      [{ frequency: 'monthly', time: '02:00', day_of_month: 32, timezone: 'UTC' }, /day_of_month/],
    ];
    for (const [input, message] of bad) {
      assert.throws(() => normalizeCalendarSchedule(input), message, JSON.stringify(input));
    }
  });
});
