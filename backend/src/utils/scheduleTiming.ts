/**
 * Calendar timing for scheduled scans: when a schedule next runs.
 *
 * A calendar schedule names wall-clock times in an IANA time zone:
 *
 *   hourly   minute past the hour, on every `every_hours`-th hour of the day
 *            (00:MM, NN:MM, 2NN:MM, ... local, restarting at midnight, like
 *            cron's `MM *\/NN`)
 *   daily    `time` (HH:MM) every day
 *   weekly   `time` on each of `days` (0 = Sunday ... 6 = Saturday)
 *   monthly  `time` on `day_of_month` (1-31); a month without that day runs on
 *            its last day
 *
 * Times stay wall-clock across daylight-saving changes:
 * - a local time that doesn't exist (the clock jumps from 02:00 to 03:00) runs
 *   at the next valid instant, the moment the clock jumps (03:00);
 * - a local time that happens twice (the clock falls back from 02:00 to 01:00)
 *   runs once, at its first occurrence.
 *
 * Only `Intl` is used (Node ships full ICU), so there is no date library.
 */

export type ScheduleFrequency = 'hourly' | 'daily' | 'weekly' | 'monthly';

export interface CalendarSchedule {
  frequency: ScheduleFrequency;
  /** IANA time zone the times are in. */
  timezone: string;
  /** HH:MM, 24-hour (daily, weekly, monthly). */
  time?: string;
  /** Minute past the hour, 0-59 (hourly). */
  minute?: number;
  /** Run on every Nth hour of the day, 1-12 (hourly; default 1). */
  every_hours?: number;
  /** Days of the week, 0 = Sunday ... 6 = Saturday (weekly). */
  days?: number[];
  /** Day of the month, 1-31 (monthly). */
  day_of_month?: number;
}

export const SCHEDULE_FREQUENCIES: readonly ScheduleFrequency[] = ['hourly', 'daily', 'weekly', 'monthly'];

const MINUTE_MS = 60_000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;

// ---------------------------------------------------------------------------
// Time zones
// ---------------------------------------------------------------------------

let supportedZones: Set<string> | null = null;
const IANA_NAME = /^[A-Za-z][A-Za-z0-9_+-]*(\/[A-Za-z0-9_+-]+)*$/;

/**
 * Whether `zone` is an IANA time zone this runtime knows. Accepts the canonical
 * names Intl lists, plus names Intl resolves that it doesn't list (UTC,
 * Etc/UTC, and links such as Asia/Calcutta that some browsers still report).
 * Rejects offsets such as "+05:00", which Intl would otherwise accept.
 */
export function isValidTimeZone(zone: unknown): zone is string {
  if (typeof zone !== 'string' || zone.length === 0 || zone.length > 64) return false;
  if (!supportedZones) {
    supportedZones = new Set(typeof Intl.supportedValuesOf === 'function' ? Intl.supportedValuesOf('timeZone') : []);
  }
  if (supportedZones.has(zone)) return true;
  if (!IANA_NAME.test(zone)) return false;
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: zone });
    return true;
  } catch {
    return false;
  }
}

const formatters = new Map<string, Intl.DateTimeFormat>();
function formatterFor(zone: string): Intl.DateTimeFormat {
  let f = formatters.get(zone);
  if (!f) {
    f = new Intl.DateTimeFormat('en-US', {
      timeZone: zone,
      hourCycle: 'h23',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
    formatters.set(zone, f);
  }
  return f;
}

interface WallClock {
  year: number;
  month: number; // 1-12
  day: number;
  hour: number;
  minute: number;
  second: number;
}

/** The wall-clock reading in `zone` at instant `ms`. */
export function wallClockAt(ms: number, zone: string): WallClock {
  const out: Record<string, number> = {};
  for (const part of formatterFor(zone).formatToParts(new Date(ms))) {
    if (part.type !== 'literal') out[part.type] = Number(part.value);
  }
  return {
    year: out.year,
    month: out.month,
    day: out.day,
    hour: out.hour === 24 ? 0 : out.hour,
    minute: out.minute,
    second: out.second,
  };
}

/** UTC offset of `zone` at instant `ms`, in whole minutes (east positive). */
function offsetMinutes(ms: number, zone: string): number {
  const w = wallClockAt(ms, zone);
  const asUtc = Date.UTC(w.year, w.month - 1, w.day, w.hour, w.minute, w.second);
  return Math.round((asUtc - Math.floor(ms / 1000) * 1000) / MINUTE_MS);
}

/**
 * The instant at which the wall clock in `zone` reads year-month-day hour:minute.
 * An ambiguous time (fall-back) resolves to its first occurrence; a time that
 * doesn't exist (spring-forward gap) resolves to the instant the clock jumps
 * past it, the next valid instant.
 */
export function zonedTimeToInstant(year: number, month: number, day: number, hour: number, minute: number, zone: string): number {
  const naive = Date.UTC(year, month - 1, day, hour, minute);
  // Offsets either side of the target; a zone changes offset at most once
  // within a day in practice, so these two cover every case.
  const before = offsetMinutes(naive - DAY_MS / 2, zone);
  const after = offsetMinutes(naive + DAY_MS / 2, zone);
  const matches: number[] = [];
  for (const off of new Set([before, after])) {
    const candidate = naive - off * MINUTE_MS;
    if (offsetMinutes(candidate, zone) === off) matches.push(candidate);
  }
  if (matches.length > 0) return Math.min(...matches);

  // In the gap. With the pre-jump offset the candidate lands after the jump,
  // with the post-jump offset before it: the jump is in between. Find the
  // first minute that already carries the post-jump offset.
  let lo = naive - after * MINUTE_MS; // still pre-jump
  let hi = naive - before * MINUTE_MS; // already post-jump
  if (lo > hi) [lo, hi] = [hi, lo];
  const postJump = offsetMinutes(hi, zone);
  lo = Math.floor(lo / MINUTE_MS);
  hi = Math.ceil(hi / MINUTE_MS);
  while (hi - lo > 1) {
    const mid = Math.floor((lo + hi) / 2);
    if (offsetMinutes(mid * MINUTE_MS, zone) === postJump) hi = mid;
    else lo = mid;
  }
  return hi * MINUTE_MS;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

const TIME = /^([01]\d|2[0-3]):([0-5]\d)$/;

export function parseTime(time: string): { hour: number; minute: number } {
  const m = TIME.exec(time);
  if (!m) throw new Error(`invalid time "${time}"`);
  return { hour: Number(m[1]), minute: Number(m[2]) };
}

function isIntIn(value: unknown, min: number, max: number): value is number {
  return Number.isInteger(value) && (value as number) >= min && (value as number) <= max;
}

/**
 * Check a calendar schedule from a request and return it normalized: only the
 * fields its frequency uses, days sorted and deduplicated. Throws an Error
 * whose message names the problem (the route turns it into a 400).
 */
export function normalizeCalendarSchedule(input: unknown): CalendarSchedule {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('schedule must be an object');
  }
  const s = input as Record<string, unknown>;
  if (s.mode !== undefined && s.mode !== 'calendar') {
    throw new Error("schedule.mode must be 'calendar' (send interval_minutes instead of schedule for a fixed interval)");
  }
  if (typeof s.frequency !== 'string' || !(SCHEDULE_FREQUENCIES as readonly string[]).includes(s.frequency)) {
    throw new Error(`schedule.frequency must be one of: ${SCHEDULE_FREQUENCIES.join(', ')}`);
  }
  const frequency = s.frequency as ScheduleFrequency;
  if (!isValidTimeZone(s.timezone)) {
    throw new Error('schedule.timezone must be an IANA time zone name, e.g. America/Chicago or UTC');
  }
  const timezone = s.timezone;

  if (frequency === 'hourly') {
    if (!isIntIn(s.minute, 0, 59)) throw new Error('schedule.minute must be an integer from 0 to 59');
    const every = s.every_hours ?? 1;
    if (!isIntIn(every, 1, 12)) throw new Error('schedule.every_hours must be an integer from 1 to 12');
    return { frequency, timezone, minute: s.minute, every_hours: every };
  }

  if (typeof s.time !== 'string' || !TIME.test(s.time)) {
    throw new Error('schedule.time must be HH:MM (24-hour), e.g. 02:30');
  }
  const time = s.time;
  if (frequency === 'daily') return { frequency, timezone, time };

  if (frequency === 'weekly') {
    if (!Array.isArray(s.days) || s.days.length === 0 || !s.days.every((d) => isIntIn(d, 0, 6))) {
      throw new Error('schedule.days must be a non-empty array of weekdays, 0 (Sunday) to 6 (Saturday)');
    }
    const days = [...new Set(s.days as number[])].sort((a, b) => a - b);
    return { frequency, timezone, time, days };
  }

  if (!isIntIn(s.day_of_month, 1, 31)) throw new Error('schedule.day_of_month must be an integer from 1 to 31');
  return { frequency, timezone, time, day_of_month: s.day_of_month };
}

// ---------------------------------------------------------------------------
// Next run
// ---------------------------------------------------------------------------

function daysInMonth(year: number, month: number): number {
  return new Date(Date.UTC(year, month, 0)).getUTCDate();
}

/** Local wall-clock slots (hour, minute) the schedule fires at on a given local date. */
function slotsOn(schedule: CalendarSchedule, year: number, month: number, day: number): Array<[number, number]> {
  if (schedule.frequency === 'hourly') {
    const every = schedule.every_hours ?? 1;
    const slots: Array<[number, number]> = [];
    for (let h = 0; h < 24; h += every) slots.push([h, schedule.minute ?? 0]);
    return slots;
  }
  const { hour, minute } = parseTime(schedule.time ?? '00:00');
  if (schedule.frequency === 'weekly') {
    const weekday = new Date(Date.UTC(year, month - 1, day)).getUTCDay();
    if (!(schedule.days ?? []).includes(weekday)) return [];
  } else if (schedule.frequency === 'monthly') {
    const target = Math.min(schedule.day_of_month ?? 1, daysInMonth(year, month));
    if (day !== target) return [];
  }
  return [[hour, minute]];
}

/**
 * The first time strictly after `after` at which `schedule` runs. When `after`
 * is itself an occurrence, the one following it is returned, so computing the
 * next run right after a run never repeats it.
 */
export function computeNextRun(schedule: CalendarSchedule, after: Date): Date {
  const afterMs = after.getTime();
  if (!Number.isFinite(afterMs)) throw new Error('computeNextRun: invalid "after" date');
  const zone = schedule.timezone;
  const start = wallClockAt(afterMs, zone);
  // Start a day early: around a fall-back at midnight the wall date can step
  // back, and an occurrence after `after` can sit on the previous local date.
  // 400 days covers any monthly or weekly gap.
  for (let i = -1; i <= 400; i++) {
    const d = new Date(Date.UTC(start.year, start.month - 1, start.day + i));
    const year = d.getUTCFullYear();
    const month = d.getUTCMonth() + 1;
    const day = d.getUTCDate();
    let best: number | null = null;
    for (const [hour, minute] of slotsOn(schedule, year, month, day)) {
      const at = zonedTimeToInstant(year, month, day, hour, minute, zone);
      if (at > afterMs && (best === null || at < best)) best = at;
    }
    if (best !== null) return new Date(best);
  }
  throw new Error('computeNextRun: no occurrence within 400 days');
}

/** The next `count` runs after `after`. */
export function nextRuns(schedule: CalendarSchedule, after: Date, count: number): Date[] {
  const runs: Date[] = [];
  let cursor = after;
  for (let i = 0; i < count; i++) {
    cursor = computeNextRun(schedule, cursor);
    runs.push(cursor);
  }
  return runs;
}
