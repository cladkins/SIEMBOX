/**
 * Scheduled-scan timing on the Scheduled Scans page: the form's timing fields,
 * the request payload they make, and the human summary in the list.
 *
 * The backend owns the rules and computes every run (backend/src/utils/
 * scheduleTiming.ts); the form's "Next runs" preview asks it
 * (POST /api/scheduled-scans/preview), so nothing here re-implements them.
 */

export type ScheduleFrequency = 'hourly' | 'daily' | 'weekly' | 'monthly';

export interface CalendarSchedule {
  frequency: ScheduleFrequency;
  timezone: string;
  time?: string;
  minute?: number;
  every_hours?: number;
  days?: number[];
  day_of_month?: number;
}

/** What the form's "Frequency" select can be: a calendar frequency, or the original fixed interval. */
export type FormFrequency = ScheduleFrequency | 'interval';

export interface TimingForm {
  frequency: FormFrequency;
  /** HH:MM (daily, weekly, monthly). */
  time: string;
  /** Minute past the hour (hourly). */
  minute: number;
  /** Every N hours, 1-12 (hourly). */
  every_hours: number;
  /** 0 = Sunday ... 6 = Saturday (weekly). */
  days: number[];
  /** 1-31 (monthly). */
  day_of_month: number;
  timezone: string;
  /** Fixed interval, minutes (interval). */
  interval_minutes: number;
}

export interface TimedRow {
  schedule?: CalendarSchedule | null;
  interval_minutes?: number | null;
}

export const WEEKDAY_SHORT = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const WEEKDAY_LONG = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
/** Monday-first order for the day picker. */
export const WEEKDAY_ORDER = [1, 2, 3, 4, 5, 6, 0];

export const INTERVAL_PRESETS: Array<{ label: string; value: number }> = [
  { label: 'Every hour', value: 60 },
  { label: 'Every 6 hours', value: 360 },
  { label: 'Every 12 hours', value: 720 },
  { label: 'Every 24 hours', value: 1440 },
  { label: 'Every 7 days', value: 10080 },
];

/** The viewer's time zone, the default for a new schedule. */
export function browserTimeZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  } catch {
    return 'UTC';
  }
}

/** Form defaults for a new schedule: daily at 02:00 in the viewer's zone. */
export function defaultTimingForm(timezone: string = browserTimeZone()): TimingForm {
  return {
    frequency: 'daily',
    time: '02:00',
    minute: 0,
    every_hours: 1,
    days: [1, 2, 3, 4, 5],
    day_of_month: 1,
    timezone,
    interval_minutes: 1440,
  };
}

/** The form fields for an existing schedule (unset fields keep the defaults). */
export function timingFormFromRow(row: TimedRow, fallbackZone: string = browserTimeZone()): TimingForm {
  const s = row.schedule;
  if (!s) {
    return { ...defaultTimingForm(fallbackZone), frequency: 'interval', interval_minutes: row.interval_minutes ?? 1440 };
  }
  const base = defaultTimingForm(s.timezone || fallbackZone);
  return {
    ...base,
    frequency: s.frequency,
    time: s.time ?? base.time,
    minute: s.minute ?? base.minute,
    every_hours: s.every_hours ?? base.every_hours,
    days: Array.isArray(s.days) && s.days.length > 0 ? [...s.days] : base.days,
    day_of_month: s.day_of_month ?? base.day_of_month,
  };
}

/** The calendar schedule the form names (null in interval mode). */
export function scheduleFromForm(form: TimingForm): CalendarSchedule | null {
  const timezone = form.timezone;
  switch (form.frequency) {
    case 'interval':
      return null;
    case 'hourly':
      return { frequency: 'hourly', timezone, minute: form.minute, every_hours: form.every_hours };
    case 'daily':
      return { frequency: 'daily', timezone, time: form.time };
    case 'weekly':
      return { frequency: 'weekly', timezone, time: form.time, days: [...new Set(form.days)].sort((a, b) => a - b) };
    case 'monthly':
      return { frequency: 'monthly', timezone, time: form.time, day_of_month: form.day_of_month };
  }
}

/**
 * The timing part of a create/update request. Interval mode sends
 * `schedule: null` so an edit switches a calendar schedule back.
 */
export function timingPayload(form: TimingForm): { schedule: CalendarSchedule | null; interval_minutes?: number } {
  const schedule = scheduleFromForm(form);
  return schedule ? { schedule } : { schedule: null, interval_minutes: form.interval_minutes };
}

/** Wall-clock parts of an instant in a zone. */
function partsInZone(iso: string, timeZone: string): { weekday: number; day: number; hour: number; minute: number } | null {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  try {
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone,
      weekday: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hourCycle: 'h23',
    }).formatToParts(d);
    const get = (type: string) => parts.find((x) => x.type === type)?.value ?? '';
    return { weekday: WEEKDAY_SHORT.indexOf(get('weekday')), day: Number(get('day')), hour: Number(get('hour')), minute: Number(get('minute')) };
  } catch {
    return null;
  }
}

/**
 * The calendar schedule a fixed-interval schedule converts to, keeping the
 * time of its next run: every 24 hours with the next run at 03:15 becomes
 * daily at 03:15; every 7 days becomes weekly on that weekday; every hour, or
 * every 2/3/4/6/8/12 hours, becomes hourly at that minute (every-N-hours
 * counts from midnight, so the hours can move -- the form lists them).
 * Null when there's no equivalent (e.g. every 30 minutes, every 2 days).
 */
export function calendarEquivalent(intervalMinutes: number, nextRunIso: string | null | undefined, timeZone: string): Partial<TimingForm> | null {
  if (!nextRunIso) return null;
  const p = partsInZone(nextRunIso, timeZone);
  if (!p || p.weekday < 0) return null;
  const time = `${String(p.hour).padStart(2, '0')}:${String(p.minute).padStart(2, '0')}`;
  if (intervalMinutes === 1440) return { frequency: 'daily', time, timezone: timeZone };
  if (intervalMinutes === 10080) return { frequency: 'weekly', time, days: [p.weekday], timezone: timeZone };
  const hours = intervalMinutes / 60;
  if (Number.isInteger(hours) && [1, 2, 3, 4, 6, 8, 12].includes(hours)) {
    return { frequency: 'hourly', minute: p.minute, every_hours: hours, timezone: timeZone };
  }
  return null;
}

/** A problem the form can see before saving, or null. The server checks again. */
export function timingFormProblem(form: TimingForm): string | null {
  if (form.frequency === 'interval') {
    return Number.isInteger(form.interval_minutes) && form.interval_minutes >= 5 ? null : 'Interval must be at least 5 minutes';
  }
  if (!form.timezone) return 'Choose a time zone';
  if (form.frequency === 'hourly') {
    if (!Number.isInteger(form.minute) || form.minute < 0 || form.minute > 59) return 'Minute must be 0-59';
    if (!Number.isInteger(form.every_hours) || form.every_hours < 1 || form.every_hours > 12) return 'Every N hours must be 1-12';
    return null;
  }
  if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(form.time || '')) return 'Choose a time of day';
  if (form.frequency === 'weekly' && form.days.length === 0) return 'Choose at least one day of the week';
  if (form.frequency === 'monthly' && (!Number.isInteger(form.day_of_month) || form.day_of_month < 1 || form.day_of_month > 31)) {
    return 'Day of month must be 1-31';
  }
  return null;
}

export function ordinal(n: number): string {
  const mod100 = n % 100;
  if (mod100 >= 11 && mod100 <= 13) return `${n}th`;
  return `${n}${({ 1: 'st', 2: 'nd', 3: 'rd' } as Record<number, string>)[n % 10] ?? 'th'}`;
}

/** The original fixed-interval label. */
export function formatInterval(minutes: number): string {
  const presets: Record<number, string> = {
    60: 'Every hour',
    360: 'Every 6 hours',
    720: 'Every 12 hours',
    1440: 'Every 24 hours',
    10080: 'Every 7 days',
  };
  if (presets[minutes]) return presets[minutes];
  if (minutes % 1440 === 0) {
    const days = minutes / 1440;
    return `Every ${days} days`;
  }
  if (minutes % 60 === 0) {
    const hours = minutes / 60;
    return `Every ${hours} hour${hours === 1 ? '' : 's'}`;
  }
  return `Every ${minutes} min`;
}

/** Which days a weekly schedule runs, in words: "Weekdays", "Weekends", "Mondays", "Mon, Wed, Fri". */
export function describeDays(days: number[]): string {
  const set = [...new Set(days)].sort((a, b) => a - b);
  const key = set.join(',');
  if (key === '0,1,2,3,4,5,6') return 'Every day';
  if (key === '1,2,3,4,5') return 'Weekdays';
  if (key === '0,6') return 'Weekends';
  if (set.length === 1) return `${WEEKDAY_LONG[set[0]]}s`;
  return WEEKDAY_ORDER.filter((d) => set.includes(d))
    .map((d) => WEEKDAY_SHORT[d])
    .join(', ');
}

/** One-line summary for the list: "Weekdays at 02:30 (America/Chicago)". */
export function describeSchedule(row: TimedRow): string {
  const s = row.schedule;
  if (!s) return row.interval_minutes ? formatInterval(row.interval_minutes) : '-';
  const zone = ` (${s.timezone})`;
  const mm = String(s.minute ?? 0).padStart(2, '0');
  switch (s.frequency) {
    case 'hourly': {
      const every = s.every_hours ?? 1;
      return `${every === 1 ? 'Hourly' : `Every ${every} hours`} at :${mm}${zone}`;
    }
    case 'daily':
      return `Daily at ${s.time}${zone}`;
    case 'weekly':
      return `${describeDays(s.days ?? [])} at ${s.time}${zone}`;
    case 'monthly': {
      const day = s.day_of_month ?? 1;
      const clamp = day > 28 ? ' (or the last day)' : '';
      return `Monthly on the ${ordinal(day)}${clamp} at ${s.time}${zone}`;
    }
    default:
      return '-';
  }
}

/** A run time in a given zone: "Mon, Oct 28, 02:30 CDT". */
export function formatInZone(iso: string, timeZone: string): string {
  try {
    return new Intl.DateTimeFormat('en-US', {
      timeZone,
      weekday: 'short',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hourCycle: 'h23',
      timeZoneName: 'short',
    }).format(new Date(iso));
  } catch {
    return iso;
  }
}

/**
 * Time zones for the picker: every zone the browser knows, plus UTC, the
 * viewer's own zone and the schedule's current one (a link name such as
 * Asia/Calcutta isn't in Intl's list but is still valid).
 */
export function timeZoneOptions(...extra: Array<string | null | undefined>): string[] {
  let zones: string[];
  try {
    const intl = Intl as unknown as { supportedValuesOf?: (key: string) => string[] };
    zones = intl.supportedValuesOf ? intl.supportedValuesOf('timeZone') : [];
  } catch {
    zones = [];
  }
  const all = new Set<string>(['UTC', ...zones]);
  for (const z of extra) if (z) all.add(z);
  return [...all].sort((a, b) => (a === 'UTC' ? -1 : b === 'UTC' ? 1 : a.localeCompare(b)));
}
