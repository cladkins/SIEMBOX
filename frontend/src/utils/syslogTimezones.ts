/**
 * Helpers for the Direct Syslog Sources timezone setting (Shippers page).
 *
 * An RFC 3164 header ("Nov  3 12:17:04") has no zone, so SIEMBox reads it in
 * the sender's configured timezone: the one set for its source IP, else the
 * default, else UTC (backend/src/services/syslog/sourceTimezone.ts). Pure, so
 * `npm run test:unit` covers it.
 */

export interface SyslogTimezoneSettings {
  default_timezone: string;
  sources: Array<{ source_ip: string; timezone: string; updated_at?: string }>;
}

/** Zones most homelabs want, listed first in the picker. */
export const COMMON_TIMEZONES = [
  'UTC',
  'America/New_York',
  'America/Chicago',
  'America/Denver',
  'America/Phoenix',
  'America/Los_Angeles',
  'Europe/London',
  'Europe/Berlin',
  'Asia/Tokyo',
  'Australia/Sydney',
] as const;

/**
 * Every IANA zone this browser knows, common ones first, then the rest
 * sorted, no duplicates. Falls back to the common list on a browser without
 * Intl.supportedValuesOf.
 */
export function timezoneOptions(supported?: readonly string[]): string[] {
  const all = supported ?? supportedTimezones();
  const rest = all.filter((tz) => !(COMMON_TIMEZONES as readonly string[]).includes(tz)).sort();
  return [...COMMON_TIMEZONES, ...rest];
}

function supportedTimezones(): string[] {
  const intl = Intl as unknown as { supportedValuesOf?: (key: string) => string[] };
  try {
    return intl.supportedValuesOf ? intl.supportedValuesOf('timeZone') : [];
  } catch {
    return [];
  }
}

/** "::ffff:10.0.0.1" -> "10.0.0.1", lowercased: the key the backend stores. */
export function normalizeSourceIp(ip: string): string {
  const trimmed = ip.trim().toLowerCase();
  return trimmed.startsWith('::ffff:') && trimmed.includes('.') ? trimmed.slice(7) : trimmed;
}

/** source IP -> timezone set for it (only sources with their own setting). */
export function timezoneMap(settings: SyslogTimezoneSettings | null): Map<string, string> {
  const map = new Map<string, string>();
  for (const s of settings?.sources ?? []) map.set(normalizeSourceIp(s.source_ip), s.timezone);
  return map;
}

/**
 * Offset of `tz` from UTC right now, as "UTC-6" / "UTC+5:30" / "UTC", for the
 * picker's labels. Empty when the browser does not know the zone.
 */
export function utcOffsetLabel(tz: string, at: Date = new Date()): string {
  try {
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      hourCycle: 'h23',
      year: 'numeric',
      month: 'numeric',
      day: 'numeric',
      hour: 'numeric',
      minute: 'numeric',
    }).formatToParts(at);
    const get = (type: string) => Number(parts.find((p) => p.type === type)?.value);
    const asUtc = Date.UTC(get('year'), get('month') - 1, get('day'), get('hour'), get('minute'));
    const minutes = Math.round((asUtc - Math.floor(at.getTime() / 60000) * 60000) / 60000);
    if (minutes === 0) return 'UTC';
    const sign = minutes < 0 ? '-' : '+';
    const h = Math.floor(Math.abs(minutes) / 60);
    const m = Math.abs(minutes) % 60;
    return `UTC${sign}${h}${m ? `:${String(m).padStart(2, '0')}` : ''}`;
  } catch {
    return '';
  }
}
