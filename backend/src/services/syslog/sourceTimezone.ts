/**
 * Which timezone a syslog sender's header timestamps are in.
 *
 * An RFC 3164 header ("Nov  3 12:17:04") carries no zone and no year. The
 * parser used to build it with `new Date(year, month, ...)`, which is the
 * BACKEND's local time (UTC in the image), so a UniFi AP or Proxmox host
 * logging in America/Chicago had every event stored 6 hours early: received
 * 18:17 UTC, stored 12:17 UTC.
 *
 * Now a zoneless header is read in the sender's configured timezone: a
 * per-source setting keyed by source IP (table syslog_source_timezones), else
 * the system setting syslog_default_timezone, else UTC. Shippers (1.5.0+)
 * always send UTC. RFC 5424 timestamps carry their own offset and are not
 * affected.
 *
 * Settings are cached in memory and re-read every REFRESH_MS, so a change
 * applies within a minute without a restart (or at once via invalidate()).
 */
import { query } from '../../config/database';
import { logger } from '../../utils/logger';

export const DEFAULT_TIMEZONE = 'UTC';
const REFRESH_MS = 60_000;

/** True for an IANA zone name (or "UTC") this runtime knows. */
export function isValidTimezone(tz: unknown): tz is string {
  if (typeof tz !== 'string' || tz.length === 0 || tz.length > 64) return false;
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}

/** A source IP as the listener saw it, normalized ("::ffff:10.0.0.1" -> "10.0.0.1"). */
export function normalizeSourceIp(ip: string): string {
  const trimmed = ip.trim().toLowerCase();
  return trimmed.startsWith('::ffff:') && trimmed.includes('.') ? trimmed.slice(7) : trimmed;
}

const formatters = new Map<string, Intl.DateTimeFormat>();
function formatter(tz: string): Intl.DateTimeFormat {
  let f = formatters.get(tz);
  if (!f) {
    f = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      hourCycle: 'h23',
      year: 'numeric',
      month: 'numeric',
      day: 'numeric',
      hour: 'numeric',
      minute: 'numeric',
      second: 'numeric',
    });
    formatters.set(tz, f);
  }
  return f;
}

/** Offset of `tz` from UTC at instant `utcMs`, in ms (Chicago in November: -6 h). */
export function zoneOffsetMs(tz: string, utcMs: number): number {
  const parts: Record<string, number> = {};
  for (const p of formatter(tz).formatToParts(new Date(utcMs))) {
    if (p.type !== 'literal') parts[p.type] = Number(p.value);
  }
  const asUtc = Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second);
  return asUtc - Math.floor(utcMs / 1000) * 1000;
}

/**
 * The UTC instant of a wall-clock time in `tz`. In a DST gap or overlap the
 * result is one of the two plausible instants (an hour's ambiguity a zoneless
 * header cannot resolve).
 */
export function wallClockToUtc(
  tz: string,
  year: number,
  month0: number,
  day: number,
  hour: number,
  minute: number,
  second: number,
  ms = 0
): Date {
  const guess = Date.UTC(year, month0, day, hour, minute, second, ms);
  if (tz === 'UTC') return new Date(guess);
  let utc = guess - zoneOffsetMs(tz, guess);
  // Re-check at the corrected instant (the offset can differ across a DST change).
  const second2 = zoneOffsetMs(tz, utc);
  utc = guess - second2;
  return new Date(utc);
}

/**
 * The instant of a zoneless "Mon DD HH:MM:SS" header in `tz`. The year is the
 * sender's current year, or the previous one when that would put the event
 * more than a day in the future (a December line read in January).
 */
export function bsdTimestampToUtc(
  tz: string,
  month0: number,
  day: number,
  hour: number,
  minute: number,
  second: number,
  now: Date = new Date()
): Date {
  const yearNow = new Date(now.getTime() + zoneOffsetMs(tz, now.getTime())).getUTCFullYear();
  let result = wallClockToUtc(tz, yearNow, month0, day, hour, minute, second);
  if (result.getTime() - now.getTime() > 24 * 3600_000) {
    result = wallClockToUtc(tz, yearNow - 1, month0, day, hour, minute, second);
  }
  return result;
}

/** Per-source timezone settings, cached. */
class SourceTimezones {
  private bySource = new Map<string, string>();
  private fallback = DEFAULT_TIMEZONE;
  private loadedAt = 0;
  private loading: Promise<void> | null = null;

  /** The timezone for a sender. Never blocks on the database: serves the cache and refreshes behind it. */
  forSource(sourceIp: string | null | undefined): string {
    if (Date.now() - this.loadedAt > REFRESH_MS) void this.refresh();
    if (!sourceIp) return this.fallback;
    return this.bySource.get(normalizeSourceIp(sourceIp)) ?? this.fallback;
  }

  /** Re-read the settings now (after a change through the API). */
  invalidate(): Promise<void> {
    this.loadedAt = 0;
    return this.refresh();
  }

  refresh(): Promise<void> {
    this.loading ??= (async () => {
      try {
        const rows = (await query(`SELECT source_ip, timezone FROM syslog_source_timezones`)).rows;
        const next = new Map<string, string>();
        for (const r of rows) if (isValidTimezone(r.timezone)) next.set(normalizeSourceIp(String(r.source_ip)), r.timezone);
        const d = (await query(`SELECT value FROM system_settings WHERE key = 'syslog_default_timezone'`)).rows[0]?.value;
        this.bySource = next;
        this.fallback = isValidTimezone(d) ? d : DEFAULT_TIMEZONE;
      } catch (error) {
        logger.debug('Could not load syslog source timezones; keeping the cached ones', {
          error: error instanceof Error ? error.message : String(error),
        });
      } finally {
        this.loadedAt = Date.now();
        this.loading = null;
      }
    })();
    return this.loading;
  }

  /** Test seam. */
  set(map: Record<string, string>, fallback = DEFAULT_TIMEZONE): void {
    this.bySource = new Map(Object.entries(map).map(([ip, tz]) => [normalizeSourceIp(ip), tz]));
    this.fallback = fallback;
    this.loadedAt = Date.now() + 365 * 24 * 3600_000;
  }
}

export const sourceTimezones = new SourceTimezones();
