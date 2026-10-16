/**
 * Numbers, ages and times as a wall screen shows them (BIG-DISPLAY.md §5.1):
 * compact above 9,999, relative ages rather than timestamps, HH:MM clocks.
 * Pure: every function takes the time it needs.
 */

/** 2,412 below 10,000; 18.1k, 1.2M above (never more than 4 significant characters). */
export function compact(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return '—';
  const abs = Math.abs(n);
  if (abs < 10_000) return Math.round(n).toLocaleString('en-US');
  const units: Array<[number, string]> = [
    [1e9, 'B'],
    [1e6, 'M'],
    [1e3, 'k'],
  ];
  for (const [size, unit] of units) {
    if (abs >= size) {
      const v = n / size;
      // 18.1k, 181k: one decimal only while it fits in four characters.
      const text = Math.abs(v) < 100 ? (Math.floor(v * 10) / 10).toFixed(1).replace(/\.0$/, '') : String(Math.floor(v));
      return `${text}${unit}`;
    }
  }
  return String(n);
}

/** A duration as a wall screen reads it: "45 s", "12 m", "3 h 12 m", "2 d 4 h". */
export function duration(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} m`;
  const h = Math.floor(m / 60);
  if (h < 24) return m % 60 === 0 ? `${h} h` : `${h} h ${m % 60} m`;
  const d = Math.floor(h / 24);
  return h % 24 === 0 ? `${d} d` : `${d} d ${h % 24} h`;
}

/** How long ago an ISO time was, against `now` (server-corrected ms). */
export function ageOf(iso: string | null | undefined, now: number): string {
  if (!iso) return '—';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '—';
  return duration(now - t);
}

/** HH:MM (24 h, no seconds) in the display's time zone, or the screen's own. */
export function clockText(ms: number, timezone: string | null): string {
  const opts: Intl.DateTimeFormatOptions = { hour: '2-digit', minute: '2-digit', hourCycle: 'h23' };
  try {
    return new Intl.DateTimeFormat('en-GB', timezone ? { ...opts, timeZone: timezone } : opts).format(ms);
  } catch {
    return new Intl.DateTimeFormat('en-GB', opts).format(ms);
  }
}

/** "3 Nov" (for an expiry date), in the screen's time zone. */
export function dayMonth(iso: string | null | undefined): string | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return new Intl.DateTimeFormat('en-GB', { day: 'numeric', month: 'short' }).format(t);
}

/** Change against the previous window: "▲ 8%", "▼ 12%", "= same", or "▲ from 0". */
export function changeText(current: number, previous: number): { text: string; direction: 'up' | 'down' | 'same' } {
  if (previous === 0) return current === 0 ? { text: '= same', direction: 'same' } : { text: '▲ from 0', direction: 'up' };
  const pct = Math.round(((current - previous) / previous) * 100);
  if (pct === 0) return { text: '= same', direction: 'same' };
  return pct > 0 ? { text: `▲ ${compact(pct)}%`, direction: 'up' } : { text: `▼ ${compact(-pct)}%`, direction: 'down' };
}

/** "updated 12 s ago" for the strip's freshness chip. */
export function freshnessText(lastSuccessAt: number | null, now: number): string {
  if (lastSuccessAt === null) return 'connecting';
  return `updated ${duration(now - lastSuccessAt)} ago`;
}

let regionNames: Intl.DisplayNames | null | undefined;

/** A country's English name from its ISO 3166 alpha-2 code (the server sends codes only). */
export function countryName(code: string): string {
  if (regionNames === undefined) {
    try {
      regionNames = new Intl.DisplayNames(['en'], { type: 'region' });
    } catch {
      regionNames = null;
    }
  }
  const upper = code.toUpperCase();
  if (!/^[A-Z]{2}$/.test(upper)) return code;
  try {
    return regionNames?.of(upper) ?? upper;
  } catch {
    return upper;
  }
}

/** "1 source" / "3 sources". */
export function plural(n: number, one: string, many = `${one}s`): string {
  return `${compact(n)} ${n === 1 ? one : many}`;
}
