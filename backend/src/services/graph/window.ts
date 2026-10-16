/**
 * Time windows (pure).
 *
 *   window=24h|7d|30d|90d   [to - preset, to], where `to` is now rounded up to
 *                           the next minute (so one minute's requests share a
 *                           window, and a cache entry, exactly)
 *   around=<ISO time T>     [T - 24 h, T + 1 h], `to` clamped to that rounded now + 1 h:
 *                           the alert entry points pass the alert's created_at,
 *                           which keeps old alerts' graphs about their own time
 *
 * The default is 7d; giving both is a 400. A window is never longer than 90
 * days and always has from < to. Alert and sign-in relations use it; inventory
 * relations (asset <-> IP, host, vulnerability, shipper, endpoint) are current
 * state and are not windowed; findings are every open one plus resolved ones
 * last seen in it. The log relationships of PR 3 use dayRange().
 */
import { badParam } from './errors';
import type { GraphWindow, WindowPreset } from './types';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

export const WINDOW_PRESETS: Record<WindowPreset, number> = {
  '24h': DAY,
  '7d': 7 * DAY,
  '30d': 30 * DAY,
  '90d': 90 * DAY,
};
export const DEFAULT_PRESET: WindowPreset = '7d';
export const AROUND_BEFORE_MS = DAY;
export const AROUND_AFTER_MS = HOUR;
export const MAX_WINDOW_MS = 90 * DAY;
/** The earliest `around` accepted: before SIEMBox existed is a typo. */
const EARLIEST_AROUND = Date.UTC(2000, 0, 1);

/** An ISO 8601 date-time with a time zone (Z or an offset), as JavaScript prints and parses it. */
const ISO_DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:\d{2})$/;

export interface ResolvedWindow extends GraphWindow {
  fromMs: number;
  toMs: number;
}

const ceilMinute = (ms: number) => Math.ceil(ms / MINUTE) * MINUTE;

function resolved(fromMs: number, toMs: number, preset: GraphWindow['preset']): ResolvedWindow {
  return { from: new Date(fromMs).toISOString(), to: new Date(toMs).toISOString(), preset, fromMs, toMs };
}

/** The window a request asks for, or a 400 GRAPH_BAD_PARAM. `now` in epoch ms. */
export function resolveWindow(input: { window?: unknown; around?: unknown }, now: number): ResolvedWindow {
  const { window, around } = input;
  if (window !== undefined && around !== undefined) {
    throw badParam('give window or around, not both');
  }
  const end = ceilMinute(now);
  if (around !== undefined) {
    if (typeof around !== 'string' || around.length > 40 || !ISO_DATE_TIME.test(around)) {
      throw badParam('around must be an ISO 8601 time with a time zone, for example 2026-10-14T09:12:00Z');
    }
    const t = Date.parse(around);
    // Date.parse rolls 2026-02-30 over into March: check the calendar date itself.
    const [year, month, day] = around.slice(0, 10).split('-').map(Number);
    const realDate = month >= 1 && month <= 12 && day >= 1 && day <= new Date(Date.UTC(year, month, 0)).getUTCDate();
    if (!realDate || !Number.isFinite(t) || t < EARLIEST_AROUND || t > end + AROUND_AFTER_MS) {
      throw badParam('around must be a time between 2000 and an hour from now');
    }
    const toMs = Math.min(t + AROUND_AFTER_MS, end + AROUND_AFTER_MS);
    return resolved(t - AROUND_BEFORE_MS, toMs, 'around');
  }
  const preset = window === undefined ? DEFAULT_PRESET : window;
  if (typeof preset !== 'string' || !Object.prototype.hasOwnProperty.call(WINDOW_PRESETS, preset)) {
    throw badParam(`window must be one of ${Object.keys(WINDOW_PRESETS).join(', ')}`);
  }
  const length = Math.min(WINDOW_PRESETS[preset as WindowPreset], MAX_WINDOW_MS);
  return resolved(end - length, end, preset as WindowPreset);
}

/** The UTC days (YYYY-MM-DD) a window touches, first and last: the rollup's ingest days (PR 3). */
export function dayRange(win: Pick<ResolvedWindow, 'fromMs' | 'toMs'>): { first: string; last: string } {
  const day = (ms: number) => new Date(ms).toISOString().slice(0, 10);
  // `to` is exclusive: a window ending at midnight doesn't touch the next day.
  return { first: day(win.fromMs), last: day(Math.max(win.fromMs, win.toMs - 1)) };
}

/** The part of a cache key that names the window. Windows are already minute-aligned for presets. */
export function windowCacheKey(win: GraphWindow): string {
  return `${win.preset}|${win.from}|${win.to}`;
}
