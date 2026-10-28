/**
 * Endpoint performance (Endpoints page: the list's CPU / memory / disk
 * indicator, the details pane's Performance tab, and the scan policy editor's
 * Performance tab): ranges, formatting, the indicator's levels, the policy
 * settings' form, and the chart series built from the API's points. Pure, so
 * it is unit-tested (endpointPerformance.test.ts).
 *
 * The server stores and buckets the data and evaluates the thresholds
 * (backend/src/services/edr/edrPerformance.ts, perfConfig.ts).
 */

/** First agent release that reports performance (MIN_PERF_AGENT_VERSION on the server). */
export const MIN_PERF_AGENT_VERSION = '0.0.23';
export const PERF_CAPABILITY = 'perf_metrics';

export type PerfRange = '1h' | '6h' | '24h' | '7d' | '30d' | '90d';
export const PERF_RANGES: { value: PerfRange; label: string }[] = [
  { value: '1h', label: '1h' },
  { value: '6h', label: '6h' },
  { value: '24h', label: '24h' },
  { value: '7d', label: '7d' },
  { value: '30d', label: '30d' },
  { value: '90d', label: '90d' },
];

export type PerfMetric = 'cpu' | 'memory' | 'disk';
export type PerfSeverity = 'low' | 'medium' | 'high' | 'critical';
export const PERF_METRICS: { value: PerfMetric; label: string; help: string }[] = [
  { value: 'cpu', label: 'CPU', help: 'Share of all CPUs busy.' },
  { value: 'memory', label: 'Memory', help: 'Memory in use (page cache the OS can reclaim is not counted).' },
  { value: 'disk', label: 'Disk', help: 'Each local filesystem, as df reports it. One alert per mount point.' },
];
export const PERF_SEVERITIES: PerfSeverity[] = ['low', 'medium', 'high', 'critical'];
export const MAX_THRESHOLD_MINUTES = 240;
/** Percentage points below the threshold a value must fall to recover (RECOVERY_MARGIN on the server). */
export const RECOVERY_MARGIN = 3;

export interface PerfThreshold {
  enabled: boolean;
  percent: number;
  minutes: number;
  severity: PerfSeverity;
}
export interface PolicyPerformance {
  metrics: boolean;
  processes: boolean;
  thresholds: Record<PerfMetric, PerfThreshold>;
}

export function defaultPerformance(): PolicyPerformance {
  return {
    metrics: true,
    processes: true,
    thresholds: {
      cpu: { enabled: true, percent: 95, minutes: 10, severity: 'medium' },
      memory: { enabled: true, percent: 95, minutes: 10, severity: 'medium' },
      disk: { enabled: true, percent: 90, minutes: 0, severity: 'high' },
    },
  };
}

/** A deep copy the editor can change (a policy row from an older server has none: the defaults). */
export function performanceForm(p: PolicyPerformance | null | undefined): PolicyPerformance {
  const d = defaultPerformance();
  if (!p) return d;
  return {
    metrics: p.metrics,
    processes: p.processes,
    thresholds: {
      cpu: { ...d.thresholds.cpu, ...p.thresholds?.cpu },
      memory: { ...d.thresholds.memory, ...p.thresholds?.memory },
      disk: { ...d.thresholds.disk, ...p.thresholds?.disk },
    },
  };
}

/** What is wrong with the form, or null (the server checks the same). */
export function performanceProblem(p: PolicyPerformance): string | null {
  for (const m of PERF_METRICS) {
    const t = p.thresholds[m.value];
    if (!t.enabled) continue;
    if (!Number.isFinite(t.percent) || t.percent < 1 || t.percent > 99.9) return `${m.label}: the threshold must be 1–99.9%`;
    if (!Number.isInteger(t.minutes) || t.minutes < 0 || t.minutes > MAX_THRESHOLD_MINUTES) {
      return `${m.label}: "for" must be 0–${MAX_THRESHOLD_MINUTES} minutes`;
    }
  }
  return null;
}

/** One line for a threshold: "> 95% for 10 min (medium)", "> 90% (high)", "off". */
export function describeThreshold(t: PerfThreshold | undefined): string {
  if (!t || !t.enabled) return 'off';
  return `> ${t.percent}%${t.minutes > 1 ? ` for ${t.minutes} min` : ''} (${t.severity})`;
}

/** The policy list's summary of a policy's performance settings. */
export function describePerformance(p: PolicyPerformance | null | undefined): string {
  const f = performanceForm(p);
  if (!f.metrics) return 'off';
  const alerts = PERF_METRICS.filter((m) => f.thresholds[m.value].enabled).map((m) => m.label.toLowerCase());
  return `on${f.processes ? ', processes' : ''}${alerts.length ? `; alerts: ${alerts.join(', ')}` : '; no alerts'}`;
}

/** Whether the agent reports performance (its heartbeat capability). */
export function supportsPerfMetrics(agent: { capabilities?: string[] | null } | null | undefined): boolean {
  return Array.isArray(agent?.capabilities) && agent!.capabilities!.includes(PERF_CAPABILITY);
}

export type Level = 'ok' | 'warn' | 'crit';

/**
 * The indicator's level for a percentage: crit at or above the threshold,
 * warn within 15 points of it, else ok. Without a threshold, 90 / 75.
 */
export function levelOf(pct: number | null | undefined, threshold?: number): Level {
  if (pct === null || pct === undefined || !Number.isFinite(pct)) return 'ok';
  const crit = threshold ?? 90;
  if (pct >= crit) return 'crit';
  if (pct >= crit - 15) return 'warn';
  return 'ok';
}

/** Whether a sample time is recent enough to show as current (3 minutes at a sample a minute). */
export function isFresh(ts: string | null | undefined, now = Date.now()): boolean {
  if (!ts) return false;
  const t = Date.parse(ts);
  return Number.isFinite(t) && now - t < 3 * 60_000;
}

export function formatBytes(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let v = Math.abs(n);
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${(n < 0 ? -v : v).toFixed(i === 0 || v >= 100 ? 0 : 1)} ${units[i]}`;
}

/** Bytes per second as bits per second ("12.3 Mbit/s"), the unit network links are sold in. */
export function formatRate(bytesPerSec: number | null | undefined): string {
  if (bytesPerSec === null || bytesPerSec === undefined || !Number.isFinite(bytesPerSec)) return '—';
  const units = ['bit/s', 'kbit/s', 'Mbit/s', 'Gbit/s', 'Tbit/s'];
  let v = bytesPerSec * 8;
  let i = 0;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  return `${v.toFixed(i === 0 || v >= 100 ? 0 : 1)} ${units[i]}`;
}

export function formatPct(v: number | null | undefined, digits = 0): string {
  return v === null || v === undefined || !Number.isFinite(v) ? '—' : `${v.toFixed(digits)}%`;
}

export function formatUptime(sec: number | null | undefined): string {
  if (sec === null || sec === undefined || !Number.isFinite(sec) || sec < 0) return '—';
  const d = Math.floor(sec / 86_400);
  const h = Math.floor((sec % 86_400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

// ---- Chart series ------------------------------------------------------------------

export interface PerfPoint {
  t: string;
  cpu: number | null;
  cpu_max: number | null;
  mem_used: number | null;
  mem_total: number | null;
  mem_pct: number | null;
  swap_used: number | null;
  swap_total: number | null;
  load1: number | null;
  load5: number | null;
  load15: number | null;
  samples: number;
}
export interface DiskSeries {
  mount: string;
  points: { t: string; pct: number | null; pct_max: number | null }[];
}
export interface NetSeries {
  iface: string;
  points: { t: string; rx: number | null; tx: number | null }[];
}

/** {x: ms, y} for chart.js's linear time axis. */
export interface XY {
  x: number;
  y: number | null;
}

/**
 * Points as {x, y}, with a null inserted wherever consecutive points are more
 * than two buckets apart, so the line breaks across a gap (the agent was off)
 * instead of drawing a straight line over it.
 */
export function toXY<T extends { t: string }>(points: T[], pick: (p: T) => number | null, bucketSeconds: number): XY[] {
  const out: XY[] = [];
  let prev: number | null = null;
  for (const p of points) {
    const x = Date.parse(p.t);
    if (prev !== null && x - prev > bucketSeconds * 2000) out.push({ x: prev + bucketSeconds * 1000, y: null });
    out.push({ x, y: pick(p) });
    prev = x;
  }
  return out;
}

/** Swap use as a percentage of the swap total (null without swap). */
export function swapPct(p: Pick<PerfPoint, 'swap_used' | 'swap_total'>): number | null {
  return p.swap_total && p.swap_total > 0 && p.swap_used !== null ? Math.round((p.swap_used / p.swap_total) * 1000) / 10 : null;
}

/** Whether any point carries a load average (Windows has none). */
export function hasLoad(points: PerfPoint[]): boolean {
  return points.some((p) => p.load1 !== null);
}

/** Tick label for a time axis: time of day within two days, else the date. */
export function axisLabel(ms: number, rangeMs: number): string {
  const d = new Date(ms);
  const pad = (n: number) => String(n).padStart(2, '0');
  if (rangeMs <= 2 * 86_400_000) return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  return `${d.toLocaleString(undefined, { month: 'short' })} ${d.getDate()}`;
}

/**
 * The time axis' tick spacing for a range, so ticks fall on round times
 * (multiples of it since the epoch: whole hours, whole UTC days) instead of
 * wherever chart.js's even split lands.
 */
export function tickStep(rangeMs: number): number {
  const steps = [5, 10, 15, 30, 60, 120, 180, 240, 360, 720, 1440, 2880, 7 * 1440, 14 * 1440].map((m) => m * 60_000);
  return steps.find((s) => rangeMs / s <= 7) ?? steps[steps.length - 1];
}

export const RANGE_MS: Record<PerfRange, number> = {
  '1h': 3_600_000,
  '6h': 6 * 3_600_000,
  '24h': 86_400_000,
  '7d': 7 * 86_400_000,
  '30d': 30 * 86_400_000,
  '90d': 90 * 86_400_000,
};

/** A fixed palette of distinguishable series colours (disks, interfaces), cycled. */
export const SERIES_COLORS = ['#409eff', '#67c23a', '#e6a23c', '#f56c6c', '#909399', '#9b59b6', '#16a085', '#d35400'];
export function seriesColor(i: number): string {
  return SERIES_COLORS[i % SERIES_COLORS.length];
}
