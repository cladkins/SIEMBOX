/**
 * A scan policy's performance settings (edr_scan_policies.performance,
 * migration 055): whether its endpoints report machine performance, whether
 * they sample their top processes, and the alert thresholds the server
 * evaluates against their samples (services/edr/edrPerformance.ts).
 *
 *   { "metrics": true, "processes": true,
 *     "thresholds": { "cpu":    { "enabled", "percent", "minutes", "severity" },
 *                     "memory": { ... }, "disk": { ... } } }
 *
 * `minutes` is how long the value must stay above `percent` before an alert
 * opens (0 = the newest sample alone; disks are usually 0, CPU sustained).
 * Pure: no database access here.
 */

export const PERF_METRICS = ['cpu', 'memory', 'disk'] as const;
export type PerfMetric = (typeof PERF_METRICS)[number];
export const PERF_SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;
export type PerfSeverity = (typeof PERF_SEVERITIES)[number];

/** Longest "sustained for" a threshold may ask for, minutes (raw samples cover it many times over). */
export const MAX_THRESHOLD_MINUTES = 240;

export interface PerfThreshold {
  enabled: boolean;
  /** Alert when the value is above this percentage. */
  percent: number;
  /** ...for at least this many minutes (0 = the newest sample). */
  minutes: number;
  severity: PerfSeverity;
}

export interface PolicyPerformance {
  /** Endpoints report performance samples at all. */
  metrics: boolean;
  /** Endpoints also sample their top processes. */
  processes: boolean;
  thresholds: Record<PerfMetric, PerfThreshold>;
}

export const BUILTIN_DEFAULT_PERFORMANCE: PolicyPerformance = {
  metrics: true,
  processes: true,
  thresholds: {
    cpu: { enabled: true, percent: 95, minutes: 10, severity: 'medium' },
    memory: { enabled: true, percent: 95, minutes: 10, severity: 'medium' },
    disk: { enabled: true, percent: 90, minutes: 0, severity: 'high' },
  },
};

function isObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

export function normalizeThreshold(input: unknown, label: string): PerfThreshold {
  if (!isObject(input)) throw new Error(`${label} must be an object`);
  if (typeof input.enabled !== 'boolean') throw new Error(`${label}.enabled must be a boolean`);
  const pct = input.percent;
  if (typeof pct !== 'number' || !Number.isFinite(pct) || pct < 1 || pct > 99.9) {
    throw new Error(`${label}.percent must be a number from 1 to 99.9`);
  }
  const min = input.minutes;
  if (!Number.isInteger(min) || (min as number) < 0 || (min as number) > MAX_THRESHOLD_MINUTES) {
    throw new Error(`${label}.minutes must be an integer from 0 to ${MAX_THRESHOLD_MINUTES}`);
  }
  if (typeof input.severity !== 'string' || !(PERF_SEVERITIES as readonly string[]).includes(input.severity)) {
    throw new Error(`${label}.severity must be one of: ${PERF_SEVERITIES.join(', ')}`);
  }
  return { enabled: input.enabled, percent: Math.round(pct * 10) / 10, minutes: min as number, severity: input.severity as PerfSeverity };
}

/** A policy's performance settings, validated, in a fixed key order. Throws an Error naming the problem. */
export function normalizePerformance(input: unknown): PolicyPerformance {
  if (!isObject(input)) throw new Error('performance must be an object');
  if (typeof input.metrics !== 'boolean') throw new Error('performance.metrics must be a boolean');
  if (typeof input.processes !== 'boolean') throw new Error('performance.processes must be a boolean');
  const th = input.thresholds;
  if (!isObject(th)) throw new Error(`performance.thresholds must be an object with: ${PERF_METRICS.join(', ')}`);
  for (const k of Object.keys(th)) {
    if (!(PERF_METRICS as readonly string[]).includes(k)) throw new Error(`performance.thresholds: unknown metric "${k.slice(0, 32)}"`);
  }
  const thresholds = {} as Record<PerfMetric, PerfThreshold>;
  for (const m of PERF_METRICS) {
    if (th[m] === undefined) throw new Error(`performance.thresholds.${m} is required`);
    thresholds[m] = normalizeThreshold(th[m], `performance.thresholds.${m}`);
  }
  return { metrics: input.metrics, processes: input.processes, thresholds };
}

/** A stored value, re-validated; a missing or invalid one reads as the built-in defaults. */
export function storedPerformance(raw: unknown): PolicyPerformance {
  if (raw === null || raw === undefined) return BUILTIN_DEFAULT_PERFORMANCE;
  try {
    return normalizePerformance(raw);
  } catch {
    return BUILTIN_DEFAULT_PERFORMANCE;
  }
}

/** Agent cadence (seconds). The agent clamps these too. */
export const PERF_SAMPLE_SECONDS = 60;
export const PERF_SEND_SECONDS = 60;
export const PERF_PROCESS_SECONDS = 300;
export const PERF_TOP_PROCESSES = 10;

/** The agent config's `performance` for an endpoint whose policy has these settings. */
export function agentPerformanceConfig(p: PolicyPerformance) {
  return {
    enabled: p.metrics,
    processes: p.metrics && p.processes,
    sample_interval_seconds: PERF_SAMPLE_SECONDS,
    send_interval_seconds: PERF_SEND_SECONDS,
    process_interval_seconds: PERF_PROCESS_SECONDS,
    top_processes: PERF_TOP_PROCESSES,
  };
}
