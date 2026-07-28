/**
 * Recurring-job registry.
 *
 * The Admin dashboard's "Background Jobs" panel used to read one table
 * (vulnerability_scans), so it showed scans and nothing else — the periodic
 * services that keep the system healthy (retention cleanup, auto-discovery,
 * the scheduler itself, ingestion health, threat-feed refresh, YARA refresh)
 * were invisible. A silently dead timer looked identical to an idle one.
 *
 * These jobs have no rows of their own, so this is an in-memory registry each
 * one reports into. State resets on restart — deliberately: it describes THIS
 * process's timers, and "never run since boot" is exactly the signal an
 * operator needs when a job is wedged. Durable history stays in the per-scan
 * tables and, for failures, in application_errors.
 */

export type RecurringJobStatus =
  | 'idle' // registered, not run yet in this process
  | 'running'
  | 'ok'
  | 'failed'
  | 'skipped' // ran, but declined to do work (disabled in settings, nothing due)
  | 'disabled'; // not scheduled at all in this process

export interface RecurringJob {
  key: string;
  name: string;
  description: string;
  /** Scheduling period in ms; null when the job is not scheduled. */
  intervalMs: number | null;
  status: RecurringJobStatus;
  lastRunAt: string | null;
  lastSuccessAt: string | null;
  lastDurationMs: number | null;
  /** One-line outcome of the last run, e.g. "deleted 1,204 rows". */
  lastResult: string | null;
  lastError: string | null;
  /** Best-effort next fire time, derived from lastRunAt + intervalMs. */
  nextRunAt: string | null;
  runs: number;
  failures: number;
}

const jobs = new Map<string, RecurringJob>();

/**
 * Declare a job. Called at startup — including when the job is disabled, so the
 * dashboard can show "disabled" rather than omitting it (an absent row is
 * indistinguishable from a missing feature).
 */
export function registerRecurringJob(params: {
  key: string;
  name: string;
  description: string;
  intervalMs?: number | null;
  enabled?: boolean;
}): void {
  const existing = jobs.get(params.key);
  const intervalMs = params.enabled === false ? null : params.intervalMs ?? null;

  jobs.set(params.key, {
    key: params.key,
    name: params.name,
    description: params.description,
    intervalMs,
    status: params.enabled === false ? 'disabled' : existing?.status ?? 'idle',
    lastRunAt: existing?.lastRunAt ?? null,
    lastSuccessAt: existing?.lastSuccessAt ?? null,
    lastDurationMs: existing?.lastDurationMs ?? null,
    lastResult: existing?.lastResult ?? null,
    lastError: existing?.lastError ?? null,
    nextRunAt: null,
    runs: existing?.runs ?? 0,
    failures: existing?.failures ?? 0,
  });
}

/** Update the scheduling period after a job reschedules itself at runtime. */
export function setRecurringJobInterval(key: string, intervalMs: number | null): void {
  const job = jobs.get(key);
  if (job) job.intervalMs = intervalMs;
}

function computeNextRun(job: RecurringJob): string | null {
  if (!job.intervalMs || !job.lastRunAt) return null;
  return new Date(new Date(job.lastRunAt).getTime() + job.intervalMs).toISOString();
}

/**
 * Run `fn` as a tracked cycle of `key`. Returns whatever `fn` returns; a string
 * return is recorded as the run's one-line result. Never swallows: the error is
 * recorded and re-thrown so existing handling (logging, ErrorLogService) is
 * unchanged.
 */
export async function trackJobRun<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const job = jobs.get(key);
  if (!job) return fn();

  const startedAt = Date.now();
  job.status = 'running';
  job.lastRunAt = new Date(startedAt).toISOString();
  job.runs += 1;

  try {
    const result = await fn();
    job.status = 'ok';
    job.lastDurationMs = Date.now() - startedAt;
    job.lastSuccessAt = new Date().toISOString();
    job.lastResult = typeof result === 'string' ? result : null;
    job.lastError = null;
    return result;
  } catch (error) {
    job.status = 'failed';
    job.failures += 1;
    job.lastDurationMs = Date.now() - startedAt;
    job.lastError = error instanceof Error ? error.message : String(error);
    throw error;
  }
}

/**
 * Attach a one-line outcome to the run that just finished, without changing its
 * status. For jobs whose real work happens after the tracked call returns (the
 * scan dispatcher queries for due work, then dispatches it).
 */
export function markJobResult(key: string, result: string): void {
  const job = jobs.get(key);
  if (job) job.lastResult = result;
}

/**
 * Record that a cycle ran but intentionally did no work (feature switched off in
 * settings, nothing due). Distinct from success so "enabled but idle" and
 * "disabled in settings" don't look the same.
 */
export function markJobSkipped(key: string, reason: string): void {
  const job = jobs.get(key);
  if (!job) return;
  job.status = 'skipped';
  job.lastRunAt = new Date().toISOString();
  job.lastResult = reason;
  job.lastError = null;
}

/** Snapshot of every registered job, next-run times resolved. */
export function listRecurringJobs(): RecurringJob[] {
  return Array.from(jobs.values())
    .map((job) => ({ ...job, nextRunAt: computeNextRun(job) }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

/** Test helper — drops all registrations. */
export function resetRecurringJobs(): void {
  jobs.clear();
}
