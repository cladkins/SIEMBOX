/**
 * Shared plumbing for the Shippers page's raw_logs summaries (unknown sources,
 * direct syslog sources). Both are aggregate queries over a hot, potentially
 * huge table that a page load must never be allowed to pile up or outrun:
 *
 *   - runReadOnly(): one pooled client, READ ONLY transaction, LOCAL statement
 *     timeout -- a slow run is cancelled server-side instead of outliving the
 *     HTTP request that asked for it.
 *   - createSnapshotCache(): short single-flight cache with a failure cooldown,
 *     so concurrent/repeated page loads share one query and a struggling
 *     database is not hammered; a stale result is preferred over an error.
 *
 * Extracted unchanged from unknownSources.ts (whose tests still cover it).
 */

/** Minimal slice of a pg client this module needs (so it can be faked in tests). */
export interface QueryClient {
  query(text: string, params?: any[]): Promise<{ rows: any[] }>;
  release(err?: Error | boolean): void;
}

/**
 * Run `sql` on a dedicated pooled client inside a READ ONLY transaction with a
 * LOCAL statement timeout (set_config is parameterizable; SET LOCAL is not).
 */
export async function runReadOnly(
  acquire: () => Promise<QueryClient>,
  sql: string,
  params: any[],
  timeoutMs: number
): Promise<any[]> {
  const client = await acquire();
  let releaseArg: Error | undefined;
  try {
    await client.query('BEGIN READ ONLY');
    await client.query("SELECT set_config('statement_timeout', $1, true)", [String(Math.trunc(timeoutMs))]);
    const result = await client.query(sql, params);
    await client.query('COMMIT');
    return result.rows;
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch (rollbackErr) {
      // The connection is in an unknown state -- have the pool discard it.
      releaseArg = rollbackErr instanceof Error ? rollbackErr : new Error(String(rollbackErr));
    }
    throw err;
  } finally {
    client.release(releaseArg);
  }
}

export interface SnapshotCacheDeps<T> {
  fetch: () => Promise<T>;
  now: () => number;
  log: { warn: (msg: string, meta?: unknown) => void; error: (msg: string, meta?: unknown) => void };
  /** Prefix for log messages, e.g. "unknown-sources". */
  label: string;
}

export interface SnapshotCacheOptions {
  ttlMs: number;
  failureCooldownMs: number;
}

export interface SnapshotCache<T> {
  /** Current value (cached; concurrent callers share one fetch). */
  get(): Promise<T>;
  /** Drop the cached value so the next get() re-fetches. */
  invalidate(): void;
}

export function createSnapshotCache<T>(deps: SnapshotCacheDeps<T>, opts: SnapshotCacheOptions): SnapshotCache<T> {
  let cache: { at: number; generation: number; value: T } | null = null;
  let generation = 0;
  let inflight: Promise<T> | null = null;
  let lastFailure: { at: number; error: unknown } | null = null;

  async function refresh(): Promise<T> {
    // A result computed before an invalidate() may already be out of date, so
    // it is returned to the callers that were waiting on it but never cached.
    const startedGeneration = generation;
    try {
      const value = await deps.fetch();
      if (startedGeneration === generation) {
        cache = { at: deps.now(), generation, value };
      }
      lastFailure = null;
      return value;
    } catch (error) {
      lastFailure = { at: deps.now(), error };
      if (cache) {
        deps.log.warn(`${deps.label}: refresh failed, serving the previous result`, {
          error: error instanceof Error ? error.message : String(error),
        });
        return cache.value;
      }
      deps.log.error(`${deps.label}: query failed`, {
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  }

  return {
    async get(): Promise<T> {
      const t = deps.now();
      if (cache && cache.generation === generation && t - cache.at < opts.ttlMs) {
        return cache.value;
      }
      if (inflight) return inflight;
      if (lastFailure && t - lastFailure.at < opts.failureCooldownMs) {
        if (cache) return cache.value; // stale beats an error while the database recovers
        throw lastFailure.error; // fail fast rather than start another doomed scan
      }
      const run = refresh();
      inflight = run;
      // Cleared from a chained handler (always a later microtask) rather than a
      // `finally` inside refresh(), so a fetcher that throws synchronously can't
      // clear `inflight` before it has been assigned and leave it pinned to a
      // rejected promise.
      const clear = () => {
        if (inflight === run) inflight = null;
      };
      run.then(clear, clear);
      return run;
    },
    invalidate(): void {
      generation++;
    },
  };
}

/** Postgres query_canceled -- what statement_timeout raises. */
export function isStatementTimeout(err: unknown): boolean {
  return (err as { code?: string } | null)?.code === '57014';
}

/**
 * The database is busy rather than broken: our statement timeout fired, or the
 * pool could not hand out a connection in time. Callers should answer 503 (try
 * again shortly), not 500.
 */
export function isDatabaseBusy(err: unknown): boolean {
  if (isStatementTimeout(err)) return true;
  const message = err instanceof Error ? err.message : '';
  return /timeout exceeded when trying to connect/i.test(message);
}
