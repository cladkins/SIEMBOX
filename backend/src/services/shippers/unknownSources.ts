/**
 * "Unknown sources": shipper IDs that appear in raw_logs but match no registered
 * log_shipper (the ghost-shipper / adopt-or-revoke banner on the Shippers page).
 *
 * The original query scanned the ENTIRE raw_logs table on every page load: a
 * per-row NOT EXISTS over all ~millions of shipper-tagged rows plus three
 * sort-based ARRAY_AGG(DISTINCT ...) aggregates. On a 2.5M-row table that is
 * ~6 s, ~19 s with one chatty ghost, and far worse on a bloated table -- past
 * the browser's 10 s timeout. The browser gives up but Postgres keeps running
 * the query (holding a pool connection and thrashing I/O), so every visit left
 * another heavy scan behind and starved log ingestion of connections.
 *
 * This module fixes that three ways:
 *
 *   1. A cheaper query (UNKNOWN_SOURCES_SQL below). Distinct shipper IDs are
 *      enumerated by a recursive "skip scan" that probes idx_raw_logs_shipper_id
 *      once per distinct id (cost ~ number of shippers, not number of rows);
 *      the known/unknown anti-join then runs on that handful of ids; and only
 *      the UNKNOWN ids are aggregated, over a recent window. Measured on 2.5M
 *      rows: ~0.6 s vs ~6 s; with a ~1M-row ghost on 3.4M rows: ~1.8 s vs ~19 s.
 *   2. A statement timeout (below the client's 10 s) so a slow run can never
 *      outlive the request that asked for it.
 *   3. A short single-flight cache with a failure cooldown, so concurrent or
 *      repeated page loads share one scan instead of stacking them, and a
 *      struggling database is not hammered. A stale result is preferred over an
 *      error while the database is busy.
 *
 * Semantics vs. the old query: log_count / first_seen / last_seen and the
 * source_ips / hostnames / app_names lists now cover the last
 * UNKNOWN_SOURCES_WINDOW_HOURS (24 h), and an unknown id with no rows in that
 * window is no longer listed. Results for ids active inside the window are
 * otherwise identical (verified against the old query on seeded data).
 */
import { getClient } from '../../config/database';
import { logger } from '../../utils/logger';

/** Window over which unknown sources are aggregated and considered "current". */
export const UNKNOWN_SOURCES_WINDOW_HOURS = 24;
/** Statement timeout for the query -- kept under the frontend's 10 s request timeout. */
export const UNKNOWN_SOURCES_TIMEOUT_MS = 8000;
/** How long a successful result is served without re-querying. */
export const UNKNOWN_SOURCES_CACHE_TTL_MS = 30_000;
/** After a failed run, re-use the stale result (or fail fast) for this long instead of retrying. */
export const UNKNOWN_SOURCES_FAILURE_COOLDOWN_MS = 20_000;
/**
 * Upper bound on distinct shipper ids examined. Generous (real fleets are tens
 * to hundreds of shippers) so no legitimate ghost is ever missed; it exists so
 * a sender spraying random shipper tags cannot turn the skip scan into an
 * unbounded loop.
 */
export const UNKNOWN_SOURCES_MAX_DISTINCT_IDS = 5000;

/**
 * $1 = window hours (int), $2 = max distinct ids (int).
 *
 * shipper_hashes is MATERIALIZED on purpose: it guarantees the api_key ~ hex
 * filter runs before decode(), so one malformed api_key can never abort the
 * whole query (issue #17) regardless of how the planner would otherwise inline
 * the CTE.
 */
export const UNKNOWN_SOURCES_SQL = `
  WITH RECURSIVE shipper_hashes AS MATERIALIZED (
    SELECT
      LOWER(SUBSTRING(MD5(decode(api_key, 'hex')), 1, 8)) AS md5_id,
      LOWER(SUBSTRING(ENCODE(SHA256(decode(api_key, 'hex')), 'hex'), 1, 8)) AS sha256_id,
      LOWER(SUBSTRING(http_push_key_hash, 1, 8)) AS http_push_id
    FROM log_shippers
    WHERE api_key ~ '^([0-9a-fA-F]{2})+$'
  ),
  ids(shipper_id, n) AS (
    (SELECT shipper_id, 1 FROM raw_logs WHERE shipper_id IS NOT NULL ORDER BY shipper_id LIMIT 1)
    UNION ALL
    SELECT (SELECT r.shipper_id FROM raw_logs r WHERE r.shipper_id > ids.shipper_id ORDER BY r.shipper_id LIMIT 1),
           ids.n + 1
    FROM ids
    WHERE ids.shipper_id IS NOT NULL AND ids.n < $2
  ),
  unknown_ids AS (
    SELECT i.shipper_id
    FROM ids i
    WHERE i.shipper_id IS NOT NULL
      AND NOT EXISTS (
        SELECT 1 FROM shipper_hashes sh
        WHERE LOWER(i.shipper_id) = sh.md5_id
           OR LOWER(i.shipper_id) = sh.sha256_id
           OR LOWER(i.shipper_id) = sh.http_push_id
      )
  )
  SELECT u.shipper_id, s.log_count, s.first_seen, s.last_seen, s.source_ips, s.hostnames, s.app_names,
         (SELECT COUNT(*) FROM ids WHERE shipper_id IS NOT NULL) AS ids_enumerated
  FROM unknown_ids u
  CROSS JOIN LATERAL (
    SELECT
      COUNT(*) AS log_count,
      MIN(rl.created_at) AS first_seen,
      MAX(rl.created_at) AS last_seen,
      COALESCE(ARRAY_AGG(DISTINCT rl.source_ip) FILTER (WHERE rl.source_ip IS NOT NULL), '{}') AS source_ips,
      COALESCE(ARRAY_AGG(DISTINCT rl.hostname)  FILTER (WHERE rl.hostname  IS NOT NULL), '{}') AS hostnames,
      COALESCE(ARRAY_AGG(DISTINCT rl.app_name)  FILTER (WHERE rl.app_name  IS NOT NULL), '{}') AS app_names
    FROM raw_logs rl
    WHERE rl.shipper_id = u.shipper_id
      AND rl.created_at >= NOW() - ($1 * INTERVAL '1 hour')
  ) s
  WHERE s.log_count > 0
  ORDER BY s.last_seen DESC
`;

export interface UnknownSourceRow {
  shipper_id: string;
  log_count: string | number;
  first_seen: Date | string;
  last_seen: Date | string;
  source_ips: Array<string | null> | null;
  hostnames: Array<string | null> | null;
  app_names: Array<string | null> | null;
  ids_enumerated?: string | number;
}

export interface UnknownSource {
  shipper_id: string;
  log_count: number;
  first_seen: Date | string;
  last_seen: Date | string;
  source_ips: string[];
  hostnames: string[];
  app_names: string[];
}

/** Minimal slice of a pg client this module needs (so it can be faked in tests). */
export interface QueryClient {
  query(text: string, params?: any[]): Promise<{ rows: any[] }>;
  release(err?: Error | boolean): void;
}

const nonNull = (v: string | null): v is string => v !== null && v !== undefined;

function toUnknownSource(row: UnknownSourceRow): UnknownSource {
  return {
    shipper_id: row.shipper_id,
    log_count: parseInt(String(row.log_count), 10),
    first_seen: row.first_seen,
    last_seen: row.last_seen,
    source_ips: (row.source_ips ?? []).filter(nonNull),
    hostnames: (row.hostnames ?? []).filter(nonNull),
    app_names: (row.app_names ?? []).filter(nonNull),
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

/**
 * Run the unknown-sources query on a dedicated pooled client inside a
 * READ ONLY transaction with a LOCAL statement timeout (set_config is
 * parameterizable; SET LOCAL is not). `acquire` is injected for tests.
 */
export function createDbFetcher(acquire: () => Promise<QueryClient>) {
  return async function fetchRows(windowHours: number, maxIds: number, timeoutMs: number): Promise<UnknownSourceRow[]> {
    const client = await acquire();
    let releaseArg: Error | undefined;
    try {
      await client.query('BEGIN READ ONLY');
      await client.query("SELECT set_config('statement_timeout', $1, true)", [String(Math.trunc(timeoutMs))]);
      const result = await client.query(UNKNOWN_SOURCES_SQL, [windowHours, maxIds]);
      await client.query('COMMIT');
      return result.rows as UnknownSourceRow[];
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
  };
}

export interface UnknownSourcesDeps {
  fetchRows: (windowHours: number, maxIds: number, timeoutMs: number) => Promise<UnknownSourceRow[]>;
  now: () => number;
  log: { warn: (msg: string, meta?: unknown) => void; error: (msg: string, meta?: unknown) => void };
}

export interface UnknownSourcesOptions {
  windowHours: number;
  timeoutMs: number;
  ttlMs: number;
  failureCooldownMs: number;
  maxDistinctIds: number;
}

export interface UnknownSourcesService {
  /** Current unknown sources (cached; concurrent callers share one query). */
  get(): Promise<UnknownSource[]>;
  /** Drop the cached result -- call whenever the set of known shippers changes. */
  invalidate(): void;
}

export function createUnknownSourcesService(deps: UnknownSourcesDeps, opts: UnknownSourcesOptions): UnknownSourcesService {
  let cache: { at: number; generation: number; value: UnknownSource[] } | null = null;
  let generation = 0;
  let inflight: Promise<UnknownSource[]> | null = null;
  let lastFailure: { at: number; error: unknown } | null = null;

  async function refresh(): Promise<UnknownSource[]> {
    // A result computed before an invalidate() may already be out of date (e.g.
    // it still lists a shipper that was just registered), so it is returned to
    // the callers that were waiting on it but never cached.
    const startedGeneration = generation;
    try {
      const rows = await deps.fetchRows(opts.windowHours, opts.maxDistinctIds, opts.timeoutMs);
      if (rows.length > 0 && Number(rows[0].ids_enumerated) >= opts.maxDistinctIds) {
        deps.log.warn(
          `unknown-sources: shipper_id enumeration hit its cap of ${opts.maxDistinctIds} distinct ids; ` +
            `some unknown sources may not be listed (a sender may be spraying random shipper tags)`
        );
      }
      const value = rows.map(toUnknownSource);
      if (startedGeneration === generation) {
        cache = { at: deps.now(), generation, value };
      }
      lastFailure = null;
      return value;
    } catch (error) {
      lastFailure = { at: deps.now(), error };
      if (cache) {
        deps.log.warn('unknown-sources: refresh failed, serving the previous result', {
          error: error instanceof Error ? error.message : String(error),
        });
        return cache.value;
      }
      deps.log.error('unknown-sources: query failed', {
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  }

  return {
    async get(): Promise<UnknownSource[]> {
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

/** The process-wide instance used by the shippers routes. */
export const unknownSources = createUnknownSourcesService(
  {
    fetchRows: createDbFetcher(getClient as () => Promise<QueryClient>),
    now: () => Date.now(),
    log: logger,
  },
  {
    windowHours: UNKNOWN_SOURCES_WINDOW_HOURS,
    timeoutMs: UNKNOWN_SOURCES_TIMEOUT_MS,
    ttlMs: UNKNOWN_SOURCES_CACHE_TTL_MS,
    failureCooldownMs: UNKNOWN_SOURCES_FAILURE_COOLDOWN_MS,
    maxDistinctIds: UNKNOWN_SOURCES_MAX_DISTINCT_IDS,
  }
);
