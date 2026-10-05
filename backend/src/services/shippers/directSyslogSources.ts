/**
 * "Direct syslog sources": hosts sending syslog straight to the listener on
 * 514/udp+tcp WITHOUT a log shipper -- a firewall, NAS, switch or UniFi device
 * using its own remote-syslog setting. Shown on the Shippers page in its own
 * section, separate from installed shippers.
 *
 * Which raw_logs rows count: shipper_id IS NULL AND discovery_source_id IS NULL.
 *   - A managed shipper tags every line with its [8-hex] id, and HTTP push
 *     always sets shipper_id, so shipper_id IS NULL means "no shipper".
 *     (Lines with an UNregistered id are the separate "unknown sources" list.)
 *   - Log Discovery's API poller sets discovery_source_id and never shipper_id,
 *     so it must be excluded explicitly or polled sources would show up here
 *     as well as in their own "API-Polled Sources" section.
 *
 * Grouped by source_ip (the sender as the listener saw it) over the last
 * DIRECT_SYSLOG_WINDOW_HOURS. The query aggregates in two stages -- hash-group
 * by (ip, hostname, app) first, then build the per-IP arrays over that small
 * intermediate result -- because ARRAY_AGG(DISTINCT ...) straight over the raw
 * rows forces a full sort: measured on 3.2M direct-syslog rows, ~0.47 s
 * (in-memory) vs ~4.6 s (155 MB spilled to disk), with identical output.
 */
import { getClient } from '../../config/database';
import { logger } from '../../utils/logger';
import { QueryClient, runReadOnly, createSnapshotCache, SnapshotCache } from './snapshotCache';

/** Window over which senders are listed and counted. Matches the unknown-sources list. */
export const DIRECT_SYSLOG_WINDOW_HOURS = 24;
/** Statement timeout -- kept under the frontend's 10 s request timeout. */
export const DIRECT_SYSLOG_TIMEOUT_MS = 8000;
/** How long a successful result is served without re-querying. */
export const DIRECT_SYSLOG_CACHE_TTL_MS = 30_000;
/** After a failed run, serve the stale result (or fail fast) for this long. */
export const DIRECT_SYSLOG_FAILURE_COOLDOWN_MS = 20_000;
/** Most senders returned (most recently seen first). Homelabs have tens. */
export const DIRECT_SYSLOG_MAX_SOURCES = 500;
/**
 * Most hostnames / app names returned per sender. One IP can legitimately
 * carry many (a relay, NAT, a chatty host), and a misbehaving sender can spray
 * thousands; the full counts are still returned alongside.
 */
export const DIRECT_SYSLOG_MAX_LIST_ITEMS = 25;

/** $1 = window hours (int), $2 = max senders (int). */
export const DIRECT_SYSLOG_SQL = `
  WITH g AS (
    SELECT source_ip, hostname, app_name,
           COUNT(*) AS n, MIN(created_at) AS first_seen, MAX(created_at) AS last_seen
    FROM raw_logs
    WHERE shipper_id IS NULL
      AND discovery_source_id IS NULL
      AND created_at >= NOW() - ($1 * INTERVAL '1 hour')
    GROUP BY source_ip, hostname, app_name
  )
  SELECT source_ip,
         SUM(n)::bigint AS log_count,
         MIN(first_seen) AS first_seen,
         MAX(last_seen) AS last_seen,
         COALESCE(ARRAY_AGG(DISTINCT hostname) FILTER (WHERE hostname IS NOT NULL), '{}') AS hostnames,
         COALESCE(ARRAY_AGG(DISTINCT app_name) FILTER (WHERE app_name IS NOT NULL), '{}') AS app_names
  FROM g
  GROUP BY source_ip
  ORDER BY MAX(last_seen) DESC
  LIMIT $2
`;

export interface DirectSyslogSourceRow {
  source_ip: string | null;
  log_count: string | number;
  first_seen: Date | string;
  last_seen: Date | string;
  hostnames: Array<string | null> | null;
  app_names: Array<string | null> | null;
}

export interface DirectSyslogSource {
  source_ip: string | null;
  log_count: number;
  first_seen: Date | string;
  last_seen: Date | string;
  /** At most DIRECT_SYSLOG_MAX_LIST_ITEMS; see hostname_count for the total. */
  hostnames: string[];
  hostname_count: number;
  /** At most DIRECT_SYSLOG_MAX_LIST_ITEMS; see app_name_count for the total. */
  app_names: string[];
  app_name_count: number;
}

const nonNull = (v: string | null): v is string => v !== null && v !== undefined;

export function toDirectSyslogSource(row: DirectSyslogSourceRow, maxListItems = DIRECT_SYSLOG_MAX_LIST_ITEMS): DirectSyslogSource {
  const hostnames = (row.hostnames ?? []).filter(nonNull);
  const appNames = (row.app_names ?? []).filter(nonNull);
  return {
    source_ip: row.source_ip,
    log_count: parseInt(String(row.log_count), 10),
    first_seen: row.first_seen,
    last_seen: row.last_seen,
    hostnames: hostnames.slice(0, maxListItems),
    hostname_count: hostnames.length,
    app_names: appNames.slice(0, maxListItems),
    app_name_count: appNames.length,
  };
}

export interface DirectSyslogSourcesDeps {
  fetchRows: (windowHours: number, maxSources: number, timeoutMs: number) => Promise<DirectSyslogSourceRow[]>;
  now: () => number;
  log: { warn: (msg: string, meta?: unknown) => void; error: (msg: string, meta?: unknown) => void };
}

export interface DirectSyslogSourcesOptions {
  windowHours: number;
  timeoutMs: number;
  ttlMs: number;
  failureCooldownMs: number;
  maxSources: number;
  maxListItems: number;
}

export function createDirectSyslogDbFetcher(acquire: () => Promise<QueryClient>) {
  return async function fetchRows(windowHours: number, maxSources: number, timeoutMs: number): Promise<DirectSyslogSourceRow[]> {
    return (await runReadOnly(acquire, DIRECT_SYSLOG_SQL, [windowHours, maxSources], timeoutMs)) as DirectSyslogSourceRow[];
  };
}

export function createDirectSyslogSourcesService(
  deps: DirectSyslogSourcesDeps,
  opts: DirectSyslogSourcesOptions
): SnapshotCache<DirectSyslogSource[]> {
  return createSnapshotCache<DirectSyslogSource[]>(
    {
      label: 'direct-syslog-sources',
      now: deps.now,
      log: deps.log,
      fetch: async () => {
        const rows = await deps.fetchRows(opts.windowHours, opts.maxSources, opts.timeoutMs);
        if (rows.length >= opts.maxSources) {
          deps.log.warn(
            `direct-syslog-sources: hit the cap of ${opts.maxSources} senders; only the most recently seen are listed`
          );
        }
        return rows.map((r) => toDirectSyslogSource(r, opts.maxListItems));
      },
    },
    { ttlMs: opts.ttlMs, failureCooldownMs: opts.failureCooldownMs }
  );
}

/** The process-wide instance used by the shippers routes. */
export const directSyslogSources = createDirectSyslogSourcesService(
  {
    fetchRows: createDirectSyslogDbFetcher(getClient as () => Promise<QueryClient>),
    now: () => Date.now(),
    log: logger,
  },
  {
    windowHours: DIRECT_SYSLOG_WINDOW_HOURS,
    timeoutMs: DIRECT_SYSLOG_TIMEOUT_MS,
    ttlMs: DIRECT_SYSLOG_CACHE_TTL_MS,
    failureCooldownMs: DIRECT_SYSLOG_FAILURE_COOLDOWN_MS,
    maxSources: DIRECT_SYSLOG_MAX_SOURCES,
    maxListItems: DIRECT_SYSLOG_MAX_LIST_ITEMS,
  }
);
