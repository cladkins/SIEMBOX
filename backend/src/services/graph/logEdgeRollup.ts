/**
 * The log-relationship rollup (migration 044): what the Context Graph's
 * dashed "seen in logs" edges are read from. jobs/graphLogEdges.ts runs it
 * every minute on the main pool; ingestion is untouched (no index, trigger or
 * code on the ingest path), so relationships trail the logs by about two to
 * three minutes.
 *
 * Each run:
 *   1. The upper bound: the newest parsed log created more than LAG before now
 *      (a backward scan of idx_parsed_logs_created_at). Inserts are single-row
 *      autocommits, so every id below it has committed.
 *   2. The first run on a database starts BACKFILL days back (graph_log_edges_
 *      backfill_days, 7 by default) and sets covered_from; until the cursor
 *      first catches up the graph says "still being built".
 *   3. Batches of up to BATCH_SIZE ids, each one transaction: lock the state
 *      row (FOR UPDATE: a second runner waits, then takes the next range), run
 *      the upsert, move the cursor and the per-day counters, commit. The
 *      cursor and the counts commit together, so a crash replays a batch and
 *      nothing is counted twice. A statement timeout halves the batch.
 *   4. Rest PAUSE_RATIO times as long as each batch took before the next
 *      (a backlog drains at well under one core), and stop after
 *      RUN_BUDGET_MS of database time.
 *   5. At most hourly, prune days older than the retention: graph_log_edges_
 *      retention_days, or the raw-log retention when that is 0 (the default),
 *      and nothing when both are 0. Relationships never outlive their logs by
 *      default.
 *
 * The daily cap: log values are attacker-controlled, so a sprayer can create a
 * new row per log. Once a day has created graph_log_edges_daily_new_cap new
 * rows, the rest of that day only updates existing rows, and the day is listed
 * in truncated_days ("incomplete: too many distinct values"). The cap is
 * checked after each batch, so a day overshoots it by at most one batch.
 */
import { batchedDelete } from '../../utils/batchDelete';
import { isStatementTimeout } from '../shippers/snapshotCache';
import type { SourceStatus } from './types';

export const BATCH_SIZE = 5_000;
export const MIN_BATCH_SIZE = 1_000;
/** How far behind ingestion the cursor stays, so every id below it has committed. */
export const LAG = '2 minutes';
export const LAG_MS = 2 * 60_000;
/** Database time one run may use. */
export const RUN_BUDGET_MS = 20_000;
export const BATCH_STATEMENT_TIMEOUT_MS = 15_000;
export const PRUNE_EVERY_MS = 60 * 60_000;
/** Rest between batches, as a multiple of the batch's own time. */
export const PAUSE_RATIO = 3;
/** covered_until older than this: the graph says relationships are behind. */
export const BEHIND_AFTER_MS = 5 * 60_000;

/** The relations the rollup writes, a -> b. */
export const LOG_EDGE_RELS = ['signed_in_as', 'seen_on', 'user_on', 'connected_to', 'queried', 'sent_by', 'shipped_by'] as const;
export type LogEdgeRel = (typeof LOG_EDGE_RELS)[number];

export interface RollupClient {
  query(sql: string, params?: unknown[]): Promise<{ rows: any[]; rowCount?: number | null }>;
  release(err?: Error | boolean): void;
}

export interface LogEdgeSettings {
  enabled: boolean;
  /** graph_log_edges_retention_days as set (0 = same as raw logs). */
  retentionDays: number;
  /** retention_raw_logs_days (30 by default; 0 keeps raw logs forever). */
  rawRetentionDays: number;
  dailyNewCap: number;
  backfillDays: number;
}

export const DEFAULT_LOG_EDGE_SETTINGS: LogEdgeSettings = {
  enabled: true,
  retentionDays: 0,
  rawRetentionDays: 30,
  dailyNewCap: 500_000,
  backfillDays: 7,
};

/** Days of relationships kept: the setting, else the raw-log retention; 0 keeps them. */
export function effectiveRetentionDays(settings: Pick<LogEdgeSettings, 'retentionDays' | 'rawRetentionDays'>): number {
  return settings.retentionDays > 0 ? settings.retentionDays : Math.max(0, settings.rawRetentionDays);
}

const SETTING_KEYS = {
  graph_log_edges_enabled: 'enabled',
  graph_log_edges_retention_days: 'retentionDays',
  graph_log_edges_daily_new_cap: 'dailyNewCap',
  graph_log_edges_backfill_days: 'backfillDays',
  retention_raw_logs_days: 'rawRetentionDays',
} as const;

type Q = (sql: string, params?: unknown[]) => Promise<{ rows: any[] }>;

export async function readLogEdgeSettings(q: Q): Promise<LogEdgeSettings> {
  const { rows } = await q(`SELECT key, value FROM system_settings WHERE key = ANY($1::text[])`, [Object.keys(SETTING_KEYS)]);
  const out: LogEdgeSettings = { ...DEFAULT_LOG_EDGE_SETTINGS };
  for (const row of rows as Array<{ key: keyof typeof SETTING_KEYS; value: string | null }>) {
    const field = SETTING_KEYS[row.key];
    if (!field) continue;
    if (field === 'enabled') {
      out.enabled = row.value !== 'false';
    } else {
      const n = Number.parseInt(String(row.value ?? ''), 10);
      if (Number.isFinite(n) && n >= 0) out[field] = n;
    }
  }
  return out;
}

/**
 * The rows of one batch: parsed_logs ids ($1, $2], their raw logs bounded by
 * the batch's raw-id range ($3, $4: without it the planner hash-joins all of
 * raw_logs). MATERIALIZED keeps the key functions from running once per
 * relation.
 *
 *   actor     parsed_data.source_ip, trusted only when the log was parsed and
 *             it differs from observer_ip (fieldNormalizer fills source_ip
 *             with the sender when the parser found no IP)
 *   device    the syslog header host, else the sender IP
 *   tag       raw_logs.shipper_id (mapped to a shipper at read time)
 */
const EDGES_CTE = `
  src AS MATERIALIZED (
    SELECT pl.created_at AS seen, pl.parser_id IS NOT NULL AS parsed,
           graph_ip(pl.parsed_data->>'source_ip')   AS actor,
           graph_ip(pl.parsed_data->>'observer_ip') AS observer,
           graph_ip(pl.parsed_data->>'dest_ip')     AS dest,
           graph_user(pl.parsed_data->>'user')      AS usr,
           graph_domain(pl.parsed_data->>'domain')  AS domain,
           graph_log_host(rl.hostname)              AS host,
           graph_ip(rl.source_ip)                   AS sender,
           pl.parsed_data->>'auth_outcome'          AS outcome,
           CASE WHEN btrim(rl.shipper_id) ~* '^[0-9a-f]{8}$' THEN lower(btrim(rl.shipper_id)) END AS tag
      FROM parsed_logs pl
      LEFT JOIN raw_logs rl ON rl.id = pl.raw_log_id AND rl.id BETWEEN $3 AND $4
     WHERE pl.id > $1 AND pl.id <= $2
  ), d AS (
    SELECT seen, parsed, actor, observer, dest, usr, domain, host, sender, outcome, tag,
           CASE WHEN host IS NOT NULL THEN 'host' WHEN sender IS NOT NULL THEN 'ip' END AS dev_type,
           COALESCE(host, sender) AS dev,
           (parsed AND actor IS NOT NULL AND actor IS DISTINCT FROM observer) AS has_actor
      FROM src
  ), e AS (
    SELECT seen, outcome, x.rel, x.a_type, x.a_value, x.b_type, x.b_value FROM d, LATERAL (VALUES
      ('signed_in_as', 'ip',     CASE WHEN has_actor THEN actor END, 'user',        usr),
      ('seen_on',      'ip',     CASE WHEN has_actor THEN actor END, dev_type,      dev),
      ('user_on',      'user',   CASE WHEN parsed THEN usr END,      dev_type,      dev),
      ('connected_to', 'ip',     CASE WHEN has_actor THEN actor END, 'ip',          CASE WHEN dest IS DISTINCT FROM actor THEN dest END),
      ('queried',      'ip',     CASE WHEN has_actor THEN actor END, 'domain',      CASE WHEN parsed THEN domain END),
      ('sent_by',      'host',   host,                               'ip',          sender),
      ('shipped_by',   dev_type, dev,                                'shipper_tag', tag)
    ) AS x(rel, a_type, a_value, b_type, b_value)
    WHERE x.a_value IS NOT NULL AND x.b_value IS NOT NULL AND x.a_type IS NOT NULL AND x.b_type IS NOT NULL
  ), agg AS (
    SELECT seen::date AS day, rel, a_type, a_value, b_type, b_value, count(*)::int AS events,
           (count(*) FILTER (WHERE outcome = 'failure'))::int AS failures,
           (count(*) FILTER (WHERE outcome = 'success'))::int AS successes,
           min(seen) AS first_seen, max(seen) AS last_seen
      FROM e GROUP BY 1, 2, 3, 4, 5, 6
  )`;

/** Upsert the batch's edges for every day not in $5 (the capped days); the new rows per day. */
export const UPSERT_SQL = `
  WITH ${EDGES_CTE}, up AS (
    INSERT INTO graph_log_edges AS g (day, rel, a_type, a_value, b_type, b_value, events, failures, successes, first_seen, last_seen)
    SELECT day, rel, a_type, a_value, b_type, b_value, events, failures, successes, first_seen, last_seen
      FROM agg WHERE day <> ALL($5::date[])
    ON CONFLICT (a_type, a_value, day, rel, b_type, b_value) DO UPDATE
       SET events = g.events + EXCLUDED.events, failures = g.failures + EXCLUDED.failures,
           successes = g.successes + EXCLUDED.successes,
           first_seen = LEAST(g.first_seen, EXCLUDED.first_seen), last_seen = GREATEST(g.last_seen, EXCLUDED.last_seen)
    RETURNING (xmax = 0) AS inserted, day
  )
  SELECT to_char(day, 'YYYY-MM-DD') AS day, count(*) FILTER (WHERE inserted)::int AS new_rows FROM up GROUP BY day ORDER BY day`;

/** For the capped days ($5): update the rows that exist, insert none. */
export const UPDATE_ONLY_SQL = `
  WITH ${EDGES_CTE}
  UPDATE graph_log_edges g
     SET events = g.events + agg.events, failures = g.failures + agg.failures, successes = g.successes + agg.successes,
         first_seen = LEAST(g.first_seen, agg.first_seen), last_seen = GREATEST(g.last_seen, agg.last_seen)
    FROM agg
   WHERE agg.day = ANY($5::date[])
     AND g.a_type = agg.a_type AND g.a_value = agg.a_value AND g.day = agg.day
     AND g.rel = agg.rel AND g.b_type = agg.b_type AND g.b_value = agg.b_value`;

/** The cursor's bound: a backward scan of idx_parsed_logs_created_at (never max(id) ... WHERE created_at <, which may read the table). */
export const UPPER_BOUND_SQL = `SELECT id FROM parsed_logs WHERE created_at < NOW() - $1::interval ORDER BY created_at DESC LIMIT 1`;
/** The backfill's first id: a forward scan of the same index. */
export const BACKFILL_START_SQL = `SELECT id FROM parsed_logs WHERE created_at >= NOW() - $1::int * interval '1 day' ORDER BY created_at ASC LIMIT 1`;

/** Everything created before NOW() - lag is consumed. */
const CAUGHT_UP_SQL = `
  UPDATE graph_log_edges_state
     SET caught_up = true, covered_until = GREATEST(covered_until, (NOW() - $1::interval)::timestamp), last_run_at = NOW()
   WHERE id = 1`;

interface StateRow {
  last_parsed_log_id: string | null;
  new_rows_day: string | null;
  new_rows_count: number;
  truncated_days: string[];
  last_pruned_at: Date | null;
}

const STATE_SQL = `
  SELECT last_parsed_log_id, to_char(new_rows_day, 'YYYY-MM-DD') AS new_rows_day, new_rows_count,
         ARRAY(SELECT to_char(t, 'YYYY-MM-DD') FROM unnest(truncated_days) t ORDER BY t) AS truncated_days,
         last_pruned_at
    FROM graph_log_edges_state WHERE id = 1`;

export interface RollupOptions {
  connect: () => Promise<RollupClient>;
  /** Read from system_settings when not given. */
  settings?: LogEdgeSettings;
  now?: () => number;
  batchSize?: number;
  budgetMs?: number;
  /**
   * After each batch, rest this many times as long as it took (default
   * PAUSE_RATIO), so a backlog never holds a database core: ingestion, on its
   * own pool, keeps its pace while the backfill runs.
   */
  pauseRatio?: number;
  /** The lag, as an interval (tests use '0 seconds'). */
  lag?: string;
  /** Called between batches (tests use it to simulate a crash). */
  afterBatch?: (batch: { from: number; to: number }) => Promise<void> | void;
}

export interface RollupResult {
  status: 'disabled' | 'ok';
  consumed: number;
  batches: number;
  newRows: number;
  /** Days that hit the cap in this run. */
  cappedDays: string[];
  pruned: number;
  /** The run stopped (time budget) before reaching the bound. */
  more: boolean;
  batchSize: number;
  /** A statement timeout halved the batch. */
  backedOff: boolean;
}

async function inTransaction<T>(client: RollupClient, work: () => Promise<T>): Promise<T> {
  await client.query('BEGIN');
  try {
    const out = await work();
    await client.query('COMMIT');
    return out;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw err;
  }
}

/** Start the cursor on a database that has none: BACKFILL days back (or at the bound when that is 0). */
async function startCursor(client: RollupClient, settings: LogEdgeSettings, hi: number | null): Promise<void> {
  await inTransaction(client, async () => {
    const { rows } = await client.query(`SELECT last_parsed_log_id FROM graph_log_edges_state WHERE id = 1 FOR UPDATE`);
    if (rows[0]?.last_parsed_log_id !== null && rows[0]?.last_parsed_log_id !== undefined) return;
    let last: number;
    let from: string;
    if (settings.backfillDays > 0) {
      const { rows: first } = await client.query(BACKFILL_START_SQL, [settings.backfillDays]);
      last = first[0] ? Number(first[0].id) - 1 : (hi ?? 0);
      from = `CURRENT_DATE - ${Math.trunc(settings.backfillDays)}`;
    } else {
      last = hi ?? 0;
      from = 'CURRENT_DATE';
    }
    await client.query(
      `UPDATE graph_log_edges_state
          SET last_parsed_log_id = $1, covered_from = ${from}, caught_up = false,
              new_rows_day = NULL, new_rows_count = 0, truncated_days = '{}'
        WHERE id = 1`,
      [last]
    );
  });
}

/** The day counters after a batch: which days crossed the cap. Pure. */
export function countNewRows(
  state: { day: string | null; count: number; truncated: string[] },
  perDay: Array<{ day: string; new_rows: number }>,
  cap: number
): { day: string | null; count: number; truncated: string[]; capped: string[] } {
  let { day, count } = state;
  const truncated = new Set(state.truncated);
  const capped: string[] = [];
  for (const row of [...perDay].sort((a, b) => a.day.localeCompare(b.day))) {
    if (day === row.day) {
      count += row.new_rows;
    } else if (day === null || row.day > day) {
      day = row.day;
      count = row.new_rows;
    } else {
      continue; // an older day (replayed or late): not counted against today's cap
    }
    if (count >= cap && !truncated.has(day)) {
      truncated.add(day);
      capped.push(day);
    }
  }
  return { day, count, truncated: [...truncated].sort(), capped };
}

async function runBatch(
  client: RollupClient,
  settings: LogEdgeSettings,
  hi: number,
  size: number,
  lag: string
): Promise<{ done: boolean; from: number; to: number; consumed: number; newRows: number; capped: string[] }> {
  return inTransaction(client, async () => {
    const { rows } = await client.query(`${STATE_SQL} FOR UPDATE`);
    const state = rows[0] as StateRow;
    const last = Number(state.last_parsed_log_id ?? 0);
    if (last >= hi) {
      await client.query(CAUGHT_UP_SQL, [lag]);
      return { done: true, from: last, to: last, consumed: 0, newRows: 0, capped: [] };
    }
    const upper = Math.min(last + size, hi);
    const { rows: bounds } = await client.query(
      `SELECT min(raw_log_id) AS raw_min, max(raw_log_id) AS raw_max, count(*)::int AS n, max(created_at) AS until
         FROM parsed_logs WHERE id > $1 AND id <= $2`,
      [last, upper]
    );
    const b = bounds[0];
    let perDay: Array<{ day: string; new_rows: number }> = [];
    if (b.n > 0) {
      await client.query("SELECT set_config('statement_timeout', $1, true), set_config('jit', 'off', true)", [String(BATCH_STATEMENT_TIMEOUT_MS)]);
      const params = [last, upper, b.raw_min ?? 0, b.raw_max ?? 0, state.truncated_days];
      if (state.truncated_days.length > 0) await client.query(UPDATE_ONLY_SQL, params);
      perDay = (await client.query(UPSERT_SQL, params)).rows;
    }
    const counted = countNewRows({ day: state.new_rows_day, count: state.new_rows_count, truncated: state.truncated_days }, perDay, settings.dailyNewCap);
    const caughtUp = upper >= hi;
    await client.query(
      `UPDATE graph_log_edges_state
          SET last_parsed_log_id = $1,
              covered_until = CASE WHEN $2::boolean THEN GREATEST(covered_until, (NOW() - $6::interval)::timestamp)
                                   ELSE GREATEST(covered_until, $3::timestamp) END,
              caught_up = caught_up OR $2::boolean,
              new_rows_day = $4::date, new_rows_count = $5::int, truncated_days = $7::date[], last_run_at = NOW()
        WHERE id = 1`,
      [upper, caughtUp, b.until, counted.day, counted.count, lag, counted.truncated]
    );
    return {
      done: caughtUp,
      from: last,
      to: upper,
      consumed: b.n,
      newRows: perDay.reduce((sum, r) => sum + r.new_rows, 0),
      capped: counted.capped,
    };
  });
}

/** Delete days past the retention, at most hourly. Returns rows deleted. */
async function prune(client: RollupClient, settings: LogEdgeSettings, nowMs: number, force = false): Promise<number> {
  const { rows } = await client.query(`SELECT last_pruned_at FROM graph_log_edges_state WHERE id = 1`);
  const lastPruned = rows[0]?.last_pruned_at ? new Date(rows[0].last_pruned_at).getTime() : 0;
  if (!force && nowMs - lastPruned < PRUNE_EVERY_MS) return 0;
  const days = effectiveRetentionDays(settings);
  let deleted = 0;
  if (days > 0) {
    deleted = await batchedDelete('graph_log_edges', 'day < CURRENT_DATE - $1::int', [days], {
      label: 'Context Graph log relationships',
      pauseMs: 20,
      exec: async (sql, params) => {
        const res = await client.query(sql, params);
        return { rowCount: res.rowCount ?? 0 };
      },
    });
    await client.query(
      `UPDATE graph_log_edges_state
          SET truncated_days = ARRAY(SELECT t FROM unnest(truncated_days) t WHERE t >= CURRENT_DATE - $1::int ORDER BY t),
              covered_from = GREATEST(covered_from, CURRENT_DATE - $1::int)
        WHERE id = 1`,
      [days]
    );
  }
  await client.query(`UPDATE graph_log_edges_state SET last_pruned_at = NOW() WHERE id = 1`);
  return deleted;
}

/** One run of the rollup. */
export async function runLogEdgeRollup(options: RollupOptions & { forcePrune?: boolean }): Promise<RollupResult> {
  const now = options.now ?? (() => Date.now());
  const budget = options.budgetMs ?? RUN_BUDGET_MS;
  let size = options.batchSize ?? BATCH_SIZE;
  const result: RollupResult = { status: 'ok', consumed: 0, batches: 0, newRows: 0, cappedDays: [], pruned: 0, more: false, batchSize: size, backedOff: false };
  const client = await options.connect();
  let releaseArg: Error | undefined;
  try {
    const q: Q = (sql, params) => client.query(sql, params);
    const settings = options.settings ?? (await readLogEdgeSettings(q));
    if (!settings.enabled) {
      result.status = 'disabled';
      return result;
    }
    const lag = options.lag ?? LAG;
    const { rows } = await client.query(UPPER_BOUND_SQL, [lag]);
    const hi = rows[0] ? Number(rows[0].id) : null;
    await startCursor(client, settings, hi);

    if (hi !== null) {
      let spent = 0;
      for (;;) {
        if (spent >= budget) {
          result.more = true;
          break;
        }
        const started = now();
        let batch;
        try {
          batch = await runBatch(client, settings, hi, size, lag);
        } catch (err) {
          if (isStatementTimeout(err) && size > MIN_BATCH_SIZE) {
            size = Math.max(MIN_BATCH_SIZE, Math.floor(size / 2));
            result.backedOff = true;
            continue;
          }
          throw err;
        } finally {
          spent += now() - started;
        }
        if (batch.to > batch.from) {
          result.batches++;
          result.consumed += batch.consumed;
          result.newRows += batch.newRows;
          result.cappedDays.push(...batch.capped);
          await options.afterBatch?.({ from: batch.from, to: batch.to });
        }
        if (batch.done) break;
        const pause = (now() - started) * (options.pauseRatio ?? PAUSE_RATIO);
        if (pause > 0) await new Promise((resolve) => setTimeout(resolve, Math.min(pause, 5_000)));
      }
    } else {
      // No log old enough yet: nothing is missing.
      await client.query(CAUGHT_UP_SQL, [lag]);
    }
    result.pruned = await prune(client, settings, now(), options.forcePrune === true);
    result.batchSize = size;
    return result;
  } catch (err) {
    if (!isStatementTimeout(err)) releaseArg = err instanceof Error ? err : new Error(String(err));
    throw err;
  } finally {
    client.release(releaseArg);
  }
}

export function describeRollup(result: RollupResult): string {
  if (result.status === 'disabled') return 'switched off in Settings -> Context Graph';
  const parts = [`${result.consumed.toLocaleString('en-US')} logs in ${result.batches} batch(es), ${result.newRows.toLocaleString('en-US')} new relationships`];
  if (result.more) parts.push('more to do (backlog)');
  if (result.backedOff) parts.push(`batch size cut to ${result.batchSize.toLocaleString('en-US')} after a timeout`);
  if (result.cappedDays.length) parts.push(`daily cap reached for ${result.cappedDays.join(', ')}`);
  if (result.pruned) parts.push(`pruned ${result.pruned.toLocaleString('en-US')} old rows`);
  return parts.join('; ');
}

/** What the graph says about the rollup (graph_log_edges_state plus the switch). */
export interface LogEdgeState {
  enabled: boolean;
  caughtUp: boolean;
  /** YYYY-MM-DD */
  coveredFrom: string | null;
  /** ISO */
  coveredUntil: string | null;
  /** YYYY-MM-DD, sorted */
  truncatedDays: string[];
  /** Effective retention in days; 0 keeps them. */
  retentionDays: number;
}

export const LOG_EDGE_STATE_SQL = `
  SELECT s.caught_up, to_char(s.covered_from, 'YYYY-MM-DD') AS covered_from, s.covered_until,
         ARRAY(SELECT to_char(t, 'YYYY-MM-DD') FROM unnest(s.truncated_days) t ORDER BY t) AS truncated_days,
         (SELECT value FROM system_settings WHERE key = 'graph_log_edges_enabled') AS enabled,
         (SELECT value FROM system_settings WHERE key = 'graph_log_edges_retention_days') AS retention_days,
         (SELECT value FROM system_settings WHERE key = 'retention_raw_logs_days') AS raw_days
    FROM graph_log_edges_state s WHERE s.id = 1`;

export async function readLogEdgeState(q: <T = Record<string, unknown>>(sql: string, params?: unknown[]) => Promise<T[]>): Promise<LogEdgeState> {
  const [row] = await q<Record<string, any>>(LOG_EDGE_STATE_SQL);
  const int = (v: unknown, fallback: number) => {
    const n = Number.parseInt(String(v ?? ''), 10);
    return Number.isFinite(n) && n >= 0 ? n : fallback;
  };
  const until = row?.covered_until ? new Date(row.covered_until) : null;
  return {
    enabled: row ? row.enabled !== 'false' : false,
    caughtUp: row?.caught_up === true,
    coveredFrom: row?.covered_from ?? null,
    coveredUntil: until && !Number.isNaN(until.getTime()) ? until.toISOString() : null,
    truncatedDays: row?.truncated_days ?? [],
    retentionDays: effectiveRetentionDays({ retentionDays: int(row?.retention_days, 0), rawRetentionDays: int(row?.raw_days, 30) }),
  };
}

/**
 * sources.logs for a window: disabled, building (backfill not caught up),
 * behind (covered_until more than 5 minutes old), else ok; plus the days the
 * cap cut short within the window. Pure.
 */
export function logSourceStatus(state: LogEdgeState, days: { first: string; last: string }, nowMs: number): SourceStatus {
  if (!state.enabled) return { status: 'disabled' };
  const out: SourceStatus = { status: 'ok' };
  if (state.coveredFrom) out.covered_from = state.coveredFrom;
  if (state.coveredUntil) out.covered_until = state.coveredUntil;
  const incomplete = state.truncatedDays.filter((d) => d >= days.first && d <= days.last);
  if (incomplete.length) out.incomplete_days = incomplete;
  if (!state.caughtUp) out.status = 'building';
  else if (!state.coveredUntil || nowMs - Date.parse(state.coveredUntil) > BEHIND_AFTER_MS) out.status = 'behind';
  return out;
}
