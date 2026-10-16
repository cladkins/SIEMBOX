/**
 * Per-minute log counts per source (ingest_source_minute, migration 041), kept
 * at ingest so the Big Display's ingestion and sources panels never aggregate
 * raw_logs. Counting 60 minutes straight from raw_logs takes 370-410 ms at 300
 * logs/s and a per-source 24 h baseline 1.26 s, both growing with volume; from
 * this table they take 2-3 ms and 42-55 ms for 100 sources.
 *
 * It follows the parser engine's parser_match_hourly counters (024):
 *
 * - RawLogModel.create bumps it once per stored row. A deduplicated push or
 *   poll returns null there and is not counted. That one choke point covers
 *   syslog, HTTP push and the API poller.
 * - A source is a shipper (shipper_id set: the 8-hex id from the syslog tag or
 *   the HTTP push key hash, lowercased), a poller (discovery_source_id set: the
 *   Log Discovery API poller) or, otherwise, a direct sender keyed by address.
 * - A bump is synchronous: one Map lookup on the row's own shipper id, poller
 *   id or address, and an increment. It allocates nothing for a source already
 *   seen this minute, awaits nothing, and never throws into the ingest path.
 *   (It runs once per stored log; in the real server a bump that built string
 *   keys cost about 3 times as much.)
 * - Pending counts are written as one upsert at most FLUSH_MS after they
 *   arrive, on an unref()ed timer (so a quiet stream still closes its last
 *   minute, and the timer never keeps the process alive): about 100 rows every
 *   5 s for 100 busy sources, whatever the log rate. FLUSH_KEYS pending keys
 *   also start a write, which in practice only happens after a slow one. The
 *   write runs on the ingest pool (its own connections, 10 s acquire,
 *   connection retry), never the UI's.
 * - One flush runs at a time; counts that arrive meanwhile wait for the next.
 * - A failed flush is logged and its counts are dropped, so memory never grows
 *   during a database outage. If a flush hangs instead of failing, at most
 *   MAX_PENDING_KEYS keys are held, and counts for new keys are dropped.
 * - At most MAX_SOURCES_PER_MINUTE distinct sources are counted per minute.
 *   Further sources count into ('overflow', '*'), so a sender spraying random
 *   shipper tags can't grow the table.
 * - Rows older than RETENTION_HOURS are deleted from the flush path, at most
 *   once per PRUNE_MS.
 * - server.ts calls close() at shutdown, which writes what is pending (waiting
 *   at most CLOSE_WAIT_MS). A crash loses up to FLUSH_MS of counts.
 *
 * Buckets are server ingest time (Date.now()), never the sender's timestamp,
 * so sender clock skew can't distort them.
 */
import { query, runInIngestContext } from '../../config/database';
import { logger } from '../../utils/logger';
import type { RawLog } from '../../models/RawLog';

/** Write pending counts at most this long after the first one arrives. */
export const FLUSH_MS = 5000;
/** Distinct sources counted per minute; any more go to the overflow row. */
export const MAX_SOURCES_PER_MINUTE = 500;
/**
 * ...or as soon as this many keys (minute + source) are pending. A safety net
 * only: a 5 s window spans at most two minutes, so the per-minute cap keeps it
 * to 2 x 501 keys, and in normal running the timer does every write. Only a
 * slow write lets more pile up. (A small trigger such as parser_match_hourly's
 * 64 keys would defeat the batching here: every active source adds a key each
 * minute, so with more than 64 sources the keys refill within milliseconds of
 * a write, and the counter wrote back-to-back: one row for every 2-3 logs.)
 */
export const FLUSH_KEYS = 1024;
/** Keys held while a flush is stuck; counts for new keys are dropped past this. */
export const MAX_PENDING_KEYS = 5000;
/** Rows older than this are pruned. */
export const RETENTION_HOURS = 48;
/** Prune at most this often. */
export const PRUNE_MS = 60 * 60 * 1000;
/** close() waits at most this long for the last write: a shutdown never hangs on statistics. */
export const CLOSE_WAIT_MS = 5000;

export const OVERFLOW_KEY = '*';

export type IngestSourceKind = 'shipper' | 'poller' | 'direct' | 'overflow';

/** The raw_logs columns a source is told apart by. */
export type IngestSourceFields = Pick<RawLog, 'shipper_id' | 'discovery_source_id' | 'source_ip'>;

/** One row of ingest_source_minute, as a flush writes it. */
export interface IngestCountRow {
  /** Start of the minute (UTC-aligned). */
  minute: Date;
  kind: IngestSourceKind;
  key: string;
  logs: number;
}

/** The minute a timestamp (ms since the epoch) falls in, as minutes since the epoch. */
export function minuteBucket(epochMs: number): number {
  return Math.floor(epochMs / 60_000);
}

export const UPSERT_SQL = `
  INSERT INTO ingest_source_minute (minute, source_kind, source_key, logs)
  SELECT * FROM unnest($1::timestamptz[], $2::text[], $3::text[], $4::bigint[])
  ON CONFLICT (minute, source_kind, source_key)
  DO UPDATE SET logs = ingest_source_minute.logs + EXCLUDED.logs`;

export const PRUNE_SQL = `DELETE FROM ingest_source_minute WHERE minute < NOW() - make_interval(hours => $1)`;

/** The upsert. Called inside runInIngestContext, so it uses the ingest pool. */
async function writeRows(rows: IngestCountRow[]): Promise<void> {
  await query(UPSERT_SQL, [
    rows.map((r) => r.minute),
    rows.map((r) => r.kind),
    rows.map((r) => r.key),
    rows.map((r) => r.logs),
  ]);
}

async function pruneRows(): Promise<void> {
  await query(PRUNE_SQL, [RETENTION_HOURS]);
}

interface TimerHandle {
  unref?: () => unknown;
}

export interface IngestCounterDeps {
  now(): number;
  write(rows: IngestCountRow[]): Promise<void>;
  prune(): Promise<void>;
  setTimer(fn: () => void, ms: number): TimerHandle;
  clearTimer(handle: TimerHandle): void;
}

const defaultDeps: IngestCounterDeps = {
  now: () => Date.now(),
  write: writeRows,
  prune: pruneRows,
  setTimer: (fn, ms) => setTimeout(fn, ms),
  clearTimer: (handle) => clearTimeout(handle as NodeJS.Timeout),
};

export interface IngestCounterStats {
  /** Keys (minute + source) waiting for the next flush. */
  pendingKeys: number;
  /** Logs those keys hold. */
  pendingLogs: number;
  /** Distinct sources counted in the current minute (the overflow row excluded). */
  sourcesThisMinute: number;
  /** A flush is running. */
  flushing: boolean;
  /** Logs whose counts were lost (failed flushes, or the pending cap). Since start. */
  droppedLogs: number;
}

export interface IngestCounter {
  /** Count one stored log. Synchronous; never throws. */
  bump(row: IngestSourceFields): void;
  /** Write what is pending now (after any flush already running). Never rejects. */
  flush(): Promise<void>;
  /** Stop the timer and write what is pending, waiting at most CLOSE_WAIT_MS. Later bumps are ignored. For shutdown. */
  close(): Promise<void>;
  stats(): IngestCounterStats;
}

/** One source in one minute. Lives for its minute; `pending` is what is not yet written. */
interface Entry {
  minute: number;
  kind: IngestSourceKind;
  /** As the row had it: shipper ids are lowercased when written. */
  key: string | number;
  pending: number;
}

/** Rows for the upsert, one per minute + source: shipper ids lowercased, and rows that then coincide merged. */
function toRows(entries: Array<{ minute: number; kind: IngestSourceKind; key: string | number; logs: number }>): IngestCountRow[] {
  const rows = new Map<string, IngestCountRow>();
  for (const e of entries) {
    const key = e.kind === 'shipper' ? String(e.key).toLowerCase() : String(e.key);
    const id = `${e.minute}|${e.kind}|${key}`;
    const row = rows.get(id);
    if (row) row.logs += e.logs;
    else rows.set(id, { minute: new Date(e.minute * 60_000), kind: e.kind, key, logs: e.logs });
  }
  return [...rows.values()];
}

export function createIngestCounter(overrides: Partial<IngestCounterDeps> = {}): IngestCounter {
  const deps: IngestCounterDeps = { ...defaultDeps, ...overrides };

  // The current minute's sources, by kind, keyed by the row's own value. Their
  // count is what the per-minute cap limits.
  let currentMinute = -1;
  const shippers = new Map<string | number, Entry>();
  const pollers = new Map<string | number, Entry>();
  const directs = new Map<string | number, Entry>();
  let overflow: Entry | null = null;
  let sourcesThisMinute = 0;
  /** Earlier minutes' entries with counts not yet written. */
  let sealed: Entry[] = [];
  /** Entries (current and sealed) with pending > 0. */
  let pendingKeys = 0;

  let timer: TimerHandle | null = null;
  let flushing: Promise<void> | null = null;
  let lastPrune = 0;
  let closed = false;
  let droppedLogs = 0;
  /** Logs dropped by the pending cap since that was last reported. */
  let cappedSinceReport = 0;

  function* currentEntries(): Generator<Entry> {
    yield* shippers.values();
    yield* pollers.values();
    yield* directs.values();
    if (overflow) yield overflow;
  }

  /** A new minute: keep the last one's unwritten entries for the next write, and start empty. */
  function startMinute(minute: number): void {
    for (const e of currentEntries()) if (e.pending > 0) sealed.push(e);
    shippers.clear();
    pollers.clear();
    directs.clear();
    overflow = null;
    sourcesThisMinute = 0;
    currentMinute = minute;
  }

  /** A source first seen this minute; the overflow entry once the cap is reached. */
  function addSource(map: Map<string | number, Entry>, kind: IngestSourceKind, key: string | number): Entry {
    if (sourcesThisMinute >= MAX_SOURCES_PER_MINUTE) {
      return (overflow ??= { minute: currentMinute, kind: 'overflow', key: OVERFLOW_KEY, pending: 0 });
    }
    const entry: Entry = { minute: currentMinute, kind, key, pending: 0 };
    map.set(key, entry);
    sourcesThisMinute++;
    return entry;
  }

  function armTimer(): void {
    if (timer || closed) return;
    timer = deps.setTimer(() => {
      timer = null;
      void startFlush();
    }, FLUSH_MS);
    timer.unref?.();
  }

  function disarmTimer(): void {
    if (!timer) return;
    deps.clearTimer(timer);
    timer = null;
  }

  async function writeBatch(rows: IngestCountRow[]): Promise<boolean> {
    try {
      await runInIngestContext(() => deps.write(rows));
      return true;
    } catch (error) {
      // Merging the batch back would grow without bound during an outage, and
      // these are statistics: log it and move on, as the parser counters do.
      const logs = rows.reduce((n, r) => n + r.logs, 0);
      droppedLogs += logs;
      logger.error('Failed to write per-minute ingest counts; they were dropped', {
        error: error instanceof Error ? error.message : String(error),
        sources: rows.length,
        logs,
      });
      return false;
    }
  }

  async function pruneIfDue(): Promise<void> {
    if (deps.now() - lastPrune < PRUNE_MS) return;
    lastPrune = deps.now();
    try {
      await runInIngestContext(() => deps.prune());
    } catch (error) {
      logger.error('Failed to prune per-minute ingest counts', {
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  /** Take every unwritten count, leaving all entries at zero. */
  function takePending(): IngestCountRow[] {
    const taken: Array<{ minute: number; kind: IngestSourceKind; key: string | number; logs: number }> = [];
    for (const e of sealed) taken.push({ minute: e.minute, kind: e.kind, key: e.key, logs: e.pending });
    sealed = [];
    for (const e of currentEntries()) {
      if (e.pending === 0) continue;
      taken.push({ minute: e.minute, kind: e.kind, key: e.key, logs: e.pending });
      e.pending = 0;
    }
    pendingKeys = 0;
    return toRows(taken);
  }

  /** Start a flush of everything pending, unless one is running (its end looks again). */
  function startFlush(): Promise<void> {
    if (flushing) return flushing;
    disarmTimer();
    if (pendingKeys === 0) return Promise.resolve();
    const rows = takePending();

    flushing = (async () => {
      if (await writeBatch(rows)) await pruneIfDue();
      if (cappedSinceReport > 0) {
        logger.warn('Per-minute ingest counts for some sources were not recorded while a write was stuck', {
          logs: cappedSinceReport,
        });
        cappedSinceReport = 0;
      }
    })().finally(() => {
      flushing = null;
      if (closed) return;
      if (pendingKeys >= FLUSH_KEYS) void startFlush();
      else if (pendingKeys > 0) armTimer();
    });
    return flushing;
  }

  async function flush(): Promise<void> {
    // A flush that finishes with FLUSH_KEYS keys pending starts the next at once.
    while (flushing) await flushing;
    await startFlush();
  }

  function bump(row: IngestSourceFields): void {
    if (closed) return;
    try {
      const minute = Math.floor(deps.now() / 60_000);
      if (minute !== currentMinute) startMinute(minute);

      let entry: Entry | undefined;
      const shipperId = row.shipper_id;
      if (shipperId) {
        entry = shippers.get(shipperId) ?? addSource(shippers, 'shipper', shipperId);
      } else if (row.discovery_source_id != null) {
        entry = pollers.get(row.discovery_source_id) ?? addSource(pollers, 'poller', row.discovery_source_id);
      } else {
        const ip = row.source_ip ?? '';
        entry = directs.get(ip) ?? addSource(directs, 'direct', ip);
      }

      if (entry.pending === 0) {
        if (pendingKeys >= MAX_PENDING_KEYS) {
          droppedLogs++;
          cappedSinceReport++;
          return;
        }
        pendingKeys++;
      }
      entry.pending++;

      if (pendingKeys >= FLUSH_KEYS) void startFlush();
      else armTimer();
    } catch {
      // Counting must never fail an ingest.
    }
  }

  return {
    bump,
    flush,
    async close() {
      closed = true;
      disarmTimer();
      // A database that hangs (connection retries run for up to 30 s) must not
      // hold the shutdown up; whatever is still unwritten then is lost.
      let gaveUp!: () => void;
      const waited = new Promise<void>((resolve) => (gaveUp = resolve));
      const giveUp = deps.setTimer(() => gaveUp(), CLOSE_WAIT_MS);
      giveUp.unref?.();
      await Promise.race([flush(), waited]);
      deps.clearTimer(giveUp);
    },
    stats() {
      let pendingLogs = 0;
      for (const e of sealed) pendingLogs += e.pending;
      for (const e of currentEntries()) pendingLogs += e.pending;
      return {
        pendingKeys,
        pendingLogs,
        sourcesThisMinute,
        flushing: flushing !== null,
        droppedLogs,
      };
    },
  };
}

/** The process-wide counter RawLogModel.create bumps and server.ts closes at shutdown. */
export const ingestCounter = createIngestCounter();
