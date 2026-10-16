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
 * - Sources per minute are limited per kind (shipper, poller, direct), so that
 *   spraying random shipper tags, which anyone who can reach port 514 can do,
 *   can't grow the table or push other sources out of it:
 *   - A source that had its own row within the last RECENT_MINUTES is
 *     established, and always gets its own row. At most
 *     ESTABLISHED_SOURCES_PER_KIND are remembered per kind; a source joins only
 *     while there is room, and leaves only after RECENT_MINUTES without logs,
 *     so newcomers never displace an established source. server.ts calls
 *     restore() at startup, which reloads them from the table (the steadiest
 *     first), so a restart while a spray is running doesn't hand every slot to
 *     the spray.
 *   - Any other source gets its own row only while fewer than
 *     NEW_SOURCES_PER_MINUTE such sources of its kind have had one this minute.
 *   - Logs from the rest count into ('overflow', '*'). Per-minute totals stay
 *     exact; only the split by source is lost. The first time that happens, and
 *     then at most once per OVERFLOW_WARN_MS, it is logged with the logs
 *     affected by kind (stats() has the running totals).
 *   So a minute has at most 3 x (500 + 100) source rows plus the overflow row,
 *   and never more rows than logs.
 * - Rows older than RETENTION_HOURS are deleted from the flush path, at most
 *   once per PRUNE_MS.
 * - server.ts calls close(closeIngestPool) at shutdown, once syslog has
 *   drained and the jobs have stopped. It writes what is pending, keeps
 *   counting while it closes the ingest pool (an HTTP push batch can still be
 *   storing logs, and so can the syslog messages that were running when the
 *   drain gave up), and then
 *   writes those logs too, on the main pool. It waits at most CLOSE_WAIT_MS in
 *   all; if closing the ingest pool takes longer, the logs stored meanwhile go
 *   uncounted (the failed write is logged). A crash loses up to FLUSH_MS of
 *   counts.
 *
 * Buckets are server ingest time (Date.now()), never the sender's timestamp,
 * so sender clock skew can't distort them.
 */
import { query, runInIngestContext } from '../../config/database';
import { logger } from '../../utils/logger';
import type { RawLog } from '../../models/RawLog';

/** Write pending counts at most this long after the first one arrives. */
export const FLUSH_MS = 5000;
/** Sources per kind that keep their own row while they log at least once per RECENT_MINUTES. */
export const ESTABLISHED_SOURCES_PER_KIND = 500;
/** Sources per kind and minute that get their own row without being established. */
export const NEW_SOURCES_PER_MINUTE = 100;
/** A source that had its own row within this many minutes is established. */
export const RECENT_MINUTES = 60;
/** Source rows per kind in one minute, at most. */
export const MAX_SOURCES_PER_KIND = ESTABLISHED_SOURCES_PER_KIND + NEW_SOURCES_PER_MINUTE;
/**
 * ...or as soon as this many keys (minute + source) are pending. A safety net
 * only: a 5 s window spans at most two minutes, so the per-kind limits keep it
 * to 2 x (3 x 600 + 1) keys, and in normal running the timer does every write.
 * Only a slow write lets more pile up. (A small trigger such as
 * parser_match_hourly's 64 keys would defeat the batching here: every active
 * source adds a key each minute, so with more than 64 sources the keys refill
 * within milliseconds of a write, and the counter wrote back-to-back: one row
 * for every 2-3 logs.)
 */
export const FLUSH_KEYS = 4096;
/** Keys held while a flush is stuck; counts for new keys are dropped past this. */
export const MAX_PENDING_KEYS = 8192;
/** Rows older than this are pruned. */
export const RETENTION_HOURS = 48;
/** Prune at most this often. */
export const PRUNE_MS = 60 * 60 * 1000;
/** close() waits at most this long in all: a shutdown never hangs on statistics. */
export const CLOSE_WAIT_MS = 5000;
/** Log that sources went to the overflow row at most this often. */
export const OVERFLOW_WARN_MS = 60 * 60 * 1000;

export const OVERFLOW_KEY = '*';

export type IngestSourceKind = 'shipper' | 'poller' | 'direct' | 'overflow';
/** The kinds a source can be; each has its own limits. */
export type CountedSourceKind = Exclude<IngestSourceKind, 'overflow'>;

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

/** The upsert. On the ingest pool inside runInIngestContext (every write but the one at shutdown), else the main pool. */
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

/**
 * The sources that had their own row in the last $1 minutes, at most $2 per
 * kind: those present in the most minutes first (a spray's one-off tags come
 * last), then the busiest. Least recent first, as the established set keeps
 * them. Reads at most 60 minutes of rows through the primary key.
 */
export const RECENT_SOURCES_SQL = `
  SELECT source_kind AS kind, source_key AS key, last_minute
    FROM (SELECT source_kind, source_key,
                 (EXTRACT(EPOCH FROM MAX(minute)) / 60)::bigint AS last_minute,
                 ROW_NUMBER() OVER (PARTITION BY source_kind
                                    ORDER BY COUNT(*) DESC, SUM(logs) DESC, MAX(minute) DESC, source_key) AS rank
            FROM ingest_source_minute
           WHERE minute >= date_trunc('minute', NOW()) - make_interval(mins => $1)
             AND source_kind IN ('shipper', 'poller', 'direct')
           GROUP BY source_kind, source_key) ranked
   WHERE rank <= $2
   ORDER BY last_minute, source_kind, source_key`;

/** A source restore() reads back: `minute` is the last one it had its own row in (minutes since the epoch). */
export interface RecentSource {
  kind: CountedSourceKind;
  key: string;
  minute: number;
}

async function loadRecentRows(): Promise<RecentSource[]> {
  const result = await query(RECENT_SOURCES_SQL, [RECENT_MINUTES, ESTABLISHED_SOURCES_PER_KIND]);
  return result.rows.map((r: { kind: CountedSourceKind; key: string; last_minute: string }) => ({
    kind: r.kind,
    key: r.key,
    minute: Number(r.last_minute),
  }));
}

interface TimerHandle {
  unref?: () => unknown;
}

export interface IngestCounterDeps {
  now(): number;
  write(rows: IngestCountRow[]): Promise<void>;
  prune(): Promise<void>;
  /** For restore(): the established sources the table shows. */
  loadRecent(): Promise<RecentSource[]>;
  setTimer(fn: () => void, ms: number): TimerHandle;
  clearTimer(handle: TimerHandle): void;
}

const defaultDeps: IngestCounterDeps = {
  now: () => Date.now(),
  write: writeRows,
  prune: pruneRows,
  loadRecent: loadRecentRows,
  setTimer: (fn, ms) => setTimeout(fn, ms),
  clearTimer: (handle) => clearTimeout(handle as NodeJS.Timeout),
};

export type CountsByKind = Record<CountedSourceKind, number>;

export interface IngestCounterStats {
  /** Keys (minute + source) waiting for the next flush. */
  pendingKeys: number;
  /** Logs those keys hold. */
  pendingLogs: number;
  /** Distinct sources with their own row in the current minute (the overflow row excluded). */
  sourcesThisMinute: number;
  /** Established sources remembered, all kinds (at most ESTABLISHED_SOURCES_PER_KIND per kind). */
  establishedSources: number;
  /** A flush is running. */
  flushing: boolean;
  /** Logs whose counts were lost (failed flushes, or the pending cap). Since start. */
  droppedLogs: number;
  /** Logs counted into the overflow row because their source was over its kind's limit. Since start. */
  overflowLogs: number;
  /** overflowLogs by the kind of source they came from. */
  overflowLogsByKind: CountsByKind;
}

export interface IngestCounter {
  /** Count one stored log. Synchronous; never throws. */
  bump(row: IngestSourceFields): void;
  /** Write what is pending now (after any flush already running). Never rejects. */
  flush(): Promise<void>;
  /**
   * For shutdown: stop the timer, let a write already running finish, and
   * write what is pending on the ingest pool. Then, if `stopIngest` is given
   * (server.ts passes closeIngestPool, after which no log can be stored), run
   * it and write the logs stored meanwhile on the main pool. Logs keep being
   * counted until that last write takes them. Waits at most CLOSE_WAIT_MS in
   * all. Never rejects.
   */
  close(stopIngest?: () => Promise<unknown>): Promise<void>;
  /**
   * For startup: reload the established sources from the table (on the main
   * pool), so a restart keeps them. Merges with any counted since start. Logs
   * and moves on if the read fails. Never rejects.
   */
  restore(): Promise<void>;
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

/** One kind of source, with its own limits. */
interface KindState {
  kind: CountedSourceKind;
  /** This minute's sources with their own row, keyed by the row's own value. */
  current: Map<string | number, Entry>;
  /**
   * Established sources: the minute each last had its own row, least recent
   * first. At most ESTABLISHED_SOURCES_PER_KIND; entries older than
   * RECENT_MINUTES are dropped when a minute starts.
   */
  established: Map<string | number, number>;
  /** The table's spelling of a key (restore() reads text) to the map's: poller ids are numbers. */
  keyOf(text: string): string | number | null;
  /** Sources that got their own row this minute without being established. */
  newThisMinute: number;
  /** Logs of this kind counted into overflow, since start. */
  overflowLogs: number;
}

const newKindState = (kind: CountedSourceKind, keyOf: KindState['keyOf'] = (text) => text): KindState => ({
  kind,
  current: new Map(),
  established: new Map(),
  keyOf,
  newThisMinute: 0,
  overflowLogs: 0,
});

/** discovery_source_id is an integer column; anything else in the table is not a poller this counter could have seen. */
const pollerKey = (text: string): number | null => (/^[1-9][0-9]{0,9}$/.test(text) ? Number(text) : null);

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

  let currentMinute = -1;
  const shippers = newKindState('shipper');
  const pollers = newKindState('poller', pollerKey);
  const directs = newKindState('direct');
  const kinds = [shippers, pollers, directs];
  let overflow: Entry | null = null;
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
  /** When overflow was last logged, the totals by kind then, and minutes with overflow since. */
  let lastOverflowWarning = -Infinity;
  let overflowAtWarning: CountsByKind = { shipper: 0, poller: 0, direct: 0 };
  let overflowMinutesSinceWarning = 0;

  function* currentEntries(): Generator<Entry> {
    for (const s of kinds) yield* s.current.values();
    if (overflow) yield overflow;
  }

  /**
   * A new minute: keep the last one's unwritten entries for the next write,
   * forget sources not seen for RECENT_MINUTES, and start empty.
   */
  function startMinute(minute: number): void {
    for (const e of currentEntries()) if (e.pending > 0) sealed.push(e);
    for (const s of kinds) {
      s.current.clear();
      s.newThisMinute = 0;
      // Least recent first; stops at the first one still recent.
      for (const [key, last] of s.established) {
        if (last >= minute - RECENT_MINUTES) break;
        s.established.delete(key);
      }
    }
    overflow = null;
    currentMinute = minute;
  }

  /** A source not yet seen this minute: its own entry if its kind's limits allow, else the overflow entry. */
  function addSource(s: KindState, key: string | number): Entry {
    const last = s.established.get(key);
    if (last === undefined || last < currentMinute - RECENT_MINUTES) {
      if (s.newThisMinute >= NEW_SOURCES_PER_MINUTE) {
        if (!overflow) {
          overflow = { minute: currentMinute, kind: 'overflow', key: OVERFLOW_KEY, pending: 0 };
          overflowMinutesSinceWarning++;
        }
        return overflow;
      }
      s.newThisMinute++;
    }
    // Established now: one already remembered moves to the most recent end;
    // a new one is remembered only while there is room.
    if (last !== undefined) s.established.delete(key);
    if (last !== undefined || s.established.size < ESTABLISHED_SOURCES_PER_KIND) s.established.set(key, currentMinute);
    const entry: Entry = { minute: currentMinute, kind: s.kind, key, pending: 0 };
    s.current.set(key, entry);
    return entry;
  }

  /**
   * restore(): the table's established sources (least recent first) go before
   * any counted since start, which are more recent. Over the limit, the
   * restored ones win: what started since could be a spray.
   */
  function mergeEstablished(s: KindState, restored: RecentSource[]): void {
    const merged = new Map<string | number, number>();
    const oldest = currentMinute - RECENT_MINUTES;
    for (const r of [...restored].sort((a, b) => a.minute - b.minute)) {
      const key = s.keyOf(r.key);
      if (key === null || s.established.has(key) || r.minute < oldest || merged.size >= ESTABLISHED_SOURCES_PER_KIND) continue;
      merged.set(key, r.minute);
    }
    for (const [key, last] of s.established) {
      if (merged.size >= ESTABLISHED_SOURCES_PER_KIND) break;
      merged.set(key, last);
    }
    s.established = merged;
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

  async function writeBatch(rows: IngestCountRow[], onIngestPool = true): Promise<boolean> {
    try {
      await (onIngestPool ? runInIngestContext(() => deps.write(rows)) : deps.write(rows));
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

  function overflowByKind(): CountsByKind {
    return { shipper: shippers.overflowLogs, poller: pollers.overflowLogs, direct: directs.overflowLogs };
  }

  /** The first overflow, then at most once per OVERFLOW_WARN_MS: what went to the overflow row since the last warning. */
  function warnOverflowIfDue(): void {
    const totals = overflowByKind();
    const since: CountsByKind = {
      shipper: totals.shipper - overflowAtWarning.shipper,
      poller: totals.poller - overflowAtWarning.poller,
      direct: totals.direct - overflowAtWarning.direct,
    };
    const logs = since.shipper + since.poller + since.direct;
    if (logs === 0 || deps.now() - lastOverflowWarning < OVERFLOW_WARN_MS) return;
    logger.warn(
      `Per-minute ingest counts: more sources than are counted one by one (per kind, up to ` +
        `${ESTABLISHED_SOURCES_PER_KIND} that logged in the last ${RECENT_MINUTES} minutes plus ` +
        `${NEW_SOURCES_PER_MINUTE} new ones a minute); the rest were counted as overflow`,
      { overflowLogs: logs, byKind: since, minutes: overflowMinutesSinceWarning }
    );
    lastOverflowWarning = deps.now();
    overflowAtWarning = totals;
    overflowMinutesSinceWarning = 0;
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
      warnOverflowIfDue();
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
    try {
      const minute = Math.floor(deps.now() / 60_000);
      if (minute !== currentMinute) startMinute(minute);

      let s: KindState;
      let key: string | number;
      if (row.shipper_id) {
        s = shippers;
        key = row.shipper_id;
      } else if (row.discovery_source_id != null) {
        s = pollers;
        key = row.discovery_source_id;
      } else {
        s = directs;
        key = row.source_ip ?? '';
      }
      const entry = s.current.get(key) ?? addSource(s, key);

      if (entry.pending === 0) {
        if (pendingKeys >= MAX_PENDING_KEYS) {
          droppedLogs++;
          cappedSinceReport++;
          return;
        }
        pendingKeys++;
      }
      entry.pending++;
      if (entry === overflow) s.overflowLogs++;

      // After close() only its own last write runs.
      if (closed) return;
      if (pendingKeys >= FLUSH_KEYS) void startFlush();
      else armTimer();
    } catch {
      // Counting must never fail an ingest.
    }
  }

  return {
    bump,
    flush,
    async close(stopIngest) {
      closed = true;
      disarmTimer();
      // A database that hangs (connection retries run for up to 30 s) must not
      // hold the shutdown up; whatever is still unwritten then is lost.
      let gaveUp!: () => void;
      const waited = new Promise<void>((resolve) => (gaveUp = resolve));
      const giveUp = deps.setTimer(() => gaveUp(), CLOSE_WAIT_MS);
      giveUp.unref?.();
      const last = (async () => {
        // One write at a time: a write already running finishes first, and
        // starts no other now that the counter is closed.
        while (flushing) await flushing;
        // What is counted so far, on the ingest pool as usual, so a slow stop
        // below can't cost more than the logs stored during it.
        if (pendingKeys > 0) await writeBatch(takePending());
        if (!stopIngest) return;
        await Promise.resolve().then(stopIngest).catch(() => undefined);
        // Nothing can be stored any more: the logs stored meanwhile, on the
        // main pool, since the ingest pool is closed.
        if (pendingKeys > 0) await writeBatch(takePending(), false);
      })();
      await Promise.race([last, waited]);
      deps.clearTimer(giveUp);
    },
    async restore() {
      let restored: RecentSource[];
      try {
        restored = await deps.loadRecent();
      } catch (error) {
        logger.warn('Could not read the recent sources of the per-minute ingest counts; counting starts afresh', {
          error: error instanceof Error ? error.message : String(error),
        });
        return;
      }
      // The minute the restored entries are judged against, if nothing has
      // been counted yet.
      if (currentMinute < 0) currentMinute = minuteBucket(deps.now());
      for (const s of kinds) mergeEstablished(s, restored.filter((r) => r.kind === s.kind));
    },
    stats() {
      let pendingLogs = 0;
      for (const e of sealed) pendingLogs += e.pending;
      for (const e of currentEntries()) pendingLogs += e.pending;
      const byKind = overflowByKind();
      return {
        pendingKeys,
        pendingLogs,
        sourcesThisMinute: shippers.current.size + pollers.current.size + directs.current.size,
        establishedSources: shippers.established.size + pollers.established.size + directs.established.size,
        flushing: flushing !== null,
        droppedLogs,
        overflowLogs: byKind.shipper + byKind.poller + byKind.direct,
        overflowLogsByKind: byKind,
      };
    },
  };
}

/** The process-wide counter RawLogModel.create bumps and server.ts closes at shutdown. */
export const ingestCounter = createIngestCounter();
