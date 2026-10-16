/**
 * The per-minute ingest counter (services/ingest/ingestCounter.ts) with its
 * clock, timer and database writes injected, plus the RawLogModel.create hook
 * with pool.query stubbed. No Postgres needed; ingestCounter.db.test.ts covers
 * the real upsert, the prune and the ingest pool.
 * Run with `npm test` (tsx --test).
 */
import { test, describe } from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import pool, { isInIngestContext } from '../../config/database';
import { logger } from '../../utils/logger';
import { RawLogModel, type RawLog } from '../../models/RawLog';
import {
  CLOSE_WAIT_MS,
  FLUSH_KEYS,
  FLUSH_MS,
  MAX_PENDING_KEYS,
  MAX_SOURCES_PER_MINUTE,
  PRUNE_MS,
  createIngestCounter,
  ingestCounter,
  minuteBucket,
  type IngestCountRow,
  type IngestCounterDeps,
} from './ingestCounter';

const MINUTE = 60_000;
/** 2026-10-15T12:00:00Z, a minute boundary. */
const T0 = Date.UTC(2026, 9, 15, 12, 0, 0);

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
/** Let pending promise callbacks (a flush's write, its finally) run. */
const settle = () => sleep(0);

class FakeTimer {
  unrefd = false;
  cleared = false;
  fired = false;
  constructor(
    readonly fn: () => void,
    readonly ms: number
  ) {}
  unref() {
    this.unrefd = true;
  }
}

interface Rig {
  counter: ReturnType<typeof createIngestCounter>;
  writes: IngestCountRow[][];
  contexts: boolean[];
  prunes: number;
  timers: FakeTimer[];
  /** The timer armed and not yet fired or cleared, if any. */
  liveTimer(): FakeTimer | undefined;
  /** Fire the armed timer (fails the test when none is armed). */
  fireTimer(): void;
  setNow(ms: number): void;
}

const callCount = (fn: unknown) => (fn as { mock: { callCount(): number } }).mock.callCount();

function rig(t: TestContext, over: Partial<IngestCounterDeps> = {}): Rig {
  // Failed and stuck flushes are logged; keep the test output clean.
  t.mock.method(logger, 'error', () => logger);
  t.mock.method(logger, 'warn', () => logger);
  let now = T0;
  const timers: FakeTimer[] = [];
  const liveTimer = () => timers.find((x) => !x.cleared && !x.fired);
  const r: Rig = {
    writes: [],
    contexts: [],
    prunes: 0,
    timers,
    liveTimer,
    fireTimer: () => {
      const live = liveTimer();
      assert.ok(live, 'expected an armed timer');
      live.fired = true;
      live.fn();
    },
    setNow: (ms) => (now = ms),
    counter: undefined as unknown as Rig['counter'],
  };
  r.counter = createIngestCounter({
    now: () => now,
    write: async (rows) => {
      r.contexts.push(isInIngestContext());
      r.writes.push(rows);
    },
    prune: async () => {
      r.prunes++;
    },
    setTimer: (fn, ms) => {
      const timer = new FakeTimer(fn, ms);
      timers.push(timer);
      return timer;
    },
    clearTimer: (handle) => {
      (handle as FakeTimer).cleared = true;
    },
    ...over,
  });
  return r;
}

const shipperRow = (id: string) => ({ shipper_id: id, discovery_source_id: null, source_ip: '10.0.0.9' });
const directRow = (ip: string) => ({ shipper_id: null, discovery_source_id: null, source_ip: ip });

/** Sum every written row per minute|kind|key. */
function totals(writes: IngestCountRow[][]): Map<string, number> {
  const out = new Map<string, number>();
  for (const batch of writes) {
    for (const row of batch) {
      const k = `${row.minute.toISOString()}|${row.kind}|${row.key}`;
      out.set(k, (out.get(k) ?? 0) + row.logs);
    }
  }
  return out;
}

describe('ingest counter', () => {
  test('sources: a shipper id wins (lowercased), then the poller source, else the sender address', async (t) => {
    const r = rig(t);
    r.counter.bump({ shipper_id: 'AB12CD34', discovery_source_id: 7, source_ip: '10.0.0.1' });
    r.counter.bump({ shipper_id: 'ab12cd34', discovery_source_id: null, source_ip: '10.0.0.2' });
    r.counter.bump({ shipper_id: null, discovery_source_id: 7, source_ip: '10.0.0.1' });
    r.counter.bump({ shipper_id: null, discovery_source_id: null, source_ip: '10.0.0.1' });
    // An empty shipper id is not a shipper.
    r.counter.bump({ shipper_id: '', discovery_source_id: null, source_ip: '::1' });
    await r.counter.flush();
    assert.equal(r.writes.length, 1);
    assert.deepEqual(
      r.writes[0].map((x) => [x.kind, x.key, x.logs]).sort(),
      [
        ['direct', '10.0.0.1', 1],
        ['direct', '::1', 1],
        ['poller', '7', 1],
        ['shipper', 'ab12cd34', 2],
      ].sort(),
      'one row per source; the two spellings of one shipper id are one row'
    );
  });


  test('buckets by server minute: the same minute accumulates, the next minute is its own row', async (t) => {
    const r = rig(t);
    assert.equal(minuteBucket(T0 + MINUTE - 1), minuteBucket(T0));
    assert.equal(minuteBucket(T0 + MINUTE), minuteBucket(T0) + 1);

    r.counter.bump(shipperRow('ab12cd34'));
    r.setNow(T0 + MINUTE - 1);
    r.counter.bump(shipperRow('AB12CD34'));
    r.setNow(T0 + MINUTE);
    r.counter.bump(shipperRow('ab12cd34'));
    r.counter.bump(directRow('192.0.2.5'));
    await r.counter.flush();

    assert.equal(r.writes.length, 1);
    assert.deepEqual(
      [...totals(r.writes)].sort(),
      [
        ['2026-10-15T12:00:00.000Z|shipper|ab12cd34', 2],
        ['2026-10-15T12:01:00.000Z|direct|192.0.2.5', 1],
        ['2026-10-15T12:01:00.000Z|shipper|ab12cd34', 1],
      ].sort()
    );
  });

  test('a clock that steps back and forth still writes one row per minute and source', async (t) => {
    // Postgres refuses an upsert that touches the same row twice, which would
    // lose the whole batch.
    const r = rig(t);
    r.setNow(T0 + MINUTE);
    r.counter.bump(directRow('192.0.2.8'));
    r.setNow(T0);
    r.counter.bump(directRow('192.0.2.8'));
    r.setNow(T0 + MINUTE);
    r.counter.bump(directRow('192.0.2.8'));
    await r.counter.flush();
    assert.deepEqual(
      r.writes[0].map((x) => [x.minute.toISOString(), x.key, x.logs]).sort(),
      [
        ['2026-10-15T12:00:00.000Z', '192.0.2.8', 1],
        ['2026-10-15T12:01:00.000Z', '192.0.2.8', 2],
      ]
    );
  });

  test('100 busy sources are written once per timer interval, not once per few logs', async (t) => {
    // The regression: a 64-key trigger refilled within milliseconds with more
    // than 64 sources sending, so the counter wrote about one row per 2 logs.
    const r = rig(t);
    for (let round = 0; round < 200; round++) {
      for (let s = 0; s < 100; s++) r.counter.bump(directRow(`10.5.0.${s}`));
    }
    await settle();
    assert.equal(r.writes.length, 0, '20,000 logs from 100 sources: nothing written before the timer');
    assert.deepEqual(r.counter.stats(), {
      pendingKeys: 100,
      pendingLogs: 20_000,
      sourcesThisMinute: 100,
      flushing: false,
      droppedLogs: 0,
    });
    r.fireTimer();
    await settle();
    assert.equal(r.writes.length, 1);
    assert.equal(r.writes[0].length, 100, 'one row per source');
    assert.equal(totals(r.writes).get('2026-10-15T12:00:00.000Z|direct|10.5.0.7'), 200);
  });

  test(`writes as soon as ${FLUSH_KEYS} keys are pending, without waiting for the timer`, async (t) => {
    // Only reachable when keys from three or more minutes pile up (a slow
    // write, here a timer that never fires): within one minute the per-source
    // cap stops far below it.
    const r = rig(t);
    let n = 0;
    for (let m = 0; n < FLUSH_KEYS - 1; m++) {
      r.setNow(T0 + m * MINUTE);
      for (let s = 0; s < MAX_SOURCES_PER_MINUTE && n < FLUSH_KEYS - 1; s++, n++) r.counter.bump(directRow(`10.1.${s >> 8}.${s & 255}`));
    }
    // Repeats of a pending key don't add keys.
    for (let i = 0; i < 50; i++) r.counter.bump(directRow('10.1.0.0'));
    await settle();
    assert.equal(r.writes.length, 0);
    assert.equal(r.counter.stats().pendingKeys, FLUSH_KEYS - 1);

    r.counter.bump(directRow('10.1.9.9'));
    await settle();
    assert.equal(r.writes.length, 1);
    assert.equal(r.writes[0].length, FLUSH_KEYS);
    assert.equal(r.counter.stats().pendingKeys, 0);
  });

  test(`a quiet stream is written ${FLUSH_MS / 1000} s after its first count, on an unref()ed timer`, async (t) => {
    const r = rig(t);
    assert.equal(r.timers.length, 0, 'no timer while nothing is pending');
    r.counter.bump(shipperRow('ab12cd34'));
    r.counter.bump(shipperRow('ab12cd34'));
    assert.equal(r.timers.length, 1, 'one timer for the pending counts');
    assert.equal(r.timers[0].ms, FLUSH_MS);
    assert.equal(r.timers[0].unrefd, true, 'the timer must not keep the process alive');
    await settle();
    assert.equal(r.writes.length, 0, 'nothing is written before the timer fires');

    r.fireTimer();
    await settle();
    assert.equal(r.writes.length, 1);
    assert.equal(totals(r.writes).get('2026-10-15T12:00:00.000Z|shipper|ab12cd34'), 2);
    assert.equal(r.liveTimer(), undefined, 'no timer once nothing is pending');
  });

  test('the real timer it arms is unref()ed', async (t) => {
    t.mock.method(logger, 'error', () => logger);
    const handles: NodeJS.Timeout[] = [];
    const counter = createIngestCounter({
      write: async () => undefined,
      prune: async () => undefined,
      setTimer: (fn, ms) => {
        const h = setTimeout(fn, ms);
        handles.push(h);
        return h;
      },
    });
    counter.bump(directRow('192.0.2.1'));
    assert.equal(handles.length, 1);
    assert.equal(handles[0].hasRef(), false);
    await counter.close();
  });

  test(`counts at most ${MAX_SOURCES_PER_MINUTE} sources per minute; the rest go to ('overflow', '*')`, async (t) => {
    const r = rig(t);
    const extra = 120;
    for (let i = 0; i < MAX_SOURCES_PER_MINUTE + extra; i++) r.counter.bump(shipperRow(i.toString(16).padStart(8, '0')));
    // A source counted before the cap keeps its own row after it.
    r.counter.bump(shipperRow('00000000'));
    await r.counter.flush();

    const minute0 = [...totals(r.writes)].filter(([k]) => k.startsWith('2026-10-15T12:00:00.000Z|'));
    const own = minute0.filter(([k]) => k.includes('|shipper|'));
    assert.equal(own.length, MAX_SOURCES_PER_MINUTE);
    assert.equal(totals(r.writes).get('2026-10-15T12:00:00.000Z|shipper|00000000'), 2);
    assert.equal(totals(r.writes).get('2026-10-15T12:00:00.000Z|overflow|*'), extra);
    assert.equal(minute0.length, MAX_SOURCES_PER_MINUTE + 1);

    // The cap is per minute: the next minute counts new sources again.
    r.setNow(T0 + MINUTE);
    r.counter.bump(shipperRow('ffffffff'));
    await r.counter.flush();
    assert.equal(totals(r.writes).get('2026-10-15T12:01:00.000Z|shipper|ffffffff'), 1);
    assert.equal(totals(r.writes).get('2026-10-15T12:01:00.000Z|overflow|*'), undefined);
  });

  test('a failed write drops its counts: nothing is kept or retried, and later counts are written normally', async (t) => {
    let fail = true;
    const written: IngestCountRow[][] = [];
    const r = rig(t, {
      write: async (rows) => {
        if (fail) throw new Error('connection terminated');
        written.push(rows);
      },
    });
    for (let i = 0; i < 64; i++) r.counter.bump(directRow(`10.2.0.${i}`));
    for (let i = 0; i < 10; i++) r.counter.bump(directRow('10.2.0.0'));
    r.fireTimer();
    await settle();
    assert.deepEqual(
      { pending: r.counter.stats().pendingKeys, dropped: r.counter.stats().droppedLogs },
      { pending: 0, dropped: 64 + 10 }
    );
    assert.equal(callCount(logger.error), 1, 'the failed write is logged');
    assert.equal(r.liveTimer(), undefined, 'nothing pending, so nothing to retry');

    fail = false;
    r.counter.bump(directRow('10.2.0.0'));
    await r.counter.flush();
    assert.deepEqual(totals(written), new Map([['2026-10-15T12:00:00.000Z|direct|10.2.0.0', 1]]));
  });

  test(`a stuck write holds at most ${MAX_PENDING_KEYS} keys; counts for new keys are dropped meanwhile`, async (t) => {
    let release!: () => void;
    const stuck = new Promise<void>((resolve) => (release = resolve));
    const batches: number[] = [];
    let calls = 0;
    const r = rig(t, {
      write: async (rows) => {
        calls++;
        batches.push(rows.length);
        if (calls === 1) await stuck;
      },
    });
    // Enough minutes x sources to start a write (FLUSH_KEYS), then pass the
    // pending cap by 300 while that write hangs (a timer that never fires).
    const total = FLUSH_KEYS + MAX_PENDING_KEYS + 300;
    let n = 0;
    for (let m = 0; n < total; m++) {
      r.setNow(T0 + m * MINUTE);
      for (let s = 0; s < MAX_SOURCES_PER_MINUTE && n < total; s++, n++) {
        r.counter.bump(directRow(`10.3.${s >> 8}.${s & 255}`));
      }
    }
    await settle();
    assert.equal(calls, 1, 'one write at a time');
    assert.equal(r.counter.stats().pendingKeys, MAX_PENDING_KEYS);
    assert.equal(r.counter.stats().droppedLogs, 300);
    // A key already pending (this minute's first source) still counts.
    r.counter.bump(directRow('10.3.0.0'));
    assert.equal(r.counter.stats().droppedLogs, 300);
    assert.equal(r.counter.stats().pendingLogs, MAX_PENDING_KEYS + 1);

    release();
    await r.counter.flush();
    assert.deepEqual(batches, [FLUSH_KEYS, MAX_PENDING_KEYS]);
    assert.equal(r.counter.stats().pendingKeys, 0);
    assert.equal(callCount(logger.warn), 1, 'the loss is reported once');
  });

  test('one write at a time: counts that arrive during a write go in the next one', async (t) => {
    let release!: () => void;
    let calls = 0;
    const r = rig(t, {
      write: async (rows) => {
        calls++;
        r.writes.push(rows);
        if (calls === 1) await new Promise<void>((resolve) => (release = resolve));
      },
    });
    r.counter.bump(directRow('192.0.2.1'));
    r.fireTimer();
    await settle();
    assert.equal(calls, 1);

    r.counter.bump(directRow('192.0.2.2'));
    r.fireTimer(); // fires while the first write is still running
    await settle();
    assert.equal(calls, 1, 'no second write while the first runs');

    release();
    await settle();
    // The first write's end re-arms the timer for what arrived meanwhile.
    r.fireTimer();
    await settle();
    assert.equal(calls, 2);
    assert.deepEqual(r.writes[1].map((x) => x.key), ['192.0.2.2']);
  });

  test('every write runs on the ingest pool context', async (t) => {
    const r = rig(t);
    assert.equal(isInIngestContext(), false);
    r.counter.bump(directRow('192.0.2.1'));
    await r.counter.flush();
    r.counter.bump(directRow('192.0.2.1'));
    r.fireTimer();
    await settle();
    assert.deepEqual(r.contexts, [true, true]);
  });

  test('prunes from the flush path at most hourly, and only after a successful write', async (t) => {
    let fail = false;
    const r = rig(t, {
      write: async () => {
        if (fail) throw new Error('down');
      },
    });
    r.counter.bump(directRow('192.0.2.1'));
    await r.counter.flush();
    assert.equal(r.prunes, 1, 'the first write prunes');

    r.setNow(T0 + PRUNE_MS - 1);
    r.counter.bump(directRow('192.0.2.1'));
    await r.counter.flush();
    assert.equal(r.prunes, 1, 'not again within the hour');

    r.setNow(T0 + PRUNE_MS);
    fail = true;
    r.counter.bump(directRow('192.0.2.1'));
    await r.counter.flush();
    assert.equal(r.prunes, 1, 'not after a failed write');

    fail = false;
    r.counter.bump(directRow('192.0.2.1'));
    await r.counter.flush();
    assert.equal(r.prunes, 2, 'an hour on, after a successful write');
  });

  test('close() writes what is pending, clears the timer and ignores later counts', async (t) => {
    const r = rig(t);
    r.counter.bump(shipperRow('ab12cd34'));
    r.counter.bump(directRow('192.0.2.7'));
    assert.ok(r.liveTimer());
    await r.counter.close();
    assert.equal(r.writes.length, 1);
    assert.equal(r.writes[0].length, 2);
    assert.equal(r.liveTimer(), undefined, 'the timer is cleared');

    r.counter.bump(shipperRow('ab12cd34'));
    assert.equal(r.counter.stats().pendingKeys, 0, 'counts after close are ignored');
    assert.equal(r.liveTimer(), undefined, 'and arm no timer');
  });

  test('close() waits for a write already running, then writes what arrived meanwhile', async (t) => {
    let release!: () => void;
    let calls = 0;
    const r = rig(t, {
      write: async (rows) => {
        calls++;
        r.writes.push(rows);
        if (calls === 1) await new Promise<void>((resolve) => (release = resolve));
      },
    });
    for (let i = 0; i < 64; i++) r.counter.bump(directRow(`10.4.0.${i}`));
    r.fireTimer();
    await settle();
    r.counter.bump(directRow('192.0.2.9'));
    let closed = false;
    const closing = r.counter.close().then(() => (closed = true));
    await settle();
    assert.equal(closed, false);
    release();
    await closing;
    assert.equal(calls, 2);
    assert.deepEqual(r.writes[1].map((x) => x.key), ['192.0.2.9']);
  });

  test(`close() gives up after ${CLOSE_WAIT_MS / 1000} s when the database hangs, so shutdown never does`, async (t) => {
    const r = rig(t, { write: () => new Promise<void>(() => undefined) });
    r.counter.bump(directRow('192.0.2.3'));
    let closed = false;
    const closing = r.counter.close().then(() => (closed = true));
    await settle();
    assert.equal(closed, false, 'waits for the write');
    const giveUp = r.liveTimer();
    assert.ok(giveUp);
    assert.equal(giveUp.ms, CLOSE_WAIT_MS);
    assert.equal(giveUp.unrefd, true);
    r.fireTimer();
    await closing;
    assert.equal(closed, true);
  });

  test('a bump never throws into the ingest path', (t) => {
    const r = rig(t);
    assert.doesNotThrow(() => r.counter.bump({ shipper_id: 42 as unknown as string, discovery_source_id: null, source_ip: '1' }));
    assert.doesNotThrow(() => r.counter.bump(null as unknown as RawLog));
  });
});

describe('RawLogModel.create', () => {
  const stored: RawLog = {
    id: 1,
    timestamp: new Date(T0),
    raw_message: 'hello',
    source_ip: '192.0.2.10',
    facility: null,
    severity: null,
    hostname: 'h',
    app_name: 'a',
    shipper_id: 'ab12cd34',
    ingest_event_id: 'evt-1',
    discovery_source_id: null,
    created_at: new Date(T0),
  };
  const params = {
    timestamp: new Date(T0),
    raw_message: 'hello',
    source_ip: '192.0.2.10',
    shipper_id: 'ab12cd34',
    ingest_event_id: 'evt-1',
  };

  test('counts a stored row once, with the row it stored', async (t) => {
    t.mock.method(pool, 'query', async () => ({ rows: [stored], rowCount: 1 }));
    const bump = t.mock.method(ingestCounter, 'bump', () => undefined);
    const row = await RawLogModel.create(params);
    assert.equal(row, stored);
    assert.equal(bump.mock.callCount(), 1);
    assert.equal(bump.mock.calls[0].arguments[0], stored);
  });

  test('does not count a deduplicated push or poll (create returns null)', async (t) => {
    t.mock.method(pool, 'query', async () => ({ rows: [], rowCount: 0 }));
    const bump = t.mock.method(ingestCounter, 'bump', () => undefined);
    assert.equal(await RawLogModel.create(params), null);
    assert.equal(bump.mock.callCount(), 0);
  });

  test('does not count a failed insert', async (t) => {
    t.mock.method(logger, 'error', () => logger);
    t.mock.method(pool, 'query', async () => {
      throw new Error('insert failed');
    });
    const bump = t.mock.method(ingestCounter, 'bump', () => undefined);
    await assert.rejects(RawLogModel.create(params), /insert failed/);
    assert.equal(bump.mock.callCount(), 0);
  });
});
