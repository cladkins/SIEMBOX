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
  ESTABLISHED_SOURCES_PER_KIND,
  FLUSH_KEYS,
  FLUSH_MS,
  MAX_PENDING_KEYS,
  MAX_SOURCES_PER_KIND,
  NEW_SOURCES_PER_MINUTE,
  OVERFLOW_WARN_MS,
  PRUNE_MS,
  RECENT_MINUTES,
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
    loadRecent: async () => [],
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
const pollerRow = (id: number) => ({ shipper_id: null, discovery_source_id: id, source_ip: '10.0.0.9' });
/** A shipper id no one has used yet (what a sender spraying random tags sends). */
let sprayed = 0;
const sprayRow = () => shipperRow(`f${(sprayed++).toString(16).padStart(7, '0')}`);

/**
 * Bump one log each from `n` never-seen sources, NEW_SOURCES_PER_MINUTE of each
 * kind per minute (all a minute admits), from minute `fromMinute` on. Returns
 * the next unused minute.
 */
let distinct = 0;
function bumpDistinct(r: Rig, n: number, fromMinute = 0): number {
  let minute = fromMinute;
  for (let made = 0; made < n; minute++) {
    r.setNow(T0 + minute * MINUTE);
    for (let i = 0; i < NEW_SOURCES_PER_MINUTE && made < n; i++) {
      for (const row of [directRow(`d${distinct}`), shipperRow(`s${distinct}`), pollerRow(1e6 + distinct)]) {
        if (made === n) break;
        r.counter.bump(row);
        made++;
      }
      distinct++;
    }
  }
  return minute;
}

/** Rows written for one minute (T0 + m minutes). */
const rowsOfMinute = (writes: IngestCountRow[][], m: number) =>
  writes.flat().filter((x) => x.minute.getTime() === T0 + m * MINUTE);

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
      establishedSources: 100,
      flushing: false,
      droppedLogs: 0,
      overflowLogs: 0,
      overflowLogsByKind: { shipper: 0, poller: 0, direct: 0 },
    });
    r.fireTimer();
    await settle();
    assert.equal(r.writes.length, 1);
    assert.equal(r.writes[0].length, 100, 'one row per source');
    assert.equal(totals(r.writes).get('2026-10-15T12:00:00.000Z|direct|10.5.0.7'), 200);
  });

  test(`writes as soon as ${FLUSH_KEYS} keys are pending, without waiting for the timer`, async (t) => {
    // Only reachable when keys from three or more minutes pile up (a slow
    // write, here a timer that never fires): within one minute the per-kind
    // limits stop far below it.
    const r = rig(t);
    const next = bumpDistinct(r, FLUSH_KEYS - 1);
    // Repeats of a pending key don't add keys.
    for (let i = 0; i < 50; i++) r.counter.bump(directRow(`d${distinct - 1}`));
    await settle();
    assert.equal(r.writes.length, 0);
    assert.equal(r.counter.stats().pendingKeys, FLUSH_KEYS - 1);

    r.setNow(T0 + next * MINUTE);
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

  test(`a minute gives ${NEW_SOURCES_PER_MINUTE} never-seen sources of a kind their own row; the rest go to ('overflow', '*')`, async (t) => {
    const r = rig(t);
    const extra = 20;
    for (let i = 0; i < NEW_SOURCES_PER_MINUTE + extra; i++) r.counter.bump(shipperRow(i.toString(16).padStart(8, '0')));
    // A source counted before the limit keeps its own row after it.
    r.counter.bump(shipperRow('00000000'));
    await r.counter.flush();

    const minute0 = rowsOfMinute(r.writes, 0);
    assert.equal(minute0.filter((x) => x.kind === 'shipper').length, NEW_SOURCES_PER_MINUTE);
    assert.equal(totals(r.writes).get('2026-10-15T12:00:00.000Z|shipper|00000000'), 2);
    assert.equal(totals(r.writes).get('2026-10-15T12:00:00.000Z|overflow|*'), extra);
    assert.equal(minute0.length, NEW_SOURCES_PER_MINUTE + 1);

    // The limit is per minute, and the sources that had their own row are now
    // established: next minute they all get one again, and so do 100 new ones.
    r.setNow(T0 + MINUTE);
    for (let i = 0; i < NEW_SOURCES_PER_MINUTE * 2 + extra; i++) r.counter.bump(shipperRow(i.toString(16).padStart(8, '0')));
    await r.counter.flush();
    const minute1 = rowsOfMinute(r.writes, 1);
    assert.equal(minute1.filter((x) => x.kind === 'shipper').length, NEW_SOURCES_PER_MINUTE * 2);
    assert.equal(totals(r.writes).get('2026-10-15T12:01:00.000Z|overflow|*'), extra);
    assert.equal(r.counter.stats().establishedSources, NEW_SOURCES_PER_MINUTE * 2);
  });

  test('500 random shipper tags at the start of a minute push no established source into overflow', async (t) => {
    // The review's reproduction: one unauthenticated sender sprays random
    // [xxxxxxxx] tags to port 514 right after each minute starts.
    const r = rig(t);
    const legit = () => {
      for (let i = 1; i <= 10; i++) r.counter.bump(directRow(`127.0.1.${i}`));
      r.counter.bump(shipperRow('aaaaaaaa'));
    };
    legit(); // minute 0, before the spray
    for (let m = 1; m <= 3; m++) {
      r.setNow(T0 + m * MINUTE);
      for (let i = 0; i < 500; i++) r.counter.bump(sprayRow());
      r.setNow(T0 + m * MINUTE + 30_000);
      legit();
    }
    await r.counter.flush();
    for (let m = 1; m <= 3; m++) {
      const rows = rowsOfMinute(r.writes, m);
      const own = rows.filter((x) => x.key === 'aaaaaaaa' || x.key.startsWith('127.0.1.'));
      assert.equal(own.length, 11, `minute ${m}: each of the 11 sources has its own row`);
      assert.equal(rows.filter((x) => x.kind === 'shipper').length, NEW_SOURCES_PER_MINUTE + 1);
      assert.equal(rows.find((x) => x.kind === 'overflow')?.logs, 500 - NEW_SOURCES_PER_MINUTE);
    }
  });

  test('each kind has its own limits: a shipper-tag spray leaves never-seen direct senders and pollers their rows', async (t) => {
    const r = rig(t);
    for (let i = 0; i < 1000; i++) r.counter.bump(sprayRow());
    r.counter.bump(directRow('192.0.2.50'));
    r.counter.bump(pollerRow(3));
    await r.counter.flush();
    const t0 = totals(r.writes);
    assert.equal(t0.get('2026-10-15T12:00:00.000Z|direct|192.0.2.50'), 1);
    assert.equal(t0.get('2026-10-15T12:00:00.000Z|poller|3'), 1);
    assert.deepEqual(r.counter.stats().overflowLogsByKind, { shipper: 1000 - NEW_SOURCES_PER_MINUTE, poller: 0, direct: 0 });
  });

  test(`at most ${ESTABLISHED_SOURCES_PER_KIND} established sources per kind, and newcomers never displace one`, async (t) => {
    const r = rig(t);
    const legit = Array.from({ length: ESTABLISHED_SOURCES_PER_KIND }, (_, i) => `10.9.${i >> 8}.${i & 255}`);
    // Minutes 0-4: the 500 arrive, 100 new ones a minute, and stay.
    for (let m = 0; m < 5; m++) {
      r.setNow(T0 + m * MINUTE);
      for (const ip of legit.slice(0, (m + 1) * NEW_SOURCES_PER_MINUTE)) r.counter.bump(directRow(ip));
    }
    assert.equal(r.counter.stats().establishedSources, ESTABLISHED_SOURCES_PER_KIND);
    // Minutes 5-7: 1,000 never-seen addresses first, then the 500.
    for (let m = 5; m < 8; m++) {
      r.setNow(T0 + m * MINUTE);
      for (let i = 0; i < 1000; i++) r.counter.bump(directRow(`198.18.${m}.${i}`));
      for (const ip of legit) r.counter.bump(directRow(ip));
    }
    await r.counter.flush();
    for (let m = 5; m < 8; m++) {
      const rows = rowsOfMinute(r.writes, m);
      assert.equal(rows.filter((x) => x.key.startsWith('10.9.')).length, ESTABLISHED_SOURCES_PER_KIND, `minute ${m}`);
      assert.equal(rows.filter((x) => x.kind === 'direct').length, MAX_SOURCES_PER_KIND, `minute ${m}: 500 + 100 new`);
      // What restore() rebuilds the set from: the 500 rows say established,
      // the newcomers' (and the overflow row) do not.
      assert.ok(rows.filter((x) => x.key.startsWith('10.9.')).every((x) => x.established), `minute ${m}: the 500 are marked`);
      assert.deepEqual(
        rows.filter((x) => !x.key.startsWith('10.9.')).map((x) => x.established),
        Array(NEW_SOURCES_PER_MINUTE + 1).fill(false),
        `minute ${m}: the newcomers and the overflow row are not`
      );
    }
    // A newcomer that joined while there was room is marked from its first row.
    assert.ok(rowsOfMinute(r.writes, 0).every((x) => x.established));
    assert.equal(r.counter.stats().establishedSources, ESTABLISHED_SOURCES_PER_KIND, 'the newcomers were not remembered');
  });

  test(`a source is established for ${RECENT_MINUTES} minutes after its last own row, then competes as a new one`, async (t) => {
    const r = rig(t);
    r.counter.bump(directRow('192.0.2.1')); // minute 0
    r.setNow(T0 + MINUTE);
    r.counter.bump(directRow('192.0.2.2')); // minute 1
    // RECENT_MINUTES + 1: the new-source budget is gone before either logs again.
    const m = RECENT_MINUTES + 1;
    r.setNow(T0 + m * MINUTE);
    for (let i = 0; i < NEW_SOURCES_PER_MINUTE; i++) r.counter.bump(directRow(`198.18.0.${i}`));
    r.counter.bump(directRow('192.0.2.1'));
    r.counter.bump(directRow('192.0.2.2'));
    await r.counter.flush();
    const rows = rowsOfMinute(r.writes, m);
    assert.equal(rows.find((x) => x.key === '192.0.2.1'), undefined, `${RECENT_MINUTES + 1} minutes quiet: no longer established`);
    assert.equal(rows.find((x) => x.key === '192.0.2.2')?.logs, 1, `${RECENT_MINUTES} minutes quiet: still established`);
    assert.equal(rows.find((x) => x.kind === 'overflow')?.logs, 1);
  });

  test('a restart while a spray runs: restore() gives the sources the table shows their own rows back', async (t) => {
    // Ten shippers that logged every minute before the restart. Without
    // restore() they are new after it, and a spray at the start of each
    // minute takes every new-shipper slot first.
    const legit = Array.from({ length: 10 }, (_, i) => `aaaaaa${i.toString(16).padStart(2, '0')}`);
    const before = minuteBucket(T0) - 1;
    const run = async (restore: boolean) => {
      const r = rig(t, {
        loadRecent: async () => legit.map((key) => ({ kind: 'shipper' as const, key, minute: before })),
      });
      if (restore) await r.counter.restore();
      for (let i = 0; i < 500; i++) r.counter.bump(sprayRow());
      for (const id of legit) r.counter.bump(shipperRow(id));
      await r.counter.flush();
      return rowsOfMinute(r.writes, 0).filter((x) => legit.includes(x.key)).length;
    };
    assert.equal(await run(false), 0, 'precondition: without restore() the spray takes every slot');
    assert.equal(await run(true), legit.length);
  });

  test('restore() keeps the per-kind limit, skips stale and malformed entries, and wins over sources counted since start', async (t) => {
    const now = minuteBucket(T0);
    const restored = [
      { kind: 'direct' as const, key: '192.0.2.200', minute: now - RECENT_MINUTES - 1 }, // stale
      { kind: 'poller' as const, key: 'not-a-number', minute: now - 1 },
      { kind: 'poller' as const, key: '7', minute: now - 1 },
      ...Array.from({ length: ESTABLISHED_SOURCES_PER_KIND }, (_, i) => ({
        kind: 'direct' as const,
        key: `10.8.${i >> 8}.${i & 255}`,
        minute: now - 1 - (i % 30),
      })),
    ];
    const r = rig(t, { loadRecent: async () => restored });
    // Counted between start and restore(): five new direct senders.
    for (let i = 0; i < 5; i++) r.counter.bump(directRow(`198.18.9.${i}`));
    await r.counter.restore();
    assert.equal(r.counter.stats().establishedSources, ESTABLISHED_SOURCES_PER_KIND + 1, '500 direct (the restored ones) and poller 7');

    // Next minute, new sources of both kinds take every new slot first.
    r.setNow(T0 + MINUTE);
    for (let i = 0; i < NEW_SOURCES_PER_MINUTE; i++) {
      r.counter.bump(directRow(`198.18.10.${i}`));
      r.counter.bump(pollerRow(1000 + i));
    }
    r.counter.bump(pollerRow(7));
    r.counter.bump(directRow('10.8.0.0'));
    r.counter.bump(directRow('10.8.1.243')); // the 500th
    r.counter.bump(directRow('192.0.2.200'));
    r.counter.bump(directRow('198.18.9.0'));
    await r.counter.flush();
    const t1 = totals(r.writes);
    const m1 = '2026-10-15T12:01:00.000Z';
    assert.equal(t1.get(`${m1}|poller|7`), 1, 'a restored poller id matches the rows its number');
    assert.equal(t1.get(`${m1}|direct|10.8.0.0`), 1);
    assert.equal(t1.get(`${m1}|direct|10.8.1.243`), 1);
    assert.equal(t1.get(`${m1}|direct|192.0.2.200`), undefined, 'stale: not restored');
    assert.equal(t1.get(`${m1}|direct|198.18.9.0`), undefined, 'counted since start, but the restored ones filled the limit');
    assert.equal(t1.get(`${m1}|overflow|*`), 2);
  });

  test('restore() that cannot read the table logs it and leaves counting as it was', async (t) => {
    const r = rig(t, {
      loadRecent: async () => {
        throw new Error('relation "ingest_source_minute" does not exist');
      },
    });
    await assert.doesNotReject(r.counter.restore());
    assert.equal(callCount(logger.warn), 1);
    r.counter.bump(directRow('192.0.2.1'));
    await r.counter.flush();
    assert.deepEqual(totals(r.writes), new Map([['2026-10-15T12:00:00.000Z|direct|192.0.2.1', 1]]));
  });

  test('a sustained spray of every kind keeps each minute bounded, and the per-minute total exact', async (t) => {
    const r = rig(t);
    let logs = 0;
    for (let m = 0; m < 8; m++) {
      r.setNow(T0 + m * MINUTE);
      for (let i = 0; i < 2000; i++) {
        r.counter.bump(sprayRow());
        r.counter.bump(directRow(`s${m}-${i}`));
        r.counter.bump(pollerRow(m * 10_000 + i));
        logs += 3;
      }
      await r.counter.flush();
    }
    for (let m = 0; m < 8; m++) {
      const rows = rowsOfMinute(r.writes, m);
      for (const kind of ['shipper', 'poller', 'direct']) {
        assert.ok(rows.filter((x) => x.kind === kind).length <= MAX_SOURCES_PER_KIND, `minute ${m}, ${kind}`);
      }
      assert.equal(rows.filter((x) => x.kind === 'overflow').length, 1);
      assert.equal(rows.reduce((n, x) => n + x.logs, 0), 6000, `minute ${m}: every log is counted somewhere`);
    }
    assert.equal(r.counter.stats().establishedSources, 3 * ESTABLISHED_SOURCES_PER_KIND);
    assert.equal(r.counter.stats().overflowLogs, logs - 8 * 3 * NEW_SOURCES_PER_MINUTE);
  });

  test(`overflow is logged at the first write that has it, then at most once per ${OVERFLOW_WARN_MS / 60_000} minutes`, async (t) => {
    const r = rig(t);
    const warn = logger.warn as unknown as { mock: { calls: Array<{ arguments: unknown[] }> } };
    const overflowWarnings = () => warn.mock.calls.filter((c) => /counted as overflow/.test(String(c.arguments[0])));
    for (let i = 0; i < NEW_SOURCES_PER_MINUTE; i++) r.counter.bump(sprayRow());
    await r.counter.flush();
    assert.equal(overflowWarnings().length, 0, 'nothing over the limit yet');

    for (let i = 0; i < 30; i++) r.counter.bump(sprayRow());
    r.counter.bump(directRow('192.0.2.1'));
    await r.counter.flush();
    assert.equal(overflowWarnings().length, 1);
    assert.deepEqual(overflowWarnings()[0].arguments[1], {
      overflowLogs: 30,
      byKind: { shipper: 30, poller: 0, direct: 0 },
      minutes: 1,
    });

    // Later minutes overflow too: no new line within the hour...
    for (let m = 1; m < 4; m++) {
      r.setNow(T0 + m * MINUTE);
      for (let i = 0; i < NEW_SOURCES_PER_MINUTE + 5; i++) r.counter.bump(sprayRow());
      await r.counter.flush();
    }
    assert.equal(overflowWarnings().length, 1);
    // ...then one, with everything since the last.
    r.setNow(T0 + OVERFLOW_WARN_MS);
    for (let i = 0; i < NEW_SOURCES_PER_MINUTE + 2; i++) r.counter.bump(sprayRow());
    await r.counter.flush();
    assert.equal(overflowWarnings().length, 2);
    assert.deepEqual(overflowWarnings()[1].arguments[1], {
      overflowLogs: 3 * 5 + 2,
      byKind: { shipper: 17, poller: 0, direct: 0 },
      minutes: 4,
    });
    assert.equal(r.counter.stats().overflowLogs, 30 + 17);
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
    // Enough minutes x sources to start a write (FLUSH_KEYS), then fill the
    // pending cap while that write hangs (a timer that never fires)...
    const next = bumpDistinct(r, FLUSH_KEYS + MAX_PENDING_KEYS - 1);
    r.setNow(T0 + next * MINUTE);
    r.counter.bump(directRow('192.0.2.99'));
    await settle();
    assert.equal(calls, 1, 'one write at a time');
    assert.equal(r.counter.stats().pendingKeys, MAX_PENDING_KEYS);
    // ...so counts for new keys are dropped,
    for (let i = 0; i < 150; i++) r.counter.bump(directRow(`198.18.1.${i}`));
    assert.equal(r.counter.stats().pendingKeys, MAX_PENDING_KEYS);
    assert.equal(r.counter.stats().droppedLogs, 150);
    // while a key already pending still counts.
    r.counter.bump(directRow('192.0.2.99'));
    assert.equal(r.counter.stats().droppedLogs, 150);
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

  test('every write runs on the ingest pool context, except the last one after the ingest pool has closed', async (t) => {
    const r = rig(t);
    assert.equal(isInIngestContext(), false);
    r.counter.bump(directRow('192.0.2.1'));
    await r.counter.flush();
    r.counter.bump(directRow('192.0.2.1'));
    r.fireTimer();
    await settle();
    r.counter.bump(directRow('192.0.2.1'));
    await r.counter.close(async () => r.counter.bump(directRow('192.0.2.1')));
    assert.deepEqual(r.contexts, [true, true, true, false]);
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

  test('close() writes what is pending (on the ingest pool when it is not told to stop ingest) and clears the timer', async (t) => {
    const r = rig(t);
    r.counter.bump(shipperRow('ab12cd34'));
    r.counter.bump(directRow('192.0.2.7'));
    assert.ok(r.liveTimer());
    await r.counter.close();
    assert.equal(r.writes.length, 1);
    assert.equal(r.writes[0].length, 2);
    assert.deepEqual(r.contexts, [true]);
    assert.equal(r.liveTimer(), undefined, 'the timer is cleared');

    r.counter.bump(shipperRow('ab12cd34'));
    assert.equal(r.liveTimer(), undefined, 'a count after close() arms no timer');
  });

  test('close(stopIngest) writes what it has, counts every log stored until ingest has stopped, then writes those on the main pool', async (t) => {
    // The review's reproduction: SIGTERM under load. The syslog backlog the
    // drain gave up on, and HTTP push batches in flight, still store logs
    // until the ingest pool closes; each of them must be counted.
    const r = rig(t);
    r.counter.bump(directRow('192.0.2.1'));
    let stopped!: () => void;
    let stops = 0;
    const closing = r.counter.close(() => {
      stops++;
      return new Promise<void>((resolve) => (stopped = resolve));
    });
    await settle();
    assert.equal(stops, 1);
    assert.deepEqual(
      r.writes.map((w) => w.map((x) => [x.key, x.logs])),
      [[['192.0.2.1', 1]]],
      'what was counted is written first, on the ingest pool'
    );

    // Stored meanwhile:
    const timersBefore = r.timers.length;
    r.counter.bump(directRow('192.0.2.1'));
    r.counter.bump(shipperRow('ab12cd34'));
    assert.equal(r.timers.length, timersBefore, 'and they arm no flush timer of their own');

    stopped();
    await closing;
    assert.equal(r.writes.length, 2);
    assert.deepEqual(
      totals(r.writes),
      new Map([
        ['2026-10-15T12:00:00.000Z|direct|192.0.2.1', 2],
        ['2026-10-15T12:00:00.000Z|shipper|ab12cd34', 1],
      ])
    );
    assert.deepEqual(r.contexts, [true, false], 'the last on the main pool: the ingest pool is closed by then');
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
    let stops = 0;
    const closing = r.counter
      .close(async () => {
        stops++;
      })
      .then(() => (closed = true));
    await settle();
    assert.equal(closed, false);
    assert.equal(stops, 0, 'ingest is stopped only once the running write has finished on the ingest pool');
    release();
    await closing;
    assert.equal(stops, 1);
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

  test(`close() gives up after ${CLOSE_WAIT_MS / 1000} s in all when stopping ingest hangs`, async (t) => {
    const r = rig(t);
    r.counter.bump(directRow('192.0.2.3'));
    let closed = false;
    const closing = r.counter.close(() => new Promise<void>(() => undefined)).then(() => (closed = true));
    await settle();
    assert.equal(closed, false);
    assert.equal(r.writes.length, 1, 'what was counted before is written');
    r.counter.bump(directRow('192.0.2.3'));
    assert.equal(r.liveTimer()?.ms, CLOSE_WAIT_MS);
    r.fireTimer();
    await closing;
    assert.equal(closed, true);
    assert.equal(r.writes.length, 1, 'a log stored while ingest would not stop is not');
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
