/**
 * The per-minute ingest counter against a real Postgres (migration 041): the
 * flush writes on the ingest pool, upserts accumulate across flushes, buckets
 * land on the right instant whatever the session time zone, rows past 48 h are
 * pruned, RawLogModel.create counts a stored log once and its deduplicated
 * repeat not at all, restore() reads the established sources back (also after
 * a steady fixed-tag spray, whose tags it must leave out), and the
 * shutdown path counts logs whose inserts were still running when it started.
 * Skips itself when Postgres (or that schema) isn't
 * reachable. Every key used here is unique to this run, and its rows are
 * removed again (checked at the end). Run with `npm test` (tsx --test).
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import pool, { closeIngestPool, closePools, getPoolStats, runInIngestContext } from '../../config/database';
import { RawLogModel } from '../../models/RawLog';
import {
  RECENT_SOURCES_SQL,
  createIngestCounter,
  ingestCounter,
  loadRecentRows,
  minuteBucket,
  writeRows,
  type IngestCountRow,
} from './ingestCounter';

let dbReady = false;
const tag = crypto.randomBytes(4).toString('hex');
/** A direct-source key no real sender has: these rows are this run's alone. */
const key = (name: string) => `dbtest-${tag}-${name}`;
/** Starts with letters, so the upper-case spelling the push test stores differs from it. */
const shipperId = `ab${crypto.randomBytes(3).toString('hex')}`;
/** The shipper the shutdown test pushes as. */
const shutdownShipperId = `cd${crypto.randomBytes(3).toString('hex')}`;
/** The raw_message prefix of every raw_logs row this run stores... */
const message = `ingest-counter db test ${tag}`;
/** ...each from one of these (TEST-NET) addresses, so cleanup goes by the source_ip index, whatever the shipper id's spelling. */
const testAddresses = ['192.0.2.44', '192.0.2.45'];

before(async () => {
  try {
    await pool.query('SELECT 1 FROM ingest_source_minute LIMIT 1');
    dbReady = true;
  } catch {
    dbReady = false;
  }
});

after(async () => {
  try {
    if (dbReady) {
      await pool.query(`DELETE FROM ingest_source_minute WHERE source_key LIKE $1 OR source_key = ANY($2)`, [
        `dbtest-${tag}-%`,
        [shipperId, shutdownShipperId],
      ]);
      // By address and message, not shipper id: the push test stores its
      // shipper id upper-cased.
      const mine = `source_ip = ANY($1) AND raw_message LIKE $2`;
      await pool.query(`DELETE FROM raw_logs WHERE ${mine}`, [testAddresses, `${message}%`]);
      const left = await pool.query(
        `SELECT (SELECT COUNT(*) FROM raw_logs WHERE ${mine} OR lower(shipper_id) = ANY($3))::int AS raw,
                (SELECT COUNT(*) FROM ingest_source_minute WHERE source_key LIKE $4 OR source_key = ANY($3))::int AS counted`,
        [testAddresses, `${message}%`, [shipperId, shutdownShipperId], `dbtest-${tag}-%`]
      );
      assert.deepEqual(left.rows[0], { raw: 0, counted: 0 }, 'this run leaves no rows behind');
    }
  } finally {
    await closePools();
  }
});

async function rowsFor(...keys: string[]): Promise<Array<{ key: string; kind: string; epoch: number; logs: number }>> {
  const r = await pool.query(
    `SELECT source_key AS key, source_kind AS kind, extract(epoch FROM minute)::bigint AS epoch, logs
       FROM ingest_source_minute WHERE source_key = ANY($1) ORDER BY source_key, minute`,
    [keys]
  );
  return r.rows.map((x) => ({ key: x.key, kind: x.kind, epoch: Number(x.epoch), logs: Number(x.logs) }));
}

const direct = (k: string) => ({ shipper_id: null, discovery_source_id: null, source_ip: k });

// First in the file: nothing in this process has touched the ingest pool yet.
test('the flush writes on the ingest pool, not the main pool', async (t) => {
  if (!dbReady) return t.skip('Postgres with migration 041 is not reachable');
  assert.equal(getPoolStats().ingest.total, 0, 'precondition: the ingest pool is unused');
  const counter = createIngestCounter();
  counter.bump(direct(key('pool')));
  await counter.flush();
  assert.ok(getPoolStats().ingest.total >= 1, 'the write opened an ingest-pool connection');
  assert.deepEqual(
    (await rowsFor(key('pool'))).map((r) => r.logs),
    [1]
  );
  await counter.close();
});

test('upserts accumulate across flushes, one row per minute and source', async (t) => {
  if (!dbReady) return t.skip('Postgres with migration 041 is not reachable');
  const now = Date.now();
  const counter = createIngestCounter({ now: () => now });
  for (let i = 0; i < 3; i++) counter.bump(direct(key('a')));
  await counter.flush();
  for (let i = 0; i < 2; i++) counter.bump(direct(key('a')));
  counter.bump(direct(key('b')));
  await counter.flush();
  await counter.close();

  const epoch = minuteBucket(now) * 60;
  assert.deepEqual(await rowsFor(key('a'), key('b')), [
    { key: key('a'), kind: 'direct', epoch, logs: 5 },
    { key: key('b'), kind: 'direct', epoch, logs: 1 },
  ]);
});

test('a bucket is the same instant whatever the session time zone', async (t) => {
  if (!dbReady) return t.skip('Postgres with migration 041 is not reachable');
  const now = Date.UTC(2026, 9, 15, 12, 34, 56);
  // The counter's own upsert, through a connection whose session time zone is
  // far from UTC.
  const counter = createIngestCounter({
    now: () => now,
    write: async (rows) => {
      const client = await pool.connect();
      try {
        await client.query(`SET TIME ZONE 'Pacific/Kiritimati'`);
        await writeRows(rows, (text, params) => client.query(text, params));
      } finally {
        await client.query('RESET TIME ZONE');
        client.release();
      }
    },
  });
  counter.bump(direct(key('tz')));
  await counter.close();
  // And through the default writer, on the ingest pool's connections.
  const real = createIngestCounter({ now: () => now });
  real.bump(direct(key('tz')));
  await real.close();
  assert.deepEqual(await rowsFor(key('tz')), [
    { key: key('tz'), kind: 'direct', epoch: Date.UTC(2026, 9, 15, 12, 34, 0) / 1000, logs: 2 },
  ]);
});

test('rows older than 48 hours are pruned from the flush path; younger ones stay', async (t) => {
  if (!dbReady) return t.skip('Postgres with migration 041 is not reachable');
  await pool.query(
    `INSERT INTO ingest_source_minute (minute, source_kind, source_key, logs) VALUES
       (date_trunc('minute', NOW() - INTERVAL '49 hours'), 'direct', $1, 4),
       (date_trunc('minute', NOW() - INTERVAL '47 hours'), 'direct', $2, 4)`,
    [key('old'), key('young')]
  );
  // A new counter prunes on its first successful write.
  const counter = createIngestCounter();
  counter.bump(direct(key('trigger')));
  await counter.flush();
  await counter.close();
  assert.deepEqual(
    (await rowsFor(key('old'), key('young'))).map((r) => r.key),
    [key('young')]
  );
});

test('RawLogModel.create counts a stored log once, and its deduplicated repeat not at all', async (t) => {
  if (!dbReady) return t.skip('Postgres with migration 041 is not reachable');
  await ingestCounter.flush(); // start from nothing pending
  const params = {
    timestamp: new Date(),
    raw_message: message,
    source_ip: testAddresses[0],
    shipper_id: shipperId.toUpperCase(),
    ingest_event_id: `evt-${tag}`,
  };
  const first = await runInIngestContext(() => RawLogModel.create(params));
  const repeat = await runInIngestContext(() => RawLogModel.create(params));
  assert.ok(first, 'the first push is stored');
  assert.equal(repeat, null, 'the repeat is deduplicated');
  assert.equal(ingestCounter.stats().pendingLogs, 1);
  await ingestCounter.flush();
  const rows = await rowsFor(shipperId);
  assert.deepEqual(
    rows.map((r) => ({ kind: r.kind, logs: r.logs })),
    [{ kind: 'shipper', logs: 1 }],
    'one shipper row, keyed by the lowercased shipper id, counting the stored log once'
  );
});

test('RECENT_SOURCES_SQL: sources with an established row in the last hour, at most N per kind (the most recent), least recent first', async (t) => {
  if (!dbReady) return t.skip('Postgres with migration 041 is not reachable');
  // On a temporary table of the same name, which this session's queries see
  // instead of the real one: other rows in the table can't change the result.
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('CREATE TEMP TABLE ingest_source_minute (LIKE public.ingest_source_minute INCLUDING ALL) ON COMMIT DROP');
    await client.query(
      `INSERT INTO ingest_source_minute (minute, source_kind, source_key, logs, established)
       SELECT date_trunc('minute', NOW()) - make_interval(mins => v.ago), v.kind, v.key, v.logs, v.established
         FROM (VALUES (3, 'direct', 'steady', 1, true), (2, 'direct', 'steady', 1, true), (1, 'direct', 'steady', 1, true),
                      (2, 'direct', 'quiet', 1, true),
                      (60, 'direct', 'edge', 5, true), (61, 'direct', 'old', 50, true),
                      -- A spray's tag with only new-source slots: in every minute, and the busiest.
                      (3, 'direct', 'sprayed', 1000, false), (2, 'direct', 'sprayed', 1000, false), (1, 'direct', 'sprayed', 1000, false),
                      (5, 'poller', '42', 3, true), (1, 'shipper', 'ab12cd34', 7, true), (1, 'shipper', 'f0000000', 400, false),
                      (1, 'overflow', '*', 99, false)
              ) AS v(ago, kind, key, logs, established)`
    );
    const nowMinute = Number(
      (await client.query(`SELECT (EXTRACT(EPOCH FROM date_trunc('minute', NOW())) / 60)::bigint AS m`)).rows[0].m
    );
    const read = async (perKind: number) =>
      (await client.query(RECENT_SOURCES_SQL, [60, perKind])).rows.map((r) => [r.kind, r.key, nowMinute - Number(r.last_minute)]);
    assert.deepEqual(
      await read(10),
      [
        ['direct', 'edge', 60],
        ['poller', '42', 5],
        ['direct', 'quiet', 2],
        ['direct', 'steady', 1],
        ['shipper', 'ab12cd34', 1],
      ],
      '60 minutes back inclusive, only established rows (never a sprayed tag or the overflow row), least recent first'
    );
    assert.deepEqual(
      await read(2),
      [
        ['poller', '42', 5],
        ['direct', 'quiet', 2],
        ['direct', 'steady', 1],
        ['shipper', 'ab12cd34', 1],
      ],
      'per kind, the most recent'
    );
  } finally {
    await client.query('ROLLBACK');
    client.release();
  }
});

test('restore() reads the sources back from the table, so a restart keeps them established', async (t) => {
  if (!dbReady) return t.skip('Postgres with migration 041 is not reachable');
  // One source that was established in the last three minutes, and one that
  // only had new-source slots then.
  await pool.query(
    `INSERT INTO ingest_source_minute (minute, source_kind, source_key, logs, established)
     SELECT date_trunc('minute', NOW()) - make_interval(mins => ago), 'direct', k.key, 1000, k.established
       FROM generate_series(1, 3) AS ago, (VALUES ($1, true), ($2, false)) AS k(key, established)`,
    [key('restored'), key('unmarked')]
  );
  const writes: IngestCountRow[] = [];
  const counter = createIngestCounter({
    write: async (rows) => {
      writes.push(...rows);
    },
  });
  await counter.restore();
  // The new-source slots are gone before the three sources log.
  for (let i = 0; i < 100; i++) counter.bump(direct(key(`new-${i}`)));
  counter.bump(direct(key('restored')));
  counter.bump(direct(key('unmarked')));
  counter.bump(direct(key('unseen')));
  await counter.close();
  const restored = writes.find((r) => r.key === key('restored'));
  assert.equal(restored?.logs, 1, 'restored: its own row');
  assert.equal(restored?.established, true, 'and it is still established');
  assert.equal(writes.find((r) => r.key === key('unmarked')), undefined, 'never established: overflow');
  assert.equal(writes.find((r) => r.key === key('unseen')), undefined, 'never seen: overflow');
  assert.equal(writes.find((r) => r.kind === 'overflow')?.logs, 2);
});

/**
 * The round 2 review's reproduction: ten shippers are established, then one
 * sender sends the same 600 tags at the start of every minute for 74 minutes,
 * and the backend restarts. Everything goes through the real counter, the real
 * upsert and the real restore() query, on one connection whose temporary table
 * of the same name hides the real one (so other rows can't change what is
 * restored). Returns, per minute, how many of the ten had their own row, and
 * the overflow logs of the minute after the restart.
 */
async function restartDuringFixedTagSpray(opts: { shippersEvery: number; shipperLines: number; sprayLines: number }) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('CREATE TEMP TABLE ingest_source_minute (LIKE public.ingest_source_minute INCLUDING ALL) ON COMMIT DROP');
    // NOW() is the transaction's start for every statement in it: restore()'s
    // window ends at this minute.
    const nowMinute = Number(
      (await client.query(`SELECT (EXTRACT(EPOCH FROM date_trunc('minute', NOW())) / 60)::bigint AS m`)).rows[0].m
    );
    const run = (text: string, params: unknown[]) => client.query(text, params);
    let now = 0;
    const counterOnClient = () =>
      createIngestCounter({
        now: () => now,
        write: (rows) => writeRows(rows, run),
        loadRecent: () => loadRecentRows(run),
        prune: async () => undefined,
        setTimer: () => ({}),
        clearTimer: () => undefined,
      });
    // The shippers' ids sort after every sprayed tag, so no tie broken by key
    // can favour them.
    const shippers = Array.from({ length: 10 }, (_, i) => `fe${i.toString(16).padStart(6, '0')}`);
    const spray = Array.from({ length: 600 }, (_, i) => `f${i.toString(16).padStart(7, '0')}`);
    const shipper = (id: string) => ({ shipper_id: id, discovery_source_id: null, source_ip: '203.0.113.7' });
    const logsIn = (m: number) => (nowMinute - m) % opts.shippersEvery === 0;
    const minute = async (counter: ReturnType<typeof createIngestCounter>, m: number, sprayed: boolean) => {
      now = m * 60_000;
      if (sprayed) for (const id of spray) for (let i = 0; i < opts.sprayLines; i++) counter.bump(shipper(id));
      now = m * 60_000 + 20_000;
      if (logsIn(m)) for (const id of shippers) for (let i = 0; i < opts.shipperLines; i++) counter.bump(shipper(id));
      await counter.flush();
    };
    const ownRows = async (m: number) =>
      Number(
        (
          await client.query(`SELECT COUNT(*) AS n FROM ingest_source_minute WHERE minute = to_timestamp($1) AND source_key = ANY($2)`, [
            m * 60,
            shippers,
          ])
        ).rows[0].n
      );

    // Before the restart: the shippers log alone once, then the spray runs.
    const first = nowMinute - 75;
    const before = counterOnClient();
    await minute(before, first, false);
    const beforeRestart: number[] = [];
    for (let m = first + 1; m < nowMinute; m++) {
      await minute(before, m, true);
      if (logsIn(m)) beforeRestart.push(await ownRows(m));
    }
    await before.close();

    // The restart, and the next minute of the spray.
    const after = counterOnClient();
    now = nowMinute * 60_000;
    await after.restore();
    await minute(after, nowMinute, true);
    await after.close();
    const overflow = Number(
      (
        await client.query(`SELECT COALESCE(SUM(logs), 0) AS n FROM ingest_source_minute WHERE minute = to_timestamp($1) AND source_kind = 'overflow'`, [
          nowMinute * 60,
        ])
      ).rows[0].n
    );
    return { beforeRestart, afterRestart: await ownRows(nowMinute), overflow };
  } finally {
    await client.query('ROLLBACK');
    client.release();
  }
}

test('a restart during a fixed-tag spray: shippers that log every minute keep their own rows', async (t) => {
  if (!dbReady) return t.skip('Postgres with migration 041 is not reachable');
  // Shippers at 3 lines a minute, the sprayer at 4 lines per tag: by minutes
  // present and then by volume, the sprayer's tags outrank them.
  const r = await restartDuringFixedTagSpray({ shippersEvery: 1, shipperLines: 3, sprayLines: 4 });
  assert.ok(r.beforeRestart.length >= 70 && r.beforeRestart.every((n) => n === 10), 'precondition: 10 of 10 in every minute before the restart');
  assert.equal(r.afterRestart, 10, 'after the restart: 10 of 10');
  // 490 sprayed tags were established with the shippers, 100 more take the
  // new-shipper budget, and the last 10 overflow: none of it the shippers'.
  assert.equal(r.overflow, 10 * 4);
});

test('a restart during a fixed-tag spray: shippers that log every 5 minutes keep their own rows', async (t) => {
  if (!dbReady) return t.skip('Postgres with migration 041 is not reachable');
  const r = await restartDuringFixedTagSpray({ shippersEvery: 5, shipperLines: 1, sprayLines: 1 });
  assert.ok(r.beforeRestart.length >= 14 && r.beforeRestart.every((n) => n === 10), 'precondition: 10 of 10 whenever they logged before the restart');
  assert.equal(r.afterRestart, 10, 'after the restart: 10 of 10');
  assert.equal(r.overflow, 10);
});

// Last in the file: it closes the ingest pool.
test('at shutdown, logs whose inserts were still running when close() started are counted', async (t) => {
  if (!dbReady) return t.skip('Postgres with migration 041 is not reachable');
  await ingestCounter.flush(); // start from nothing pending
  // Ten pushes whose inserts are running, as a syslog backlog or an HTTP push
  // batch can be when server.ts shuts down. Uncommitted rows with the same
  // dedup keys hold each insert inside Postgres until they are rolled back.
  const n = 10;
  const params = (i: number) => ({
    timestamp: new Date(),
    raw_message: `${message} shutdown ${i}`,
    source_ip: testAddresses[1],
    shipper_id: shutdownShipperId,
    ingest_event_id: `evt-${tag}-shutdown-${i}`,
  });
  const holder = await pool.connect();
  let inserts: Array<Promise<unknown>> = [];
  try {
    await holder.query('BEGIN');
    for (let i = 0; i < n; i++) {
      const p = params(i);
      await holder.query(
        `INSERT INTO raw_logs (timestamp, raw_message, source_ip, shipper_id, ingest_event_id) VALUES ($1, $2, $3, $4, $5)`,
        [p.timestamp, p.raw_message, p.source_ip, p.shipper_id, p.ingest_event_id]
      );
    }
    inserts = Array.from({ length: n }, (_, i) => runInIngestContext(() => RawLogModel.create(params(i))));
    for (let waited = 0; getPoolStats().ingest.total - getPoolStats().ingest.idle < n; waited += 10) {
      assert.ok(waited < 5000, 'the inserts reach Postgres');
      await new Promise((r) => setTimeout(r, 10));
    }

    let closed = false;
    const closing = ingestCounter.close(closeIngestPool).then(() => (closed = true));
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(closed, false, 'close() waits for the inserts still running');
    await holder.query('ROLLBACK');
    await closing;
  } finally {
    // Also when an assertion above failed: the held inserts finish before the
    // cleanup in after() runs, and the holder goes back to the pool outside
    // its transaction. (A second ROLLBACK is only a warning.)
    await holder.query('ROLLBACK').catch(() => undefined);
    holder.release();
    await Promise.allSettled(inserts);
  }
  const stored = (await Promise.all(inserts)).filter(Boolean).length;
  assert.equal(stored, n, 'every insert already running stores its row');
  assert.deepEqual(
    (await rowsFor(shutdownShipperId)).map((r) => ({ kind: r.kind, logs: r.logs })),
    [{ kind: 'shipper', logs: n }],
    'and each is counted, in the write close() makes on the main pool once the ingest pool has closed'
  );
  assert.equal(getPoolStats().ingest.total, 0, 'the ingest pool is closed');
});
