/**
 * The per-minute ingest counter against a real Postgres (migration 041): the
 * flush writes on the ingest pool, upserts accumulate across flushes, buckets
 * land on the right instant whatever the session time zone, rows past 48 h are
 * pruned, RawLogModel.create counts a stored log once and its deduplicated
 * repeat not at all, restore() reads the established sources back, and the
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
import { RECENT_SOURCES_SQL, createIngestCounter, ingestCounter, minuteBucket, type IngestCountRow } from './ingestCounter';

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
  // Write through a connection whose session time zone is far from UTC.
  const counter = createIngestCounter({
    now: () => now,
    write: async (rows) => {
      const client = await pool.connect();
      try {
        await client.query(`SET TIME ZONE 'Pacific/Kiritimati'`);
        await client.query(
          `INSERT INTO ingest_source_minute (minute, source_kind, source_key, logs)
           SELECT * FROM unnest($1::timestamptz[], $2::text[], $3::text[], $4::bigint[])
           ON CONFLICT (minute, source_kind, source_key) DO UPDATE SET logs = ingest_source_minute.logs + EXCLUDED.logs`,
          [rows.map((r) => r.minute), rows.map((r) => r.kind), rows.map((r) => r.key), rows.map((r) => r.logs)]
        );
      } finally {
        await client.query('RESET TIME ZONE');
        client.release();
      }
    },
  });
  counter.bump(direct(key('tz')));
  await counter.close();
  // Read back with the default writer's own path too: the counter's real upsert.
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

test("RECENT_SOURCES_SQL: the last hour's sources, steadiest then busiest first, at most N per kind, least recent first", async (t) => {
  if (!dbReady) return t.skip('Postgres with migration 041 is not reachable');
  // On a temporary table of the same name, which this session's queries see
  // instead of the real one: other rows in the table can't change the ranking.
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('CREATE TEMP TABLE ingest_source_minute (LIKE public.ingest_source_minute INCLUDING ALL) ON COMMIT DROP');
    await client.query(
      `INSERT INTO ingest_source_minute (minute, source_kind, source_key, logs)
       SELECT date_trunc('minute', NOW()) - make_interval(mins => v.ago), v.kind, v.key, v.logs
         FROM (VALUES (3, 'direct', 'steady', 1), (2, 'direct', 'steady', 1), (1, 'direct', 'steady', 1),
                      (1, 'direct', 'busy', 1000), (2, 'direct', 'oneoff', 1),
                      (60, 'direct', 'edge', 5), (61, 'direct', 'old', 50),
                      (5, 'poller', '42', 3), (1, 'shipper', 'ab12cd34', 7), (1, 'overflow', '*', 99)
              ) AS v(ago, kind, key, logs)`
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
        ['direct', 'oneoff', 2],
        ['direct', 'busy', 1],
        ['direct', 'steady', 1],
        ['shipper', 'ab12cd34', 1],
      ],
      '60 minutes back inclusive, never the overflow row, least recent first'
    );
    assert.deepEqual(
      await read(2),
      [
        ['poller', '42', 5],
        ['direct', 'busy', 1],
        ['direct', 'steady', 1],
        ['shipper', 'ab12cd34', 1],
      ],
      'per kind, the one present in the most minutes, then the busiest'
    );
  } finally {
    await client.query('ROLLBACK');
    client.release();
  }
});

test('restore() reads the sources back from the table, so a restart keeps them established', async (t) => {
  if (!dbReady) return t.skip('Postgres with migration 041 is not reachable');
  await pool.query(
    `INSERT INTO ingest_source_minute (minute, source_kind, source_key, logs)
     SELECT date_trunc('minute', NOW()) - make_interval(mins => ago), 'direct', $1, 1000 FROM generate_series(1, 3) AS ago`,
    [key('restored')]
  );
  const writes: IngestCountRow[] = [];
  const counter = createIngestCounter({
    write: async (rows) => {
      writes.push(...rows);
    },
  });
  await counter.restore();
  // The new-source slots are gone before the two sources log.
  for (let i = 0; i < 100; i++) counter.bump(direct(key(`new-${i}`)));
  counter.bump(direct(key('restored')));
  counter.bump(direct(key('unseen')));
  await counter.close();
  assert.equal(writes.find((r) => r.key === key('restored'))?.logs, 1, 'restored: its own row');
  assert.equal(writes.find((r) => r.key === key('unseen')), undefined, 'never seen: overflow');
  assert.equal(writes.find((r) => r.kind === 'overflow')?.logs, 1);
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
