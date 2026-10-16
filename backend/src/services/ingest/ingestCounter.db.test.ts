/**
 * The per-minute ingest counter against a real Postgres (migration 041): the
 * flush writes on the ingest pool, upserts accumulate across flushes, buckets
 * land on the right instant whatever the session time zone, rows past 48 h are
 * pruned, and RawLogModel.create counts a stored log once and its deduplicated
 * repeat not at all. Skips itself when Postgres (or that schema) isn't
 * reachable. Every key used here is unique to this run, and its rows are
 * removed again. Run with `npm test` (tsx --test).
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import pool, { closePools, getPoolStats, runInIngestContext } from '../../config/database';
import { RawLogModel } from '../../models/RawLog';
import { createIngestCounter, ingestCounter, minuteBucket } from './ingestCounter';

let dbReady = false;
const tag = crypto.randomBytes(4).toString('hex');
/** A direct-source key no real sender has: these rows are this run's alone. */
const key = (name: string) => `dbtest-${tag}-${name}`;
const shipperId = crypto.randomBytes(4).toString('hex');

before(async () => {
  try {
    await pool.query('SELECT 1 FROM ingest_source_minute LIMIT 1');
    dbReady = true;
  } catch {
    dbReady = false;
  }
});

after(async () => {
  if (dbReady) {
    await pool.query(`DELETE FROM ingest_source_minute WHERE source_key LIKE $1 OR source_key = $2`, [
      `dbtest-${tag}-%`,
      shipperId,
    ]);
    await pool.query('DELETE FROM raw_logs WHERE shipper_id = $1', [shipperId]);
  }
  await closePools();
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
    raw_message: `ingest-counter db test ${tag}`,
    source_ip: '192.0.2.44',
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
