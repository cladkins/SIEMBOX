/**
 * Tests for batchedDelete — the bounded-batch purge that replaced the unbounded
 * retention DELETEs (one of which ran 15h, held a lock, and jammed a migration).
 * Uses the injectable `exec` so it runs with no database. `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { batchedDelete } from './batchDelete';

test('loops until a short batch and sums the rows deleted', async () => {
  const calls: Array<{ sql: string; params: any[] }> = [];
  let remaining = 25000;
  const batchSize = 10000;
  const exec = async (sql: string, params: any[]) => {
    calls.push({ sql, params });
    const n = Math.min(batchSize, remaining);
    remaining -= n;
    return { rowCount: n };
  };

  const total = await batchedDelete(
    'raw_logs',
    "timestamp < NOW() - INTERVAL '1 day' * $1",
    [30],
    { exec, batchSize, pauseMs: 0 }
  );

  assert.equal(total, 25000);
  assert.equal(calls.length, 3); // 10000 + 10000 + 5000, then stop
  assert.equal(
    calls[0].sql,
    "DELETE FROM raw_logs WHERE ctid IN (SELECT ctid FROM raw_logs WHERE timestamp < NOW() - INTERVAL '1 day' * $1 LIMIT $2)"
  );
  // where-params first, batch-size bind appended last
  assert.deepEqual(calls[0].params, [30, 10000]);
});

test('stops after a single statement when the first batch is short', async () => {
  let n = 0;
  const exec = async () => {
    n++;
    return { rowCount: 5 };
  };
  const total = await batchedDelete('alerts', 'created_at < NOW()', [], {
    exec,
    batchSize: 10000,
    pauseMs: 0,
  });
  assert.equal(total, 5);
  assert.equal(n, 1);
});

test('appends the LIMIT bind after multi-param where clauses', async () => {
  let captured: any[] = [];
  const exec = async (_sql: string, params: any[]) => {
    captured = params;
    return { rowCount: 0 };
  };
  await batchedDelete(
    'alerts',
    "created_at < NOW() - INTERVAL '1 day' * $1 AND status = 'closed'",
    [90],
    { exec, batchSize: 500, pauseMs: 0 }
  );
  assert.deepEqual(captured, [90, 500]);
});
