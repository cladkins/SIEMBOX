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
  assert.equal(calls.length, 4); // 10000 + 10000 + 5000 + 0 (empty batch terminates)
  assert.equal(
    calls[0].sql,
    "DELETE FROM raw_logs WHERE ctid IN (SELECT ctid FROM raw_logs WHERE timestamp < NOW() - INTERVAL '1 day' * $1 LIMIT $2)"
  );
  // where-params first, batch-size bind appended last
  assert.deepEqual(calls[0].params, [30, 10000]);
});

test('a short batch does not terminate; only an empty batch does', async () => {
  // Regression: with a concurrent deleter (auto cleanup overlapping a manual
  // purge), batches come up short while qualifying rows remain — terminating
  // on short batches reported "completed" purges that had barely started.
  let call = 0;
  const returns = [5, 7, 0]; // short, short, empty
  const exec = async () => ({ rowCount: returns[call++] });
  const total = await batchedDelete('alerts', 'created_at < NOW()', [], {
    exec,
    batchSize: 10000,
    pauseMs: 0,
  });
  assert.equal(total, 12);
  assert.equal(call, 3);
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
