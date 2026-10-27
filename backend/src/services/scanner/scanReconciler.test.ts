/**
 * The startup reconciler fails scans orphaned by a restart, but never a scan
 * dispatched to a log shipper: the shipper is its worker, and a queued one is
 * governed by shipper job expiry instead (shipperJobs.ts). Hermetic: the pool
 * is mocked and records the SQL. Run with `npm test` (tsx --test).
 */
import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import pool from '../../config/database';
import { reconcileInterruptedScans } from './scanReconciler';

test('reconciliation leaves shipper-dispatched scans alone', async () => {
  const sql: string[] = [];
  const q = mock.method(pool, 'query', async (text: string) => {
    sql.push(text);
    return { rows: [], rowCount: 0 };
  });
  try {
    assert.equal(await reconcileInterruptedScans(), 0);
  } finally {
    q.mock.restore();
  }
  const updates = sql.filter((s) => /UPDATE (vulnerability_scans|discovery_scans)/.test(s));
  assert.equal(updates.length, 2);
  for (const s of updates) assert.match(s, /assigned_shipper_id IS NULL/);
});
