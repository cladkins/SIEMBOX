/**
 * Tests for the recurring-job registry that backs the Admin dashboard's
 * "Recurring Services" panel. In-memory and DB-free. `npm test` (tsx --test).
 */
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  registerRecurringJob,
  trackJobRun,
  markJobSkipped,
  markJobResult,
  setRecurringJobInterval,
  listRecurringJobs,
  resetRecurringJobs,
} from './jobRegistry';

beforeEach(() => resetRecurringJobs());

function get(key: string) {
  return listRecurringJobs().find((j) => j.key === key)!;
}

test('a registered job starts idle with no run history', () => {
  registerRecurringJob({ key: 'cleanup', name: 'Cleanup', description: 'x', intervalMs: 1000 });

  const job = get('cleanup');
  assert.equal(job.status, 'idle');
  assert.equal(job.lastRunAt, null);
  assert.equal(job.runs, 0);
  assert.equal(job.nextRunAt, null); // no last run yet, so nothing to project from
});

test('a successful run records status, result and next-run projection', async () => {
  registerRecurringJob({ key: 'cleanup', name: 'Cleanup', description: 'x', intervalMs: 60_000 });

  const returned = await trackJobRun('cleanup', async () => 'deleted 5 rows');

  const job = get('cleanup');
  assert.equal(returned, 'deleted 5 rows');
  assert.equal(job.status, 'ok');
  assert.equal(job.lastResult, 'deleted 5 rows');
  assert.equal(job.runs, 1);
  assert.equal(job.failures, 0);
  assert.ok(job.lastSuccessAt);
  // nextRunAt is lastRunAt + interval
  assert.equal(
    new Date(job.nextRunAt!).getTime() - new Date(job.lastRunAt!).getTime(),
    60_000
  );
});

test('a failing run is recorded and the error still propagates', async () => {
  registerRecurringJob({ key: 'feeds', name: 'Feeds', description: 'x', intervalMs: 1000 });

  await assert.rejects(
    () => trackJobRun('feeds', async () => { throw new Error('upstream 503'); }),
    /upstream 503/
  );

  const job = get('feeds');
  assert.equal(job.status, 'failed');
  assert.equal(job.lastError, 'upstream 503');
  assert.equal(job.failures, 1);
  // A failed cycle must not look like a successful one.
  assert.equal(job.lastSuccessAt, null);
});

test('a later success clears the previous error but keeps the failure tally', async () => {
  registerRecurringJob({ key: 'feeds', name: 'Feeds', description: 'x', intervalMs: 1000 });

  await assert.rejects(() => trackJobRun('feeds', async () => { throw new Error('boom'); }));
  await trackJobRun('feeds', async () => 'refreshed 3 feed(s)');

  const job = get('feeds');
  assert.equal(job.status, 'ok');
  assert.equal(job.lastError, null);
  assert.equal(job.runs, 2);
  assert.equal(job.failures, 1);
});

test('skipped is distinct from success so "switched off" never reads as "ran fine"', () => {
  registerRecurringJob({ key: 'cleanup', name: 'Cleanup', description: 'x', intervalMs: 1000 });

  markJobSkipped('cleanup', 'auto cleanup disabled in settings');

  const job = get('cleanup');
  assert.equal(job.status, 'skipped');
  assert.equal(job.lastResult, 'auto cleanup disabled in settings');
  assert.ok(job.lastRunAt);
});

test('a job registered as disabled reports disabled with no interval', () => {
  registerRecurringJob({
    key: 'yara-forge',
    name: 'YARA-Forge refresh',
    description: 'x',
    intervalMs: 86_400_000,
    enabled: false,
  });

  const job = get('yara-forge');
  assert.equal(job.status, 'disabled');
  assert.equal(job.intervalMs, null);
  assert.equal(job.nextRunAt, null);
});

test('markJobResult annotates the last run without changing its status', async () => {
  registerRecurringJob({ key: 'sched', name: 'Scheduler', description: 'x', intervalMs: 1000 });

  await trackJobRun('sched', async () => undefined);
  markJobResult('sched', 'triggered 2 of 2 due schedule(s)');

  const job = get('sched');
  assert.equal(job.status, 'ok');
  assert.equal(job.lastResult, 'triggered 2 of 2 due schedule(s)');
});

test('re-registering keeps run history (jobs that reschedule themselves)', async () => {
  registerRecurringJob({ key: 'discovery', name: 'Discovery', description: 'x', intervalMs: 1000 });
  await trackJobRun('discovery', async () => 'ok');

  registerRecurringJob({ key: 'discovery', name: 'Discovery', description: 'x', intervalMs: 5000 });
  setRecurringJobInterval('discovery', 5000);

  const job = get('discovery');
  assert.equal(job.runs, 1);
  assert.equal(job.intervalMs, 5000);
});

test('tracking an unregistered key still runs the work', async () => {
  const result = await trackJobRun('never-registered', async () => 42);
  assert.equal(result, 42);
  assert.equal(listRecurringJobs().length, 0);
});
