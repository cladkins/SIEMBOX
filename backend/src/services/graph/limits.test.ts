/**
 * The graph's concurrency limits and cache: at most 4 requests in flight and 2
 * per user, a 1 s wait before GRAPH_BUSY; a 20 s single-flight cache whose
 * keys start with the caller's visibility class.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as sleep } from 'node:timers/promises';
import { GraphBusyError } from './errors';
import { createGraphCache, createSemaphore, DEFAULT_CACHE, DEFAULT_SEMAPHORE } from './limits';
import { visibilityClass } from './visibility';

test('the defaults are the spec bounds', () => {
  assert.deepEqual(DEFAULT_SEMAPHORE, { global: 4, perUser: 2, waitMs: 1000 });
  assert.equal(DEFAULT_CACHE.ttlMs, 20_000);
  assert.equal(DEFAULT_CACHE.maxEntries, 500);
});

test('semaphore: at most `global` in flight; the next waits and is admitted when one is released', async () => {
  const sem = createSemaphore({ global: 2, perUser: 2, waitMs: 1000 });
  const a = await sem.acquire('u1');
  await sem.acquire('u2');
  let admitted = false;
  const waiting = sem.acquire('u3').then((release) => {
    admitted = true;
    return release;
  });
  await sleep(20);
  assert.equal(admitted, false);
  assert.deepEqual(sem.stats(), { inFlight: 2, waiting: 1 });
  a();
  const c = await waiting;
  assert.equal(admitted, true);
  assert.deepEqual(sem.stats(), { inFlight: 2, waiting: 0 });
  c();
  a(); // releasing twice is a no-op
  assert.equal(sem.stats().inFlight, 1);
});

test('semaphore: at most `perUser` per user, while other users still get in', async () => {
  const sem = createSemaphore({ global: 4, perUser: 2, waitMs: 1000 });
  const r1 = await sem.acquire('alice');
  await sem.acquire('alice');
  const third = sem.acquire('alice');
  const bob = await sem.acquire('bob'); // not blocked behind alice's third
  assert.equal(sem.stats().inFlight, 3);
  r1();
  await third;
  assert.equal(sem.stats().inFlight, 3);
  bob();
});

test('semaphore: a waiter not admitted within waitMs gets GraphBusyError (503 GRAPH_BUSY)', async () => {
  const sem = createSemaphore({ global: 1, perUser: 1, waitMs: 50 });
  const release = await sem.acquire('u1');
  const started = Date.now();
  await assert.rejects(sem.acquire('u2'), (err: unknown) => err instanceof GraphBusyError && err.code === 'GRAPH_BUSY');
  assert.ok(Date.now() - started >= 45);
  assert.equal(sem.stats().waiting, 0, 'a timed-out waiter leaves the queue');
  release();
  assert.equal(sem.stats().inFlight, 0, 'and is never admitted later');
});

test('cache: single-flight, then served from cache within the TTL, recomputed after', async () => {
  const clock = { t: 0 };
  const cache = createGraphCache({ ttlMs: 20_000, maxEntries: 10, now: () => clock.t });
  let runs = 0;
  const compute = async () => {
    runs++;
    await sleep(10);
    return { n: runs };
  };
  const [x, y] = await Promise.all([cache.get('k', compute), cache.get('k', compute)]);
  assert.equal(runs, 1, 'concurrent callers share one computation');
  assert.deepEqual([x.value, y.value], [{ n: 1 }, { n: 1 }]);
  assert.equal((await cache.get('k', compute)).cached, true);
  clock.t = 20_001;
  const later = await cache.get('k', compute);
  assert.deepEqual(later, { value: { n: 2 }, cached: false });
});

test('cache: results `keep` refuses and failures are not kept', async () => {
  const cache = createGraphCache({ ttlMs: 20_000, maxEntries: 10, now: () => 0 });
  let runs = 0;
  await cache.get('partial', async () => ++runs, () => false);
  await cache.get('partial', async () => ++runs, () => false);
  assert.equal(runs, 2);
  await assert.rejects(cache.get('fails', async () => Promise.reject(new Error('boom'))));
  assert.deepEqual(await cache.get('fails', async () => 'ok'), { value: 'ok', cached: false });
});

test('cache: least recently used out first beyond maxEntries', async () => {
  const cache = createGraphCache({ ttlMs: 20_000, maxEntries: 2, now: () => 0 });
  await cache.get('a', async () => 'a');
  await cache.get('b', async () => 'b');
  await cache.get('a', async () => 'a2'); // a is now the most recent
  await cache.get('c', async () => 'c'); // evicts b
  assert.equal(cache.size(), 2);
  assert.equal((await cache.get('a', async () => 'x')).cached, true);
  assert.equal((await cache.get('b', async () => 'b2')).value, 'b2');
});

test('visibility classes: an admin never shares a cache key with any other role', () => {
  const admin = visibilityClass('admin');
  for (const role of ['operator', 'analyst', 'viewer'] as const) {
    assert.notEqual(visibilityClass(role), admin, role);
  }
  // Roles that see the same graph share answers: operators and analysts see
  // endpoints (the Endpoints page); viewers don't.
  assert.equal(visibilityClass('operator'), visibilityClass('analyst'));
  assert.notEqual(visibilityClass('analyst'), visibilityClass('viewer'));
  assert.equal(visibilityClass('admin'), visibilityClass('admin'));
});
