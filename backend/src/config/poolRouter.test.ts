/**
 * Tests for the ingest/main pool router. The whole point is that code deep in
 * the per-log pipeline -- which never mentions pools -- lands on the ingest pool
 * because an ancestor entered the ingest context, and that nothing outside it
 * does. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createPoolRouter } from './poolRouter';

const MAIN = { name: 'main' };
const INGEST = { name: 'ingest' };
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

test('defaults to the main pool outside any ingest context', () => {
  const router = createPoolRouter(MAIN, INGEST);
  assert.equal(router.current(), MAIN);
  assert.equal(router.inIngest(), false);
});

test('inside runInIngest the ingest pool is used, and the return value passes through', () => {
  const router = createPoolRouter(MAIN, INGEST);
  const out = router.runInIngest(() => {
    assert.equal(router.current(), INGEST);
    assert.equal(router.inIngest(), true);
    return 42;
  });
  assert.equal(out, 42);
  assert.equal(router.current(), MAIN, 'context does not leak after the call returns');
});

test('the context follows awaits, timers, promise chains and fan-out (the real pipeline shape)', async () => {
  const router = createPoolRouter(MAIN, INGEST);
  const seen: string[] = [];
  const note = (label: string) => seen.push(`${label}:${router.current().name}`);

  // A stand-in for rawInsert -> parse -> parsedInsert -> rules -> fire-and-forget notify.
  const deepCallee = async () => {
    await sleep(1);
    note('after-await');
    await Promise.all([sleep(1).then(() => note('fan-out-a')), sleep(2).then(() => note('fan-out-b'))]);
    setTimeout(() => note('timer'), 1);
    void (async () => {
      await sleep(2);
      note('fire-and-forget');
    })();
  };

  await router.runInIngest(deepCallee);
  await sleep(15); // let the timer + fire-and-forget finish
  assert.deepEqual(
    seen.filter((s) => !s.endsWith(':ingest')),
    [],
    `everything spawned inside the ingest context must stay on the ingest pool, saw: ${seen.join(', ')}`
  );
  assert.equal(seen.length, 5);
});

test('concurrent flows are isolated: ingest work never makes UI work use the ingest pool, or vice versa', async () => {
  const router = createPoolRouter(MAIN, INGEST);
  const results: Array<{ who: string; pool: string }> = [];

  const ui = async (i: number) => {
    await sleep(1 + (i % 3));
    results.push({ who: `ui${i}`, pool: router.current().name });
  };
  const ingest = (i: number) =>
    router.runInIngest(async () => {
      await sleep(1 + (i % 3));
      results.push({ who: `ingest${i}`, pool: router.current().name });
    });

  // Interleave 50 of each so their awaits overlap.
  const jobs: Array<Promise<void>> = [];
  for (let i = 0; i < 50; i++) {
    jobs.push(ui(i));
    jobs.push(ingest(i));
  }
  await Promise.all(jobs);

  assert.equal(results.length, 100);
  for (const r of results) {
    assert.equal(r.pool, r.who.startsWith('ingest') ? 'ingest' : 'main', `${r.who} used ${r.pool}`);
  }
});

test('nested runInIngest is harmless', () => {
  const router = createPoolRouter(MAIN, INGEST);
  router.runInIngest(() => {
    router.runInIngest(() => assert.equal(router.current(), INGEST));
    assert.equal(router.current(), INGEST);
  });
});
