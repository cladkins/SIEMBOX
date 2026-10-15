/**
 * The regex test pool: a catastrophic pattern is stopped at its budget, the
 * worker that ran it is replaced, and the event loop keeps serving meanwhile.
 * Run with `npm test` (tsx --test). DB-free.
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { RegexWorkerPool, RegexTimeoutError, RegexPoolBusyError, RegexWorkerError } from './workerPool';

const pools: RegexWorkerPool[] = [];
function pool(overrides: Partial<ConstructorParameters<typeof RegexWorkerPool>[0]> = {}): RegexWorkerPool {
  const p = new RegexWorkerPool({ name: 'test pool', size: 1, timeoutMs: 800, maxQueue: 4, maxQueueWaitMs: 5000, ...overrides });
  pools.push(p);
  return p;
}
after(async () => {
  await Promise.all(pools.map((p) => p.close()));
});

const CATASTROPHIC = { name: 't', parser_type: 'regex', pattern: '^(a+)+$', field_mappings: {} };
const ATTACK = 'a'.repeat(40) + '!';
const SAFE = { name: 't', parser_type: 'regex', pattern: '^(?<user>\\w+) logged in$', field_mappings: { user: 'user' } };
/**
 * Budget for a quick task that is the first on a fresh worker: under tsx the
 * worker loads the backend's modules first, which on a busy CI runner can
 * outlast an 800 ms budget. The timeout tests still use their short budgets for
 * the catastrophic task itself.
 */
const WARM_UP_MS = 15_000;

test('runs a parser in a worker and returns its fields', async () => {
  const p = pool();
  const result = await p.run<any>('runParser', { parser: SAFE, message: 'alice logged in' }, { timeoutMs: WARM_UP_MS });
  assert.equal(result.fields.user, 'alice');
  assert.equal(await p.run('runParser', { parser: SAFE, message: 'nothing to see' }), null);
});

test('^(a+)+$ on a crafted line is stopped at the budget while the event loop keeps running', async () => {
  const p = pool({ timeoutMs: 1000 });
  await p.run('runParser', { parser: SAFE, message: 'warm up' }, { timeoutMs: WARM_UP_MS }); // worker started

  // The main thread must stay responsive: count timer ticks during the run.
  let ticks = 0;
  const ticker = setInterval(() => ticks++, 20);
  const started = Date.now();
  await assert.rejects(p.run('runParser', { parser: CATASTROPHIC, message: ATTACK }), (error: unknown) => {
    assert.ok(error instanceof RegexTimeoutError);
    assert.equal(error.timeoutMs, 1000);
    return true;
  });
  clearInterval(ticker);
  const elapsed = Date.now() - started;
  assert.ok(elapsed >= 950 && elapsed < 2000, `stopped after ${elapsed} ms (budget 1000)`);
  // ~50 ticks would fire in 1 s; a blocked loop fires none until the match ends.
  assert.ok(ticks >= 30, `the event loop ran ${ticks} timer ticks during the run`);
});

test('the worker that timed out is terminated and replaced, and the pool keeps working', async () => {
  const p = pool({ timeoutMs: 500 });
  await p.run('runParser', { parser: SAFE, message: 'warm up' }, { timeoutMs: WARM_UP_MS });
  const before = p.threadIds();
  assert.equal(before.length, 1);

  await assert.rejects(p.run('runParser', { parser: CATASTROPHIC, message: ATTACK }), RegexTimeoutError);
  const after = p.threadIds();
  assert.equal(after.length, 1, 'a replacement took the slot');
  assert.notEqual(after[0], before[0], 'it is a new thread');
  assert.deepEqual(
    { timedOut: p.stats().timedOut, replaced: p.stats().replaced },
    { timedOut: 1, replaced: 1 }
  );

  // The replacement is a cold worker too.
  const result = await p.run<any>('runParser', { parser: SAFE, message: 'bob logged in' }, { timeoutMs: WARM_UP_MS });
  assert.equal(result.fields.user, 'bob', 'the replacement serves the next request');
});

test('a full queue is refused as busy instead of waiting behind a stuck worker', async () => {
  const p = pool({ timeoutMs: 1500, maxQueue: 1 });
  const stuck = p.run('runParser', { parser: CATASTROPHIC, message: ATTACK });
  // It runs on the replacement for the stuck worker, a cold one.
  const queued = p.run('runParser', { parser: SAFE, message: 'carol logged in' }, { timeoutMs: WARM_UP_MS });
  await assert.rejects(p.run('runParser', { parser: SAFE, message: 'dave logged in' }), RegexPoolBusyError);
  await assert.rejects(stuck, RegexTimeoutError);
  assert.equal(((await queued) as any).fields.user, 'carol', 'the queued task ran once a worker was free');
});

test('a pattern that does not compile is reported, not thrown on the main thread', async () => {
  const p = pool();
  await assert.rejects(
    p.run('runParser', { parser: { ...SAFE, pattern: '(unclosed' }, message: 'x' }, { timeoutMs: WARM_UP_MS }),
    (error: unknown) => error instanceof RegexWorkerError && /Invalid regular expression/.test(error.message)
  );
});

test('self-tests run in the worker too', async () => {
  const p = pool();
  const result = await p.run<any>(
    'selfTest',
    { parser: { ...SAFE, schema: 'siembox.parser/v1', test_samples: [{ input: 'erin logged in', expect: { user: 'erin' } }] } },
    { timeoutMs: WARM_UP_MS }
  );
  assert.deepEqual({ ok: result.ok, passed: result.passed }, { ok: true, passed: 1 });
});
