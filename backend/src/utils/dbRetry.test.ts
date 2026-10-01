/**
 * Tests for connection-failure retry. The invariant that matters: ONLY failures
 * where the statement cannot have run are retried -- so a retry can never write
 * a log row twice -- and the wait is bounded so a worker is never held forever.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isConnectFailure, withConnectRetry, DEFAULT_RETRY_OPTIONS, RetryOptions } from './dbRetry';

const coded = (code: string, message = code) => Object.assign(new Error(message), { code });

test('isConnectFailure: connection-phase errors are retryable', () => {
  assert.equal(isConnectFailure(new Error('timeout exceeded when trying to connect')), true); // pg-pool acquire timeout
  assert.equal(isConnectFailure(new Error('Connection terminated due to connection timeout')), true);
  for (const code of ['ECONNREFUSED', 'EAI_AGAIN', 'ENOTFOUND', 'EHOSTUNREACH', 'ENETUNREACH', '57P03', '53300']) {
    assert.equal(isConnectFailure(coded(code)), true, code);
  }
});

test('isConnectFailure: errors where the statement MAY have run are NOT retryable (no double-writes)', () => {
  for (const code of ['ECONNRESET', 'EPIPE', 'ETIMEDOUT', '57P01', '08006', '40001']) {
    assert.equal(isConnectFailure(coded(code)), false, code);
  }
  assert.equal(isConnectFailure(new Error('Connection terminated unexpectedly')), false);
});

test('isConnectFailure: SQL-level errors are not retryable (they would just fail again)', () => {
  for (const code of ['23505', '23503', '42601', '42P01', '22P02', '57014']) {
    assert.equal(isConnectFailure(coded(code)), false, code);
  }
  assert.equal(isConnectFailure(new Error('syntax error at or near "SELEC"')), false);
});

test('isConnectFailure: AggregateError counts only if EVERY inner attempt was a connect failure', () => {
  const allRefused = new AggregateError([coded('ECONNREFUSED'), coded('ECONNREFUSED')], '');
  const mixed = new AggregateError([coded('ECONNREFUSED'), coded('ECONNRESET')], '');
  assert.equal(isConnectFailure(allRefused), true);
  assert.equal(isConnectFailure(mixed), false);
});

test('isConnectFailure: junk in, false out', () => {
  for (const v of [null, undefined, 'boom', 42, {}, []]) assert.equal(isConnectFailure(v), false);
});

// A scripted clock/sleep so the tests are instant and deterministic.
function fakeTime() {
  let t = 0;
  const sleeps: number[] = [];
  return {
    sleeps,
    advance: (ms: number) => (t += ms),
    deps: {
      now: () => t,
      sleep: async (ms: number) => {
        sleeps.push(ms);
        t += ms;
      },
      random: () => 0.5, // jitter factor = 0.8 + 0.4*0.5 = 1.0 -> exact backoff
    },
  };
}

const OPTS: RetryOptions = { maxElapsedMs: 30_000, baseDelayMs: 250, maxDelayMs: 8_000 };

test('succeeds first time: no retries, no sleeping', async () => {
  const time = fakeTime();
  let calls = 0;
  const out = await withConnectRetry(async () => ++calls, OPTS, time.deps);
  assert.equal(out, 1);
  assert.deepEqual(time.sleeps, []);
});

test('retries connection failures with doubling backoff, then returns the successful result', async () => {
  const time = fakeTime();
  let calls = 0;
  const retries: number[] = [];
  const out = await withConnectRetry(
    async () => {
      if (++calls <= 3) throw new Error('timeout exceeded when trying to connect');
      return 'stored';
    },
    OPTS,
    { ...time.deps, onRetry: (attempt) => retries.push(attempt) }
  );
  assert.equal(out, 'stored');
  assert.equal(calls, 4);
  assert.deepEqual(time.sleeps, [250, 500, 1000], 'backoff doubles');
  assert.deepEqual(retries, [1, 2, 3]);
});

test('backoff is capped at maxDelayMs', async () => {
  const time = fakeTime();
  let calls = 0;
  await withConnectRetry(
    async () => {
      if (++calls <= 8) throw coded('ECONNREFUSED');
      return 'ok';
    },
    { maxElapsedMs: 10 * 60_000, baseDelayMs: 250, maxDelayMs: 2_000 },
    time.deps
  );
  assert.deepEqual(time.sleeps, [250, 500, 1000, 2000, 2000, 2000, 2000, 2000]);
});

test('gives up once the NEXT wait would exceed the time budget, rethrowing the last error unchanged', async () => {
  const time = fakeTime();
  const err = coded('ECONNREFUSED', 'connect ECONNREFUSED 127.0.0.1:5432');
  let calls = 0;
  await assert.rejects(
    withConnectRetry(
      async () => {
        calls++;
        throw err;
      },
      OPTS,
      time.deps
    ),
    (e) => e === err
  );
  // 250+500+1000+2000+4000+8000 = 15750; +8000 -> 23750; +8000 -> 31750 > 30000 -> stop before sleeping.
  assert.deepEqual(time.sleeps, [250, 500, 1000, 2000, 4000, 8000, 8000]);
  assert.equal(calls, 8);
  assert.ok(time.sleeps.reduce((a, b) => a + b, 0) <= OPTS.maxElapsedMs, 'never sleeps past the budget');
});

test('time spent INSIDE fn (e.g. a 10 s pool-acquire wait) counts against the budget', async () => {
  const time = fakeTime();
  let calls = 0;
  await assert.rejects(
    withConnectRetry(
      async () => {
        calls++;
        time.advance(10_000); // each attempt waits 10 s for a connection, then times out
        throw new Error('timeout exceeded when trying to connect');
      },
      OPTS,
      time.deps
    ),
    /timeout exceeded/
  );
  // t=10.0 (+250) -> 10.25 attempt -> 20.25 (+500) -> 20.75 attempt -> 30.75 > budget: stop.
  assert.equal(calls, 3);
});

test('does NOT retry a non-connection error: thrown immediately, fn called once', async () => {
  for (const err of [coded('23505', 'duplicate key'), coded('ECONNRESET'), new Error('Connection terminated unexpectedly')]) {
    const time = fakeTime();
    let calls = 0;
    await assert.rejects(
      withConnectRetry(
        async () => {
          calls++;
          throw err;
        },
        OPTS,
        time.deps
      ),
      (e) => e === err
    );
    assert.equal(calls, 1, `${String((err as Error).message)} must not be retried`);
    assert.deepEqual(time.sleeps, []);
  }
});

test('jitter stays within +/-20% of the backoff', async () => {
  for (const [rand, expected] of [
    [0, 200], // 250 * 0.8
    [0.999999, 300], // 250 * ~1.2
  ] as const) {
    const time = fakeTime();
    let calls = 0;
    await withConnectRetry(
      async () => {
        if (++calls === 1) throw coded('ECONNREFUSED');
        return 'ok';
      },
      OPTS,
      { ...time.deps, random: () => rand }
    );
    assert.equal(time.sleeps[0], expected);
  }
});

test('a fn that THROWS synchronously is handled like one that rejects (retried if a connection failure)', async () => {
  const time = fakeTime();
  let calls = 0;
  const out = await withConnectRetry(
    () => {
      if (++calls === 1) throw coded('ECONNREFUSED');
      return Promise.resolve('ok');
    },
    OPTS,
    time.deps
  );
  assert.equal(out, 'ok');
  assert.deepEqual(time.sleeps, [250]);

  await assert.rejects(
    withConnectRetry(
      () => {
        throw coded('23505', 'duplicate key');
      },
      OPTS,
      fakeTime().deps
    ),
    /duplicate key/
  );
});

test('default options bound a worker to ~30 s of retrying', () => {
  assert.equal(DEFAULT_RETRY_OPTIONS.maxElapsedMs, 30_000);
});
