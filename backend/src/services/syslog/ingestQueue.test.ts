/**
 * Tests for the bounded ingest queue. The properties that matter in production:
 * concurrency never exceeds the cap, overload is bounded and COUNTED (never
 * silent), blocked submitters are admitted in order and never lost (even with no
 * backlog at all), and a failing task can't kill a worker.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { IngestQueue } from './ingestQueue';

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
/** Let already-resolved promises run their continuations. */
const tick = () => new Promise<void>((r) => setImmediate(r));

/** A task that stays "running" until released -- lets tests hold workers busy. */
function gate() {
  let release!: () => void;
  const promise = new Promise<void>((r) => (release = r));
  return { promise, release };
}

test('rejects nonsensical options', () => {
  assert.throws(() => new IngestQueue({ concurrency: 0, maxQueued: 10 }), RangeError);
  assert.throws(() => new IngestQueue({ concurrency: 1.5, maxQueued: 10 }), RangeError);
  assert.throws(() => new IngestQueue({ concurrency: 4, maxQueued: -1 }), RangeError);
});

test('never runs more than `concurrency` tasks at once, and runs them all', async () => {
  const q = new IngestQueue({ concurrency: 5, maxQueued: 1000 });
  let inFlight = 0;
  let peak = 0;
  const jobs: Array<Promise<void>> = [];
  for (let i = 0; i < 200; i++) {
    jobs.push(
      q.submit(async () => {
        inFlight++;
        peak = Math.max(peak, inFlight);
        await sleep(1 + (i % 4));
        inFlight--;
      })
    );
  }
  await Promise.all(jobs);
  assert.equal(peak, 5, 'saturates the workers but never exceeds the cap');
  assert.deepEqual(q.stats(), { active: 0, queued: 0, blocked: 0, dropped: 0, processed: 200, failed: 0 });
});

test('starts tasks in FIFO order', async () => {
  const q = new IngestQueue({ concurrency: 1, maxQueued: 100 });
  const order: number[] = [];
  await Promise.all(Array.from({ length: 20 }, (_, i) => q.submit(async () => void order.push(i))));
  assert.deepEqual(order, Array.from({ length: 20 }, (_, i) => i));
});

test('trySubmit drops when workers are busy AND the backlog is full -- and COUNTS every drop', async () => {
  const q = new IngestQueue({ concurrency: 2, maxQueued: 3 });
  const hold = gate();
  const started: number[] = [];
  const accepted: boolean[] = [];
  for (let i = 0; i < 10; i++) {
    accepted.push(
      q.trySubmit(async () => {
        started.push(i);
        await hold.promise;
      })
    );
  }
  // 2 running + 3 queued accepted; the other 5 refused.
  assert.equal(accepted.filter(Boolean).length, 5);
  assert.equal(accepted.filter((a) => !a).length, 5);
  assert.deepEqual(q.stats(), { active: 2, queued: 3, blocked: 0, dropped: 5, processed: 0, failed: 0 });

  hold.release();
  assert.equal(await q.drain(1000), true);
  assert.deepEqual(started, [0, 1, 2, 3, 4], 'only accepted tasks ran; dropped ones never did');

  // THE invariant: every submitted task was either processed or counted as dropped.
  const s = q.stats();
  assert.equal(s.processed + s.dropped, 10);
});

test('trySubmit never drops while a worker is free, even with maxQueued = 0', async () => {
  const q = new IngestQueue({ concurrency: 3, maxQueued: 0 });
  const hold = gate();
  const accepted = [0, 1, 2].map(() => q.trySubmit(() => hold.promise));
  assert.deepEqual(accepted, [true, true, true], 'three free workers accept three tasks');
  assert.equal(q.trySubmit(() => undefined), false, 'the fourth is refused: no worker, no backlog');
  hold.release();
  assert.equal(await q.drain(1000), true);
  assert.equal(q.stats().dropped, 1);
});

test('admit() WAITS for room and resolves on ACCEPTANCE, not completion (TCP backpressure)', async () => {
  const q = new IngestQueue({ concurrency: 1, maxQueued: 1 });
  const holdA = gate();
  const holdB = gate();
  const order: string[] = [];

  await q.admit(async () => {
    order.push('A');
    await holdA.promise;
  });
  await q.admit(async () => {
    order.push('B');
    await holdB.promise;
  }); // accepted into the backlog
  assert.equal(q.stats().active, 1);
  assert.equal(q.stats().queued, 1);

  let cAdmitted = false;
  const cPending = q.admit(() => void order.push('C')).then(() => {
    cAdmitted = true;
  });
  await tick();
  assert.equal(cAdmitted, false, 'C is refused room while A runs and B fills the backlog');
  assert.equal(q.stats().blocked, 1);
  assert.equal(q.stats().dropped, 0, 'blocking admission never drops');

  holdA.release(); // A finishes -> B starts -> C moves into the freed backlog slot
  await cPending;
  assert.equal(cAdmitted, true);
  assert.deepEqual(order, ['A', 'B'], 'C is ACCEPTED but has not run: B still holds the only worker');
  assert.equal(q.stats().blocked, 0);

  holdB.release();
  assert.equal(await q.drain(1000), true);
  assert.deepEqual(order, ['A', 'B', 'C'], 'FIFO preserved across the blocked submitter');
});

test('blocked submitters are admitted strictly in call order', async () => {
  const q = new IngestQueue({ concurrency: 1, maxQueued: 2 });
  const hold = gate();
  const order: number[] = [];
  const jobs: Array<Promise<void>> = [q.submit(() => hold.promise)]; // occupies the worker
  for (let i = 0; i < 30; i++) jobs.push(q.submit(() => void order.push(i)));
  await tick();
  assert.equal(q.stats().queued, 2);
  assert.equal(q.stats().blocked, 28);
  hold.release();
  await Promise.all(jobs);
  assert.deepEqual(order, Array.from({ length: 30 }, (_, i) => i));
});

test('maxQueued = 0: blocked submitters still wake when a WORKER frees (no backlog slot ever opens)', async () => {
  const q = new IngestQueue({ concurrency: 1, maxQueued: 0 });
  const hold = gate();
  const ran: string[] = [];
  const a = q.submit(async () => {
    ran.push('A');
    await hold.promise;
  });
  const b = q.submit(() => void ran.push('B'));
  const c = q.submit(() => void ran.push('C'));
  await tick();
  assert.deepEqual(ran, ['A']);
  assert.equal(q.stats().blocked, 2);
  hold.release();
  await Promise.all([a, b, c]);
  assert.deepEqual(ran, ['A', 'B', 'C']);
});

test('blocked callers have priority over UDP-style trySubmit: it drops rather than jump the line', async () => {
  const q = new IngestQueue({ concurrency: 1, maxQueued: 0 });
  const hold = gate();
  const a = q.submit(() => hold.promise);
  const blockedOne = q.submit(() => undefined);
  await tick();
  assert.equal(q.trySubmit(() => undefined), false);
  assert.equal(q.stats().dropped, 1);
  hold.release();
  await Promise.all([a, blockedOne]);
});

test('many blocked submitters are all eventually admitted -- none lost', async () => {
  const q = new IngestQueue({ concurrency: 2, maxQueued: 3 });
  let ran = 0;
  await Promise.all(
    Array.from({ length: 300 }, () =>
      q.submit(async () => {
        await sleep(1);
        ran++;
      })
    )
  );
  assert.equal(ran, 300);
  assert.equal(q.stats().dropped, 0);
  assert.equal(q.stats().processed, 300);
});

test('a task may submit more work to its own queue without deadlocking or exceeding the cap', async () => {
  const q = new IngestQueue({ concurrency: 2, maxQueued: 100 });
  let inFlight = 0;
  let peak = 0;
  let ran = 0;
  const work = async () => {
    inFlight++;
    peak = Math.max(peak, inFlight);
    await sleep(1);
    inFlight--;
    ran++;
  };
  await q.submit(async () => {
    await work();
    // fire-and-forget children, both flavours
    q.trySubmit(work);
    void q.admit(work);
  });
  assert.equal(await q.drain(1000), true);
  assert.equal(ran, 3);
  assert.ok(peak <= 2);
});

test('a task that rejects or throws synchronously never kills a worker', async () => {
  const errors: unknown[] = [];
  const q = new IngestQueue({ concurrency: 1, maxQueued: 10, onTaskError: (e) => errors.push(e) });
  let after = 0;
  await Promise.all([
    q.submit(async () => {
      throw new Error('async boom');
    }),
    q.submit(() => {
      throw new Error('sync boom');
    }),
    q.submit(async () => void after++),
    q.submit(async () => void after++),
  ]);
  assert.equal(after, 2, 'later tasks still ran on the single worker');
  assert.equal(errors.length, 2);
  assert.deepEqual(q.stats(), { active: 0, queued: 0, blocked: 0, dropped: 0, processed: 4, failed: 2 });
});

test('a throwing onTaskError handler cannot take a worker down either', async () => {
  const q = new IngestQueue({
    concurrency: 1,
    maxQueued: 10,
    onTaskError: () => {
      throw new Error('handler boom');
    },
  });
  let ran = 0;
  await q.submit(async () => {
    throw new Error('x');
  });
  await q.submit(async () => void ran++);
  assert.equal(ran, 1);
});

test('drain(): resolves true when work completes, immediately when idle, false on timeout', async () => {
  const q = new IngestQueue({ concurrency: 2, maxQueued: 10 });
  assert.equal(await q.drain(50), true, 'already idle');

  const hold = gate();
  const p = q.submit(() => hold.promise);
  const timedOut = await q.drain(20);
  assert.equal(timedOut, false, 'still running -> times out');
  assert.equal(q.stats().active, 1);

  const drained = q.drain(1000);
  hold.release();
  assert.equal(await drained, true);
  await p;
  assert.equal(q.stats().active, 0);
});

test('drain() also waits for callers still BLOCKED waiting for room (they are accepted-but-unread data)', async () => {
  const q = new IngestQueue({ concurrency: 1, maxQueued: 0 });
  const holdA = gate();
  const ran: string[] = [];
  const a = q.submit(() => holdA.promise);
  const b = q.submit(() => void ran.push('B'));
  await tick();
  const drained = q.drain(1000);
  holdA.release();
  assert.equal(await drained, true);
  assert.deepEqual(ran, ['B'], 'drain did not resolve until the blocked task had also run');
  await Promise.all([a, b]);
});

test('drain() timeout does not leak its waiter (a later completion does not double-resolve)', async () => {
  const q = new IngestQueue({ concurrency: 1, maxQueued: 1 });
  const hold = gate();
  const p = q.submit(() => hold.promise);
  assert.equal(await q.drain(5), false);
  hold.release();
  await p;
  assert.equal(await q.drain(5), true);
});

test('survives a large burst: 20,000 tasks, accounting exact, internals empty afterwards', async () => {
  const q = new IngestQueue({ concurrency: 24, maxQueued: 50_000 });
  let ran = 0;
  const jobs: Array<Promise<void>> = [];
  for (let i = 0; i < 20_000; i++) jobs.push(q.submit(async () => void ran++));
  await Promise.all(jobs);
  assert.equal(ran, 20_000);
  assert.deepEqual(q.stats(), { active: 0, queued: 0, blocked: 0, dropped: 0, processed: 20_000, failed: 0 });
});

test('survives a large burst THROUGH the blocking path: 20,000 blocked callers, none lost, order kept', async () => {
  const q = new IngestQueue({ concurrency: 4, maxQueued: 8 });
  const seen: number[] = [];
  const jobs: Array<Promise<void>> = [];
  for (let i = 0; i < 20_000; i++) jobs.push(q.submit(async () => void seen.push(i)));
  await Promise.all(jobs);
  assert.equal(seen.length, 20_000);
  // concurrency 4 means completion order can differ, but START order is FIFO.
  assert.deepEqual(seen, Array.from({ length: 20_000 }, (_, i) => i));
  assert.equal(q.stats().blocked, 0);
});

test('overload accounting under a mixed burst: processed + dropped === submitted, always', async () => {
  const q = new IngestQueue({ concurrency: 4, maxQueued: 50 });
  const submitted = 5_000;
  for (let i = 0; i < submitted; i++) {
    q.trySubmit(async () => {
      await sleep(0);
    });
    if (i % 100 === 0) await sleep(0); // let workers make some progress mid-burst
  }
  assert.equal(await q.drain(10_000), true);
  const s = q.stats();
  assert.ok(s.dropped > 0, 'the burst genuinely overloaded the queue');
  assert.equal(s.processed + s.dropped, submitted);
});

test('a long run of SYNCHRONOUS tasks (and synchronous throws) does not blow the stack', async () => {
  const q = new IngestQueue({ concurrency: 1, maxQueued: 100_000, onTaskError: () => undefined });
  let ran = 0;
  for (let i = 0; i < 50_000; i++) {
    q.trySubmit(i % 5 === 0 ? () => { throw new Error('sync'); } : () => void ran++);
  }
  assert.equal(await q.drain(10_000), true);
  assert.equal(ran, 40_000);
  assert.equal(q.stats().failed, 10_000);
  assert.equal(q.stats().processed, 50_000);
});

test('the backlog keeps strict FIFO order across the deque\'s internal compaction', async () => {
  const q = new IngestQueue({ concurrency: 1, maxQueued: 100_000 });
  const hold = gate();
  const seen: number[] = [];
  q.trySubmit(() => hold.promise); // occupy the worker so everything below queues up
  for (let i = 0; i < 6_000; i++) q.trySubmit(() => void seen.push(i));
  assert.equal(q.stats().queued, 6_000);
  hold.release();
  assert.equal(await q.drain(10_000), true);
  assert.deepEqual(seen, Array.from({ length: 6_000 }, (_, i) => i));
});
