/**
 * The budgeted runner, with a fake client in the snapshotCache test style: a
 * source that times out rolls back to its savepoint while the others still
 * answer; no step starts after 3.5 s and late steps get a shorter statement
 * timeout; the client is released on every path, and discarded when a
 * rollback fails. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { BudgetConnectionError, DEFAULT_BUDGET, runBudgeted } from './budget';
import type { QueryClient } from '../shippers/snapshotCache';

interface Fake extends QueryClient {
  sql: string[];
  released: Array<Error | boolean | undefined>;
}

const timeoutError = () => Object.assign(new Error('canceling statement due to statement timeout'), { code: '57014' });

function fake(answer: (sql: string, params?: unknown[]) => unknown[] | Error = () => []): Fake {
  const client: Fake = {
    sql: [],
    released: [],
    async query(text: string, params?: unknown[]) {
      client.sql.push(params && params.length ? `${text} ${JSON.stringify(params)}` : text);
      const out = answer(text, params);
      if (out instanceof Error) throw out;
      return { rows: out };
    },
    release(err?: Error | boolean) {
      client.released.push(err);
    },
  };
  return client;
}

test('the defaults: 1.5 s per statement, no new step after 3.5 s, 4 s in all', () => {
  assert.equal(DEFAULT_BUDGET.statementTimeoutMs, 1500);
  assert.equal(DEFAULT_BUDGET.stopNewStepsAfterMs, 3500);
  assert.equal(DEFAULT_BUDGET.wallClockMs, 4000);
});

test('READ ONLY, a local statement timeout and jit off; each step in a savepoint; commit; release', async () => {
  const client = fake((sql) => (sql.startsWith('SELECT 1') ? [{ x: 1 }] : []));
  const result = await runBudgeted(
    async () => client,
    async (ctx) => {
      const step = await ctx.step('one', (q) => q('SELECT 1'));
      return step;
    }
  );
  assert.deepEqual(result, { status: 'ok', value: [{ x: 1 }] });
  assert.deepEqual(client.sql, [
    'BEGIN READ ONLY',
    `SELECT set_config('statement_timeout', $1, true), set_config('jit', 'off', true) ["1500"]`,
    'SAVEPOINT graph_step_1',
    'SELECT 1',
    'RELEASE SAVEPOINT graph_step_1',
    'COMMIT',
  ]);
  assert.deepEqual(client.released, [undefined]);
});

test('a source that times out rolls back to its savepoint; the others still answer', async () => {
  const client = fake((sql) => (sql.includes('slow') ? timeoutError() : [{ ok: true }]));
  const out = await runBudgeted(
    async () => client,
    async (ctx) => {
      const a = await ctx.step('fast-1', (q) => q('SELECT fast'));
      const b = await ctx.step('slow', (q) => q('SELECT slow'));
      const c = await ctx.step('fast-2', (q) => q('SELECT fast'));
      return { a: a.status, b: b.status, c: c.status, timeouts: ctx.timeouts(), steps: ctx.steps() };
    }
  );
  assert.deepEqual(out, { a: 'ok', b: 'timeout', c: 'ok', timeouts: 1, steps: 3 });
  assert.ok(client.sql.includes('ROLLBACK TO SAVEPOINT graph_step_2'));
  assert.equal(client.sql.at(-1), 'COMMIT');
  assert.deepEqual(client.released, [undefined]);
});

test('any other error marks the source unavailable and the request carries on', async () => {
  const client = fake((sql) => (sql.includes('broken') ? Object.assign(new Error('relation does not exist'), { code: '42P01' }) : []));
  const out = await runBudgeted(
    async () => client,
    async (ctx) => [(await ctx.step('broken', (q) => q('SELECT broken'))).status, (await ctx.step('fine', (q) => q('SELECT 1'))).status]
  );
  assert.deepEqual(out, ['unavailable', 'ok']);
  assert.deepEqual(client.released, [undefined]);
});

test('no step starts after 3.5 s; a late step gets the rest of the 4 s as its statement timeout', async () => {
  const clock = { t: 0 };
  const client = fake();
  let ran = 0;
  const out = await runBudgeted(
    async () => client,
    async (ctx) => {
      clock.t = 3000;
      const late = await ctx.step('late', async (q) => {
        ran++;
        return q('SELECT late');
      });
      clock.t = 3500;
      const tooLate = await ctx.step('too-late', async (q) => {
        ran++;
        return q('SELECT never');
      });
      return [late.status, tooLate.status, ctx.timeouts()];
    },
    { now: () => clock.t }
  );
  assert.deepEqual(out, ['ok', 'timeout', 1]);
  assert.equal(ran, 1);
  assert.ok(client.sql.includes(`SELECT set_config('statement_timeout', $1, true) ["1000"]`), client.sql.join('\n'));
  assert.ok(!client.sql.some((s) => s.includes('never')));
});

test('the 4 s holds per statement: a step sending several gets no statement past it', async () => {
  const clock = { t: 0 };
  const client = fake((sql) => {
    if (sql.startsWith('SELECT first')) clock.t = 3800; // the first statement ran long
    if (sql.startsWith('SELECT second')) clock.t = 4000; // and the second used up the rest
    return [];
  });
  const out = await runBudgeted(
    async () => client,
    async (ctx) => {
      clock.t = 3000;
      return ctx.step('two statements', async (q) => {
        await q('SELECT first');
        await q('SELECT second');
        await q('SELECT third');
      });
    },
    { now: () => clock.t }
  );
  assert.equal(out.status, 'timeout');
  // 1000 ms left before the first, 200 ms before the second; none for the third.
  assert.ok(client.sql.includes(`SELECT set_config('statement_timeout', $1, true) ["1000"]`), client.sql.join('\n'));
  assert.ok(client.sql.includes(`SELECT set_config('statement_timeout', $1, true) ["200"]`), client.sql.join('\n'));
  assert.ok(client.sql.includes('SELECT second'));
  assert.ok(!client.sql.includes('SELECT third'), 'a statement with no time left is not sent');
  // A step that starts in time but whose first statement would start too late.
  clock.t = 0;
  const late = fake();
  const after = await runBudgeted(
    async () => late,
    async (ctx) => {
      clock.t = 3400;
      return ctx.step('late', async (q) => {
        clock.t = 4000;
        return q('SELECT never');
      });
    },
    { now: () => clock.t }
  );
  assert.equal(after.status, 'timeout');
  assert.ok(!late.sql.includes('SELECT never'), 'a statement with no time left is not sent');
});

test('a failed rollback to a savepoint discards the client', async () => {
  const client = fake((sql) => (sql.includes('slow') ? timeoutError() : sql.startsWith('ROLLBACK TO') ? new Error('connection lost') : []));
  await assert.rejects(
    runBudgeted(
      async () => client,
      async (ctx) => ctx.step('slow', (q) => q('SELECT slow'))
    ),
    BudgetConnectionError
  );
  assert.equal(client.released.length, 1);
  assert.ok(client.released[0] instanceof Error, 'released with an error: the pool drops the connection');
  assert.ok(!client.sql.includes('COMMIT'));
});

test('an error thrown by the work rolls back and releases the client normally', async () => {
  const client = fake();
  await assert.rejects(
    runBudgeted(
      async () => client,
      async () => {
        throw new Error('busy');
      }
    ),
    /busy/
  );
  assert.equal(client.sql.at(-1), 'ROLLBACK');
  assert.deepEqual(client.released, [undefined]);
});

test('when the final rollback fails too, the client is discarded', async () => {
  const client = fake((sql) => (sql === 'ROLLBACK' ? new Error('gone') : []));
  await assert.rejects(
    runBudgeted(
      async () => client,
      async () => {
        throw new Error('work failed');
      }
    ),
    /work failed/
  );
  assert.ok(client.released[0] instanceof Error);
});

test('a failed acquire is thrown as is, with nothing to release', async () => {
  const err = new Error('timeout exceeded when trying to connect');
  await assert.rejects(
    runBudgeted(
      async () => {
        throw err;
      },
      async () => 'never'
    ),
    (thrown) => thrown === err
  );
});
