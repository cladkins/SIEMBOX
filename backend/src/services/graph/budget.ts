/**
 * The budget one graph request runs under: the runReadOnly() pattern
 * (services/shippers/snapshotCache.ts), extended to several statements with a
 * savepoint per source and a wall clock.
 *
 *   - One main-pool client per request: BEGIN READ ONLY, a LOCAL
 *     statement_timeout of 1.5 s, jit off.
 *   - Each source (a relation, the centre, the enrichment) runs inside its own
 *     SAVEPOINT. A statement timeout (57014) rolls back to it, marks that source
 *     'timeout' and the request carries on; one slow source never blanks the
 *     graph. Any other error is logged and marks it 'unavailable'.
 *   - No new step starts after 3.5 s, and every statement (a step may send
 *     several) gets a statement timeout cut to what is left of the 4 s, so the
 *     request's queries end within 4 s and it returns what it has.
 *   - The client is released on every path, and discarded when a rollback
 *     fails (its connection is in an unknown state).
 */
import type { QueryClient } from '../shippers/snapshotCache';
import { isStatementTimeout } from '../shippers/snapshotCache';
import { logger } from '../../utils/logger';

export const STATEMENT_TIMEOUT_MS = 1500;
export const STOP_NEW_STEPS_AFTER_MS = 3500;
export const WALL_CLOCK_MS = 4000;

/** Run one statement inside the request's transaction. */
export type Query = <T = Record<string, unknown>>(sql: string, params?: unknown[]) => Promise<T[]>;

export type StepResult<T> = { status: 'ok'; value: T } | { status: 'timeout' } | { status: 'unavailable' };

export interface BudgetContext {
  /** Run `fn` as one source, inside its own savepoint. */
  step<T>(label: string, fn: (q: Query) => Promise<T>): Promise<StepResult<T>>;
  /** Milliseconds since the request's transaction began. */
  elapsed(): number;
  /** How many steps timed out (or were not started for lack of time). */
  timeouts(): number;
  /** How many steps ran or were refused. */
  steps(): number;
}

export interface BudgetOptions {
  statementTimeoutMs: number;
  stopNewStepsAfterMs: number;
  wallClockMs: number;
  now: () => number;
}

export const DEFAULT_BUDGET: BudgetOptions = {
  statementTimeoutMs: STATEMENT_TIMEOUT_MS,
  stopNewStepsAfterMs: STOP_NEW_STEPS_AFTER_MS,
  wallClockMs: WALL_CLOCK_MS,
  now: () => Date.now(),
};

/** What a statement with no time left fails with: it reads as a statement timeout (57014). */
function outOfTime(): Error {
  return Object.assign(new Error('Context Graph: the request is out of time'), { code: '57014' });
}

/** Raised when the connection itself failed (a rollback did not go through): the request can't go on. */
export class BudgetConnectionError extends Error {
  constructor(cause: unknown) {
    super(`graph query connection failed: ${cause instanceof Error ? cause.message : String(cause)}`);
    this.name = 'BudgetConnectionError';
  }
}

/**
 * Acquire a client, run `fn` with a BudgetContext in one READ ONLY transaction,
 * commit, release. A failure to acquire (the pool's 2 s timeout) is thrown as
 * is, for the caller to map to 503.
 */
export async function runBudgeted<T>(
  acquire: () => Promise<QueryClient>,
  fn: (ctx: BudgetContext) => Promise<T>,
  options: Partial<BudgetOptions> = {}
): Promise<T> {
  const opts: BudgetOptions = { ...DEFAULT_BUDGET, ...options };
  const client = await acquire();
  let releaseArg: Error | undefined;
  const started = opts.now();
  let timeoutsSeen = 0;
  let stepsSeen = 0;
  let savepoints = 0;
  /** The statement_timeout currently set in the transaction. */
  let currentTimeout = opts.statementTimeoutMs;

  /**
   * Each statement gets at most what is left of the wall clock: the timeout is
   * cut (never raised) before a statement that would otherwise outlive it, and
   * a statement with no time left isn't sent (it fails as a timeout).
   */
  const q: Query = async <R>(sql: string, params: unknown[] = []) => {
    const left = Math.floor(opts.wallClockMs - (opts.now() - started));
    if (left <= 0) throw outOfTime();
    if (left < currentTimeout) {
      await client.query("SELECT set_config('statement_timeout', $1, true)", [String(left)]);
      currentTimeout = left;
    }
    return (await client.query(sql, params as unknown[])).rows as R[];
  };

  const ctx: BudgetContext = {
    elapsed: () => opts.now() - started,
    timeouts: () => timeoutsSeen,
    steps: () => stepsSeen,
    async step<R>(label: string, run: (query: Query) => Promise<R>): Promise<StepResult<R>> {
      stepsSeen++;
      const elapsed = opts.now() - started;
      if (elapsed >= opts.stopNewStepsAfterMs) {
        timeoutsSeen++;
        return { status: 'timeout' };
      }
      const name = `graph_step_${++savepoints}`;
      await client.query(`SAVEPOINT ${name}`);
      try {
        const value = await run(q);
        await client.query(`RELEASE SAVEPOINT ${name}`);
        return { status: 'ok', value };
      } catch (err) {
        try {
          await client.query(`ROLLBACK TO SAVEPOINT ${name}`);
        } catch (rollbackErr) {
          throw new BudgetConnectionError(rollbackErr);
        }
        if (isStatementTimeout(err)) {
          timeoutsSeen++;
          logger.warn('Context Graph: a source timed out and was left out', { source: label, elapsedMs: opts.now() - started });
          return { status: 'timeout' };
        }
        logger.error('Context Graph: a source failed and was left out', {
          source: label,
          error: err instanceof Error ? err.message : String(err),
          code: (err as { code?: string } | null)?.code,
        });
        return { status: 'unavailable' };
      }
    },
  };

  try {
    await client.query('BEGIN READ ONLY');
    await client.query(
      "SELECT set_config('statement_timeout', $1, true), set_config('jit', 'off', true)",
      [String(Math.trunc(opts.statementTimeoutMs))]
    );
    const result = await fn(ctx);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    if (err instanceof BudgetConnectionError) {
      releaseArg = err;
    } else {
      try {
        await client.query('ROLLBACK');
      } catch (rollbackErr) {
        releaseArg = rollbackErr instanceof Error ? rollbackErr : new Error(String(rollbackErr));
      }
    }
    throw err;
  } finally {
    client.release(releaseArg);
  }
}
