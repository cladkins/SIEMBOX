/**
 * Routes database work to one of two connection pools based on the async
 * context it runs in.
 *
 * Why two pools: log ingestion and the web UI/background jobs used to share one
 * pool of 20 connections with a 2 s wait. A few heavy UI queries (or a slow
 * background job) could hold enough connections that ingestion's per-message
 * INSERTs queued past the 2 s limit and failed -- "timeout exceeded when trying
 * to connect" -- dropping logs. Giving ingestion its own pool makes the two
 * independent: the UI can't starve ingestion, and an ingestion burst can't
 * starve the UI.
 *
 * Why AsyncLocalStorage instead of passing a pool around: the per-log pipeline
 * (raw insert -> parsers -> parsed insert -> detection rules -> alert creation
 * -> notifications) spans a dozen modules that all call the shared `query()`.
 * Entering the ingest context once at the pipeline's entry point routes every
 * query it makes -- including ones issued by code that has no idea it is on the
 * ingest path -- without touching any of it. The context follows `await`s,
 * timers and promise chains automatically and is isolated per concurrent flow.
 *
 * Generic over the pool type and free of any pg import so it is unit-testable
 * with plain objects.
 */
import { AsyncLocalStorage } from 'async_hooks';

export interface PoolRouter<P> {
  /** The pool the current async context should use. */
  current(): P;
  /** True inside runInIngest(). */
  inIngest(): boolean;
  /** Run `fn` -- and everything it awaits or spawns -- against the ingest pool. */
  runInIngest<T>(fn: () => T): T;
}

export function createPoolRouter<P>(main: P, ingest: P): PoolRouter<P> {
  const storage = new AsyncLocalStorage<true>();
  return {
    current: () => (storage.getStore() === true ? ingest : main),
    inIngest: () => storage.getStore() === true,
    runInIngest: (fn) => storage.run(true, fn),
  };
}
