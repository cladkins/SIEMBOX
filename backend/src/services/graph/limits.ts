/**
 * What keeps the Context Graph from crowding out the rest of SIEMBox.
 *
 *   Semaphore  at most 4 graph requests in flight in the process (20 % of the
 *              20-connection main pool) and 2 per user. A request that isn't
 *              admitted within 1 s gets GraphBusyError (503 GRAPH_BUSY,
 *              Retry-After: 2).
 *   Cache      20 s TTL, single-flight, at most 500 entries (least recently
 *              used out first). Keys start with the caller's visibility class
 *              (visibility.ts), so an answer is only ever shared between roles
 *              that see the same graph. Answers with a timed-out source are not
 *              kept, so "Try again" really tries again; failures aren't either.
 *
 * Cache hits and followers of an in-flight request take no semaphore slot:
 * only the request that does the work does.
 */
import { GraphBusyError } from './errors';

export interface SemaphoreOptions {
  global: number;
  perUser: number;
  waitMs: number;
}

export const DEFAULT_SEMAPHORE: SemaphoreOptions = { global: 4, perUser: 2, waitMs: 1000 };

export interface Semaphore {
  /** Wait for a slot (rejects with GraphBusyError after waitMs); resolves to its release function. */
  acquire(user: string): Promise<() => void>;
  stats(): { inFlight: number; waiting: number };
}

interface Waiter {
  user: string;
  admit: (release: () => void) => void;
  timer: ReturnType<typeof setTimeout>;
}

export function createSemaphore(options: SemaphoreOptions = DEFAULT_SEMAPHORE): Semaphore {
  let inFlight = 0;
  const perUser = new Map<string, number>();
  const queue: Waiter[] = [];

  const fits = (user: string) => inFlight < options.global && (perUser.get(user) ?? 0) < options.perUser;

  function take(user: string): () => void {
    inFlight++;
    perUser.set(user, (perUser.get(user) ?? 0) + 1);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      inFlight--;
      const left = (perUser.get(user) ?? 1) - 1;
      if (left > 0) perUser.set(user, left);
      else perUser.delete(user);
      drain();
    };
  }

  function drain(): void {
    for (let i = 0; i < queue.length; ) {
      const waiter = queue[i];
      if (!fits(waiter.user)) {
        i++;
        continue;
      }
      queue.splice(i, 1);
      clearTimeout(waiter.timer);
      waiter.admit(take(waiter.user));
    }
  }

  return {
    acquire(user: string) {
      // drain() admits every queued waiter that fits, so whoever is still
      // queued doesn't: a caller that fits now jumps no one.
      if (fits(user)) return Promise.resolve(take(user));
      return new Promise((resolve, reject) => {
        const waiter: Waiter = {
          user,
          admit: resolve,
          timer: setTimeout(() => {
            const index = queue.indexOf(waiter);
            if (index >= 0) queue.splice(index, 1);
            reject(new GraphBusyError());
          }, options.waitMs),
        };
        queue.push(waiter);
        drain();
      });
    },
    stats: () => ({ inFlight, waiting: queue.length }),
  };
}

export interface CacheOptions {
  ttlMs: number;
  maxEntries: number;
  now: () => number;
}

export const DEFAULT_CACHE: CacheOptions = { ttlMs: 20_000, maxEntries: 500, now: () => Date.now() };

export interface GraphCache {
  /**
   * The value for `key`: a fresh cached one (cached: true), the in-flight
   * computation's, or a new one from `compute`. `keep(value)` says whether the
   * result may be cached.
   */
  get<T>(key: string, compute: () => Promise<T>, keep?: (value: T) => boolean): Promise<{ value: T; cached: boolean }>;
  clear(): void;
  size(): number;
}

export function createGraphCache(options: CacheOptions = DEFAULT_CACHE): GraphCache {
  // A Map iterates in insertion order: re-inserting on a hit keeps it LRU.
  const entries = new Map<string, { at: number; value: unknown }>();
  const inflight = new Map<string, Promise<unknown>>();

  return {
    async get<T>(key: string, compute: () => Promise<T>, keep: (value: T) => boolean = () => true) {
      const hit = entries.get(key);
      if (hit && options.now() - hit.at < options.ttlMs) {
        entries.delete(key);
        entries.set(key, hit);
        return { value: hit.value as T, cached: true };
      }
      if (hit) entries.delete(key);
      const running = inflight.get(key) as Promise<T> | undefined;
      if (running) return { value: await running, cached: false };
      const run = compute();
      inflight.set(key, run);
      try {
        const value = await run;
        if (keep(value)) {
          entries.set(key, { at: options.now(), value });
          while (entries.size > options.maxEntries) {
            entries.delete(entries.keys().next().value as string);
          }
        }
        return { value, cached: false };
      } finally {
        if (inflight.get(key) === run) inflight.delete(key);
      }
    },
    clear() {
      entries.clear();
    },
    size: () => entries.size,
  };
}

/** The process-wide limits the graph routes use. */
export const graphSemaphore = createSemaphore();
export const graphCache = createGraphCache();
