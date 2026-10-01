/**
 * Bounded retry for database CONNECTION failures -- the one class of error where
 * retrying a write is always safe, because the statement provably never ran.
 *
 * Used on the ingestion path, where dropping a log because the pool was briefly
 * exhausted (or the server momentarily refused a connection) is worse than
 * waiting a moment.
 *
 * What is retried (statement cannot have executed):
 *   - pg-pool's acquire timeout ("timeout exceeded when trying to connect")
 *   - pg's connect-phase timeout ("Connection terminated due to connection timeout")
 *   - ECONNREFUSED / EAI_AGAIN / ENOTFOUND / EHOSTUNREACH / ENETUNREACH
 *   - 57P03 cannot_connect_now (server starting up), 53300 too_many_connections
 *
 * What is deliberately NOT retried, because the outcome is unknown and a retry
 * could write the row twice: ECONNRESET, EPIPE, ETIMEDOUT mid-query,
 * "Connection terminated unexpectedly", 57P01 (terminated by administrator), and
 * every SQL-level error (constraint violations, syntax, ...), which would only
 * fail again.
 *
 * One theoretical gap: the OS can report EHOSTUNREACH/ENETUNREACH on an
 * ESTABLISHED connection, but only after it has given up on it -- minutes after
 * the statement was sent. If that ever lands on a write that had in fact
 * executed, the retry stores the row twice. For a SIEM a rare duplicate beats a
 * lost log, so the risk is accepted rather than dropping those from the list
 * (they are exactly what a restarting Postgres container looks like).
 */

const CONNECT_ERROR_CODES = new Set([
  'ECONNREFUSED',
  'EAI_AGAIN',
  'ENOTFOUND',
  'EHOSTUNREACH',
  'ENETUNREACH',
  '57P03',
  '53300',
]);

export function isConnectFailure(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false;
  const e = err as { code?: unknown; message?: unknown; errors?: unknown };
  if (typeof e.code === 'string' && CONNECT_ERROR_CODES.has(e.code)) return true;
  const message = typeof e.message === 'string' ? e.message : '';
  if (/timeout exceeded when trying to connect/i.test(message)) return true;
  if (/Connection terminated due to connection timeout/i.test(message)) return true;
  // Node's address-family fallback wraps multi-address failures in an
  // AggregateError; it is a connect failure only if every attempt was.
  if (Array.isArray(e.errors) && e.errors.length > 0) return e.errors.every(isConnectFailure);
  return false;
}

export interface RetryOptions {
  /** Give up once the next wait would push total elapsed time past this. */
  maxElapsedMs: number;
  /** First backoff; doubles each attempt. */
  baseDelayMs: number;
  /** Ceiling for a single backoff. */
  maxDelayMs: number;
}

export interface RetryDeps {
  sleep(ms: number): Promise<void>;
  now(): number;
  /** Uniform [0, 1) -- injectable for deterministic tests. */
  random(): number;
  onRetry?(attempt: number, delayMs: number, err: unknown): void;
}

export const DEFAULT_RETRY_OPTIONS: RetryOptions = {
  maxElapsedMs: 30_000,
  baseDelayMs: 250,
  maxDelayMs: 8_000,
};

const DEFAULT_DEPS: RetryDeps = {
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  now: () => Date.now(),
  random: () => Math.random(),
};

/**
 * Run `fn`, retrying with jittered exponential backoff while it fails with a
 * connection-phase error and the time budget allows. Any other error -- and the
 * last connection error once the budget is spent -- is rethrown unchanged.
 *
 * Sits under every ingest query, so the healthy path is kept to a single
 * `.catch` on the promise `fn` returns: the retry machinery below is only
 * built once a connection failure has actually happened.
 */
export function withConnectRetry<T>(
  fn: () => Promise<T>,
  options: RetryOptions = DEFAULT_RETRY_OPTIONS,
  deps: Partial<RetryDeps> = {}
): Promise<T> {
  const start = (deps.now ?? Date.now)();
  let first: Promise<T>;
  try {
    first = fn();
  } catch (err) {
    first = Promise.reject(err);
  }
  return first.catch((err) => {
    if (!isConnectFailure(err)) throw err;
    return retryLoop(fn, options, { ...DEFAULT_DEPS, ...deps }, start, err);
  });
}

async function retryLoop<T>(
  fn: () => Promise<T>,
  options: RetryOptions,
  d: RetryDeps,
  start: number,
  firstError: unknown
): Promise<T> {
  let err = firstError; // always a connection failure here
  for (let attempt = 1; ; attempt++) {
    const backoff = Math.min(options.maxDelayMs, options.baseDelayMs * 2 ** (attempt - 1));
    const delay = Math.round(backoff * (0.8 + 0.4 * d.random())); // +/-20% jitter
    if (d.now() - start + delay > options.maxElapsedMs) throw err;
    d.onRetry?.(attempt, delay, err);
    await d.sleep(delay);
    try {
      return await fn();
    } catch (e) {
      if (!isConnectFailure(e)) throw e;
      err = e;
    }
  }
}
