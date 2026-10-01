import { Pool } from 'pg';
import dotenv from 'dotenv';
import { logger } from '../utils/logger';
import { createPoolRouter } from './poolRouter';
import { withConnectRetry, DEFAULT_RETRY_OPTIONS, RetryOptions } from '../utils/dbRetry';
import { envInt } from '../utils/envInt';

dotenv.config();

const connection = {
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME || 'siembox',
  user: process.env.DB_USER || 'siembox',
  password: process.env.DB_PASSWORD || 'changeme',
  idleTimeoutMillis: 30000,
};

// API handlers, the web UI and background jobs. Fails fast (2 s) so a stuck
// page load surfaces as an error instead of hanging.
const MAIN_POOL_MAX = 20;
const pool = new Pool({
  ...connection,
  application_name: 'siembox-backend',
  max: MAIN_POOL_MAX,
  connectionTimeoutMillis: 2000,
});

// Log ingestion (syslog, HTTP push, API polling) gets its own pool so a heavy UI
// query or a slow background job can't starve it -- and an ingestion burst can't
// starve the UI. It waits much longer for a connection than the main pool does:
// a worker blocked here is just backpressure, whereas a dropped log is data loss.
// See config/poolRouter.ts for how code lands on it.
export const INGEST_POOL_MAX = envInt('DB_INGEST_POOL_MAX', 20, 1);
const ingestPool = new Pool({
  ...connection,
  application_name: 'siembox-ingest',
  max: INGEST_POOL_MAX,
  connectionTimeoutMillis: envInt('DB_INGEST_ACQUIRE_TIMEOUT_MS', 10_000, 1),
});

// Connection-phase retries for ingest queries (see utils/dbRetry.ts). Rides out
// pool pressure, "too many clients" and brief connection failures instead of
// dropping the log. (A Postgres restart still restarts the backend whenever the
// main pool has idle connections: see its error handler below.)
// DB_INGEST_RETRY_MS=0 turns retrying off.
const ingestRetry: RetryOptions = {
  ...DEFAULT_RETRY_OPTIONS,
  maxElapsedMs: envInt('DB_INGEST_RETRY_MS', DEFAULT_RETRY_OPTIONS.maxElapsedMs, 0),
};
let ingestRetries = 0;
const ingestRetryDeps = {
  onRetry: (attempt: number, delayMs: number, err: unknown) => {
    ingestRetries++;
    logger.debug('Ingest database connection failed; retrying', {
      attempt,
      delayMs,
      error: err instanceof Error ? err.message : String(err),
    });
  },
};

const router = createPoolRouter(pool, ingestPool);

/**
 * Run `fn` -- and everything it awaits or spawns -- on the ingest pool with
 * connection retry. Call it at the entry point of a log-ingestion unit of work
 * (one syslog message, one HTTP push batch, one poller batch); every query made
 * underneath, however deep, follows without having to know about pools.
 */
export const runInIngestContext = router.runInIngest;

/** True while running inside runInIngestContext() -- for diagnostics and tests. */
export const isInIngestContext = router.inIngest;

pool.on('connect', () => {
  logger.info('Database connection established');
});

pool.on('error', (err) => {
  logger.error('Unexpected database error:', err);
  process.exit(-1);
});

// Deliberately log-only, unlike the main pool above: that handler already
// restarts the process when Postgres goes away, and an idle ingest connection
// that dies (network blip, admin-terminated session) is discarded by the pool and
// replaced on demand -- which is exactly the situation ingest retries cover.
ingestPool.on('error', (err) => {
  logger.warn('Ingest database connection lost; it will be replaced on demand', { error: err.message });
});

ingestPool.on('connect', () => {
  logger.debug('Ingest database connection established');
});

const execute = (text: string, params?: any[]) =>
  router.inIngest()
    ? withConnectRetry(() => ingestPool.query(text, params), ingestRetry, ingestRetryDeps)
    : pool.query(text, params);

export const query = async (text: string, params?: any[]) => {
  const start = Date.now();
  try {
    const res = await execute(text, params);
    const duration = Date.now() - start;
    logger.debug('Executed query', { text, duration, rows: res.rowCount });
    return res;
  } catch (error: any) {
    // Extract PostgreSQL error details for proper logging
    // Error properties exist on prototype chain and don't serialize with JSON.stringify
    const errorDetails = {
      message: error.message || 'Unknown error',
      code: error.code || 'UNKNOWN',
      detail: error.detail || null,
      hint: error.hint || null,
      position: error.position || null,
      where: error.where || null,
      schema: error.schema || null,
      table: error.table || null,
      column: error.column || null,
      dataType: error.dataType || null,
      constraint: error.constraint || null,
    };

    // Never log the parameter VALUES — they routinely carry secrets (password
    // hashes, encrypted MFA secrets, API keys). The query text + a param count is
    // enough to debug; values stay out of the logs.
    logger.error('Database query error:', {
      query: text,
      paramCount: Array.isArray(params) ? params.length : 0,
      error: errorDetails,
      stack: error.stack,
    });

    throw error;
  }
};

export const getClient = () => {
  return router.inIngest()
    ? withConnectRetry(() => ingestPool.connect(), ingestRetry, ingestRetryDeps)
    : pool.connect();
};

export interface PoolStats {
  /** Connections open (checked out + idle). */
  total: number;
  idle: number;
  /** Callers queued waiting for a free connection. */
  waiting: number;
  max: number;
}

/** Point-in-time pool usage plus how often ingest had to retry a connection -- for diagnosing overload. */
export function getPoolStats(): { main: PoolStats; ingest: PoolStats; ingestRetries: number } {
  const stats = (p: Pool, max: number): PoolStats => ({
    total: p.totalCount,
    idle: p.idleCount,
    waiting: p.waitingCount,
    max,
  });
  return {
    main: stats(pool, MAIN_POOL_MAX),
    ingest: stats(ingestPool, INGEST_POOL_MAX),
    ingestRetries,
  };
}

let closing: Promise<void> | null = null;

/** Close both pools (idempotent). Resolves once every checked-out client has been returned. */
export function closePools(): Promise<void> {
  closing ??= Promise.allSettled([pool.end(), ingestPool.end()]).then(() => undefined);
  return closing;
}

export default pool;
