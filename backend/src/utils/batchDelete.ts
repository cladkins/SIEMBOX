import { query } from '../config/database';
import { logger } from './logger';

export interface BatchDeleteOpts {
  /** Rows deleted per statement. Default 10,000. */
  batchSize?: number;
  /** Short label for the completion log line. */
  label?: string;
  /** Milliseconds to pause between batches so ingestion isn't starved. Default 100. */
  pauseMs?: number;
  /** Injectable executor (defaults to the pooled `query`) — used by tests. */
  exec?: (sql: string, params: any[]) => Promise<{ rowCount: number | null }>;
}

/**
 * Delete the rows matching `where` from `table` in bounded batches.
 *
 * A single unbounded `DELETE` on a high-volume, append-heavy table (raw_logs,
 * parsed_logs, audit_logs, ...) can run for HOURS, hold a lock the entire time,
 * and block schema migrations and writes — which took the backend down on a
 * restart (a retention delete had been running 15h and jammed the boot-time
 * migration). Batching keeps every statement short: each batch is its own
 * autocommitted delete, so locks are held only per-batch and an interrupted run
 * only loses the current batch, never a marathon transaction.
 *
 * SECURITY: `table` and `where` MUST be trusted, code-defined literals (never
 * user input). Row VALUES go through `params` ($1..$N), which are parameterized;
 * the batch-size bind is appended as the final positional parameter.
 */
export async function batchedDelete(
  table: string,
  where: string,
  params: any[] = [],
  opts: BatchDeleteOpts = {}
): Promise<number> {
  const batchSize = opts.batchSize ?? 10_000;
  const pauseMs = opts.pauseMs ?? 100;
  const exec = opts.exec ?? query;
  const limitPlaceholder = `$${params.length + 1}`;

  // ctid-in-subquery is the standard bounded-delete: the inner SELECT uses the
  // indexed predicate + LIMIT to pick a batch, the outer DELETE removes exactly
  // those rows.
  const sql =
    `DELETE FROM ${table} WHERE ctid IN ` +
    `(SELECT ctid FROM ${table} WHERE ${where} LIMIT ${limitPlaceholder})`;

  let total = 0;
  // Hard safety net against a non-terminating loop (10k * 1M = 10B rows).
  for (let i = 0; i < 1_000_000; i++) {
    const res = await exec(sql, [...params, batchSize]);
    const n = res.rowCount || 0;
    total += n;
    if (n < batchSize) break;
    if (pauseMs > 0) await new Promise((resolve) => setTimeout(resolve, pauseMs));
  }

  if (total > 0) {
    logger.info(`batchedDelete: purged ${total} rows from ${table}${opts.label ? ` (${opts.label})` : ''}`);
  }
  return total;
}
