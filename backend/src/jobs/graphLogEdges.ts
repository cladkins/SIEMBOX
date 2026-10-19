/**
 * Context Graph log relationships: runs the rollup (services/graph/
 * logEdgeRollup.ts) every minute on the main pool, never the ingest pool, so
 * ingestion is untouched and relationships trail the logs by about two to
 * three minutes. A backlog (the upgrade's backfill, or catching up after the
 * switch was off) drains in small batches with rests between them, at up to
 * 20 s of database time a run.
 *
 * Admin -> Background Jobs shows it as "Context Graph log relationships"; it
 * reads "disabled" while Settings -> Context Graph has it switched off (the
 * timer keeps ticking, so switching it back on needs no restart).
 */
import pool from '../config/database';
import { logger } from '../utils/logger';
import { ErrorLogService } from '../services/errors/errorLogService';
import { registerRecurringJob, trackJobRun } from '../services/jobs/jobRegistry';
import { describeRollup, readLogEdgeSettings, runLogEdgeRollup, type RollupClient } from '../services/graph/logEdgeRollup';

export const GRAPH_LOG_EDGES_JOB_KEY = 'graph-log-edges';
const INTERVAL_MS = 60_000;
const STARTUP_DELAY_MS = 30_000;
const NAME = 'Context Graph log relationships';
const DESCRIPTION =
  'Rolls up who signed in from where, which device logged what, and which domains an IP queried, for the Context Graph. ' +
  'Runs every minute, a few minutes behind ingestion, and keeps relationships as long as raw logs.';

let intervalId: NodeJS.Timeout | null = null;
let startupTimer: NodeJS.Timeout | null = null;
let running = false;
let registeredEnabled: boolean | null = null;

// The main pool explicitly: never the ingest pool.
const connect = () => pool.connect() as unknown as Promise<RollupClient>;

function register(enabled: boolean): void {
  if (registeredEnabled === enabled) return;
  registerRecurringJob({ key: GRAPH_LOG_EDGES_JOB_KEY, name: NAME, description: DESCRIPTION, intervalMs: INTERVAL_MS, enabled });
  registeredEnabled = enabled;
}

export async function tickGraphLogEdges(): Promise<void> {
  if (running) return; // the previous run is still going: never overlap
  running = true;
  try {
    const client = await connect();
    let enabled: boolean;
    try {
      enabled = (await readLogEdgeSettings((sql, params) => client.query(sql, params))).enabled;
    } finally {
      client.release();
    }
    register(enabled);
    if (!enabled) return;
    const summary = await trackJobRun(GRAPH_LOG_EDGES_JOB_KEY, async () => describeRollup(await runLogEdgeRollup({ connect })));
    logger.debug(`[GraphLogEdges] ${summary}`);
  } catch (error) {
    ErrorLogService.logBackgroundError('graph-log-edges', error, { dedupeKey: 'rollup' });
  } finally {
    running = false;
  }
}

export function startGraphLogEdgesJob(): void {
  if (intervalId) return;
  register(true);
  startupTimer = setTimeout(() => void tickGraphLogEdges(), STARTUP_DELAY_MS);
  intervalId = setInterval(() => void tickGraphLogEdges(), INTERVAL_MS);
}

export function stopGraphLogEdgesJob(): void {
  if (startupTimer) {
    clearTimeout(startupTimer);
    startupTimer = null;
  }
  if (intervalId) {
    clearInterval(intervalId);
    intervalId = null;
  }
}
