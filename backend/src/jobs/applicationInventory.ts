/**
 * Application Monitoring: runs the inventory rollup (services/applications/
 * rollup.ts) every two minutes on the main pool, never the ingest pool, so
 * ingestion is untouched and the inventory trails the logs by a few minutes.
 * A backlog (the upgrade's backfill) drains in small batches with rests
 * between them, at up to 15 s of database time a run.
 *
 * Admin -> Background Jobs shows it as "Application inventory"; it reads
 * "disabled" while Settings -> Application Monitoring has it switched off
 * (the timer keeps ticking, so switching it back on needs no restart).
 * POST /api/applications/refresh runs it at once (runApplicationInventoryNow);
 * saving a local signature starts a run too (kickApplicationInventory).
 */
import pool from '../config/database';
import { logger } from '../utils/logger';
import { ErrorLogService } from '../services/errors/errorLogService';
import { registerRecurringJob, trackJobRun } from '../services/jobs/jobRegistry';
import { describeInventoryRun, readInventorySettings, runInventoryRollup, type InventoryRunResult, type RollupClient } from '../services/applications/rollup';

export const APPLICATION_INVENTORY_JOB_KEY = 'application-inventory';
const INTERVAL_MS = 120_000;
const STARTUP_DELAY_MS = 45_000;
const NAME = 'Application inventory';
const DESCRIPTION =
  'Matches log programs, parsers, nmap services, shipper containers, EDR findings, user agents and DNS queries against the ' +
  "catalog's application signatures and your local ones for Application Monitoring. Runs every two minutes, a few minutes behind ingestion.";

let intervalId: NodeJS.Timeout | null = null;
let startupTimer: NodeJS.Timeout | null = null;
let running: Promise<InventoryRunResult | null> | null = null;
let registeredEnabled: boolean | null = null;

const connect = () => pool.connect() as unknown as Promise<RollupClient>;

function register(enabled: boolean): void {
  if (registeredEnabled === enabled) return;
  registerRecurringJob({ key: APPLICATION_INVENTORY_JOB_KEY, name: NAME, description: DESCRIPTION, intervalMs: INTERVAL_MS, enabled });
  registeredEnabled = enabled;
}

async function tick(forceCatalog: boolean): Promise<InventoryRunResult | null> {
  const client = await connect();
  let enabled: boolean;
  try {
    enabled = (await readInventorySettings((sql, params) => client.query(sql, params))).enabled;
  } finally {
    client.release();
  }
  register(enabled);
  if (!enabled) return null;
  let result: InventoryRunResult | null = null;
  await trackJobRun(APPLICATION_INVENTORY_JOB_KEY, async () => {
    result = await runInventoryRollup({ connect, forceCatalog });
    return describeInventoryRun(result);
  });
  logger.debug(`[ApplicationInventory] ${result ? describeInventoryRun(result) : 'no result'}`);
  return result;
}

export async function tickApplicationInventory(): Promise<void> {
  if (running) return; // the previous run is still going: never overlap
  running = tick(false);
  try {
    await running;
  } catch (error) {
    ErrorLogService.logBackgroundError('application-inventory', error, { dedupeKey: 'rollup' });
  } finally {
    running = null;
  }
}

/**
 * Run now (the page's Refresh): re-reads the catalog. 'busy' when a run is
 * already going (the caller answers 409), null when switched off.
 */
export async function runApplicationInventoryNow(): Promise<InventoryRunResult | null | 'busy'> {
  if (running) return 'busy';
  running = tick(true);
  try {
    return await running;
  } finally {
    running = null;
  }
}

/**
 * A saved local signature: run the rollup now (snapshot evidence matches on
 * this run, the look back starts) instead of at the next tick. Only while
 * the job is running (not in tests or one-off scripts); a run already going
 * leaves it to the next tick.
 */
export function kickApplicationInventory(): void {
  if (!intervalId || running) return;
  void tickApplicationInventory();
}

export function startApplicationInventoryJob(): void {
  if (intervalId) return;
  register(true);
  startupTimer = setTimeout(() => void tickApplicationInventory(), STARTUP_DELAY_MS);
  intervalId = setInterval(() => void tickApplicationInventory(), INTERVAL_MS);
}

export function stopApplicationInventoryJob(): void {
  if (startupTimer) {
    clearTimeout(startupTimer);
    startupTimer = null;
  }
  if (intervalId) {
    clearInterval(intervalId);
    intervalId = null;
  }
}
