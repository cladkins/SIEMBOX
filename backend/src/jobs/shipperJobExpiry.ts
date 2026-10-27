/**
 * Shipper job expiry, every five minutes (first run a minute after boot): marks
 * scan jobs queued for a log shipper 'expired' once they have waited longer
 * than shipper_job_expiry_hours without being claimed, so they are never run
 * late. See services/scanner/shipperJobs.ts; the claim queries enforce the same
 * window between sweeps.
 */
import { logger } from '../utils/logger';
import { ErrorLogService } from '../services/errors/errorLogService';
import { registerRecurringJob, trackJobRun } from '../services/jobs/jobRegistry';
import { expireStaleShipperJobs, type ExpiryResult } from '../services/scanner/shipperJobs';

export const SHIPPER_JOB_EXPIRY_JOB_KEY = 'shipper-job-expiry';
const INTERVAL_MS = 5 * 60 * 1000;
const STARTUP_DELAY_MS = 60 * 1000;

let intervalId: NodeJS.Timeout | null = null;
let startupTimer: NodeJS.Timeout | null = null;

export function describeExpiry(result: ExpiryResult): string {
  const n = result.scans.length + result.discoveryScans.length;
  return n === 0
    ? `nothing older than ${result.hours} h`
    : `expired ${n} unclaimed job(s) older than ${result.hours} h`;
}

async function tick(): Promise<void> {
  try {
    const summary = await trackJobRun(SHIPPER_JOB_EXPIRY_JOB_KEY, async () => describeExpiry(await expireStaleShipperJobs()));
    if (!summary.startsWith('nothing')) logger.info(`[ShipperJobExpiry] ${summary}`);
  } catch (error) {
    ErrorLogService.logBackgroundError('shipper-job-expiry', error, { dedupeKey: 'cycle' });
  }
}

export function startShipperJobExpiryJob(): void {
  if (intervalId) return;
  registerRecurringJob({
    key: SHIPPER_JOB_EXPIRY_JOB_KEY,
    name: 'Shipper job expiry',
    description:
      'Expires scan jobs queued for a log shipper that the shipper has not picked up within the expiry window (Settings > Asset Discovery), so they never run late.',
    intervalMs: INTERVAL_MS,
  });
  startupTimer = setTimeout(() => void tick(), STARTUP_DELAY_MS);
  intervalId = setInterval(() => void tick(), INTERVAL_MS);
}

export function stopShipperJobExpiryJob(): void {
  if (startupTimer) {
    clearTimeout(startupTimer);
    startupTimer = null;
  }
  if (intervalId) {
    clearInterval(intervalId);
    intervalId = null;
  }
}
