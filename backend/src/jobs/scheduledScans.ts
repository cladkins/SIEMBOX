/**
 * Scheduled Scans Job
 *
 * Periodically triggers user-defined recurring vulnerability and asset scans.
 * A schedule is "due" when enabled and next_run_at <= NOW(); after triggering,
 * next_run_at is rolled forward by interval_minutes.
 */

import { ScheduledScanModel, ScheduledScan } from '../models/ScheduledScan';
import { NucleiScanner } from '../services/scanner/nucleiScanner';
import { NmapScanner } from '../services/scanner/nmapScanner';
import { TrivyScanner } from '../services/scanner/trivyScanner';
import { LogShipperModel } from '../models/LogShipper';
import { logger } from '../utils/logger';
import { ErrorLogService } from '../services/errors/errorLogService';
import { registerRecurringJob, trackJobRun, markJobResult } from '../services/jobs/jobRegistry';
import { pendingScheduledRun, type ScanOrigin } from '../services/scanner/shipperJobs';

const JOB_KEY = 'scheduled-scans';

let intervalId: NodeJS.Timeout | null = null;
const CHECK_INTERVAL_MS = 60 * 1000; // look for due scans once a minute

/**
 * The schedule's previous run, when it is still queued for the schedule's
 * shipper (not yet picked up). While one waits, the scheduler doesn't queue
 * another: an offline shipper would otherwise collect one identical job per
 * interval and run them all back to back when it returns. The waiting run
 * expires like any other shipper job (services/scanner/shipperJobs.ts), after
 * which the next due run queues normally.
 */
export async function pendingRunFor(schedule: ScheduledScan): Promise<number | null> {
  if (schedule.scan_type === 'container') return null;
  const shipperId = schedule.scan_options?.assignedShipperId ?? null;
  return pendingScheduledRun(schedule.last_scan_id ?? null, shipperId);
}

/**
 * Trigger a single schedule's scan and return the created scan id.
 * Reused by both the scheduler loop and the "run now" route.
 */
export async function triggerScheduledScan(schedule: ScheduledScan): Promise<number> {
  const opts = schedule.scan_options || {};
  const userId = schedule.created_by || 1;
  const description = `Scheduled: ${schedule.name}`;
  const origin: ScanOrigin = { page: 'scheduled_scans', scheduledScanId: schedule.id, scheduledScanName: schedule.name };
  // A schedule saved with confirmed public targets passes that on to each run.
  // One saved before the public-target check has none and still runs.
  const publicTargetsConfirmation = opts.publicTargetsConfirmation ?? null;

  // Container scans are Trivy image scans (no LAN scan), so they are never
  // dispatched to a shipper -- handle first, before resolving any shipper.
  if (schedule.scan_type === 'container') {
    return TrivyScanner.scan(opts.image_ref, userId);
  }

  // Optional LAN-side dispatch: run this scheduled scan from a log shipper
  // (stored as scan_options.assignedShipperId). Re-check the shipper still
  // exists at fire time -- it may have been deleted since the schedule was
  // configured -- and fall back to an in-process scan rather than failing the
  // run (a hard FK insert would otherwise throw and the schedule would error
  // every cycle).
  let assignedShipperId: number | null = opts.assignedShipperId ?? null;
  if (assignedShipperId != null) {
    const shipper = await LogShipperModel.findById(assignedShipperId);
    if (!shipper) {
      logger.warn(
        `[Scheduled Scans] Schedule #${schedule.id} ("${schedule.name}") references missing shipper ${assignedShipperId}; running on the backend instead`
      );
      assignedShipperId = null;
    }
  }

  if (schedule.scan_type === 'vulnerability') {
    return NucleiScanner.scan({
      target: opts.target,
      templateSelection: opts.templateSelection || { tags: ['cve', 'rce', 'sqli', 'xss', 'lfi'] },
      userId,
      description,
      timeout: opts.timeout,
      rateLimit: opts.rateLimit,
      assignedShipperId,
      origin,
      publicTargetsConfirmation,
    });
  }

  return NmapScanner.scan({
    targets: Array.isArray(opts.targets) ? opts.targets : [],
    scanType: opts.scanType || 'port',
    userId,
    description,
    assignedShipperId,
    origin,
    publicTargetsConfirmation,
  });
}

/**
 * Find and run all due schedules. Each schedule advances next_run_at even on
 * failure so a broken one cannot hammer the scanner every minute.
 */
export async function runDueScheduledScans(): Promise<void> {
  let due: ScheduledScan[];
  try {
    due = await trackJobRun(JOB_KEY, () => ScheduledScanModel.findDue());
  } catch (error) {
    logger.error('[Scheduled Scans] Failed to query due schedules:', error);
    ErrorLogService.logBackgroundError('scheduled-scan', error, { dedupeKey: 'find-due' });
    return;
  }

  let triggered = 0;
  let deferred = 0;
  for (const schedule of due) {
    try {
      const pending = await pendingRunFor(schedule);
      if (pending !== null) {
        // Previous run still waiting for its shipper: roll the schedule
        // forward without queuing a duplicate.
        await ScheduledScanModel.markRun(schedule.id, pending);
        deferred += 1;
        logger.info(
          `[Scheduled Scans] "${schedule.name}" (#${schedule.id}) is due, but its previous run (scan ${pending}) is still queued for its shipper; not queuing another`
        );
        continue;
      }
      const scanId = await triggerScheduledScan(schedule);
      await ScheduledScanModel.markRun(schedule.id, scanId);
      triggered += 1;
      logger.info(
        `[Scheduled Scans] Triggered ${schedule.scan_type} scan for "${schedule.name}" (#${schedule.id}) -> scan ${scanId}`
      );
    } catch (error) {
      logger.error(`[Scheduled Scans] Schedule #${schedule.id} (${schedule.name}) failed:`, error);
      ErrorLogService.logBackgroundError('scheduled-scan', error, {
        dedupeKey: `run-${schedule.id}`,
        scheduleId: schedule.id,
        scanType: schedule.scan_type,
      });
      // Advance next_run_at anyway so the failure doesn't retry every minute.
      await ScheduledScanModel.markRun(schedule.id, null).catch(() => {});
    }
  }

  markJobResult(
    JOB_KEY,
    due.length === 0
      ? 'nothing due'
      : `triggered ${triggered} of ${due.length} due schedule(s)` +
          (deferred > 0 ? `; ${deferred} still waiting on a queued shipper run` : '')
  );
}

export function startScheduledScansJob(): void {
  if (intervalId) {
    return;
  }
  registerRecurringJob({
    key: JOB_KEY,
    name: 'Scheduled scan dispatcher',
    description: 'Triggers user-defined recurring vulnerability, asset and container scans when due.',
    intervalMs: CHECK_INTERVAL_MS,
  });
  logger.info('[Scheduled Scans] Scheduler started (checking every 60s)');
  intervalId = setInterval(() => {
    runDueScheduledScans().catch((err) => logger.error('[Scheduled Scans] cycle error:', err));
  }, CHECK_INTERVAL_MS);
}

export function stopScheduledScansJob(): void {
  if (intervalId) {
    clearInterval(intervalId);
    intervalId = null;
    logger.info('[Scheduled Scans] Scheduler stopped');
  }
}
