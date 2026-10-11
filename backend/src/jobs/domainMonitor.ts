/**
 * Domain-monitor job (Digital Risk): certificate transparency, lookalike
 * domains, RDAP registration data and DNS drift for the watched domains.
 *
 * Wakes every 15 minutes; each domain's own interval_minutes (daily by
 * default) decides whether it is actually checked, so the tick only bounds how
 * late a check can start. Skips cheaply (no outbound traffic) when the feature
 * is switched off or no domain is due.
 */

import { logger } from '../utils/logger';
import { ErrorLogService } from '../services/errors/errorLogService';
import {
  registerRecurringJob,
  trackJobRun,
  markJobResult,
  markJobSkipped,
} from '../services/jobs/jobRegistry';
import {
  DOMAIN_MONITOR_JOB_KEY,
  describeDomainMonitorRun,
  getDomainMonitorSkipReason,
  runDomainChecks,
} from '../services/exposure/domainMonitor/domainMonitorService';

let intervalId: NodeJS.Timeout | null = null;
let startupTimer: NodeJS.Timeout | null = null;
const CHECK_INTERVAL_MS = 15 * 60 * 1000; // re-evaluate due domains every 15 min
const STARTUP_DELAY_MS = 2 * 60 * 1000; // after boot settles (and after the leaked-creds job's first run)

async function tick(): Promise<void> {
  try {
    const skipReason = await getDomainMonitorSkipReason();
    if (skipReason) {
      markJobSkipped(DOMAIN_MONITOR_JOB_KEY, skipReason);
      return;
    }

    const summary = await trackJobRun(DOMAIN_MONITOR_JOB_KEY, () => runDomainChecks());
    if (summary.skipped) {
      // e.g. the previous cycle is still running.
      markJobSkipped(DOMAIN_MONITOR_JOB_KEY, summary.reason ?? 'skipped');
      return;
    }
    const line = describeDomainMonitorRun(summary);
    markJobResult(DOMAIN_MONITOR_JOB_KEY, line);
    logger.info(`[DomainMonitor] ${line}`);
  } catch (err) {
    logger.error('[DomainMonitor] check cycle failed:', err);
    ErrorLogService.logBackgroundError('domain-monitor', err, { dedupeKey: 'check-cycle' });
  }
}

export function startDomainMonitorJob(): void {
  if (intervalId) return;
  registerRecurringJob({
    key: DOMAIN_MONITOR_JOB_KEY,
    name: 'Domain monitoring',
    description:
      'Checks watched domains for new certificates, registered lookalikes, registration (RDAP) changes and DNS drift when each is due.',
    intervalMs: CHECK_INTERVAL_MS,
  });
  startupTimer = setTimeout(() => {
    void tick();
  }, STARTUP_DELAY_MS);
  intervalId = setInterval(() => {
    void tick();
  }, CHECK_INTERVAL_MS);
  logger.info('[DomainMonitor] check job started');
}

export function stopDomainMonitorJob(): void {
  if (startupTimer) {
    clearTimeout(startupTimer);
    startupTimer = null;
  }
  if (intervalId) {
    clearInterval(intervalId);
    intervalId = null;
  }
}
