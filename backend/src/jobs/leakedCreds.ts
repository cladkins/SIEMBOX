/**
 * Leaked-credential check job (exposure monitoring).
 *
 * Wakes every 15 minutes and checks the monitored identities that are due —
 * each identity's own interval_minutes (daily by default) decides how often it
 * is actually polled, so the tick only bounds how late a check can start.
 * Skips cheaply (no HIBP call) when the feature is off, no provider is
 * configured, HIBP asked us to back off, or nothing is due.
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
  LEAKED_CREDS_JOB_KEY,
  describeRunSummary,
  getLeakedCredentialSkipReason,
  runLeakedCredentialChecks,
} from '../services/exposure/leakedCredentialService';

let intervalId: NodeJS.Timeout | null = null;
let startupTimer: NodeJS.Timeout | null = null;
const CHECK_INTERVAL_MS = 15 * 60 * 1000; // re-evaluate due identities every 15 min
const STARTUP_DELAY_MS = 60 * 1000; // let boot (and the other jobs' first runs) settle

async function tick(): Promise<void> {
  try {
    const skipReason = await getLeakedCredentialSkipReason();
    if (skipReason) {
      markJobSkipped(LEAKED_CREDS_JOB_KEY, skipReason);
      return;
    }

    const summary = await trackJobRun(LEAKED_CREDS_JOB_KEY, async () => {
      const result = await runLeakedCredentialChecks({ trigger: 'schedule' });
      // A rejected key or an unreachable provider is a failed cycle; a rate
      // limit is HIBP's normal backpressure, handled by pausing.
      if (result.error && !result.rateLimitedUntil) {
        throw new Error(`${result.error} (${describeRunSummary({ ...result, error: undefined })})`);
      }
      return result;
    });

    if (summary.skipped) {
      // e.g. an admin's "run now" was already in flight.
      markJobSkipped(LEAKED_CREDS_JOB_KEY, summary.reason ?? 'skipped');
      return;
    }
    const line = describeRunSummary(summary);
    markJobResult(LEAKED_CREDS_JOB_KEY, line);
    logger.info(`[LeakedCreds] ${line}`);
  } catch (err) {
    logger.error('[LeakedCreds] check cycle failed:', err);
    ErrorLogService.logBackgroundError('leaked-creds', err, { dedupeKey: 'check-cycle' });
  }
}

export function startLeakedCredsJob(): void {
  if (intervalId) return;
  registerRecurringJob({
    key: LEAKED_CREDS_JOB_KEY,
    name: 'Leaked-credential checks',
    description:
      'Checks monitored email addresses and email domains against Have I Been Pwned when each is due.',
    intervalMs: CHECK_INTERVAL_MS,
  });
  startupTimer = setTimeout(() => {
    void tick();
  }, STARTUP_DELAY_MS);
  intervalId = setInterval(() => {
    void tick();
  }, CHECK_INTERVAL_MS);
  logger.info('[LeakedCreds] check job started');
}

export function stopLeakedCredsJob(): void {
  if (startupTimer) {
    clearTimeout(startupTimer);
    startupTimer = null;
  }
  if (intervalId) {
    clearInterval(intervalId);
    intervalId = null;
  }
}
