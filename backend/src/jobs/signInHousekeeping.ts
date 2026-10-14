/**
 * Sign-in housekeeping, hourly (first run a minute after boot):
 *
 * - sign-in counters that aren't paused and saw no failure for 24 hours (their
 *   streak has ended anyway);
 * - recognized browsers not used for 90 days;
 * - expired sessions (nothing else removes them);
 * - auth.login.failure audit rows older than AUTH_FAILURE_AUDIT_RETENTION_DAYS
 *   (default 90; 0 keeps them), in batches.
 *
 * Runs with LOGIN_PROTECTION=off too: sessions and audit rows still need it.
 */
import { logger } from '../utils/logger';
import { ErrorLogService } from '../services/errors/errorLogService';
import { registerRecurringJob, trackJobRun } from '../services/jobs/jobRegistry';
import { LoginThrottleModel } from '../models/LoginThrottle';
import { SessionModel } from '../models/Session';
import { deleteStaleBrowsers } from '../services/auth/recognizedBrowsers';
import { signInSettings } from '../services/auth/signInPolicy';
import { batchedDelete } from '../utils/batchDelete';

export const SIGN_IN_HOUSEKEEPING_JOB_KEY = 'sign-in-housekeeping';
const INTERVAL_MS = 60 * 60 * 1000;
const STARTUP_DELAY_MS = 60 * 1000;

let intervalId: NodeJS.Timeout | null = null;
let startupTimer: NodeJS.Timeout | null = null;

export interface HousekeepingResult {
  counters: number;
  browsers: number;
  sessions: number;
  failureAuditRows: number;
}

/** One pass; every step runs even if an earlier one failed, and the first error is re-thrown at the end. */
export async function runSignInHousekeeping(): Promise<HousekeepingResult> {
  const result: HousekeepingResult = { counters: 0, browsers: 0, sessions: 0, failureAuditRows: 0 };
  let firstError: unknown = null;
  const step = async (name: keyof HousekeepingResult, fn: () => Promise<number>) => {
    try {
      result[name] = await fn();
    } catch (error) {
      logger.error(`[SignInHousekeeping] ${name} cleanup failed:`, error);
      firstError ??= error;
    }
  };
  await step('counters', () => LoginThrottleModel.deleteIdle());
  await step('browsers', () => deleteStaleBrowsers());
  await step('sessions', () => SessionModel.deleteExpired());
  const days = signInSettings().failureAuditRetentionDays;
  if (days > 0) {
    await step('failureAuditRows', () =>
      batchedDelete('audit_logs', "action = 'auth.login.failure' AND timestamp < NOW() - INTERVAL '1 day' * $1", [days], {
        label: 'failed sign-in audit retention',
      })
    );
  }
  if (firstError) throw firstError;
  return result;
}

export function describeHousekeeping(result: HousekeepingResult): string {
  return (
    `removed ${result.counters} idle sign-in counters, ${result.browsers} unused browsers, ` +
    `${result.sessions} expired sessions, ${result.failureAuditRows} old failed sign-in audit rows`
  );
}

async function tick(): Promise<void> {
  try {
    const result = await trackJobRun(SIGN_IN_HOUSEKEEPING_JOB_KEY, async () => describeHousekeeping(await runSignInHousekeeping()));
    logger.info(`[SignInHousekeeping] ${result}`);
  } catch (error) {
    ErrorLogService.logBackgroundError('sign-in-housekeeping', error, { dedupeKey: 'cycle' });
  }
}

export function startSignInHousekeepingJob(): void {
  if (intervalId) return;
  registerRecurringJob({
    key: SIGN_IN_HOUSEKEEPING_JOB_KEY,
    name: 'Sign-in housekeeping',
    description:
      'Removes idle sign-in counters, recognized browsers unused for 90 days, expired sessions and old failed sign-in audit rows.',
    intervalMs: INTERVAL_MS,
  });
  startupTimer = setTimeout(() => void tick(), STARTUP_DELAY_MS);
  intervalId = setInterval(() => void tick(), INTERVAL_MS);
}

export function stopSignInHousekeepingJob(): void {
  if (startupTimer) {
    clearTimeout(startupTimer);
    startupTimer = null;
  }
  if (intervalId) {
    clearInterval(intervalId);
    intervalId = null;
  }
}
