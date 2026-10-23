/**
 * SigmaHQ library refresh. Checks hourly whether the cache is a day old and,
 * if so, refreshes it (one small request when the release is unchanged; the
 * archive is downloaded only for a new release). The check is against the
 * stored fetch time, so restarts do not refetch. SIGMAHQ_AUTO_REFRESH=false
 * turns the job off (air-gapped installs): Refresh on the page still works.
 * Failures are recorded in sigma_library_state and never crash the process.
 */
import { logger } from '../utils/logger';
import { ErrorLogService } from '../services/errors/errorLogService';
import { registerRecurringJob, trackJobRun } from '../services/jobs/jobRegistry';
import { getSigmaState, refreshSigmaLibrary, sigmaAutoRefresh } from '../services/sigma/sigmaStore';

const JOB_KEY = 'sigmahq-library';
const CHECK_INTERVAL_MS = 60 * 60 * 1000;
const REFRESH_AFTER_MS = 24 * 60 * 60 * 1000;
const STARTUP_DELAY_MS = 3 * 60 * 1000;

let intervalId: NodeJS.Timeout | null = null;
let startupTimer: NodeJS.Timeout | null = null;

/** Due when there is no cache, or the last attempt (success or failure) is a day old. */
export function sigmaRefreshDue(state: { last_attempt_at: string | null; fetched_at: string | null }, now = Date.now()): boolean {
  const last = state.last_attempt_at ?? state.fetched_at;
  return !last || now - new Date(last).getTime() >= REFRESH_AFTER_MS;
}

async function tick(): Promise<void> {
  try {
    if (!sigmaRefreshDue(await getSigmaState())) return;
    await trackJobRun(JOB_KEY, async () => {
      const r = await refreshSigmaLibrary();
      return r.status === 'updated' ? `stored SigmaHQ ${r.release_tag}` : `SigmaHQ ${r.release_tag} unchanged`;
    });
  } catch (err) {
    logger.warn('[sigma] SigmaHQ library refresh failed:', err instanceof Error ? err.message : err);
    ErrorLogService.logBackgroundError('sigmahq-library', err, { dedupeKey: 'refresh' });
  }
}

export function startSigmaLibraryJob(): void {
  if (intervalId) return;
  const enabled = sigmaAutoRefresh();
  registerRecurringJob({
    key: JOB_KEY,
    name: 'SigmaHQ library refresh',
    description: 'Downloads the latest SigmaHQ rule release once a day for Detection Rules > SigmaHQ.',
    intervalMs: REFRESH_AFTER_MS,
    enabled,
  });
  if (!enabled) {
    logger.info('[sigma] SigmaHQ library auto-refresh is off (SIGMAHQ_AUTO_REFRESH=false)');
    return;
  }
  startupTimer = setTimeout(() => void tick(), STARTUP_DELAY_MS);
  intervalId = setInterval(() => void tick(), CHECK_INTERVAL_MS);
}

export function stopSigmaLibraryJob(): void {
  if (startupTimer) clearTimeout(startupTimer);
  if (intervalId) clearInterval(intervalId);
  startupTimer = null;
  intervalId = null;
}
