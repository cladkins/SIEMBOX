/**
 * Log Discovery API-pull poller job.
 *
 * Wakes periodically and polls any source that's due (per its own
 * poll_interval_minutes). pollDueSources handles per-source failures
 * internally (see apiPoll/poller.ts), so one misbehaving source just keeps
 * recording last_status='error' without affecting the others. Mirrors
 * jobs/threatFeeds.ts's structure.
 */

import { pollDueSources } from '../services/logDiscovery/apiPoll/poller';
import { logger } from '../utils/logger';
import { ErrorLogService } from '../services/errors/errorLogService';
import { registerRecurringJob, trackJobRun } from '../services/jobs/jobRegistry';

const JOB_KEY = 'discovery-api-poller';

let intervalId: NodeJS.Timeout | null = null;
let startupTimer: NodeJS.Timeout | null = null;
// Tighter than threat-feeds' 30min tick: per-source poll_interval_minutes goes
// as low as 1 minute, so the check itself needs to run at least that often.
const CHECK_INTERVAL_MS = 60 * 1000;
const STARTUP_DELAY_MS = 20 * 1000; // let the rest of boot settle first

async function tick(): Promise<void> {
  try {
    await trackJobRun(JOB_KEY, async () => {
      const { polled } = await pollDueSources();
      return `polled ${polled} source(s)`;
    });
  } catch (err) {
    logger.error('[DiscoveryApiPoller] poll cycle failed:', err);
    ErrorLogService.logBackgroundError('discovery-api-poller', err, { dedupeKey: 'poll-cycle' });
  }
}

export function startDiscoveryApiPollerJob(): void {
  if (intervalId) return;
  registerRecurringJob({
    key: JOB_KEY,
    name: 'Log Discovery API poller',
    description: 'Pulls events from discovered sources configured for API-based polling (Authentik, Home Assistant, Pi-hole, AdGuard Home).',
    intervalMs: CHECK_INTERVAL_MS,
  });
  startupTimer = setTimeout(() => {
    void tick();
  }, STARTUP_DELAY_MS);
  intervalId = setInterval(() => {
    void tick();
  }, CHECK_INTERVAL_MS);
  logger.info('[DiscoveryApiPoller] poller job started');
}

export function stopDiscoveryApiPollerJob(): void {
  if (startupTimer) {
    clearTimeout(startupTimer);
    startupTimer = null;
  }
  if (intervalId) {
    clearInterval(intervalId);
    intervalId = null;
  }
}
