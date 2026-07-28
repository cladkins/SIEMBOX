/**
 * Threat-feed refresh job.
 *
 * Wakes periodically and refreshes any enabled feed that's due (per its own
 * refresh_interval_minutes). FeedService handles fetch failures internally, so
 * a blocked-egress deployment just keeps recording last_status='error' without
 * crashing anything. Also kicks an initial refresh shortly after startup so a
 * fresh install populates without waiting a full interval.
 */

import { FeedService } from '../services/threatintel/feedService';
import { logger } from '../utils/logger';
import { ErrorLogService } from '../services/errors/errorLogService';
import { registerRecurringJob, trackJobRun } from '../services/jobs/jobRegistry';

const JOB_KEY = 'threat-feeds';

let intervalId: NodeJS.Timeout | null = null;
let startupTimer: NodeJS.Timeout | null = null;
const CHECK_INTERVAL_MS = 30 * 60 * 1000; // re-evaluate due feeds every 30 min
const STARTUP_DELAY_MS = 15 * 1000; // let the rest of boot settle first

async function tick(): Promise<void> {
  try {
    await trackJobRun(JOB_KEY, async () => {
      const { refreshed } = await FeedService.refreshAllEnabled(false);
      if (refreshed > 0) logger.info(`[ThreatFeeds] refreshed ${refreshed} feed(s)`);
      return `refreshed ${refreshed} feed(s)`;
    });
  } catch (err) {
    logger.error('[ThreatFeeds] refresh cycle failed:', err);
    ErrorLogService.logBackgroundError('threat-feed', err, { dedupeKey: 'refresh-cycle' });
  }
}

export function startThreatFeedsJob(): void {
  if (intervalId) return;
  registerRecurringJob({
    key: JOB_KEY,
    name: 'Threat feed refresh',
    description: 'Re-fetches enabled external blocklists and updates threat indicators.',
    intervalMs: CHECK_INTERVAL_MS,
  });
  startupTimer = setTimeout(() => {
    void tick();
  }, STARTUP_DELAY_MS);
  intervalId = setInterval(() => {
    void tick();
  }, CHECK_INTERVAL_MS);
  logger.info('[ThreatFeeds] refresh job started');
}

export function stopThreatFeedsJob(): void {
  if (startupTimer) {
    clearTimeout(startupTimer);
    startupTimer = null;
  }
  if (intervalId) {
    clearInterval(intervalId);
    intervalId = null;
  }
}
