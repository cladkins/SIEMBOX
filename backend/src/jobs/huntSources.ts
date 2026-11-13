/**
 * Threat Hunting background job.
 *
 * At startup it queues again any hunt the previous process left unfinished.
 * Then, every CHECK_INTERVAL_MS (5 minutes), it checks the monitored hunt sources that are
 * due (each has its own check_interval_minutes); new feed items and changed
 * pages become hunts (services/hunting/sourceMonitor.ts).
 */
import { checkDueSources } from '../services/hunting/sourceMonitor';
import { recoverHunts, stopHuntQueue } from '../services/hunting/huntService';
import { logger } from '../utils/logger';
import { ErrorLogService } from '../services/errors/errorLogService';
import { registerRecurringJob, trackJobRun } from '../services/jobs/jobRegistry';

const JOB_KEY = 'hunt-sources';
// Cheap when nothing is due (one query); each source keeps its own interval.
const CHECK_INTERVAL_MS = 5 * 60 * 1000;
const STARTUP_DELAY_MS = 30 * 1000;

let intervalId: NodeJS.Timeout | null = null;
let startupTimer: NodeJS.Timeout | null = null;

async function tick(): Promise<void> {
  try {
    await trackJobRun(JOB_KEY, async () => {
      const { checked, hunts_created } = await checkDueSources();
      if (checked > 0) logger.info(`[HuntSources] checked ${checked} source(s), created ${hunts_created} hunt(s)`);
      return `checked ${checked} source(s), created ${hunts_created} hunt(s)`;
    });
  } catch (err) {
    logger.error('[HuntSources] check cycle failed:', err);
    ErrorLogService.logBackgroundError('hunt-source', err, { dedupeKey: 'check-cycle' });
  }
}

export function startHuntSourcesJob(): void {
  if (intervalId) return;
  registerRecurringJob({
    key: JOB_KEY,
    name: 'Threat hunt sources',
    description: 'Checks monitored threat-report feeds and pages, and turns new reports into threat hunts.',
    intervalMs: CHECK_INTERVAL_MS,
  });
  startupTimer = setTimeout(() => {
    recoverHunts().catch((err) => logger.warn('[Hunt] could not resume unfinished hunts:', err));
    void tick();
  }, STARTUP_DELAY_MS);
  intervalId = setInterval(() => {
    void tick();
  }, CHECK_INTERVAL_MS);
  logger.info('[HuntSources] job started');
}

export function stopHuntSourcesJob(): void {
  if (startupTimer) {
    clearTimeout(startupTimer);
    startupTimer = null;
  }
  if (intervalId) {
    clearInterval(intervalId);
    intervalId = null;
  }
  stopHuntQueue();
}
