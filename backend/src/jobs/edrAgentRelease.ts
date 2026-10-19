/**
 * Endpoint-agent release check. Every 6 hours (and shortly after startup) asks
 * GitHub for the latest siembox-endpoint release and stores it; with
 * auto-update on, outdated agents are then asked to update. Network failures
 * are recorded (edr_agent_latest_error) and never crash the process.
 */
import { checkForAgentRelease } from '../services/edr/agentUpdateService';
import { logger } from '../utils/logger';
import { ErrorLogService } from '../services/errors/errorLogService';
import { registerRecurringJob, trackJobRun } from '../services/jobs/jobRegistry';

const JOB_KEY = 'edr-agent-release';
const CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000;
const STARTUP_DELAY_MS = 60 * 1000;

let intervalId: NodeJS.Timeout | null = null;
let startupTimer: NodeJS.Timeout | null = null;

async function tick(): Promise<void> {
  try {
    await trackJobRun(JOB_KEY, async () => {
      const status = await checkForAgentRelease();
      if (status.error) throw new Error(status.error);
      return `latest agent release v${status.latest_version}`;
    });
  } catch (err) {
    logger.warn('[EDR] agent release check failed:', err instanceof Error ? err.message : err);
    ErrorLogService.logBackgroundError('edr-agent-release', err, { dedupeKey: 'check' });
  }
}

export function startEdrAgentReleaseJob(): void {
  if (intervalId) return;
  registerRecurringJob({
    key: JOB_KEY,
    name: 'Endpoint agent release check',
    description:
      'Checks GitHub for the latest siembox-endpoint release and, when auto-update is on, requests updates for outdated endpoints.',
    intervalMs: CHECK_INTERVAL_MS,
  });
  startupTimer = setTimeout(() => void tick(), STARTUP_DELAY_MS);
  intervalId = setInterval(() => void tick(), CHECK_INTERVAL_MS);
  logger.info('[EDR] agent release check job started (every 6h)');
}

export function stopEdrAgentReleaseJob(): void {
  if (startupTimer) {
    clearTimeout(startupTimer);
    startupTimer = null;
  }
  if (intervalId) {
    clearInterval(intervalId);
    intervalId = null;
  }
}
