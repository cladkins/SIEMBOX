/**
 * AI triage reconciler.
 *
 * The triage queue/concurrency state lives in-memory (triageService.ts), so a
 * backend restart orphans any run left 'pending'/'analyzing' — same failure
 * mode as scanReconciler.ts for vulnerability/discovery scans. On its FIRST
 * tick after boot this job treats every such row as orphaned regardless of
 * age (the in-memory queue is empty right after boot, so any row still
 * "in flight" is by definition dead); on later ticks it only requeues rows
 * stale for longer than STALE_MINUTES (well past the agent loop's own wall
 * budget), and gives up after MAX_ATTEMPTS.
 *
 * It also backfills a small, capped number of recently-created eligible
 * alerts that have no triage row at all — self-healing a crash between the
 * alert insert and the fire-and-forget triage hook.
 */
import { AlertModel } from '../models/Alert';
import { AlertTriageModel } from '../models/AlertTriage';
import { triageAlert } from '../services/ai/triageService';
import { getTriageOperationalConfig } from '../services/ai/aiService';
import { logger } from '../utils/logger';
import { ErrorLogService } from '../services/errors/errorLogService';
import { registerRecurringJob, trackJobRun, markJobSkipped } from '../services/jobs/jobRegistry';

const JOB_KEY = 'ai-triage-reconcile';
const CHECK_INTERVAL_MS = 5 * 60 * 1000;
const STARTUP_DELAY_MS = 20 * 1000;
const STALE_MINUTES = 15; // well beyond the agent loop's own ~110s wall budget
const MAX_ATTEMPTS = 2;
const BATCH = 25;
const BACKFILL_LOOKBACK_HOURS = 2;
const BACKFILL_BATCH = 10;

const SEVERITY_RANK: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };

let intervalId: NodeJS.Timeout | null = null;
let startupTimer: NodeJS.Timeout | null = null;
let firstRun = true;

async function requeueStuck(): Promise<number> {
  const stuck = await AlertTriageModel.findStuck(STALE_MINUTES, BATCH, firstRun);
  let requeued = 0;
  for (const row of stuck) {
    if (row.attempts >= MAX_ATTEMPTS) {
      await AlertTriageModel.markFailed(row.alert_id, 'Triage interrupted (backend restart or timeout)');
      continue;
    }
    void triageAlert(row.alert_id, { triggeredBy: 'reconciler', force: true });
    requeued++;
  }
  return requeued;
}

async function backfillMissed(minSeverity: string): Promise<number> {
  const minRank = SEVERITY_RANK[minSeverity] ?? 1;
  const { alerts } = await AlertModel.findAll({
    startTime: new Date(Date.now() - BACKFILL_LOOKBACK_HOURS * 3600_000),
    limit: 100,
  });
  let queued = 0;
  for (const alert of alerts as any[]) {
    if (queued >= BACKFILL_BATCH) break;
    if ((SEVERITY_RANK[alert.severity] ?? 0) < minRank) continue;
    if (alert.triage_status) continue; // already has a triage row
    void triageAlert(alert.id, { triggeredBy: 'reconciler' });
    queued++;
  }
  return queued;
}

async function tick(): Promise<void> {
  try {
    const cfg = await getTriageOperationalConfig();
    if (!cfg.enabled) {
      markJobSkipped(JOB_KEY, 'AI triage disabled');
      firstRun = false;
      return;
    }

    await trackJobRun(JOB_KEY, async () => {
      const requeued = await requeueStuck();
      const backfilled = await backfillMissed(cfg.minSeverity);
      return `requeued ${requeued}, backfilled ${backfilled}`;
    });
  } catch (err) {
    logger.error('[TriageReconciler] cycle failed:', err);
    ErrorLogService.logBackgroundError('ai-triage-reconcile', err, { dedupeKey: 'cycle' });
  } finally {
    firstRun = false;
  }
}

export function startTriageReconcilerJob(): void {
  if (intervalId) return;
  registerRecurringJob({
    key: JOB_KEY,
    name: 'AI triage reconcile',
    description: 'Re-queues alert triage runs orphaned by a restart and backfills missed eligible alerts.',
    intervalMs: CHECK_INTERVAL_MS,
  });
  startupTimer = setTimeout(() => {
    void tick();
  }, STARTUP_DELAY_MS);
  intervalId = setInterval(() => {
    void tick();
  }, CHECK_INTERVAL_MS);
  logger.info('[TriageReconciler] job started');
}

export function stopTriageReconcilerJob(): void {
  if (startupTimer) {
    clearTimeout(startupTimer);
    startupTimer = null;
  }
  if (intervalId) {
    clearInterval(intervalId);
    intervalId = null;
  }
  firstRun = true;
}
