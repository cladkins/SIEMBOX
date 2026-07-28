import { query } from '../../config/database';
import { logger } from '../../utils/logger';
import { ErrorLogService } from '../errors/errorLogService';
import { batchedDelete } from '../../utils/batchDelete';
import { registerRecurringJob, trackJobRun, markJobSkipped } from '../jobs/jobRegistry';

const JOB_KEY = 'retention-cleanup';

/**
 * The current (or most recent) cleanup job — automated sweep or manual purge.
 * ONE shared slot: the two paths must never overlap (concurrent deleters steal
 * each other's batches and double the I/O for the same work), and sharing the
 * tracker means the Settings page can attach to and display EITHER kind of
 * running purge — the startup auto sweep used to be an invisible
 * multi-million-row delete that looked like a hung system.
 */
export interface CleanupParams {
  raw_logs_days?: number;
  parsed_logs_days?: number;
  alerts_days?: number;
}

export interface CleanupJob {
  trigger: 'automatic' | 'manual';
  status: 'running' | 'completed' | 'failed';
  started_at: string;
  finished_at?: string;
  params: CleanupParams;
  /** Live cumulative counts, updated after every delete batch. */
  results: {
    raw_logs_deleted: number;
    parsed_logs_deleted: number;
    alerts_deleted: number;
  };
  error?: string;
}

let currentJob: CleanupJob | null = null;

export function getCleanupJob(): CleanupJob | null {
  return currentJob;
}

/**
 * Refresh planner statistics so the Settings page's estimated totals reflect a
 * purge immediately instead of waiting for autovacuum. Best-effort and cheap
 * (page sampling — seconds even on large tables).
 */
async function refreshPlannerStats(): Promise<void> {
  try {
    await query('ANALYZE raw_logs');
    await query('ANALYZE parsed_logs');
    await query('ANALYZE alerts');
  } catch (error) {
    logger.warn('Post-cleanup ANALYZE failed (stats may lag until autovacuum):', { error });
  }
}

export class CleanupService {
  private intervalId: NodeJS.Timeout | null = null;
  private readonly cleanupIntervalHours: number;

  constructor(cleanupIntervalHours: number = 24) {
    this.cleanupIntervalHours = cleanupIntervalHours;
  }

  /**
   * Start the automated cleanup scheduler
   */
  start(): void {
    logger.info('Starting cleanup service scheduler');

    const intervalMs = this.cleanupIntervalHours * 60 * 60 * 1000;
    registerRecurringJob({
      key: JOB_KEY,
      name: 'Retention cleanup',
      description: 'Deletes raw logs, parsed logs and closed alerts past their retention window.',
      intervalMs,
    });

    // Run cleanup immediately on start
    this.runCleanup();

    this.intervalId = setInterval(() => {
      this.runCleanup();
    }, intervalMs);

    logger.info(`Cleanup service scheduled to run every ${this.cleanupIntervalHours} hours`);
  }

  /**
   * Stop the automated cleanup scheduler
   */
  stop(): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
      logger.info('Cleanup service scheduler stopped');
    }
  }

  /**
   * Run the cleanup process
   */
  async runCleanup(): Promise<void> {
    // Never run two purges concurrently. Overlapping deleters steal each
    // other's selected batches; even with batchedDelete's empty-batch
    // termination, concurrent purges just waste I/O doing the same work twice.
    // A running manual job takes priority — the auto sweep catches up next cycle.
    if (currentJob?.status === 'running') {
      logger.info(`Skipping automated cleanup: a ${currentJob.trigger} cleanup is already running`);
      markJobSkipped(JOB_KEY, `a ${currentJob.trigger} cleanup is already running`);
      return;
    }

    // Check if auto cleanup is enabled
    let settings: { raw_logs_days: number; parsed_logs_days: number; alerts_days: number };
    try {
      const enabledResult = await query(
        `SELECT value FROM system_settings WHERE key = 'retention_auto_cleanup_enabled'`
      );
      if (enabledResult.rows.length === 0 || enabledResult.rows[0].value !== 'true') {
        logger.info('Auto cleanup is disabled, skipping');
        markJobSkipped(JOB_KEY, 'auto cleanup disabled in settings');
        return;
      }
      settings = await this.getRetentionSettings();
    } catch (error) {
      logger.error('Error reading cleanup settings:', error);
      ErrorLogService.logBackgroundError('cleanup', error);
      return;
    }

    // Runs through the SAME tracked-job path as a manual cleanup, so the
    // Settings page can attach to and display an automated sweep's live
    // progress too (the sweep fires on every backend startup — an invisible
    // multi-million-row purge looked like a hung system).
    const job: CleanupJob = {
      trigger: 'automatic',
      status: 'running',
      started_at: new Date().toISOString(),
      params: settings,
      results: { raw_logs_deleted: 0, parsed_logs_deleted: 0, alerts_deleted: 0 },
    };
    currentJob = job;
    logger.info('Starting automated log cleanup');

    try {
      await trackJobRun(JOB_KEY, async () => {
        // Delete in bounded batches so a large purge never holds a long lock. A
        // single unbounded DELETE here once ran 15h and jammed a boot-time migration.
        if (settings.raw_logs_days > 0) {
          job.results.raw_logs_deleted = await batchedDelete(
            'raw_logs',
            "timestamp < NOW() - INTERVAL '1 day' * $1",
            [settings.raw_logs_days],
            { label: 'retention', onProgress: (n) => (job.results.raw_logs_deleted = n) }
          );
        }

        if (settings.parsed_logs_days > 0) {
          job.results.parsed_logs_deleted = await batchedDelete(
            'parsed_logs',
            "timestamp < NOW() - INTERVAL '1 day' * $1",
            [settings.parsed_logs_days],
            { label: 'retention', onProgress: (n) => (job.results.parsed_logs_deleted = n) }
          );
        }

        if (settings.alerts_days > 0) {
          job.results.alerts_deleted = await batchedDelete(
            'alerts',
            "created_at < NOW() - INTERVAL '1 day' * $1 AND status = 'closed'",
            [settings.alerts_days],
            { label: 'retention', onProgress: (n) => (job.results.alerts_deleted = n) }
          );
        }

        await refreshPlannerStats();
        return (
          `${job.results.raw_logs_deleted} raw, ${job.results.parsed_logs_deleted} parsed, ` +
          `${job.results.alerts_deleted} alert row(s) deleted`
        );
      });
      job.status = 'completed';
      logger.info('Automated log cleanup completed', job.results);
    } catch (error) {
      job.status = 'failed';
      job.error = error instanceof Error ? error.message : String(error);
      logger.error('Error during automated cleanup:', error);
      ErrorLogService.logBackgroundError('cleanup', error);
    } finally {
      job.finished_at = new Date().toISOString();
    }
  }

  /**
   * Get retention settings from database
   */
  private async getRetentionSettings(): Promise<{
    raw_logs_days: number;
    parsed_logs_days: number;
    alerts_days: number;
  }> {
    const result = await query(
      `SELECT key, value FROM system_settings WHERE key LIKE 'retention_%_days'`
    );

    const settings = {
      raw_logs_days: 30,
      parsed_logs_days: 90,
      alerts_days: 365,
    };

    result.rows.forEach((row) => {
      const key = row.key.replace('retention_', '') as keyof typeof settings;
      if (key in settings) {
        settings[key] = parseInt(row.value, 10);
      }
    });

    return settings;
  }

  /**
   * Get cleanup statistics
   */
  async getStatistics(): Promise<any> {
    const result = await query(`
      SELECT
        (SELECT COUNT(*) FROM raw_logs) as total_raw_logs,
        (SELECT COUNT(*) FROM parsed_logs) as total_parsed_logs,
        (SELECT COUNT(*) FROM alerts) as total_alerts,
        (SELECT MIN(timestamp) FROM raw_logs) as oldest_raw_log,
        (SELECT MIN(timestamp) FROM parsed_logs) as oldest_parsed_log,
        (SELECT MIN(created_at) FROM alerts) as oldest_alert,
        (SELECT pg_size_pretty(pg_total_relation_size('raw_logs'))) as raw_logs_size,
        (SELECT pg_size_pretty(pg_total_relation_size('parsed_logs'))) as parsed_logs_size,
        (SELECT pg_size_pretty(pg_total_relation_size('alerts'))) as alerts_size
    `);

    return result.rows[0];
  }
}

// ---------------------------------------------------------------------------
// Manual cleanup as a tracked background job.
//
// A manual purge of a multi-million-row table takes minutes to hours even
// batched, far past any sane HTTP timeout — the old synchronous handler kept
// deleting after the client aborted at 10s while the UI reported failure, and
// a retry click stacked a SECOND concurrent purge. The route starts the job
// and returns immediately; the UI polls getCleanupJob() for live per-table
// progress. One job at a time, shared with the automated sweep above.
// ---------------------------------------------------------------------------

export function startManualCleanup(params: CleanupParams): {
  started: boolean;
  job: CleanupJob | null;
} {
  if (currentJob?.status === 'running') {
    // Whichever purge is running (manual or the automated sweep), hand it back
    // so the caller can attach to its progress instead of racing it.
    return { started: false, job: currentJob };
  }

  const job: CleanupJob = {
    trigger: 'manual',
    status: 'running',
    started_at: new Date().toISOString(),
    params,
    results: { raw_logs_deleted: 0, parsed_logs_deleted: 0, alerts_deleted: 0 },
  };
  currentJob = job;

  void (async () => {
    try {
      if (params.raw_logs_days) {
        job.results.raw_logs_deleted = await batchedDelete(
          'raw_logs',
          "timestamp < NOW() - INTERVAL '1 day' * $1",
          [params.raw_logs_days],
          { label: 'manual retention', onProgress: (n) => (job.results.raw_logs_deleted = n) }
        );
      }
      if (params.parsed_logs_days) {
        job.results.parsed_logs_deleted = await batchedDelete(
          'parsed_logs',
          "timestamp < NOW() - INTERVAL '1 day' * $1",
          [params.parsed_logs_days],
          { label: 'manual retention', onProgress: (n) => (job.results.parsed_logs_deleted = n) }
        );
      }
      if (params.alerts_days) {
        job.results.alerts_deleted = await batchedDelete(
          'alerts',
          "created_at < NOW() - INTERVAL '1 day' * $1",
          [params.alerts_days],
          { label: 'manual retention', onProgress: (n) => (job.results.alerts_deleted = n) }
        );
      }
      await refreshPlannerStats();
      job.status = 'completed';
    } catch (error) {
      job.status = 'failed';
      job.error = error instanceof Error ? error.message : String(error);
      logger.error('Manual cleanup failed:', { error });
      ErrorLogService.logBackgroundError('manual-cleanup', error, { dedupeKey: 'manual-cleanup' });
    } finally {
      job.finished_at = new Date().toISOString();
    }
  })();

  return { started: true, job };
}
