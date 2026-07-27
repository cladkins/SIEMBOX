import { query } from '../../config/database';
import { logger } from '../../utils/logger';
import { ErrorLogService } from '../errors/errorLogService';
import { batchedDelete } from '../../utils/batchDelete';

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

    // Run cleanup immediately on start
    this.runCleanup();

    // Schedule periodic cleanup
    const intervalMs = this.cleanupIntervalHours * 60 * 60 * 1000;
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
    try {
      logger.info('Starting automated log cleanup');

      // Check if auto cleanup is enabled
      const enabledResult = await query(
        `SELECT value FROM system_settings WHERE key = 'retention_auto_cleanup_enabled'`
      );

      if (enabledResult.rows.length === 0 || enabledResult.rows[0].value !== 'true') {
        logger.info('Auto cleanup is disabled, skipping');
        return;
      }

      // Get retention settings
      const settings = await this.getRetentionSettings();

      const results = {
        raw_logs_deleted: 0,
        parsed_logs_deleted: 0,
        alerts_deleted: 0,
      };

      // Delete in bounded batches so a large purge never holds a long lock. A
      // single unbounded DELETE here once ran 15h and jammed a boot-time migration.
      if (settings.raw_logs_days > 0) {
        results.raw_logs_deleted = await batchedDelete(
          'raw_logs',
          "timestamp < NOW() - INTERVAL '1 day' * $1",
          [settings.raw_logs_days],
          { label: 'retention' }
        );
      }

      if (settings.parsed_logs_days > 0) {
        results.parsed_logs_deleted = await batchedDelete(
          'parsed_logs',
          "timestamp < NOW() - INTERVAL '1 day' * $1",
          [settings.parsed_logs_days],
          { label: 'retention' }
        );
      }

      if (settings.alerts_days > 0) {
        results.alerts_deleted = await batchedDelete(
          'alerts',
          "created_at < NOW() - INTERVAL '1 day' * $1 AND status = 'closed'",
          [settings.alerts_days],
          { label: 'retention' }
        );
      }

      logger.info('Automated log cleanup completed', results);
    } catch (error) {
      logger.error('Error during automated cleanup:', error);
      ErrorLogService.logBackgroundError('cleanup', error);
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
// a retry click stacked a SECOND concurrent purge. The route now starts the
// job and returns immediately; the UI polls getManualCleanupJob() for live
// per-table progress. One job at a time.
// ---------------------------------------------------------------------------

export interface ManualCleanupParams {
  raw_logs_days?: number;
  parsed_logs_days?: number;
  alerts_days?: number;
}

export interface ManualCleanupJob {
  status: 'running' | 'completed' | 'failed';
  started_at: string;
  finished_at?: string;
  params: ManualCleanupParams;
  /** Live cumulative counts, updated after every delete batch. */
  results: {
    raw_logs_deleted: number;
    parsed_logs_deleted: number;
    alerts_deleted: number;
  };
  error?: string;
}

let manualJob: ManualCleanupJob | null = null;

export function getManualCleanupJob(): ManualCleanupJob | null {
  return manualJob;
}

export function startManualCleanup(params: ManualCleanupParams): {
  started: boolean;
  job: ManualCleanupJob;
} {
  if (manualJob && manualJob.status === 'running') {
    return { started: false, job: manualJob };
  }

  const job: ManualCleanupJob = {
    status: 'running',
    started_at: new Date().toISOString(),
    params,
    results: { raw_logs_deleted: 0, parsed_logs_deleted: 0, alerts_deleted: 0 },
  };
  manualJob = job;

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
