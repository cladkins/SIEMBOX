import { query } from '../../config/database';
import { logger } from '../../utils/logger';
import { ErrorLogService } from '../errors/errorLogService';

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

      // Clean up raw logs
      if (settings.raw_logs_days > 0) {
        const rawResult = await query(
          `DELETE FROM raw_logs WHERE timestamp < NOW() - INTERVAL '1 day' * $1`,
          [settings.raw_logs_days]
        );
        results.raw_logs_deleted = rawResult.rowCount || 0;
      }

      // Clean up parsed logs
      if (settings.parsed_logs_days > 0) {
        const parsedResult = await query(
          `DELETE FROM parsed_logs WHERE timestamp < NOW() - INTERVAL '1 day' * $1`,
          [settings.parsed_logs_days]
        );
        results.parsed_logs_deleted = parsedResult.rowCount || 0;
      }

      // Clean up old alerts
      if (settings.alerts_days > 0) {
        const alertsResult = await query(
          `DELETE FROM alerts WHERE created_at < NOW() - INTERVAL '1 day' * $1 AND status = 'closed'`,
          [settings.alerts_days]
        );
        results.alerts_deleted = alertsResult.rowCount || 0;
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
