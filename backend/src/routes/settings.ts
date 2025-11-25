import { Router, Request, Response } from 'express';
import { query } from '../config/database';
import { ApiError } from '../middleware/errorHandler';
import { authorize } from '../middleware/auth';

const router = Router();

// Get retention settings
router.get('/retention', authorize('admin'), async (req: Request, res: Response) => {
  try {
    const result = await query(
      `SELECT * FROM system_settings WHERE key LIKE 'retention_%'`
    );

    const settings = {
      raw_logs_days: 30,
      parsed_logs_days: 90,
      alerts_days: 365,
      auto_cleanup_enabled: true,
    };

    result.rows.forEach((row) => {
      settings[row.key.replace('retention_', '')] = row.value;
    });

    res.json(settings);
  } catch (error) {
    throw new ApiError(500, 'Failed to fetch retention settings');
  }
});

// Update retention settings
router.put('/retention', authorize('admin'), async (req: Request, res: Response) => {
  try {
    const { raw_logs_days, parsed_logs_days, alerts_days, auto_cleanup_enabled } = req.body;

    const settings = [
      { key: 'retention_raw_logs_days', value: raw_logs_days },
      { key: 'retention_parsed_logs_days', value: parsed_logs_days },
      { key: 'retention_alerts_days', value: alerts_days },
      { key: 'retention_auto_cleanup_enabled', value: auto_cleanup_enabled },
    ];

    for (const setting of settings) {
      await query(
        `INSERT INTO system_settings (key, value)
         VALUES ($1, $2)
         ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`,
        [setting.key, setting.value]
      );
    }

    res.json({ message: 'Retention settings updated successfully' });
  } catch (error) {
    throw new ApiError(500, 'Failed to update retention settings');
  }
});

// Manual cleanup trigger
router.post('/retention/cleanup', authorize('admin'), async (req: Request, res: Response) => {
  try {
    const { raw_logs_days, parsed_logs_days, alerts_days } = req.body;

    const results = {
      raw_logs_deleted: 0,
      parsed_logs_deleted: 0,
      alerts_deleted: 0,
    };

    // Delete old raw logs
    if (raw_logs_days) {
      const rawResult = await query(
        `DELETE FROM raw_logs WHERE timestamp < NOW() - INTERVAL '1 day' * $1`,
        [raw_logs_days]
      );
      results.raw_logs_deleted = rawResult.rowCount || 0;
    }

    // Delete old parsed logs
    if (parsed_logs_days) {
      const parsedResult = await query(
        `DELETE FROM parsed_logs WHERE timestamp < NOW() - INTERVAL '1 day' * $1`,
        [parsed_logs_days]
      );
      results.parsed_logs_deleted = parsedResult.rowCount || 0;
    }

    // Delete old alerts
    if (alerts_days) {
      const alertsResult = await query(
        `DELETE FROM alerts WHERE created_at < NOW() - INTERVAL '1 day' * $1`,
        [alerts_days]
      );
      results.alerts_deleted = alertsResult.rowCount || 0;
    }

    res.json({
      message: 'Cleanup completed successfully',
      results,
    });
  } catch (error) {
    throw new ApiError(500, 'Failed to run cleanup');
  }
});

// Get cleanup statistics
router.get('/retention/stats', authorize('admin'), async (req: Request, res: Response) => {
  try {
    const stats = await query(`
      SELECT
        (SELECT COUNT(*) FROM raw_logs) as total_raw_logs,
        (SELECT COUNT(*) FROM parsed_logs) as total_parsed_logs,
        (SELECT COUNT(*) FROM alerts) as total_alerts,
        (SELECT COUNT(*) FROM raw_logs WHERE timestamp < NOW() - INTERVAL '30 days') as raw_logs_older_30d,
        (SELECT COUNT(*) FROM parsed_logs WHERE timestamp < NOW() - INTERVAL '90 days') as parsed_logs_older_90d,
        (SELECT COUNT(*) FROM alerts WHERE created_at < NOW() - INTERVAL '365 days') as alerts_older_365d,
        (SELECT pg_size_pretty(pg_total_relation_size('raw_logs'))) as raw_logs_size,
        (SELECT pg_size_pretty(pg_total_relation_size('parsed_logs'))) as parsed_logs_size,
        (SELECT pg_size_pretty(pg_total_relation_size('alerts'))) as alerts_size
    `);

    res.json(stats.rows[0]);
  } catch (error) {
    throw new ApiError(500, 'Failed to fetch statistics');
  }
});

export default router;
