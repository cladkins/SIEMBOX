import { Router, Request, Response } from 'express';
import { query } from '../config/database';
import { ApiError } from '../middleware/errorHandler';
import { authorize } from '../middleware/auth';

const router = Router();

// Get retention settings
router.get('/retention', authorize('admin'), async (_req: Request, res: Response) => {
  try {
    const result = await query(
      `SELECT * FROM system_settings WHERE key LIKE 'retention_%'`
    );

    const settings: Record<string, any> = {
      raw_logs_days: 30,
      parsed_logs_days: 90,
      alerts_days: 365,
      auto_cleanup_enabled: true,
    };

    result.rows.forEach((row) => {
      const key = row.key.replace('retention_', '');
      settings[key] = row.value;
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
router.get('/retention/stats', authorize('admin'), async (_req: Request, res: Response) => {
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

// Get syslog server settings
router.get('/syslog', async (_req: Request, res: Response) => {
  try {
    const result = await query(
      `SELECT * FROM system_settings WHERE key IN ('syslog_host', 'syslog_port')`
    );

    const settings: Record<string, any> = {
      syslog_host: '',
      syslog_port: 514,
    };

    result.rows.forEach((row) => {
      settings[row.key] = row.value;
    });

    res.json(settings);
  } catch (error) {
    throw new ApiError(500, 'Failed to fetch syslog settings');
  }
});

// Update syslog server settings
router.put('/syslog', authorize('admin'), async (req: Request, res: Response) => {
  try {
    const { syslog_host, syslog_port } = req.body;

    if (!syslog_host) {
      throw new ApiError(400, 'Syslog host is required');
    }

    const settings = [
      { key: 'syslog_host', value: syslog_host },
      { key: 'syslog_port', value: syslog_port || 514 },
    ];

    for (const setting of settings) {
      await query(
        `INSERT INTO system_settings (key, value)
         VALUES ($1, $2)
         ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`,
        [setting.key, setting.value]
      );
    }

    res.json({ message: 'Syslog settings updated successfully' });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to update syslog settings');
  }
});

// ===========================
// IP Whitelist Management
// ===========================

// Get all IP whitelist entries
router.get('/ip-whitelist', authorize('admin'), async (_req: Request, res: Response) => {
  try {
    const result = await query(
      `SELECT id, ip_address::text, description, rule_id, created_at, updated_at
       FROM ip_whitelist
       ORDER BY created_at DESC`
    );

    res.json(result.rows);
  } catch (error) {
    throw new ApiError(500, 'Failed to fetch IP whitelist');
  }
});

// Add IP to whitelist
router.post('/ip-whitelist', authorize('admin'), async (req: Request, res: Response) => {
  try {
    const { ip_address, description, rule_id } = req.body;

    if (!ip_address) {
      throw new ApiError(400, 'IP address is required');
    }

    // Validate CIDR format by attempting to insert (PostgreSQL will validate)
    const result = await query(
      `INSERT INTO ip_whitelist (ip_address, description, rule_id, created_by)
       VALUES ($1::cidr, $2, $3, $4)
       RETURNING id, ip_address::text, description, rule_id, created_at`,
      [ip_address, description || null, rule_id || null, req.user?.id || null]
    );

    res.status(201).json({
      message: 'IP address added to whitelist',
      entry: result.rows[0],
    });
  } catch (error: any) {
    if (error.code === '23505') {
      // Unique constraint violation
      throw new ApiError(409, 'IP address already exists in whitelist');
    } else if (error.code === '22P02') {
      // Invalid CIDR format
      throw new ApiError(400, 'Invalid IP address or CIDR format');
    }
    throw new ApiError(500, 'Failed to add IP to whitelist');
  }
});

// Update IP whitelist entry
router.put('/ip-whitelist/:id', authorize('admin'), async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { description, rule_id } = req.body;

    const result = await query(
      `UPDATE ip_whitelist
       SET description = $1, rule_id = $2, updated_at = NOW()
       WHERE id = $3
       RETURNING id, ip_address::text, description, rule_id, updated_at`,
      [description || null, rule_id || null, parseInt(id, 10)]
    );

    if (result.rowCount === 0) {
      throw new ApiError(404, 'IP whitelist entry not found');
    }

    res.json({
      message: 'IP whitelist entry updated',
      entry: result.rows[0],
    });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to update IP whitelist entry');
  }
});

// Delete IP from whitelist
router.delete('/ip-whitelist/:id', authorize('admin'), async (req: Request, res: Response) => {
  try {
    const { id } = req.params;

    const result = await query(
      `DELETE FROM ip_whitelist WHERE id = $1 RETURNING ip_address::text`,
      [parseInt(id, 10)]
    );

    if (result.rowCount === 0) {
      throw new ApiError(404, 'IP whitelist entry not found');
    }

    res.json({
      message: 'IP address removed from whitelist',
      ip_address: result.rows[0].ip_address,
    });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to delete IP whitelist entry');
  }
});

// Check if IP is whitelisted (utility endpoint for testing)
router.post('/ip-whitelist/check', authorize('admin'), async (req: Request, res: Response) => {
  try {
    const { ip_address } = req.body;

    if (!ip_address) {
      throw new ApiError(400, 'IP address is required');
    }

    const result = await query(
      `SELECT id, ip_address::text, description
       FROM ip_whitelist
       WHERE ip_address >> $1::inet
       LIMIT 1`,
      [ip_address]
    );

    const isWhitelisted = result.rowCount! > 0;

    res.json({
      ip_address,
      is_whitelisted: isWhitelisted,
      matched_entry: isWhitelisted ? result.rows[0] : null,
    });
  } catch (error: any) {
    if (error.code === '22P02') {
      throw new ApiError(400, 'Invalid IP address format');
    }
    throw new ApiError(500, 'Failed to check IP whitelist');
  }
});

export default router;
