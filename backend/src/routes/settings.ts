import { Router, Request, Response } from 'express';
import { query } from '../config/database';
import {
  startManualCleanup,
  getCleanupJob,
  CleanupParams,
} from '../services/cleanup/cleanupService';
import { ApiError } from '../middleware/errorHandler';
import { authorize } from '../middleware/auth';
import {
  getAiPublicConfig,
  saveAiConfig,
  AiProvider,
  getChatAiPublicConfig,
  saveChatAiConfig,
  getTriagePublicConfig,
  saveTriageConfig,
} from '../services/ai/aiService';

const router = Router();

// ===========================
// AI builder configuration
// ===========================

// Current AI config (never returns the key — only whether/where one is set).
router.get('/ai', authorize('admin'), async (_req: Request, res: Response) => {
  try {
    res.json(await getAiPublicConfig());
  } catch (error) {
    throw new ApiError(500, 'Failed to fetch AI settings');
  }
});

// Update AI config. Pass apiKey to set it (encrypted at rest), '' to clear it.
router.put('/ai', authorize('admin'), async (req: Request, res: Response) => {
  try {
    const { provider, model, baseUrl, apiKey } = req.body ?? {};
    if (provider && !['anthropic', 'openai', 'ollama'].includes(provider)) {
      throw new ApiError(400, 'provider must be anthropic, openai, or ollama');
    }
    await saveAiConfig({ provider: provider as AiProvider, model, baseUrl, apiKey });
    res.json(await getAiPublicConfig());
  } catch (error: any) {
    if (error instanceof ApiError) throw error;
    // Most likely CREDENTIAL_ENCRYPTION_KEY is unset when storing a key.
    throw new ApiError(500, error?.message?.includes('CREDENTIAL_ENCRYPTION_KEY')
      ? 'Set CREDENTIAL_ENCRYPTION_KEY to store an API key, or use the ANTHROPIC_API_KEY/OPENAI_API_KEY env var instead.'
      : 'Failed to update AI settings');
  }
});

// Current AI Analyst (chat) config — a separate model selection that falls back
// to the main AI config when unset (see getChatAiConfig). Never returns the key.
router.get('/ai-chat', authorize('admin'), async (_req: Request, res: Response) => {
  try {
    res.json(await getChatAiPublicConfig());
  } catch (error) {
    throw new ApiError(500, 'Failed to fetch AI analyst settings');
  }
});

// Update the analyst chat config. Empty provider ('') reverts to inheriting the
// main AI config. Pass apiKey to set it (encrypted at rest), '' to clear it.
router.put('/ai-chat', authorize('admin'), async (req: Request, res: Response) => {
  try {
    const { provider, model, baseUrl, apiKey } = req.body ?? {};
    if (provider && provider !== '' && !['anthropic', 'openai', 'ollama'].includes(provider)) {
      throw new ApiError(400, "provider must be anthropic, openai, ollama, or '' to inherit");
    }
    await saveChatAiConfig({ provider: provider as AiProvider | '', model, baseUrl, apiKey });
    res.json(await getChatAiPublicConfig());
  } catch (error: any) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, error?.message?.includes('CREDENTIAL_ENCRYPTION_KEY')
      ? 'Set CREDENTIAL_ENCRYPTION_KEY to store an API key, or use the ANTHROPIC_API_KEY/OPENAI_API_KEY env var instead.'
      : 'Failed to update AI analyst settings');
  }
});

// Current AI Triage (automatic alert analysis) config — a third model
// selection that falls back to the chat analyst's config when unset (see
// getTriageAiConfig), plus the operational knobs (enabled, severity gate,
// cost caps). Never returns the key.
router.get('/ai-triage', authorize('admin'), async (_req: Request, res: Response) => {
  try {
    res.json(await getTriagePublicConfig());
  } catch (error) {
    throw new ApiError(500, 'Failed to fetch AI triage settings');
  }
});

// Update the triage config. Empty provider ('') reverts to inheriting the chat
// analyst config. Pass apiKey to set it (encrypted at rest), '' to clear it.
router.put('/ai-triage', authorize('admin'), async (req: Request, res: Response) => {
  try {
    const {
      provider,
      model,
      baseUrl,
      apiKey,
      enabled,
      minSeverity,
      dailyCap,
      maxConcurrent,
      dedupeHours,
      maxToolCalls,
      wallBudgetSeconds,
    } = req.body ?? {};
    if (provider && provider !== '' && !['anthropic', 'openai', 'ollama'].includes(provider)) {
      throw new ApiError(400, "provider must be anthropic, openai, ollama, or '' to inherit");
    }
    if (minSeverity !== undefined && !['low', 'medium', 'high', 'critical'].includes(minSeverity)) {
      throw new ApiError(400, 'minSeverity must be low, medium, high, or critical');
    }
    if (enabled !== undefined && typeof enabled !== 'boolean') {
      throw new ApiError(400, 'enabled must be a boolean');
    }
    if (dailyCap !== undefined && (!Number.isFinite(dailyCap) || dailyCap < 0 || dailyCap > 10000)) {
      throw new ApiError(400, 'dailyCap must be between 0 and 10000');
    }
    if (maxConcurrent !== undefined && (!Number.isFinite(maxConcurrent) || maxConcurrent < 1 || maxConcurrent > 10)) {
      throw new ApiError(400, 'maxConcurrent must be between 1 and 10');
    }
    if (dedupeHours !== undefined && (!Number.isFinite(dedupeHours) || dedupeHours < 0 || dedupeHours > 168)) {
      throw new ApiError(400, 'dedupeHours must be between 0 and 168');
    }
    if (maxToolCalls !== undefined && (!Number.isFinite(maxToolCalls) || maxToolCalls < 1 || maxToolCalls > 12)) {
      throw new ApiError(400, 'maxToolCalls must be between 1 and 12');
    }
    if (
      wallBudgetSeconds !== undefined &&
      (!Number.isFinite(wallBudgetSeconds) || wallBudgetSeconds < 20 || wallBudgetSeconds > 280)
    ) {
      throw new ApiError(400, 'wallBudgetSeconds must be between 20 and 280');
    }
    await saveTriageConfig({
      provider: provider as AiProvider | '',
      model,
      baseUrl,
      apiKey,
      enabled,
      minSeverity,
      dailyCap,
      maxConcurrent,
      dedupeHours,
      maxToolCalls,
      wallBudgetSeconds,
    });
    res.json(await getTriagePublicConfig());
  } catch (error: any) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, error?.message?.includes('CREDENTIAL_ENCRYPTION_KEY')
      ? 'Set CREDENTIAL_ENCRYPTION_KEY to store an API key, or use the ANTHROPIC_API_KEY/OPENAI_API_KEY env var instead.'
      : 'Failed to update AI triage settings');
  }
});

// Get all system settings as a key/value list
// Frontend reads these as [{ setting_key, setting_value }, ...]
router.get('/', async (_req: Request, res: Response) => {
  try {
    const result = await query(
      `SELECT key AS setting_key, value AS setting_value FROM system_settings ORDER BY key`
    );
    res.json(result.rows);
  } catch (error) {
    throw new ApiError(500, 'Failed to fetch settings');
  }
});

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
      if (key === 'auto_cleanup_enabled') {
        // Stored as TEXT; coerce back to a real boolean so the el-switch
        // (active-value: true) reflects the saved state on reload.
        settings[key] = row.value === 'true';
      } else {
        const n = Number(row.value);
        settings[key] = Number.isFinite(n) ? n : row.value;
      }
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
      // Persist a canonical 'true'/'false' string: the column is TEXT and the
      // cleanup scheduler checks `value === 'true'` exactly, so store it
      // explicitly rather than relying on the driver's boolean coercion.
      {
        key: 'retention_auto_cleanup_enabled',
        value: auto_cleanup_enabled === true || auto_cleanup_enabled === 'true' ? 'true' : 'false',
      },
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
// Start a manual cleanup as a background job (a large purge runs for minutes
// to hours — far past any HTTP timeout). Poll GET /retention/cleanup/status
// for live progress. 409 when a job is already running.
router.post('/retention/cleanup', authorize('admin'), async (req: Request, res: Response) => {
  try {
    const { raw_logs_days, parsed_logs_days, alerts_days } = req.body ?? {};
    const params: CleanupParams = {};
    for (const [key, value] of Object.entries({ raw_logs_days, parsed_logs_days, alerts_days })) {
      if (value === undefined || value === null) continue;
      const days = Number(value);
      if (!Number.isFinite(days) || days < 1) {
        throw new ApiError(400, `${key} must be a positive number of days`);
      }
      (params as any)[key] = days;
    }
    if (Object.keys(params).length === 0) {
      throw new ApiError(400, 'Provide at least one of raw_logs_days, parsed_logs_days, alerts_days');
    }

    const { started, job } = startManualCleanup(params);
    if (!started) {
      // Whichever purge is running (an earlier manual click or the automated
      // sweep), the job is returned so the UI can attach to its progress.
      res.status(409).json({
        message:
          job?.trigger === 'automatic'
            ? 'The automated retention sweep is currently running'
            : 'A cleanup is already running',
        job,
      });
      return;
    }
    res.status(202).json({ message: 'Cleanup started', job });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to start cleanup');
  }
});

// Live status of the current/last cleanup job — manual purge OR the automated
// sweep (they share one tracked slot; `trigger` says which).
router.get('/retention/cleanup/status', authorize('admin'), (_req: Request, res: Response) => {
  res.json({ job: getCleanupJob() });
});

// Get cleanup statistics
router.get('/retention/stats', authorize('admin'), async (_req: Request, res: Response) => {
  try {
    // Row totals are ESTIMATES from pg_stat_user_tables.n_live_tup — exact
    // COUNT(*) seq-scans multi-million-row tables and blew the UI's timeout.
    // n_live_tup (not pg_class.reltuples) is used deliberately: the stats
    // collector decrements it as deletes commit, whereas reltuples stays frozen
    // until the next ANALYZE — which is why the old code could show more parsed
    // logs than raw logs (impossible; every parsed row FK-cascades from a raw
    // row) right after a large purge. n_dead_tup exposes bloat so the UI can
    // explain why on-disk size stays high after deletions (Postgres reuses that
    // space but doesn't return it to the OS without VACUUM FULL).
    //
    // alerts is small, so it stays an exact count. The "older than" counts are
    // exact (index-assisted) — they tell the operator what a cleanup deletes.
    // Sizes are exact (pg_total_relation_size reads the actual on-disk files).
    const stats = await query(`
      SELECT
        (SELECT GREATEST(COALESCE(n_live_tup, 0), 0)::bigint FROM pg_stat_user_tables WHERE relname = 'raw_logs') as total_raw_logs,
        (SELECT GREATEST(COALESCE(n_live_tup, 0), 0)::bigint FROM pg_stat_user_tables WHERE relname = 'parsed_logs') as total_parsed_logs,
        (SELECT COUNT(*) FROM alerts) as total_alerts,
        (SELECT GREATEST(COALESCE(n_dead_tup, 0), 0)::bigint FROM pg_stat_user_tables WHERE relname = 'raw_logs') as raw_logs_dead,
        (SELECT GREATEST(COALESCE(n_dead_tup, 0), 0)::bigint FROM pg_stat_user_tables WHERE relname = 'parsed_logs') as parsed_logs_dead,
        (SELECT COUNT(*) FROM raw_logs WHERE timestamp < NOW() - INTERVAL '30 days') as raw_logs_older_30d,
        (SELECT COUNT(*) FROM parsed_logs WHERE timestamp < NOW() - INTERVAL '90 days') as parsed_logs_older_90d,
        (SELECT COUNT(*) FROM alerts WHERE created_at < NOW() - INTERVAL '365 days') as alerts_older_365d,
        (SELECT pg_size_pretty(pg_total_relation_size('raw_logs'))) as raw_logs_size,
        (SELECT pg_size_pretty(pg_total_relation_size('parsed_logs'))) as parsed_logs_size,
        (SELECT pg_size_pretty(pg_total_relation_size('alerts'))) as alerts_size,
        (SELECT MIN(timestamp) FROM raw_logs) as oldest_raw_log,
        (SELECT MIN(timestamp) FROM parsed_logs) as oldest_parsed_log,
        (SELECT MIN(created_at) FROM alerts) as oldest_alert
    `);

    // Bloat fraction per big table (dead / (live + dead)). A high value explains
    // an on-disk size that dwarfs the live-row count — reclaimable space from
    // deleted rows that autovacuum frees for reuse but doesn't shrink on disk.
    const row = stats.rows[0];
    const bloat = (live: any, dead: any) => {
      const l = Number(live) || 0;
      const d = Number(dead) || 0;
      return l + d > 0 ? Math.round((d / (l + d)) * 100) : 0;
    };
    row.counts_are_estimated = true;
    row.raw_logs_bloat_pct = bloat(row.total_raw_logs, row.raw_logs_dead);
    row.parsed_logs_bloat_pct = bloat(row.total_parsed_logs, row.parsed_logs_dead);

    res.json(row);
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

// Get syslog server status (for verification)
router.get('/syslog/status', authorize('admin'), async (_req: Request, res: Response) => {
  try {
    // Get actual listening port from environment
    const actualListeningPort = process.env.SYSLOG_PORT
      ? parseInt(process.env.SYSLOG_PORT)
      : 514;

    // Get configured port from database
    const configResult = await query(
      `SELECT value FROM system_settings WHERE key = 'syslog_port'`
    );
    const configuredPort = configResult.rows.length > 0
      ? parseInt(configResult.rows[0].value)
      : 514;

    // Check recent log activity (last 5 minutes)
    const activityResult = await query(`
      SELECT
        COUNT(*) as total_logs,
        MAX(created_at) as last_log_time,
        COUNT(DISTINCT source_ip) as unique_sources
      FROM raw_logs
      WHERE created_at > NOW() - INTERVAL '5 minutes'
    `);

    const activity = activityResult.rows[0];
    const lastLogTime = activity.last_log_time;
    const logsReceivedLast5Min = parseInt(activity.total_logs, 10);

    // Determine status
    let status: 'healthy' | 'warning' | 'error';
    let statusMessage: string;

    const portsMatch = actualListeningPort === configuredPort;
    const hasRecentLogs = logsReceivedLast5Min > 0;

    if (portsMatch && hasRecentLogs) {
      status = 'healthy';
      statusMessage = 'Syslog receiver is active and receiving logs';
    } else if (!portsMatch && hasRecentLogs) {
      status = 'warning';
      statusMessage = 'Configuration port mismatch, but logs are being received';
    } else if (!portsMatch) {
      status = 'error';
      statusMessage = 'Configuration port mismatch - shippers may be misconfigured';
    } else {
      status = 'warning';
      statusMessage = 'No logs received in the last 5 minutes';
    }

    res.json({
      actual_listening_port: actualListeningPort,
      configured_port: configuredPort,
      ports_match: portsMatch,
      last_log_received: lastLogTime,
      logs_received_last_5min: logsReceivedLast5Min,
      unique_sources_last_5min: parseInt(activity.unique_sources, 10),
      status,
      status_message: statusMessage,
    });
  } catch (error) {
    throw new ApiError(500, 'Failed to fetch syslog status');
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

    // Normalize to the network address (network() zeroes the host bits) so an
    // input like "192.168.1.1/24" is accepted as "192.168.1.0/24" instead of
    // being rejected by the cidr type. Genuinely invalid input still throws
    // 22P02 -> 400 below.
    const result = await query(
      `INSERT INTO ip_whitelist (ip_address, description, rule_id, created_by)
       VALUES (network($1::inet)::cidr, $2, $3, $4)
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

// ===========================
// Auto-Discovery Settings
// ===========================

// Get auto-discovery settings
router.get('/auto-discovery', authorize('admin'), async (_req: Request, res: Response) => {
  try {
    const result = await query(
      `SELECT key, value, description
       FROM system_settings
       WHERE key IN ('auto_discovery_enabled', 'auto_discovery_interval_minutes', 'stale_asset_threshold_days')`
    );

    const settings: Record<string, any> = {
      auto_discovery_enabled: 'true',
      auto_discovery_interval_minutes: '360',
      stale_asset_threshold_days: '30',
    };

    result.rows.forEach((row) => {
      settings[row.key] = row.value;
    });

    // Parse to appropriate types for frontend
    res.json({
      enabled: settings.auto_discovery_enabled === 'true',
      interval_minutes: parseInt(settings.auto_discovery_interval_minutes),
      stale_threshold_days: parseInt(settings.stale_asset_threshold_days),
    });
  } catch (error) {
    throw new ApiError(500, 'Failed to fetch auto-discovery settings');
  }
});

// Update auto-discovery settings
router.put('/auto-discovery', authorize('admin'), async (req: Request, res: Response) => {
  try {
    const { enabled, interval_minutes, stale_threshold_days } = req.body;

    // Validation
    if (interval_minutes !== undefined) {
      const intervalNum = parseInt(interval_minutes);
      if (isNaN(intervalNum) || intervalNum < 5 || intervalNum > 10080) {
        throw new ApiError(400, 'Interval must be between 5 minutes and 7 days (10080 minutes)');
      }
    }

    if (stale_threshold_days !== undefined) {
      const thresholdNum = parseInt(stale_threshold_days);
      if (isNaN(thresholdNum) || thresholdNum < 1 || thresholdNum > 365) {
        throw new ApiError(400, 'Stale threshold must be between 1 and 365 days');
      }
    }

    const settings = [];

    if (enabled !== undefined) {
      settings.push({
        key: 'auto_discovery_enabled',
        value: enabled ? 'true' : 'false',
      });
    }

    if (interval_minutes !== undefined) {
      settings.push({
        key: 'auto_discovery_interval_minutes',
        value: interval_minutes.toString(),
      });
    }

    if (stale_threshold_days !== undefined) {
      settings.push({
        key: 'stale_asset_threshold_days',
        value: stale_threshold_days.toString(),
      });
    }

    for (const setting of settings) {
      await query(
        `UPDATE system_settings
         SET value = $1, updated_by = $2, updated_at = NOW()
         WHERE key = $3`,
        [setting.value, req.user?.id || null, setting.key]
      );
    }

    // Log the update
    if (interval_minutes !== undefined) {
      console.log(`[Auto-Discovery Settings] Interval updated to ${interval_minutes} minutes by user ${req.user?.username}`);
    }
    if (enabled !== undefined) {
      console.log(`[Auto-Discovery Settings] Status ${enabled ? 'enabled' : 'disabled'} by user ${req.user?.username}`);
    }

    res.json({
      message: 'Auto-discovery settings updated successfully',
      settings: {
        enabled: enabled !== undefined ? enabled : undefined,
        interval_minutes,
        stale_threshold_days,
      },
    });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to update auto-discovery settings');
  }
});

// Get auto-discovery statistics
router.get('/auto-discovery/stats', authorize('admin'), async (_req: Request, res: Response) => {
  try {
    const stats = await query(`
      SELECT
        COUNT(*) FILTER (WHERE discovery_method = 'log_correlation') as auto_discovered_assets,
        COUNT(*) FILTER (WHERE status = 'offline') as offline_assets,
        MAX(last_seen) as last_discovery_time,
        COUNT(*) FILTER (WHERE last_seen > NOW() - INTERVAL '24 hours') as assets_seen_24h,
        COUNT(*) FILTER (WHERE last_seen > NOW() - INTERVAL '7 days') as assets_seen_7d,
        COUNT(*) FILTER (WHERE first_seen > NOW() - INTERVAL '30 days') as new_assets_30d
      FROM assets
    `);

    res.json(stats.rows[0]);
  } catch (error) {
    throw new ApiError(500, 'Failed to fetch auto-discovery statistics');
  }
});

export default router;
