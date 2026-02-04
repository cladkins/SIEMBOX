/**
 * Admin API Routes
 *
 * Unified admin dashboard endpoints for system overview, user management,
 * error tracking, and background job monitoring.
 * All endpoints require admin authentication.
 */

import { Router, Request, Response } from 'express';
import { authenticate, requireAdmin } from '../middleware/auth';
import { query } from '../config/database';
import { ErrorLogService } from '../services/errors/errorLogService';
import { logger } from '../utils/logger';

const router = Router();

// All admin routes require authentication and admin role
router.use(authenticate);
router.use(requireAdmin);

/**
 * GET /api/admin/overview
 * Get system health and aggregated metrics
 */
router.get('/overview', async (_req: Request, res: Response) => {
  try {
    // System information
    const system = {
      version: process.env.npm_package_version || '0.1.0',
      uptime: process.uptime(),
      nodeVersion: process.version,
      environment: process.env.NODE_ENV || 'development',
    };

    // Database health check
    let dbHealth = 'healthy';
    try {
      await query('SELECT 1');
    } catch {
      dbHealth = 'unhealthy';
    }

    // Syslog receiver health (check if logs received recently)
    let syslogHealth = 'unknown';
    try {
      const syslogResult = await query(
        `SELECT
           COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '5 minutes') as recent_count,
           MAX(created_at) as last_log
         FROM raw_logs`
      );
      syslogHealth = parseInt(syslogResult.rows[0]?.recent_count || '0', 10) > 0
        ? 'healthy'
        : 'warning';
    } catch (err) {
      logger.warn('Failed to check syslog health:', err);
    }

    // Shipper health
    let shippersOnline = 0;
    let shippersOffline = 0;
    let shippersError = 0;
    try {
      const shipperResult = await query(
        `SELECT
           COUNT(*) FILTER (WHERE last_seen > NOW() - INTERVAL '5 minutes') as online,
           COUNT(*) FILTER (WHERE last_seen <= NOW() - INTERVAL '5 minutes' AND last_seen > NOW() - INTERVAL '1 hour') as offline,
           COUNT(*) FILTER (WHERE last_seen <= NOW() - INTERVAL '1 hour' OR last_seen IS NULL) as error
         FROM log_shippers`
      );
      shippersOnline = parseInt(shipperResult.rows[0]?.online || '0', 10);
      shippersOffline = parseInt(shipperResult.rows[0]?.offline || '0', 10);
      shippersError = parseInt(shipperResult.rows[0]?.error || '0', 10);
    } catch (err) {
      logger.warn('Failed to check shipper health:', err);
    }

    const health = {
      database: dbHealth,
      syslog: syslogHealth,
      shippers: {
        online: shippersOnline,
        offline: shippersOffline,
        error: shippersError,
      },
    };

    // Aggregated metrics - wrap each in try/catch for resilience
    const safeQuery = async (sql: string, defaultValue: any = { rows: [{ count: '0' }] }) => {
      try {
        return await query(sql);
      } catch (err) {
        logger.warn(`Admin overview query failed: ${sql}`, err);
        return defaultValue;
      }
    };

    const [
      usersResult,
      activeUsersResult,
      alertsTodayResult,
      criticalAlertsResult,
      assetsResult,
      vulnsResult,
      scansResult,
      dbSizeResult,
      errorsResult,
    ] = await Promise.all([
      // Total users
      safeQuery('SELECT COUNT(*) as count FROM users'),
      // Active users (logged in within 24h)
      safeQuery('SELECT COUNT(DISTINCT user_id) as count FROM sessions WHERE expires_at > NOW()'),
      // Alerts today
      safeQuery(`SELECT COUNT(*) as count FROM alerts WHERE created_at > NOW() - INTERVAL '24 hours'`),
      // Critical alerts (new or investigating)
      safeQuery(`SELECT COUNT(*) as count FROM alerts WHERE severity = 'critical' AND status IN ('new', 'investigating')`),
      // Total assets
      safeQuery('SELECT COUNT(*) as count FROM assets'),
      // Open vulnerabilities
      safeQuery(`SELECT COUNT(*) as count FROM asset_vulnerabilities WHERE status = 'open'`),
      // Active scans
      safeQuery(`SELECT COUNT(*) as count FROM vulnerability_scans WHERE status IN ('queued', 'running')`),
      // Database size
      safeQuery(`SELECT pg_database_size(current_database()) / 1024 / 1024 as size_mb`, { rows: [{ size_mb: '0' }] }),
      // Recent errors (last hour) - table may not exist yet
      safeQuery(`SELECT COUNT(*) as count FROM application_errors WHERE timestamp > NOW() - INTERVAL '1 hour'`),
    ]);

    const metrics = {
      totalUsers: parseInt(usersResult.rows[0]?.count || '0', 10),
      activeUsers24h: parseInt(activeUsersResult.rows[0]?.count || '0', 10),
      alertsToday: parseInt(alertsTodayResult.rows[0]?.count || '0', 10),
      criticalAlerts: parseInt(criticalAlertsResult.rows[0]?.count || '0', 10),
      totalAssets: parseInt(assetsResult.rows[0]?.count || '0', 10),
      openVulnerabilities: parseInt(vulnsResult.rows[0]?.count || '0', 10),
      activeScans: parseInt(scansResult.rows[0]?.count || '0', 10),
      dbSizeMB: parseInt(dbSizeResult.rows[0]?.size_mb || '0', 10),
      recentErrors: parseInt(errorsResult.rows[0]?.count || '0', 10),
    };

    res.json({ system, health, metrics });
  } catch (error) {
    logger.error('Admin overview error:', error);
    res.status(500).json({
      error: 'Failed to retrieve admin overview',
      message: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * GET /api/admin/users/search
 * Search users with recent activity
 */
router.get('/users/search', async (req: Request, res: Response) => {
  try {
    const searchQuery = req.query.q as string || '';
    const limit = parseInt(req.query.limit as string) || 20;

    let whereClause = '';
    const params: any[] = [limit];

    if (searchQuery) {
      whereClause = 'WHERE username ILIKE $2 OR email ILIKE $2';
      params.push(`%${searchQuery}%`);
    }

    const result = await query(
      `SELECT
         u.id, u.username, u.email, u.role, u.enabled,
         u.last_login, u.created_at,
         (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id AND s.expires_at > NOW()) as active_sessions,
         (SELECT COUNT(*) FROM audit_logs a WHERE a.user_id = u.id AND a.timestamp > NOW() - INTERVAL '24 hours') as actions_24h
       FROM users u
       ${whereClause}
       ORDER BY u.last_login DESC NULLS LAST
       LIMIT $1`,
      params
    );

    res.json({
      users: result.rows,
      total: result.rowCount,
    });
  } catch (error) {
    logger.error('Admin user search error:', error);
    res.status(500).json({
      error: 'Failed to search users',
      message: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * GET /api/admin/users/:id/activity
 * Get full activity log for a user
 */
router.get('/users/:id/activity', async (req: Request, res: Response) => {
  try {
    const userId = parseInt(req.params.id);
    const limit = parseInt(req.query.limit as string) || 50;
    const offset = parseInt(req.query.offset as string) || 0;

    if (isNaN(userId)) {
      res.status(400).json({ error: 'Invalid user ID' });
      return;
    }

    // Get user info
    const userResult = await query(
      'SELECT id, username, email, role, enabled, last_login, created_at FROM users WHERE id = $1',
      [userId]
    );

    if (userResult.rowCount === 0) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    // Get activity log
    const activityResult = await query(
      `SELECT
         id, timestamp, action, resource_type, resource_id,
         ip_address, user_agent, response_status, details
       FROM audit_logs
       WHERE user_id = $1
       ORDER BY timestamp DESC
       LIMIT $2 OFFSET $3`,
      [userId, limit, offset]
    );

    // Get activity summary
    const summaryResult = await query(
      `SELECT
         COUNT(*) as total_actions,
         COUNT(*) FILTER (WHERE timestamp > NOW() - INTERVAL '24 hours') as actions_24h,
         COUNT(*) FILTER (WHERE timestamp > NOW() - INTERVAL '7 days') as actions_7d,
         COUNT(*) FILTER (WHERE response_status >= 400) as errors
       FROM audit_logs
       WHERE user_id = $1`,
      [userId]
    );

    res.json({
      user: userResult.rows[0],
      activity: activityResult.rows,
      summary: {
        totalActions: parseInt(summaryResult.rows[0]?.total_actions || '0', 10),
        actions24h: parseInt(summaryResult.rows[0]?.actions_24h || '0', 10),
        actions7d: parseInt(summaryResult.rows[0]?.actions_7d || '0', 10),
        errors: parseInt(summaryResult.rows[0]?.errors || '0', 10),
      },
      pagination: { limit, offset },
    });
  } catch (error) {
    logger.error('Admin user activity error:', error);
    res.status(500).json({
      error: 'Failed to retrieve user activity',
      message: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * GET /api/admin/errors
 * Get recent application errors with human-readable messages
 */
router.get('/errors', async (req: Request, res: Response) => {
  try {
    const hours = parseInt(req.query.hours as string) || 24;
    const limit = parseInt(req.query.limit as string) || 50;
    const offset = parseInt(req.query.offset as string) || 0;

    const result = await ErrorLogService.getRecentErrors(hours, limit, offset);

    res.json(result);
  } catch (error) {
    logger.error('Admin errors fetch error:', error);
    res.status(500).json({
      error: 'Failed to retrieve errors',
      message: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * GET /api/admin/jobs
 * Get unified view of all background jobs (scans)
 */
router.get('/jobs', async (req: Request, res: Response) => {
  try {
    const status = req.query.status as string;
    const limit = parseInt(req.query.limit as string) || 50;
    const offset = parseInt(req.query.offset as string) || 0;

    let whereClause = '';
    const params: any[] = [limit, offset];

    if (status) {
      whereClause = 'WHERE status = $3';
      params.push(status);
    }

    // Get all scans (both asset discovery and vulnerability)
    const scansResult = await query(
      `SELECT
         id, scan_type as type, target, status,
         started_at, completed_at, duration_seconds,
         assets_discovered, vulnerabilities_found,
         error_message, initiated_by,
         created_at, updated_at,
         results_summary
       FROM vulnerability_scans
       ${whereClause}
       ORDER BY
         CASE status
           WHEN 'running' THEN 1
           WHEN 'queued' THEN 2
           ELSE 3
         END,
         created_at DESC
       LIMIT $1 OFFSET $2`,
      params
    );

    // Get job counts by status
    const countsResult = await query(
      `SELECT
         status,
         COUNT(*) as count
       FROM vulnerability_scans
       GROUP BY status`
    );

    const counts: Record<string, number> = {};
    for (const row of countsResult.rows) {
      counts[row.status] = parseInt(row.count, 10);
    }

    // Get user info for initiated_by
    const userIds = [...new Set(scansResult.rows.map((r: any) => r.initiated_by).filter(Boolean))];
    let userMap: Record<number, string> = {};

    if (userIds.length > 0) {
      const usersResult = await query(
        'SELECT id, username FROM users WHERE id = ANY($1)',
        [userIds]
      );
      for (const row of usersResult.rows) {
        userMap[row.id] = row.username;
      }
    }

    // Enhance jobs with user info
    const jobs = scansResult.rows.map((job: any) => ({
      ...job,
      initiated_by_username: job.initiated_by ? userMap[job.initiated_by] || 'Unknown' : 'System',
    }));

    res.json({
      jobs,
      counts,
      total: Object.values(counts).reduce((a, b) => a + b, 0),
      pagination: { limit, offset },
    });
  } catch (error) {
    logger.error('Admin jobs fetch error:', error);
    res.status(500).json({
      error: 'Failed to retrieve jobs',
      message: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

export default router;
