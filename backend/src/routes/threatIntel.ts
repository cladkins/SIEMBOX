import { Router, Request, Response } from 'express';
import { isIP } from 'net';
import { query } from '../config/database';
import { ApiError } from '../middleware/errorHandler';
import { geoipService } from '../services/geoip/geoipService';

const router = Router();

/**
 * GET /ip/:ip — everything we know about an IP: its GeoIP country, recent parsed
 * log events from it, and recent alerts that referenced it. All three IP-keyed
 * queries are index-/key-filtered, so they stay fast.
 */
router.get('/ip/:ip', async (req: Request, res: Response) => {
  const ip = (req.params.ip || '').trim();
  if (!isIP(ip)) {
    throw new ApiError(400, 'Invalid IP address');
  }

  const geo = geoipService.lookup(ip);

  const events = await query(
    `SELECT pl.id, pl.timestamp, pl.event_type, pl.source_ip, pl.parsed_data, rl.app_name
       FROM parsed_logs pl
       LEFT JOIN raw_logs rl ON pl.raw_log_id = rl.id
      WHERE pl.source_ip = $1
      ORDER BY pl.timestamp DESC
      LIMIT 50`,
    [ip]
  );

  const alerts = await query(
    `SELECT a.id, a.created_at, a.severity, a.title, a.status, a.matched_data,
            r.name AS rule_name
       FROM alerts a
       LEFT JOIN detection_rules r ON a.rule_id = r.id
      WHERE a.matched_data->>'source_ip' = $1
         OR a.matched_data->>'client_ip' = $1
         OR a.matched_data->>'dest_ip' = $1
      ORDER BY a.created_at DESC
      LIMIT 50`,
    [ip]
  );

  const counts = await query(
    `SELECT
       (SELECT COUNT(*) FROM parsed_logs WHERE source_ip = $1) AS event_count,
       (SELECT COUNT(*) FROM alerts
          WHERE matched_data->>'source_ip' = $1
             OR matched_data->>'client_ip' = $1
             OR matched_data->>'dest_ip' = $1) AS alert_count`,
    [ip]
  );

  res.json({
    ip,
    geo: geo
      ? { ...geo, foreign: geoipService.isForeign(geo.country_code) }
      : null,
    counts: {
      events: parseInt(counts.rows[0]?.event_count || '0', 10),
      alerts: parseInt(counts.rows[0]?.alert_count || '0', 10),
    },
    events: events.rows,
    alerts: alerts.rows,
  });
});

/**
 * GET /country/:code — the IPs seen from a country (derived from alerts), with
 * per-IP alert counts. Backs the map drill-down (click a country -> its IPs).
 */
router.get('/country/:code', async (req: Request, res: Response) => {
  const code = (req.params.code || '').trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(code)) {
    throw new ApiError(400, 'Invalid country code');
  }
  const days = Math.min(Math.max(parseInt(String(req.query.days)) || 30, 1), 365);

  const rows = await query(
    `SELECT
       COALESCE(matched_data->>'source_ip', matched_data->>'client_ip') AS ip,
       COUNT(*)::int AS alert_count,
       MAX(created_at) AS last_seen
       FROM alerts
      WHERE matched_data->>'country_code' = $1
        AND created_at >= NOW() - ($2 || ' days')::interval
        AND COALESCE(matched_data->>'source_ip', matched_data->>'client_ip') IS NOT NULL
      GROUP BY ip
      ORDER BY alert_count DESC
      LIMIT 100`,
    [code, days]
  );

  res.json({ country_code: code, ips: rows.rows });
});

export default router;
