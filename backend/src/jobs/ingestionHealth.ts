/**
 * Ingestion Health Monitor
 *
 * Periodically checks whether logs are still being received and notifies on
 * transitions (stalled -> resumed and vice-versa) when ingestion notifications
 * are enabled. State is tracked in memory, so a notification fires once per
 * transition rather than every cycle.
 */

import { query } from '../config/database';
import { NotificationService } from '../services/notifications/notificationService';
import { logger } from '../utils/logger';
import { ErrorLogService } from '../services/errors/errorLogService';
import { registerRecurringJob, trackJobRun, markJobSkipped } from '../services/jobs/jobRegistry';
import { AlertModel } from '../models/Alert';
import { evaluateIngestHealth, readIngestSnapshot } from '../services/ingest/ingestHealth';

const JOB_KEY = 'ingestion-health';

let intervalId: NodeJS.Timeout | null = null;
let lastHealthy: boolean | null = null;
const CHECK_INTERVAL_MS = 2 * 60 * 1000; // every 2 minutes

async function getSetting(key: string, fallback: string): Promise<string> {
  try {
    const r = await query(`SELECT value FROM system_settings WHERE key = $1`, [key]);
    return r.rows[0]?.value ?? fallback;
  } catch {
    return fallback;
  }
}

/** Source of the built-in stall alert on the Alerts page (alerts.source). */
export const STALL_ALERT_SOURCE = 'siembox:ingestion';

/** Minutes of zero ingest (with shippers online) before the built-in alert fires (setting ingestion_stall_alert_minutes). */
export const DEFAULT_STALL_ALERT_MINUTES = 10;

/**
 * The stall alert's dedupe id: one alert per stall, keyed by the newest log's
 * time (the moment ingestion stopped). A later stall has a later newest log.
 */
export function stallAlertEventId(newestRawLogAt: Date | null): string {
  return `ingestion-stall:${newestRawLogAt ? newestRawLogAt.toISOString() : 'never'}`;
}

/**
 * Built-in alert, on by default and independent of the notification settings:
 * raise one alert on the Alerts page when no log has been stored for
 * ingestion_stall_alert_minutes (default 10) while shippers are online.
 * ingestion_stall_alert_enabled = 'false' turns it off. Returns the verdict.
 */
export async function checkStallAlert(now: number = Date.now()): Promise<'disabled' | 'healthy' | 'stalled'> {
  if ((await getSetting('ingestion_stall_alert_enabled', 'true')) === 'false') return 'disabled';
  const minutes = parseInt(await getSetting('ingestion_stall_alert_minutes', String(DEFAULT_STALL_ALERT_MINUTES)), 10);
  const thresholdSeconds = (Number.isFinite(minutes) && minutes > 0 ? minutes : DEFAULT_STALL_ALERT_MINUTES) * 60;
  const snapshot = await readIngestSnapshot();
  const verdict = evaluateIngestHealth(snapshot, thresholdSeconds, now);
  if (verdict.ok) return 'healthy';
  const created = await AlertModel.createSourced({
    source: STALL_ALERT_SOURCE,
    event_id: stallAlertEventId(snapshot.newestRawLogAt),
    severity: 'critical',
    title: 'Log ingestion stalled',
    description:
      `SIEMBox has stored no logs for ${Math.round(thresholdSeconds / 60)}+ minutes while ` +
      `${snapshot.onlineShippers} shipper(s) are online (${verdict.reason}). ` +
      'Check GET /health, the backend log, and Troubleshooting -> "No Logs Appearing in SIEMBox".',
    matched_data: {
      newest_raw_log_at: snapshot.newestRawLogAt ? snapshot.newestRawLogAt.toISOString() : null,
      online_shippers: snapshot.onlineShippers,
      threshold_minutes: Math.round(thresholdSeconds / 60),
    },
  });
  if (created !== null) {
    logger.error(`[Ingestion Health] ${verdict.reason}; raised alert ${created}`);
  }
  return 'stalled';
}

export async function checkIngestionHealth(): Promise<void> {
  try {
    await checkStallAlert().catch((err) => {
      logger.error('[Ingestion Health] stall alert check failed:', err);
      ErrorLogService.logBackgroundError('ingestion-health', err, { dedupeKey: 'stall-alert' });
    });

    if ((await getSetting('notify_ingestion_enabled', 'false')) !== 'true') {
      lastHealthy = null;
      markJobSkipped(JOB_KEY, 'ingestion notifications disabled in settings');
      return;
    }

    // Only meaningful once at least one shipper exists.
    const shipperCount = (await query(`SELECT COUNT(*)::int AS c FROM log_shippers`)).rows[0].c;
    if (shipperCount === 0) {
      lastHealthy = null;
      markJobSkipped(JOB_KEY, 'no shippers registered');
      return;
    }

    await trackJobRun(JOB_KEY, async () => {
      const stallMinutes = parseInt(await getSetting('notify_ingestion_stall_minutes', '15'), 10) || 15;
      const last = (await query(`SELECT MAX(created_at) AS last FROM raw_logs`)).rows[0].last;
      const healthy = last !== null && Date.now() - new Date(last).getTime() < stallMinutes * 60 * 1000;

      if (lastHealthy === null) {
        // First observation since enabling: set the baseline, and alert if already stalled.
        lastHealthy = healthy;
        if (!healthy) {
          await NotificationService.notifyIngestion({ healthy: false, stallMinutes });
        }
        return healthy ? 'ingestion healthy' : 'ingestion stalled';
      }

      if (healthy !== lastHealthy) {
        await NotificationService.notifyIngestion({ healthy, stallMinutes });
        lastHealthy = healthy;
      }
      return healthy ? 'ingestion healthy' : 'ingestion stalled';
    });
  } catch (err) {
    logger.error('[Ingestion Health] check failed:', err);
    ErrorLogService.logBackgroundError('ingestion-health', err, { dedupeKey: 'check' });
  }
}

export function startIngestionHealthJob(): void {
  if (intervalId) return;
  registerRecurringJob({
    key: JOB_KEY,
    name: 'Ingestion health monitor',
    description:
      'Watches for a stalled log stream: raises a built-in alert after 10 minutes of zero ingest while shippers are online, and notifies on stall/recovery transitions.',
    intervalMs: CHECK_INTERVAL_MS,
  });
  logger.info('[Ingestion Health] Monitor started (every 2 min)');
  intervalId = setInterval(() => {
    checkIngestionHealth().catch((err) => logger.error('[Ingestion Health] cycle error:', err));
  }, CHECK_INTERVAL_MS);
}

export function stopIngestionHealthJob(): void {
  if (intervalId) {
    clearInterval(intervalId);
    intervalId = null;
    logger.info('[Ingestion Health] Monitor stopped');
  }
}
