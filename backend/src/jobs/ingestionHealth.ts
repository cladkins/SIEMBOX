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

export async function checkIngestionHealth(): Promise<void> {
  try {
    if ((await getSetting('notify_ingestion_enabled', 'false')) !== 'true') {
      lastHealthy = null;
      return;
    }

    // Only meaningful once at least one shipper exists.
    const shipperCount = (await query(`SELECT COUNT(*)::int AS c FROM log_shippers`)).rows[0].c;
    if (shipperCount === 0) {
      lastHealthy = null;
      return;
    }

    const stallMinutes = parseInt(await getSetting('notify_ingestion_stall_minutes', '15'), 10) || 15;
    const last = (await query(`SELECT MAX(created_at) AS last FROM raw_logs`)).rows[0].last;
    const healthy = last !== null && Date.now() - new Date(last).getTime() < stallMinutes * 60 * 1000;

    if (lastHealthy === null) {
      // First observation since enabling: set the baseline, and alert if already stalled.
      lastHealthy = healthy;
      if (!healthy) {
        await NotificationService.notifyIngestion({ healthy: false, stallMinutes });
      }
      return;
    }

    if (healthy !== lastHealthy) {
      await NotificationService.notifyIngestion({ healthy, stallMinutes });
      lastHealthy = healthy;
    }
  } catch (err) {
    logger.error('[Ingestion Health] check failed:', err);
  }
}

export function startIngestionHealthJob(): void {
  if (intervalId) return;
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
