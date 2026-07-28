/**
 * Auto-Discovery Background Job
 *
 * Periodically runs asset discovery from log correlation.
 * Marks stale assets as offline and enriches asset data.
 *
 * Default interval: 6 hours (configurable via system_settings)
 */

import { AutoDiscoveryService } from '../services/assets/autoDiscoveryService';
import pool from '../config/database';
import { ErrorLogService } from '../services/errors/errorLogService';
import {
  registerRecurringJob,
  trackJobRun,
  markJobSkipped,
  setRecurringJobInterval,
} from '../services/jobs/jobRegistry';

const JOB_KEY = 'auto-discovery';

let intervalId: NodeJS.Timeout | null = null;
let currentIntervalMinutes = 360; // Track current interval to detect changes

/**
 * Get auto-discovery settings from database
 */
async function getAutoDiscoverySettings(): Promise<{
  enabled: boolean;
  intervalMinutes: number;
  staleThresholdDays: number;
}> {
  try {
    const result = await pool.query(`
      SELECT key, value
      FROM system_settings
      WHERE key IN ('auto_discovery_enabled', 'auto_discovery_interval_minutes', 'stale_asset_threshold_days')
    `);

    const settings: Record<string, string> = {
      auto_discovery_enabled: 'true',
      auto_discovery_interval_minutes: '360',
      stale_asset_threshold_days: '30',
    };

    result.rows.forEach((row: { key: string; value: string }) => {
      settings[row.key] = row.value;
    });

    return {
      enabled: settings.auto_discovery_enabled === 'true',
      intervalMinutes: parseInt(settings.auto_discovery_interval_minutes) || 360,
      staleThresholdDays: parseInt(settings.stale_asset_threshold_days) || 30,
    };
  } catch (error) {
    console.error('[Auto-Discovery Job] Failed to fetch settings, using defaults:', error);
    return {
      enabled: true,
      intervalMinutes: 360,
      staleThresholdDays: 30,
    };
  }
}

/**
 * Run auto-discovery cycle
 */
export async function runAutoDiscovery(): Promise<void> {
  const startTime = Date.now();

  // Check if auto-discovery is enabled
  const settings = await getAutoDiscoverySettings();

  if (!settings.enabled) {
    console.log('[Auto-Discovery Job] Auto-discovery is disabled via settings');
    markJobSkipped(JOB_KEY, 'auto-discovery disabled in settings');
    return;
  }

  console.log('[Auto-Discovery Job] Starting auto-discovery cycle...', {
    staleThresholdDays: settings.staleThresholdDays,
  });

  try {
    await trackJobRun(JOB_KEY, async () => {
      const result = await AutoDiscoveryService.runFullDiscovery();

      const duration = ((Date.now() - startTime) / 1000).toFixed(2);

      console.log('[Auto-Discovery Job] Cycle completed successfully:', {
        duration: `${duration}s`,
        discovered: result.discovered,
        staleMarked: result.staleMarked,
        enriched: result.enriched,
      });

      return `${result.discovered} discovered, ${result.staleMarked} marked stale, ${result.enriched} enriched`;
    });
  } catch (error) {
    console.error('[Auto-Discovery Job] Cycle failed:', error);
    ErrorLogService.logBackgroundError('auto-discovery-job', error);
  }
}

/**
 * Start the auto-discovery job with dynamic scheduling
 */
export async function startAutoDiscoveryJob(): Promise<void> {
  // Get initial settings
  const settings = await getAutoDiscoverySettings();
  currentIntervalMinutes = settings.intervalMinutes;

  const intervalMs = currentIntervalMinutes * 60 * 1000;

  registerRecurringJob({
    key: JOB_KEY,
    name: 'Asset auto-discovery',
    description: 'Derives assets from log activity, marks stale hosts offline and enriches records.',
    intervalMs,
  });
  setRecurringJobInterval(JOB_KEY, intervalMs);

  console.log('[Auto-Discovery Job] Starting background job', {
    enabled: settings.enabled,
    intervalMinutes: currentIntervalMinutes,
    staleThresholdDays: settings.staleThresholdDays,
  });

  // Run immediately on startup
  runAutoDiscovery();

  // Schedule recurring runs with interval check
  intervalId = setInterval(async () => {
    // Check if interval changed
    const currentSettings = await getAutoDiscoverySettings();

    if (currentSettings.intervalMinutes !== currentIntervalMinutes) {
      console.log(
        `[Auto-Discovery Job] Interval changed from ${currentIntervalMinutes} to ${currentSettings.intervalMinutes} minutes, rescheduling...`
      );
      // Reschedule with new interval
      stopAutoDiscoveryJob();
      startAutoDiscoveryJob();
      return;
    }

    // Run the discovery cycle
    runAutoDiscovery();
  }, intervalMs);
}

/**
 * Stop the auto-discovery job
 */
export function stopAutoDiscoveryJob(): void {
  if (intervalId) {
    clearInterval(intervalId);
    intervalId = null;
    console.log('[Auto-Discovery Job] Background job stopped');
  }
}
