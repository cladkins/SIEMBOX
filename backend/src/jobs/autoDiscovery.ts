/**
 * Auto-Discovery Background Job
 *
 * Periodically runs asset discovery from log correlation.
 * Marks stale assets as offline and enriches asset data.
 *
 * Runs every 6 hours by default.
 */

import { AutoDiscoveryService } from '../services/assets/autoDiscoveryService';

/**
 * Run auto-discovery cycle
 */
export async function runAutoDiscovery(): Promise<void> {
  const startTime = Date.now();
  console.log('[Auto-Discovery Job] Starting auto-discovery cycle...');

  try {
    const result = await AutoDiscoveryService.runFullDiscovery();

    const duration = ((Date.now() - startTime) / 1000).toFixed(2);

    console.log('[Auto-Discovery Job] Cycle completed successfully:', {
      duration: `${duration}s`,
      discovered: result.discovered,
      staleMarked: result.staleMarked,
      enriched: result.enriched,
    });
  } catch (error) {
    console.error('[Auto-Discovery Job] Cycle failed:', error);
  }
}

// Run every 6 hours (21600000 milliseconds)
const INTERVAL_MS = 6 * 60 * 60 * 1000;

let intervalId: NodeJS.Timeout | null = null;

/**
 * Start the auto-discovery job
 */
export function startAutoDiscoveryJob(): void {
  console.log('[Auto-Discovery Job] Starting background job (interval: 6 hours)');

  // Run immediately on startup
  runAutoDiscovery();

  // Then run every 6 hours
  intervalId = setInterval(runAutoDiscovery, INTERVAL_MS);
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
