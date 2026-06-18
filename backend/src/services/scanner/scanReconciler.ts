/**
 * Scan Reconciler
 *
 * A scan's worker (the Nuclei child process / nmap run) lives in memory, so a
 * backend restart orphans any in-flight scan: the DB still shows it as
 * 'running'/'queued', but the process is gone. Such scans can never complete
 * and can't be cancelled through the normal path. On startup we mark them as
 * failed so they don't stay stuck (issue #19), and surface the event in the
 * admin dashboard.
 */

import { query } from '../../config/database';
import { logger } from '../../utils/logger';
import { ErrorLogService } from '../errors/errorLogService';

/**
 * Mark any scans left 'running' or 'queued' by a previous process as failed.
 * Safe to call once at startup (before the API accepts requests). Never throws.
 * Returns the number of scans reconciled.
 */
export async function reconcileInterruptedScans(): Promise<number> {
  try {
    const result = await query(
      `UPDATE vulnerability_scans
       SET status = 'failed',
           error_message = 'Interrupted by backend restart',
           completed_at = NOW(),
           updated_at = NOW()
       WHERE status IN ('running', 'queued')
       RETURNING id`
    );

    const count = result.rowCount || 0;
    if (count === 0) {
      logger.info('No interrupted scans to reconcile on startup');
      return 0;
    }

    const ids = result.rows.map((r: { id: number }) => r.id);
    logger.warn(`Reconciled ${count} interrupted scan(s) on startup: ${ids.join(', ')}`);

    // Surface in the admin dashboard. Deduped per startup so a crash loop
    // can't flood the error table.
    ErrorLogService.logBackgroundError(
      'scan-reconcile',
      `${count} scan(s) marked failed after a backend restart left them orphaned (ids: ${ids.join(', ')})`,
      { dedupeKey: 'startup', scanIds: ids }
    );

    return count;
  } catch (error) {
    logger.error('Failed to reconcile interrupted scans on startup:', error);
    return 0;
  }
}
