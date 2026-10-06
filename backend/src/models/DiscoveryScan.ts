import { query } from '../config/database';

export type DiscoveryScanMode = 'passive' | 'active' | 'full';
// 'queued' is a shipper-dispatched scan waiting to be claimed (migration 033);
// an in-process scan is created straight into 'running'.
export type DiscoveryScanStatus = 'queued' | 'running' | 'completed' | 'failed';

export interface DiscoveryScan {
  id: number;
  mode: DiscoveryScanMode;
  cidrs: string[];
  status: DiscoveryScanStatus;
  started_at: string;
  completed_at: string | null;
  error_message: string | null;
  results_summary: Record<string, unknown> | null;
  created_by: number | null;
  /** Shipper this scan was dispatched to (null = run in-process on the backend). */
  assigned_shipper_id: number | null;
  claimed_at: string | null;
  created_at: string;
}

export const DiscoveryScanModel = {
  async findAll(limit = 20): Promise<DiscoveryScan[]> {
    const result = await query(`SELECT * FROM discovery_scans ORDER BY started_at DESC LIMIT $1`, [limit]);
    return result.rows;
  },

  async findById(id: number): Promise<DiscoveryScan | null> {
    const result = await query(`SELECT * FROM discovery_scans WHERE id = $1`, [id]);
    return result.rows[0] || null;
  },

  async create(mode: DiscoveryScanMode, cidrs: string[], createdBy: number | null): Promise<DiscoveryScan> {
    const result = await query(
      `INSERT INTO discovery_scans (mode, cidrs, status, created_by) VALUES ($1, $2, 'running', $3) RETURNING *`,
      [mode, JSON.stringify(cidrs), createdBy]
    );
    return result.rows[0];
  },

  /**
   * Create a scan dispatched to a shipper: status 'queued' (NOT run in-process),
   * waiting for that shipper to claim it via claimForShipper.
   */
  async createAssigned(
    mode: DiscoveryScanMode,
    cidrs: string[],
    createdBy: number | null,
    shipperId: number
  ): Promise<DiscoveryScan> {
    const result = await query(
      `INSERT INTO discovery_scans (mode, cidrs, status, created_by, assigned_shipper_id)
       VALUES ($1, $2, 'queued', $3, $4) RETURNING *`,
      [mode, JSON.stringify(cidrs), createdBy, shipperId]
    );
    return result.rows[0];
  },

  /**
   * Atomically hand out and claim every queued scan assigned to a shipper
   * (queued -> running, stamping claimed_at), so a job is claimed once even
   * under concurrent polls. Mirrors the nmap/nuclei claim.
   */
  async claimForShipper(shipperId: number): Promise<DiscoveryScan[]> {
    const result = await query(
      `UPDATE discovery_scans
          SET status = 'running', claimed_at = NOW(), started_at = NOW()
        WHERE id IN (
          SELECT id FROM discovery_scans
           WHERE assigned_shipper_id = $1 AND status = 'queued'
           ORDER BY created_at
           FOR UPDATE SKIP LOCKED
        )
        RETURNING *`,
      [shipperId]
    );
    return result.rows;
  },

  // complete/fail only transition OUT of 'running', so a scan that was already
  // cancelled or watchdog-timed-out can't be flipped back by its (still
  // finishing) worker, and duplicate terminal writes are no-ops. Both return
  // whether the transition happened.

  async complete(id: number, resultsSummary: Record<string, unknown>): Promise<boolean> {
    const result = await query(
      `UPDATE discovery_scans SET status = 'completed', completed_at = NOW(), results_summary = $2
       WHERE id = $1 AND status = 'running'`,
      [id, JSON.stringify(resultsSummary)]
    );
    return (result.rowCount || 0) > 0;
  },

  async fail(id: number, errorMessage: string): Promise<boolean> {
    const result = await query(
      `UPDATE discovery_scans SET status = 'failed', completed_at = NOW(), error_message = $2
       WHERE id = $1 AND status = 'running'`,
      [id, errorMessage]
    );
    return (result.rowCount || 0) > 0;
  },
};
