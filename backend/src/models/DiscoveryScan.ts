import { query } from '../config/database';

export type DiscoveryScanMode = 'passive' | 'active' | 'full';
export type DiscoveryScanStatus = 'running' | 'completed' | 'failed';

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
