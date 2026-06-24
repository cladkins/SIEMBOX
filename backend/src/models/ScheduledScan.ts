import { query } from '../config/database';

export type ScheduledScanType = 'asset' | 'vulnerability' | 'container';

export interface ScheduledScan {
  id: number;
  name: string;
  scan_type: ScheduledScanType;
  scan_options: Record<string, any>;
  interval_minutes: number;
  enabled: boolean;
  last_run_at: string | null;
  last_scan_id: number | null;
  next_run_at: string;
  created_by: number | null;
  created_at: string;
  updated_at: string;
}

export interface ScheduledScanInput {
  name: string;
  scan_type: ScheduledScanType;
  scan_options: Record<string, any>;
  interval_minutes: number;
  enabled?: boolean;
  created_by?: number | null;
}

export const ScheduledScanModel = {
  async findAll(): Promise<ScheduledScan[]> {
    const result = await query(`SELECT * FROM scheduled_scans ORDER BY created_at DESC`);
    return result.rows;
  },

  async findById(id: number): Promise<ScheduledScan | null> {
    const result = await query(`SELECT * FROM scheduled_scans WHERE id = $1`, [id]);
    return result.rows[0] || null;
  },

  // Enabled schedules whose next run is due.
  async findDue(): Promise<ScheduledScan[]> {
    const result = await query(
      `SELECT * FROM scheduled_scans
       WHERE enabled = true AND next_run_at <= NOW()
       ORDER BY next_run_at ASC`
    );
    return result.rows;
  },

  async create(input: ScheduledScanInput): Promise<ScheduledScan> {
    const result = await query(
      `INSERT INTO scheduled_scans
         (name, scan_type, scan_options, interval_minutes, enabled, created_by, next_run_at)
       VALUES ($1, $2, $3, $4, COALESCE($5, true), $6, NOW() + make_interval(mins => $4::int))
       RETURNING *`,
      [
        input.name,
        input.scan_type,
        JSON.stringify(input.scan_options || {}),
        input.interval_minutes,
        input.enabled ?? true,
        input.created_by ?? null,
      ]
    );
    return result.rows[0];
  },

  async update(id: number, fields: Partial<ScheduledScanInput>): Promise<ScheduledScan | null> {
    const sets: string[] = [];
    const params: any[] = [];
    let i = 1;

    if (fields.name !== undefined) { sets.push(`name = $${i++}`); params.push(fields.name); }
    if (fields.scan_type !== undefined) { sets.push(`scan_type = $${i++}`); params.push(fields.scan_type); }
    if (fields.scan_options !== undefined) { sets.push(`scan_options = $${i++}`); params.push(JSON.stringify(fields.scan_options)); }
    if (fields.interval_minutes !== undefined) { sets.push(`interval_minutes = $${i++}`); params.push(fields.interval_minutes); }
    if (fields.enabled !== undefined) { sets.push(`enabled = $${i++}`); params.push(fields.enabled); }

    if (sets.length === 0) {
      return ScheduledScanModel.findById(id);
    }

    sets.push(`updated_at = NOW()`);
    params.push(id);

    const result = await query(
      `UPDATE scheduled_scans SET ${sets.join(', ')} WHERE id = $${i} RETURNING *`,
      params
    );
    return result.rows[0] || null;
  },

  async delete(id: number): Promise<boolean> {
    const result = await query(`DELETE FROM scheduled_scans WHERE id = $1`, [id]);
    return (result.rowCount || 0) > 0;
  },

  // Record that a schedule ran and roll next_run_at forward by its interval.
  async markRun(id: number, scanId: number | null): Promise<void> {
    await query(
      `UPDATE scheduled_scans
       SET last_run_at = NOW(),
           last_scan_id = $2,
           next_run_at = NOW() + make_interval(mins => interval_minutes),
           updated_at = NOW()
       WHERE id = $1`,
      [id, scanId]
    );
  },

  // Recompute next_run_at from now (used when interval changes or a schedule is re-enabled).
  async resetNextRun(id: number): Promise<void> {
    await query(
      `UPDATE scheduled_scans
       SET next_run_at = NOW() + make_interval(mins => interval_minutes), updated_at = NOW()
       WHERE id = $1`,
      [id]
    );
  },
};
