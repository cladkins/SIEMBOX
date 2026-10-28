import { query } from '../config/database';
import { computeNextRun, type CalendarSchedule } from '../utils/scheduleTiming';

export type ScheduledScanType = 'asset' | 'vulnerability' | 'container' | 'log_discovery';

export interface ScheduledScan {
  id: number;
  name: string;
  scan_type: ScheduledScanType;
  scan_options: Record<string, any>;
  /** Fixed-interval cadence (schedule is null); null for a calendar schedule. */
  interval_minutes: number | null;
  /** Calendar timing (utils/scheduleTiming.ts); null = fixed interval. */
  schedule: CalendarSchedule | null;
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
  /** Exactly one of interval_minutes and schedule is non-null. */
  interval_minutes: number | null;
  schedule?: CalendarSchedule | null;
  enabled?: boolean;
  created_by?: number | null;
}

/**
 * The calendar schedule's next run after now, as a timestamptz parameter, or
 * null for a fixed-interval schedule (whose next run the SQL computes as
 * NOW() + interval_minutes, unchanged from before calendar timing). next_run_at
 * is a timestamp column like NOW()'s session-zone value, so the instant goes in
 * as timestamptz and Postgres converts it the same way.
 *
 * "Now" is the later of this process's clock and the database's: the
 * dispatcher compares next_run_at with the database's NOW(), so a backend
 * clock running behind it must not compute a run that is already due.
 */
export async function calendarNextRunParam(schedule: CalendarSchedule | null | undefined): Promise<string | null> {
  if (!schedule) return null;
  const db = (await query(`SELECT NOW() AS now`)).rows[0]?.now;
  const now = Math.max(Date.now(), db instanceof Date ? db.getTime() : 0);
  return computeNextRun(schedule, new Date(now)).toISOString();
}

const NEXT_RUN_SQL = (param: string) => `COALESCE(${param}::timestamptz, NOW() + make_interval(mins => interval_minutes))`;

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
         (name, scan_type, scan_options, interval_minutes, schedule, enabled, created_by, next_run_at)
       VALUES ($1, $2, $3, $4::int, $5, COALESCE($6, true), $7,
               COALESCE($8::timestamptz, NOW() + make_interval(mins => $4::int)))
       RETURNING *`,
      [
        input.name,
        input.scan_type,
        JSON.stringify(input.scan_options || {}),
        input.schedule ? null : input.interval_minutes,
        input.schedule ? JSON.stringify(input.schedule) : null,
        input.enabled ?? true,
        input.created_by ?? null,
        await calendarNextRunParam(input.schedule),
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
    if (fields.schedule !== undefined) {
      sets.push(`schedule = $${i++}`);
      params.push(fields.schedule ? JSON.stringify(fields.schedule) : null);
    }
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

  /**
   * Record that a schedule ran and roll next_run_at forward: by its interval,
   * or to its next calendar occurrence after now. Either way the next run is
   * in the future, so a schedule that was due several times over while
   * SIEMBox was down runs once and then resumes its normal times, without a
   * burst of catch-up runs.
   */
  async markRun(id: number, scanId: number | null): Promise<void> {
    const row = await ScheduledScanModel.findById(id);
    if (!row) return;
    await query(
      `UPDATE scheduled_scans
       SET last_run_at = NOW(),
           last_scan_id = $2,
           next_run_at = ${NEXT_RUN_SQL('$3')},
           updated_at = NOW()
       WHERE id = $1`,
      [id, scanId, await calendarNextRunParam(row.schedule)]
    );
  },

  // Recompute next_run_at from now (used when the timing changes or a schedule is re-enabled).
  async resetNextRun(id: number): Promise<void> {
    const row = await ScheduledScanModel.findById(id);
    if (!row) return;
    await query(
      `UPDATE scheduled_scans
       SET next_run_at = ${NEXT_RUN_SQL('$2')}, updated_at = NOW()
       WHERE id = $1`,
      [id, await calendarNextRunParam(row.schedule)]
    );
  },
};
