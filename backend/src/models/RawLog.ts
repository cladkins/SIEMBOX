import { query } from '../config/database';

export interface RawLog {
  id: number;
  timestamp: Date;
  raw_message: string;
  source_ip: string;
  facility: number | null;
  severity: number | null;
  hostname: string | null;
  created_at: Date;
}

export interface CreateRawLogParams {
  timestamp: Date;
  raw_message: string;
  source_ip: string;
  facility?: number | null;
  severity?: number | null;
  hostname?: string | null;
}

export class RawLogModel {
  static async create(params: CreateRawLogParams): Promise<RawLog> {
    const result = await query(
      `INSERT INTO raw_logs (timestamp, raw_message, source_ip, facility, severity, hostname)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [
        params.timestamp,
        params.raw_message,
        params.source_ip,
        params.facility ?? null,
        params.severity ?? null,
        params.hostname ?? null,
      ]
    );

    return result.rows[0];
  }

  static async findById(id: number): Promise<RawLog | null> {
    const result = await query('SELECT * FROM raw_logs WHERE id = $1', [id]);
    return result.rows[0] || null;
  }

  static async findAll(options?: {
    limit?: number;
    offset?: number;
    sourceIp?: string;
    search?: string;
    severity?: number;
    startTime?: Date;
    endTime?: Date;
  }): Promise<{ logs: RawLog[]; total: number }> {
    const conditions: string[] = [];
    const params: any[] = [];
    let paramIndex = 1;

    if (options?.sourceIp) {
      conditions.push(`source_ip = $${paramIndex++}`);
      params.push(options.sourceIp);
    }

    if (options?.search) {
      conditions.push(`raw_message ILIKE $${paramIndex++}`);
      params.push(`%${options.search}%`);
    }

    if (options?.severity !== undefined) {
      conditions.push(`severity = $${paramIndex++}`);
      params.push(options.severity);
    }

    if (options?.startTime) {
      conditions.push(`timestamp >= $${paramIndex++}`);
      params.push(options.startTime);
    }

    if (options?.endTime) {
      conditions.push(`timestamp <= $${paramIndex++}`);
      params.push(options.endTime);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    // Get total count
    const countResult = await query(`SELECT COUNT(*) FROM raw_logs ${whereClause}`, params);
    const total = parseInt(countResult.rows[0].count, 10);

    // Get logs
    const limit = options?.limit ?? 100;
    const offset = options?.offset ?? 0;

    params.push(limit, offset);
    const logsResult = await query(
      `SELECT * FROM raw_logs ${whereClause}
       ORDER BY created_at DESC
       LIMIT $${paramIndex++} OFFSET $${paramIndex++}`,
      params
    );

    return {
      logs: logsResult.rows,
      total,
    };
  }

  static async deleteOlderThan(days: number): Promise<number> {
    const result = await query(
      `DELETE FROM raw_logs WHERE created_at < NOW() - INTERVAL '${days} days'`
    );
    return result.rowCount || 0;
  }
}
