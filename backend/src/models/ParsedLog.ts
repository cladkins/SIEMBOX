import { query } from '../config/database';

export interface ParsedLog {
  id: number;
  raw_log_id: number;
  parser_id: number | null;
  parsed_data: Record<string, any>;
  timestamp: Date;
  source_ip: string;
  event_type: string | null;
  created_at: Date;
  app_name?: string | null; // From joined raw_logs table
  parser_name?: string | null; // From joined parsers table (which parser matched)
}

export interface CreateParsedLogParams {
  raw_log_id: number;
  parser_id: number | null;
  parsed_data: Record<string, any>;
  timestamp: Date;
  source_ip: string;
  event_type?: string | null;
}

export class ParsedLogModel {
  static async create(params: CreateParsedLogParams): Promise<ParsedLog> {
    const result = await query(
      `INSERT INTO parsed_logs (raw_log_id, parser_id, parsed_data, timestamp, source_ip, event_type)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [
        params.raw_log_id,
        params.parser_id,
        JSON.stringify(params.parsed_data),
        params.timestamp,
        params.source_ip,
        params.event_type ?? null,
      ]
    );

    return result.rows[0];
  }

  static async findById(id: number): Promise<ParsedLog | null> {
    const result = await query('SELECT * FROM parsed_logs WHERE id = $1', [id]);
    return result.rows[0] || null;
  }

  static async findAll(options?: {
    limit?: number;
    offset?: number;
    sourceIp?: string;
    eventType?: string;
    appName?: string;
    parserId?: number;
    search?: string;
    startTime?: Date;
    endTime?: Date;
  }): Promise<{ logs: ParsedLog[]; total: number }> {
    const conditions: string[] = [];
    const params: any[] = [];
    let paramIndex = 1;

    if (options?.sourceIp) {
      conditions.push(`pl.source_ip = $${paramIndex++}`);
      params.push(options.sourceIp);
    }

    if (options?.eventType) {
      conditions.push(`pl.event_type = $${paramIndex++}`);
      params.push(options.eventType);
    }

    if (options?.appName) {
      conditions.push(`rl.app_name = $${paramIndex++}`);
      params.push(options.appName);
    }

    if (options?.parserId !== undefined && !Number.isNaN(options.parserId)) {
      conditions.push(`pl.parser_id = $${paramIndex++}`);
      params.push(options.parserId);
    }

    if (options?.search) {
      conditions.push(`pl.parsed_data::text ILIKE $${paramIndex++}`);
      params.push(`%${options.search}%`);
    }

    if (options?.startTime) {
      conditions.push(`pl.timestamp >= $${paramIndex++}`);
      params.push(options.startTime);
    }

    if (options?.endTime) {
      conditions.push(`pl.timestamp <= $${paramIndex++}`);
      params.push(options.endTime);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    // Get total count
    const countResult = await query(
      `SELECT COUNT(*)
       FROM parsed_logs pl
       LEFT JOIN raw_logs rl ON pl.raw_log_id = rl.id
       ${whereClause}`,
      params
    );
    const total = parseInt(countResult.rows[0].count, 10);

    // Get logs
    const limit = options?.limit ?? 100;
    const offset = options?.offset ?? 0;

    params.push(limit, offset);
    const logsResult = await query(
      `SELECT pl.*, rl.app_name, p.name AS parser_name
       FROM parsed_logs pl
       LEFT JOIN raw_logs rl ON pl.raw_log_id = rl.id
       LEFT JOIN parsers p ON pl.parser_id = p.id
       ${whereClause}
       ORDER BY pl.created_at DESC
       LIMIT $${paramIndex++} OFFSET $${paramIndex++}`,
      params
    );

    return {
      logs: logsResult.rows,
      total,
    };
  }

  static async searchByField(
    field: string,
    value: string,
    options?: { limit?: number; offset?: number }
  ): Promise<{ logs: ParsedLog[]; total: number }> {
    const limit = options?.limit ?? 100;
    const offset = options?.offset ?? 0;

    // Search in JSONB data
    const logsResult = await query(
      `SELECT * FROM parsed_logs
       WHERE parsed_data->>$1 = $2
       ORDER BY created_at DESC
       LIMIT $3 OFFSET $4`,
      [field, value, limit, offset]
    );

    const countResult = await query(
      `SELECT COUNT(*) FROM parsed_logs WHERE parsed_data->>$1 = $2`,
      [field, value]
    );

    return {
      logs: logsResult.rows,
      total: parseInt(countResult.rows[0].count, 10),
    };
  }

  static async deleteOlderThan(days: number): Promise<number> {
    const result = await query(
      `DELETE FROM parsed_logs WHERE created_at < NOW() - INTERVAL '${days} days'`
    );
    return result.rowCount || 0;
  }
}
