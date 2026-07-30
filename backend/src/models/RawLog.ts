import { query } from '../config/database';
import { batchedDelete } from '../utils/batchDelete';

export interface RawLog {
  id: number;
  timestamp: Date;
  raw_message: string;
  source_ip: string;
  facility: number | null;
  severity: number | null;
  hostname: string | null;
  app_name: string | null;
  shipper_id: string | null;
  /** Client-supplied dedup key for HTTP-pushed logs (see 029_shipper_http_push.sql). Always null for syslog-ingested rows. */
  ingest_event_id: string | null;
  /** Set for logs pulled by the Log Discovery API poller (030_discovery_api_poller.sql); mutually exclusive with shipper_id. */
  discovery_source_id: number | null;
  created_at: Date;
}

export interface CreateRawLogParams {
  timestamp: Date;
  raw_message: string;
  source_ip: string;
  facility?: number | null;
  severity?: number | null;
  hostname?: string | null;
  app_name?: string | null;
  shipper_id?: string | null;
  ingest_event_id?: string | null;
  discovery_source_id?: number | null;
}

export interface RawLogFilters {
  limit?: number;
  offset?: number;
  sourceIp?: string;
  /** Syslog tag/program — the same value the Parsed Logs view labels "Source". */
  appName?: string;
  hostname?: string;
  search?: string;
  severity?: number;
  startTime?: Date;
  endTime?: Date;
}

/**
 * Build the WHERE clause + bind params shared by the count and page queries.
 * Extracted so the bind-index bookkeeping is testable without a database.
 */
export function buildRawLogFilters(options?: RawLogFilters): {
  whereClause: string;
  params: any[];
} {
  const conditions: string[] = [];
  const params: any[] = [];
  let paramIndex = 1;

  if (options?.sourceIp) {
    conditions.push(`source_ip = $${paramIndex++}`);
    params.push(options.sourceIp);
  }

  // The Parsed Logs "Source" column is raw_logs.app_name joined through
  // raw_log_id, so the same filter has to work on the raw side or the shared
  // filter bar silently does nothing on this tab.
  if (options?.appName) {
    conditions.push(`app_name = $${paramIndex++}`);
    params.push(options.appName);
  }

  if (options?.hostname) {
    conditions.push(`hostname = $${paramIndex++}`);
    params.push(options.hostname);
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

  return {
    whereClause: conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '',
    params,
  };
}

export class RawLogModel {
  /**
   * Returns null when `ingest_event_id` is set and a row with the same
   * (shipper_id, ingest_event_id) — or (discovery_source_id, ingest_event_id)
   * for poller-attributed rows — already exists: a retried HTTP push or an
   * overlapping poll window is silently deduped rather than creating a second
   * row and re-firing detections. Callers that never pass `ingest_event_id`
   * (syslog ingestion) always get a row back. `shipper_id` and
   * `discovery_source_id` are mutually exclusive by construction (push vs.
   * pull ingestion paths never set both), so exactly one partial unique index
   * is ever a candidate conflict target for a given row.
   */
  static async create(params: CreateRawLogParams): Promise<RawLog | null> {
    const conflictClause =
      params.discovery_source_id != null
        ? `ON CONFLICT (discovery_source_id, ingest_event_id) WHERE discovery_source_id IS NOT NULL AND ingest_event_id IS NOT NULL DO NOTHING`
        : `ON CONFLICT (shipper_id, ingest_event_id) WHERE ingest_event_id IS NOT NULL DO NOTHING`;
    const result = await query(
      `INSERT INTO raw_logs (timestamp, raw_message, source_ip, facility, severity, hostname, app_name, shipper_id, ingest_event_id, discovery_source_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       ${conflictClause}
       RETURNING *`,
      [
        params.timestamp,
        params.raw_message,
        params.source_ip,
        params.facility ?? null,
        params.severity ?? null,
        params.hostname ?? null,
        params.app_name ?? null,
        params.shipper_id ?? null,
        params.ingest_event_id ?? null,
        params.discovery_source_id ?? null,
      ]
    );

    return result.rows[0] || null;
  }

  static async findById(id: number): Promise<RawLog | null> {
    const result = await query('SELECT * FROM raw_logs WHERE id = $1', [id]);
    return result.rows[0] || null;
  }

  static async findAll(options?: RawLogFilters): Promise<{ logs: RawLog[]; total: number }> {
    const { whereClause, params } = buildRawLogFilters(options);
    let paramIndex = params.length + 1;

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
    // Batched + parameterized (was an unbounded, string-interpolated DELETE).
    return batchedDelete('raw_logs', "created_at < NOW() - INTERVAL '1 day' * $1", [days], {
      label: 'raw_logs retention',
    });
  }
}
