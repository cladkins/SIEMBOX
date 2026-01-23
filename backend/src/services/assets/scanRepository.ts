/**
 * Scan Repository
 *
 * Database queries for vulnerability scan status and history.
 * Provides filtering, pagination, and detailed scan information.
 */

import pool from '../../config/database';

export interface ScanFilters {
  status?: string;
  scan_type?: string;
  excludeTypes?: string[];
  limit?: number;
  offset?: number;
}

export interface ScanResult {
  id: number;
  scan_type: string;
  target: string;
  status: string;
  started_at: Date | null;
  completed_at: Date | null;
  duration_seconds: number | null;
  assets_discovered: number;
  vulnerabilities_found: number;
  initiated_by: number | null;
  initiated_by_username: string | null;
  scan_options: any;
  error_message: string | null;
  results_summary: any;
  created_at: Date;
  updated_at: Date;
}

export class ScanRepository {
  /**
   * Get all scans with filtering and pagination
   */
  static async getScans(filters: ScanFilters): Promise<{ scans: ScanResult[]; total: number }> {
    const conditions: string[] = [];
    const params: any[] = [];
    let paramCount = 1;

    if (filters.status) {
      conditions.push(`vs.status = $${paramCount++}`);
      params.push(filters.status);
    }

    if (filters.scan_type) {
      conditions.push(`vs.scan_type = $${paramCount++}`);
      params.push(filters.scan_type);
    }

    // Exclude specific scan types (e.g., exclude 'vulnerability' from asset scans page)
    if (filters.excludeTypes && filters.excludeTypes.length > 0) {
      const placeholders = filters.excludeTypes.map(() => `$${paramCount++}`).join(', ');
      conditions.push(`vs.scan_type NOT IN (${placeholders})`);
      params.push(...filters.excludeTypes);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    // Get total count
    const countQuery = `SELECT COUNT(*) FROM vulnerability_scans vs ${whereClause}`;
    const countResult = await pool.query(countQuery, params);
    const total = parseInt(countResult.rows[0].count);

    // Get paginated results with user info
    // NOTE: Excludes scan_options and results_summary to reduce payload size
    // These large JSONB fields are only included in the detail endpoint
    const query = `
      SELECT
        vs.id,
        vs.scan_type,
        vs.target,
        vs.status,
        vs.started_at,
        vs.completed_at,
        vs.duration_seconds,
        vs.assets_discovered,
        vs.vulnerabilities_found,
        vs.initiated_by,
        vs.error_message,
        vs.created_at,
        vs.updated_at,
        u.username as initiated_by_username
      FROM vulnerability_scans vs
      LEFT JOIN users u ON vs.initiated_by = u.id
      ${whereClause}
      ORDER BY vs.created_at DESC
      LIMIT $${paramCount++} OFFSET $${paramCount}
    `;

    params.push(filters.limit || 50);
    params.push(filters.offset || 0);

    const result = await pool.query(query, params);
    return { scans: result.rows, total };
  }

  /**
   * Get scan by ID with details
   */
  static async getScanById(scanId: number): Promise<ScanResult | null> {
    const query = `
      SELECT
        vs.id,
        vs.scan_type,
        vs.target,
        vs.status,
        vs.started_at,
        vs.completed_at,
        vs.duration_seconds,
        vs.assets_discovered,
        vs.vulnerabilities_found,
        vs.initiated_by,
        vs.scan_options,
        vs.error_message,
        vs.results_summary,
        vs.created_at,
        vs.updated_at,
        u.username as initiated_by_username
      FROM vulnerability_scans vs
      LEFT JOIN users u ON vs.initiated_by = u.id
      WHERE vs.id = $1
    `;

    const result = await pool.query(query, [scanId]);
    return result.rows[0] || null;
  }

  /**
   * Get active scans (queued or running)
   * @param excludeTypes - Optional array of scan_type values to exclude (e.g., ['vulnerability'])
   */
  static async getActiveScans(excludeTypes?: string[]): Promise<ScanResult[]> {
    // NOTE: Excludes scan_options and results_summary to reduce payload size
    let whereClause = `vs.status IN ('queued', 'running')`;
    const params: any[] = [];

    if (excludeTypes && excludeTypes.length > 0) {
      const placeholders = excludeTypes.map((_, i) => `$${i + 1}`).join(', ');
      whereClause += ` AND vs.scan_type NOT IN (${placeholders})`;
      params.push(...excludeTypes);
    }

    const query = `
      SELECT
        vs.id,
        vs.scan_type,
        vs.target,
        vs.status,
        vs.started_at,
        vs.completed_at,
        vs.duration_seconds,
        vs.assets_discovered,
        vs.vulnerabilities_found,
        vs.initiated_by,
        vs.error_message,
        vs.created_at,
        vs.updated_at,
        u.username as initiated_by_username
      FROM vulnerability_scans vs
      LEFT JOIN users u ON vs.initiated_by = u.id
      WHERE ${whereClause}
      ORDER BY vs.created_at DESC
    `;

    const result = await pool.query(query, params);
    return result.rows;
  }

  /**
   * Get recent scans for a specific user
   */
  static async getUserScans(userId: number, limit: number = 20): Promise<ScanResult[]> {
    const query = `
      SELECT
        vs.id,
        vs.scan_type,
        vs.target,
        vs.status,
        vs.started_at,
        vs.completed_at,
        vs.duration_seconds,
        vs.assets_discovered,
        vs.vulnerabilities_found,
        vs.initiated_by,
        vs.scan_options,
        vs.error_message,
        vs.results_summary,
        vs.created_at,
        vs.updated_at,
        u.username as initiated_by_username
      FROM vulnerability_scans vs
      LEFT JOIN users u ON vs.initiated_by = u.id
      WHERE vs.initiated_by = $1
      ORDER BY vs.created_at DESC
      LIMIT $2
    `;

    const result = await pool.query(query, [userId, limit]);
    return result.rows;
  }

  /**
   * Get scan statistics
   */
  static async getStatistics(): Promise<any> {
    const query = `
      SELECT
        COUNT(*) as total_scans,
        COUNT(*) FILTER (WHERE status = 'completed') as completed_scans,
        COUNT(*) FILTER (WHERE status = 'failed') as failed_scans,
        COUNT(*) FILTER (WHERE status IN ('queued', 'running')) as active_scans,
        SUM(assets_discovered) FILTER (WHERE status = 'completed') as total_assets_discovered,
        SUM(vulnerabilities_found) FILTER (WHERE status = 'completed') as total_vulnerabilities_found,
        AVG(duration_seconds) FILTER (WHERE status = 'completed' AND duration_seconds IS NOT NULL) as avg_scan_duration,
        MAX(created_at) as last_scan_time
      FROM vulnerability_scans
    `;

    const result = await pool.query(query);
    return result.rows[0];
  }
}
