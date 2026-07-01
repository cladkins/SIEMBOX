import { query } from '../../config/database';
import { batchedDelete } from '../../utils/batchDelete';

/**
 * Audit log entry interface
 */
export interface AuditLogEntry {
  userId: number;
  action: string;
  resourceType?: string;
  resourceId?: number;
  ipAddress: string;
  userAgent: string;
  requestBody?: any;
  responseStatus: number;
  details?: any;
}

/**
 * Audit log query filters
 */
export interface AuditLogFilters {
  userId?: number;
  action?: string;
  resourceType?: string;
  startDate?: Date;
  endDate?: Date;
  limit?: number;
  offset?: number;
}

/**
 * Audit log with user information
 */
export interface AuditLogWithUser extends AuditLogEntry {
  id: number;
  timestamp: Date;
  username?: string;
  created_at: Date;
}

/**
 * Audit Service for logging security-sensitive operations
 *
 * Logs all scanning operations, credential access, and administrative actions
 * with comprehensive context for security monitoring and compliance.
 */
export class AuditService {
  /**
   * Log a security-sensitive operation
   * Handles errors gracefully to avoid failing the main request
   */
  static async log(entry: AuditLogEntry): Promise<void> {
    try {
      // Redact sensitive fields from request body
      const sanitizedBody = this.redactSensitiveFields(entry.requestBody);

      await query(
        `INSERT INTO audit_logs (
          user_id, action, resource_type, resource_id,
          ip_address, user_agent, request_body, response_status, details
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [
          entry.userId,
          entry.action,
          entry.resourceType || null,
          entry.resourceId || null,
          entry.ipAddress,
          entry.userAgent,
          sanitizedBody ? JSON.stringify(sanitizedBody) : null,
          entry.responseStatus,
          entry.details ? JSON.stringify(entry.details) : null,
        ]
      );
    } catch (error) {
      // Log error but don't throw - audit logging should never break the application
      console.error('Failed to write audit log:', error);
    }
  }

  /**
   * Query audit logs with filters
   * Admin-only access
   */
  static async getAuditLogs(filters: AuditLogFilters): Promise<AuditLogWithUser[]> {
    try {
      const conditions: string[] = [];
      const params: any[] = [];
      let paramIndex = 1;

      // Build WHERE clause
      if (filters.userId) {
        conditions.push(`al.user_id = $${paramIndex++}`);
        params.push(filters.userId);
      }

      if (filters.action) {
        conditions.push(`al.action = $${paramIndex++}`);
        params.push(filters.action);
      }

      if (filters.resourceType) {
        conditions.push(`al.resource_type = $${paramIndex++}`);
        params.push(filters.resourceType);
      }

      if (filters.startDate) {
        conditions.push(`al.timestamp >= $${paramIndex++}`);
        params.push(filters.startDate);
      }

      if (filters.endDate) {
        conditions.push(`al.timestamp <= $${paramIndex++}`);
        params.push(filters.endDate);
      }

      const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

      // Add limit and offset
      const limit = filters.limit || 100;
      const offset = filters.offset || 0;

      params.push(limit, offset);

      const sql = `
        SELECT
          al.id,
          al.timestamp,
          al.user_id as "userId",
          al.action,
          al.resource_type as "resourceType",
          al.resource_id as "resourceId",
          al.ip_address as "ipAddress",
          al.user_agent as "userAgent",
          al.request_body as "requestBody",
          al.response_status as "responseStatus",
          al.details,
          al.created_at,
          u.username
        FROM audit_logs al
        LEFT JOIN users u ON al.user_id = u.id
        ${whereClause}
        ORDER BY al.timestamp DESC
        LIMIT $${paramIndex++} OFFSET $${paramIndex++}
      `;

      const result = await query(sql, params);
      return result.rows;
    } catch (error) {
      console.error('Failed to query audit logs:', error);
      throw error;
    }
  }

  /**
   * Get audit log statistics
   * Admin-only access
   */
  static async getStatistics(startDate?: Date, endDate?: Date): Promise<any> {
    try {
      const conditions: string[] = [];
      const params: any[] = [];
      let paramIndex = 1;

      if (startDate) {
        conditions.push(`timestamp >= $${paramIndex++}`);
        params.push(startDate);
      }

      if (endDate) {
        conditions.push(`timestamp <= $${paramIndex++}`);
        params.push(endDate);
      }

      const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

      const sql = `
        SELECT
          COUNT(*) as total_events,
          COUNT(DISTINCT user_id) as unique_users,
          COUNT(CASE WHEN response_status >= 400 THEN 1 END) as failed_operations,
          COUNT(CASE WHEN action LIKE 'scan.%' THEN 1 END) as scan_operations,
          COUNT(CASE WHEN action LIKE 'credential.%' THEN 1 END) as credential_operations,
          COUNT(CASE WHEN action = 'access.denied' THEN 1 END) as access_denied_count
        FROM audit_logs
        ${whereClause}
      `;

      const result = await query(sql, params);
      return result.rows[0];
    } catch (error) {
      console.error('Failed to get audit statistics:', error);
      throw error;
    }
  }

  /**
   * Get recent activity for a specific user
   */
  static async getUserActivity(userId: number, limit: number = 50): Promise<AuditLogWithUser[]> {
    try {
      const sql = `
        SELECT
          al.id,
          al.timestamp,
          al.user_id as "userId",
          al.action,
          al.resource_type as "resourceType",
          al.resource_id as "resourceId",
          al.ip_address as "ipAddress",
          al.user_agent as "userAgent",
          al.response_status as "responseStatus",
          al.details,
          al.created_at,
          u.username
        FROM audit_logs al
        LEFT JOIN users u ON al.user_id = u.id
        WHERE al.user_id = $1
        ORDER BY al.timestamp DESC
        LIMIT $2
      `;

      const result = await query(sql, [userId, limit]);
      return result.rows;
    } catch (error) {
      console.error('Failed to get user activity:', error);
      throw error;
    }
  }

  /**
   * Get failed access attempts (potential security incidents)
   */
  static async getFailedAccessAttempts(hours: number = 24): Promise<AuditLogWithUser[]> {
    try {
      const sql = `
        SELECT
          al.id,
          al.timestamp,
          al.user_id as "userId",
          al.action,
          al.resource_type as "resourceType",
          al.ip_address as "ipAddress",
          al.details,
          al.created_at,
          u.username
        FROM audit_logs al
        LEFT JOIN users u ON al.user_id = u.id
        WHERE al.action = 'access.denied'
          AND al.timestamp >= NOW() - INTERVAL '${hours} hours'
        ORDER BY al.timestamp DESC
      `;

      const result = await query(sql);
      return result.rows;
    } catch (error) {
      console.error('Failed to get failed access attempts:', error);
      throw error;
    }
  }

  /**
   * Redact sensitive fields from objects before logging
   * Prevents credentials, tokens, and passwords from being stored in audit logs
   */
  private static redactSensitiveFields(obj: any): any {
    if (!obj || typeof obj !== 'object') {
      return obj;
    }

    // Handle arrays
    if (Array.isArray(obj)) {
      return obj.map((item) => this.redactSensitiveFields(item));
    }

    // Clone object to avoid modifying original
    const redacted: any = {};

    // List of sensitive field names (case-insensitive)
    const sensitiveFields = [
      'password',
      'secret',
      'token',
      'api_key',
      'apikey',
      'private_key',
      'privatekey',
      'encrypted_password',
      'credential',
      'credentials',
      'auth',
      'authorization',
      'passphrase',
    ];

    for (const [key, value] of Object.entries(obj)) {
      const lowerKey = key.toLowerCase();

      // Check if field should be redacted
      if (sensitiveFields.some((field) => lowerKey.includes(field))) {
        redacted[key] = '[REDACTED]';
      } else if (typeof value === 'object' && value !== null) {
        // Recursively redact nested objects
        redacted[key] = this.redactSensitiveFields(value);
      } else {
        redacted[key] = value;
      }
    }

    return redacted;
  }

  /**
   * Clean up old audit logs based on retention policy
   * Should be run as a scheduled task
   */
  static async cleanupOldLogs(retentionDays: number = 365): Promise<number> {
    try {
      // Batched + parameterized (was one unbounded, string-interpolated DELETE).
      return await batchedDelete(
        'audit_logs',
        "timestamp < NOW() - INTERVAL '1 day' * $1",
        [retentionDays],
        { label: 'audit retention' }
      );
    } catch (error) {
      console.error('Failed to cleanup old audit logs:', error);
      throw error;
    }
  }
}
