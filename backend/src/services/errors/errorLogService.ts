/**
 * Error Log Service
 *
 * Provides error logging to database and human-readable error translation
 * for the admin dashboard.
 */

import { query } from '../../config/database';
import { logger } from '../../utils/logger';
import { batchedDelete } from '../../utils/batchDelete';

// Throttle for background/async errors (scans, jobs, syslog, engines) so a
// high-frequency failure cannot flood the application_errors table.
const recentBackgroundErrors = new Map<string, number>();
const BACKGROUND_ERROR_TTL_MS = 60_000;

interface ErrorContext {
  endpoint?: string;
  method?: string;
  userId?: number;
  requestBody?: any;
  stack?: string;
  [key: string]: any;
}

interface LoggedError {
  id: number;
  timestamp: string;
  error_type: string;
  message: string;
  human_message: string;
  category: string;
  severity: string;
  user_id: number | null;
  endpoint: string | null;
  context: any;
  resolution?: string;
}

interface ErrorSummary {
  total: number;
  byCategory: Record<string, number>;
  bySeverity: Record<string, number>;
}

// Error translation mappings for common error types
const ERROR_TRANSLATIONS: Record<string, { human: string; category: string; resolution: string }> = {
  // Database errors
  'ECONNREFUSED': {
    human: 'Database connection refused',
    category: 'database',
    resolution: 'Check PostgreSQL is running and accepting connections',
  },
  'ETIMEDOUT': {
    human: 'Database connection timed out',
    category: 'database',
    resolution: 'Check database server load and network connectivity',
  },
  '23505': {
    human: 'Duplicate entry already exists',
    category: 'database',
    resolution: 'Check for existing records before creating new ones',
  },
  '23503': {
    human: 'Referenced record does not exist',
    category: 'database',
    resolution: 'Ensure all foreign key references are valid',
  },
  '42P01': {
    human: 'Database table does not exist',
    category: 'database',
    resolution: 'Run database migrations to create missing tables',
  },
  'ENOTFOUND': {
    human: 'Database host not found',
    category: 'database',
    resolution: 'Check database hostname configuration',
  },

  // Authentication errors
  'JsonWebTokenError': {
    human: 'Invalid authentication token',
    category: 'auth',
    resolution: 'User needs to log in again',
  },
  'TokenExpiredError': {
    human: 'Authentication session expired',
    category: 'auth',
    resolution: 'User needs to log in again',
  },
  'NotBeforeError': {
    human: 'Token not yet valid',
    category: 'auth',
    resolution: 'Check server time synchronization',
  },

  // Network errors
  'ECONNRESET': {
    human: 'Network connection was reset',
    category: 'network',
    resolution: 'Check network stability and retry the request',
  },
  'EPIPE': {
    human: 'Network connection closed unexpectedly',
    category: 'network',
    resolution: 'Check for client disconnections or timeouts',
  },
  'EADDRINUSE': {
    human: 'Port already in use',
    category: 'network',
    resolution: 'Stop conflicting service or use a different port',
  },

  // Scanner errors
  'ENOENT_nuclei': {
    human: 'Nuclei scanner not installed',
    category: 'scanner',
    resolution: 'Install Nuclei: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
  },
  'ENOENT_nmap': {
    human: 'Nmap scanner not installed',
    category: 'scanner',
    resolution: 'Install Nmap: apt-get install nmap',
  },
  'TEMPLATES_NOT_FOUND': {
    human: 'Nuclei templates not found',
    category: 'scanner',
    resolution: 'Download templates from the Templates page in the UI',
  },

  // Parser errors
  'INVALID_REGEX': {
    human: 'Invalid regular expression pattern',
    category: 'parser',
    resolution: 'Review and fix the parser pattern syntax',
  },
  'GROK_PATTERN_ERROR': {
    human: 'Invalid grok pattern',
    category: 'parser',
    resolution: 'Check grok pattern syntax and field mappings',
  },
};

export class ErrorLogService {
  /**
   * Log an error to the database
   */
  static async logError(
    error: Error | string,
    context: ErrorContext = {}
  ): Promise<number | null> {
    try {
      const errorType = error instanceof Error
        ? error.name || error.constructor.name
        : 'UnknownError';

      const message = error instanceof Error
        ? error.message
        : String(error);

      const stack = error instanceof Error ? error.stack : undefined;

      // Translate the error to human-readable form
      const translation = this.translateError(errorType, message);

      const result = await query(
        `INSERT INTO application_errors
         (error_type, message, human_message, category, severity, user_id, endpoint, context)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING id`,
        [
          errorType,
          message,
          translation.human,
          translation.category,
          translation.severity,
          context.userId || null,
          context.endpoint || null,
          JSON.stringify({
            ...context,
            stack: stack?.split('\n').slice(0, 10), // Limit stack trace
          }),
        ]
      );

      return result.rows[0]?.id || null;
    } catch (logError) {
      // Don't let logging errors break the application
      logger.error('Failed to log error to database:', logError);
      return null;
    }
  }

  /**
   * Log a background/async error (scans, jobs, syslog, engines) to the
   * dashboard's error log. Throttled per source + dedupeKey so high-frequency
   * paths cannot flood the table. Fire-and-forget — never throws.
   */
  static logBackgroundError(
    source: string,
    error: unknown,
    context: ErrorContext & { dedupeKey?: string } = {}
  ): void {
    const errObj =
      error instanceof Error
        ? error
        : new Error(typeof error === 'string' ? error : String(error));

    const { dedupeKey, ...rest } = context;
    const key = `${source}:${dedupeKey ?? errObj.message}`;
    const now = Date.now();
    const last = recentBackgroundErrors.get(key);
    if (last && now - last < BACKGROUND_ERROR_TTL_MS) {
      return;
    }
    if (recentBackgroundErrors.size > 1000) {
      recentBackgroundErrors.clear();
    }
    recentBackgroundErrors.set(key, now);

    void this.logError(errObj, {
      ...rest,
      source,
      endpoint: rest.endpoint ?? `background:${source}`,
    }).catch(() => {
      // Never let logging break background work
    });
  }

  /**
   * Translate a technical error to a human-readable message
   */
  static translateError(
    errorType: string,
    message: string
  ): { human: string; category: string; severity: string; resolution: string } {
    // Check for direct match in translations
    if (ERROR_TRANSLATIONS[errorType]) {
      return {
        ...ERROR_TRANSLATIONS[errorType],
        severity: 'error',
      };
    }

    // Check for error codes in message (e.g., PostgreSQL codes)
    for (const [code, translation] of Object.entries(ERROR_TRANSLATIONS)) {
      if (message.includes(code)) {
        return {
          ...translation,
          severity: 'error',
        };
      }
    }

    // Categorize by common patterns in message
    const lowerMessage = message.toLowerCase();

    if (lowerMessage.includes('password') || lowerMessage.includes('authentication')) {
      return {
        human: 'Authentication error',
        category: 'auth',
        severity: 'warning',
        resolution: 'Check credentials and authentication configuration',
      };
    }

    if (lowerMessage.includes('permission') || lowerMessage.includes('forbidden') || lowerMessage.includes('unauthorized')) {
      return {
        human: 'Access denied',
        category: 'auth',
        severity: 'warning',
        resolution: 'User does not have required permissions',
      };
    }

    if (lowerMessage.includes('database') || lowerMessage.includes('postgres') || lowerMessage.includes('sql')) {
      return {
        human: 'Database operation failed',
        category: 'database',
        severity: 'error',
        resolution: 'Check database connection and query syntax',
      };
    }

    if (lowerMessage.includes('timeout')) {
      return {
        human: 'Operation timed out',
        category: 'network',
        severity: 'warning',
        resolution: 'Check network connectivity and server responsiveness',
      };
    }

    if (lowerMessage.includes('not found') || lowerMessage.includes('404')) {
      return {
        human: 'Resource not found',
        category: 'application',
        severity: 'info',
        resolution: 'Verify the requested resource exists',
      };
    }

    if (lowerMessage.includes('scan') || lowerMessage.includes('nuclei') || lowerMessage.includes('nmap')) {
      return {
        human: 'Scan operation failed',
        category: 'scanner',
        severity: 'error',
        resolution: 'Check scanner installation and target accessibility',
      };
    }

    if (lowerMessage.includes('parse') || lowerMessage.includes('regex') || lowerMessage.includes('pattern')) {
      return {
        human: 'Parsing error',
        category: 'parser',
        severity: 'warning',
        resolution: 'Check parser configuration and log format',
      };
    }

    // Default fallback
    return {
      human: message.length > 100 ? message.substring(0, 100) + '...' : message,
      category: 'application',
      severity: 'error',
      resolution: 'Review application logs for more details',
    };
  }

  /**
   * Get recent errors with pagination
   */
  static async getRecentErrors(
    hours: number = 24,
    limit: number = 50,
    offset: number = 0
  ): Promise<{ errors: LoggedError[]; summary: ErrorSummary }> {
    try {
      // Get errors within time window
      const errorsResult = await query(
        `SELECT
           id, timestamp, error_type, message, human_message,
           category, severity, user_id, endpoint, context
         FROM application_errors
         WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
         ORDER BY timestamp DESC
         LIMIT $2 OFFSET $3`,
        [hours, limit, offset]
      );

      // Get summary counts
      const summaryResult = await query(
        `SELECT
           COUNT(*) as total,
           category,
           severity
         FROM application_errors
         WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
         GROUP BY category, severity`,
        [hours]
      );

      // Build summary
      const summary: ErrorSummary = {
        total: 0,
        byCategory: {},
        bySeverity: {},
      };

      for (const row of summaryResult.rows) {
        const count = parseInt(row.count, 10);
        summary.total += count;

        if (row.category) {
          summary.byCategory[row.category] = (summary.byCategory[row.category] || 0) + count;
        }

        if (row.severity) {
          summary.bySeverity[row.severity] = (summary.bySeverity[row.severity] || 0) + count;
        }
      }

      // Add resolution hints to errors
      const errors: LoggedError[] = errorsResult.rows.map((row: any) => {
        const translation = this.translateError(row.error_type, row.message);
        return {
          ...row,
          resolution: translation.resolution,
        };
      });

      return { errors, summary };
    } catch (error) {
      logger.error('Failed to get recent errors:', error);
      return {
        errors: [],
        summary: { total: 0, byCategory: {}, bySeverity: {} },
      };
    }
  }

  /**
   * Get error count for quick health check
   */
  static async getErrorCount(hours: number = 1): Promise<number> {
    try {
      const result = await query(
        `SELECT COUNT(*) as count
         FROM application_errors
         WHERE timestamp > NOW() - INTERVAL '1 hour' * $1`,
        [hours]
      );
      return parseInt(result.rows[0]?.count || '0', 10);
    } catch (error) {
      logger.error('Failed to get error count:', error);
      return 0;
    }
  }

  /**
   * Clean up old errors based on retention period
   */
  static async cleanupOldErrors(retentionDays: number = 30): Promise<number> {
    try {
      // Batched (was one unbounded DELETE ... RETURNING id that materialized
      // every deleted row into memory).
      return await batchedDelete(
        'application_errors',
        "timestamp < NOW() - INTERVAL '1 day' * $1",
        [retentionDays],
        { label: 'error-log retention' }
      );
    } catch (error) {
      logger.error('Failed to cleanup old errors:', error);
      return 0;
    }
  }
}
