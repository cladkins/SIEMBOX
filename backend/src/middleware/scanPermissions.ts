import { Request, Response, NextFunction } from 'express';
import { ApiError } from './errorHandler';
import { AuditService } from '../services/audit/auditService';

/**
 * Role hierarchy for scanning permissions
 * Viewer < Analyst < Operator < Admin
 */
export enum UserRole {
  Viewer = 'viewer',
  Analyst = 'analyst',
  Operator = 'operator',
  Admin = 'admin',
}

/**
 * Role hierarchy mapping
 * Higher index = higher privileges
 */
const ROLE_HIERARCHY: UserRole[] = [
  UserRole.Viewer,
  UserRole.Analyst,
  UserRole.Operator,
  UserRole.Admin,
];

/**
 * Check if user has required role or higher in hierarchy
 */
function hasRequiredRole(userRole: string, requiredRole: UserRole): boolean {
  const userRoleIndex = ROLE_HIERARCHY.indexOf(userRole as UserRole);
  const requiredRoleIndex = ROLE_HIERARCHY.indexOf(requiredRole);

  if (userRoleIndex === -1) {
    return false; // Invalid role
  }

  return userRoleIndex >= requiredRoleIndex;
}

/**
 * Generic middleware factory for scan permission checking
 * Requires user to have specified role or higher in hierarchy
 */
export const requireScanPermission = (requiredRole: UserRole, resourceType?: string) => {
  return async (req: Request, _res: Response, next: NextFunction) => {
    try {
      // Ensure user is authenticated
      if (!req.user) {
        throw new ApiError(401, 'Authentication required');
      }

      // Check role hierarchy
      if (!hasRequiredRole(req.user.role, requiredRole)) {
        // Log unauthorized access attempt
        await AuditService.log({
          userId: req.user.id,
          action: 'access.denied',
          resourceType: resourceType || 'scan',
          ipAddress: req.ip || req.socket.remoteAddress || 'unknown',
          userAgent: req.headers['user-agent'] || 'unknown',
          responseStatus: 403,
          details: {
            requiredRole,
            userRole: req.user.role,
            path: req.path,
            method: req.method,
          },
        });

        throw new ApiError(
          403,
          `Access denied. Required role: ${requiredRole} or higher. Your role: ${req.user.role}`
        );
      }

      next();
    } catch (error) {
      next(error);
    }
  };
};

/**
 * Require Viewer role (read-only access)
 * - View assets and vulnerabilities
 * - View scan history
 * - No scan initiation
 * - No credential access
 */
export const requireViewer = requireScanPermission(UserRole.Viewer);

/**
 * Require Analyst role (limited scanning)
 * - All Viewer permissions
 * - Trigger asset discovery scans
 * - View scan configurations
 * - No vulnerability scanning (requires credentials)
 * - No credential management
 */
export const requireAssetScanPermission = requireScanPermission(UserRole.Analyst, 'asset_scan');

/**
 * Require Operator role (operational scanning)
 * - All Analyst permissions
 * - Trigger vulnerability scans using pre-configured credentials
 * - Manage scan schedules
 * - Mark vulnerabilities as remediated
 * - No credential creation/modification
 */
export const requireVulnScanPermission = requireScanPermission(UserRole.Operator, 'vuln_scan');

/**
 * Require Admin role (full access)
 * - All permissions
 * - Create/modify scan credentials
 * - Configure scan targets and whitelists
 * - Manage user roles
 * - Access all audit logs
 */
export const requireCredentialPermission = requireScanPermission(UserRole.Admin, 'credential');

/**
 * Require Operator role (can mark vulnerabilities as remediated)
 */
export const requireRemediationPermission = requireScanPermission(
  UserRole.Operator,
  'remediation'
);

/**
 * Middleware to log all scan-related operations
 * Should be applied before permission checks
 */
export const logScanOperation = async (req: Request, _res: Response, next: NextFunction) => {
  try {
    if (req.user) {
      // Determine action from route and method
      let action = 'scan.unknown';
      const path = req.path.toLowerCase();

      if (path.includes('/assets') && req.method === 'POST') {
        action = 'scan.asset.create';
      } else if (path.includes('/vulnerabilities') && req.method === 'POST') {
        action = 'scan.vuln.create';
      } else if (path.includes('/credentials') && req.method === 'GET') {
        action = 'credential.read';
      } else if (path.includes('/credentials') && req.method === 'POST') {
        action = 'credential.create';
      } else if (path.includes('/credentials') && req.method === 'PUT') {
        action = 'credential.update';
      } else if (path.includes('/credentials') && req.method === 'DELETE') {
        action = 'credential.delete';
      }

      // Log the operation attempt (will log result after response)
      req.on('finish', async () => {
        try {
          await AuditService.log({
            userId: req.user!.id,
            action,
            resourceType: extractResourceType(path),
            ipAddress: req.ip || req.socket.remoteAddress || 'unknown',
            userAgent: req.headers['user-agent'] || 'unknown',
            requestBody: redactSensitiveFields(req.body),
            responseStatus: _res.statusCode,
            details: {
              method: req.method,
              path: req.path,
              query: req.query,
            },
          });
        } catch (error) {
          // Don't fail the request if audit logging fails
          console.error('Failed to log scan operation:', error);
        }
      });
    }

    next();
  } catch (error) {
    // Don't fail the request if logging setup fails
    console.error('Failed to setup scan operation logging:', error);
    next();
  }
};

/**
 * Extract resource type from request path
 */
function extractResourceType(path: string): string | undefined {
  if (path.includes('/assets')) return 'asset';
  if (path.includes('/vulnerabilities')) return 'vulnerability';
  if (path.includes('/credentials')) return 'credential';
  if (path.includes('/scans')) return 'scan';
  return undefined;
}

/**
 * Redact sensitive fields from request body for audit logging
 */
function redactSensitiveFields(body: any): any {
  if (!body || typeof body !== 'object') {
    return body;
  }

  const redacted = { ...body };
  const sensitiveFields = [
    'password',
    'secret',
    'token',
    'api_key',
    'private_key',
    'encrypted_password',
    'credential',
  ];

  for (const field of sensitiveFields) {
    if (field in redacted) {
      redacted[field] = '[REDACTED]';
    }
  }

  return redacted;
}
