import rateLimit from 'express-rate-limit';
import { Request } from 'express';

/**
 * Rate limiter for scan operations
 *
 * Prevents abuse of scanning functionality by limiting the number of scans
 * a user can initiate within a time window.
 *
 * Limits:
 * - 10 scans per 15 minutes per user
 * - Different limits for different scan types
 * - Admin users bypass rate limits
 */
export const scanRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 requests per window per user
  standardHeaders: true, // Return rate limit info in `RateLimit-*` headers
  legacyHeaders: false, // Disable `X-RateLimit-*` headers
  skipSuccessfulRequests: false, // Count all requests
  skipFailedRequests: false, // Count all requests including failures

  // Rate limit per user
  keyGenerator: (req: Request) => {
    if (req.user) {
      return `scan_${req.user.id}`;
    }
    // Fallback to IP if no user (shouldn't happen with auth middleware)
    return `scan_ip_${req.ip}`;
  },

  // Skip rate limiting for admin users
  skip: (req: Request) => {
    return req.user?.role === 'admin';
  },

  handler: (_req, res) => {
    res.status(429).json({
      error: 'Too many scan requests',
      message: 'You have exceeded the rate limit of 10 scans per 15 minutes. Please try again later.',
      retryAfter: res.getHeader('Retry-After'),
    });
  },
});

/**
 * Rate limiter for asset discovery scans
 * More lenient than vulnerability scans
 */
export const assetScanRateLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 15, // 15 asset scans per 10 minutes
  standardHeaders: true,
  legacyHeaders: false,

  keyGenerator: (req: Request) => {
    return req.user ? `asset_scan_${req.user.id}` : `asset_scan_ip_${req.ip}`;
  },

  skip: (req: Request) => {
    return req.user?.role === 'admin';
  },

  handler: (_req, res) => {
    res.status(429).json({
      error: 'Too many asset scans',
      message: 'You have exceeded the rate limit of 15 asset scans per 10 minutes. Please try again later.',
      retryAfter: res.getHeader('Retry-After'),
    });
  },
});

/**
 * Rate limiter for vulnerability scans
 * More restrictive due to credential usage and resource intensity
 */
export const vulnScanRateLimiter = rateLimit({
  windowMs: 30 * 60 * 1000, // 30 minutes
  max: 5, // 5 vulnerability scans per 30 minutes
  standardHeaders: true,
  legacyHeaders: false,

  keyGenerator: (req: Request) => {
    return req.user ? `vuln_scan_${req.user.id}` : `vuln_scan_ip_${req.ip}`;
  },

  skip: (req: Request) => {
    return req.user?.role === 'admin';
  },

  handler: (_req, res) => {
    res.status(429).json({
      error: 'Too many vulnerability scans',
      message:
        'You have exceeded the rate limit of 5 vulnerability scans per 30 minutes. Please try again later.',
      retryAfter: res.getHeader('Retry-After'),
    });
  },
});

/**
 * Rate limiter for credential operations
 * Very restrictive to prevent credential harvesting
 */
export const credentialRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20, // 20 credential operations per hour
  standardHeaders: true,
  legacyHeaders: false,

  keyGenerator: (req: Request) => {
    return req.user ? `credential_${req.user.id}` : `credential_ip_${req.ip}`;
  },

  // Even admins are rate limited for credential operations
  skip: () => false,

  handler: (_req, res) => {
    res.status(429).json({
      error: 'Too many credential operations',
      message:
        'You have exceeded the rate limit of 20 credential operations per hour. Please try again later.',
      retryAfter: res.getHeader('Retry-After'),
    });
  },
});

/**
 * Rate limiter for audit log queries
 * Prevent audit log mining
 */
export const auditLogRateLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 30, // 30 audit log queries per 5 minutes
  standardHeaders: true,
  legacyHeaders: false,

  keyGenerator: (req: Request) => {
    return req.user ? `audit_${req.user.id}` : `audit_ip_${req.ip}`;
  },

  skip: (req: Request) => {
    return req.user?.role === 'admin';
  },

  handler: (_req, res) => {
    res.status(429).json({
      error: 'Too many audit log queries',
      message:
        'You have exceeded the rate limit of 30 audit log queries per 5 minutes. Please try again later.',
      retryAfter: res.getHeader('Retry-After'),
    });
  },
});
