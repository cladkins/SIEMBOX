import { body, param, query, validationResult, ValidationChain } from 'express-validator';
import { Request, Response, NextFunction } from 'express';

/**
 * Validation error handler middleware
 * Returns structured validation errors to client
 */
export const handleValidationErrors = (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Validation failed',
      details: errors.array().map((err) => ({
        field: err.type === 'field' ? err.path : 'unknown',
        message: err.msg,
        value: err.type === 'field' ? err.value : undefined,
      })),
    });
  }

  next();
};

/**
 * Validation rules for asset discovery scan requests
 */
export const validateAssetScanRequest: ValidationChain[] = [
  body('targets')
    .isArray({ min: 1, max: 100 })
    .withMessage('Targets must be an array with 1-100 entries'),

  body('targets.*')
    .trim()
    .matches(/^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/)
    .withMessage('Invalid IP address or CIDR notation')
    .custom((value) => {
      // Validate CIDR range
      if (value.includes('/')) {
        const [ip, mask] = value.split('/');
        const maskNum = parseInt(mask, 10);

        // Validate mask
        if (maskNum < 8 || maskNum > 32) {
          throw new Error('CIDR mask must be between 8 and 32');
        }

        // Prevent scanning massive ranges
        if (maskNum < 16) {
          throw new Error('CIDR mask must be /16 or smaller (more specific)');
        }

        // Validate IP octets
        const octets = ip.split('.').map(Number);
        if (octets.some((octet) => octet < 0 || octet > 255)) {
          throw new Error('Invalid IP address octets');
        }
      } else {
        // Validate single IP octets
        const octets = value.split('.').map(Number);
        if (octets.length !== 4 || octets.some((octet) => octet < 0 || octet > 255)) {
          throw new Error('Invalid IP address');
        }
      }

      // Block RFC 1918 and other reserved ranges if configured
      const ip = value.split('/')[0];
      const firstOctet = parseInt(ip.split('.')[0], 10);

      // Block loopback
      if (firstOctet === 127) {
        throw new Error('Cannot scan loopback addresses (127.x.x.x)');
      }

      // Block multicast
      if (firstOctet >= 224 && firstOctet <= 239) {
        throw new Error('Cannot scan multicast addresses (224.x.x.x - 239.x.x.x)');
      }

      return true;
    }),

  body('scanType')
    .optional()
    .isIn(['ping', 'port', 'service', 'os', 'full'])
    .withMessage('Invalid scan type. Must be: ping, port, service, os, or full'),

  body('ports')
    .optional()
    .isString()
    .matches(/^(\d+(-\d+)?,)*(\d+(-\d+)?)$/)
    .withMessage('Invalid port specification. Use format: 80,443,8000-9000'),

  body('timeout')
    .optional()
    .isInt({ min: 1, max: 3600 })
    .withMessage('Timeout must be between 1 and 3600 seconds'),

  body('description').optional().isString().trim().isLength({ max: 500 }).withMessage('Description too long (max 500 characters)'),
];

/**
 * Validation rules for vulnerability scan requests
 */
export const validateVulnScanRequest: ValidationChain[] = [
  body('assetIds')
    .optional()
    .isArray({ min: 1, max: 50 })
    .withMessage('Asset IDs must be an array with 1-50 entries'),

  body('assetIds.*')
    .isInt({ min: 1 })
    .withMessage('Asset ID must be a positive integer'),

  body('targets')
    .optional()
    .isArray({ min: 1, max: 50 })
    .withMessage('Targets must be an array with 1-50 entries'),

  body('targets.*')
    .trim()
    .matches(/^(\d{1,3}\.){3}\d{1,3}$/)
    .withMessage('Invalid IP address (CIDR not supported for vulnerability scans)'),

  body('credentialId')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Credential ID must be a positive integer'),

  body('scanTemplate')
    .optional()
    .isIn(['quick', 'standard', 'thorough', 'compliance'])
    .withMessage('Invalid scan template. Must be: quick, standard, thorough, or compliance'),

  body('vulnerabilityTypes')
    .optional()
    .isArray()
    .withMessage('Vulnerability types must be an array'),

  body('vulnerabilityTypes.*')
    .isIn(['misconfig', 'outdated', 'exposure', 'weakness', 'all'])
    .withMessage('Invalid vulnerability type'),

  body('description')
    .optional()
    .isString()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Description too long (max 500 characters)'),
];

/**
 * Validation rules for credential creation
 */
export const validateCredentialCreation: ValidationChain[] = [
  body('name')
    .trim()
    .notEmpty()
    .withMessage('Credential name is required')
    .isLength({ min: 3, max: 255 })
    .withMessage('Name must be between 3 and 255 characters')
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Name can only contain letters, numbers, underscores, and hyphens'),

  body('credentialType')
    .trim()
    .notEmpty()
    .isIn(['ssh', 'windows', 'snmp', 'http', 'database'])
    .withMessage('Invalid credential type. Must be: ssh, windows, snmp, http, or database'),

  body('username')
    .optional()
    .trim()
    .isLength({ min: 1, max: 255 })
    .withMessage('Username must be between 1 and 255 characters'),

  body('password')
    .optional()
    .isString()
    .isLength({ min: 1, max: 1000 })
    .withMessage('Password must be between 1 and 1000 characters'),

  body('privateKey')
    .optional()
    .isString()
    .custom((value) => {
      // Validate SSH private key format
      if (value && !value.includes('BEGIN') && !value.includes('PRIVATE KEY')) {
        throw new Error('Invalid private key format');
      }
      return true;
    }),

  body('rotationPolicyDays')
    .optional()
    .isInt({ min: 1, max: 365 })
    .withMessage('Rotation policy must be between 1 and 365 days'),
];

/**
 * Validation rules for credential updates
 */
export const validateCredentialUpdate: ValidationChain[] = [
  param('id').isInt({ min: 1 }).withMessage('Invalid credential ID'),

  body('name')
    .optional()
    .trim()
    .isLength({ min: 3, max: 255 })
    .withMessage('Name must be between 3 and 255 characters')
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Name can only contain letters, numbers, underscores, and hyphens'),

  body('username')
    .optional()
    .trim()
    .isLength({ min: 1, max: 255 })
    .withMessage('Username must be between 1 and 255 characters'),

  body('password')
    .optional()
    .isString()
    .isLength({ min: 1, max: 1000 })
    .withMessage('Password must be between 1 and 1000 characters'),

  body('isActive').optional().isBoolean().withMessage('isActive must be a boolean'),

  body('rotationPolicyDays')
    .optional()
    .isInt({ min: 1, max: 365 })
    .withMessage('Rotation policy must be between 1 and 365 days'),
];

/**
 * Validation rules for vulnerability remediation
 */
export const validateVulnRemediation: ValidationChain[] = [
  param('id').isInt({ min: 1 }).withMessage('Invalid vulnerability ID'),

  body('status')
    .trim()
    .isIn(['open', 'confirmed', 'false_positive', 'remediated'])
    .withMessage('Invalid status. Must be: open, confirmed, false_positive, or remediated'),

  body('notes')
    .optional()
    .isString()
    .trim()
    .isLength({ max: 2000 })
    .withMessage('Notes too long (max 2000 characters)'),
];

/**
 * Validation rules for audit log queries
 */
export const validateAuditLogQuery: ValidationChain[] = [
  query('userId').optional().isInt({ min: 1 }).withMessage('User ID must be a positive integer'),

  query('action')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('Action too long (max 100 characters)'),

  query('resourceType')
    .optional()
    .trim()
    .isIn(['asset', 'vulnerability', 'credential', 'scan', 'user', 'config'])
    .withMessage('Invalid resource type'),

  query('startDate')
    .optional()
    .isISO8601()
    .withMessage('Start date must be in ISO 8601 format'),

  query('endDate').optional().isISO8601().withMessage('End date must be in ISO 8601 format'),

  query('limit')
    .optional()
    .isInt({ min: 1, max: 1000 })
    .withMessage('Limit must be between 1 and 1000'),

  query('offset')
    .optional()
    .isInt({ min: 0 })
    .withMessage('Offset must be a non-negative integer'),
];

/**
 * Validation rules for asset updates
 */
export const validateAssetUpdate: ValidationChain[] = [
  param('id').isInt({ min: 1 }).withMessage('Invalid asset ID'),

  body('hostname')
    .optional()
    .trim()
    .isLength({ min: 1, max: 255 })
    .withMessage('Hostname must be between 1 and 255 characters')
    .matches(/^[a-zA-Z0-9.-]+$/)
    .withMessage('Invalid hostname format'),

  body('assetType')
    .optional()
    .trim()
    .isIn(['server', 'workstation', 'network_device', 'iot', 'unknown'])
    .withMessage('Invalid asset type'),

  body('isActive').optional().isBoolean().withMessage('isActive must be a boolean'),
];

/**
 * Custom validator to check if at least one of the specified fields is present
 */
export const requireAtLeastOne = (fields: string[]) => {
  return body().custom((value, { req }) => {
    const hasField = fields.some((field) => req.body[field] !== undefined);
    if (!hasField) {
      throw new Error(`At least one of the following fields is required: ${fields.join(', ')}`);
    }
    return true;
  });
};
