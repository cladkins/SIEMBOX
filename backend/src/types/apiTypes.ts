/**
 * API Response Types
 *
 * Type-safe API response envelopes and generic response structures.
 * Ensures consistent API response format across all endpoints.
 */

import type { Asset, AssetWithServices, AssetWithRelations, AssetStatistics } from '../models/Asset';
import type {
  VulnerabilityScan,
  ScanWithUser,
  ScanWithResults,
  ScanStatistics
} from '../models/Scan';

/**
 * Generic API response envelope
 * Standard wrapper for all API responses
 */
export interface ApiResponse<T = unknown> {
  /** Whether the request succeeded */
  success: boolean;
  /** Response data (if successful) */
  data?: T;
  /** Error message (if failed) */
  error?: string;
  /** Additional message (optional) */
  message?: string;
  /** Timestamp of the response */
  timestamp?: string;
}

/**
 * Paginated response structure
 * Used for list endpoints with pagination
 */
export interface PaginatedResponse<T> {
  /** Items for this page */
  items: T[];
  /** Total count across all pages */
  total: number;
  /** Items per page */
  limit: number;
  /** Current offset */
  offset: number;
  /** Whether more results exist */
  hasMore: boolean;
  /** Current page number (1-indexed) */
  page?: number;
  /** Total number of pages */
  totalPages?: number;
}

/**
 * Error response structure
 * Detailed error information
 */
export interface ErrorResponse {
  /** Error message */
  error: string;
  /** Error code (for programmatic handling) */
  code?: string;
  /** HTTP status code */
  status?: number;
  /** Detailed error information */
  details?: unknown;
  /** Stack trace (only in development) */
  stack?: string;
  /** Timestamp of the error */
  timestamp: string;
}

/**
 * Validation error structure
 * Used for input validation errors
 */
export interface ValidationError {
  /** Field that failed validation */
  field: string;
  /** Validation error message */
  message: string;
  /** Validation rule that failed */
  rule?: string;
  /** Received value */
  value?: unknown;
}

/**
 * Validation error response
 */
export interface ValidationErrorResponse extends ErrorResponse {
  /** List of validation errors */
  errors: ValidationError[];
}

// ============================================================================
// Asset API Response Types
// ============================================================================

/**
 * Get assets response (paginated list)
 */
export type GetAssetsResponse = ApiResponse<PaginatedResponse<Asset>>;

/**
 * Get single asset response (with services)
 */
export type GetAssetResponse = ApiResponse<AssetWithServices>;

/**
 * Get asset with full relations response
 */
export type GetAssetDetailResponse = ApiResponse<AssetWithRelations>;

/**
 * Create asset response
 */
export type CreateAssetResponse = ApiResponse<Asset>;

/**
 * Update asset response
 */
export type UpdateAssetResponse = ApiResponse<Asset>;

/**
 * Delete asset response
 */
export type DeleteAssetResponse = ApiResponse<{ deleted: boolean; id: number }>;

/**
 * Get asset statistics response
 */
export type GetAssetStatisticsResponse = ApiResponse<AssetStatistics>;

// ============================================================================
// Scan API Response Types
// ============================================================================

/**
 * Trigger scan response
 */
export type TriggerScanResponse = ApiResponse<{
  /** Scan ID */
  scanId: number;
  /** Status message */
  message: string;
  /** Estimated completion time */
  estimatedCompletionTime?: string;
}>;

/**
 * Get single scan response
 */
export type GetScanResponse = ApiResponse<ScanWithUser>;

/**
 * Get scan with results response
 */
export type GetScanDetailResponse = ApiResponse<ScanWithResults>;

/**
 * Get scans response (paginated list)
 */
export type GetScansResponse = ApiResponse<PaginatedResponse<VulnerabilityScan>>;

/**
 * Cancel scan response
 */
export type CancelScanResponse = ApiResponse<{
  /** Scan ID */
  scanId: number;
  /** Whether the scan was cancelled */
  cancelled: boolean;
  /** Status message */
  message: string;
}>;

/**
 * Get scan statistics response
 */
export type GetScanStatisticsResponse = ApiResponse<ScanStatistics>;

// ============================================================================
// Service API Response Types
// ============================================================================

/**
 * Get services for an asset response
 */
export type GetServicesResponse = ApiResponse<
  Array<{
    id: number;
    asset_id: number;
    port: number;
    protocol: string;
    service_name?: string | null;
    service_version?: string | null;
    state: string;
    banner?: string | null;
    discovered_at: Date;
    last_seen: Date;
  }>
>;

// ============================================================================
// Generic CRUD Response Types
// ============================================================================

/**
 * Generic list response
 */
export type ListResponse<T> = ApiResponse<PaginatedResponse<T>>;

/**
 * Generic get response
 */
export type GetResponse<T> = ApiResponse<T>;

/**
 * Generic create response
 */
export type CreateResponse<T> = ApiResponse<T>;

/**
 * Generic update response
 */
export type UpdateResponse<T> = ApiResponse<T>;

/**
 * Generic delete response
 */
export type DeleteResponse = ApiResponse<{ deleted: boolean; id: number }>;

// ============================================================================
// Utility Types
// ============================================================================

/**
 * Extract data type from API response
 */
export type ResponseData<T> = T extends ApiResponse<infer U> ? U : never;

/**
 * Extract paginated items type
 */
export type PaginatedItems<T> = T extends PaginatedResponse<infer U> ? U : never;

/**
 * API error codes
 * Standard error codes for consistent error handling
 */
export enum ApiErrorCode {
  /** Invalid input */
  BAD_REQUEST = 'BAD_REQUEST',
  /** Authentication required */
  UNAUTHORIZED = 'UNAUTHORIZED',
  /** Insufficient permissions */
  FORBIDDEN = 'FORBIDDEN',
  /** Resource not found */
  NOT_FOUND = 'NOT_FOUND',
  /** Validation failed */
  VALIDATION_ERROR = 'VALIDATION_ERROR',
  /** Internal server error */
  INTERNAL_ERROR = 'INTERNAL_ERROR',
  /** Service unavailable */
  SERVICE_UNAVAILABLE = 'SERVICE_UNAVAILABLE',
  /** Rate limit exceeded */
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  /** Conflict (e.g., duplicate resource) */
  CONFLICT = 'CONFLICT',
  /** Request timeout */
  TIMEOUT = 'TIMEOUT'
}

/**
 * Success response helper
 * Creates a successful API response
 */
export function successResponse<T>(data: T, message?: string): ApiResponse<T> {
  return {
    success: true,
    data,
    message,
    timestamp: new Date().toISOString()
  };
}

/**
 * Error response helper
 * Creates an error API response
 */
export function errorResponse(
  error: string,
  _code?: ApiErrorCode,
  _details?: unknown
): ApiResponse<never> {
  return {
    success: false,
    error,
    timestamp: new Date().toISOString()
  };
}

/**
 * Paginated response helper
 * Creates a paginated API response
 */
export function paginatedResponse<T>(
  items: T[],
  total: number,
  limit: number,
  offset: number
): ApiResponse<PaginatedResponse<T>> {
  return successResponse({
    items,
    total,
    limit,
    offset,
    hasMore: offset + items.length < total,
    page: Math.floor(offset / limit) + 1,
    totalPages: Math.ceil(total / limit)
  });
}
