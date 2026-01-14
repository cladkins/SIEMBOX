/**
 * Type Guards
 *
 * Runtime type validation functions for TypeScript.
 * Provides type narrowing and validation for API inputs and database results.
 */

import {
  Asset,
  AssetType,
  AssetCriticality,
  AssetStatus,
  DiscoveryMethod,
  ServiceProtocol,
  ServiceState
} from '../models/Asset';
import { ScanType, ScanStatus, NmapScanMode } from '../models/Scan';

// ============================================================================
// Asset Type Guards
// ============================================================================

/**
 * Type guard for Asset interface
 * Validates that an object matches the Asset structure
 */
export function isAsset(obj: unknown): obj is Asset {
  if (typeof obj !== 'object' || obj === null) {
    return false;
  }

  const asset = obj as Partial<Asset>;

  return (
    typeof asset.id === 'number' &&
    typeof asset.ip_address === 'string' &&
    isAssetType(asset.asset_type) &&
    isAssetCriticality(asset.criticality) &&
    isAssetStatus(asset.status) &&
    isDiscoveryMethod(asset.discovery_method) &&
    asset.first_seen instanceof Date &&
    asset.last_seen instanceof Date
  );
}

/**
 * Type guard for AssetType enum
 */
export function isAssetType(value: unknown): value is AssetType {
  return Object.values(AssetType).includes(value as AssetType);
}

/**
 * Type guard for AssetCriticality enum
 */
export function isAssetCriticality(value: unknown): value is AssetCriticality {
  return Object.values(AssetCriticality).includes(value as AssetCriticality);
}

/**
 * Type guard for AssetStatus enum
 */
export function isAssetStatus(value: unknown): value is AssetStatus {
  return Object.values(AssetStatus).includes(value as AssetStatus);
}

/**
 * Type guard for DiscoveryMethod enum
 */
export function isDiscoveryMethod(value: unknown): value is DiscoveryMethod {
  return Object.values(DiscoveryMethod).includes(value as DiscoveryMethod);
}

/**
 * Type guard for ServiceProtocol enum
 */
export function isServiceProtocol(value: unknown): value is ServiceProtocol {
  return Object.values(ServiceProtocol).includes(value as ServiceProtocol);
}

/**
 * Type guard for ServiceState enum
 */
export function isServiceState(value: unknown): value is ServiceState {
  return Object.values(ServiceState).includes(value as ServiceState);
}

// ============================================================================
// Scan Type Guards
// ============================================================================

/**
 * Type guard for ScanType enum
 */
export function isScanType(value: unknown): value is ScanType {
  return Object.values(ScanType).includes(value as ScanType);
}

/**
 * Type guard for ScanStatus enum
 */
export function isScanStatus(value: unknown): value is ScanStatus {
  return Object.values(ScanStatus).includes(value as ScanStatus);
}

/**
 * Type guard for NmapScanMode enum
 */
export function isNmapScanMode(value: unknown): value is NmapScanMode {
  return Object.values(NmapScanMode).includes(value as NmapScanMode);
}

// ============================================================================
// IP Address Validation
// ============================================================================

/**
 * IPv4 address regex
 */
const IPV4_REGEX =
  /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

/**
 * IPv6 address regex (simplified)
 */
const IPV6_REGEX =
  /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;

/**
 * Validates IPv4 address format
 */
export function isValidIPv4Address(ip: string): boolean {
  return IPV4_REGEX.test(ip);
}

/**
 * Validates IPv6 address format
 */
export function isValidIPv6Address(ip: string): boolean {
  return IPV6_REGEX.test(ip);
}

/**
 * Validates IP address (IPv4 or IPv6)
 */
export function isValidIPAddress(ip: string): boolean {
  return isValidIPv4Address(ip) || isValidIPv6Address(ip);
}

/**
 * Validates CIDR notation (IPv4 only)
 */
export function isValidCIDR(cidr: string): boolean {
  const parts = cidr.split('/');
  if (parts.length !== 2) {
    return false;
  }

  const [ip, prefix] = parts;

  // Validate IP part
  if (!isValidIPv4Address(ip)) {
    return false;
  }

  // Validate prefix (0-32)
  const prefixNum = parseInt(prefix, 10);
  return !isNaN(prefixNum) && prefixNum >= 0 && prefixNum <= 32;
}

/**
 * Validates MAC address format
 */
export function isValidMACAddress(mac: string): boolean {
  // Support formats: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
  const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
  return macRegex.test(mac);
}

// ============================================================================
// Port Validation
// ============================================================================

/**
 * Validates port number (1-65535)
 */
export function isValidPort(port: number): boolean {
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

/**
 * Validates port range string (e.g., "80", "80-443", "1-1024")
 */
export function isValidPortRange(portRange: string): boolean {
  // Single port
  if (/^\d+$/.test(portRange)) {
    const port = parseInt(portRange, 10);
    return isValidPort(port);
  }

  // Port range
  if (/^\d+-\d+$/.test(portRange)) {
    const [start, end] = portRange.split('-').map((p) => parseInt(p, 10));
    return isValidPort(start) && isValidPort(end) && start <= end;
  }

  // Comma-separated ports or ranges
  if (portRange.includes(',')) {
    const parts = portRange.split(',');
    return parts.every((part) => isValidPortRange(part.trim()));
  }

  return false;
}

// ============================================================================
// Hostname Validation
// ============================================================================

/**
 * Validates hostname format (RFC 1123)
 */
export function isValidHostname(hostname: string): boolean {
  // Hostname can be 1-253 characters
  if (hostname.length < 1 || hostname.length > 253) {
    return false;
  }

  // Each label can be 1-63 characters
  const labels = hostname.split('.');
  if (labels.some((label) => label.length < 1 || label.length > 63)) {
    return false;
  }

  // Valid hostname regex
  const hostnameRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/;
  return hostnameRegex.test(hostname);
}

// ============================================================================
// Target Validation
// ============================================================================

/**
 * Validates scan target (IP, CIDR, or hostname)
 */
export function isValidScanTarget(target: string): boolean {
  return isValidIPAddress(target) || isValidCIDR(target) || isValidHostname(target);
}

/**
 * Validates multiple scan targets (comma or space separated)
 */
export function isValidScanTargets(targets: string): boolean {
  // Split by comma or space
  const targetList = targets.split(/[,\s]+/).filter((t) => t.length > 0);

  if (targetList.length === 0) {
    return false;
  }

  return targetList.every((target) => isValidScanTarget(target));
}

// ============================================================================
// CVSS Score Validation
// ============================================================================

/**
 * Validates CVSS score (0-10)
 */
export function isValidCVSSScore(score: number): boolean {
  return typeof score === 'number' && score >= 0 && score <= 10;
}

// ============================================================================
// Generic Validation Helpers
// ============================================================================

/**
 * Type guard for non-null values
 */
export function isNotNull<T>(value: T | null | undefined): value is T {
  return value !== null && value !== undefined;
}

/**
 * Type guard for string with minimum length
 */
export function isNonEmptyString(value: unknown, minLength = 1): value is string {
  return typeof value === 'string' && value.length >= minLength;
}

/**
 * Type guard for positive integer
 */
export function isPositiveInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value > 0;
}

/**
 * Type guard for non-negative integer
 */
export function isNonNegativeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0;
}

/**
 * Type guard for array of specific type
 */
export function isArrayOf<T>(
  value: unknown,
  guard: (item: unknown) => item is T
): value is T[] {
  return Array.isArray(value) && value.every(guard);
}

/**
 * Type guard for valid date
 */
export function isValidDate(value: unknown): value is Date {
  return value instanceof Date && !isNaN(value.getTime());
}

/**
 * Type guard for ISO date string
 */
export function isISODateString(value: unknown): boolean {
  if (typeof value !== 'string') {
    return false;
  }

  const date = new Date(value);
  return isValidDate(date) && date.toISOString() === value;
}

// ============================================================================
// Validation Error Helpers
// ============================================================================

/**
 * Validation error class
 */
export class ValidationError extends Error {
  constructor(
    message: string,
    public field?: string,
    public value?: unknown
  ) {
    super(message);
    this.name = 'ValidationError';
  }
}

/**
 * Assert that a value passes a type guard
 * Throws ValidationError if the guard fails
 */
export function assertValid<T>(
  value: unknown,
  guard: (v: unknown) => v is T,
  errorMessage: string,
  field?: string
): asserts value is T {
  if (!guard(value)) {
    throw new ValidationError(errorMessage, field, value);
  }
}

/**
 * Validate required field
 */
export function validateRequired(value: unknown, field: string): void {
  if (value === null || value === undefined) {
    throw new ValidationError(`${field} is required`, field, value);
  }
}

/**
 * Validate enum value
 */
export function validateEnum<T extends string>(
  value: unknown,
  enumObj: Record<string, T>,
  field: string
): asserts value is T {
  const validValues = Object.values(enumObj);
  if (!validValues.includes(value as T)) {
    throw new ValidationError(
      `${field} must be one of: ${validValues.join(', ')}`,
      field,
      value
    );
  }
}
