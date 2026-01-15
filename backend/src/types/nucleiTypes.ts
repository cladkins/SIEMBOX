/**
 * Nuclei Types
 *
 * Type definitions for Nuclei vulnerability scanner results and configuration.
 * Based on Nuclei JSON output format and CLI options.
 */

/**
 * Nuclei severity levels
 */
export type NucleiSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

/**
 * Nuclei template type
 */
export type NucleiTemplateType =
  | 'http'
  | 'dns'
  | 'tcp'
  | 'ssl'
  | 'file'
  | 'headless'
  | 'network'
  | 'workflow';

/**
 * Nuclei template information
 * Metadata about the template that found a vulnerability
 */
export interface NucleiTemplateInfo {
  /** Template identifier (e.g., "CVE-2021-44228" or "nginx-version-detect") */
  name: string;
  /** Author(s) of the template */
  author?: string | string[];
  /** Tags for categorization */
  tags?: string[];
  /** Template description */
  description?: string;
  /** Severity level */
  severity: NucleiSeverity;
  /** CVE identifier (if applicable) */
  'cve-id'?: string;
  /** CWE identifier (if applicable) */
  'cwe-id'?: string | string[];
  /** CVSS score */
  'cvss-score'?: number;
  /** CVSS metrics string */
  'cvss-metrics'?: string;
  /** External references */
  reference?: string | string[];
  /** Metadata object */
  metadata?: Record<string, unknown>;
  /** Classification */
  classification?: {
    'cvss-metrics'?: string;
    'cvss-score'?: number;
    'cve-id'?: string | string[];
    'cwe-id'?: string | string[];
  };
  /** Remediation guidance */
  remediation?: string;
}

/**
 * Nuclei matcher information
 * Details about what matched in the scan
 */
export interface NucleiMatcher {
  /** Matcher name */
  name?: string;
  /** Matched content */
  matched?: string;
  /** Matcher type (word, regex, status, etc.) */
  type?: string;
}

/**
 * Nuclei extracted values
 * Data extracted from the response
 */
export interface NucleiExtractedData {
  [key: string]: string | string[];
}

/**
 * Nuclei curl command
 * Reconstructed HTTP request for reproduction
 */
export interface NucleiCurlCommand {
  /** Curl command string */
  command?: string;
}

/**
 * Nuclei result
 * Single vulnerability finding from Nuclei
 */
export interface NucleiResult {
  /** Template ID that generated this result */
  'template-id': string;
  /** Template information */
  info: NucleiTemplateInfo;
  /** Template type */
  type: NucleiTemplateType;
  /** Target host */
  host: string;
  /** Matched URL/endpoint */
  'matched-at': string;
  /** Matched IP address */
  ip?: string;
  /** Timestamp of detection */
  timestamp: string;
  /** Matcher information */
  'matcher-name'?: string;
  /** Extracted data */
  'extracted-results'?: string[];
  /** Additional metadata */
  metadata?: Record<string, unknown>;
  /** Curl command for reproduction */
  'curl-command'?: string;
  /** Matcher details */
  matcher?: NucleiMatcher;
  /** Request/Response data */
  request?: string;
  response?: string;
}

/**
 * Nuclei template selection
 * Defines which templates to use for scanning
 */
export interface NucleiTemplateSelection {
  /** Use all templates */
  all?: boolean;
  /** Specific template files or directories */
  templates?: string[];
  /** Template tags to include */
  tags?: string[];
  /** CVE templates only */
  cves?: boolean;
  /** Severity filter */
  severities?: NucleiSeverity[];
  /** Exclude specific templates */
  exclude?: string[];
  /** Exclude specific tags */
  excludeTags?: string[];
}

/**
 * Nuclei scan configuration
 * Configuration for initiating a Nuclei vulnerability scan
 */
export interface NucleiScanConfig {
  /** Target URL or IP address */
  target: string;
  /** Template selection criteria */
  templateSelection: NucleiTemplateSelection;
  /** Scan timeout in milliseconds (default: 30 minutes) */
  timeout?: number;
  /** Maximum concurrent requests */
  rateLimit?: number;
  /** Number of retries for failed requests */
  retries?: number;
  /** Follow HTTP redirects */
  followRedirects?: boolean;
  /** Custom headers */
  headers?: Record<string, string>;
  /** Proxy URL */
  proxy?: string;
  /** User agent string */
  userAgent?: string;
  /** Additional Nuclei flags */
  additionalFlags?: string[];
}

/**
 * Nuclei scan progress
 * Real-time scan progress information
 */
export interface NucleiScanProgress {
  /** Scan ID */
  scanId: number;
  /** Current status */
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
  /** Progress percentage (0-100) */
  progress: number;
  /** Number of templates executed */
  templatesExecuted: number;
  /** Total templates to execute */
  templatesTotal: number;
  /** Vulnerabilities found so far */
  vulnerabilitiesFound: number;
  /** Current target being scanned */
  currentTarget?: string;
  /** Scan start time */
  startedAt?: Date;
  /** Estimated completion time */
  estimatedCompletion?: Date;
}

/**
 * Nuclei scan summary
 * High-level summary of scan results
 */
export interface NucleiScanSummary {
  /** Total templates executed */
  templatesExecuted: number;
  /** Total hosts scanned */
  hostsScanned: number;
  /** Total vulnerabilities found */
  totalVulnerabilities: number;
  /** Vulnerabilities by severity */
  bySeverity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  /** Unique CVEs found */
  uniqueCVEs: number;
  /** Scan duration in seconds */
  durationSeconds: number;
  /** Error count */
  errors: number;
}

/**
 * Processed Nuclei vulnerability
 * Normalized vulnerability data for database storage
 */
export interface ProcessedNucleiVulnerability {
  /** CVE identifier (if available) */
  cveId?: string;
  /** Vulnerability title */
  title: string;
  /** Description */
  description?: string;
  /** Severity level */
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  /** CVSS score */
  cvssScore?: number;
  /** CVSS vector string */
  cvssVector?: string;
  /** Target IP or hostname */
  target: string;
  /** Matched URL/endpoint */
  matchedAt: string;
  /** Template ID that found this */
  templateId: string;
  /** Evidence/proof */
  evidence?: string;
  /** Remediation guidance */
  remediation?: string;
  /** External references */
  references?: string[];
  /** CWE identifier */
  cweId?: string;
  /** Raw Nuclei result */
  rawResult: NucleiResult;
  /** Timestamp of detection */
  detectedAt: Date;
}

/**
 * Nuclei error codes
 */
export enum NucleiErrorCode {
  /** Nuclei binary not found */
  NUCLEI_NOT_FOUND = 'NUCLEI_NOT_FOUND',
  /** Invalid target specification */
  INVALID_TARGET = 'INVALID_TARGET',
  /** Template not found */
  TEMPLATE_NOT_FOUND = 'TEMPLATE_NOT_FOUND',
  /** Scan timeout */
  TIMEOUT = 'TIMEOUT',
  /** Network error */
  NETWORK_ERROR = 'NETWORK_ERROR',
  /** Permission denied */
  PERMISSION_DENIED = 'PERMISSION_DENIED',
  /** Invalid configuration */
  INVALID_CONFIG = 'INVALID_CONFIG',
  /** General error */
  GENERAL_ERROR = 'GENERAL_ERROR',
}

/**
 * Nuclei error
 * Custom error type for Nuclei operations
 */
export class NucleiError extends Error {
  constructor(
    message: string,
    public code: NucleiErrorCode,
    public details?: unknown
  ) {
    super(message);
    this.name = 'NucleiError';
  }
}

/**
 * Nuclei template metadata
 * Information about available templates
 */
export interface NucleiTemplateMetadata {
  /** Template ID */
  id: string;
  /** Template name */
  name: string;
  /** Template path */
  path: string;
  /** Severity */
  severity: NucleiSeverity;
  /** Tags */
  tags: string[];
  /** CVE ID (if applicable) */
  cveId?: string;
  /** Template type */
  type: NucleiTemplateType;
}

/**
 * Nuclei output line
 * Single line of Nuclei output during scanning
 */
export interface NucleiOutputLine {
  /** Output type */
  type: 'result' | 'info' | 'error' | 'warning';
  /** Line content */
  content: string;
  /** Timestamp */
  timestamp: Date;
  /** Parsed result (if type is 'result') */
  result?: NucleiResult;
}
