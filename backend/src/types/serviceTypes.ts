/**
 * Service Types
 *
 * Generic interfaces for scanner services and extensibility patterns.
 * Enables pluggable scanner architecture (NMAP, Nuclei, custom scanners).
 */

import type { ScanResult } from './nmapTypes';
import type { ScanType, ScanOptions } from '../models/Scan';

/**
 * Generic scanner interface
 * Contract for all scanner implementations (NMAP, Nuclei, etc.)
 */
export interface Scanner<TConfig = unknown, TResult = unknown> {
  /**
   * Execute a scan with the given configuration
   * @param config - Scanner-specific configuration
   * @returns Promise resolving to scan results
   */
  scan(config: TConfig): Promise<ScanResult<TResult>>;

  /**
   * Validate scanner configuration
   * @param config - Configuration to validate
   * @returns True if configuration is valid
   */
  validateConfig(config: TConfig): boolean;

  /**
   * Get the scanner name/identifier
   * @returns Scanner name (e.g., "nmap", "nuclei")
   */
  getScannerName(): string;

  /**
   * Get supported scan types
   * @returns Array of supported ScanType values
   */
  getSupportedScanTypes(): ScanType[];

  /**
   * Check if the scanner is available and properly configured
   * @returns Promise resolving to availability status
   */
  isAvailable(): Promise<boolean>;

  /**
   * Get scanner version information
   * @returns Promise resolving to version string
   */
  getVersion(): Promise<string>;

  /**
   * Stop a running scan (if supported)
   * @param scanId - ID of the scan to stop
   * @returns Promise resolving to cancellation status
   */
  cancelScan?(scanId: number): Promise<boolean>;
}

/**
 * Scanner registry type
 * Maps scanner names to scanner instances
 */
export type ScannerRegistry = Map<string, Scanner>;

/**
 * Scanner metadata
 * Information about a registered scanner
 */
export interface ScannerMetadata {
  /** Scanner identifier */
  name: string;
  /** Display name */
  displayName: string;
  /** Scanner description */
  description: string;
  /** Scanner version */
  version: string;
  /** Supported scan types */
  supportedTypes: ScanType[];
  /** Whether the scanner is currently available */
  available: boolean;
  /** Additional capabilities */
  capabilities?: {
    /** Supports authenticated scanning */
    supportsAuth?: boolean;
    /** Supports real-time progress updates */
    supportsProgress?: boolean;
    /** Supports scan cancellation */
    supportsCancellation?: boolean;
    /** Supports custom scripts */
    supportsScripts?: boolean;
    /** Additional custom capabilities */
    [key: string]: boolean | undefined;
  };
}

/**
 * Scanner factory interface
 * Creates scanner instances based on scan type
 */
export interface ScannerFactory {
  /**
   * Create a scanner instance for the given scan type
   * @param scanType - Type of scan to perform
   * @param options - Scanner options
   * @returns Scanner instance or null if not supported
   */
  createScanner(scanType: ScanType, options?: ScanOptions): Scanner | null;

  /**
   * Get all registered scanners
   * @returns Array of scanner metadata
   */
  getRegisteredScanners(): ScannerMetadata[];

  /**
   * Register a new scanner
   * @param scanner - Scanner to register
   */
  registerScanner(scanner: Scanner): void;

  /**
   * Unregister a scanner
   * @param scannerName - Name of scanner to unregister
   */
  unregisterScanner(scannerName: string): void;
}

/**
 * Scan event types
 * Events emitted during scan execution
 */
export enum ScanEventType {
  /** Scan started */
  STARTED = 'started',
  /** Scan progress update */
  PROGRESS = 'progress',
  /** Host discovered */
  HOST_DISCOVERED = 'host_discovered',
  /** Service discovered */
  SERVICE_DISCOVERED = 'service_discovered',
  /** Vulnerability found */
  VULNERABILITY_FOUND = 'vulnerability_found',
  /** Scan completed successfully */
  COMPLETED = 'completed',
  /** Scan failed */
  FAILED = 'failed',
  /** Scan cancelled */
  CANCELLED = 'cancelled'
}

/**
 * Scan event
 * Event data emitted during scan execution
 */
export interface ScanEvent {
  /** Event type */
  type: ScanEventType;
  /** Scan ID */
  scanId: number;
  /** Event timestamp */
  timestamp: Date;
  /** Event data (type-specific) */
  data?: unknown;
}

/**
 * Scan event listener
 * Callback for scan events
 */
export type ScanEventListener = (event: ScanEvent) => void;

/**
 * Scanner with event support
 * Extended scanner interface with event emission
 */
export interface EventEmittingScanner<TConfig = unknown, TResult = unknown>
  extends Scanner<TConfig, TResult> {
  /**
   * Register an event listener
   * @param listener - Event listener callback
   */
  on(listener: ScanEventListener): void;

  /**
   * Unregister an event listener
   * @param listener - Event listener callback
   */
  off(listener: ScanEventListener): void;

  /**
   * Emit a scan event
   * @param event - Event to emit
   */
  emit(event: ScanEvent): void;
}

/**
 * Scanner configuration validator
 * Validates scanner-specific configuration
 */
export interface ConfigValidator<TConfig> {
  /**
   * Validate configuration object
   * @param config - Configuration to validate
   * @returns Validation result
   */
  validate(config: TConfig): ValidationResult;
}

/**
 * Validation result
 */
export interface ValidationResult {
  /** Whether validation passed */
  valid: boolean;
  /** Validation errors (if any) */
  errors?: Array<{
    field: string;
    message: string;
  }>;
}

/**
 * Scanner result parser
 * Parses scanner-specific output into common format
 */
export interface ResultParser<TRawResult, TParsedResult> {
  /**
   * Parse raw scanner output
   * @param rawResult - Raw scanner output
   * @returns Parsed result
   */
  parse(rawResult: TRawResult): Promise<TParsedResult>;
}

/**
 * Asset data extracted from scan
 * Common structure for asset discovery results
 */
export interface DiscoveredAsset {
  /** IP address */
  ip_address: string;
  /** Hostname (if resolved) */
  hostname?: string;
  /** MAC address (if discovered) */
  mac_address?: string;
  /** OS type */
  os_type?: string;
  /** OS version */
  os_version?: string;
  /** Discovered services */
  services?: DiscoveredService[];
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Service data extracted from scan
 * Common structure for service discovery results
 */
export interface DiscoveredService {
  /** Port number */
  port: number;
  /** Protocol (tcp, udp, sctp) */
  protocol: string;
  /** Service name */
  service_name?: string;
  /** Service version */
  service_version?: string;
  /** Port state */
  state: string;
  /** Service banner */
  banner?: string;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Vulnerability data extracted from scan
 * Common structure for vulnerability scan results
 */
export interface DiscoveredVulnerability {
  /** CVE identifier */
  cve_id?: string;
  /** Vulnerability title */
  title: string;
  /** Description */
  description?: string;
  /** Severity */
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  /** CVSS score */
  cvss_score?: number;
  /** Affected asset IP */
  asset_ip: string;
  /** Affected service (if applicable) */
  service?: {
    port: number;
    protocol: string;
  };
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Scan result processor
 * Processes scan results and stores them in the database
 */
export interface ScanResultProcessor {
  /**
   * Process discovered assets
   * @param scanId - Scan ID
   * @param assets - Discovered assets
   */
  processAssets(scanId: number, assets: DiscoveredAsset[]): Promise<void>;

  /**
   * Process discovered services
   * @param scanId - Scan ID
   * @param services - Discovered services
   */
  processServices(scanId: number, services: DiscoveredService[]): Promise<void>;

  /**
   * Process discovered vulnerabilities
   * @param scanId - Scan ID
   * @param vulnerabilities - Discovered vulnerabilities
   */
  processVulnerabilities(
    scanId: number,
    vulnerabilities: DiscoveredVulnerability[]
  ): Promise<void>;
}

/**
 * Scanner health check result
 */
export interface ScannerHealthCheck {
  /** Scanner name */
  scanner: string;
  /** Whether the scanner is healthy */
  healthy: boolean;
  /** Scanner version */
  version?: string;
  /** Error message (if unhealthy) */
  error?: string;
  /** Last check timestamp */
  lastChecked: Date;
}

/**
 * Scanner manager interface
 * Manages multiple scanners and their lifecycle
 */
export interface ScannerManager {
  /**
   * Initialize all scanners
   */
  initialize(): Promise<void>;

  /**
   * Shutdown all scanners
   */
  shutdown(): Promise<void>;

  /**
   * Get a scanner by name
   * @param name - Scanner name
   */
  getScanner(name: string): Scanner | null;

  /**
   * Get scanner for scan type
   * @param scanType - Scan type
   */
  getScannerForType(scanType: ScanType): Scanner | null;

  /**
   * Health check for all scanners
   */
  healthCheck(): Promise<ScannerHealthCheck[]>;
}
