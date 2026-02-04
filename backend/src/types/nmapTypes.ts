/**
 * NMAP Types
 *
 * Type definitions for NMAP scan results and configuration.
 * Based on the node-nmap library and NMAP XML output format.
 */

/**
 * NMAP host status
 */
export type NmapHostStatus = 'up' | 'down' | 'unknown';

/**
 * NMAP port state
 */
export type NmapPortState =
  | 'open'
  | 'closed'
  | 'filtered'
  | 'unfiltered'
  | 'open|filtered'
  | 'closed|filtered';

/**
 * NMAP service information
 * Details about a service running on a port
 */
export interface NmapService {
  /** Service name (e.g., "http", "ssh") */
  name?: string;
  /** Service product (e.g., "Apache httpd", "OpenSSH") */
  product?: string;
  /** Service version */
  version?: string;
  /** Additional information */
  extrainfo?: string;
  /** Operating system family */
  ostype?: string;
  /** Service detection method */
  method?: string;
  /** Service confidence level (0-10) */
  conf?: number;
}

/**
 * NMAP port information
 * Details about a scanned port
 */
export interface NmapPort {
  /** Port number */
  port: number;
  /** Protocol (tcp, udp, sctp) */
  protocol: string;
  /** Port state */
  state: NmapPortState;
  /** Reason for the state */
  reason?: string;
  /** Service information (if detected) */
  service?: NmapService;
  /** Service script results */
  scripts?: Array<{
    id: string;
    output: string;
  }>;
}

/**
 * NMAP OS match
 * Operating system detection result
 */
export interface NmapOSMatch {
  /** OS name */
  name: string;
  /** Match accuracy (0-100) */
  accuracy: number;
  /** Line number in OS database */
  line?: number;
}

/**
 * NMAP OS class
 * Operating system classification
 */
export interface NmapOSClass {
  /** Device type (general-purpose, router, switch, etc.) */
  type: string;
  /** Vendor name */
  vendor: string;
  /** OS family (Linux, Windows, Cisco IOS, etc.) */
  osfamily: string;
  /** OS generation */
  osgen?: string;
  /** Classification accuracy (0-100) */
  accuracy: number;
}

/**
 * NMAP OS detection result
 */
export interface NmapOS {
  /** List of OS matches */
  osmatch?: NmapOSMatch[];
  /** List of OS classifications */
  osclass?: NmapOSClass[];
  /** TCP/IP fingerprint */
  fingerprint?: string;
}

/**
 * NMAP host information
 * Complete information about a scanned host
 */
export interface NmapHost {
  /** IP address */
  ip: string;
  /** Hostname (from DNS or reverse lookup) */
  hostname?: string;
  /** MAC address */
  mac?: string;
  /** MAC vendor */
  vendor?: string;
  /** Host status */
  status: NmapHostStatus;
  /** List of open/closed/filtered ports */
  ports?: NmapPort[];
  /** Operating system detection results */
  os?: NmapOS;
  /** Host uptime (if detected) */
  uptime?: {
    seconds: number;
    lastboot?: string;
  };
  /** Host script results */
  hostscripts?: Array<{
    id: string;
    output: string;
  }>;
  /** Distance (hops) to target */
  distance?: number;
}

/**
 * NMAP scan statistics
 * Overall scan metadata and statistics
 */
export interface NmapScanStats {
  /** When the scan started */
  timestr: string;
  /** Scan start timestamp (Unix epoch) */
  elapsed: number;
  /** Summary of scan results */
  summary: string;
  /** Exit status */
  exit: string;
}

/**
 * NMAP scan result
 * Complete result from an NMAP scan
 */
export interface NmapScanResult {
  /** NMAP command that was executed */
  command?: string;
  /** NMAP version */
  version?: string;
  /** Scan arguments */
  args?: string;
  /** Scan start time */
  startstr?: string;
  /** List of scanned hosts */
  hosts: NmapHost[];
  /** Overall scan statistics */
  runstats?: NmapScanStats;
  /** Any warnings or errors */
  warnings?: string[];
}

/**
 * NMAP scan configuration
 * Configuration for initiating an NMAP scan
 */
export interface NmapScanConfig {
  /** Target hosts/networks (array of IPs, hostnames, or CIDR blocks) */
  targets: string[];
  /** NMAP flags (e.g., "-sS -sV -O -T4") */
  flags: string;
  /** Scan timeout in milliseconds */
  timeout?: number;
  /** Whether to scan UDP ports */
  udp?: boolean;
  /** Custom DNS servers */
  dns?: string[];
  /** Network interface to use */
  interface?: string;
  /** Source port for scanning */
  source_port?: number;
  /** Data directory for NMAP scripts and databases */
  datadir?: string;
}

/**
 * Generic scan result wrapper
 * Used to wrap scan results with success/error status
 */
export interface ScanResult<T = unknown> {
  /** Whether the scan succeeded */
  success: boolean;
  /** Scan result data (if successful) */
  data?: T;
  /** Error message (if failed) */
  error?: string;
  /** Additional metadata */
  metadata?: {
    /** Scan start time */
    started_at?: Date;
    /** Scan end time */
    completed_at?: Date;
    /** Duration in seconds */
    duration_seconds?: number;
    /** Command executed */
    command?: string;
    /** Additional flexible fields */
    [key: string]: unknown;
  };
}

/**
 * NMAP error types
 * Common error codes from NMAP
 */
export enum NmapErrorCode {
  /** Target not found or unreachable */
  TARGET_NOT_FOUND = 'TARGET_NOT_FOUND',
  /** Permission denied (needs root/sudo) */
  PERMISSION_DENIED = 'PERMISSION_DENIED',
  /** Invalid target specification */
  INVALID_TARGET = 'INVALID_TARGET',
  /** Scan timeout */
  TIMEOUT = 'TIMEOUT',
  /** NMAP binary not found */
  NMAP_NOT_FOUND = 'NMAP_NOT_FOUND',
  /** Invalid flags or options */
  INVALID_OPTIONS = 'INVALID_OPTIONS',
  /** General error */
  GENERAL_ERROR = 'GENERAL_ERROR'
}

/**
 * NMAP error
 * Custom error type for NMAP operations
 */
export class NmapError extends Error {
  constructor(
    message: string,
    public code: NmapErrorCode,
    public details?: unknown
  ) {
    super(message);
    this.name = 'NmapError';
  }
}

/**
 * Parsed NMAP output line
 * Used during real-time scan progress parsing
 */
export interface NmapOutputLine {
  /** Output line type */
  type: 'info' | 'warning' | 'error' | 'progress';
  /** Line content */
  content: string;
  /** Timestamp */
  timestamp: Date;
}

/**
 * NMAP scan progress
 * Real-time scan progress information
 */
export interface NmapScanProgress {
  /** Scan ID */
  scan_id: number;
  /** Current status */
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled' | 'timeout';
  /** Progress percentage (0-100) */
  progress: number;
  /** Current host being scanned */
  current_host?: string;
  /** Hosts completed */
  hosts_completed: number;
  /** Total hosts to scan */
  hosts_total: number;
  /** Output lines */
  output?: NmapOutputLine[];
}
