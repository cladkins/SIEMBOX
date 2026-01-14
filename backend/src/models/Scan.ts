/**
 * Scan Model
 *
 * Type definitions for vulnerability and asset discovery scans.
 * Supports NMAP scans and future vulnerability scanners (Nuclei, etc.).
 */

/**
 * Scan type enumeration
 */
export enum ScanType {
  ASSET_DISCOVERY = 'asset_discovery',
  VULNERABILITY = 'vulnerability',
  PORT_SCAN = 'port_scan',
  SERVICE_DETECTION = 'service_detection',
  OS_DETECTION = 'os_detection'
}

/**
 * Scan status enumeration
 */
export enum ScanStatus {
  QUEUED = 'queued',
  RUNNING = 'running',
  COMPLETED = 'completed',
  FAILED = 'failed',
  CANCELLED = 'cancelled',
  TIMEOUT = 'timeout'
}

/**
 * NMAP scan mode enumeration
 * Maps to specific NMAP command flags
 */
export enum NmapScanMode {
  /** Ping scan only (-sn) */
  PING = 'ping',
  /** Port scan (-sS, -sT) */
  PORT = 'port',
  /** Service version detection (-sV) */
  SERVICE = 'service',
  /** OS detection (-O) */
  OS = 'os',
  /** Aggressive scan (-A) */
  AGGRESSIVE = 'aggressive',
  /** Quick scan (-F) */
  QUICK = 'quick'
}

/**
 * NMAP timing template enumeration
 */
export type NmapTiming = 'T0' | 'T1' | 'T2' | 'T3' | 'T4' | 'T5';

/**
 * Scan options (flexible JSONB)
 * Used to configure scan behavior and NMAP flags
 */
export interface ScanOptions {
  /** NMAP scan mode */
  scan_mode?: NmapScanMode;
  /** Target hosts/networks (CIDR notation supported) */
  targets?: string[];
  /** Port specification (e.g., "80,443,8080-8090" or "1-65535") */
  ports?: string;
  /** NMAP timing template (T0=paranoid, T5=insane) */
  timing?: NmapTiming;
  /** Additional NMAP flags */
  additional_flags?: string[];
  /** Scan timeout in seconds */
  timeout?: number;
  /** Whether to perform service version detection */
  version_detection?: boolean;
  /** Whether to perform OS detection */
  os_detection?: boolean;
  /** Whether to scan UDP ports */
  udp_scan?: boolean;
  /** Whether to skip host discovery (assume all hosts are up) */
  skip_host_discovery?: boolean;
  /** Custom DNS servers */
  dns_servers?: string[];
  /** Additional flexible fields */
  [key: string]: unknown;
}

/**
 * Scan results summary (flexible JSONB)
 * Stores high-level scan statistics
 */
export interface ScanResultsSummary {
  /** Number of hosts that responded */
  hosts_up: number;
  /** Number of hosts that did not respond */
  hosts_down: number;
  /** Total ports scanned */
  ports_scanned: number;
  /** Number of services identified */
  services_identified: number;
  /** Number of open ports found */
  open_ports?: number;
  /** Number of filtered ports */
  filtered_ports?: number;
  /** Number of new assets discovered */
  new_assets?: number;
  /** Number of existing assets updated */
  updated_assets?: number;
  /** Additional flexible fields */
  [key: string]: unknown;
}

/**
 * Vulnerability Scan interface
 * Represents a scan operation (NMAP, Nuclei, etc.)
 */
export interface VulnerabilityScan {
  /** Unique identifier */
  id: number;
  /** Type of scan performed */
  scan_type: ScanType;
  /** Target specification (IP, CIDR, hostname) */
  target: string;
  /** Current scan status */
  status: ScanStatus;
  /** When the scan started */
  started_at?: Date | null;
  /** When the scan completed */
  completed_at?: Date | null;
  /** Scan duration in seconds */
  duration_seconds?: number | null;
  /** Number of assets discovered */
  assets_discovered: number;
  /** Number of vulnerabilities found */
  vulnerabilities_found: number;
  /** SSH/credential ID for authenticated scans */
  credential_id?: number | null;
  /** User who initiated the scan */
  initiated_by?: number | null;
  /** Scan configuration options (JSONB) */
  scan_options?: ScanOptions;
  /** Error message if scan failed */
  error_message?: string | null;
  /** High-level scan results (JSONB) */
  results_summary?: ScanResultsSummary;
  /** Record creation timestamp */
  created_at: Date;
  /** Record update timestamp */
  updated_at: Date;
}

/**
 * Create scan input type
 * Used when queuing a new scan
 */
export type CreateScanInput = {
  /** Type of scan to perform */
  scan_type: ScanType;
  /** Target(s) to scan */
  target: string;
  /** User initiating the scan */
  initiated_by?: number;
  /** Scan configuration */
  scan_options?: ScanOptions;
  /** Optional credential for authenticated scans */
  credential_id?: number;
};

/**
 * Update scan input type
 * Used to update scan progress and results
 */
export type UpdateScanInput = Partial<
  Pick<
    VulnerabilityScan,
    | 'status'
    | 'started_at'
    | 'completed_at'
    | 'duration_seconds'
    | 'assets_discovered'
    | 'vulnerabilities_found'
    | 'error_message'
    | 'results_summary'
  >
>;

/**
 * Scan with user details
 * Used when displaying scans with initiator information
 */
export interface ScanWithUser extends VulnerabilityScan {
  /** User who initiated the scan */
  user?: {
    id: number;
    username: string;
    email?: string;
  };
}

/**
 * Scan with detailed results
 * Used when displaying scan with discovered assets and services
 */
export interface ScanWithResults extends VulnerabilityScan {
  /** Assets discovered or updated by this scan */
  assets?: Array<{
    id: number;
    ip_address: string;
    hostname?: string | null;
    asset_type: string;
  }>;
  /** Services discovered by this scan */
  services?: Array<{
    id: number;
    asset_id: number;
    port: number;
    protocol: string;
    service_name?: string | null;
  }>;
}

/**
 * Scan filters for querying
 */
export interface ScanFilters {
  /** Filter by scan status */
  status?: ScanStatus;
  /** Filter by scan type */
  scan_type?: ScanType;
  /** Filter by initiating user */
  initiated_by?: number;
  /** Filter scans starting after this date */
  date_from?: Date;
  /** Filter scans starting before this date */
  date_to?: Date;
  /** Filter by target (partial match) */
  target?: string;
  /** Results limit */
  limit?: number;
  /** Results offset for pagination */
  offset?: number;
  /** Sort field */
  sort_by?: 'created_at' | 'started_at' | 'completed_at' | 'status';
  /** Sort direction */
  sort_order?: 'asc' | 'desc';
}

/**
 * Paginated scan results
 */
export interface PaginatedScans {
  /** List of scans for this page */
  scans: VulnerabilityScan[];
  /** Total count across all pages */
  total: number;
  /** Items per page */
  limit: number;
  /** Current offset */
  offset: number;
  /** Whether more results exist */
  hasMore: boolean;
}

/**
 * Scan statistics
 * Used for dashboard metrics
 */
export interface ScanStatistics {
  /** Total scans performed */
  total: number;
  /** Scans by status */
  by_status: Record<ScanStatus, number>;
  /** Scans by type */
  by_type: Record<ScanType, number>;
  /** Scans completed in last 24 hours */
  last_24h: number;
  /** Average scan duration in seconds */
  avg_duration_seconds: number;
  /** Total assets discovered across all scans */
  total_assets_discovered: number;
  /** Total vulnerabilities found across all scans */
  total_vulnerabilities_found: number;
}

/**
 * Scan credential interface
 * Stores credentials for authenticated scans
 */
export interface ScanCredential {
  /** Unique identifier */
  id: number;
  /** Credential name */
  name: string;
  /** Credential type (ssh, snmp, etc.) */
  type: 'ssh' | 'snmp' | 'wmi' | 'http';
  /** Username for authentication */
  username?: string | null;
  /** Encrypted password or key */
  password_encrypted?: string | null;
  /** SSH private key (encrypted) */
  ssh_key_encrypted?: string | null;
  /** Additional credential metadata */
  metadata?: Record<string, unknown>;
  /** Record creation timestamp */
  created_at: Date;
  /** Record update timestamp */
  updated_at: Date;
}

/**
 * Create credential input type
 */
export type CreateCredentialInput = Omit<ScanCredential, 'id' | 'created_at' | 'updated_at'>;
