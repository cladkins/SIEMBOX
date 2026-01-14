/**
 * Asset Discovery & Management Models
 *
 * Defines TypeScript interfaces for discovered network assets,
 * services running on those assets, and related metadata.
 *
 * Type-safe definitions prevent runtime errors and enable IDE autocomplete.
 */

/**
 * Asset type enumeration
 * Categorizes assets by their primary function
 */
export enum AssetType {
  SERVER = 'server',
  WORKSTATION = 'workstation',
  NETWORK = 'network',
  IOT = 'iot',
  MOBILE = 'mobile',
  UNKNOWN = 'unknown'
}

/**
 * Asset criticality levels
 * Used for prioritizing security monitoring and incident response
 */
export enum AssetCriticality {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

/**
 * Asset operational status
 */
export enum AssetStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  OFFLINE = 'offline'
}

/**
 * Asset discovery method
 * Tracks how the asset was initially discovered
 */
export enum DiscoveryMethod {
  NMAP = 'nmap',
  LOG_CORRELATION = 'log_correlation',
  MANUAL = 'manual'
}

/**
 * Asset metadata structure
 * Flexible JSONB field for storing additional asset information
 */
export interface AssetMetadata {
  /** NMAP scan ID that discovered this asset */
  nmap_scan_id?: number;
  /** Number of log entries associated with this asset */
  log_count?: number;
  /** Custom fields defined by administrators */
  custom_fields?: Record<string, unknown>;
  /** Environment (production, staging, development, etc.) */
  environment?: string;
  /** Business owner or department */
  owner?: string;
  /** Compliance tags (PCI-DSS, HIPAA, etc.) */
  compliance_tags?: string[];
  /** Additional flexible fields */
  [key: string]: unknown;
}

/**
 * Base Asset interface
 * Represents a discovered network asset with all database fields
 */
export interface Asset {
  /** Unique identifier */
  id: number;
  /** IPv4 or IPv6 address */
  ip_address: string;
  /** DNS hostname (optional) */
  hostname?: string | null;
  /** MAC address (optional) */
  mac_address?: string | null;
  /** Operating system type (e.g., "Linux", "Windows", "Cisco IOS") */
  os_type?: string | null;
  /** Operating system version */
  os_version?: string | null;
  /** Asset type category */
  asset_type: AssetType;
  /** Business criticality level */
  criticality: AssetCriticality;
  /** Operational status */
  status: AssetStatus;
  /** How this asset was discovered */
  discovery_method: DiscoveryMethod;
  /** When the asset was first seen */
  first_seen: Date;
  /** When the asset was last observed */
  last_seen: Date;
  /** When the asset was last scanned by NMAP */
  last_scanned?: Date | null;
  /** Additional metadata (JSONB) */
  metadata?: AssetMetadata;
  /** Tags for categorization */
  tags?: string[];
  /** Record creation timestamp */
  created_at: Date;
  /** Record update timestamp */
  updated_at: Date;
}

/**
 * Create asset input type
 * Used when creating new assets (omits auto-generated fields)
 */
export type CreateAssetInput = Omit<Asset, 'id' | 'created_at' | 'updated_at' | 'first_seen'> & {
  /** Optional first_seen override (defaults to NOW()) */
  first_seen?: Date;
};

/**
 * Update asset input type
 * Used for partial updates (all fields optional except ID)
 */
export type UpdateAssetInput = Partial<Omit<Asset, 'id' | 'created_at'>>;

/**
 * Network service protocol enumeration
 */
export enum ServiceProtocol {
  TCP = 'tcp',
  UDP = 'udp',
  SCTP = 'sctp'
}

/**
 * Network service state (from NMAP)
 */
export enum ServiceState {
  OPEN = 'open',
  CLOSED = 'closed',
  FILTERED = 'filtered',
  UNFILTERED = 'unfiltered',
  OPEN_FILTERED = 'open|filtered',
  CLOSED_FILTERED = 'closed|filtered'
}

/**
 * Asset Service interface
 * Represents a network service discovered on an asset
 */
export interface AssetService {
  /** Unique identifier */
  id: number;
  /** Associated asset ID */
  asset_id: number;
  /** Service port number (1-65535) */
  port: number;
  /** Network protocol */
  protocol: ServiceProtocol;
  /** Service name (e.g., "http", "ssh", "mysql") */
  service_name?: string | null;
  /** Service version string */
  service_version?: string | null;
  /** Port state from scan */
  state: ServiceState;
  /** Service banner text */
  banner?: string | null;
  /** When the service was first discovered */
  discovered_at: Date;
  /** When the service was last seen */
  last_seen: Date;
  /** Record creation timestamp */
  created_at: Date;
}

/**
 * Create service input type
 */
export type CreateServiceInput = Omit<AssetService, 'id' | 'created_at' | 'discovered_at'> & {
  /** Optional discovered_at override (defaults to NOW()) */
  discovered_at?: Date;
};

/**
 * Asset with services relationship
 * Used when fetching assets with their associated network services
 */
export interface AssetWithServices extends Asset {
  /** List of network services running on this asset */
  services: AssetService[];
}

/**
 * Asset with vulnerabilities relationship
 * Used when fetching assets with their vulnerability scan results
 */
export interface AssetWithVulnerabilities extends Asset {
  /** List of vulnerabilities found on this asset */
  vulnerabilities: AssetVulnerability[];
}

/**
 * Asset with all relationships
 * Used for detailed asset views with complete context
 */
export interface AssetWithRelations extends Asset {
  /** Network services */
  services: AssetService[];
  /** Vulnerabilities */
  vulnerabilities: AssetVulnerability[];
  /** Recent log count (last 24 hours) */
  recent_logs?: number;
}

/**
 * Asset Vulnerability interface
 * Represents a vulnerability found on an asset
 */
export interface AssetVulnerability {
  /** Unique identifier */
  id: number;
  /** Associated asset ID */
  asset_id: number;
  /** CVE identifier (if applicable) */
  cve_id?: string | null;
  /** Vulnerability title */
  title: string;
  /** Detailed description */
  description?: string | null;
  /** Severity level */
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  /** CVSS score (0-10) */
  cvss_score?: number | null;
  /** Vulnerability status */
  status: 'open' | 'acknowledged' | 'mitigated' | 'false_positive';
  /** When the vulnerability was discovered */
  discovered_at: Date;
  /** When the vulnerability was last verified */
  last_verified?: Date | null;
  /** Record creation timestamp */
  created_at: Date;
  /** Record update timestamp */
  updated_at: Date;
}

/**
 * Asset filters for querying
 */
export interface AssetFilters {
  /** Filter by operational status */
  status?: AssetStatus;
  /** Filter by criticality level */
  criticality?: AssetCriticality;
  /** Filter by asset type */
  asset_type?: AssetType;
  /** Filter by discovery method */
  discovery_method?: DiscoveryMethod;
  /** Search IP address or hostname */
  search?: string;
  /** Filter by tags */
  tags?: string[];
  /** Results limit */
  limit?: number;
  /** Results offset for pagination */
  offset?: number;
  /** Sort field */
  sort_by?: 'ip_address' | 'hostname' | 'last_seen' | 'criticality' | 'created_at';
  /** Sort direction */
  sort_order?: 'asc' | 'desc';
}

/**
 * Paginated asset result
 */
export interface PaginatedAssets {
  /** List of assets for this page */
  assets: Asset[];
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
 * Asset summary statistics
 * Used for dashboard metrics
 */
export interface AssetStatistics {
  /** Total number of assets */
  total: number;
  /** Assets by status */
  by_status: Record<AssetStatus, number>;
  /** Assets by criticality */
  by_criticality: Record<AssetCriticality, number>;
  /** Assets by type */
  by_type: Record<AssetType, number>;
  /** Assets discovered in last 24 hours */
  new_last_24h: number;
  /** Assets with open vulnerabilities */
  with_vulnerabilities: number;
}
