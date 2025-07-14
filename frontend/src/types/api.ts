// Base API response types
export interface ApiResponse<T> {
  data: T;
  message?: string;
  status: 'success' | 'error';
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

// Authentication types
export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

export interface User {
  id: number;
  username: string;
  email: string;
  is_active: boolean;
  is_superuser: boolean;
  created_at: string;
  updated_at: string;
}

// Log types
export interface RawLog {
  id: number;
  timestamp: string;
  source_ip: string;
  source_type: string;
  raw_message: string;
  created_at: string;
}

export interface ParsedLog {
  id: number;
  raw_log_id: number;
  timestamp: string;
  source_ip: string;
  source_type: string;
  log_level: string;
  message: string;
  parsed_fields: Record<string, string | number | boolean | null>;
  created_at: string;
  raw_log?: RawLog;
}

// Detection Rule types
export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  rule_type: 'threshold' | 'pattern' | 'correlation' | 'anomaly';
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  conditions: Record<string, string | number | boolean>;
  is_enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateDetectionRuleRequest {
  name: string;
  description: string;
  rule_type: 'threshold' | 'pattern' | 'correlation' | 'anomaly';
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  conditions: Record<string, string | number | boolean | string[]>;
  is_enabled?: boolean;
}

export interface DetectionStats {
  rules: {
    total: number;
    enabled: number;
    disabled: number;
  };
  alerts: {
    total: number;
    open: number;
    recent_24h: number;
  };
  severity_distribution: Record<string, number>;
  category_distribution: Record<string, number>;
}

export interface DetectionTestResult {
  success: boolean;
  alerts_generated: number;
  rules_applied: number;
  errors: string[];
}

// Alert types
export interface Alert {
  id: string;
  parsed_log_id: string;
  detection_rule_id: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  status: 'open' | 'investigating' | 'resolved' | 'false_positive';
  alert_data: Record<string, string | number | boolean | object | null>;
  triggered_at: string;
  updated_at: string;
  resolved_at?: string;
  notifications_sent?: Record<string, string | number | boolean | object | null>;
  rule?: DetectionRule;
  log?: ParsedLog;
}

export interface UpdateAlertRequest {
  status?: 'open' | 'investigating' | 'resolved' | 'false_positive';
  description?: string;
  alert_data?: Record<string, string | number | boolean | object | null>;
}

export interface AlertStats {
  total_alerts: number;
  status_distribution: {
    open: number;
    investigating: number;
    resolved: number;
    false_positive: number;
  };
  severity_distribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  recent_24h: number;
  top_categories_7d: Array<{
    category: string;
    count: number;
  }>;
}

export interface AlertTimelineData {
  timeline: Record<string, {
    critical: number;
    high: number;
    medium: number;
    low: number;
  }>;
  hours: number;
}

export interface AlertContext {
  alert: Alert;
  parsed_log: ParsedLog | null;
  detection_rule: DetectionRule | null;
  related_alerts: Alert[];
}

export interface NotificationResponse {
  success: boolean;
  sent_count: number;
  failed_count: number;
  errors: string[];
}

// Dashboard types
export interface DashboardStats {
  total_logs: number;
  total_alerts: number;
  open_alerts: number;
  critical_alerts: number;
  logs_last_24h?: number;
  alerts_last_24h?: number;
  // Vulnerability statistics
  total_assets?: number;
  active_assets?: number;
  total_vulnerabilities?: number;
  critical_vulnerabilities?: number;
  high_vulnerabilities?: number;
  medium_vulnerabilities?: number;
  low_vulnerabilities?: number;
  open_vulnerabilities?: number;
  active_scans?: number;
  recent_scans?: number;
}

export interface LogVolumeData {
  timestamp: string;
  count: number;
}

export interface AlertTrendData {
  timestamp: string;
  count: number;
  severity: string;
}

export interface TopSourcesData {
  source_ip: string;
  count: number;
}

// Query parameters
export interface LogQueryParams {
  page?: number;
  size?: number;
  source_type?: string;
  source_ip?: string;
  log_level?: string;
  start_time?: string;
  end_time?: string;
  search?: string;
}

export interface AlertQueryParams {
  page?: number;
  size?: number;
  severity?: string;
  status?: string;
  rule_id?: number;
  start_time?: string;
  end_time?: string;
}

// WebSocket message types
export interface WebSocketMessage {
  type: 'new_log' | 'new_alert' | 'alert_updated' | 'stats_update';
  data: unknown;
}

export interface NewLogMessage extends WebSocketMessage {
  type: 'new_log';
  data: ParsedLog;
}

export interface NewAlertMessage extends WebSocketMessage {
  type: 'new_alert';
  data: Alert;
}

export interface AlertUpdatedMessage extends WebSocketMessage {
  type: 'alert_updated';
  data: Alert;
}

export interface StatsUpdateMessage extends WebSocketMessage {
  type: 'stats_update';
  data: DashboardStats;
}

// Vulnerability Management Types
export interface Asset {
  id: string;
  ip_address: string;
  hostname?: string;
  mac_address?: string;
  asset_type?: string;
  operating_system?: string;
  os_version?: string;
  open_ports?: Record<string, string | number>;
  services?: Record<string, string | number>;
  is_active: boolean;
  last_seen: string;
  discovery_method?: string;
  confidence_score?: number;
  asset_metadata?: Record<string, string | number | boolean>;
  created_at: string;
  updated_at: string;
}

export interface VulnerabilityScan {
  id: string;
  asset_id?: string;
  scan_name: string;
  scan_type: string;
  target: string;
  scan_config?: Record<string, string | number | boolean>;
  scanner_version?: string;
  status: string;
  progress: number;
  vulnerabilities_found: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  started_at?: string;
  completed_at?: string;
  duration_seconds?: number;
  error_message?: string;
  created_at: string;
  updated_at: string;
}

export interface Vulnerability {
  id: string;
  scan_id: string;
  asset_id?: string;
  cve_id?: string;
  vulnerability_id?: string;
  title: string;
  description?: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cvss_score?: number;
  cvss_vector?: string;
  component?: string;
  version?: string;
  port?: number;
  service?: string;
  category?: string;
  attack_vector?: string;
  attack_complexity?: string;
  solution?: string;
  references?: string[];
  status: 'open' | 'investigating' | 'fixed' | 'false_positive';
  risk_accepted: boolean;
  first_detected: string;
  last_detected: string;
  scanner_data?: Record<string, string | number | boolean | string[]>;
  created_at: string;
  updated_at: string;
}

export interface ScanSchedule {
  id: string;
  name: string;
  scan_type: string;
  target: string;
  scan_config?: Record<string, string | number | boolean>;
  schedule_expression: string;
  is_active: boolean;
  last_run?: string;
  next_run?: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface VulnerabilityStats {
  total_assets: number;
  active_assets: number;
  total_vulnerabilities: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  medium_vulnerabilities: number;
  low_vulnerabilities: number;
  open_vulnerabilities: number;
  fixed_vulnerabilities: number;
  false_positive_vulnerabilities: number;
  recent_scans: number;
  active_scans: number;
}

export interface AssetDiscoveryRequest {
  target: string;
  discovery_method?: string;
  scan_config?: Record<string, string | number | boolean>;
}


export interface UpdateVulnerabilityRequest {
  status?: 'open' | 'investigating' | 'fixed' | 'false_positive';
  risk_accepted?: boolean;
  notes?: string;
}

export interface CreateScanScheduleRequest {
  name: string;
  scan_type: string;
  target: string;
  scan_config?: Record<string, string | number | boolean>;
  schedule_expression: string;
  is_active?: boolean;
}

export interface VulnerabilityStats {
  total_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  open_count: number;
  fixed_count: number;
  false_positive_count: number;
  risk_accepted_count: number;
}

export interface AssetStats {
  total_assets: number;
  active_assets: number;
  inactive_assets: number;
  scanned_assets: number;
  vulnerable_assets: number;
}

export interface ScanStats {
  total_scans: number;
  completed_scans: number;
  failed_scans: number;
  running_scans: number;
  scheduled_scans: number;
}

export interface VulnerabilityDashboardStats {
  vulnerability_stats: VulnerabilityStats;
  asset_stats: AssetStats;
  scan_stats: ScanStats;
  recent_scans: VulnerabilityScan[];
  top_vulnerabilities: Vulnerability[];
}

export interface ScanRequest {
  scan_name: string;
  scan_type: 'nmap' | 'trivy' | 'custom';
  targets: string[];
  scan_config?: Record<string, string | number | boolean>;
}

export interface ScanStatusResponse {
  scan_id: string;
  status: string;
  progress: number;
  message?: string;
}

// Query parameters for vulnerability endpoints
export interface VulnerabilityQueryParams {
  page?: number;
  size?: number;
  severity?: string;
  status?: string;
  asset_id?: string;
  cve_id?: string;
}

export interface AssetQueryParams {
  page?: number;
  size?: number;
  active_only?: boolean;
  asset_type?: string;
}

export interface ScanQueryParams {
  page?: number;
  size?: number;
  status?: string;
  scan_type?: string;
}