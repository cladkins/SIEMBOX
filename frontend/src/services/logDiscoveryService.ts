import apiClient from './api';

export type DiscoverySourceStatus = 'candidate' | 'confirmed' | 'onboarded' | 'ignored';
export type DiscoveryScanMode = 'passive' | 'active' | 'full';
export type DiscoveryScanStatus = 'queued' | 'running' | 'completed' | 'failed';

/** A log shipper as returned by GET /api/shippers (only the fields the picker needs). */
export interface ShipperSummary {
  id: number;
  name: string;
  status: 'pending' | 'online' | 'offline' | 'error';
  hostname?: string | null;
}

export interface LogAccessMethod {
  method: string;
  target_port?: number;
  format?: string;
  auth?: string;
  path?: string;
  endpoint?: string;
}

export interface FingerprintEntry {
  id: string;
  name: string;
  category: string;
  security_value: number;
  confidence_floor: number;
  attack_data_sources: string[];
  log_access: LogAccessMethod[];
  credentials: { required: boolean; optional: Array<{ type: string; unlocks?: string[] }> };
}

export interface RankedSourcePollerStatus {
  configured: boolean;
  enabled: boolean;
  last_status: 'ok' | 'error' | null;
  last_polled_at: string | null;
  last_error: string | null;
}

export interface RankedSource {
  id: number;
  ip: string;
  mac: string | null;
  hostname: string | null;
  open_ports: number[];
  matched_fingerprint_id: string | null;
  confidence: number;
  is_guess: boolean;
  security_value: number | null;
  status: DiscoverySourceStatus;
  selected_log_access: LogAccessMethod | null;
  evidence: Record<string, unknown>;
  reason: string;
  poller?: RankedSourcePollerStatus;
}

export interface RankedSources {
  top: RankedSource[];
  advanced: RankedSource[];
}

export interface DiscoveryScan {
  id: number;
  mode: DiscoveryScanMode;
  cidrs: string[];
  status: DiscoveryScanStatus;
  started_at: string;
  completed_at: string | null;
  error_message: string | null;
  results_summary: { hosts_seen: number; hosts_matched: number } | null;
  /** Shipper the scan ran on (null/absent = ran on the SIEMBox backend). */
  assigned_shipper_id?: number | null;
  assigned_shipper_name?: string | null;
}

export interface ScopePreview {
  cidrs: string[];
  vlan_warning: string | null;
  rejected_cidrs: string[];
  /** The host's real detected LAN CIDR, offered as a one-click suggestion. Only ever non-null under the opt-in host-networking mode — see DEPLOYMENT.md's "Log Discovery and Network Visibility" section. */
  detected_lan_cidr: string | null;
}

export interface TriggerScanResponse {
  scan_id: number;
  cidrs: string[];
  vlan_warning: string | null;
  rejected_cidrs: string[];
}

export interface OnboardPreview {
  instructions: string;
  log_access: LogAccessMethod;
}

export interface PollerStatus {
  configured: boolean;
  fingerprint_id?: string;
  credential_username?: string | null;
  enabled?: boolean;
  poll_interval_minutes?: number;
  last_polled_at?: string | null;
  last_status?: 'ok' | 'error' | null;
  last_error?: string | null;
  last_event_count?: number | null;
}

export interface PollNowResult {
  ok: boolean;
  count: number;
  error?: string;
}

class LogDiscoveryServiceClient {
  async getScope(manualCidrs: string[] = []): Promise<ScopePreview> {
    const params = manualCidrs.length > 0 ? `?manual_cidrs=${encodeURIComponent(manualCidrs.join(','))}` : '';
    const response = await apiClient.get(`/log-discovery/scope${params}`);
    return response.data;
  }

  /** The persisted standing scan-scope CIDRs (server-side, shared across admins/devices). */
  async getScopeCidrs(): Promise<string[]> {
    const response = await apiClient.get('/log-discovery/scope/cidrs');
    return response.data.cidrs;
  }

  /** Replace the persisted scan scope. Returns the accepted set plus any CIDRs the server rejected (invalid or larger than /22). */
  async saveScopeCidrs(cidrs: string[]): Promise<{ cidrs: string[]; rejected: string[] }> {
    const response = await apiClient.put('/log-discovery/scope/cidrs', { cidrs });
    return response.data;
  }

  async getFingerprints(): Promise<FingerprintEntry[]> {
    const response = await apiClient.get('/log-discovery/fingerprints');
    return response.data;
  }

  async triggerScan(
    mode: DiscoveryScanMode,
    manualCidrs: string[] = [],
    assignedShipperId?: number | null
  ): Promise<TriggerScanResponse> {
    const body: Record<string, unknown> = { mode, manual_cidrs: manualCidrs };
    if (assignedShipperId != null) body.assignedShipperId = assignedShipperId;
    const response = await apiClient.post('/log-discovery/scans', body);
    return response.data;
  }

  /** List log shippers (for the "Run from" discovery-scan picker). */
  async getShippers(): Promise<ShipperSummary[]> {
    const response = await apiClient.get('/shippers');
    return response.data;
  }

  async getScans(): Promise<DiscoveryScan[]> {
    const response = await apiClient.get('/log-discovery/scans');
    return response.data;
  }

  async getScan(id: number): Promise<DiscoveryScan> {
    const response = await apiClient.get(`/log-discovery/scans/${id}`);
    return response.data;
  }

  async cancelScan(id: number): Promise<{ cancelled: boolean; scan: DiscoveryScan }> {
    const response = await apiClient.post(`/log-discovery/scans/${id}/cancel`);
    return response.data;
  }

  async getSources(): Promise<RankedSources> {
    const response = await apiClient.get('/log-discovery/sources');
    return response.data;
  }

  async confirmSource(id: number): Promise<RankedSource> {
    const response = await apiClient.post(`/log-discovery/sources/${id}/confirm`);
    return response.data;
  }

  async ignoreSource(id: number): Promise<RankedSource> {
    const response = await apiClient.post(`/log-discovery/sources/${id}/ignore`);
    return response.data;
  }

  async previewOnboard(id: number, methodIndex = 0): Promise<OnboardPreview> {
    const response = await apiClient.post(`/log-discovery/sources/${id}/onboard/preview`, { method_index: methodIndex });
    return response.data;
  }

  async confirmOnboard(id: number, methodIndex = 0): Promise<{ source: RankedSource; instructions: string }> {
    const response = await apiClient.post(`/log-discovery/sources/${id}/onboard/confirm`, {
      method_index: methodIndex,
      confirm: true,
    });
    return response.data;
  }

  /** Fingerprint ids with a real poll adapter — so the UI doesn't hardcode which of the 10 bundled fingerprints support it. */
  async getPollableFingerprintIds(): Promise<string[]> {
    const response = await apiClient.get('/log-discovery/poller/supported-fingerprints');
    return response.data;
  }

  async getPollerStatus(id: number): Promise<PollerStatus> {
    const response = await apiClient.get(`/log-discovery/sources/${id}/poller`);
    return response.data;
  }

  async savePollerCredential(id: number, secret: string, username?: string): Promise<PollerStatus> {
    const response = await apiClient.post(`/log-discovery/sources/${id}/poller/credential`, { secret, username });
    return response.data;
  }

  async revokePollerCredential(id: number): Promise<{ cleared: boolean }> {
    const response = await apiClient.delete(`/log-discovery/sources/${id}/poller/credential`);
    return response.data;
  }

  async setPolling(id: number, changes: { enabled?: boolean; poll_interval_minutes?: number }): Promise<PollerStatus> {
    const response = await apiClient.patch(`/log-discovery/sources/${id}/poller`, changes);
    return response.data;
  }

  async runPollNow(id: number): Promise<PollNowResult> {
    const response = await apiClient.post(`/log-discovery/sources/${id}/poller/run-now`);
    return response.data;
  }
}

export default new LogDiscoveryServiceClient();
