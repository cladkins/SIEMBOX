import apiClient from './api';

export type DiscoverySourceStatus = 'candidate' | 'confirmed' | 'onboarded' | 'ignored';
export type DiscoveryScanMode = 'passive' | 'active' | 'full';
export type DiscoveryScanStatus = 'running' | 'completed' | 'failed';

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
}

export interface ScopePreview {
  cidrs: string[];
  vlan_warning: string | null;
  rejected_cidrs: string[];
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

class LogDiscoveryServiceClient {
  async getScope(manualCidrs: string[] = []): Promise<ScopePreview> {
    const params = manualCidrs.length > 0 ? `?manual_cidrs=${encodeURIComponent(manualCidrs.join(','))}` : '';
    const response = await apiClient.get(`/log-discovery/scope${params}`);
    return response.data;
  }

  async getFingerprints(): Promise<FingerprintEntry[]> {
    const response = await apiClient.get('/log-discovery/fingerprints');
    return response.data;
  }

  async triggerScan(mode: DiscoveryScanMode, manualCidrs: string[] = []): Promise<TriggerScanResponse> {
    const response = await apiClient.post('/log-discovery/scans', { mode, manual_cidrs: manualCidrs });
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
}

export default new LogDiscoveryServiceClient();
