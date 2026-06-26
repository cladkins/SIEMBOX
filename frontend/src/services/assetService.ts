import apiClient from './api';

export interface Asset {
  id: number;
  ip_address: string;
  hostname?: string;
  mac_address?: string;
  os_type?: string;
  os_version?: string;
  asset_type: 'server' | 'workstation' | 'network' | 'iot';
  criticality: 'low' | 'medium' | 'high' | 'critical';
  status: 'active' | 'inactive' | 'offline';
  discovery_method: 'nmap' | 'log_correlation' | 'manual';
  first_seen: string;
  last_seen: string;
  last_scanned?: string;
  metadata?: any;
  tags?: string[];
  created_at: string;
  updated_at: string;
}

export interface AssetService {
  id: number;
  asset_id: number;
  port: number;
  protocol: 'tcp' | 'udp';
  service_name?: string;
  service_version?: string;
  state: 'open' | 'closed' | 'filtered';
  banner?: string;
  discovered_at: string;
  last_seen: string;
}

export interface AssetWithServices extends Asset {
  services: AssetService[];
}

// --- Asset-360: everything correlated to an asset --------------------------

export interface RelatedAgent {
  agent_id: string;
  asset_id: number | null;
  hostname: string | null;
  os: string | null;
  os_version: string | null;
  arch: string | null;
  agent_version: string | null;
  ip: string | null;
  status: string;
  config_version: number;
  last_seen: string | null;
  created_at: string;
  online: boolean;
}

export interface RelatedShipper {
  id: number;
  name: string;
  status: string;
  version: string | null;
  last_seen: string | null;
  ip_address: string | null;
  hostname: string | null;
}

export interface GeoInfo {
  country_code: string;
  country_name: string;
}

export interface RelatedVulnerability {
  id: number;
  asset_id: number;
  status: string;
  risk_score: number | null;
  first_detected: string;
  last_detected: string;
  vulnerability: {
    id: number;
    cve_id: string;
    cvss_score: number | null;
    severity: string;
    title: string;
    description?: string;
  };
}

export interface RelatedAlert {
  id: number;
  rule_id: number | null;
  severity: string;
  title: string;
  description: string | null;
  status: string;
  source: string | null;
  event_id: string | null;
  matched_data: any;
  created_at: string;
}

export interface AssetRelated {
  agent: RelatedAgent | null;
  shipper: RelatedShipper | null;
  geo: GeoInfo | null;
  vulnerabilities: RelatedVulnerability[];
  alerts: RelatedAlert[];
}

export interface AssetFilters {
  status?: string;
  criticality?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

export interface AssetsResponse {
  assets: Asset[];
  total: number;
}

export interface ScanRequest {
  targets: string[];
  scanType: string;
}

export interface ScanResponse {
  scanId: number;
}

class AssetServiceClient {
  async getAssets(filters: AssetFilters = {}): Promise<AssetsResponse> {
    const params = new URLSearchParams();
    Object.entries(filters).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== '') {
        params.append(key, value.toString());
      }
    });
    const response = await apiClient.get(`/assets?${params}`);
    return response.data;
  }

  async getAsset(id: number): Promise<AssetWithServices> {
    const response = await apiClient.get(`/assets/${id}`);
    return response.data;
  }

  async getAssetRelated(id: number): Promise<AssetRelated> {
    const response = await apiClient.get(`/assets/${id}/related`);
    return response.data;
  }

  async createAsset(asset: Partial<Asset>): Promise<Asset> {
    const response = await apiClient.post('/assets', asset);
    return response.data;
  }

  async updateAsset(id: number, updates: Partial<Asset>): Promise<Asset> {
    const response = await apiClient.put(`/assets/${id}`, updates);
    return response.data;
  }

  async deleteAsset(id: number): Promise<void> {
    await apiClient.delete(`/assets/${id}`);
  }

  async getServices(assetId: number): Promise<AssetService[]> {
    const response = await apiClient.get(`/assets/${assetId}/services`);
    return response.data;
  }

  async triggerScan(targets: string[], scanType: string): Promise<ScanResponse> {
    const response = await apiClient.post('/assets/scan', { targets, scanType });
    return response.data;
  }
}

export default new AssetServiceClient();
