import type {
  PaginatedResponse,
  LoginRequest,
  LoginResponse,
  User,
  ParsedLog,
  RawLog,
  DetectionRule,
  CreateDetectionRuleRequest,
  DetectionStats,
  DetectionTestResult,
  Alert,
  UpdateAlertRequest,
  AlertStats,
  AlertTimelineData,
  AlertContext,
  NotificationResponse,
  DashboardStats,
  LogVolumeData,
  AlertTrendData,
  TopSourcesData,
  LogQueryParams,
  AlertQueryParams,
  Asset,
  VulnerabilityScan,
  Vulnerability,
  ScanSchedule,
  VulnerabilityStats,
  AssetDiscoveryRequest,
  ScanRequest,
  UpdateVulnerabilityRequest,
  CreateScanScheduleRequest,
  VulnerabilityQueryParams,
  AssetQueryParams,
  ScanQueryParams,
} from '../types/api';

class ApiClient {
  private baseURL = '/api/v1';

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const token = this.getToken();
    
    const config: RequestInit = {
      headers: {
        'Content-Type': 'application/json',
        ...(token && { Authorization: `Bearer ${token}` }),
        ...options.headers,
      },
      ...options,
    };

    const response = await fetch(`${this.baseURL}${endpoint}`, config);

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.detail || `HTTP ${response.status}: ${response.statusText}`);
    }

    return response.json();
  }

  private getToken(): string | null {
    const authData = localStorage.getItem('siembox-auth');
    if (authData) {
      const parsed = JSON.parse(authData);
      return parsed.state?.token || null;
    }
    return null;
  }

  // Authentication endpoints
  async login(credentials: LoginRequest): Promise<LoginResponse> {
    return this.request<LoginResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    });
  }

  async getCurrentUser(): Promise<User> {
    return this.request<User>('/auth/me');
  }

  // Dashboard endpoints
  async getDashboardStats(): Promise<DashboardStats> {
    const response = await this.request<any>('/dashboard/stats');
    
    // Transform backend response to match frontend expectations
    return {
      total_logs: response.total_logs || response.log_stats?.total_logs || 0,
      total_alerts: response.total_alerts || response.alert_stats?.total_alerts || 0,
      open_alerts: response.open_alerts || response.alert_stats?.open_alerts || 0,
      critical_alerts: response.critical_alerts || response.alert_stats?.critical_alerts || 0,
      logs_last_24h: response.logs_last_24h || response.log_stats?.recent_logs_24h || 0,
      alerts_last_24h: response.alerts_last_24h || response.alert_stats?.recent_alerts_24h || 0,
      // Vulnerability statistics
      total_assets: response.total_assets || response.asset_stats?.total_assets,
      active_assets: response.active_assets || response.asset_stats?.active_assets,
      total_vulnerabilities: response.total_vulnerabilities || response.vulnerability_stats?.total_vulnerabilities,
      critical_vulnerabilities: response.critical_vulnerabilities || response.vulnerability_stats?.critical_count,
      high_vulnerabilities: response.high_vulnerabilities || response.vulnerability_stats?.high_count,
      medium_vulnerabilities: response.medium_vulnerabilities || response.vulnerability_stats?.medium_count,
      low_vulnerabilities: response.low_vulnerabilities || response.vulnerability_stats?.low_count,
      open_vulnerabilities: response.open_vulnerabilities || response.vulnerability_stats?.open_count,
      active_scans: response.active_scans || response.scan_stats?.running_scans,
      recent_scans: response.recent_scans || response.scan_stats?.completed_scans,
    };
  }

  async getLogVolume(hours = 24): Promise<LogVolumeData[]> {
    const response = await this.request<any>(`/dashboard/log-volume?hours=${hours}`);
    return response.data || response;
  }

  async getAlertTrends(hours = 24): Promise<AlertTrendData[]> {
    // This endpoint doesn't exist in backend, return empty array for now
    return [];
  }

  async getTopSources(limit = 10): Promise<TopSourcesData[]> {
    // This endpoint doesn't exist in backend, return empty array for now
    return [];
  }

  // Log endpoints
  async getLogs(params: LogQueryParams = {}): Promise<PaginatedResponse<ParsedLog>> {
    const searchParams = new URLSearchParams();
    
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        if (key === 'page' && typeof value === 'number') {
          // Convert page to skip (0-based)
          searchParams.append('skip', ((value - 1) * (params.size || 100)).toString());
        } else if (key === 'size') {
          searchParams.append('limit', value.toString());
        } else if (key === 'source_type') {
          searchParams.append('app_name', value.toString());
        } else if (key === 'source_ip') {
          searchParams.append('hostname', value.toString());
        } else if (key === 'start_time' || key === 'end_time') {
          searchParams.append(key, value.toString());
        }
      }
    });

    const queryString = searchParams.toString();
    const endpoint = `/logs/parsed${queryString ? `?${queryString}` : ''}`;
    
    return this.request<PaginatedResponse<ParsedLog>>(endpoint);
  }

  async getLogById(id: number): Promise<ParsedLog> {
    return this.request<ParsedLog>(`/logs/${id}`);
  }

  async getRawLogs(params: LogQueryParams = {}): Promise<PaginatedResponse<RawLog>> {
    const searchParams = new URLSearchParams();
    
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        if (key === 'page' && typeof value === 'number') {
          // Convert page to skip (0-based)
          searchParams.append('skip', ((value - 1) * (params.size || 100)).toString());
        } else if (key === 'size') {
          searchParams.append('limit', value.toString());
        } else if (key === 'source_type') {
          searchParams.append('app_name', value.toString());
        } else if (key === 'source_ip') {
          searchParams.append('hostname', value.toString());
        } else if (key === 'start_time' || key === 'end_time') {
          searchParams.append(key, value.toString());
        }
      }
    });

    const queryString = searchParams.toString();
    const endpoint = `/logs${queryString ? `?${queryString}` : ''}`;
    
    return this.request<PaginatedResponse<RawLog>>(endpoint);
  }

  // Detection Rule endpoints
  async getDetectionRules(params: { enabled_only?: boolean; category?: string; severity?: string } = {}): Promise<DetectionRule[]> {
    const searchParams = new URLSearchParams();
    
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        searchParams.append(key, value.toString());
      }
    });

    const queryString = searchParams.toString();
    const endpoint = `/detection/rules${queryString ? `?${queryString}` : ''}`;
    
    return this.request<DetectionRule[]>(endpoint);
  }

  async getDetectionRuleById(id: string): Promise<DetectionRule> {
    return this.request<DetectionRule>(`/detection/rules/${id}`);
  }

  async createDetectionRule(rule: CreateDetectionRuleRequest): Promise<DetectionRule> {
    return this.request<DetectionRule>('/detection/rules', {
      method: 'POST',
      body: JSON.stringify(rule),
    });
  }

  async updateDetectionRule(id: string, rule: Partial<CreateDetectionRuleRequest>): Promise<DetectionRule> {
    return this.request<DetectionRule>(`/detection/rules/${id}`, {
      method: 'PUT',
      body: JSON.stringify(rule),
    });
  }

  async deleteDetectionRule(id: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(`/detection/rules/${id}`, {
      method: 'DELETE',
    });
  }

  async enableDetectionRule(id: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(`/detection/rules/${id}/enable`, {
      method: 'POST',
    });
  }

  async disableDetectionRule(id: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(`/detection/rules/${id}/disable`, {
      method: 'POST',
    });
  }

  async getDetectionStats(): Promise<DetectionStats> {
    return this.request<DetectionStats>('/detection/stats');
  }

  async testDetectionRule(logId: string): Promise<DetectionTestResult> {
    return this.request<DetectionTestResult>(`/detection/check/${logId}`, {
      method: 'POST',
    });
  }

  async initializeDefaultRules(): Promise<{ message: string; created_count: number }> {
    return this.request<{ message: string; created_count: number }>('/detection/initialize-rules', {
      method: 'POST',
    });
  }

  // Alert endpoints
  async getAlerts(params: AlertQueryParams = {}): Promise<PaginatedResponse<Alert>> {
    const searchParams = new URLSearchParams();
    
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        if (key === 'page' && typeof value === 'number') {
          // Convert page to offset (0-based)
          searchParams.append('offset', ((value - 1) * (params.size || 100)).toString());
        } else if (key === 'size') {
          searchParams.append('limit', value.toString());
        } else if (key === 'status' || key === 'severity' || key === 'category' || key === 'hours') {
          // These are the exact parameters the backend accepts
          searchParams.append(key, value.toString());
        }
        // Skip other parameters that the backend doesn't support
      }
    });

    const queryString = searchParams.toString();
    const endpoint = `/alerts/${queryString ? `?${queryString}` : ''}`;
    
    // Backend returns array directly, need to wrap in pagination format
    const alerts = await this.request<Alert[]>(endpoint);
    
    return {
      items: alerts,
      total: alerts.length,
      page: params.page || 1,
      size: params.size || 100,
      pages: Math.ceil(alerts.length / (params.size || 100))
    };
  }

  async getAlertById(id: string): Promise<Alert> {
    return this.request<Alert>(`/alerts/${id}/`);
  }

  async updateAlert(id: string, update: UpdateAlertRequest): Promise<Alert> {
    return this.request<Alert>(`/alerts/${id}/`, {
      method: 'PUT',
      body: JSON.stringify(update),
    });
  }

  async acknowledgeAlert(id: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(`/alerts/${id}/acknowledge/`, {
      method: 'POST',
    });
  }

  async resolveAlert(id: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(`/alerts/${id}/resolve/`, {
      method: 'POST',
    });
  }

  async markAlertFalsePositive(id: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(`/alerts/${id}/false-positive/`, {
      method: 'POST',
    });
  }

  async bulkUpdateAlerts(alertIds: string[], status: string): Promise<{ message: string; updated_count: number; status: string }> {
    return this.request<{ message: string; updated_count: number; status: string }>('/alerts/bulk-update/', {
      method: 'POST',
      body: JSON.stringify({ alert_ids: alertIds, status }),
    });
  }

  async getAlertStats(): Promise<AlertStats> {
    return this.request<AlertStats>('/alerts/stats/summary/');
  }

  async getAlertTimeline(hours = 24): Promise<AlertTimelineData> {
    return this.request<AlertTimelineData>(`/alerts/stats/timeline/?hours=${hours}`);
  }

  async getAlertContext(id: string): Promise<AlertContext> {
    return this.request<AlertContext>(`/alerts/${id}/context/`);
  }

  async sendAlertNotifications(alertIds: string[], notificationTypes?: string[]): Promise<NotificationResponse> {
    return this.request<NotificationResponse>('/alerts/notify/', {
      method: 'POST',
      body: JSON.stringify({
        alert_ids: alertIds,
        notification_types: notificationTypes
      }),
    });
  }

  // Health check
  async healthCheck(): Promise<{ status: string; timestamp: string }> {
    return this.request<{ status: string; timestamp: string }>('/health');
  }

  // Vulnerability Management endpoints
  
  // Asset Management
  async getAssets(params: AssetQueryParams = {}): Promise<PaginatedResponse<Asset>> {
    const searchParams = new URLSearchParams();
    
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        searchParams.append(key, value.toString());
      }
    });

    const queryString = searchParams.toString();
    const endpoint = `/vulnerabilities/assets${queryString ? `?${queryString}` : ''}`;
    
    return this.request<PaginatedResponse<Asset>>(endpoint);
  }

  async getAssetById(id: string): Promise<Asset> {
    return this.request<Asset>(`/vulnerabilities/assets/${id}`);
  }

  async discoverAssets(request: AssetDiscoveryRequest): Promise<{ message: string; task_id: string }> {
    return this.request<{ message: string; task_id: string }>('/vulnerabilities/assets/discover', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async deleteAsset(id: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(`/vulnerabilities/assets/${id}`, {
      method: 'DELETE',
    });
  }

  // Vulnerability Scanning
  async getScans(params: ScanQueryParams = {}): Promise<PaginatedResponse<VulnerabilityScan>> {
    const searchParams = new URLSearchParams();
    
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        searchParams.append(key, value.toString());
      }
    });

    const queryString = searchParams.toString();
    const endpoint = `/vulnerabilities/scans${queryString ? `?${queryString}` : ''}`;
    
    return this.request<PaginatedResponse<VulnerabilityScan>>(endpoint);
  }

  async getScanById(id: string): Promise<VulnerabilityScan> {
    return this.request<VulnerabilityScan>(`/vulnerabilities/scans/${id}`);
  }

  async startScan(request: ScanRequest): Promise<{ message: string; scan_id: string }> {
    return this.request<{ message: string; scan_id: string }>('/vulnerabilities/scans/start', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async stopScan(id: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(`/vulnerabilities/scans/${id}/stop`, {
      method: 'POST',
    });
  }

  async deleteScan(id: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(`/vulnerabilities/scans/${id}`, {
      method: 'DELETE',
    });
  }

  // Vulnerability Management
  async getVulnerabilities(params: VulnerabilityQueryParams = {}): Promise<PaginatedResponse<Vulnerability>> {
    const searchParams = new URLSearchParams();
    
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        searchParams.append(key, value.toString());
      }
    });

    const queryString = searchParams.toString();
    const endpoint = `/vulnerabilities${queryString ? `?${queryString}` : ''}`;
    
    return this.request<PaginatedResponse<Vulnerability>>(endpoint);
  }

  async getVulnerabilityById(id: string): Promise<Vulnerability> {
    return this.request<Vulnerability>(`/vulnerabilities/${id}`);
  }

  async updateVulnerability(id: string, update: UpdateVulnerabilityRequest): Promise<Vulnerability> {
    return this.request<Vulnerability>(`/vulnerabilities/${id}`, {
      method: 'PUT',
      body: JSON.stringify(update),
    });
  }

  async deleteVulnerability(id: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(`/vulnerabilities/${id}`, {
      method: 'DELETE',
    });
  }

  // Scan Scheduling
  async getScanSchedules(): Promise<ScanSchedule[]> {
    return this.request<ScanSchedule[]>('/vulnerabilities/schedules');
  }

  async getScanScheduleById(id: string): Promise<ScanSchedule> {
    return this.request<ScanSchedule>(`/vulnerabilities/schedules/${id}`);
  }

  async createScanSchedule(schedule: CreateScanScheduleRequest): Promise<ScanSchedule> {
    return this.request<ScanSchedule>('/vulnerabilities/schedules', {
      method: 'POST',
      body: JSON.stringify(schedule),
    });
  }

  async updateScanSchedule(id: string, schedule: Partial<CreateScanScheduleRequest>): Promise<ScanSchedule> {
    return this.request<ScanSchedule>(`/vulnerabilities/schedules/${id}`, {
      method: 'PUT',
      body: JSON.stringify(schedule),
    });
  }

  async deleteScanSchedule(id: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(`/vulnerabilities/schedules/${id}`, {
      method: 'DELETE',
    });
  }

  async enableScanSchedule(id: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(`/vulnerabilities/schedules/${id}/enable`, {
      method: 'POST',
    });
  }

  async disableScanSchedule(id: string): Promise<{ message: string }> {
    return this.request<{ message: string }>(`/vulnerabilities/schedules/${id}/disable`, {
      method: 'POST',
    });
  }

  // Dashboard and Statistics
  async getVulnerabilityStats(): Promise<VulnerabilityStats> {
    return this.request<VulnerabilityStats>('/vulnerabilities/stats');
  }

  async exportVulnerabilities(format: 'csv' | 'json' = 'csv'): Promise<Blob> {
    const response = await fetch(`${this.baseURL}/vulnerabilities/export?format=${format}`, {
      headers: {
        Authorization: `Bearer ${this.getToken()}`,
      },
    });

    if (!response.ok) {
      throw new Error(`Export failed: ${response.statusText}`);
    }

    return response.blob();
  }
}

export const apiClient = new ApiClient();