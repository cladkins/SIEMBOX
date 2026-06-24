import axios, { AxiosInstance, AxiosError } from 'axios';
import { ElMessage } from 'element-plus';
import { useAuthStore } from '@/stores/auth';

const apiClient: AxiosInstance = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '/api',
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor
apiClient.interceptors.request.use(
  (config) => {
    // Public endpoints that don't require authentication (GET only)
    const publicGetEndpoints = [
      '/assets/scans',
      '/assets/scans/active',
      '/assets/scans/statistics'
    ];

    // Check if this is a public GET endpoint
    const isPublicEndpoint = config.method?.toUpperCase() === 'GET' && publicGetEndpoints.some(endpoint =>
      config.url === endpoint ||
      config.url?.startsWith(endpoint + '/') ||
      config.url?.startsWith(endpoint + '?')
    );

    // Only add auth token if not a public endpoint
    if (!isPublicEndpoint) {
      const authStore = useAuthStore();
      if (authStore.token) {
        config.headers.Authorization = `Bearer ${authStore.token}`;
      }
    }

    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor
apiClient.interceptors.response.use(
  (response) => response,
  (error: AxiosError) => {
    const authStore = useAuthStore();

    if (error.response) {
      switch (error.response.status) {
        case 401:
          authStore.logout();
          ElMessage.error('Session expired. Please login again.');
          break;
        case 403:
          ElMessage.error('You do not have permission to perform this action.');
          break;
        case 404:
          ElMessage.error('Resource not found.');
          break;
        case 500:
          ElMessage.error('Server error. Please try again later.');
          break;
        default:
          ElMessage.error('An error occurred. Please try again.');
      }
    } else if (error.code === 'ECONNABORTED' || /timeout/i.test(error.message || '')) {
      // Axios aborts on the client when a request exceeds its timeout; there is
      // no response, so this is distinct from a real connectivity failure. Say so
      // — otherwise a slow endpoint reads as "check your connection".
      ElMessage.error('Request timed out — the server took too long to respond.');
    } else if (error.request) {
      ElMessage.error('Network error. Please check your connection.');
    }

    return Promise.reject(error);
  }
);

export default apiClient;

// API service methods
export const api = {
  // Auth
  login: (username: string, password: string) =>
    apiClient.post('/auth/login', { username, password }),
  logout: () => apiClient.post('/auth/logout'),
  getProfile: () => apiClient.get('/auth/me'),

  // Logs
  getRawLogs: (params?: any) => apiClient.get('/logs/raw', { params }),
  getParsedLogs: (params?: any) => apiClient.get('/logs/parsed', { params }),

  // Parsers
  getParsers: () => apiClient.get('/parsers'),
  getParser: (id: number) => apiClient.get(`/parsers/${id}`),
  createParser: (data: any) => apiClient.post('/parsers', data),
  updateParser: (id: number, data: any) => apiClient.put(`/parsers/${id}`, data),
  deleteParser: (id: number) => apiClient.delete(`/parsers/${id}`),
  testParser: (id: number, sample: string) => apiClient.post(`/parsers/${id}/test`, { sample }),
  testParserConfig: (parser_type: string, pattern: string, field_mappings: any, sample: string) =>
    apiClient.post('/parsers/test', { parser_type, pattern, field_mappings, sample }),
  // Portable parser export/import (shareable .parser.json; same format the catalog uses)
  exportParser: (id: number) => apiClient.get(`/parsers/${id}/export`, { responseType: 'blob' }),
  validatePortableParser: (parser: any, strict = false) =>
    apiClient.post('/parsers/validate', { parser, strict }),
  importParser: (parser: any, force = false) => apiClient.post('/parsers/import', { parser, force }),
  // Parser catalog (browse/install from a GitHub repo, in-app)
  getCatalog: (refresh = false) => apiClient.get('/parsers/catalog', { params: refresh ? { refresh: true } : {} }),
  getCatalogSource: () => apiClient.get('/parsers/catalog/source'),
  installCatalogParser: (name: string, force = false) =>
    apiClient.post('/parsers/catalog/install', { name, force }),
  installAllCatalogParsers: (force = false) =>
    apiClient.post('/parsers/catalog/install-all', { force }, { timeout: 120000 }),

  // Detection Rules
  getRules: () => apiClient.get('/rules'),
  getRule: (id: number) => apiClient.get(`/rules/${id}`),
  createRule: (data: any) => apiClient.post('/rules', data),
  updateRule: (id: number, data: any) => apiClient.put(`/rules/${id}`, data),
  deleteRule: (id: number) => apiClient.delete(`/rules/${id}`),
  // Detection catalog (browse/install rules from the GitHub repo, in-app)
  getRuleCatalog: (refresh = false) => apiClient.get('/rules/catalog', { params: refresh ? { refresh: true } : {} }),
  installCatalogRule: (name: string) => apiClient.post('/rules/catalog/install', { name }),
  installAllCatalogRules: () => apiClient.post('/rules/catalog/install-all', {}, { timeout: 120000 }),

  // AI builder
  getAiSettings: () => apiClient.get('/settings/ai'),
  updateAiSettings: (data: any) => apiClient.put('/settings/ai', data),
  // Long timeout: generation runs an auto-refine loop of up to 3 model calls.
  generateParserAI: (sample: string, hints?: string) =>
    apiClient.post('/parsers/ai/generate', { sample, hints }, { timeout: 240000 }),
  generateDetectionAI: (description: string, context?: string) =>
    apiClient.post('/rules/ai/generate', { description, context }, { timeout: 240000 }),
  explainWithAI: (kind: string, data: any, question?: string) =>
    apiClient.post('/ai/explain', { kind, data, question }, { timeout: 240000 }),

  // Alerts
  getAlerts: (params?: any) => apiClient.get('/alerts', { params }),
  getAlertStatistics: () => apiClient.get('/alerts/statistics'),
  getAlertsByCountry: (params?: { days?: number; limit?: number }) =>
    apiClient.get('/alerts/by-country', { params }),

  // Threat Intel (IP-centric geo / events / alerts)
  getThreatIntelIp: (ip: string) => apiClient.get(`/threat-intel/ip/${encodeURIComponent(ip)}`),
  getThreatIntelCountry: (code: string, days = 30) =>
    apiClient.get(`/threat-intel/country/${encodeURIComponent(code)}`, { params: { days } }),

  // External threat feeds + IP reputation (Phase 4)
  getThreatFeeds: () => apiClient.get('/threat-feeds'),
  updateThreatFeed: (id: number, data: { enabled?: boolean; refresh_interval_minutes?: number }) =>
    apiClient.put(`/threat-feeds/feeds/${id}`, data),
  refreshThreatFeed: (id: number) => apiClient.post(`/threat-feeds/feeds/${id}/refresh`, {}, { timeout: 60000 }),
  refreshAllThreatFeeds: () => apiClient.post('/threat-feeds/refresh', {}, { timeout: 120000 }),
  saveThreatProvider: (name: string, data: { apiKey?: string | null; enabled?: boolean }) =>
    apiClient.put(`/threat-feeds/providers/${name}`, data),
  lookupThreatIp: (ip: string) => apiClient.get(`/threat-feeds/lookup/${encodeURIComponent(ip)}`),
  getAlert: (id: number) => apiClient.get(`/alerts/${id}`),
  updateAlert: (id: number, data: any) => apiClient.put(`/alerts/${id}`, data),
  deleteAlert: (id: number) => apiClient.delete(`/alerts/${id}`),

  // Users
  getUsers: () => apiClient.get('/users'),
  getUser: (id: number) => apiClient.get(`/users/${id}`),
  createUser: (data: any) => apiClient.post('/users', data),
  updateUser: (id: number, data: any) => apiClient.put(`/users/${id}`, data),
  deleteUser: (id: number) => apiClient.delete(`/users/${id}`),

  // Settings - Retention
  getRetentionSettings: () => apiClient.get('/settings/retention'),
  updateRetentionSettings: (data: any) => apiClient.put('/settings/retention', data),
  runManualCleanup: (data: any) => apiClient.post('/settings/retention/cleanup', data),
  getRetentionStatistics: () => apiClient.get('/settings/retention/stats'),

  // Settings - Syslog
  getSyslogSettings: () => apiClient.get('/settings/syslog'),
  updateSyslogSettings: (data: any) => apiClient.put('/settings/syslog', data),
  getSyslogStatus: () => apiClient.get('/settings/syslog/status'),

  // Log Shippers
  getShippers: () => apiClient.get('/shippers'),
  getShipper: (id: number) => apiClient.get(`/shippers/${id}`),
  createShipper: (data: any) => apiClient.post('/shippers', data),
  updateShipper: (id: number, data: any) => apiClient.put(`/shippers/${id}`, data),
  deleteShipper: (id: number) => apiClient.delete(`/shippers/${id}`),
  getUnknownSources: () => apiClient.get('/shippers/unknown-sources'),

  // Shipper Sources
  getShipperSources: (shipperId: number) => apiClient.get(`/shippers/${shipperId}/sources`),
  createShipperSource: (shipperId: number, data: any) => apiClient.post(`/shippers/${shipperId}/sources`, data),
  updateShipperSource: (sourceId: number, data: any) => apiClient.put(`/shippers/sources/${sourceId}`, data),
  deleteShipperSource: (sourceId: number) => apiClient.delete(`/shippers/sources/${sourceId}`),

  // Shipper Volumes
  getShipperVolumes: (shipperId: number) => apiClient.get(`/shippers/${shipperId}/volumes`),
  createShipperVolume: (shipperId: number, data: any) => apiClient.post(`/shippers/${shipperId}/volumes`, data),
  deleteShipperVolume: (shipperId: number, volumeId: number) => apiClient.delete(`/shippers/${shipperId}/volumes/${volumeId}`),

  // Shipper API Key Management
  regenerateShipperKey: (id: number) => apiClient.post(`/shippers/${id}/regenerate-key`),

  // Shipper Activity Log
  getShipperActivity: (id: number, limit?: number) =>
    apiClient.get(`/shippers/${id}/activity`, { params: { limit } }),

  // Settings - IP Whitelist Management
  getIpWhitelist: () => apiClient.get('/settings/ip-whitelist'),
  addIpWhitelist: (data: any) => apiClient.post('/settings/ip-whitelist', data),
  updateIpWhitelist: (id: number, data: any) =>
    apiClient.put(`/settings/ip-whitelist/${id}`, data),
  deleteIpWhitelist: (id: number) =>
    apiClient.delete(`/settings/ip-whitelist/${id}`),
  checkIpWhitelist: (ip: string) =>
    apiClient.post('/settings/ip-whitelist/check', { ip_address: ip }),

  // Settings - General
  getSettings: () => apiClient.get('/settings'),
  updateSetting: (key: string, data: any) => apiClient.put(`/settings/${key}`, data),

  // Assets
  getAssets: (params?: any) => apiClient.get('/assets', { params }),
  getAssetStatistics: () => apiClient.get('/assets/statistics'),
  getScans: (params?: any) => apiClient.get('/assets/scans', { params }),
  getScan: (id: number) => apiClient.get(`/assets/scans/${id}`),
  getActiveScans: () => apiClient.get('/assets/scans/active'),

  // Vulnerabilities
  getVulnerabilities: (params?: any) => apiClient.get('/vulnerabilities', { params }),
  getVulnerabilitySummary: () => apiClient.get('/vulnerabilities/summary'),

  // Container image scanning (Trivy)
  scanContainer: (image_ref: string) =>
    apiClient.post('/containers/scan', { image_ref }, { timeout: 30000 }),
  getContainerScans: (limit = 20) => apiClient.get('/containers/scans', { params: { limit } }),
  getContainerScan: (id: number) => apiClient.get(`/containers/scans/${id}`),
  // Images already present on the Docker host (requires the socket to be mounted).
  getDiscoveredImages: () => apiClient.get('/containers/discovered'),

  // Scheduled Scans
  getScheduledScans: () => apiClient.get('/scheduled-scans'),
  createScheduledScan: (data: any) => apiClient.post('/scheduled-scans', data),
  updateScheduledScan: (id: number, data: any) => apiClient.put(`/scheduled-scans/${id}`, data),
  deleteScheduledScan: (id: number) => apiClient.delete(`/scheduled-scans/${id}`),
  runScheduledScan: (id: number) => apiClient.post(`/scheduled-scans/${id}/run`),

  // Notifications - Channels
  getNotificationChannels: () => apiClient.get('/notifications/channels'),
  createNotificationChannel: (data: any) => apiClient.post('/notifications/channels', data),
  updateNotificationChannel: (id: number, data: any) => apiClient.put(`/notifications/channels/${id}`, data),
  deleteNotificationChannel: (id: number) => apiClient.delete(`/notifications/channels/${id}`),
  testNotificationChannel: (id: number) => apiClient.post(`/notifications/channels/${id}/test`),

  // Notifications - Settings
  getNotificationSettings: () => apiClient.get('/notifications/settings'),
  updateNotificationSettings: (data: any) => apiClient.put('/notifications/settings', data),

  // Admin Dashboard
  getAdminOverview: () => apiClient.get('/admin/overview'),
  searchAdminUsers: (query?: string, limit?: number) =>
    apiClient.get('/admin/users/search', { params: { q: query, limit } }),
  getUserActivity: (userId: number, limit?: number, offset?: number) =>
    apiClient.get(`/admin/users/${userId}/activity`, { params: { limit, offset } }),
  getAdminErrors: (hours?: number, limit?: number, offset?: number) =>
    apiClient.get('/admin/errors', { params: { hours, limit, offset } }),
  getAdminJobs: (status?: string, limit?: number, offset?: number) =>
    apiClient.get('/admin/jobs', { params: { status, limit, offset } }),

  // Generic methods
  get: (url: string, config?: any) => apiClient.get(url, config),
  post: (url: string, data?: any) => apiClient.post(url, data),
  put: (url: string, data?: any) => apiClient.put(url, data),
  delete: (url: string) => apiClient.delete(url),
};
