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
    // Public endpoints that don't require authentication
    const publicEndpoints = [
      '/assets/scans',
      '/assets/scans/active',
      '/assets/scans/statistics'
    ];

    // Check if this is a public endpoint (exact match or starts with for parameterized routes)
    const isPublicEndpoint = publicEndpoints.some(endpoint =>
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

  // Detection Rules
  getRules: () => apiClient.get('/rules'),
  getRule: (id: number) => apiClient.get(`/rules/${id}`),
  createRule: (data: any) => apiClient.post('/rules', data),
  updateRule: (id: number, data: any) => apiClient.put(`/rules/${id}`, data),
  deleteRule: (id: number) => apiClient.delete(`/rules/${id}`),

  // Alerts
  getAlerts: (params?: any) => apiClient.get('/alerts', { params }),
  getAlertStatistics: () => apiClient.get('/alerts/statistics'),
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

  // Asset Scans
  getScans: (params?: any) => apiClient.get('/assets/scans', { params }),
  getScan: (id: number) => apiClient.get(`/assets/scans/${id}`),
  getActiveScans: () => apiClient.get('/assets/scans/active'),
};
