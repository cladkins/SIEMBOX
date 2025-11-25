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
    const authStore = useAuthStore();
    if (authStore.token) {
      config.headers.Authorization = `Bearer ${authStore.token}`;
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
  createUser: (data: any) => apiClient.post('/users', data),
  updateUser: (id: number, data: any) => apiClient.put(`/users/${id}`, data),
  deleteUser: (id: number) => apiClient.delete(`/users/${id}`),
};
