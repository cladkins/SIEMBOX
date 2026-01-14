/**
 * Log Mock Data Fixtures
 * Static test data for log-related tests
 */

export const mockRawLog = {
  id: 1,
  raw_message: '[13/Jan/2025:10:00:00 +0000] 192.168.1.50 - - GET /api/logs 200 1234',
  parsed_data: {
    timestamp: '13/Jan/2025:10:00:00 +0000',
    client_ip: '192.168.1.50',
    method: 'GET',
    path: '/api/logs',
    status: '200',
    bytes: '1234',
  },
  timestamp: '2025-01-13T10:00:00Z',
  source_ip: '192.168.1.50',
  facility: 23,
  severity: 6,
  hostname: 'webserver',
  app_name: 'nginx',
  shipper_id: 'web1234',
  created_at: '2025-01-13T10:00:00Z',
};

export const mockErrorLog = {
  id: 2,
  raw_message: 'ERROR: Database connection failed - connection timeout',
  parsed_data: {
    level: 'ERROR',
    message: 'Database connection failed - connection timeout',
  },
  timestamp: '2025-01-13T10:01:00Z',
  source_ip: '192.168.1.100',
  facility: 16,
  severity: 3,
  hostname: 'appserver',
  app_name: 'myapp',
  shipper_id: 'app1234',
  created_at: '2025-01-13T10:01:00Z',
};

export const mockSSHLog = {
  id: 3,
  raw_message: 'Failed password for invalid user admin from 192.168.1.50 port 22 ssh2',
  parsed_data: {
    event: 'Failed password',
    user: 'admin',
    source_ip: '192.168.1.50',
    port: '22',
  },
  timestamp: '2025-01-13T10:02:00Z',
  source_ip: '192.168.1.50',
  facility: 10,
  severity: 5,
  hostname: 'authserver',
  app_name: 'sshd',
  shipper_id: 'auth1234',
  created_at: '2025-01-13T10:02:00Z',
};

export const mockLogs = [mockRawLog, mockErrorLog, mockSSHLog];

export const mockLogsResponse = {
  logs: mockLogs,
  total: 150,
  page: 1,
  limit: 20,
  totalPages: 8,
};

export const mockLogFilters = {
  search: '',
  startDate: null,
  endDate: null,
  severity: null,
  hostname: null,
  app_name: null,
};
