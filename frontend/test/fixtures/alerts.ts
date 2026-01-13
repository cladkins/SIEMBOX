/**
 * Alert Mock Data Fixtures
 * Static test data for alert-related tests
 */

export const mockCriticalAlert = {
  id: 1,
  rule_id: 1,
  rule_name: 'Brute Force Attack',
  severity: 'critical' as const,
  message: 'Multiple failed login attempts from 192.168.1.50',
  count: 15,
  first_seen: '2025-01-13T10:00:00Z',
  last_seen: '2025-01-13T10:05:00Z',
  acknowledged: false,
  acknowledged_by: null,
  acknowledged_at: null,
  created_at: '2025-01-13T10:00:00Z',
  updated_at: '2025-01-13T10:05:00Z',
};

export const mockHighAlert = {
  id: 2,
  rule_id: 2,
  rule_name: 'Failed SSH Login Attempts',
  severity: 'high' as const,
  message: 'Failed password attempts detected',
  count: 8,
  first_seen: '2025-01-13T09:30:00Z',
  last_seen: '2025-01-13T09:35:00Z',
  acknowledged: true,
  acknowledged_by: 'admin',
  acknowledged_at: '2025-01-13T09:40:00Z',
  created_at: '2025-01-13T09:30:00Z',
  updated_at: '2025-01-13T09:40:00Z',
};

export const mockMediumAlert = {
  id: 3,
  rule_id: 3,
  rule_name: 'Unusual Traffic Pattern',
  severity: 'medium' as const,
  message: 'Unusual traffic detected from IP 192.168.1.100',
  count: 3,
  first_seen: '2025-01-13T08:00:00Z',
  last_seen: '2025-01-13T08:10:00Z',
  acknowledged: false,
  acknowledged_by: null,
  acknowledged_at: null,
  created_at: '2025-01-13T08:00:00Z',
  updated_at: '2025-01-13T08:10:00Z',
};

export const mockLowAlert = {
  id: 4,
  rule_id: 4,
  rule_name: 'Log Volume Increase',
  severity: 'low' as const,
  message: 'Log volume increased by 20%',
  count: 1,
  first_seen: '2025-01-13T07:00:00Z',
  last_seen: '2025-01-13T07:00:00Z',
  acknowledged: true,
  acknowledged_by: 'analyst',
  acknowledged_at: '2025-01-13T07:30:00Z',
  created_at: '2025-01-13T07:00:00Z',
  updated_at: '2025-01-13T07:30:00Z',
};

export const mockAlerts = [
  mockCriticalAlert,
  mockHighAlert,
  mockMediumAlert,
  mockLowAlert,
];

export const mockAlertsResponse = {
  alerts: mockAlerts,
  total: 4,
  unacknowledged: 2,
};

export const mockAlertStats = {
  total: 24,
  critical: 3,
  high: 8,
  medium: 10,
  low: 3,
  unacknowledged: 11,
};
