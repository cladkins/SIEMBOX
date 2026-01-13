/**
 * User Mock Data Fixtures
 * Static test data for user-related tests
 */

export const mockAdminUser = {
  id: 1,
  username: 'admin',
  email: 'admin@siembox.local',
  role: 'Admin' as const,
  enabled: true,
  last_login: '2025-01-13T10:00:00Z',
  created_at: '2025-01-01T00:00:00Z',
  updated_at: '2025-01-13T10:00:00Z',
};

export const mockAnalystUser = {
  id: 2,
  username: 'analyst',
  email: 'analyst@siembox.local',
  role: 'Analyst' as const,
  enabled: true,
  last_login: '2025-01-13T09:30:00Z',
  created_at: '2025-01-01T00:00:00Z',
  updated_at: '2025-01-13T09:30:00Z',
};

export const mockViewerUser = {
  id: 3,
  username: 'viewer',
  email: 'viewer@siembox.local',
  role: 'Viewer' as const,
  enabled: true,
  last_login: '2025-01-13T08:00:00Z',
  created_at: '2025-01-01T00:00:00Z',
  updated_at: '2025-01-13T08:00:00Z',
};

export const mockOperatorUser = {
  id: 4,
  username: 'operator',
  email: 'operator@siembox.local',
  role: 'Operator' as const,
  enabled: true,
  last_login: '2025-01-13T07:00:00Z',
  created_at: '2025-01-01T00:00:00Z',
  updated_at: '2025-01-13T07:00:00Z',
};

export const mockDisabledUser = {
  id: 5,
  username: 'disabled',
  email: 'disabled@siembox.local',
  role: 'Viewer' as const,
  enabled: false,
  last_login: null,
  created_at: '2025-01-01T00:00:00Z',
  updated_at: '2025-01-01T00:00:00Z',
};

export const mockUsers = [
  mockAdminUser,
  mockAnalystUser,
  mockViewerUser,
  mockOperatorUser,
];

export const mockAuthToken = 'mock-jwt-token-12345-67890-abcdef';

export const mockLoginResponse = {
  token: mockAuthToken,
  user: mockAdminUser,
};
