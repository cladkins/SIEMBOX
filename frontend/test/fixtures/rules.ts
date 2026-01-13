/**
 * Detection Rule Mock Data Fixtures
 * Static test data for detection rule-related tests
 */

export const mockFailedLoginRule = {
  id: 1,
  name: 'Failed SSH Login Attempts',
  description: 'Detects multiple failed SSH login attempts',
  enabled: true,
  severity: 'high' as const,
  rule_yaml: `name: "Failed SSH Login Attempts"
description: "Detects multiple failed SSH login attempts"
severity: high
conditions:
  - field: message
    operator: contains
    value: "Failed password"
  - field: app_name
    operator: equals
    value: "sshd"
threshold: 5
time_window: 300`,
  rule_logic: {
    conditions: [
      {
        field: 'message',
        operator: 'contains',
        value: 'Failed password',
      },
      {
        field: 'app_name',
        operator: 'equals',
        value: 'sshd',
      },
    ],
    threshold: 5,
    time_window: 300,
  },
  tags: ['authentication', 'ssh', 'security'],
  created_at: '2025-01-01T00:00:00Z',
  updated_at: '2025-01-01T00:00:00Z',
};

export const mockBruteForceRule = {
  id: 2,
  name: 'Brute Force Attack',
  description: 'Detects brute force authentication attempts',
  enabled: true,
  severity: 'critical' as const,
  rule_yaml: `name: "Brute Force Attack"
description: "Detects brute force authentication attempts"
severity: critical
conditions:
  - field: http_status
    operator: equals
    value: "401"
threshold: 10
time_window: 60`,
  rule_logic: {
    conditions: [
      {
        field: 'http_status',
        operator: 'equals',
        value: '401',
      },
    ],
    threshold: 10,
    time_window: 60,
  },
  tags: ['web', 'brute-force', 'authentication'],
  created_at: '2025-01-01T00:00:00Z',
  updated_at: '2025-01-01T00:00:00Z',
};

export const mockErrorThresholdRule = {
  id: 3,
  name: 'High Error Rate',
  description: 'Alerts on high error rate',
  enabled: true,
  severity: 'medium' as const,
  rule_yaml: `name: "High Error Rate"
description: "Alerts on high error rate"
severity: medium
conditions:
  - field: level
    operator: equals
    value: "error"
threshold: 20
time_window: 600`,
  rule_logic: {
    conditions: [
      {
        field: 'level',
        operator: 'equals',
        value: 'error',
      },
    ],
    threshold: 20,
    time_window: 600,
  },
  tags: ['errors', 'performance'],
  created_at: '2025-01-01T00:00:00Z',
  updated_at: '2025-01-01T00:00:00Z',
};

export const mockDisabledRule = {
  id: 4,
  name: 'Disabled Rule',
  description: 'A disabled rule for testing',
  enabled: false,
  severity: 'low' as const,
  rule_yaml: '',
  rule_logic: {},
  tags: ['test'],
  created_at: '2025-01-01T00:00:00Z',
  updated_at: '2025-01-01T00:00:00Z',
};

export const mockRules = [
  mockFailedLoginRule,
  mockBruteForceRule,
  mockErrorThresholdRule,
  mockDisabledRule,
];

export const mockRulesResponse = {
  rules: mockRules,
  total: 4,
};
