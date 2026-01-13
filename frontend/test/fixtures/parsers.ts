/**
 * Parser Mock Data Fixtures
 * Static test data for parser-related tests
 */

export const mockRegexParser = {
  id: 1,
  name: 'NGINX Access Log',
  description: 'Parses NGINX access logs',
  enabled: true,
  priority: 10,
  parser_type: 'regex' as const,
  pattern: '^(?<remote_addr>[\\d.]+) - (?<remote_user>\\S+) \\[(?<time_local>[^\\]]+)\\]',
  field_mappings: {
    remote_addr: 'client_ip',
    remote_user: 'user',
    time_local: 'timestamp',
  },
  test_samples: [
    {
      input: '192.168.1.50 - - [13/Jan/2025:10:00:00 +0000] GET /api/logs 200',
      expected: {
        client_ip: '192.168.1.50',
        user: '-',
        timestamp: '13/Jan/2025:10:00:00 +0000',
      },
    },
  ],
  event_type: 'web_access',
  created_at: '2025-01-01T00:00:00Z',
  updated_at: '2025-01-01T00:00:00Z',
};

export const mockGrokParser = {
  id: 2,
  name: 'Syslog Parser',
  description: 'Parses standard syslog messages',
  enabled: true,
  priority: 20,
  parser_type: 'grok' as const,
  pattern: '%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} %{WORD:app_name}',
  field_mappings: {
    timestamp: 'timestamp',
    hostname: 'hostname',
    app_name: 'app_name',
  },
  test_samples: [],
  event_type: 'syslog',
  created_at: '2025-01-01T00:00:00Z',
  updated_at: '2025-01-01T00:00:00Z',
};

export const mockJSONParser = {
  id: 3,
  name: 'JSON Log Parser',
  description: 'Parses JSON formatted logs',
  enabled: true,
  priority: 30,
  parser_type: 'json' as const,
  pattern: '',
  field_mappings: {},
  test_samples: [
    {
      input: '{"level":"error","message":"Test error","timestamp":"2025-01-13T10:00:00Z"}',
      expected: {
        level: 'error',
        message: 'Test error',
        timestamp: '2025-01-13T10:00:00Z',
      },
    },
  ],
  event_type: 'json',
  created_at: '2025-01-01T00:00:00Z',
  updated_at: '2025-01-01T00:00:00Z',
};

export const mockDisabledParser = {
  id: 4,
  name: 'Disabled Parser',
  description: 'A disabled parser for testing',
  enabled: false,
  priority: 100,
  parser_type: 'regex' as const,
  pattern: '.*',
  field_mappings: {},
  test_samples: [],
  event_type: null,
  created_at: '2025-01-01T00:00:00Z',
  updated_at: '2025-01-01T00:00:00Z',
};

export const mockParsers = [
  mockRegexParser,
  mockGrokParser,
  mockJSONParser,
  mockDisabledParser,
];

export const mockParsersResponse = {
  parsers: mockParsers,
  total: 4,
};
