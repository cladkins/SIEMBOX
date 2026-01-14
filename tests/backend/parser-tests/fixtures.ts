/**
 * Test fixtures for parser testing
 * Contains sample logs and expected parser configurations
 */

export const SYSLOG_FIXTURES = {
  // NGINX access logs
  nginx_access_1: {
    raw_syslog: '<134>Dec 09 20:36:20 test-host NGINX: [09/Dec/2025:20:35:53 +0000] - 200 200 - GET',
    expected_message: '[09/Dec/2025:20:35:53 +0000] - 200 200 - GET',
    expected_parsed_syslog: {
      facility: 16, // local0
      severity: 6, // info
      hostname: 'test-host',
      appName: 'NGINX',
      processId: null,
    },
  },

  nginx_access_2: {
    raw_syslog: '<134>Dec 09 20:36:19 test-host NGINX: [09/Dec/2025:20:12:14 +0000] 301 - GET http w',
    expected_message: '[09/Dec/2025:20:12:14 +0000] 301 - GET http w',
    expected_parsed_syslog: {
      facility: 16,
      severity: 6,
      hostname: 'test-host',
      appName: 'NGINX',
      processId: null,
    },
  },

  nginx_error: {
    raw_syslog: '<134>Dec 09 20:36:19 test-host NGINX: 2025/12/08 19:37:36 [error] 1484#1484: *17597',
    expected_message: '2025/12/08 19:37:36 [error] 1484#1484: *17597',
    expected_parsed_syslog: {
      facility: 16,
      severity: 6,
      hostname: 'test-host',
      appName: 'NGINX',
      processId: null,
    },
  },

  nginx_minimal: {
    raw_syslog: '<134>Dec 09 19:52:03 test-host NGINX: 203.0.113.50 -',
    expected_message: '203.0.113.50 -',
    expected_parsed_syslog: {
      facility: 16,
      severity: 6,
      hostname: 'test-host',
      appName: 'NGINX',
      processId: null,
    },
  },

  // Non-NGINX logs for negative testing
  apache_access: {
    raw_syslog: '<134>Dec 09 20:36:20 test-host APACHE: 192.0.2.1 - - [09/Dec/2025:20:36:20 +0000] "GET / HTTP/1.1" 200 1234',
    expected_message: '192.0.2.1 - - [09/Dec/2025:20:36:20 +0000] "GET / HTTP/1.1" 200 1234',
    expected_parsed_syslog: {
      facility: 16,
      severity: 6,
      hostname: 'test-host',
      appName: 'APACHE',
      processId: null,
    },
  },

  ssh_login: {
    raw_syslog: '<85>Dec 09 20:36:20 test-host sshd[1234]: Failed password for root from 192.0.2.100 port 52894 ssh2',
    expected_message: 'Failed password for root from 192.0.2.100 port 52894 ssh2',
    expected_parsed_syslog: {
      facility: 10, // authpriv
      severity: 5, // notice
      hostname: 'test-host',
      appName: 'sshd',
      processId: '1234',
    },
  },

  sudo_command: {
    raw_syslog: '<86>Dec 09 20:36:20 test-host sudo: root : TTY=pts/0 ; PWD=/home/root ; USER=root ; COMMAND=/bin/ls',
    expected_message: 'root : TTY=pts/0 ; PWD=/home/root ; USER=root ; COMMAND=/bin/ls',
    expected_parsed_syslog: {
      facility: 10,
      severity: 6,
      hostname: 'test-host',
      appName: 'sudo',
      processId: null,
    },
  },
};

export const NGINX_PARSER_FIXTURES = {
  // Standard NGINX access log format variations
  access_log_basic: {
    message: '[09/Dec/2025:20:35:53 +0000] - 200 200 - GET',
    should_match: true,
    expected_fields: {
      timestamp: '[09/Dec/2025:20:35:53 +0000]',
      status_code: '200',
      upstream_status: '200',
      method: 'GET',
    },
  },

  access_log_full: {
    message: '192.0.2.100 - john [09/Dec/2025:20:35:53 +0000] "GET /api/users HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0"',
    should_match: true,
    expected_fields: {
      client_ip: '192.0.2.100',
      remote_user: 'john',
      timestamp: '[09/Dec/2025:20:35:53 +0000]',
      method: 'GET',
      path: '/api/users',
      http_version: 'HTTP/1.1',
      status_code: '200',
      bytes_sent: '1234',
      referrer: 'https://example.com',
      user_agent: 'Mozilla/5.0',
    },
  },

  access_log_with_upstream: {
    message: '[09/Dec/2025:20:12:14 +0000] 301 - GET http w',
    should_match: true,
    expected_fields: {
      timestamp: '[09/Dec/2025:20:12:14 +0000]',
      status_code: '301',
      method: 'GET',
    },
  },

  access_log_minimal: {
    message: '203.0.113.50 -',
    should_match: false, // Too minimal, likely malformed
  },

  // Error log formats
  error_log_standard: {
    message: '2025/12/08 19:37:36 [error] 1484#1484: *17597 connect() failed (111: Connection refused) while connecting to upstream',
    should_match: true,
    expected_fields: {
      timestamp: '2025/12/08 19:37:36',
      severity: 'error',
      pid: '1484',
      worker_id: '1484',
      connection_id: '17597',
      level: 'error',
    },
  },

  error_log_warn: {
    message: '2025/12/08 19:37:36 [warn] 1484#1484: *17597 upstream timed out',
    should_match: true,
    expected_fields: {
      timestamp: '2025/12/08 19:37:36',
      severity: 'warn',
      pid: '1484',
      level: 'warn',
    },
  },

  error_log_crit: {
    message: '2025/12/08 19:37:36 [crit] 1484#1484: *17597 socket() failed',
    should_match: true,
    expected_fields: {
      timestamp: '2025/12/08 19:37:36',
      severity: 'crit',
      level: 'crit',
    },
  },

  // Non-NGINX logs (negative cases)
  apache_log: {
    message: '192.0.2.1 - - [09/Dec/2025:20:36:20 +0000] "GET / HTTP/1.1" 200 1234',
    should_match: false,
  },

  syslog_generic: {
    message: 'kernel: [12345.678901] Out of memory: Kill process',
    should_match: false,
  },

  ssh_log: {
    message: 'Failed password for root from 192.0.2.100 port 52894 ssh2',
    should_match: false,
  },

  json_log: {
    message: '{"timestamp":"2025-12-09T20:35:53Z","level":"error","message":"Test error"}',
    should_match: false,
  },

  // Edge cases
  malformed_missing_timestamp: {
    message: '- 200 200 - GET',
    should_match: false,
  },

  empty_message: {
    message: '',
    should_match: false,
  },

  very_long_user_agent: {
    message: '192.0.2.100 - - [09/Dec/2025:20:35:53 +0000] "GET / HTTP/1.1" 200 1234 "-" "' +
             'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) ' +
             'Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59 ' +
             'SomeVeryLongUserAgentStringThatShouldStillParse/1.0' + '"',
    should_match: true,
    expected_fields: {
      status_code: '200',
    },
  },

  ipv6_address: {
    message: '[2001:db8::1] - - [09/Dec/2025:20:35:53 +0000] "GET / HTTP/1.1" 200 1234',
    should_match: true,
    expected_fields: {
      client_ip: '[2001:db8::1]',
      status_code: '200',
    },
  },
};

export const NEGATIVE_TEST_CASES = {
  completely_different: [
    'This is just random text with no structure',
    '123456 some numbers and text',
    'zzz zzz zzz',
  ],

  apache_variations: [
    '192.0.2.1 - - [09/Dec/2025:20:36:20 +0000] "GET / HTTP/1.1" 200 1234',
    '192.0.2.1 - frank [09/Dec/2025:10:15:30 +0000] "GET /path HTTP/1.0" 200 1043',
    '192.0.2.2 - - [01/Jan/2020:12:00:00 +0000] "POST /api HTTP/1.1" 201 512',
  ],

  ssh_variations: [
    'Failed password for invalid user admin from 192.0.2.100 port 54321 ssh2',
    'Accepted publickey for user from 192.0.2.100 port 54321 ssh2',
    'Invalid user admin from 192.0.2.100 port 54321',
  ],

  system_logs: [
    'kernel: [1234567.890123] Out of memory: Kill process 1234 (nginx)',
    'systemd[1]: Started Session 123 of user root.',
    'dhclient[1234]: DHCPDISCOVER on eth0 from 08:00:27:00:04:00',
  ],
};

/**
 * Parser configurations for testing
 * These should match what the backend-architect provides
 */
export const NGINX_PARSER_CONFIGS = {
  // NGINX access log parser
  nginx_access: {
    name: 'nginx-access',
    parser_type: 'regex' as const,
    // This pattern will be updated based on backend-architect recommendations
    pattern: '',
    field_mappings: {
      '1': 'client_ip',
      '2': 'remote_user',
      '3': 'timestamp',
      '4': 'method',
      '5': 'path',
      '6': 'http_version',
      '7': 'status_code',
      '8': 'bytes_sent',
      '9': 'referrer',
      '10': 'user_agent',
    },
    priority: 10,
    enabled: true,
  },

  // NGINX error log parser
  nginx_error: {
    name: 'nginx-error',
    parser_type: 'regex' as const,
    // This pattern will be updated based on backend-architect recommendations
    pattern: '',
    field_mappings: {
      '1': 'timestamp',
      '2': 'severity',
      '3': 'pid',
      '4': 'worker_id',
      '5': 'connection_id',
      '6': 'message',
    },
    priority: 10,
    enabled: true,
  },
};
