#!/usr/bin/env node

/**
 * Test script for NGINX Komodo parser patterns
 *
 * This script validates the regex patterns against actual log samples
 * from the komodo system (192.168.1.194) before applying to production.
 *
 * Usage:
 *   node backend/test-nginx-komodo-patterns.js
 */

// Sample logs from the database (after syslog extraction)
const testSamples = [
  {
    name: 'Timestamp-first access log - Format 1',
    message: '[09/Dec/2025:20:35:53 +0000] - 200 200 - GET',
    expectedParser: 'timestamp-first',
    expectedFields: {
      timestamp: '09/Dec/2025:20:35:53 +0000',
      status_code1: '200',
      status_code2: '200',
      method: 'GET'
    }
  },
  {
    name: 'Timestamp-first access log - Format 2',
    message: '[09/Dec/2025:20:12:14 +0000] 301 - GET http w',
    expectedParser: 'timestamp-first',
    expectedFields: {
      timestamp: '09/Dec/2025:20:12:14 +0000',
      status_code1: '301',
      method: 'GET',
      protocol: 'http'
    }
  },
  {
    name: 'Error log format',
    message: '2025/12/08 19:37:36 [error] 1484#1484: *17597',
    expectedParser: 'error',
    expectedFields: {
      timestamp: '2025/12/08 19:37:36',
      log_level: 'error',
      pid: '1484',
      worker_id: '1484',
      connection_id: '17597'
    }
  },
  {
    name: 'Error log with message',
    message: '2025/12/09 19:57:00 [warn] 1484#1484: *24156 upstream server temporarily disabled',
    expectedParser: 'error',
    expectedFields: {
      timestamp: '2025/12/09 19:57:00',
      log_level: 'warn',
      pid: '1484',
      worker_id: '1484',
      connection_id: '24156',
      message: 'upstream server temporarily disabled'
    }
  },
  {
    name: 'IP-only minimal format',
    message: '68.218.17.107 -',
    expectedParser: 'ip-only',
    expectedFields: {
      client_ip: '68.218.17.107'
    }
  },
  {
    name: 'IP-only with additional data',
    message: '192.168.1.100 - some additional content',
    expectedParser: 'ip-only',
    expectedFields: {
      client_ip: '192.168.1.100',
      message: 'some additional content'
    }
  }
];

// Parser patterns from migration file
const patterns = {
  'timestamp-first': /^\[(?<timestamp>[^\]]+)\]\s+(?:-\s+)?(?<status_code1>\d{3})?\s*(?<status_code2>\d{3})?\s*-?\s*(?<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)?\s*(?<protocol>https?|wss?)?\s*(?<request_uri>\S+)?/,

  'error': /^(?<timestamp>\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?<log_level>\w+)\]\s+(?<pid>\d+)#(?<worker_id>\d+):\s+\*(?<connection_id>\d+)\s*(?<message>.*)?/,

  'ip-only': /^(?<client_ip>[\d.]+)\s+-\s*(?<message>.*)?/
};

// ANSI color codes for output
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m'
};

// Test execution
console.log(`${colors.blue}========================================`);
console.log('NGINX Komodo Parser Pattern Validation');
console.log(`========================================${colors.reset}\n`);

let passCount = 0;
let failCount = 0;

testSamples.forEach((sample, index) => {
  console.log(`${colors.cyan}Test ${index + 1}: ${sample.name}${colors.reset}`);
  console.log(`Message: "${sample.message}"\n`);

  // Find matching parser
  const pattern = patterns[sample.expectedParser];
  if (!pattern) {
    console.log(`${colors.red}✗ ERROR: Parser "${sample.expectedParser}" not found${colors.reset}\n`);
    failCount++;
    return;
  }

  // Test pattern match
  const match = sample.message.match(pattern);

  if (!match) {
    console.log(`${colors.red}✗ FAIL: Pattern did not match${colors.reset}`);
    console.log(`Expected parser: ${sample.expectedParser}\n`);
    failCount++;
    return;
  }

  // Verify extracted fields
  const groups = match.groups || {};
  let allFieldsMatch = true;

  console.log('Extracted fields:');
  for (const [key, value] of Object.entries(groups)) {
    if (value !== undefined && value !== '') {
      const expected = sample.expectedFields[key];
      const matches = expected ? value === expected : true;
      const symbol = matches ? '✓' : '✗';
      const color = matches ? colors.green : colors.red;

      console.log(`  ${color}${symbol} ${key}: "${value}"${colors.reset}`);

      if (expected && !matches) {
        console.log(`    ${colors.yellow}Expected: "${expected}"${colors.reset}`);
        allFieldsMatch = false;
      }
    }
  }

  // Check for missing expected fields
  for (const [key, value] of Object.entries(sample.expectedFields)) {
    if (groups[key] === undefined || groups[key] === '') {
      console.log(`  ${colors.red}✗ ${key}: MISSING (expected "${value}")${colors.reset}`);
      allFieldsMatch = false;
    }
  }

  if (allFieldsMatch) {
    console.log(`\n${colors.green}✓ PASS: All fields extracted correctly${colors.reset}\n`);
    passCount++;
  } else {
    console.log(`\n${colors.red}✗ FAIL: Field extraction mismatch${colors.reset}\n`);
    failCount++;
  }

  console.log('---\n');
});

// Summary
console.log(`${colors.blue}========================================`);
console.log('Test Summary');
console.log(`========================================${colors.reset}`);
console.log(`Total tests: ${testSamples.length}`);
console.log(`${colors.green}Passed: ${passCount}${colors.reset}`);
console.log(`${colors.red}Failed: ${failCount}${colors.reset}`);

if (failCount === 0) {
  console.log(`\n${colors.green}✓ ALL TESTS PASSED${colors.reset}`);
  console.log('\nThe parser patterns are ready for production deployment.');
  console.log('Run the migration: psql -U siembox -d siembox -f backend/migrations/003_add_nginx_custom_parsers.sql\n');
  process.exit(0);
} else {
  console.log(`\n${colors.red}✗ SOME TESTS FAILED${colors.reset}`);
  console.log('\nPlease review the failed tests and adjust the patterns before deployment.\n');
  process.exit(1);
}
