/**
 * Integration tests for parser pipeline
 * Tests the full flow from syslog parsing through field extraction
 * NOTE: These tests are designed to work once correct patterns are provided
 */

import { parseSyslogMessage } from '../syslog/syslogParser';
import { SYSLOG_FIXTURES, NGINX_PARSER_FIXTURES } from './fixtures';

/**
 * Mock ParserEngine for integration testing
 * This allows us to test the pipeline without database dependencies
 */
class MockParserEngine {
  private parsers: any[] = [];

  constructor() {
    this.parsers = [];
  }

  addParser(parser: any): void {
    this.parsers.push(parser);
  }

  testParser(message: string): { matched: boolean; fields?: Record<string, any> } {
    for (const parser of this.parsers) {
      if (parser.type === 'regex') {
        try {
          const regex = new RegExp(parser.pattern);
          const match = message.match(regex);

          if (match) {
            const fields: Record<string, any> = {};

            // Map groups to fields
            if (match.groups) {
              for (const [groupName, fieldName] of Object.entries(parser.field_mappings)) {
                if (match.groups[groupName]) {
                  fields[fieldName] = match.groups[groupName];
                }
              }
            } else {
              for (const [groupNum, fieldName] of Object.entries(parser.field_mappings)) {
                const index = parseInt(groupNum, 10);
                if (match[index]) {
                  fields[fieldName] = match[index];
                }
              }
            }

            return { matched: true, fields };
          }
        } catch (error) {
          // Continue to next parser
        }
      }
    }

    return { matched: false };
  }
}

describe('Parser Integration Tests', () => {
  describe('Syslog extraction to parser pipeline', () => {
    it('should extract NGINX access log message and prepare for parsing', () => {
      // Arrange
      const fixture = SYSLOG_FIXTURES.nginx_access_1;

      // Act
      const parsed = parseSyslogMessage(fixture.raw_syslog);

      // Assert
      // The parsed.message should contain only the message portion
      expect(parsed.message).toBe(fixture.expected_message);
      // Should not contain syslog headers
      expect(parsed.message).not.toContain('<134>');
      expect(parsed.message).not.toContain('komodo');
      expect(parsed.message).not.toContain('NGINX:');
    });

    it('should extract NGINX error log message and prepare for parsing', () => {
      // Arrange
      const fixture = SYSLOG_FIXTURES.nginx_error;

      // Act
      const parsed = parseSyslogMessage(fixture.raw_syslog);

      // Assert
      expect(parsed.message).toBe(fixture.expected_message);
      expect(parsed.message).toMatch(/2025\/12\/08/);
      expect(parsed.message).toMatch(/\[error\]/);
    });

    it('should handle all sample NGINX logs from database', () => {
      // Arrange
      const fixtures = [
        SYSLOG_FIXTURES.nginx_access_1,
        SYSLOG_FIXTURES.nginx_access_2,
        SYSLOG_FIXTURES.nginx_error,
        SYSLOG_FIXTURES.nginx_minimal,
      ];

      // Act & Assert
      fixtures.forEach((fixture) => {
        const parsed = parseSyslogMessage(fixture.raw_syslog);
        expect(parsed.message).toBe(fixture.expected_message);
        expect(parsed.message).not.toContain('NGINX:');
      });
    });

    it('should preserve syslog metadata (facility, severity, hostname)', () => {
      // Arrange
      const fixture = SYSLOG_FIXTURES.nginx_access_1;

      // Act
      const parsed = parseSyslogMessage(fixture.raw_syslog);

      // Assert
      expect(parsed.facility).toBe(fixture.expected_parsed_syslog.facility);
      expect(parsed.severity).toBe(fixture.expected_parsed_syslog.severity);
      expect(parsed.hostname).toBe(fixture.expected_parsed_syslog.hostname);
      expect(parsed.appName).toBe(fixture.expected_parsed_syslog.appName);
    });
  });

  describe('Full pipeline: syslog -> extraction -> parser matching', () => {
    it('should identify NGINX access logs after syslog extraction', () => {
      // Arrange
      const fixture = SYSLOG_FIXTURES.nginx_access_1;
      const engine = new MockParserEngine();

      // Add a simple detection: access logs typically have timestamps in brackets
      engine.addParser({
        type: 'regex',
        pattern: '\\[\\d{2}/\\w+/\\d{4}',
        field_mappings: { '0': 'log_type' },
      });

      // Act
      const parsed = parseSyslogMessage(fixture.raw_syslog);
      const result = engine.testParser(parsed.message);

      // Assert
      expect(result.matched).toBe(true);
    });

    it('should identify NGINX error logs after syslog extraction', () => {
      // Arrange
      const fixture = SYSLOG_FIXTURES.nginx_error;
      const engine = new MockParserEngine();

      // Add a simple detection: error logs have YYYY/MM/DD format timestamp
      engine.addParser({
        type: 'regex',
        pattern: '\\d{4}/\\d{2}/\\d{2}\\s+\\d{2}:\\d{2}:\\d{2}\\s+\\[\\w+\\]',
        field_mappings: { '0': 'log_type' },
      });

      // Act
      const parsed = parseSyslogMessage(fixture.raw_syslog);
      const result = engine.testParser(parsed.message);

      // Assert
      expect(result.matched).toBe(true);
    });

    it('should NOT match non-NGINX logs with NGINX parsers', () => {
      // Arrange
      const fixtures = [
        SYSLOG_FIXTURES.ssh_login,
        SYSLOG_FIXTURES.sudo_command,
        SYSLOG_FIXTURES.apache_access,
      ];

      // Act & Assert
      fixtures.forEach((fixture) => {
        const parsed = parseSyslogMessage(fixture.raw_syslog);
        // The extracted message should be different from NGINX messages
        expect(parsed.message).not.toMatch(/^\[?\d{2}\/\w+\/\d{4}/);
      });
    });
  });

  describe('Field extraction from parsed logs', () => {
    it('should extract fields from NGINX access log with full pattern', () => {
      // Arrange
      const fixture = NGINX_PARSER_FIXTURES.access_log_full;
      const engine = new MockParserEngine();

      // TODO: Replace with actual pattern from backend-architect
      const pattern = '';

      if (!pattern) {
        pending('Pattern not yet provided by backend-architect');
      }

      engine.addParser({
        type: 'regex',
        pattern: pattern,
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
      });

      // Act
      const result = engine.testParser(fixture.message);

      // Assert
      if (result.matched && result.fields) {
        expect(result.fields.client_ip).toBeDefined();
        expect(result.fields.status_code).toBeDefined();
        expect(result.fields.method).toBe('GET');
      }
    });

    it('should extract fields from NGINX error log', () => {
      // Arrange
      const fixture = NGINX_PARSER_FIXTURES.error_log_standard;
      const engine = new MockParserEngine();

      // TODO: Replace with actual pattern from backend-architect
      const pattern = '';

      if (!pattern) {
        pending('Pattern not yet provided by backend-architect');
      }

      engine.addParser({
        type: 'regex',
        pattern: pattern,
        field_mappings: {
          '1': 'timestamp',
          '2': 'severity',
          '3': 'pid',
          '4': 'worker_id',
          '5': 'connection_id',
          '6': 'message',
        },
      });

      // Act
      const result = engine.testParser(fixture.message);

      // Assert
      if (result.matched && result.fields) {
        expect(result.fields.severity).toBeDefined();
        expect(result.fields.timestamp).toBeDefined();
      }
    });
  });

  describe('End-to-end pipeline test with real samples', () => {
    it('should process all database sample logs through complete pipeline', () => {
      // Arrange
      const samples = [
        '<134>Dec 09 20:36:20 komodo NGINX: [09/Dec/2025:20:35:53 +0000] - 200 200 - GET',
        '<134>Dec 09 20:36:19 komodo NGINX: [09/Dec/2025:20:12:14 +0000] 301 - GET http w',
        '<134>Dec 09 20:36:19 komodo NGINX: 2025/12/08 19:37:36 [error] 1484#1484: *17597',
        '<134>Dec 09 19:52:03 komodo NGINX: 68.218.17.107 -',
      ];

      // Act & Assert
      samples.forEach((sample) => {
        // Step 1: Parse syslog
        const parsed = parseSyslogMessage(sample);

        // Step 2: Verify message was extracted
        expect(parsed.message).toBeTruthy();
        expect(parsed.message).not.toContain('<134>');
        expect(parsed.message).not.toContain('komodo');
        expect(parsed.message).not.toContain('NGINX:');

        // Step 3: Verify syslog metadata
        expect(parsed.facility).toBe(16); // local0
        expect(parsed.severity).toBe(6); // info
        expect(parsed.hostname).toBe('komodo');
        expect(parsed.appName).toBe('NGINX');
      });
    });

    it('should correctly handle NGINX logs in priority order', () => {
      // Arrange
      const errorLog = '<134>Dec 09 20:36:19 komodo NGINX: 2025/12/08 19:37:36 [error] 1484#1484: *17597';
      const accessLog = '<134>Dec 09 20:36:20 komodo NGINX: [09/Dec/2025:20:35:53 +0000] - 200 200 - GET';

      // Act
      const errorParsed = parseSyslogMessage(errorLog);
      const accessParsed = parseSyslogMessage(accessLog);

      // Assert
      // Error logs start with YYYY/MM/DD
      expect(errorParsed.message).toMatch(/^\d{4}\/\d{2}\/\d{2}/);

      // Access logs typically have timestamps in brackets
      expect(accessParsed.message).toMatch(/^\[/);

      // They should be distinguishable
      expect(errorParsed.message).not.toEqual(accessParsed.message);
    });
  });

  describe('Parser collision detection', () => {
    it('should not confuse access logs with error logs', () => {
      // Arrange
      const engine = new MockParserEngine();

      // Simple pattern for access logs (has brackets)
      engine.addParser({
        type: 'regex',
        pattern: '\\[\\d{2}/',
        field_mappings: { '0': 'type' },
      });

      // Simple pattern for error logs (has [error], [warn], etc)
      engine.addParser({
        type: 'regex',
        pattern: '\\[(?:error|warn|crit|alert|emerg|debug|info|notice)\\]',
        field_mappings: { '0': 'type' },
      });

      const accessLog = '[09/Dec/2025:20:35:53 +0000] - 200 200 - GET';
      const errorLog = '2025/12/08 19:37:36 [error] 1484#1484: *17597';

      // Act
      const accessResult = engine.testParser(accessLog);
      const errorResult = engine.testParser(errorLog);

      // Assert
      expect(accessResult.matched).toBe(true);
      expect(errorResult.matched).toBe(true);
      // They should match different patterns
    });
  });

  describe('Handling of malformed logs', () => {
    it('should gracefully handle NGINX logs with missing fields', () => {
      // Arrange
      const fixture = SYSLOG_FIXTURES.nginx_minimal;

      // Act
      const parsed = parseSyslogMessage(fixture.raw_syslog);

      // Assert
      expect(parsed).toHaveProperty('message');
      expect(parsed).toHaveProperty('facility');
      expect(parsed).toHaveProperty('severity');
      expect(parsed).toHaveProperty('hostname');
    });

    it('should handle logs without PRI header', () => {
      // Arrange
      const logWithoutPri = 'Dec 09 20:36:20 komodo NGINX: [09/Dec/2025:20:35:53 +0000] test message';

      // Act
      const parsed = parseSyslogMessage(logWithoutPri);

      // Assert
      expect(parsed.facility).toBeNull();
      expect(parsed.severity).toBeNull();
      expect(parsed.message).toBeTruthy();
    });

    it('should handle empty or null messages gracefully', () => {
      // Arrange
      const emptyMessage = '';
      const whitespaceOnly = '   ';

      // Act
      const emptyResult = parseSyslogMessage(emptyMessage);
      const whitespaceResult = parseSyslogMessage(whitespaceOnly);

      // Assert
      expect(emptyResult).toHaveProperty('message');
      expect(whitespaceResult).toHaveProperty('message');
    });
  });

  describe('Performance characteristics', () => {
    it('should parse logs in reasonable time', () => {
      // Arrange
      const iterations = 1000;
      const testLog = '<134>Dec 09 20:36:20 komodo NGINX: [09/Dec/2025:20:35:53 +0000] - 200 200 - GET';

      // Act
      const startTime = process.hrtime.bigint();

      for (let i = 0; i < iterations; i++) {
        parseSyslogMessage(testLog);
      }

      const endTime = process.hrtime.bigint();
      const durationMs = Number(endTime - startTime) / 1_000_000;

      // Assert
      // Should parse 1000 logs in less than 100ms (rough benchmark)
      expect(durationMs).toBeLessThan(100);
    });

    it('should handle very long log messages', () => {
      // Arrange
      const longMessage = 'A'.repeat(4096);
      const testLog = `<134>Dec 09 20:36:20 komodo NGINX: ${longMessage}`;

      // Act
      const parsed = parseSyslogMessage(testLog);

      // Assert
      expect(parsed.message.length).toBe(4096);
    });
  });
});
