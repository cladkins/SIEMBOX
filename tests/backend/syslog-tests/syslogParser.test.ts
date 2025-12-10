/**
 * Unit tests for syslog parser
 * Tests RFC 3164 and RFC 5424 syslog format parsing
 */

import { parseSyslogMessage, getFacilityName, getSeverityName } from '../syslogParser';
import { SYSLOG_FIXTURES } from '../../parser/__tests__/fixtures';

describe('Syslog Parser', () => {
  describe('parseSyslogMessage', () => {
    describe('RFC 3164 format (BSD syslog)', () => {
      it('should parse NGINX access log with priority and TAG', () => {
        // Arrange
        const fixture = SYSLOG_FIXTURES.nginx_access_1;

        // Act
        const result = parseSyslogMessage(fixture.raw_syslog);

        // Assert
        expect(result.facility).toBe(fixture.expected_parsed_syslog.facility);
        expect(result.severity).toBe(fixture.expected_parsed_syslog.severity);
        expect(result.hostname).toBe(fixture.expected_parsed_syslog.hostname);
        expect(result.appName).toBe(fixture.expected_parsed_syslog.appName);
        expect(result.processId).toBe(fixture.expected_parsed_syslog.processId);
        expect(result.message).toBe(fixture.expected_message);
      });

      it('should extract only the message portion after TAG colon', () => {
        // Arrange
        const fixture = SYSLOG_FIXTURES.nginx_access_2;

        // Act
        const result = parseSyslogMessage(fixture.raw_syslog);

        // Assert
        // The raw_message field in the database should contain only the extracted message
        expect(result.message).toBe(fixture.expected_message);
        expect(result.message).not.toContain('test-host');
        expect(result.message).not.toContain('NGINX');
        expect(result.message).not.toContain('<134>');
      });

      it('should parse NGINX error log format', () => {
        // Arrange
        const fixture = SYSLOG_FIXTURES.nginx_error;

        // Act
        const result = parseSyslogMessage(fixture.raw_syslog);

        // Assert
        expect(result.facility).toBe(fixture.expected_parsed_syslog.facility);
        expect(result.severity).toBe(fixture.expected_parsed_syslog.severity);
        expect(result.hostname).toBe(fixture.expected_parsed_syslog.hostname);
        expect(result.appName).toBe(fixture.expected_parsed_syslog.appName);
        expect(result.message).toBe(fixture.expected_message);
      });

      it('should parse minimal NGINX log', () => {
        // Arrange
        const fixture = SYSLOG_FIXTURES.nginx_minimal;

        // Act
        const result = parseSyslogMessage(fixture.raw_syslog);

        // Assert
        expect(result.facility).toBe(fixture.expected_parsed_syslog.facility);
        expect(result.severity).toBe(fixture.expected_parsed_syslog.severity);
        expect(result.hostname).toBe(fixture.expected_parsed_syslog.hostname);
        expect(result.appName).toBe(fixture.expected_parsed_syslog.appName);
        expect(result.message).toBe(fixture.expected_message);
      });

      it('should parse SSH logs with process ID', () => {
        // Arrange
        const fixture = SYSLOG_FIXTURES.ssh_login;

        // Act
        const result = parseSyslogMessage(fixture.raw_syslog);

        // Assert
        expect(result.facility).toBe(fixture.expected_parsed_syslog.facility);
        expect(result.severity).toBe(fixture.expected_parsed_syslog.severity);
        expect(result.hostname).toBe(fixture.expected_parsed_syslog.hostname);
        expect(result.appName).toBe(fixture.expected_parsed_syslog.appName);
        expect(result.processId).toBe(fixture.expected_parsed_syslog.processId);
        expect(result.message).toBe(fixture.expected_message);
      });

      it('should parse sudo logs', () => {
        // Arrange
        const fixture = SYSLOG_FIXTURES.sudo_command;

        // Act
        const result = parseSyslogMessage(fixture.raw_syslog);

        // Assert
        expect(result.facility).toBe(fixture.expected_parsed_syslog.facility);
        expect(result.severity).toBe(fixture.expected_parsed_syslog.severity);
        expect(result.hostname).toBe(fixture.expected_parsed_syslog.hostname);
        expect(result.appName).toBe(fixture.expected_parsed_syslog.appName);
        expect(result.message).toBe(fixture.expected_message);
      });
    });

    describe('Priority (PRI) calculation', () => {
      it('should correctly calculate facility and severity from priority 134', () => {
        // Arrange & Act
        const result = parseSyslogMessage('<134>Dec 09 20:36:20 test-host NGINX: test message');

        // Assert
        // Priority 134 = facility 16 (local0), severity 6 (info)
        // 134 / 8 = 16 (facility), 134 % 8 = 6 (severity)
        expect(result.facility).toBe(16);
        expect(result.severity).toBe(6);
      });

      it('should correctly calculate facility and severity from priority 85', () => {
        // Arrange & Act
        const result = parseSyslogMessage('<85>Dec 09 20:36:20 test-host sshd: test message');

        // Assert
        // Priority 85 = facility 10 (authpriv), severity 5 (notice)
        expect(result.facility).toBe(10);
        expect(result.severity).toBe(5);
      });

      it('should correctly calculate facility and severity from priority 86', () => {
        // Arrange & Act
        const result = parseSyslogMessage('<86>Dec 09 20:36:20 test-host sudo: test message');

        // Assert
        // Priority 86 = facility 10 (authpriv), severity 6 (info)
        expect(result.facility).toBe(10);
        expect(result.severity).toBe(6);
      });
    });

    describe('Timestamp parsing', () => {
      it('should parse BSD syslog timestamp format (RFC 3164)', () => {
        // Arrange & Act
        const result = parseSyslogMessage('<134>Dec 09 20:36:20 test-host NGINX: test message');

        // Assert
        expect(result.timestamp).toBeInstanceOf(Date);
        expect(result.timestamp.getMonth()).toBe(11); // December (0-indexed)
        expect(result.timestamp.getDate()).toBe(9);
        expect(result.timestamp.getHours()).toBe(20);
        expect(result.timestamp.getMinutes()).toBe(36);
        expect(result.timestamp.getSeconds()).toBe(20);
      });

      it('should use current year for BSD syslog timestamp', () => {
        // Arrange & Act
        const result = parseSyslogMessage('<134>Jan 01 00:00:00 test-host NGINX: test message');

        // Assert
        const currentYear = new Date().getFullYear();
        expect(result.timestamp.getFullYear()).toBe(currentYear);
      });

      it('should handle month abbreviations correctly', () => {
        // Arrange
        const months = [
          { abbr: 'Jan', month: 0 },
          { abbr: 'Feb', month: 1 },
          { abbr: 'Mar', month: 2 },
          { abbr: 'Apr', month: 3 },
          { abbr: 'May', month: 4 },
          { abbr: 'Jun', month: 5 },
          { abbr: 'Jul', month: 6 },
          { abbr: 'Aug', month: 7 },
          { abbr: 'Sep', month: 8 },
          { abbr: 'Oct', month: 9 },
          { abbr: 'Nov', month: 10 },
          { abbr: 'Dec', month: 11 },
        ];

        for (const { abbr, month } of months) {
          // Act
          const result = parseSyslogMessage(`<134>${abbr} 15 12:30:45 test-host NGINX: test message`);

          // Assert
          expect(result.timestamp.getMonth()).toBe(month);
        }
      });
    });

    describe('Hostname extraction', () => {
      it('should extract hostname from RFC 3164 format', () => {
        // Arrange & Act
        const result = parseSyslogMessage('<134>Dec 09 20:36:20 myhost NGINX: test message');

        // Assert
        expect(result.hostname).toBe('myhost');
      });

      it('should handle different hostname formats', () => {
        // Arrange
        const hostnames = ['localhost', 'server-01', 'web.example.com', 'host123'];

        for (const hostname of hostnames) {
          // Act
          const result = parseSyslogMessage(`<134>Dec 09 20:36:20 ${hostname} NGINX: test message`);

          // Assert
          expect(result.hostname).toBe(hostname);
        }
      });
    });

    describe('TAG and process ID extraction', () => {
      it('should extract TAG without process ID', () => {
        // Arrange & Act
        const result = parseSyslogMessage('<134>Dec 09 20:36:20 test-host NGINX: test message');

        // Assert
        expect(result.appName).toBe('NGINX');
        expect(result.processId).toBeNull();
      });

      it('should extract TAG with process ID in brackets', () => {
        // Arrange & Act
        const result = parseSyslogMessage('<134>Dec 09 20:36:20 test-host sshd[1234]: test message');

        // Assert
        expect(result.appName).toBe('sshd');
        expect(result.processId).toBe('1234');
      });

      it('should handle multiple digit process IDs', () => {
        // Arrange & Act
        const result = parseSyslogMessage('<134>Dec 09 20:36:20 test-host test[999999]: test message');

        // Assert
        expect(result.appName).toBe('test');
        expect(result.processId).toBe('999999');
      });
    });

    describe('Message extraction', () => {
      it('should extract message after TAG and colon', () => {
        // Arrange
        const testMessage = 'This is the actual log message content';

        // Act
        const result = parseSyslogMessage(`<134>Dec 09 20:36:20 test-host NGINX: ${testMessage}`);

        // Assert
        expect(result.message).toBe(testMessage);
      });

      it('should handle messages with special characters', () => {
        // Arrange
        const specialMessage = 'Error: [ERR_001] Connection failed @ 192.0.2.1 (retry: 3x)';

        // Act
        const result = parseSyslogMessage(`<134>Dec 09 20:36:20 test-host NGINX: ${specialMessage}`);

        // Assert
        expect(result.message).toBe(specialMessage);
      });

      it('should preserve whitespace in message', () => {
        // Arrange
        const messageWithSpaces = '  Multiple   spaces  should  be  preserved  ';

        // Act
        const result = parseSyslogMessage(`<134>Dec 09 20:36:20 test-host NGINX: ${messageWithSpaces}`);

        // Assert
        expect(result.message).toBe(messageWithSpaces);
      });

      it('should handle very long messages', () => {
        // Arrange
        const longMessage = 'A'.repeat(2000);

        // Act
        const result = parseSyslogMessage(`<134>Dec 09 20:36:20 test-host NGINX: ${longMessage}`);

        // Assert
        expect(result.message).toBe(longMessage);
        expect(result.message.length).toBe(2000);
      });
    });

    describe('Error handling', () => {
      it('should handle message without PRI gracefully', () => {
        // Arrange & Act
        const result = parseSyslogMessage('Dec 09 20:36:20 test-host NGINX: test message');

        // Assert
        expect(result.facility).toBeNull();
        expect(result.severity).toBeNull();
        expect(result.hostname).not.toBeNull();
      });

      it('should handle malformed messages gracefully', () => {
        // Arrange & Act
        const result = parseSyslogMessage('completely malformed message');

        // Assert
        // Should return default values without throwing
        expect(result).toHaveProperty('timestamp');
        expect(result).toHaveProperty('facility');
        expect(result).toHaveProperty('severity');
        expect(result).toHaveProperty('hostname');
        expect(result).toHaveProperty('message');
      });

      it('should handle empty string gracefully', () => {
        // Arrange & Act
        const result = parseSyslogMessage('');

        // Assert
        expect(result).toHaveProperty('timestamp');
        expect(result).toHaveProperty('message');
        expect(result.message).toBe('');
      });

      it('should handle null-like input gracefully', () => {
        // This would depend on how the function handles edge cases
        // Arrange & Act
        const result = parseSyslogMessage('\0null character');

        // Assert
        expect(result).toHaveProperty('message');
      });
    });
  });

  describe('Facility name lookup', () => {
    it('should return correct facility name for known facilities', () => {
      expect(getFacilityName(0)).toBe('kern');
      expect(getFacilityName(1)).toBe('user');
      expect(getFacilityName(3)).toBe('daemon');
      expect(getFacilityName(4)).toBe('auth');
      expect(getFacilityName(10)).toBe('authpriv');
      expect(getFacilityName(16)).toBe('local0');
      expect(getFacilityName(23)).toBe('local7');
    });

    it('should return unknown format for unknown facilities', () => {
      expect(getFacilityName(999)).toBe('unknown(999)');
    });
  });

  describe('Severity name lookup', () => {
    it('should return correct severity name for known severities', () => {
      expect(getSeverityName(0)).toBe('emerg');
      expect(getSeverityName(1)).toBe('alert');
      expect(getSeverityName(2)).toBe('crit');
      expect(getSeverityName(3)).toBe('err');
      expect(getSeverityName(4)).toBe('warning');
      expect(getSeverityName(5)).toBe('notice');
      expect(getSeverityName(6)).toBe('info');
      expect(getSeverityName(7)).toBe('debug');
    });

    it('should return unknown format for unknown severities', () => {
      expect(getSeverityName(99)).toBe('unknown(99)');
    });
  });
});
