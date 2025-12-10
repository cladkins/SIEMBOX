/**
 * Regression tests for existing parsers
 * Ensures that adding NGINX parsers doesn't break existing parsers
 */

import { parseSyslogMessage } from '../syslog/syslogParser';
import { SYSLOG_FIXTURES, NEGATIVE_TEST_CASES } from './fixtures';

describe('Parser Regression Tests', () => {
  describe('Existing parser support - SSH', () => {
    it('should correctly parse SSH logs after NGINX parser addition', () => {
      // Arrange
      const fixture = SYSLOG_FIXTURES.ssh_login;

      // Act
      const parsed = parseSyslogMessage(fixture.raw_syslog);

      // Assert
      expect(parsed.facility).toBe(fixture.expected_parsed_syslog.facility);
      expect(parsed.severity).toBe(fixture.expected_parsed_syslog.severity);
      expect(parsed.hostname).toBe(fixture.expected_parsed_syslog.hostname);
      expect(parsed.appName).toBe(fixture.expected_parsed_syslog.appName);
      expect(parsed.processId).toBe(fixture.expected_parsed_syslog.processId);
      expect(parsed.message).toContain('Failed password');
    });

    it('should extract SSH login failure details', () => {
      // Arrange
      const sshLog = '<85>Dec 09 20:36:20 komodo sshd[1234]: Failed password for root from 192.168.1.100 port 52894 ssh2';

      // Act
      const parsed = parseSyslogMessage(sshLog);

      // Assert
      expect(parsed.message).toContain('root');
      expect(parsed.message).toContain('192.168.1.100');
      expect(parsed.processId).toBe('1234');
    });

    it('should handle various SSH messages', () => {
      // Arrange
      const sshMessages = [
        'Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2',
        'Accepted publickey for user from 192.168.1.100 port 54321 ssh2',
        'Invalid user admin from 192.168.1.100 port 54321',
        'Connection closed by authenticating user root 192.168.1.100 port 52894 ssh2',
      ];

      // Act & Assert
      sshMessages.forEach((message) => {
        const testLog = `<85>Dec 09 20:36:20 komodo sshd[1234]: ${message}`;
        const parsed = parseSyslogMessage(testLog);

        expect(parsed.appName).toBe('sshd');
        expect(parsed.message).toBe(message);
      });
    });
  });

  describe('Existing parser support - Sudo', () => {
    it('should correctly parse Sudo logs after NGINX parser addition', () => {
      // Arrange
      const fixture = SYSLOG_FIXTURES.sudo_command;

      // Act
      const parsed = parseSyslogMessage(fixture.raw_syslog);

      // Assert
      expect(parsed.facility).toBe(fixture.expected_parsed_syslog.facility);
      expect(parsed.severity).toBe(fixture.expected_parsed_syslog.severity);
      expect(parsed.hostname).toBe(fixture.expected_parsed_syslog.hostname);
      expect(parsed.appName).toBe(fixture.expected_parsed_syslog.appName);
      expect(parsed.message).toContain('COMMAND');
    });

    it('should extract Sudo command details', () => {
      // Arrange
      const sudoLog = '<86>Dec 09 20:36:20 komodo sudo: root : TTY=pts/0 ; PWD=/home/root ; USER=root ; COMMAND=/bin/ls -la';

      // Act
      const parsed = parseSyslogMessage(sudoLog);

      // Assert
      expect(parsed.message).toContain('root');
      expect(parsed.message).toContain('/bin/ls');
      expect(parsed.message).toContain('COMMAND');
    });

    it('should handle various Sudo messages', () => {
      // Arrange
      const sudoMessages = [
        'admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/rm -rf /tmp/*',
        'user1 : TTY=unknown ; PWD=/ ; USER=root ; COMMAND=/sbin/systemctl restart nginx',
        'john : TTY=pts/1 ; PWD=/var/www ; USER=www-data ; COMMAND=/usr/bin/python script.py',
      ];

      // Act & Assert
      sudoMessages.forEach((message) => {
        const testLog = `<86>Dec 09 20:36:20 komodo sudo: ${message}`;
        const parsed = parseSyslogMessage(testLog);

        expect(parsed.appName).toBe('sudo');
        expect(parsed.message).toBe(message);
      });
    });
  });

  describe('Existing parser support - Apache', () => {
    it('should correctly parse Apache logs after NGINX parser addition', () => {
      // Arrange
      const fixture = SYSLOG_FIXTURES.apache_access;

      // Act
      const parsed = parseSyslogMessage(fixture.raw_syslog);

      // Assert
      expect(parsed.facility).toBe(fixture.expected_parsed_syslog.facility);
      expect(parsed.severity).toBe(fixture.expected_parsed_syslog.severity);
      expect(parsed.hostname).toBe(fixture.expected_parsed_syslog.hostname);
      expect(parsed.appName).toBe(fixture.expected_parsed_syslog.appName);
    });

    it('should extract Apache access log details', () => {
      // Arrange
      const apacheLog = '<134>Dec 09 20:36:20 komodo APACHE: 192.168.1.1 - frank [09/Dec/2025:10:15:30 +0000] "GET /path HTTP/1.0" 200 1043';

      // Act
      const parsed = parseSyslogMessage(apacheLog);

      // Assert
      expect(parsed.message).toContain('192.168.1.1');
      expect(parsed.message).toContain('frank');
      expect(parsed.message).toContain('GET');
    });

    it('should distinguish Apache logs from NGINX logs', () => {
      // Arrange
      const apacheLog = '<134>Dec 09 20:36:20 komodo APACHE: 192.168.1.1 - - [09/Dec/2025:20:36:20 +0000] "GET / HTTP/1.1" 200 1234';
      const nginxLog = '<134>Dec 09 20:36:20 komodo NGINX: [09/Dec/2025:20:35:53 +0000] - 200 200 - GET';

      // Act
      const apacheParsed = parseSyslogMessage(apacheLog);
      const nginxParsed = parseSyslogMessage(nginxLog);

      // Assert
      expect(apacheParsed.appName).toBe('APACHE');
      expect(nginxParsed.appName).toBe('NGINX');
      expect(apacheParsed.message).not.toEqual(nginxParsed.message);
    });
  });

  describe('Syslog parsing stability', () => {
    it('should consistently parse same log the same way', () => {
      // Arrange
      const testLog = '<85>Dec 09 20:36:20 komodo sshd[1234]: Failed password for root from 192.168.1.100 port 52894 ssh2';

      // Act
      const results = Array(10)
        .fill(null)
        .map(() => parseSyslogMessage(testLog));

      // Assert
      const firstResult = results[0];
      results.forEach((result) => {
        expect(result.facility).toBe(firstResult.facility);
        expect(result.severity).toBe(firstResult.severity);
        expect(result.hostname).toBe(firstResult.hostname);
        expect(result.appName).toBe(firstResult.appName);
        expect(result.processId).toBe(firstResult.processId);
        expect(result.message).toBe(firstResult.message);
      });
    });

    it('should handle mixed log types in sequence', () => {
      // Arrange
      const logs = [
        SYSLOG_FIXTURES.nginx_access_1,
        SYSLOG_FIXTURES.ssh_login,
        SYSLOG_FIXTURES.sudo_command,
        SYSLOG_FIXTURES.apache_access,
        SYSLOG_FIXTURES.nginx_error,
      ];

      // Act & Assert
      logs.forEach((fixture) => {
        const parsed = parseSyslogMessage(fixture.raw_syslog);

        // Should not modify state between calls
        expect(parsed.message).toBe(fixture.expected_message);
        expect(parsed.hostname).toBe(fixture.expected_parsed_syslog.hostname);
        expect(parsed.appName).toBe(fixture.expected_parsed_syslog.appName);
      });
    });
  });

  describe('No cross-contamination between parsers', () => {
    it('should not apply NGINX patterns to SSH logs', () => {
      // Arrange
      const sshLog = SYSLOG_FIXTURES.ssh_login;

      // Act
      const parsed = parseSyslogMessage(sshLog.raw_syslog);

      // Assert
      // SSH logs should not be misidentified as NGINX
      expect(parsed.appName).toBe('sshd');
      expect(parsed.appName).not.toBe('NGINX');
      expect(parsed.message).not.toMatch(/^\[\d{2}\/\w+/); // Not NGINX access format
    });

    it('should not apply NGINX patterns to Sudo logs', () => {
      // Arrange
      const sudoLog = SYSLOG_FIXTURES.sudo_command;

      // Act
      const parsed = parseSyslogMessage(sudoLog.raw_syslog);

      // Assert
      expect(parsed.appName).toBe('sudo');
      expect(parsed.appName).not.toBe('NGINX');
      expect(parsed.message).toContain('COMMAND');
    });

    it('should not apply NGINX patterns to Apache logs', () => {
      // Arrange
      const apacheLog = SYSLOG_FIXTURES.apache_access;

      // Act
      const parsed = parseSyslogMessage(apacheLog.raw_syslog);

      // Assert
      expect(parsed.appName).toBe('APACHE');
      expect(parsed.appName).not.toBe('NGINX');
    });
  });

  describe('Backward compatibility', () => {
    it('should maintain RFC 3164 parsing behavior', () => {
      // Arrange
      const rfc3164Logs = [
        '<85>Dec 09 20:36:20 komodo sshd[1234]: test message',
        '<86>Dec 09 20:36:20 komodo sudo: test message',
        '<134>Dec 09 20:36:20 komodo APACHE: test message',
      ];

      // Act & Assert
      rfc3164Logs.forEach((log) => {
        const parsed = parseSyslogMessage(log);

        // All should have extracted hostname, appName, and message
        expect(parsed.hostname).toBe('komodo');
        expect(parsed.appName).toBeTruthy();
        expect(parsed.message).toBeTruthy();
      });
    });

    it('should maintain facility and severity calculation', () => {
      // Arrange
      const priorities = [
        { pri: 85, expectedFacility: 10, expectedSeverity: 5 },
        { pri: 86, expectedFacility: 10, expectedSeverity: 6 },
        { pri: 134, expectedFacility: 16, expectedSeverity: 6 },
      ];

      // Act & Assert
      priorities.forEach(({ pri, expectedFacility, expectedSeverity }) => {
        const log = `<${pri}>Dec 09 20:36:20 komodo test: test message`;
        const parsed = parseSyslogMessage(log);

        expect(parsed.facility).toBe(expectedFacility);
        expect(parsed.severity).toBe(expectedSeverity);
      });
    });
  });

  describe('Load testing with existing parsers', () => {
    it('should handle rapid sequential parsing of mixed log types', () => {
      // Arrange
      const logs = Array(1000)
        .fill(null)
        .map((_, i) => {
          const types = [
            SYSLOG_FIXTURES.nginx_access_1,
            SYSLOG_FIXTURES.ssh_login,
            SYSLOG_FIXTURES.sudo_command,
          ];
          return types[i % types.length];
        });

      // Act
      const startTime = process.hrtime.bigint();

      logs.forEach((fixture) => {
        parseSyslogMessage(fixture.raw_syslog);
      });

      const endTime = process.hrtime.bigint();
      const durationMs = Number(endTime - startTime) / 1_000_000;

      // Assert
      // Should parse 1000 logs in reasonable time
      expect(durationMs).toBeLessThan(200);
    });

    it('should maintain consistency under load', () => {
      // Arrange
      const testLog = SYSLOG_FIXTURES.ssh_login.raw_syslog;
      const iterations = 100;

      // Act
      const results = Array(iterations)
        .fill(null)
        .map(() => parseSyslogMessage(testLog));

      // Assert
      const firstResult = results[0];
      results.forEach((result) => {
        expect(result.facility).toBe(firstResult.facility);
        expect(result.appName).toBe(firstResult.appName);
        expect(result.message).toBe(firstResult.message);
      });
    });
  });
});
