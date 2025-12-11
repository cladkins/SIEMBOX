import { parseSyslogMessage, getFacilityName, getSeverityName } from '../../../src/services/syslog/syslogParser';

describe('syslogParser', () => {
  describe('parseSyslogMessage', () => {
    describe('Basic RFC 3164 Parsing', () => {
      it('should parse standard syslog message with process ID', () => {
        const message = '<134>Dec 09 20:36:20 webserver sshd[1234]: User login successful';
        const result = parseSyslogMessage(message);

        expect(result.facility).toBe(16); // local0 (134 / 8 = 16)
        expect(result.severity).toBe(6);  // info (134 % 8 = 6)
        expect(result.hostname).toBe('webserver');
        expect(result.appName).toBe('sshd');
        expect(result.processId).toBe('1234');
        expect(result.shipperId).toBe(null);
        expect(result.message).toBe('User login successful');
      });

      it('should parse syslog message without process ID', () => {
        const message = '<134>Dec 09 20:36:20 webserver nginx: Request completed';
        const result = parseSyslogMessage(message);

        expect(result.hostname).toBe('webserver');
        expect(result.appName).toBe('nginx');
        expect(result.processId).toBe(null);
        expect(result.shipperId).toBe(null);
        expect(result.message).toBe('Request completed');
      });

      it('should parse syslog message with multi-word app name', () => {
        const message = '<134>Dec 09 20:36:20 authserver Authentik Server: Authentication successful';
        const result = parseSyslogMessage(message);

        expect(result.hostname).toBe('authserver');
        expect(result.appName).toBe('Authentik Server');
        expect(result.processId).toBe(null);
        expect(result.shipperId).toBe(null);
        expect(result.message).toBe('Authentication successful');
      });
    });

    describe('Shipper ID Support (Regression Test for Fix)', () => {
      it('should parse syslog message with shipper ID only', () => {
        const message = '<134>Dec 09 20:36:20 webserver nginx[a1b2c3d4]: GET /api/health 200';
        const result = parseSyslogMessage(message);

        expect(result.hostname).toBe('webserver');
        expect(result.appName).toBe('nginx');
        expect(result.processId).toBe(null);
        expect(result.shipperId).toBe('a1b2c3d4');
        expect(result.message).toBe('GET /api/health 200');
      });

      it('should parse syslog message with both process ID and shipper ID', () => {
        const message = '<134>Dec 09 20:36:20 webserver sshd[1234][a1b2c3d4]: User login from 192.168.1.1';
        const result = parseSyslogMessage(message);

        expect(result.hostname).toBe('webserver');
        expect(result.appName).toBe('sshd');
        expect(result.processId).toBe('1234');
        expect(result.shipperId).toBe('a1b2c3d4');
        expect(result.message).toBe('User login from 192.168.1.1');
      });

      it('should parse multi-word app name with shipper ID', () => {
        const message = '<134>Dec 09 20:36:20 authserver Authentik Server[deadbeef]: OAuth token issued';
        const result = parseSyslogMessage(message);

        expect(result.hostname).toBe('authserver');
        expect(result.appName).toBe('Authentik Server');
        expect(result.processId).toBe(null);
        expect(result.shipperId).toBe('deadbeef');
        expect(result.message).toBe('OAuth token issued');
      });

      it('should parse multi-word app name with process ID and shipper ID', () => {
        const message = '<134>Dec 09 20:36:20 server Custom App[9876][12345678]: Complex log entry';
        const result = parseSyslogMessage(message);

        expect(result.hostname).toBe('server');
        expect(result.appName).toBe('Custom App');
        expect(result.processId).toBe('9876');
        expect(result.shipperId).toBe('12345678');
        expect(result.message).toBe('Complex log entry');
      });
    });

    describe('Message Content with Special Characters', () => {
      it('should handle message with colons', () => {
        const message = '<134>Dec 09 20:36:20 webserver nginx: [09/Dec/2025:20:35:53 +0000] - 200 GET';
        const result = parseSyslogMessage(message);

        expect(result.appName).toBe('nginx');
        expect(result.message).toBe('[09/Dec/2025:20:35:53 +0000] - 200 GET');
      });

      it('should handle message with brackets', () => {
        const message = '<134>Dec 09 20:36:20 webserver app: [ERROR] [component] Failed to connect';
        const result = parseSyslogMessage(message);

        expect(result.appName).toBe('app');
        expect(result.message).toBe('[ERROR] [component] Failed to connect');
      });

      it('should handle message with JSON content', () => {
        const message = '<134>Dec 09 20:36:20 webserver app: {"level":"info","msg":"request completed","status":200}';
        const result = parseSyslogMessage(message);

        expect(result.appName).toBe('app');
        expect(result.message).toBe('{"level":"info","msg":"request completed","status":200}');
      });

      it('should handle message with leading/trailing whitespace', () => {
        const message = '<134>Dec 09 20:36:20 webserver app:   Message with spaces  ';
        const result = parseSyslogMessage(message);

        expect(result.appName).toBe('app');
        // Note: regex \s* after colon strips leading whitespace
        expect(result.message).toBe('Message with spaces  ');
      });

      it('should handle empty message after TAG', () => {
        const message = '<134>Dec 09 20:36:20 webserver app: ';
        const result = parseSyslogMessage(message);

        expect(result.appName).toBe('app');
        expect(result.message).toBe('');
      });
    });

    describe('Complex Real-World Scenarios', () => {
      it('should parse Authentik log with timestamp in message', () => {
        const message = '<134>Dec 09 20:36:20 authserver Authentik Server[a1b2c3d4]: 2025-12-09T20:36:20.123Z [INFO] User authenticated';
        const result = parseSyslogMessage(message);

        expect(result.appName).toBe('Authentik Server');
        expect(result.shipperId).toBe('a1b2c3d4');
        expect(result.message).toBe('2025-12-09T20:36:20.123Z [INFO] User authenticated');
      });

      it('should parse NGINX access log format', () => {
        const message = '<134>Dec 09 20:36:20 webserver nginx[deadbeef]: 192.168.1.1 - - [09/Dec/2025:20:36:20 +0000] "GET /api/logs HTTP/1.1" 200 1234';
        const result = parseSyslogMessage(message);

        expect(result.appName).toBe('nginx');
        expect(result.shipperId).toBe('deadbeef');
        expect(result.message).toBe('192.168.1.1 - - [09/Dec/2025:20:36:20 +0000] "GET /api/logs HTTP/1.1" 200 1234');
      });

      it('should parse Vaultwarden log format', () => {
        const message = '<134>Dec 09 20:36:20 vaultserver vaultwarden[12ab34cd]: [2025-12-09 20:36:20.456][INFO] Token validated for user@example.com';
        const result = parseSyslogMessage(message);

        expect(result.appName).toBe('vaultwarden');
        expect(result.shipperId).toBe('12ab34cd');
        expect(result.message).toBe('[2025-12-09 20:36:20.456][INFO] Token validated for user@example.com');
      });

      it('should parse Docker container log', () => {
        const message = '<134>Dec 09 20:36:20 dockerhost docker[5678]: [container-name] Application started on port 8080';
        const result = parseSyslogMessage(message);

        expect(result.appName).toBe('docker');
        expect(result.processId).toBe('5678');
        expect(result.message).toBe('[container-name] Application started on port 8080');
      });
    });

    describe('RFC 5424 Format', () => {
      it('should parse RFC 5424 format message', () => {
        const message = '<134>1 2025-12-09T20:36:20.123Z webserver app 1234 - - Application started';
        const result = parseSyslogMessage(message);

        expect(result.hostname).toBe('webserver');
        expect(result.appName).toBe('app');
        expect(result.processId).toBe('1234');
        expect(result.message).toBe('Application started');
      });

      it('should parse RFC 5424 format with null values', () => {
        const message = '<134>1 2025-12-09T20:36:20.123Z - - - - - Application started';
        const result = parseSyslogMessage(message);

        expect(result.hostname).toBe(null);
        expect(result.appName).toBe(null);
        expect(result.processId).toBe(null);
        expect(result.message).toBe('Application started');
      });
    });

    describe('Edge Cases and Error Handling', () => {
      it('should handle malformed priority', () => {
        const message = '<abc>Dec 09 20:36:20 webserver app: message';
        const result = parseSyslogMessage(message);

        expect(result.facility).toBe(null);
        expect(result.severity).toBe(null);
        // When priority parsing fails, it still tries to parse the syslog format
        // and extracts the message portion
        expect(result.message).toBe('message');
        expect(result.appName).toBe('app');
      });

      it('should handle message without priority', () => {
        const message = 'Dec 09 20:36:20 webserver app: message';
        const result = parseSyslogMessage(message);

        expect(result.facility).toBe(null);
        expect(result.severity).toBe(null);
      });

      it('should handle message without colon in TAG', () => {
        const message = '<134>Dec 09 20:36:20 webserver app message without colon';
        const result = parseSyslogMessage(message);

        expect(result.message).toContain('message');
      });

      it('should handle very long app names', () => {
        const message = '<134>Dec 09 20:36:20 webserver VeryLongApplicationNameThatExceedsNormalLengths: message';
        const result = parseSyslogMessage(message);

        expect(result.appName).toBe('VeryLongApplicationNameThatExceedsNormalLengths');
        expect(result.message).toBe('message');
      });

      it('should handle 8-digit number (all digits 0-9, valid hex)', () => {
        const message = '<134>Dec 09 20:36:20 webserver app[12345678]: message';
        const result = parseSyslogMessage(message);

        // 12345678 is valid hex (uses digits 0-9 only), so it matches shipper ID pattern
        // This is correct behavior - shipper IDs are 8 hex chars, and 0-9 are valid hex
        expect(result.processId).toBe(null);
        expect(result.shipperId).toBe('12345678');
      });

      it('should handle invalid shipper ID length (not 8 chars)', () => {
        const message = '<134>Dec 09 20:36:20 webserver app[abc]: message';
        const result = parseSyslogMessage(message);

        // Should not match shipper ID pattern
        expect(result.shipperId).toBe(null);
      });
    });

    describe('Facility and Severity Calculations', () => {
      it('should correctly calculate facility and severity for priority 0', () => {
        const message = '<0>Dec 09 20:36:20 webserver app: Emergency message';
        const result = parseSyslogMessage(message);

        expect(result.facility).toBe(0); // kern
        expect(result.severity).toBe(0); // emerg
      });

      it('should correctly calculate facility and severity for priority 191', () => {
        const message = '<191>Dec 09 20:36:20 webserver app: Debug message';
        const result = parseSyslogMessage(message);

        expect(result.facility).toBe(23); // local7 (191 / 8 = 23)
        expect(result.severity).toBe(7);  // debug (191 % 8 = 7)
      });

      it('should correctly calculate facility and severity for local0.info', () => {
        const message = '<134>Dec 09 20:36:20 webserver app: Info message';
        const result = parseSyslogMessage(message);

        expect(result.facility).toBe(16); // local0
        expect(result.severity).toBe(6);  // info
      });
    });
  });

  describe('getFacilityName', () => {
    it('should return correct facility names', () => {
      expect(getFacilityName(0)).toBe('kern');
      expect(getFacilityName(1)).toBe('user');
      expect(getFacilityName(16)).toBe('local0');
      expect(getFacilityName(23)).toBe('local7');
    });

    it('should return unknown for invalid facility', () => {
      expect(getFacilityName(99)).toBe('unknown(99)');
    });
  });

  describe('getSeverityName', () => {
    it('should return correct severity names', () => {
      expect(getSeverityName(0)).toBe('emerg');
      expect(getSeverityName(3)).toBe('err');
      expect(getSeverityName(6)).toBe('info');
      expect(getSeverityName(7)).toBe('debug');
    });

    it('should return unknown for invalid severity', () => {
      expect(getSeverityName(99)).toBe('unknown(99)');
    });
  });

  describe('Regression Tests for Backtracking Bug', () => {
    it('should not fail on messages with multiple optional components', () => {
      // This test specifically addresses the backtracking issue
      const messages = [
        '<134>Dec 09 20:36:20 server app: simple message',
        '<134>Dec 09 20:36:20 server app[1234]: message with pid',
        '<134>Dec 09 20:36:20 server app[deadbeef]: message with shipper',
        '<134>Dec 09 20:36:20 server app[1234][deadbeef]: message with both',
        '<134>Dec 09 20:36:20 server Multi Word App: message',
        '<134>Dec 09 20:36:20 server Multi Word App[abcd1234]: message',
      ];

      messages.forEach(msg => {
        const result = parseSyslogMessage(msg);
        expect(result.message).toBeTruthy();
        expect(result.appName).toBeTruthy();
      });
    });

    it('should handle all Authentik patterns correctly', () => {
      const authentikMessages = [
        '<134>Dec 09 20:36:20 auth Authentik Server: User login',
        '<134>Dec 09 20:36:20 auth Authentik Server[a1b2c3d4]: User login',
        '<134>Dec 09 20:36:20 auth Authentik Server[9999][a1b2c3d4]: User login',
      ];

      authentikMessages.forEach(msg => {
        const result = parseSyslogMessage(msg);
        expect(result.appName).toBe('Authentik Server');
        expect(result.message).toBe('User login');
      });
    });
  });
});
