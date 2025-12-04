#!/usr/bin/env node
/**
 * Direct Parser Insert Script
 *
 * Bypasses migrations and directly inserts Phase 2 parsers into database
 * Run with: npm run direct-insert
 */

import { query } from '../config/database';
import { logger } from '../utils/logger';

const parsers = [
  {
    name: 'nginx-proxy-manager-access',
    description: 'Parses NGINX Proxy Manager access logs for web traffic monitoring and attack detection',
    enabled: true,
    priority: 50,
    parser_type: 'regex',
    pattern: '^(?P<client_ip>[\\d.]+)\\s+-\\s+(?P<remote_user>\\S+)\\s+\\[(?P<timestamp>[^\\]]+)\\]\\s+"(?P<method>\\w+)\\s+(?P<request_uri>\\S+)\\s+HTTP/(?P<http_version>[\\d.]+)"\\s+(?P<status_code>\\d{3})\\s+(?P<body_bytes_sent>\\d+)\\s+"(?P<http_referer>[^"]*)"\\s+"(?P<user_agent>[^"]*)"',
    field_mappings: {
      "client_ip": "client_ip",
      "source_ip": "client_ip",
      "remote_user": "remote_user",
      "timestamp": "timestamp",
      "method": "method",
      "request_uri": "request_uri",
      "path": "request_uri",
      "http_version": "http_version",
      "status_code": "status_code",
      "body_bytes_sent": "body_bytes_sent",
      "http_referer": "http_referer",
      "user_agent": "user_agent",
      "service": "nginx-proxy-manager"
    },
    test_samples: [
      {
        "raw_message": '192.168.1.100 - - [03/Dec/2025:12:34:56 +0000] "GET /api/users HTTP/1.1" 200 1234 "https://example.com/" "Mozilla/5.0"',
        "expected_fields": {
          "client_ip": "192.168.1.100",
          "method": "GET",
          "status_code": "200"
        }
      }
    ]
  },
  {
    name: 'nginx-proxy-manager-error',
    description: 'Parses NGINX Proxy Manager error logs for troubleshooting and security monitoring',
    enabled: true,
    priority: 49,
    parser_type: 'regex',
    pattern: '^(?P<timestamp>\\d{4}/\\d{2}/\\d{2}\\s+\\d{2}:\\d{2}:\\d{2})\\s+\\[(?P<log_level>\\w+)\\]\\s+(?P<message>.*)$',
    field_mappings: {
      "timestamp": "timestamp",
      "log_level": "log_level",
      "severity": "log_level",
      "message": "message",
      "service": "nginx-proxy-manager"
    },
    test_samples: [
      {
        "raw_message": "2025/12/03 12:34:56 [error] 1234#1234: *56789 connect() failed (111: Connection refused) while connecting to upstream",
        "expected_fields": {
          "log_level": "error",
          "message": "1234#1234: *56789 connect() failed (111: Connection refused) while connecting to upstream"
        }
      }
    ]
  },
  {
    name: 'traefik-access',
    description: 'Parses Traefik reverse proxy access logs in JSON format',
    enabled: true,
    priority: 48,
    parser_type: 'json',
    pattern: '',
    field_mappings: {
      "ClientAddr": "client_ip",
      "ClientAddr": "source_ip",
      "RequestMethod": "method",
      "RequestPath": "request_uri",
      "RequestPath": "path",
      "RequestProtocol": "http_version",
      "DownstreamStatus": "status_code",
      "DownstreamContentSize": "body_bytes_sent",
      "RequestRefererHeader": "http_referer",
      "RequestUserAgentHeader": "user_agent",
      "Duration": "duration",
      "service": "traefik"
    },
    test_samples: [
      {
        "raw_message": '{"ClientAddr":"192.168.1.100:54321","RequestMethod":"GET","RequestPath":"/api/data","RequestProtocol":"HTTP/2.0","DownstreamStatus":200,"DownstreamContentSize":1234,"RequestRefererHeader":"https://example.com/","RequestUserAgentHeader":"Mozilla/5.0","Duration":45123456}',
        "expected_fields": {
          "client_ip": "192.168.1.100:54321",
          "method": "GET",
          "status_code": "200",
          "duration": "45"
        }
      }
    ]
  },
  {
    name: 'caddy-access',
    description: 'Parses Caddy web server access logs with JSON format',
    enabled: true,
    priority: 42,
    parser_type: 'json',
    pattern: '',
    field_mappings: {
      "ts": "timestamp",
      "request.client_ip": "client_ip",
      "request.method": "method",
      "request.uri": "request_uri",
      "request.proto": "http_version",
      "status": "status_code",
      "size": "body_bytes_sent",
      "request.headers.Referer[0]": "http_referer",
      "request.headers.User-Agent[0]": "user_agent",
      "duration": "duration",
      "service": "caddy"
    },
    test_samples: [
      {
        "raw_message": '{"ts":1701610496.789,"request":{"client_ip":"192.168.1.100","method":"GET","uri":"/api/data","proto":"HTTP/2.0","headers":{"User-Agent":["Mozilla/5.0"]}},"status":200,"size":1234,"duration":0.045}',
        "expected_fields": {
          "client_ip": "192.168.1.100",
          "method": "GET",
          "status_code": "200"
        }
      }
    ]
  },
  {
    name: 'standard-nginx-access',
    description: 'Parses standard NGINX access logs (combined format)',
    enabled: true,
    priority: 40,
    parser_type: 'regex',
    pattern: '^(?P<client_ip>[\\d.]+)\\s+-\\s+(?P<remote_user>\\S+)\\s+\\[(?P<timestamp>[^\\]]+)\\]\\s+"(?P<method>\\w+)\\s+(?P<request_uri>\\S+)\\s+HTTP/(?P<http_version>[\\d.]+)"\\s+(?P<status_code>\\d{3})\\s+(?P<body_bytes_sent>\\d+)\\s+"(?P<http_referer>[^"]*)"\\s+"(?P<user_agent>[^"]*)"',
    field_mappings: {
      "client_ip": "client_ip",
      "source_ip": "client_ip",
      "remote_user": "remote_user",
      "timestamp": "timestamp",
      "method": "method",
      "request_uri": "request_uri",
      "path": "request_uri",
      "http_version": "http_version",
      "status_code": "status_code",
      "body_bytes_sent": "body_bytes_sent",
      "http_referer": "http_referer",
      "user_agent": "user_agent",
      "service": "nginx"
    },
    test_samples: [
      {
        "raw_message": '192.168.1.100 - - [03/Dec/2025:12:34:56 +0000] "GET /index.html HTTP/1.1" 200 1234 "https://example.com/" "Mozilla/5.0"',
        "expected_fields": {
          "client_ip": "192.168.1.100",
          "method": "GET",
          "status_code": "200"
        }
      }
    ]
  },
  {
    name: 'standard-nginx-error',
    description: 'Parses standard NGINX error logs',
    enabled: true,
    priority: 39,
    parser_type: 'regex',
    pattern: '^(?P<timestamp>\\d{4}/\\d{2}/\\d{2}\\s+\\d{2}:\\d{2}:\\d{2})\\s+\\[(?P<log_level>\\w+)\\]\\s+(?P<message>.*)$',
    field_mappings: {
      "timestamp": "timestamp",
      "log_level": "log_level",
      "severity": "log_level",
      "message": "message",
      "service": "nginx"
    },
    test_samples: [
      {
        "raw_message": "2025/12/03 12:34:56 [error] 1234#1234: *56789 open() \"/var/www/html/test.html\" failed (2: No such file or directory)",
        "expected_fields": {
          "log_level": "error",
          "message": "1234#1234: *56789 open() \"/var/www/html/test.html\" failed (2: No such file or directory)"
        }
      }
    ]
  },
  {
    name: 'authelia-access',
    description: 'Parses Authelia authentication gateway access logs',
    enabled: true,
    priority: 25,
    parser_type: 'regex',
    pattern: '^time="(?P<timestamp>[^"]+)"\\s+level=(?P<log_level>\\w+)\\s+msg="(?P<message>[^"]*)"(?:\\s+method=(?P<method>\\w+))?(?:\\s+path=(?P<path>[^\\s]+))?(?:\\s+remote_ip=(?P<client_ip>[\\d.]+))?(?:\\s+status_code=(?P<status_code>\\d+))?',
    field_mappings: {
      "timestamp": "timestamp",
      "log_level": "log_level",
      "severity": "log_level",
      "message": "message",
      "method": "method",
      "path": "path",
      "request_uri": "path",
      "client_ip": "client_ip",
      "source_ip": "client_ip",
      "status_code": "status_code",
      "service": "authelia"
    },
    test_samples: [
      {
        "raw_message": 'time="2025-12-03T12:34:56Z" level=info msg="Access Log" method=GET path=/api/verify remote_ip=192.168.1.100 status_code=200',
        "expected_fields": {
          "method": "GET",
          "path": "/api/verify",
          "client_ip": "192.168.1.100",
          "status_code": "200"
        }
      }
    ]
  },
  {
    name: 'authentik-audit',
    description: 'Parses Authentik SSO audit logs in JSON format',
    enabled: true,
    priority: 24,
    parser_type: 'json',
    pattern: '',
    field_mappings: {
      "timestamp": "timestamp",
      "event": "event",
      "action": "event",
      "user": "user",
      "username": "user",
      "ip": "client_ip",
      "ip": "source_ip",
      "success": "success",
      "app": "app",
      "service": "authentik"
    },
    test_samples: [
      {
        "raw_message": '{"timestamp":"2025-12-03T12:34:56Z","event":"login","user":"admin","ip":"192.168.1.100","success":true,"app":"admin-ui"}',
        "expected_fields": {
          "event": "login",
          "user": "admin",
          "client_ip": "192.168.1.100",
          "success": "true"
        }
      }
    ]
  },
  {
    name: 'keycloak-event',
    description: 'Parses Keycloak identity provider event logs',
    enabled: true,
    priority: 23,
    parser_type: 'regex',
    pattern: '^(?P<timestamp>\\d{4}-\\d{2}-\\d{2}\\s+\\d{2}:\\d{2}:\\d{2},\\d+)\\s+\\w+\\s+\\[(?P<logger>[^\\]]+)\\].*?type=(?P<event>\\w+).*?(?:realmId=(?P<realm>\\w+))?.*?(?:userId=(?P<user_id>[^,\\s]+))?.*?(?:ipAddress=(?P<client_ip>[\\d.]+))?',
    field_mappings: {
      "timestamp": "timestamp",
      "logger": "logger",
      "event": "event",
      "action": "event",
      "realm": "realm",
      "user_id": "user_id",
      "client_ip": "client_ip",
      "source_ip": "client_ip",
      "service": "keycloak"
    },
    test_samples: [
      {
        "raw_message": "2025-12-03 12:34:56,789 INFO  [org.keycloak.events] type=LOGIN, realmId=master, userId=abc123, ipAddress=192.168.1.100",
        "expected_fields": {
          "event": "LOGIN",
          "realm": "master",
          "user_id": "abc123",
          "client_ip": "192.168.1.100"
        }
      }
    ]
  },
  {
    name: 'nextcloud-access',
    description: 'Parses Nextcloud file sharing and collaboration platform logs',
    enabled: true,
    priority: 35,
    parser_type: 'regex',
    pattern: '^\\[(?P<timestamp>[^\\]]+)\\]\\s+(?P<app>\\w+)\\.(?P<log_level>\\w+):\\s+(?P<message>.+?)\\s+\\{.*?"user":"(?P<user>[^"]*)".*?"url":"(?P<url>[^"]*)".*?"method":"(?P<method>[^"]*)".*?"ip":"(?P<client_ip>[^"]*)"',
    field_mappings: {
      "timestamp": "timestamp",
      "app": "app",
      "log_level": "log_level",
      "severity": "log_level",
      "message": "message",
      "user": "user",
      "url": "url",
      "path": "url",
      "method": "method",
      "client_ip": "client_ip",
      "source_ip": "client_ip",
      "service": "nextcloud"
    },
    test_samples: [
      {
        "raw_message": '[2025-12-03T12:34:56+00:00] webdav.INFO: File accessed {"user":"admin","url":"/remote.php/dav/files/admin/Documents/test.pdf","method":"GET","ip":"192.168.1.100"}',
        "expected_fields": {
          "user": "admin",
          "method": "GET",
          "client_ip": "192.168.1.100"
        }
      }
    ]
  },
  {
    name: 'pihole-query',
    description: 'Parses Pi-hole DNS query logs for network monitoring and ad blocking',
    enabled: true,
    priority: 30,
    parser_type: 'regex',
    pattern: '^(?P<timestamp>\\w{3}\\s+\\d+\\s+\\d{2}:\\d{2}:\\d{2})\\s+dnsmasq\\[\\d+\\]:\\s+(?P<query_type>\\w+)\\s+(?P<domain>[^\\s]+)\\s+(?:is\\s+(?P<result>[^\\s]+))?(?:from\\s+(?P<client_ip>[\\d.]+))?',
    field_mappings: {
      "timestamp": "timestamp",
      "query_type": "query_type",
      "domain": "domain",
      "query": "domain",
      "result": "result",
      "client_ip": "client_ip",
      "source_ip": "client_ip",
      "service": "pihole"
    },
    test_samples: [
      {
        "raw_message": "Dec  3 12:34:56 dnsmasq[1234]: query[A] example.com from 192.168.1.100",
        "expected_fields": {
          "query_type": "query",
          "domain": "example.com",
          "client_ip": "192.168.1.100"
        }
      }
    ]
  }
];

async function insertParsers() {
  try {
    logger.info('Starting direct parser insertion...');

    // Delete existing parsers with these names (idempotent)
    const parserNames = parsers.map(p => `'${p.name}'`).join(', ');
    await query(`DELETE FROM parsers WHERE name IN (${parserNames})`);
    logger.info(`Deleted existing parsers (if any)`);

    // Insert each parser
    for (const parser of parsers) {
      await query(
        `INSERT INTO parsers (name, description, enabled, priority, parser_type, pattern, field_mappings, test_samples, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())`,
        [
          parser.name,
          parser.description,
          parser.enabled,
          parser.priority,
          parser.parser_type,
          parser.pattern,
          JSON.stringify(parser.field_mappings),
          JSON.stringify(parser.test_samples)
        ]
      );
      logger.info(`Inserted parser: ${parser.name}`);
    }

    // Verify
    const result = await query('SELECT COUNT(*) as count FROM parsers');
    logger.info(`Total parsers in database: ${result.rows[0].count}`);

    logger.info('✓ Parser insertion complete');
    process.exit(0);
  } catch (error) {
    logger.error('Failed to insert parsers:', error);
    process.exit(1);
  }
}

if (require.main === module) {
  insertParsers();
}

export { insertParsers };
