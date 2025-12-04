-- Migration: Import Phase 2 Parsers (11 parsers)
-- Date: 2025-12-04
-- Purpose: Import all Phase 2 parsers for reverse proxies, authentication services, and critical applications
-- Reference: docs/parsers/*.md

-- Delete existing parsers if present (for re-runs)
DELETE FROM parsers WHERE name IN (
  'nginx-proxy-manager-access',
  'nginx-proxy-manager-error',
  'traefik-access',
  'caddy-access',
  'nginx-access',
  'nginx-error',
  'authelia-access',
  'authentik-audit',
  'keycloak-events',
  'nextcloud-access',
  'pihole-query'
);

-- ============================================================================
-- REVERSE PROXY PARSERS (6 parsers)
-- Priority: 40-45 (NGINX Proxy Manager highest, Standard NGINX lowest)
-- ============================================================================

-- Parser 1: NGINX Proxy Manager - Access Logs
INSERT INTO parsers (name, description, enabled, priority, parser_type, pattern, field_mappings, test_samples, created_at, updated_at)
VALUES (
  'nginx-proxy-manager-access',
  'Parses NGINX Proxy Manager access logs for web traffic monitoring and attack detection',
  true,
  45,
  'regex',
  '^(?P<client_ip>[\d.]+)\s+-\s+(?P<remote_user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<request_uri>[^\s]+)\s+(?P<http_version>[^"]+)"\s+(?P<status_code>\d+)\s+(?P<body_bytes_sent>\d+)\s+"(?P<http_referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"',
  '{
    "client_ip": "client_ip",
    "source_ip": "client_ip",
    "remote_user": "remote_user",
    "user": "remote_user",
    "timestamp": "timestamp",
    "method": "method",
    "request_uri": "request_uri",
    "path": "request_uri",
    "http_version": "http_version",
    "status_code": "status_code",
    "body_bytes_sent": "body_bytes_sent",
    "http_referer": "http_referer",
    "user_agent": "user_agent",
    "service": "nginx_proxy_manager"
  }',
  '[
    {
      "raw_message": "192.168.1.100 - user@example.com [03/Dec/2025:12:34:56 +0000] \"GET /api/users HTTP/1.1\" 200 1234 \"https://example.com/\" \"Mozilla/5.0\"",
      "expected_fields": {
        "client_ip": "192.168.1.100",
        "remote_user": "user@example.com",
        "method": "GET",
        "request_uri": "/api/users",
        "status_code": "200"
      }
    }
  ]',
  NOW(),
  NOW()
);

-- Parser 2: NGINX Proxy Manager - Error Logs
INSERT INTO parsers (name, description, enabled, priority, parser_type, pattern, field_mappings, test_samples, created_at, updated_at)
VALUES (
  'nginx-proxy-manager-error',
  'Parses NGINX Proxy Manager error logs for backend connection issues and security events',
  true,
  44,
  'regex',
  '^(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?P<log_level>\w+)\]\s+(?P<pid>\d+)#(?P<tid>\d+):\s+(?:\*(?P<connection_id>\d+)\s+)?(?P<message>.+?)(?:,\s+client:\s+(?P<client_ip>[\d.]+))?(?:,\s+server:\s+(?P<server_name>[^,]+))?(?:,\s+request:\s+"(?P<request>[^"]*)")?(?:,\s+upstream:\s+"(?P<upstream>[^"]*)")?',
  '{
    "timestamp": "timestamp",
    "log_level": "log_level",
    "severity": "log_level",
    "pid": "pid",
    "tid": "tid",
    "connection_id": "connection_id",
    "message": "message",
    "client_ip": "client_ip",
    "source_ip": "client_ip",
    "server_name": "server_name",
    "request": "request",
    "upstream": "upstream",
    "service": "nginx_proxy_manager"
  }',
  '[
    {
      "raw_message": "2025/12/03 12:34:56 [error] 1234#0: *567 connect() failed (111: Connection refused) while connecting to upstream, client: 192.168.1.100, server: example.com, request: \"GET /api HTTP/1.1\", upstream: \"http://192.168.1.10:3000/api\"",
      "expected_fields": {
        "log_level": "error",
        "client_ip": "192.168.1.100",
        "server_name": "example.com"
      }
    }
  ]',
  NOW(),
  NOW()
);

-- Parser 3: Traefik - Access Logs
INSERT INTO parsers (name, description, enabled, priority, parser_type, pattern, field_mappings, test_samples, created_at, updated_at)
VALUES (
  'traefik-access',
  'Parses Traefik access logs for reverse proxy traffic monitoring',
  true,
  43,
  'regex',
  '^(?P<client_ip>[\d.]+)\s+-\s+(?P<remote_user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<request_uri>[^\s]+)\s+(?P<http_version>[^"]+)"\s+(?P<status_code>\d+)\s+(?P<body_bytes_sent>\d+)\s+"(?P<http_referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"\s+(?P<request_count>\d+)\s+"(?P<router_name>[^"]*)"\s+"(?P<service_url>[^"]*)"\s+(?P<duration>\d+)ms',
  '{
    "client_ip": "client_ip",
    "source_ip": "client_ip",
    "remote_user": "remote_user",
    "user": "remote_user",
    "timestamp": "timestamp",
    "method": "method",
    "request_uri": "request_uri",
    "path": "request_uri",
    "http_version": "http_version",
    "status_code": "status_code",
    "body_bytes_sent": "body_bytes_sent",
    "http_referer": "http_referer",
    "user_agent": "user_agent",
    "request_count": "request_count",
    "router_name": "router_name",
    "service_url": "service_url",
    "duration": "duration",
    "service": "traefik"
  }',
  '[
    {
      "raw_message": "192.168.1.100 - - [03/Dec/2025:12:34:56 +0000] \"GET /api/data HTTP/1.1\" 200 567 \"-\" \"Mozilla/5.0\" 123 \"web-router\" \"http://backend:3000\" 45ms",
      "expected_fields": {
        "client_ip": "192.168.1.100",
        "method": "GET",
        "status_code": "200",
        "duration": "45"
      }
    }
  ]',
  NOW(),
  NOW()
);

-- Parser 4: Caddy - Access Logs
INSERT INTO parsers (name, description, enabled, priority, parser_type, pattern, field_mappings, test_samples, created_at, updated_at)
VALUES (
  'caddy-access',
  'Parses Caddy web server access logs with JSON format',
  true,
  42,
  'json',
  NULL,
  '{
    "ts": "timestamp",
    "request.client_ip": "client_ip",
    "request.client_ip": "source_ip",
    "request.method": "method",
    "request.uri": "request_uri",
    "request.uri": "path",
    "request.proto": "http_version",
    "status": "status_code",
    "size": "body_bytes_sent",
    "request.headers.Referer[0]": "http_referer",
    "request.headers.User-Agent[0]": "user_agent",
    "duration": "duration",
    "service": "caddy"
  }',
  '[
    {
      "raw_message": "{\"ts\":1701610496.789,\"request\":{\"client_ip\":\"192.168.1.100\",\"method\":\"GET\",\"uri\":\"/api/data\",\"proto\":\"HTTP/2.0\",\"headers\":{\"User-Agent\":[\"Mozilla/5.0\"]}},\"status\":200,\"size\":1234,\"duration\":0.045}",
      "expected_fields": {
        "client_ip": "192.168.1.100",
        "method": "GET",
        "status_code": "200"
      }
    }
  ]',
  NOW(),
  NOW()
);

-- Parser 5: Standard NGINX - Access Logs
INSERT INTO parsers (name, description, enabled, priority, parser_type, pattern, field_mappings, test_samples, created_at, updated_at)
VALUES (
  'nginx-access',
  'Parses standard NGINX access logs in combined format',
  true,
  41,
  'regex',
  '^(?P<client_ip>[\d.]+)\s+-\s+(?P<remote_user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<request_uri>[^\s]+)\s+(?P<http_version>[^"]+)"\s+(?P<status_code>\d+)\s+(?P<body_bytes_sent>\d+)\s+"(?P<http_referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"',
  '{
    "client_ip": "client_ip",
    "source_ip": "client_ip",
    "remote_user": "remote_user",
    "user": "remote_user",
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
  }',
  '[
    {
      "raw_message": "192.168.1.100 - - [03/Dec/2025:12:34:56 +0000] \"GET /index.html HTTP/1.1\" 200 615 \"-\" \"Mozilla/5.0\"",
      "expected_fields": {
        "client_ip": "192.168.1.100",
        "method": "GET",
        "status_code": "200"
      }
    }
  ]',
  NOW(),
  NOW()
);

-- Parser 6: Standard NGINX - Error Logs
INSERT INTO parsers (name, description, enabled, priority, parser_type, pattern, field_mappings, test_samples, created_at, updated_at)
VALUES (
  'nginx-error',
  'Parses standard NGINX error logs',
  true,
  40,
  'regex',
  '^(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?P<log_level>\w+)\]\s+(?P<pid>\d+)#(?P<tid>\d+):\s+(?:\*(?P<connection_id>\d+)\s+)?(?P<message>.+?)(?:,\s+client:\s+(?P<client_ip>[\d.]+))?',
  '{
    "timestamp": "timestamp",
    "log_level": "log_level",
    "severity": "log_level",
    "pid": "pid",
    "tid": "tid",
    "connection_id": "connection_id",
    "message": "message",
    "client_ip": "client_ip",
    "source_ip": "client_ip",
    "service": "nginx"
  }',
  '[
    {
      "raw_message": "2025/12/03 12:34:56 [error] 1234#0: *567 open() \"/var/www/html/favicon.ico\" failed (2: No such file or directory), client: 192.168.1.100",
      "expected_fields": {
        "log_level": "error",
        "client_ip": "192.168.1.100"
      }
    }
  ]',
  NOW(),
  NOW()
);

-- ============================================================================
-- AUTHENTICATION SERVICE PARSERS (3 parsers)
-- Priority: 50-52 (Higher than reverse proxies - authentication is critical)
-- ============================================================================

-- Parser 7: Authelia - Access Logs
INSERT INTO parsers (name, description, enabled, priority, parser_type, pattern, field_mappings, test_samples, created_at, updated_at)
VALUES (
  'authelia-access',
  'Parses Authelia authentication service logs with JSON format',
  true,
  52,
  'json',
  NULL,
  '{
    "time": "timestamp",
    "level": "log_level",
    "level": "severity",
    "msg": "message",
    "remote_ip": "client_ip",
    "remote_ip": "source_ip",
    "method": "method",
    "path": "path",
    "status_code": "status_code",
    "username": "user",
    "service": "authelia"
  }',
  '[
    {
      "raw_message": "{\"time\":\"2025-12-03T12:34:56Z\",\"level\":\"info\",\"msg\":\"Access Log\",\"remote_ip\":\"192.168.1.100\",\"method\":\"POST\",\"path\":\"/api/verify\",\"status_code\":200,\"username\":\"admin\"}",
      "expected_fields": {
        "client_ip": "192.168.1.100",
        "user": "admin",
        "status_code": "200"
      }
    }
  ]',
  NOW(),
  NOW()
);

-- Parser 8: Authentik - Audit Logs
INSERT INTO parsers (name, description, enabled, priority, parser_type, pattern, field_mappings, test_samples, created_at, updated_at)
VALUES (
  'authentik-audit',
  'Parses Authentik SSO audit logs with JSON format',
  true,
  51,
  'json',
  NULL,
  '{
    "timestamp": "timestamp",
    "event": "event",
    "user.username": "user",
    "user.email": "email",
    "client_ip": "client_ip",
    "client_ip": "source_ip",
    "action": "action",
    "result": "result",
    "app": "app",
    "service": "authentik"
  }',
  '[
    {
      "raw_message": "{\"timestamp\":\"2025-12-03T12:34:56Z\",\"event\":\"login\",\"user\":{\"username\":\"admin\",\"email\":\"admin@example.com\"},\"client_ip\":\"192.168.1.100\",\"action\":\"authentication\",\"result\":\"success\",\"app\":\"default\"}",
      "expected_fields": {
        "user": "admin",
        "email": "admin@example.com",
        "client_ip": "192.168.1.100",
        "event": "login"
      }
    }
  ]',
  NOW(),
  NOW()
);

-- Parser 9: Keycloak - Event Logs
INSERT INTO parsers (name, description, enabled, priority, parser_type, pattern, field_mappings, test_samples, created_at, updated_at)
VALUES (
  'keycloak-events',
  'Parses Keycloak SSO event logs with JSON format',
  true,
  50,
  'json',
  NULL,
  '{
    "time": "timestamp",
    "type": "event",
    "realmId": "realm",
    "clientId": "client_id",
    "userId": "user_id",
    "ipAddress": "client_ip",
    "ipAddress": "source_ip",
    "error": "error",
    "details.username": "user",
    "service": "keycloak"
  }',
  '[
    {
      "raw_message": "{\"time\":1701610496789,\"type\":\"LOGIN\",\"realmId\":\"master\",\"clientId\":\"security-admin-console\",\"userId\":\"abc123\",\"ipAddress\":\"192.168.1.100\",\"details\":{\"username\":\"admin\"}}",
      "expected_fields": {
        "event": "LOGIN",
        "user": "admin",
        "client_ip": "192.168.1.100"
      }
    }
  ]',
  NOW(),
  NOW()
);

-- ============================================================================
-- CRITICAL APPLICATION PARSERS (2 parsers)
-- Priority: 30-35 (Lower than auth, but still important)
-- Note: Vaultwarden (priority 55) already exists from migration 005
-- ============================================================================

-- Parser 10: Nextcloud - Access Logs
INSERT INTO parsers (name, description, enabled, priority, parser_type, pattern, field_mappings, test_samples, created_at, updated_at)
VALUES (
  'nextcloud-access',
  'Parses Nextcloud file sharing and collaboration platform logs',
  true,
  35,
  'regex',
  '^\[(?P<timestamp>[^\]]+)\]\s+(?P<app>\w+)\\.(?P<log_level>\w+):\s+(?P<message>.+?)\s+\{.*?"user":"(?P<user>[^"]*)".*?"url":"(?P<url>[^"]*)".*?"method":"(?P<method>[^"]*)".*?"ip":"(?P<client_ip>[^"]*)"',
  '{
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
  }',
  '[
    {
      "raw_message": "[2025-12-03T12:34:56+00:00] webdav.INFO: File accessed {\"user\":\"admin\",\"url\":\"/remote.php/dav/files/admin/Documents/test.pdf\",\"method\":\"GET\",\"ip\":\"192.168.1.100\"}",
      "expected_fields": {
        "user": "admin",
        "method": "GET",
        "client_ip": "192.168.1.100"
      }
    }
  ]',
  NOW(),
  NOW()
);

-- Parser 11: Pi-hole - Query Logs
INSERT INTO parsers (name, description, enabled, priority, parser_type, pattern, field_mappings, test_samples, created_at, updated_at)
VALUES (
  'pihole-query',
  'Parses Pi-hole DNS query logs for network monitoring and ad blocking',
  true,
  30,
  'regex',
  '^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+dnsmasq\[\d+\]:\s+(?P<query_type>\w+)\s+(?P<domain>[^\s]+)\s+(?:is\s+(?P<result>[^\s]+))?(?:from\s+(?P<client_ip>[\d.]+))?',
  '{
    "timestamp": "timestamp",
    "query_type": "query_type",
    "domain": "domain",
    "query": "domain",
    "result": "result",
    "client_ip": "client_ip",
    "source_ip": "client_ip",
    "service": "pihole"
  }',
  '[
    {
      "raw_message": "Dec  3 12:34:56 dnsmasq[1234]: query[A] example.com from 192.168.1.100",
      "expected_fields": {
        "query_type": "query",
        "domain": "example.com",
        "client_ip": "192.168.1.100"
      }
    }
  ]',
  NOW(),
  NOW()
);

-- ============================================================================
-- Verification
-- ============================================================================

-- Display imported parsers
SELECT
  id,
  name,
  priority,
  enabled,
  parser_type,
  description
FROM parsers
ORDER BY priority DESC, name;

-- Count total parsers
SELECT COUNT(*) as total_parsers FROM parsers;
