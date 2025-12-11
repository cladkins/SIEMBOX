-- SIEMBox Seed Data
-- Default admin user and sample parsers/rules

-- Create default admin user
-- Username: admin
-- Password: changeme (MUST be changed after first login)
-- Hashed password: $2b$10$YourHashedPasswordHere (placeholder - will be generated properly)
INSERT INTO users (username, email, password_hash, role)
VALUES ('admin', 'admin@siembox.local', '$2b$10$placeholder', 'admin')
ON CONFLICT (username) DO NOTHING;

-- Built-in Parser: SSH Authentication Logs
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, event_type, enabled)
VALUES (
    'SSH Authentication',
    'Parses SSH authentication logs (success and failure)',
    'regex',
    10,
    '^(?<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?<hostname>\S+)\s+sshd\[(?<pid>\d+)\]:\s+(?<event>Failed password|Accepted password|Accepted publickey)\s+for\s+(?<user>\S+)\s+from\s+(?<src_ip>[\d.]+)\s+port\s+(?<src_port>\d+)',
    '{"timestamp": "timestamp", "hostname": "hostname", "pid": "pid", "event": "event", "user": "user", "source_ip": "src_ip", "source_port": "src_port"}',
    'ssh_auth',
    true
)
ON CONFLICT (name) DO NOTHING;

-- Built-in Parser: Apache/Nginx Access Logs
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, event_type, enabled)
VALUES (
    'Apache/Nginx Access Log',
    'Parses standard Apache/Nginx access logs',
    'regex',
    20,
    '^(?<client_ip>[\d.]+)\s+-\s+-\s+\[(?<timestamp>[^\]]+)\]\s+"(?<method>\S+)\s+(?<path>\S+)\s+(?<protocol>[^"]+)"\s+(?<status>\d+)\s+(?<size>\d+)',
    '{"client_ip": "client_ip", "timestamp": "timestamp", "method": "method", "path": "path", "protocol": "protocol", "status_code": "status", "response_size": "size"}',
    'http_request',
    true
)
ON CONFLICT (name) DO NOTHING;

-- Built-in Parser: Linux Sudo Commands
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, event_type, enabled)
VALUES (
    'Linux Sudo',
    'Parses sudo command execution logs',
    'regex',
    15,
    '^(?<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?<hostname>\S+)\s+sudo:\s+(?<user>\S+)\s+:\s+TTY=(?<tty>\S+)\s+;\s+PWD=(?<pwd>\S+)\s+;\s+USER=(?<target_user>\S+)\s+;\s+COMMAND=(?<command>.+)$',
    '{"timestamp": "timestamp", "hostname": "hostname", "user": "user", "tty": "tty", "working_dir": "pwd", "target_user": "target_user", "command": "command"}',
    'sudo_command',
    true
)
ON CONFLICT (name) DO NOTHING;

-- Built-in Parser: Generic Syslog
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, event_type, enabled)
VALUES (
    'Generic Syslog',
    'Fallback parser for standard syslog format',
    'regex',
    1000,
    '^(?<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?<hostname>\S+)\s+(?<process>\S+?)(?:\[(?<pid>\d+)\])?:\s+(?<message>.+)$',
    '{"timestamp": "timestamp", "hostname": "hostname", "process": "process", "pid": "pid", "message": "message"}',
    'generic',
    true
)
ON CONFLICT (name) DO NOTHING;

-- Built-in Parser: JSON Logs
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, event_type, enabled)
VALUES (
    'JSON Parser',
    'Parses logs already in JSON format',
    'json',
    50,
    '.*',
    '{}',
    'json_log',
    true
)
ON CONFLICT (name) DO NOTHING;

-- ============================================================================
-- PHASE 2 PARSERS: Reverse Proxy and Application Parsers
-- ============================================================================

-- Phase 2 Parser: NGINX Proxy Manager - Access Logs
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, event_type, enabled)
VALUES (
    'nginx-proxy-manager-access',
    'Parses NGINX Proxy Manager access logs for web traffic monitoring and attack detection',
    'regex',
    50,
    '^(?<client_ip>[\d.]+)\s+-\s+(?<remote_user>\S+)\s+\[(?<timestamp>[^\]]+)\]\s+"(?<method>\w+)\s+(?<request_uri>\S+)\s+HTTP/(?<http_version>[\d.]+)"\s+(?<status_code>\d{3})\s+(?<body_bytes_sent>\d+)\s+"(?<http_referer>[^"]*)"\s+"(?<user_agent>[^"]*)"',
    '{"client_ip": "client_ip", "remote_user": "remote_user", "timestamp": "timestamp", "method": "method", "request_uri": "request_uri", "http_version": "http_version", "status_code": "status_code", "body_bytes_sent": "body_bytes_sent", "http_referer": "http_referer", "user_agent": "user_agent", "service": "nginx-proxy-manager"}',
    'http_request',
    true
)
ON CONFLICT (name) DO NOTHING;

-- Phase 2 Parser: NGINX Proxy Manager - Error Logs
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, event_type, enabled)
VALUES (
    'nginx-proxy-manager-error',
    'Parses NGINX Proxy Manager error logs for troubleshooting and security monitoring',
    'regex',
    49,
    '^(?<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?<log_level>\w+)\]\s+(?<message>.*)$',
    '{"timestamp": "timestamp", "log_level": "log_level", "message": "message", "service": "nginx-proxy-manager"}',
    'nginx_error',
    true
)
ON CONFLICT (name) DO NOTHING;

-- Phase 2 Parser: Traefik - Access Logs (JSON)
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, event_type, enabled)
VALUES (
    'traefik-access',
    'Parses Traefik reverse proxy access logs in JSON format',
    'json',
    48,
    '',
    '{"ClientAddr": "client_ip", "RequestMethod": "method", "RequestPath": "request_uri", "RequestProtocol": "http_version", "DownstreamStatus": "status_code", "DownstreamContentSize": "body_bytes_sent", "RequestRefererHeader": "http_referer", "RequestUserAgentHeader": "user_agent", "Duration": "duration", "service": "traefik"}',
    'http_request',
    true
)
ON CONFLICT (name) DO NOTHING;

-- Phase 2 Parser: Caddy - Access Logs (JSON)
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, event_type, enabled)
VALUES (
    'caddy-access',
    'Parses Caddy web server access logs with JSON format',
    'json',
    42,
    '',
    '{"ts": "timestamp", "request.client_ip": "client_ip", "request.method": "method", "request.uri": "request_uri", "request.proto": "http_version", "status": "status_code", "size": "body_bytes_sent", "request.headers.Referer[0]": "http_referer", "request.headers.User-Agent[0]": "user_agent", "duration": "duration", "service": "caddy"}',
    'http_request',
    true
)
ON CONFLICT (name) DO NOTHING;

-- Phase 2 Parser: Standard NGINX - Access Logs
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, event_type, enabled)
VALUES (
    'standard-nginx-access',
    'Parses standard NGINX access logs (combined format)',
    'regex',
    40,
    '^(?<client_ip>[\d.]+)\s+-\s+(?<remote_user>\S+)\s+\[(?<timestamp>[^\]]+)\]\s+"(?<method>\w+)\s+(?<request_uri>\S+)\s+HTTP/(?<http_version>[\d.]+)"\s+(?<status_code>\d{3})\s+(?<body_bytes_sent>\d+)\s+"(?<http_referer>[^"]*)"\s+"(?<user_agent>[^"]*)"',
    '{"client_ip": "client_ip", "remote_user": "remote_user", "timestamp": "timestamp", "method": "method", "request_uri": "request_uri", "http_version": "http_version", "status_code": "status_code", "body_bytes_sent": "body_bytes_sent", "http_referer": "http_referer", "user_agent": "user_agent", "service": "nginx"}',
    'http_request',
    true
)
ON CONFLICT (name) DO NOTHING;

-- Phase 2 Parser: Standard NGINX - Error Logs
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, event_type, enabled)
VALUES (
    'standard-nginx-error',
    'Parses standard NGINX error logs',
    'regex',
    39,
    '^(?<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?<log_level>\w+)\]\s+(?<message>.*)$',
    '{"timestamp": "timestamp", "log_level": "log_level", "message": "message", "service": "nginx"}',
    'nginx_error',
    true
)
ON CONFLICT (name) DO NOTHING;

-- Phase 2 Parser: NGINX Komodo - Timestamp-First Access Logs
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, event_type, enabled)
VALUES (
    'nginx-komodo-timestamp-first',
    'Parses custom NGINX access logs from komodo that start with timestamp',
    'regex',
    45,
    '^\[(?<timestamp>[^\]]+)\]\s+(?:-\s+)?(?<status_code1>\d{3})?\s*(?<status_code2>\d{3})?\s*-?\s*(?<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)?\s*(?<protocol>https?|wss?)?\s*(?<request_uri>\S+)?',
    '{"timestamp": "timestamp", "status_code": "status_code1", "upstream_status": "status_code2", "method": "method", "protocol": "protocol", "request_uri": "request_uri", "service": "nginx-komodo"}',
    'http_request',
    true
)
ON CONFLICT (name) DO NOTHING;

-- Phase 2 Parser: NGINX Komodo - Error Logs
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, event_type, enabled)
VALUES (
    'nginx-komodo-error',
    'Parses NGINX error logs from komodo system',
    'regex',
    44,
    '^(?<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?<log_level>\w+)\]\s+(?<pid>\d+)#(?<worker_id>\d+):\s+\*(?<connection_id>\d+)\s*(?<message>.*)?',
    '{"timestamp": "timestamp", "log_level": "log_level", "pid": "pid", "worker_id": "worker_id", "connection_id": "connection_id", "message": "error_message", "service": "nginx-komodo"}',
    'nginx_error',
    true
)
ON CONFLICT (name) DO NOTHING;

-- Phase 2 Parser: NGINX Komodo - IP-Only Minimal Format
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, event_type, enabled)
VALUES (
    'nginx-komodo-ip-only',
    'Parses minimal NGINX access logs from komodo with only IP address',
    'regex',
    43,
    '^(?<client_ip>[\d.]+)\s+-\s*(?<message>.*)?',
    '{"client_ip": "client_ip", "message": "message", "service": "nginx-komodo"}',
    true
)
ON CONFLICT (name) DO NOTHING;

-- Phase 2 Parser: Authelia - Access Logs
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, event_type, enabled)
VALUES (
    'authelia-access',
    'Parses Authelia authentication gateway access logs',
    'regex',
    25,
    '^time="(?<timestamp>[^"]+)"\s+level=(?<log_level>\w+)\s+msg="(?<message>[^"]*)"(?:\s+method=(?<method>\w+))?(?:\s+path=(?<path>[^\s]+))?(?:\s+remote_ip=(?<client_ip>[\d.]+))?(?:\s+status_code=(?<status_code>\d+))?',
    '{"timestamp": "timestamp", "log_level": "log_level", "message": "message", "method": "method", "path": "path", "client_ip": "client_ip", "status_code": "status_code", "service": "authelia"}',
    'authelia_auth',
    true
)
ON CONFLICT (name) DO NOTHING;

-- Phase 2 Parser: Authentik - Audit Logs (JSON)
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, event_type, enabled)
VALUES (
    'authentik-audit',
    'Parses Authentik SSO audit logs in JSON format',
    'json',
    24,
    '',
    '{"timestamp": "timestamp", "event": "event", "user": "user", "ip": "client_ip", "success": "success", "app": "app", "service": "authentik"}',
    'authentik_audit',
    true
)
ON CONFLICT (name) DO NOTHING;

-- Phase 2 Parser: Keycloak - Event Logs
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, event_type, enabled)
VALUES (
    'keycloak-event',
    'Parses Keycloak identity provider event logs',
    'regex',
    23,
    '^(?<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d+)\s+\w+\s+\[(?<logger>[^\]]+)\].*?type=(?<event>\w+).*?(?:realmId=(?<realm>\w+))?.*?(?:userId=(?<user_id>[^,\s]+))?.*?(?:ipAddress=(?<client_ip>[\d.]+))?',
    '{"timestamp": "timestamp", "logger": "logger", "event": "event", "realm": "realm", "user_id": "user_id", "client_ip": "client_ip", "service": "keycloak"}',
    'keycloak_event',
    true
)
ON CONFLICT (name) DO NOTHING;

-- Phase 2 Parser: Nextcloud - Access Logs
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, event_type, enabled)
VALUES (
    'nextcloud-access',
    'Parses Nextcloud file sharing and collaboration platform logs',
    'regex',
    35,
    '^\[(?<timestamp>[^\]]+)\]\s+(?<app>\w+)\.(?<log_level>\w+):\s+(?<message>.+?)\s+\{.*?"user":"(?<user>[^"]*)".*?"url":"(?<url>[^"]*)".*?"method":"(?<method>[^"]*)".*?"ip":"(?<client_ip>[^"]*)"',
    '{"timestamp": "timestamp", "app": "app", "log_level": "log_level", "message": "message", "user": "user", "url": "url", "method": "method", "client_ip": "client_ip", "service": "nextcloud"}',
    'nextcloud_access',
    true
)
ON CONFLICT (name) DO NOTHING;

-- Phase 2 Parser: Pi-hole - Query Logs
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, event_type, enabled)
VALUES (
    'pihole-query',
    'Parses Pi-hole DNS query logs for network monitoring and ad blocking',
    'regex',
    30,
    '^(?<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+dnsmasq\[\d+\]:\s+(?<query_type>\w+)\s+(?<domain>[^\s]+)\s+(?:is\s+(?<result>[^\s]+))?(?:from\s+(?<client_ip>[\d.]+))?',
    '{"timestamp": "timestamp", "query_type": "query_type", "domain": "domain", "result": "result", "client_ip": "client_ip", "service": "pihole"}',
    'dns_query',
    true
)
ON CONFLICT (name) DO NOTHING;

-- Phase 2 Parser: Vaultwarden - Authentication and Vault Access
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, test_samples, event_type, enabled)
VALUES (
    'vaultwarden-access',
    'Parses Vaultwarden authentication and vault access logs for critical security monitoring',
    'regex',
    55,
    '^\[(?<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\]\[(?<module>[^\]]+)\]\[(?<log_level>\w+)\]\s+(?<message>(?:(?!(?:\s+(?:for|from(?:\s+IP:)?|by)\s+|,\s+(?:Email|Device):)).)+?)(?:\s+for\s+(?<user_email>\S+))?(?:\s+by\s+(?<admin_email>\S+)\s+from\s+(?<admin_ip>[\d.]+)|(?:\s+from\s+(?:IP:\s+)?(?<client_ip>[\d.]+)(?:,\s+Email:\s+(?<login_email>\S+))?))(?:,\s+Device:\s+(?<device>[^,]+))?$',
    '{"timestamp": "timestamp", "module": "module", "log_level": "log_level", "message": "message", "client_ip": "client_ip", "source_ip": "client_ip", "user_email": "email", "login_email": "email", "email": "email", "user": "email", "admin_email": "admin_email", "admin_ip": "admin_ip", "device": "device", "service": "vaultwarden", "action": "message", "event": "message"}',
    '[{"raw_message": "[2025-12-03 12:34:56.789][vaultwarden::api::identity][WARN] Failed login attempt from IP: 192.0.2.100, Email: admin@example.com", "expected_fields": {"timestamp": "2025-12-03 12:34:56.789", "module": "vaultwarden::api::identity", "log_level": "WARN", "message": "Failed login attempt", "client_ip": "192.0.2.100", "source_ip": "192.0.2.100", "email": "admin@example.com", "user": "admin@example.com", "service": "vaultwarden"}}, {"raw_message": "[2025-12-03 12:35:10.123][vaultwarden::api::identity][INFO] Successful login from IP: 192.0.2.100, Email: admin@example.com", "expected_fields": {"timestamp": "2025-12-03 12:35:10.123", "module": "vaultwarden::api::identity", "log_level": "INFO", "message": "Successful login", "client_ip": "192.0.2.100", "source_ip": "192.0.2.100", "email": "admin@example.com", "user": "admin@example.com", "service": "vaultwarden"}}, {"raw_message": "[2025-12-03 12:36:22.456][vaultwarden::api::core][INFO] Vault accessed by admin@example.com from 192.0.2.100", "expected_fields": {"timestamp": "2025-12-03 12:36:22.456", "module": "vaultwarden::api::core", "log_level": "INFO", "message": "Vault accessed", "admin_email": "admin@example.com", "admin_ip": "192.0.2.100", "service": "vaultwarden"}}, {"raw_message": "[2025-12-03 12:40:00.678][vaultwarden::api::identity][INFO] New device registered for admin@example.com from 192.0.2.100, Device: Chrome/Desktop", "expected_fields": {"timestamp": "2025-12-03 12:40:00.678", "module": "vaultwarden::api::identity", "log_level": "INFO", "message": "New device registered", "client_ip": "192.0.2.100", "source_ip": "192.0.2.100", "email": "admin@example.com", "user": "admin@example.com", "device": "Chrome/Desktop", "service": "vaultwarden", "event": "device_registered"}}]',
    'vaultwarden_event',
    true
)
ON CONFLICT (name) DO NOTHING;

-- Phase 2 Parser: UniFi - Firewall Logs
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, test_samples, enabled)
VALUES (
    'unifi-firewall',
    'Parses Ubiquiti UniFi (UCG-Max) firewall rule logs for network security monitoring',
    'regex',
    50,
    '\[(?<rule_name>[^\]]+)\].*?DESCR="(?<rule_description>[^"]+)".*?IN=(?<in_interface>\S+).*?OUT=(?<out_interface>\S*).*?SRC=(?<source_ip>[\d\.]+).*?DST=(?<dest_ip>[\d\.]+).*?PROTO=(?<protocol>\w+)',
    '{"rule_name": "rule_name", "rule_description": "rule_description", "in_interface": "in_interface", "out_interface": "out_interface", "source_ip": "source_ip", "client_ip": "source_ip", "dest_ip": "dest_ip", "destination_ip": "dest_ip", "protocol": "protocol", "service": "unifi-firewall"}',
    '[{"raw_message": "<13>Nov 29 19:44:35 UCG-Max [LAN_LOCAL-RET-2147483647] DESCR=\"no rule description\" IN=br0 OUT= MAC=01:00:5e:00:00:fb:5e:07:7d:96:02:d7:08:00 SRC=192.0.2.158 DST=224.0.0.251 LEN=473 TOS=00 PREC=0x00 TTL=255 ID=62191 PROTO=UDP SPT=5353 DPT=5353 LEN=453 MARK=1a0000", "expected_fields": {"rule_name": "LAN_LOCAL-RET-2147483647", "rule_description": "no rule description", "in_interface": "br0", "out_interface": "", "source_ip": "192.0.2.158", "client_ip": "192.0.2.158", "dest_ip": "224.0.0.251", "destination_ip": "224.0.0.251", "protocol": "UDP", "service": "unifi-firewall"}}, {"raw_message": "<12>Nov 29 20:15:42 UCG-Max [WAN_IN-DROP-4000] DESCR=\"Block external traffic\" IN=eth4 OUT=br0 SRC=203.0.113.50 DST=192.0.2.100 PROTO=TCP SPT=443 DPT=80", "expected_fields": {"rule_name": "WAN_IN-DROP-4000", "rule_description": "Block external traffic", "in_interface": "eth4", "out_interface": "br0", "source_ip": "203.0.113.50", "client_ip": "203.0.113.50", "dest_ip": "192.0.2.100", "destination_ip": "192.0.2.100", "protocol": "TCP", "service": "unifi-firewall"}}]',
    'firewall_event',
    true
)
ON CONFLICT (name) DO NOTHING;

-- Phase 2 Parser: UniFi - IDS/IPS Logs
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, test_samples, event_type, enabled)
VALUES (
    'unifi-idsips',
    'Parses Ubiquiti UniFi IDS/IPS daemon event logs for intrusion detection and prevention',
    'regex',
    50,
    'ubnt-idsips-daemon\[\d+\]:\s+[\d-]+T[\d:.-]+\s+(?<severity>\w+):\s+(?<event_type>.+?):\s+ipset\[(?<action_type>\w+)\]\s+(?<action>\w+)\s+failed\s+ip1:(?<external_ip>[\d.]+),\s+port1:(?<external_port>\d+),\s+ip2:(?<internal_ip>[\d.]+),\s+port2:(?<internal_port>\d+),\s+proto:(?<protocol>\w+)',
    '{"severity": "severity", "log_level": "severity", "event_type": "event_type", "action_type": "action_type", "action": "action", "external_ip": "external_ip", "source_ip": "external_ip", "client_ip": "external_ip", "external_port": "external_port", "source_port": "external_port", "internal_ip": "internal_ip", "dest_ip": "internal_ip", "destination_ip": "internal_ip", "internal_port": "internal_port", "dest_port": "internal_port", "protocol": "protocol", "service": "unifi-idsips"}',
    '[{"raw_message": "<28>Nov 29 15:51:19 UCG-Max UCG-Max ubnt-idsips-daemon[2402]: 2025-11-29T15:51:19.543-0600 Warn: error handling event: ipset[ips] add failed ip1:198.51.100.179, port1:52686, ip2:192.0.2.194, port2:80, proto:tcp, err1:ipset v7.10: Element cannot be added to the set: it''s already added", "expected_fields": {"severity": "Warn", "log_level": "Warn", "event_type": "error handling event", "action_type": "ips", "action": "add", "external_ip": "156.218.17.179", "source_ip": "156.218.17.179", "client_ip": "156.218.17.179", "external_port": "52686", "source_port": "52686", "internal_ip": "192.0.2.194", "dest_ip": "192.0.2.194", "destination_ip": "192.0.2.194", "internal_port": "80", "dest_port": "80", "protocol": "tcp", "service": "unifi-idsips"}}, {"raw_message": "<28>Nov 30 08:22:15 UCG-Max UCG-Max ubnt-idsips-daemon[2402]: 2025-11-30T08:22:15.123-0600 Error: attack detected: ipset[ids] add failed ip1:198.51.100.42, port1:443, ip2:192.168.1.50, port2:8080, proto:tcp", "expected_fields": {"severity": "Error", "log_level": "Error", "event_type": "attack detected", "action_type": "ids", "action": "add", "external_ip": "198.51.100.42", "source_ip": "198.51.100.42", "client_ip": "198.51.100.42", "external_port": "443", "source_port": "443", "internal_ip": "192.168.1.50", "dest_ip": "192.168.1.50", "destination_ip": "192.168.1.50", "internal_port": "8080", "dest_port": "8080", "protocol": "tcp", "service": "unifi-idsips"}}]',
    'ids_alert',
    true
)
ON CONFLICT (name) DO NOTHING;

-- ============================================================================
-- DETECTION RULES
-- ============================================================================

-- Built-in Detection Rule: SSH Brute Force
INSERT INTO detection_rules (name, description, severity, rule_yaml, rule_logic, tags, enabled)
VALUES (
    'SSH Brute Force Attempt',
    'Detects multiple failed SSH login attempts from the same IP address',
    'high',
    'name: SSH Brute Force Attempt
description: Detects multiple failed SSH login attempts from same IP
severity: high
enabled: true
tags: [ssh, brute-force, authentication]

conditions:
  - field: event
    operator: equals
    value: "Failed password"

aggregation:
  field: source_ip
  timeframe: 5m
  threshold: 5

alert:
  title: "SSH Brute Force Detected from {source_ip}"
  description: "{count} failed SSH login attempts detected in 5 minutes"',
    '{"conditions": [{"field": "event", "operator": "equals", "value": "Failed password"}], "aggregation": {"field": "source_ip", "timeframe": "5m", "threshold": 5}}',
    ARRAY['ssh', 'brute-force', 'authentication'],
    true
)
ON CONFLICT (name) DO NOTHING;

-- Built-in Detection Rule: Root Login
INSERT INTO detection_rules (name, description, severity, rule_yaml, rule_logic, tags, enabled)
VALUES (
    'Direct Root SSH Login',
    'Detects successful SSH login as root user',
    'critical',
    'name: Direct Root SSH Login
description: Detects successful SSH login as root user
severity: critical
enabled: true
tags: [ssh, root, privilege]

conditions:
  - field: event
    operator: contains
    value: "Accepted"
  - field: user
    operator: equals
    value: "root"

alert:
  title: "Root SSH Login from {source_ip}"
  description: "Direct root login detected from {source_ip}"',
    '{"conditions": [{"field": "event", "operator": "contains", "value": "Accepted"}, {"field": "user", "operator": "equals", "value": "root"}]}',
    ARRAY['ssh', 'root', 'privilege'],
    true
)
ON CONFLICT (name) DO NOTHING;

-- Built-in Detection Rule: Sudo to Root
INSERT INTO detection_rules (name, description, severity, rule_yaml, rule_logic, tags, enabled)
VALUES (
    'Sudo Privilege Escalation',
    'Detects sudo commands executed to become root',
    'medium',
    'name: Sudo Privilege Escalation
description: Detects sudo commands executed to become root
severity: medium
enabled: true
tags: [sudo, privilege-escalation]

conditions:
  - field: target_user
    operator: equals
    value: "root"
  - field: command
    operator: not_contains
    value: "/usr/bin/whoami"

alert:
  title: "Sudo to Root by {user}"
  description: "User {user} executed sudo command as root: {command}"',
    '{"conditions": [{"field": "target_user", "operator": "equals", "value": "root"}, {"field": "command", "operator": "not_contains", "value": "/usr/bin/whoami"}]}',
    ARRAY['sudo', 'privilege-escalation'],
    true
)
ON CONFLICT (name) DO NOTHING;

-- Built-in Detection Rule: HTTP 404 Scanning
INSERT INTO detection_rules (name, description, severity, rule_yaml, rule_logic, tags, enabled)
VALUES (
    'Web Path Scanning',
    'Detects multiple 404 errors from same IP (directory scanning)',
    'medium',
    'name: Web Path Scanning
description: Detects multiple 404 errors from same IP (directory scanning)
severity: medium
enabled: true
tags: [web, scanning, reconnaissance]

conditions:
  - field: status_code
    operator: equals
    value: "404"

aggregation:
  field: client_ip
  timeframe: 5m
  threshold: 20

alert:
  title: "Web Scanning Detected from {client_ip}"
  description: "{count} 404 errors detected in 5 minutes from {client_ip}"',
    '{"conditions": [{"field": "status_code", "operator": "equals", "value": "404"}], "aggregation": {"field": "client_ip", "timeframe": "5m", "threshold": 20}}',
    ARRAY['web', 'scanning', 'reconnaissance'],
    true
)
ON CONFLICT (name) DO NOTHING;

-- Built-in Detection Rule: HTTP 5xx Errors
INSERT INTO detection_rules (name, description, severity, rule_yaml, rule_logic, tags, enabled)
VALUES (
    'Web Server Errors',
    'Detects multiple HTTP 5xx server errors',
    'low',
    'name: Web Server Errors
description: Detects multiple HTTP 5xx server errors
severity: low
enabled: true
tags: [web, availability, errors]

conditions:
  - field: status_code
    operator: regex
    value: "^5\\d{2}$"

aggregation:
  field: path
  timeframe: 10m
  threshold: 10

alert:
  title: "Multiple Server Errors on {path}"
  description: "{count} HTTP 5xx errors detected in 10 minutes"',
    '{"conditions": [{"field": "status_code", "operator": "regex", "value": "^5\\\\d{2}$"}], "aggregation": {"field": "path", "timeframe": "10m", "threshold": 10}}',
    ARRAY['web', 'availability', 'errors'],
    true
)
ON CONFLICT (name) DO NOTHING;

-- Built-in Detection Rule: Multiple Failed Logins (Generic)
INSERT INTO detection_rules (name, description, severity, rule_yaml, rule_logic, tags, enabled)
VALUES (
    'Multiple Failed Authentication',
    'Detects multiple failed authentication attempts (generic)',
    'medium',
    'name: Multiple Failed Authentication
description: Detects multiple failed authentication attempts (generic)
severity: medium
enabled: true
tags: [authentication, failed-login]

conditions:
  - field: message
    operator: contains
    value: "failed"
  - field: message
    operator: contains
    value: "authentication"

aggregation:
  field: source_ip
  timeframe: 10m
  threshold: 8

alert:
  title: "Multiple Failed Logins from {source_ip}"
  description: "{count} failed authentication attempts in 10 minutes"',
    '{"conditions": [{"field": "message", "operator": "contains", "value": "failed"}, {"field": "message", "operator": "contains", "value": "authentication"}], "aggregation": {"field": "source_ip", "timeframe": "10m", "threshold": 8}}',
    ARRAY['authentication', 'failed-login'],
    true
)
ON CONFLICT (name) DO NOTHING;

-- Built-in Detection Rule: UniFi IPS Repeated Blocks
INSERT INTO detection_rules (name, description, severity, rule_yaml, rule_logic, tags, enabled)
VALUES (
    'UniFi IPS Repeated Attack Attempts',
    'Detects multiple IPS block events from same external IP (persistent attack)',
    'high',
    'name: UniFi IPS Repeated Attack Attempts
description: Detects multiple IPS block events from same external IP (persistent attack)
severity: high
enabled: true
tags: [unifi, ips, intrusion, attack]

conditions:
  - field: action_type
    operator: equals
    value: "ips"
  - field: action
    operator: equals
    value: "add"

aggregation:
  field: external_ip
  timeframe: 10m
  threshold: 5

alert:
  title: "Repeated IPS Blocks from {external_ip}"
  description: "{count} IPS block events from {external_ip} in 10 minutes - possible persistent attack"',
    '{"conditions": [{"field": "action_type", "operator": "equals", "value": "ips"}, {"field": "action", "operator": "equals", "value": "add"}], "aggregation": {"field": "external_ip", "timeframe": "10m", "threshold": 5}}',
    ARRAY['unifi', 'ips', 'intrusion', 'attack'],
    true
)
ON CONFLICT (name) DO NOTHING;

-- Built-in Detection Rule: UniFi IPS Internal System Targeted
INSERT INTO detection_rules (name, description, severity, rule_yaml, rule_logic, tags, enabled)
VALUES (
    'UniFi IPS Internal System Under Attack',
    'Detects when internal system is being repeatedly targeted by IPS blocks',
    'critical',
    'name: UniFi IPS Internal System Under Attack
description: Detects when internal system is being repeatedly targeted by IPS blocks
severity: critical
enabled: true
tags: [unifi, ips, internal-threat, attack]

conditions:
  - field: action_type
    operator: equals
    value: "ips"
  - field: action
    operator: equals
    value: "add"

aggregation:
  field: internal_ip
  timeframe: 15m
  threshold: 10

alert:
  title: "Internal System {internal_ip} Under Attack"
  description: "{count} IPS blocks targeting {internal_ip} in 15 minutes - system may be compromised or under heavy attack"',
    '{"conditions": [{"field": "action_type", "operator": "equals", "value": "ips"}, {"field": "action", "operator": "equals", "value": "add"}], "aggregation": {"field": "internal_ip", "timeframe": "15m", "threshold": 10}}',
    ARRAY['unifi', 'ips', 'internal-threat', 'attack'],
    true
)
ON CONFLICT (name) DO NOTHING;

-- Built-in Detection Rule: UniFi IDS/IPS Error Events
INSERT INTO detection_rules (name, description, severity, rule_yaml, rule_logic, tags, enabled)
VALUES (
    'UniFi IDS/IPS Error Events',
    'Detects error-level events in UniFi IDS/IPS system',
    'medium',
    'name: UniFi IDS/IPS Error Events
description: Detects error-level events in UniFi IDS/IPS system
severity: medium
enabled: true
tags: [unifi, ips, ids, errors]

conditions:
  - field: severity
    operator: equals
    value: "Error"
  - field: event_type
    operator: contains
    value: "error"

alert:
  title: "UniFi IDS/IPS Error Detected"
  description: "IDS/IPS error event: {event_type} - {external_ip}:{external_port} -> {internal_ip}:{internal_port}"',
    '{"conditions": [{"field": "severity", "operator": "equals", "value": "Error"}, {"field": "event_type", "operator": "contains", "value": "error"}]}',
    ARRAY['unifi', 'ips', 'ids', 'errors'],
    true
)
ON CONFLICT (name) DO NOTHING;

-- Built-in Detection Rule: UniFi IPS Port Scan Detection
INSERT INTO detection_rules (name, description, severity, rule_yaml, rule_logic, tags, enabled)
VALUES (
    'UniFi IPS Port Scan Detection',
    'Detects potential port scanning activity based on IPS blocks from same IP to multiple internal ports',
    'high',
    'name: UniFi IPS Port Scan Detection
description: Detects potential port scanning activity based on IPS blocks from same IP to multiple internal ports
severity: high
enabled: true
tags: [unifi, ips, port-scan, reconnaissance]

conditions:
  - field: action_type
    operator: equals
    value: "ips"
  - field: action
    operator: equals
    value: "add"

aggregation:
  field: external_ip
  timeframe: 5m
  threshold: 8

alert:
  title: "Port Scan Detected from {external_ip}"
  description: "{count} IPS blocks from {external_ip} in 5 minutes - likely port scanning activity"',
    '{"conditions": [{"field": "action_type", "operator": "equals", "value": "ips"}, {"field": "action", "operator": "equals", "value": "add"}], "aggregation": {"field": "external_ip", "timeframe": "5m", "threshold": 8}}',
    ARRAY['unifi', 'ips', 'port-scan', 'reconnaissance'],
    true
)
ON CONFLICT (name) DO NOTHING;
