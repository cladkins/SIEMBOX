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
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, enabled)
VALUES (
    'SSH Authentication',
    'Parses SSH authentication logs (success and failure)',
    'regex',
    10,
    '^(?<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?<hostname>\S+)\s+sshd\[(?<pid>\d+)\]:\s+(?<event>Failed password|Accepted password|Accepted publickey)\s+for\s+(?<user>\S+)\s+from\s+(?<src_ip>[\d.]+)\s+port\s+(?<src_port>\d+)',
    '{"timestamp": "timestamp", "hostname": "hostname", "pid": "pid", "event": "event", "user": "user", "source_ip": "src_ip", "source_port": "src_port"}',
    true
)
ON CONFLICT (name) DO NOTHING;

-- Built-in Parser: Apache/Nginx Access Logs
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, enabled)
VALUES (
    'Apache/Nginx Access Log',
    'Parses standard Apache/Nginx access logs',
    'regex',
    20,
    '^(?<client_ip>[\d.]+)\s+-\s+-\s+\[(?<timestamp>[^\]]+)\]\s+"(?<method>\S+)\s+(?<path>\S+)\s+(?<protocol>[^"]+)"\s+(?<status>\d+)\s+(?<size>\d+)',
    '{"client_ip": "client_ip", "timestamp": "timestamp", "method": "method", "path": "path", "protocol": "protocol", "status_code": "status", "response_size": "size"}',
    true
)
ON CONFLICT (name) DO NOTHING;

-- Built-in Parser: Linux Sudo Commands
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, enabled)
VALUES (
    'Linux Sudo',
    'Parses sudo command execution logs',
    'regex',
    15,
    '^(?<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?<hostname>\S+)\s+sudo:\s+(?<user>\S+)\s+:\s+TTY=(?<tty>\S+)\s+;\s+PWD=(?<pwd>\S+)\s+;\s+USER=(?<target_user>\S+)\s+;\s+COMMAND=(?<command>.+)$',
    '{"timestamp": "timestamp", "hostname": "hostname", "user": "user", "tty": "tty", "working_dir": "pwd", "target_user": "target_user", "command": "command"}',
    true
)
ON CONFLICT (name) DO NOTHING;

-- Built-in Parser: Generic Syslog
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, enabled)
VALUES (
    'Generic Syslog',
    'Fallback parser for standard syslog format',
    'regex',
    1000,
    '^(?<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?<hostname>\S+)\s+(?<process>\S+?)(?:\[(?<pid>\d+)\])?:\s+(?<message>.+)$',
    '{"timestamp": "timestamp", "hostname": "hostname", "process": "process", "pid": "pid", "message": "message"}',
    true
)
ON CONFLICT (name) DO NOTHING;

-- Built-in Parser: JSON Logs
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, enabled)
VALUES (
    'JSON Parser',
    'Parses logs already in JSON format',
    'json',
    50,
    '.*',
    '{}',
    true
)
ON CONFLICT (name) DO NOTHING;

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
