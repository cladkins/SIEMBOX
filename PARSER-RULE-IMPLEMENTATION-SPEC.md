# SIEMBox Parser & Rule Implementation Specification

**Version:** 1.0
**Last Updated:** 2025-12-03
**Purpose:** Technical specification for implementing parsers and detection rules in SIEMBox

---

## Table of Contents

1. [System Architecture Overview](#1-system-architecture-overview)
2. [Parser Implementation](#2-parser-implementation)
3. [Rule Implementation](#3-rule-implementation)
4. [Conventions and Standards](#4-conventions-and-standards)
5. [Implementation Examples](#5-implementation-examples)
6. [Best Practices](#6-best-practices)
7. [API Reference](#7-api-reference)
8. [Templates](#8-templates)
9. [Appendix](#appendix)

---

## 1. System Architecture Overview

### 1.1 Log Processing Flow

```
Raw Log (Syslog/API)
    ↓
Raw Logs Table
    ↓
Parser Engine (Priority Order)
    ↓
Parsed Logs Table (JSONB fields)
    ↓
Rules Engine (Evaluates ALL enabled rules)
    ↓
Alerts Table
```

### 1.2 Key Components

- **Raw Logs:** Unprocessed syslog messages as received
- **Parsers:** Transform raw text into structured JSONB data
- **Parsed Logs:** Structured logs with extracted fields
- **Detection Rules:** YAML-based conditions that trigger alerts
- **Alerts:** Security events requiring investigation

### 1.3 Processing Logic

1. Raw log arrives via syslog server (UDP/TCP port 514) or API
2. Parser engine tries each enabled parser in priority order (lowest number first)
3. First matching parser extracts fields into JSONB format
4. Parsed log is evaluated against ALL enabled detection rules
5. Matching rules create alerts with severity levels
6. Processing stops after first successful parse (no fallthrough)

---

## 2. Parser Implementation

### 2.1 Database Schema

**Table:** `parsers`

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | SERIAL | No | Primary key |
| `name` | VARCHAR(255) | No | Unique parser name |
| `description` | TEXT | Yes | Human-readable description |
| `enabled` | BOOLEAN | No | Is parser active (default: true) |
| `priority` | INTEGER | No | Execution priority (default: 100) |
| `parser_type` | VARCHAR(50) | No | Type: 'regex', 'grok', 'json' |
| `pattern` | TEXT | No | Regex/grok pattern or empty for JSON |
| `field_mappings` | JSONB | No | Maps groups to field names |
| `test_samples` | JSONB | Yes | Array of sample logs for testing |
| `created_at` | TIMESTAMP | No | Creation timestamp |
| `updated_at` | TIMESTAMP | No | Last update timestamp |

**Indexes:**
- `idx_parsers_enabled` on `enabled`
- `idx_parsers_priority` on `priority`

### 2.2 Parser Types

#### 2.2.1 Regex Parser

**Description:** Uses JavaScript regular expressions with named or numbered capture groups.

**Pattern Format:**
- Named groups: `(?<field_name>pattern)`
- Numbered groups: `(pattern)` - accessed via match[1], match[2], etc.

**Field Mappings:**
- Named groups: `{ "group_name": "output_field_name" }`
- Numbered groups: `{ "1": "output_field_name", "2": "another_field" }`

**Example:**
```json
{
  "name": "SSH Authentication",
  "parser_type": "regex",
  "pattern": "^(?<timestamp>\\w+\\s+\\d+\\s+\\d+:\\d+:\\d+)\\s+(?<hostname>\\S+)\\s+sshd\\[(?<pid>\\d+)\\]:\\s+(?<event>Failed password|Accepted password)\\s+for\\s+(?<user>\\S+)\\s+from\\s+(?<src_ip>[\\d.]+)\\s+port\\s+(?<src_port>\\d+)",
  "field_mappings": {
    "timestamp": "timestamp",
    "hostname": "hostname",
    "pid": "pid",
    "event": "event",
    "user": "user",
    "src_ip": "source_ip",
    "src_port": "source_port"
  }
}
```

#### 2.2.2 Grok Parser

**Description:** Grok patterns (Logstash-compatible). Currently falls back to regex implementation.

**Status:** Basic implementation - full grok library integration pending.

**Pattern Format:** Standard grok syntax (e.g., `%{IP:client_ip}`)

**Note:** For production use, consider implementing full grok library (node-grok or grok-js).

#### 2.2.3 JSON Parser

**Description:** Automatically parses JSON-formatted logs.

**Pattern:** Empty string or not used

**Field Mappings:**
- Empty object `{}`: Auto-extract all JSON fields as-is
- With mappings: `{ "source_field": "target_field" }` for field renaming

**Example:**
```json
{
  "name": "JSON Parser",
  "parser_type": "json",
  "pattern": "",
  "field_mappings": {}
}
```

### 2.3 Field Mapping Structure

**JSONB Format:**
```json
{
  "group_identifier": "output_field_name"
}
```

**For Regex Named Groups:**
```json
{
  "timestamp": "timestamp",
  "hostname": "hostname",
  "user": "user"
}
```

**For Regex Numbered Groups:**
```json
{
  "1": "timestamp",
  "2": "hostname",
  "3": "user"
}
```

**For JSON:**
```json
{
  "ts": "timestamp",
  "host": "hostname",
  "usr": "user"
}
```
Or empty object `{}` to use all fields as-is.

### 2.4 Priority System

**How Priority Works:**
- Lower number = Higher priority (executed first)
- Parsers are tried in ascending priority order
- First match wins - no fallthrough to lower priority parsers
- Default priority: 100

**Priority Guidelines:**

| Priority Range | Usage | Examples |
|---------------|-------|----------|
| 1-10 | Critical system parsers | Built-in SSH, Sudo parsers |
| 11-49 | High-priority application-specific | Custom authentication logs |
| 50-99 | Standard application parsers | Web servers, databases, network devices |
| 100-499 | Generic/flexible parsers | Standard syslog formats |
| 500-999 | Low-priority catch-all | Generic syslog, fallback patterns |
| 1000+ | Debug/testing parsers | Experimental parsers |

**Best Practices:**
- Application-specific parsers: 50-100
- Vendor-specific parsers (e.g., UniFi): 50
- Generic fallback parsers: 500-1000
- Leave room between priorities for future insertions

### 2.5 Event Type Determination

The parser engine automatically determines event_type based on:
1. Parser name keywords (ssh, apache, nginx, sudo, firewall)
2. Extracted field values (e.g., "Failed" vs "Accepted" in SSH logs)

**Event Type Examples:**
- `ssh_failed_login` - Failed SSH authentication
- `ssh_successful_login` - Successful SSH authentication
- `http_request` - Web server request
- `sudo_command` - Sudo privilege escalation
- `firewall_event` - Firewall rule match
- `generic` - Fallback for unknown types

**Usage:** Event types enable efficient filtering and rule targeting.

### 2.6 Test Samples

**Format:** Array of strings (raw log examples)

```json
{
  "test_samples": [
    "Nov 29 19:30:15 server1 sshd[12345]: Failed password for root from 192.168.1.100 port 54321",
    "Nov 29 19:35:20 server1 sshd[12346]: Accepted password for admin from 192.168.1.50 port 43210"
  ]
}
```

**Purpose:**
- Validate parser patterns before deployment
- Regression testing when updating parsers
- Documentation of expected log formats

### 2.7 Parser Template

**Complete JSON Structure:**
```json
{
  "name": "Application-LogType",
  "description": "Parses [application] [log type] logs",
  "enabled": true,
  "priority": 50,
  "parser_type": "regex",
  "pattern": "^(?<field1>pattern1)\\s+(?<field2>pattern2)",
  "field_mappings": {
    "field1": "output_field1",
    "field2": "output_field2"
  },
  "test_samples": [
    "Example log line 1",
    "Example log line 2"
  ]
}
```

---

## 3. Rule Implementation

### 3.1 Database Schema

**Table:** `detection_rules`

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | SERIAL | No | Primary key |
| `name` | VARCHAR(255) | No | Unique rule name |
| `description` | TEXT | Yes | Human-readable description |
| `enabled` | BOOLEAN | No | Is rule active (default: true) |
| `severity` | VARCHAR(20) | No | Alert severity level |
| `rule_yaml` | TEXT | No | Complete YAML rule definition |
| `rule_logic` | JSONB | No | Parsed YAML for execution |
| `tags` | TEXT[] | No | Categorization tags (array) |
| `created_at` | TIMESTAMP | No | Creation timestamp |
| `updated_at` | TIMESTAMP | No | Last update timestamp |

**Indexes:**
- `idx_rules_enabled` on `enabled`
- `idx_rules_severity` on `severity`
- `idx_rules_tags` on `tags` (GIN index)

### 3.2 Rule YAML Format

**Complete YAML Structure:**
```yaml
name: Rule Name
description: What this rule detects and why it matters
severity: low|medium|high|critical
enabled: true
tags: [category1, category2, threat-type]

conditions:
  - field: field_name
    operator: equals
    value: "expected_value"
  - field: another_field
    operator: contains
    value: "substring"

aggregation:  # Optional - for threshold-based detection
  field: grouping_field
  timeframe: 5m
  threshold: 10

alert:
  title: "Alert Title with {variable} substitution"
  description: "Alert description with {count} and {field_name} variables"
```

**Required Fields:**
- `name`: Unique identifier (used in database)
- `description`: Explains detection purpose
- `severity`: One of: low, medium, high, critical
- `conditions`: Array of field matching conditions
- `alert`: Title and description templates

**Optional Fields:**
- `enabled`: Default true
- `tags`: Array of categorization strings
- `aggregation`: For count-based detection over time

### 3.3 Condition Types

**Condition Structure:**
```yaml
- field: field_name
  operator: operator_type
  value: comparison_value
```

**Supported Operators:**

| Operator | Description | Example Use Case |
|----------|-------------|------------------|
| `equals` | Exact string match (case-sensitive) | User equals "root" |
| `contains` | Substring match (case-insensitive) | Message contains "failed" |
| `not_contains` | Does not contain substring | Command not contains "whoami" |
| `regex` | Regular expression match | Status matches "^5\\d{2}$" |
| `greater_than` | Numeric comparison (>) | Count greater than 10 |
| `less_than` | Numeric comparison (<) | Response time less than 100 |

**Condition Logic:**
- Multiple conditions are ANDed together (all must match)
- All conditions must match for rule to trigger
- Missing fields cause condition to fail (no match)
- Field values are extracted from `parsed_data` JSONB

**Example - Multiple Conditions:**
```yaml
conditions:
  - field: event
    operator: contains
    value: "Failed"
  - field: user
    operator: equals
    value: "root"
  - field: source_ip
    operator: not_contains
    value: "192.168.1.50"
```
This triggers only if: event contains "Failed" AND user equals "root" AND source_ip is not "192.168.1.50"

### 3.4 Aggregation Logic

**Aggregation Structure:**
```yaml
aggregation:
  field: field_to_group_by
  timeframe: 5m
  threshold: 10
```

**Components:**
- `field`: JSONB field to group by (e.g., source_ip, user, client_ip)
- `timeframe`: Time window for counting events
- `threshold`: Minimum count to trigger alert

**Timeframe Values:**

| Value | Minutes | Use Case |
|-------|---------|----------|
| `1m` | 1 | Rapid attack detection |
| `5m` | 5 | Brute force attempts |
| `10m` | 10 | Reconnaissance scanning |
| `15m` | 15 | Sustained attacks |
| `30m` | 30 | Slow attacks |
| `1h` | 60 | Pattern analysis |
| `24h` | 1440 | Daily baseline deviations |

**How It Works:**
1. Rule conditions filter logs
2. Matching logs are counted by `field` value
3. Count is checked within `timeframe` window
4. Alert created when count >= `threshold`
5. Alert includes `{count}` variable

**Example - Brute Force Detection:**
```yaml
conditions:
  - field: event
    operator: equals
    value: "Failed password"

aggregation:
  field: source_ip
  timeframe: 5m
  threshold: 5
```
This triggers when 5+ failed password attempts occur from same IP within 5 minutes.

### 3.5 Alert Templates

**Variable Substitution:**
- `{field_name}` - Any field from parsed_data
- `{count}` - Event count (for aggregation rules)
- `{source_ip}` - Special: always available from parsed_logs table
- `{timestamp}` - Special: always available from parsed_logs table

**Example:**
```yaml
alert:
  title: "SSH Brute Force from {source_ip}"
  description: "{count} failed login attempts for user {user} in 5 minutes"
```

**Rendered Alert:**
```json
{
  "title": "SSH Brute Force from 192.168.1.100",
  "description": "5 failed login attempts for user root in 5 minutes"
}
```

### 3.6 Severity Levels

| Level | Use Cases | Examples |
|-------|-----------|----------|
| `critical` | System compromise, credential theft, data exfiltration | Root SSH login, privilege escalation, malware detection |
| `high` | Unauthorized access, serious policy violations, active attacks | Brute force attacks, port scanning, repeated IPS blocks |
| `medium` | Suspicious activity, potential threats, policy violations | Multiple authentication failures, directory scanning |
| `low` | Informational, minor anomalies, baseline deviations | After-hours logins, configuration changes, non-critical errors |

**Guidelines:**
- Critical: Immediate response required, potential active incident
- High: Investigate within hours, likely security issue
- Medium: Investigate within day, monitor for patterns
- Low: Review when convenient, informational tracking

### 3.7 Rule Template

**Complete YAML Template:**
```yaml
name: Descriptive Rule Name
description: Explain what threat or behavior this detects and why it matters
severity: medium
enabled: true
tags: [category, threat-type, technology]

conditions:
  - field: field_name
    operator: equals
    value: "value"

# Optional aggregation for threshold-based detection
aggregation:
  field: grouping_field
  timeframe: 5m
  threshold: 5

alert:
  title: "Alert Title with {variable} substitution"
  description: "Detailed description with {count} and {field_name}"
```

---

## 4. Conventions and Standards

### 4.1 Naming Conventions

#### 4.1.1 Parser Naming

**Format:** `[Vendor/Application]-[LogType]`

**Examples:**
- `SSH Authentication` (built-in system parser)
- `Apache/Nginx Access Log` (web server parser)
- `Ubiquiti UniFi Firewall` (vendor-specific parser)
- `Linux Sudo` (system command parser)
- `JSON Parser` (generic format parser)

**Guidelines:**
- Use title case
- Include vendor/application name
- Specify log type if multiple exist
- Keep concise but descriptive
- Avoid abbreviations unless standard (SSH, IDS, IPS)

#### 4.1.2 Field Naming

**Format:** `snake_case` (lowercase with underscores)

**Standard Field Names:**
| Field | Description | Example |
|-------|-------------|---------|
| `timestamp` | Event timestamp | "Nov 29 19:30:15" |
| `hostname` | Server hostname | "server1" |
| `source_ip` | Source IP address | "192.168.1.100" |
| `dest_ip` | Destination IP | "192.168.1.1" |
| `source_port` | Source port number | "54321" |
| `dest_port` | Destination port | "443" |
| `user` | Username | "admin" |
| `event` | Event type/action | "Failed password" |
| `message` | Full log message | "Login failed..." |
| `status_code` | HTTP status code | "404" |
| `method` | HTTP method | "GET" |
| `path` | URL path | "/api/users" |
| `command` | Executed command | "/usr/bin/apt update" |
| `severity` | Log severity | "ERROR" |
| `protocol` | Network protocol | "TCP" |

**Guidelines:**
- Always use snake_case
- Use descriptive names
- Be consistent across parsers
- Prefer standard names (see Appendix A)
- Avoid special characters except underscore

#### 4.1.3 Rule Naming

**Format:** Descriptive action-oriented name

**Examples:**
- `SSH Brute Force Detection`
- `Direct Root SSH Login`
- `Web Path Scanning`
- `Multiple Failed Authentication`
- `UniFi IPS Repeated Attack Attempts`

**Guidelines:**
- Use title case
- Start with action or threat type
- Be specific about detection method
- Keep under 60 characters
- Avoid jargon

#### 4.1.4 Tag Naming

**Format:** `kebab-case` (lowercase with hyphens)

**Standard Tags:**
| Tag | Usage |
|-----|-------|
| `ssh` | SSH-related events |
| `brute-force` | Brute force attacks |
| `authentication` | Authentication events |
| `web` | Web server events |
| `scanning` | Reconnaissance/scanning |
| `privilege-escalation` | Privilege changes |
| `firewall` | Firewall events |
| `ids` | IDS/IPS events |
| `database` | Database events |
| `availability` | Service availability |
| `errors` | Error conditions |
| `root` | Root/admin access |

**Guidelines:**
- Use kebab-case
- Use existing tags when applicable
- Create new tags for new categories
- Avoid redundant tags
- Keep tags concise

### 4.2 Priority Guidelines

**Parser Priority Assignment:**

```
Priority 1-10: Critical System Parsers
├─ 10: SSH Authentication
├─ 15: Linux Sudo
└─ 20: Apache/Nginx Access Log

Priority 50-99: Application-Specific Parsers
├─ 50: Ubiquiti UniFi Firewall
├─ 50: Ubiquiti UniFi IDS/IPS
├─ 50: JSON Parser
└─ 60-90: Custom application parsers

Priority 100-499: Standard Parsers
└─ 100: Default priority for new parsers

Priority 500-999: Generic Fallback Parsers
└─ 1000: Generic Syslog (catch-all)
```

**Decision Matrix:**

| Parser Type | Priority | Reasoning |
|------------|----------|-----------|
| Built-in critical | 1-20 | Always process first |
| Vendor-specific | 50-99 | Specific before generic |
| Application-specific | 50-99 | Targeted parsing |
| Generic formats | 100-499 | Standard processing |
| Catch-all fallback | 500+ | Last resort parsing |

### 4.3 Severity Levels

**Severity Assignment Guidelines:**

#### Critical
- **Criteria:** Confirmed compromise, root access, credential theft, data exfiltration
- **Response Time:** Immediate (minutes)
- **Examples:**
  - Direct root SSH login from internet
  - Privilege escalation to root
  - Successful exploitation detected
  - Malware/backdoor execution
  - Unauthorized database access

#### High
- **Criteria:** Active attacks, repeated violations, serious policy breach
- **Response Time:** Within hours
- **Examples:**
  - SSH brute force (5+ attempts in 5 min)
  - Port scanning (8+ connections in 5 min)
  - Repeated IPS blocks (5+ in 10 min)
  - Web application scanning (20+ 404s)
  - Unauthorized access attempts

#### Medium
- **Criteria:** Suspicious activity, potential threats, policy violations
- **Response Time:** Within day
- **Examples:**
  - Multiple failed logins (8+ in 10 min)
  - After-hours administrative access
  - Configuration changes
  - IDS/IPS errors
  - Unusual sudo usage

#### Low
- **Criteria:** Informational, minor anomalies, baseline tracking
- **Response Time:** Review as convenient
- **Examples:**
  - Server errors (HTTP 5xx)
  - Service availability issues
  - Non-critical errors
  - Normal administrative actions
  - Baseline deviations

### 4.4 Testing Requirements

#### 4.4.1 Parser Testing

**Requirements:**
- Minimum 3 test samples per parser
- Cover positive and edge cases
- Test with real log samples
- Validate all field extractions

**Test Sample Types:**
1. **Happy Path:** Normal successful log
2. **Alternative Format:** Variations in log format
3. **Edge Case:** Unusual but valid logs

**Example:**
```json
{
  "test_samples": [
    "Nov 29 19:30:15 server1 sshd[12345]: Failed password for root from 192.168.1.100 port 54321",
    "Nov 29 19:35:20 server1 sshd[12346]: Accepted password for admin from 192.168.1.50 port 43210",
    "Nov 29 19:40:30 server1 sshd[12347]: Accepted publickey for deploy from 10.0.1.200 port 22"
  ]
}
```

#### 4.4.2 Rule Testing

**Requirements:**
- Test with positive cases (should trigger)
- Test with negative cases (should not trigger)
- Verify threshold values with real data
- Validate alert variable substitution

**Test Scenarios:**
1. **True Positive:** Logs that should trigger alert
2. **True Negative:** Logs that should not trigger
3. **Threshold Boundary:** Logs at threshold edge
4. **Variable Substitution:** Verify alert formatting

### 4.5 Documentation Requirements

**Parser Documentation (PARSERS.md):**
- Parser name and description
- Parser type and priority
- Pattern (regex/grok)
- Field mappings table
- Example log samples
- Parsed output examples
- Use cases

**Rule Documentation (RULES.md):**
- Rule name and severity
- Complete YAML definition
- What it detects (threat description)
- Use cases and scenarios
- Compatible parsers
- Expected alert format

---

## 5. Implementation Examples

### 5.1 Complete Parser Examples

#### 5.1.1 Regex Parser with Named Groups

**Use Case:** Parse Windows Security Event Logs

```json
{
  "name": "Windows Security Events",
  "description": "Parses Windows Security Event Log entries",
  "enabled": true,
  "priority": 50,
  "parser_type": "regex",
  "pattern": "^(?<timestamp>\\d{4}-\\d{2}-\\d{2}\\s+\\d{2}:\\d{2}:\\d{2})\\s+EventID:\\s+(?<event_id>\\d+)\\s+User:\\s+(?<user>\\S+)\\s+Computer:\\s+(?<computer>\\S+)\\s+Result:\\s+(?<result>\\w+)",
  "field_mappings": {
    "timestamp": "timestamp",
    "event_id": "event_id",
    "user": "user",
    "computer": "hostname",
    "result": "status"
  },
  "test_samples": [
    "2025-11-30 14:30:45 EventID: 4624 User: DOMAIN\\admin Computer: WORKSTATION01 Result: Success",
    "2025-11-30 14:31:10 EventID: 4625 User: DOMAIN\\test Computer: WORKSTATION01 Result: Failure"
  ]
}
```

**Sample Log:**
```
2025-11-30 14:30:45 EventID: 4624 User: DOMAIN\admin Computer: WORKSTATION01 Result: Success
```

**Parsed Output:**
```json
{
  "timestamp": "2025-11-30 14:30:45",
  "event_id": "4624",
  "user": "DOMAIN\\admin",
  "hostname": "WORKSTATION01",
  "status": "Success",
  "message": "2025-11-30 14:30:45 EventID: 4624 User: DOMAIN\\admin Computer: WORKSTATION01 Result: Success"
}
```

#### 5.1.2 Regex Parser with Numbered Groups

**Use Case:** Parse legacy application logs without named groups

```json
{
  "name": "Legacy Application Logger",
  "description": "Parses legacy application log format",
  "enabled": true,
  "priority": 75,
  "parser_type": "regex",
  "pattern": "^\\[(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})\\]\\s+(\\w+)\\s+-\\s+(\\S+)\\s+-\\s+(.+)$",
  "field_mappings": {
    "1": "timestamp",
    "2": "level",
    "3": "module",
    "4": "message"
  },
  "test_samples": [
    "[2025-11-30 14:45:23] ERROR - DatabaseModule - Connection timeout after 30 seconds",
    "[2025-11-30 14:45:24] INFO - AuthModule - User login successful"
  ]
}
```

**Sample Log:**
```
[2025-11-30 14:45:23] ERROR - DatabaseModule - Connection timeout after 30 seconds
```

**Parsed Output:**
```json
{
  "timestamp": "2025-11-30 14:45:23",
  "level": "ERROR",
  "module": "DatabaseModule",
  "message": "Connection timeout after 30 seconds"
}
```

#### 5.1.3 JSON Parser with Field Remapping

**Use Case:** Parse structured JSON logs with field normalization

```json
{
  "name": "Kubernetes Audit Logs",
  "description": "Parses Kubernetes audit log JSON format",
  "enabled": true,
  "priority": 50,
  "parser_type": "json",
  "pattern": "",
  "field_mappings": {
    "timestamp": "timestamp",
    "verb": "action",
    "user.username": "user",
    "sourceIPs": "source_ip",
    "objectRef.name": "resource_name",
    "objectRef.namespace": "namespace",
    "responseStatus.code": "status_code"
  },
  "test_samples": [
    "{\"timestamp\":\"2025-11-30T14:50:00Z\",\"verb\":\"delete\",\"user\":{\"username\":\"admin\"},\"sourceIPs\":[\"10.0.1.50\"],\"objectRef\":{\"name\":\"nginx-pod\",\"namespace\":\"production\"},\"responseStatus\":{\"code\":200}}"
  ]
}
```

**Sample Log:**
```json
{
  "timestamp": "2025-11-30T14:50:00Z",
  "verb": "delete",
  "user": {
    "username": "admin"
  },
  "sourceIPs": ["10.0.1.50"],
  "objectRef": {
    "name": "nginx-pod",
    "namespace": "production"
  },
  "responseStatus": {
    "code": 200
  }
}
```

**Parsed Output:**
```json
{
  "timestamp": "2025-11-30T14:50:00Z",
  "action": "delete",
  "user": "admin",
  "source_ip": ["10.0.1.50"],
  "resource_name": "nginx-pod",
  "namespace": "production",
  "status_code": 200
}
```

### 5.2 Complete Rule Examples

#### 5.2.1 Simple Condition Rule (No Aggregation)

**Use Case:** Detect any direct root SSH login

```yaml
name: Direct Root SSH Login
description: Detects successful SSH login as root user (critical security violation)
severity: critical
enabled: true
tags: [ssh, root, privilege, authentication]

conditions:
  - field: event
    operator: contains
    value: "Accepted"
  - field: user
    operator: equals
    value: "root"

alert:
  title: "Critical: Root SSH Login from {source_ip}"
  description: "Direct root SSH login detected from {source_ip} to {hostname}. This violates security best practices and should be investigated immediately."
```

**Triggers On:**
- ANY successful SSH login with user "root"
- No threshold required
- Creates alert immediately

**Sample Triggering Log:**
```json
{
  "event": "Accepted password",
  "user": "root",
  "source_ip": "192.168.1.100",
  "hostname": "server1"
}
```

**Generated Alert:**
```json
{
  "severity": "critical",
  "title": "Critical: Root SSH Login from 192.168.1.100",
  "description": "Direct root SSH login detected from 192.168.1.100 to server1. This violates security best practices and should be investigated immediately."
}
```

#### 5.2.2 Aggregation Rule (Threshold-Based)

**Use Case:** Detect SSH brute force attacks

```yaml
name: SSH Brute Force Detection
description: Detects multiple failed SSH login attempts from same IP address
severity: high
enabled: true
tags: [ssh, brute-force, authentication, attack]

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
  description: "{count} failed SSH login attempts detected from {source_ip} in 5 minutes. User attempted: {user}. This indicates an automated brute force attack."
```

**Triggers On:**
- 5+ failed password events from same source_ip
- Within 5 minute window
- Creates single alert when threshold reached

**Sample Triggering Logs:**
```json
{"event": "Failed password", "user": "root", "source_ip": "192.168.1.100"}
{"event": "Failed password", "user": "admin", "source_ip": "192.168.1.100"}
{"event": "Failed password", "user": "test", "source_ip": "192.168.1.100"}
{"event": "Failed password", "user": "user", "source_ip": "192.168.1.100"}
{"event": "Failed password", "user": "oracle", "source_ip": "192.168.1.100"}
```

**Generated Alert:**
```json
{
  "severity": "high",
  "title": "SSH Brute Force Detected from 192.168.1.100",
  "description": "5 failed SSH login attempts detected from 192.168.1.100 in 5 minutes. User attempted: oracle. This indicates an automated brute force attack."
}
```

#### 5.2.3 Complex Multi-Condition Rule

**Use Case:** Detect privilege escalation excluding benign commands

```yaml
name: Sudo Privilege Escalation
description: Detects sudo commands executed as root, excluding benign maintenance commands
severity: medium
enabled: true
tags: [sudo, privilege-escalation, linux, monitoring]

conditions:
  - field: target_user
    operator: equals
    value: "root"
  - field: command
    operator: not_contains
    value: "/usr/bin/whoami"
  - field: command
    operator: not_contains
    value: "/usr/bin/id"
  - field: command
    operator: not_contains
    value: "/bin/ls"

alert:
  title: "Sudo Privilege Escalation by {user}"
  description: "User {user} executed sudo command as root on {hostname}: {command}. Review command for unauthorized administrative activity."
```

**Triggers On:**
- target_user equals "root" AND
- command does NOT contain "whoami" AND
- command does NOT contain "id" AND
- command does NOT contain "ls"

**Sample Triggering Log:**
```json
{
  "user": "john",
  "target_user": "root",
  "command": "/usr/bin/apt update",
  "hostname": "server1",
  "tty": "/dev/pts/1"
}
```

**Generated Alert:**
```json
{
  "severity": "medium",
  "title": "Sudo Privilege Escalation by john",
  "description": "User john executed sudo command as root on server1: /usr/bin/apt update. Review command for unauthorized administrative activity."
}
```

**Does NOT Trigger On:**
```json
{
  "user": "john",
  "target_user": "root",
  "command": "/usr/bin/whoami",
  "hostname": "server1"
}
```
(Excluded by not_contains condition)

### 5.3 Test Sample Format

**Parser Test:**
```bash
POST /api/parsers/test
{
  "parser_type": "regex",
  "pattern": "^(?<level>\\w+):\\s+(?<message>.+)$",
  "field_mappings": {
    "level": "level",
    "message": "message"
  },
  "sample": "ERROR: Database connection failed"
}
```

**Expected Response:**
```json
{
  "matched": true,
  "fields": {
    "level": "ERROR",
    "message": "Database connection failed"
  }
}
```

**Rule Test (Manual):**
1. Create parser and parse logs
2. Query parsed_logs for test data
3. Enable rule
4. Check alerts table for triggered alerts
5. Verify alert fields match expectations

---

## 6. Best Practices

### 6.1 Parser Best Practices

#### 6.1.1 Pattern Design

**DO:**
- Use named capture groups for clarity: `(?<field>pattern)`
- Anchor patterns when possible: `^pattern$`
- Make patterns specific to avoid false matches
- Test with real production logs
- Handle optional fields gracefully: `(?:optional)?`

**DON'T:**
- Create overly broad patterns that match everything
- Forget to escape special regex characters: `\.` not `.`
- Use greedy quantifiers when not needed: `.+?` vs `.+`
- Assume log format never changes

**Examples:**

Good:
```regex
^(?<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(?<level>ERROR|WARN|INFO)\s+(?<message>.+)$
```

Bad (too greedy):
```regex
(.+)\s+(.+)\s+(.+)
```

#### 6.1.2 Field Extraction

**DO:**
- Extract all relevant security fields (IPs, users, actions)
- Use consistent field names across parsers
- Normalize field values when possible
- Include original message in parsed_data

**DON'T:**
- Extract unnecessary fields that bloat storage
- Use inconsistent field names between parsers
- Lose important context during parsing

#### 6.1.3 Priority Assignment

**DO:**
- Assign specific parsers lower priority numbers
- Leave gaps for future parser insertion
- Test parser order with overlapping patterns
- Document priority rationale

**DON'T:**
- Use same priority for unrelated parsers
- Create parser conflicts where wrong one matches first
- Forget that lower number = higher priority

#### 6.1.4 Testing

**DO:**
- Test with at least 3 varied samples
- Test with real logs from production
- Verify all fields extract correctly
- Test edge cases (missing fields, unusual formats)

**DON'T:**
- Test only happy path scenarios
- Assume parser works without testing
- Deploy to production without validation

### 6.2 Rule Best Practices

#### 6.2.1 Condition Design

**DO:**
- Make conditions specific enough to avoid false positives
- Use aggregation for pattern-based detection
- Consider normal vs. abnormal behavior
- Document why thresholds were chosen

**DON'T:**
- Create rules that trigger on normal activity
- Set thresholds too low (noise)
- Set thresholds too high (miss attacks)
- Forget to exclude known-good scenarios

**Example:**

Good (specific):
```yaml
conditions:
  - field: event
    operator: equals
    value: "Failed password"
  - field: user
    operator: not_equals
    value: "service-account"
```

Bad (too broad):
```yaml
conditions:
  - field: message
    operator: contains
    value: "failed"
```

#### 6.2.2 Severity Assignment

**DO:**
- Assign severity based on potential impact
- Consider context (internal vs. external source)
- Be consistent across similar rules
- Escalate severity for confirmed threats

**DON'T:**
- Mark everything as critical
- Underestimate genuine threats
- Ignore business context

**Guidelines:**
- External brute force: High
- Internal brute force: Medium
- Root login from known IP: Medium
- Root login from unknown IP: Critical

#### 6.2.3 Alert Content

**DO:**
- Make alert titles scannable and actionable
- Include key context in description
- Use variable substitution effectively
- Provide investigation guidance

**DON'T:**
- Create vague alert titles
- Omit important context
- Use technical jargon excessively
- Forget to include remediation guidance

**Example:**

Good:
```yaml
alert:
  title: "SSH Brute Force from {source_ip}"
  description: "{count} failed attempts for user {user} in 5 minutes. Block {source_ip} at firewall and review authentication logs."
```

Bad:
```yaml
alert:
  title: "Rule 1 triggered"
  description: "Event detected"
```

#### 6.2.4 Threshold Tuning

**Process:**
1. Start with conservative (high) thresholds
2. Monitor false positive rate
3. Gradually tune down to catch attacks
4. Document tuning rationale

**Example Tuning:**
- Initial: 20 failed logins in 10 minutes
- Week 1: 15 failed logins in 10 minutes
- Week 2: 10 failed logins in 10 minutes
- Final: 5 failed logins in 5 minutes

**Baseline Analysis:**
- Query normal activity levels
- Set threshold 2-3x above baseline
- Account for legitimate spikes

#### 6.2.5 Testing Rules

**DO:**
- Test with historical data first
- Verify variable substitution
- Check aggregation counts
- Monitor false positive rate

**DON'T:**
- Deploy untested rules to production
- Forget to validate alert content
- Skip threshold verification

**Test Checklist:**
- [ ] Rule triggers on attack samples
- [ ] Rule does NOT trigger on normal activity
- [ ] Alert title renders correctly
- [ ] Alert description includes all variables
- [ ] Severity level is appropriate
- [ ] Tags are correct

### 6.3 Performance Best Practices

#### 6.3.1 Parser Performance

**DO:**
- Keep regex patterns efficient
- Use anchors to fail fast: `^pattern`
- Avoid excessive backtracking
- Limit number of enabled parsers

**DON'T:**
- Create catastrophic backtracking patterns
- Enable unused parsers
- Use complex nested groups unnecessarily

#### 6.3.2 Rule Performance

**DO:**
- Use specific field conditions
- Leverage indexes on filtered fields
- Keep aggregation timeframes reasonable
- Disable unused rules

**DON'T:**
- Create rules that scan full message text
- Use extremely long timeframes (>24h)
- Have overlapping redundant rules

#### 6.3.3 Database Optimization

**DO:**
- Use GIN indexes on JSONB fields
- Implement log retention policies
- Archive old parsed_logs regularly
- Monitor database size growth

**DON'T:**
- Store logs indefinitely
- Ignore database performance degradation
- Skip index maintenance

---

## 7. API Reference

### 7.1 Parser Management APIs

Base URL: `/api/parsers`

#### GET /api/parsers
**Description:** Get all parsers

**Authentication:** Required

**Response:**
```json
[
  {
    "id": 1,
    "name": "SSH Authentication",
    "description": "Parses SSH authentication logs",
    "enabled": true,
    "priority": 10,
    "parser_type": "regex",
    "pattern": "...",
    "field_mappings": {...},
    "test_samples": null,
    "created_at": "2025-01-01T00:00:00Z",
    "updated_at": "2025-01-01T00:00:00Z"
  }
]
```

#### GET /api/parsers/:id
**Description:** Get single parser by ID

**Authentication:** Required

**Response:** Single parser object (same structure as above)

**Errors:**
- 404: Parser not found

#### POST /api/parsers
**Description:** Create new parser

**Authentication:** Required

**Request Body:**
```json
{
  "name": "Custom Parser",
  "description": "Parses custom logs",
  "enabled": true,
  "priority": 50,
  "parser_type": "regex",
  "pattern": "^(?<field>pattern)$",
  "field_mappings": {
    "field": "output_field"
  },
  "test_samples": ["sample log line"]
}
```

**Response:** Created parser object (201)

**Errors:**
- 400: Missing required fields

#### PUT /api/parsers/:id
**Description:** Update parser

**Authentication:** Required

**Request Body:** Partial parser object (all fields optional)

**Response:** Updated parser object

**Errors:**
- 404: Parser not found

#### DELETE /api/parsers/:id
**Description:** Delete parser

**Authentication:** Required

**Response:**
```json
{
  "message": "Parser deleted successfully"
}
```

**Errors:**
- 404: Parser not found

#### POST /api/parsers/test
**Description:** Test parser configuration without saving

**Authentication:** Required

**Request Body:**
```json
{
  "parser_type": "regex",
  "pattern": "^(?<field>pattern)$",
  "field_mappings": {
    "field": "output_field"
  },
  "sample": "log line to test"
}
```

**Response:**
```json
{
  "matched": true,
  "fields": {
    "output_field": "extracted_value"
  }
}
```

**Use Case:** Frontend parser builder for real-time validation

#### POST /api/parsers/:id/test
**Description:** Test saved parser against sample

**Authentication:** Required

**Request Body:**
```json
{
  "sample": "log line to test"
}
```

**Response:**
```json
{
  "matched": true,
  "fields": {
    "field_name": "extracted_value"
  }
}
```

### 7.2 Rule Management APIs

Base URL: `/api/rules`

#### GET /api/rules
**Description:** Get all detection rules

**Authentication:** Required

**Response:**
```json
[
  {
    "id": 1,
    "name": "SSH Brute Force Detection",
    "description": "Detects multiple failed SSH attempts",
    "enabled": true,
    "severity": "high",
    "rule_yaml": "name: SSH Brute Force...",
    "rule_logic": {
      "conditions": [...],
      "aggregation": {...}
    },
    "tags": ["ssh", "brute-force"],
    "created_at": "2025-01-01T00:00:00Z",
    "updated_at": "2025-01-01T00:00:00Z"
  }
]
```

#### GET /api/rules/:id
**Description:** Get single rule by ID

**Authentication:** Required

**Response:** Single rule object

**Errors:**
- 404: Rule not found

#### POST /api/rules
**Description:** Create new detection rule

**Authentication:** Required

**Request Body:**
```json
{
  "name": "Custom Rule",
  "description": "Detects custom threat",
  "enabled": true,
  "severity": "medium",
  "tags": ["custom", "security"],
  "rule_yaml": "name: Custom Rule\ndescription: ...\n..."
}
```

**Note:** `rule_logic` is automatically parsed from `rule_yaml`

**Response:** Created rule object (201)

**Errors:**
- 400: Missing fields or invalid YAML

#### PUT /api/rules/:id
**Description:** Update detection rule

**Authentication:** Required

**Request Body:** Partial rule object (all fields optional)

**Note:** If `rule_yaml` is updated, `rule_logic` is automatically re-parsed

**Response:** Updated rule object

**Errors:**
- 400: Invalid YAML format
- 404: Rule not found

#### DELETE /api/rules/:id
**Description:** Delete detection rule

**Authentication:** Required

**Response:**
```json
{
  "message": "Rule deleted successfully"
}
```

**Errors:**
- 404: Rule not found

### 7.3 Testing APIs

#### POST /api/parsers/test
Test parser configuration without saving (see section 7.1)

#### POST /api/parsers/:id/test
Test saved parser against sample (see section 7.1)

**Note:** There is no direct API endpoint for testing rules. Rule testing is done by:
1. Creating/enabling the rule
2. Sending test logs through the system
3. Checking the alerts table for generated alerts

---

## 8. Templates

### 8.1 Parser Template (JSON)

**Complete Template:**
```json
{
  "name": "[Application]-[LogType]",
  "description": "Parses [application] [log type] logs from [source]",
  "enabled": true,
  "priority": 50,
  "parser_type": "regex",
  "pattern": "^(?<field1>\\w+)\\s+(?<field2>\\S+)\\s+(?<field3>.+)$",
  "field_mappings": {
    "field1": "output_field1",
    "field2": "output_field2",
    "field3": "output_field3"
  },
  "test_samples": [
    "Sample log line 1 with expected format",
    "Sample log line 2 with alternative format",
    "Sample log line 3 with edge case"
  ]
}
```

**Regex Parser (Named Groups):**
```json
{
  "name": "Custom Application Parser",
  "description": "Parses custom application logs",
  "enabled": true,
  "priority": 50,
  "parser_type": "regex",
  "pattern": "^(?<timestamp>\\d{4}-\\d{2}-\\d{2}\\s+\\d{2}:\\d{2}:\\d{2})\\s+(?<level>\\w+)\\s+(?<message>.+)$",
  "field_mappings": {
    "timestamp": "timestamp",
    "level": "severity",
    "message": "message"
  },
  "test_samples": [
    "2025-11-30 14:30:00 ERROR Database connection failed"
  ]
}
```

**Regex Parser (Numbered Groups):**
```json
{
  "name": "Legacy Log Parser",
  "description": "Parses legacy format logs",
  "enabled": true,
  "priority": 75,
  "parser_type": "regex",
  "pattern": "^\\[(\\d{4}-\\d{2}-\\d{2})\\]\\s+(\\w+):\\s+(.+)$",
  "field_mappings": {
    "1": "timestamp",
    "2": "level",
    "3": "message"
  },
  "test_samples": [
    "[2025-11-30] ERROR: Connection timeout"
  ]
}
```

**JSON Parser:**
```json
{
  "name": "JSON Application Logs",
  "description": "Parses JSON-formatted application logs",
  "enabled": true,
  "priority": 50,
  "parser_type": "json",
  "pattern": "",
  "field_mappings": {},
  "test_samples": [
    "{\"timestamp\":\"2025-11-30T14:30:00Z\",\"level\":\"ERROR\",\"message\":\"Connection failed\"}"
  ]
}
```

### 8.2 Rule Template (YAML)

**Complete Template:**
```yaml
name: Descriptive Rule Name
description: Detailed explanation of what this rule detects and why it matters for security
severity: medium
enabled: true
tags: [category, threat-type, technology]

conditions:
  - field: field_name
    operator: equals
    value: "expected_value"

alert:
  title: "Alert Title with {variable} Substitution"
  description: "Detailed alert description with {field_name} and context"
```

**Simple Condition Rule:**
```yaml
name: Unauthorized Root Access
description: Detects any successful root login via SSH
severity: critical
enabled: true
tags: [ssh, root, authentication, critical]

conditions:
  - field: event
    operator: contains
    value: "Accepted"
  - field: user
    operator: equals
    value: "root"

alert:
  title: "Critical: Root SSH Login from {source_ip}"
  description: "Direct root SSH login from {source_ip} to {hostname}. Immediate investigation required."
```

**Aggregation Rule:**
```yaml
name: Brute Force Attack Detection
description: Detects multiple failed authentication attempts indicating brute force attack
severity: high
enabled: true
tags: [authentication, brute-force, attack]

conditions:
  - field: event
    operator: equals
    value: "Failed password"

aggregation:
  field: source_ip
  timeframe: 5m
  threshold: 5

alert:
  title: "Brute Force Attack from {source_ip}"
  description: "{count} failed login attempts from {source_ip} in 5 minutes. Targeted user: {user}"
```

**Complex Multi-Condition Rule:**
```yaml
name: Suspicious Command Execution
description: Detects potentially malicious commands executed with elevated privileges
severity: high
enabled: true
tags: [sudo, privilege-escalation, command-execution]

conditions:
  - field: target_user
    operator: equals
    value: "root"
  - field: command
    operator: regex
    value: "(wget|curl|nc|netcat|bash|sh|python).*(http|tcp|udp)"
  - field: command
    operator: not_contains
    value: "apt-get"

alert:
  title: "Suspicious Privileged Command by {user}"
  description: "User {user} executed suspicious command as root: {command}. Possible lateral movement or malware download."
```

### 8.3 Documentation Template

**Parser Documentation (for PARSERS.md):**

```markdown
### [Parser Name]

[Brief description of what logs this parser handles]

**Configuration:**
- **Name:** `Parser Name`
- **Description:** `Detailed description`
- **Parser Type:** `regex` | `grok` | `json`
- **Priority:** `50`

**Pattern:**
```regex
^(?<field1>pattern1)\s+(?<field2>pattern2)
```

**Field Mappings:**
| Field Name | Description |
|------------|-------------|
| `field1` | Description of field1 |
| `field2` | Description of field2 |

**Example Log:**
```
Sample log line here
```

**Parsed Fields:**
```json
{
  "field1": "value1",
  "field2": "value2"
}
```

**Use Cases:**
- Use case 1
- Use case 2
- Use case 3
```

**Rule Documentation (for RULES.md):**

```markdown
### [Rule Name]

[Brief description of what threat this rule detects]

**Configuration:**
- **Name:** `Rule Name`
- **Severity:** `medium` | `high` | `critical`
- **Tags:** `tag1`, `tag2`, `tag3`

**YAML:**
```yaml
[Complete YAML rule definition]
```

**What It Detects:**
- Specific behavior 1
- Specific behavior 2

**Use Cases:**
- Use case 1
- Use case 2

**Works With Parsers:**
- Parser 1
- Parser 2
```

---

## Appendix

### A. Field Name Registry

**Standard field names to use across all parsers:**

| Field Name | Type | Description | Example |
|------------|------|-------------|---------|
| `timestamp` | string | Event timestamp | "Nov 29 19:30:15" |
| `hostname` | string | Server/host name | "server1" |
| `source_ip` | string | Source IP address | "192.168.1.100" |
| `dest_ip` | string | Destination IP | "192.168.1.1" |
| `source_port` | string/int | Source port | "54321" |
| `dest_port` | string/int | Destination port | "443" |
| `user` | string | Username | "admin" |
| `target_user` | string | Target user (sudo) | "root" |
| `event` | string | Event type | "Failed password" |
| `action` | string | Action performed | "login", "delete" |
| `status` | string | Status/result | "success", "failure" |
| `status_code` | string/int | HTTP status | "404" |
| `method` | string | HTTP method | "GET" |
| `path` | string | URL/file path | "/api/users" |
| `protocol` | string | Network protocol | "TCP", "HTTP/1.1" |
| `severity` | string | Log severity | "ERROR", "WARN" |
| `level` | string | Log level | "ERROR", "INFO" |
| `message` | string | Full log message | Complete log text |
| `command` | string | Executed command | "/usr/bin/apt update" |
| `process` | string | Process name | "sshd" |
| `pid` | string/int | Process ID | "12345" |
| `tty` | string | Terminal | "/dev/pts/1" |
| `working_dir` | string | Working directory | "/home/user" |
| `client_ip` | string | Client IP (HTTP) | "192.168.1.50" |
| `response_size` | string/int | Response bytes | "1234" |
| `rule_name` | string | Firewall rule | "LAN_LOCAL" |
| `rule_description` | string | Rule description | "Block outbound" |
| `in_interface` | string | Input interface | "eth0" |
| `out_interface` | string | Output interface | "eth1" |
| `external_ip` | string | External IP | "156.218.17.179" |
| `internal_ip` | string | Internal IP | "192.168.1.194" |
| `external_port` | string/int | External port | "52686" |
| `internal_port` | string/int | Internal port | "80" |
| `action_type` | string | IPS action type | "ips", "ids" |
| `event_type` | string | Event category | "ssh_login" |
| `service` | string | Service name | "api", "web" |
| `module` | string | Application module | "AuthModule" |
| `facility` | string | Syslog facility | "local0" |

**Usage Guidelines:**
- Always use these standard names when applicable
- Maintain consistency across all parsers
- Add new standard names here when needed
- Document deviations from standards

### B. Tag Registry

**Standard tags for rule categorization:**

| Tag | Usage |
|-----|-------|
| `ssh` | SSH-related events |
| `authentication` | Authentication events |
| `brute-force` | Brute force attacks |
| `root` | Root/admin access |
| `privilege` | Privilege-related events |
| `privilege-escalation` | Privilege escalation attempts |
| `sudo` | Sudo command execution |
| `web` | Web server events |
| `http` | HTTP-specific events |
| `scanning` | Scanning/reconnaissance |
| `reconnaissance` | Reconnaissance activities |
| `attack` | Active attacks |
| `intrusion` | Intrusion attempts |
| `ids` | IDS events |
| `ips` | IPS events |
| `firewall` | Firewall events |
| `network` | Network-related events |
| `database` | Database events |
| `availability` | Service availability |
| `errors` | Error conditions |
| `performance` | Performance issues |
| `compliance` | Compliance violations |
| `policy` | Policy violations |
| `anomaly` | Anomalous behavior |
| `malware` | Malware detection |
| `exfiltration` | Data exfiltration |
| `lateral-movement` | Lateral movement |
| `persistence` | Persistence mechanisms |
| `credential-theft` | Credential theft |
| `dos` | Denial of service |
| `port-scan` | Port scanning |
| `vulnerability` | Vulnerability exploitation |
| `unifi` | UniFi devices |
| `linux` | Linux systems |
| `windows` | Windows systems |
| `cloud` | Cloud services |
| `container` | Container events |
| `kubernetes` | Kubernetes events |

**Guidelines:**
- Use lowercase kebab-case
- Be specific but not overly granular
- Combine tags for context (e.g., `ssh`, `brute-force`, `authentication`)
- Add new tags here when creating new categories

### C. Severity Decision Matrix

**Use this matrix to determine appropriate severity:**

| Scenario | Severity | Reasoning |
|----------|----------|-----------|
| Direct root SSH login from internet | Critical | Confirmed compromise vector |
| Direct root SSH login from internal network | High | Violation of best practices |
| 5+ failed SSH attempts in 5 min | High | Active brute force attack |
| 3-4 failed SSH attempts in 10 min | Medium | Potential attack or user error |
| Sudo to root (standard commands) | Medium | Normal admin activity |
| Sudo to root (suspicious commands) | High | Potential malicious activity |
| Web path scanning (20+ 404s in 5 min) | Medium | Reconnaissance activity |
| Web path scanning (50+ 404s in 5 min) | High | Active scanning tool |
| Server errors (5xx) spike | Low | Application issue |
| Server errors with attack indicators | Medium | Possible exploitation |
| IPS blocks from same IP (5+ in 10 min) | High | Persistent attacker |
| IPS blocks targeting same internal IP (10+ in 15 min) | Critical | Internal system under attack |
| After-hours login from known location | Low | Informational |
| After-hours login from unknown location | Medium | Suspicious timing |
| Configuration change | Low | Audit trail |
| Configuration change with other alerts | Medium | Possible compromise |

### D. Common Regex Patterns

**Reusable regex patterns for parsers:**

```regex
# Timestamps
\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}              # 2025-11-30 14:30:00
\w+\s+\d+\s+\d{2}:\d{2}:\d{2}                      # Nov 30 14:30:00
\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}     # 30/Nov/2025:14:30:00 +0000

# IP Addresses
(?:[0-9]{1,3}\.){3}[0-9]{1,3}                      # IPv4
[0-9a-fA-F:]{2,39}                                  # IPv6

# Hostnames
[a-zA-Z0-9][a-zA-Z0-9\-\.]*[a-zA-Z0-9]             # Hostname

# Usernames
[a-zA-Z0-9_\-\.@]+                                  # Username

# File Paths
/(?:[^/\s]+/)*[^/\s]*                              # Unix path
[a-zA-Z]:\\(?:[^\\]+\\)*[^\\]*                     # Windows path

# URLs
https?://[^\s]+                                     # URL

# Email
[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}    # Email

# Process IDs
\d+                                                 # PID

# Port Numbers
\d{1,5}                                            # Port

# Log Levels
(?:TRACE|DEBUG|INFO|WARN|ERROR|FATAL|CRITICAL)    # Log level
```

### E. Testing Checklist

**Pre-Deployment Checklist:**

**Parsers:**
- [ ] Parser name follows convention
- [ ] Description is clear and complete
- [ ] Priority is appropriate for specificity
- [ ] Pattern has been tested with real logs
- [ ] All relevant fields are extracted
- [ ] Field names use standard registry names
- [ ] At least 3 test samples included
- [ ] Test samples cover variations
- [ ] No regex catastrophic backtracking
- [ ] Pattern is specific enough to avoid false matches

**Rules:**
- [ ] Rule name is descriptive and actionable
- [ ] Description explains threat and context
- [ ] Severity level is appropriate
- [ ] Tags use standard registry
- [ ] Conditions are specific enough
- [ ] Aggregation threshold is tuned
- [ ] Aggregation timeframe is appropriate
- [ ] Alert title is clear and scannable
- [ ] Alert description includes context
- [ ] Variable substitution tested
- [ ] Rule tested with positive cases
- [ ] Rule tested with negative cases
- [ ] False positive rate acceptable
- [ ] Compatible parsers documented

**Documentation:**
- [ ] Parser documented in PARSERS.md
- [ ] Rule documented in RULES.md
- [ ] Examples included
- [ ] Use cases listed
- [ ] Integration points noted

### F. Troubleshooting Guide

**Common Issues:**

**Parser Not Matching:**
1. Check parser is enabled
2. Verify priority order
3. Test pattern in isolation with `/api/parsers/test`
4. Check for special character escaping
5. Verify log format hasn't changed

**Rule Not Triggering:**
1. Check rule is enabled
2. Verify parser is extracting required fields
3. Check condition operators and values
4. Test aggregation threshold with query
5. Verify timeframe calculations

**False Positives:**
1. Increase aggregation threshold
2. Add exclusion conditions (not_contains)
3. Make conditions more specific
4. Exclude known-good IPs/users
5. Adjust severity if appropriate

**Performance Issues:**
1. Optimize regex patterns
2. Reduce enabled parsers
3. Tune aggregation timeframes
4. Add database indexes
5. Implement log retention

**Field Not Extracted:**
1. Verify field in pattern
2. Check field_mappings configuration
3. Test with sample log
4. Check for optional groups
5. Verify log format

### G. Migration Notes

**Version Compatibility:**
- Current schema version: 1.0
- Database migrations in `/backend/migrations/`
- No breaking changes in current version

**Future Considerations:**
- Grok library integration planned
- Advanced aggregation operators planned
- Rule chaining/correlation planned
- Machine learning detection planned

---

## Version History

**Version 1.0** (2025-12-03)
- Initial specification
- Complete parser system documentation
- Complete rule system documentation
- Conventions and best practices
- Templates and examples

---

## Contributors

This specification was developed to support the SIEMBox project's goal of providing a flexible, community-driven SIEM solution.

**Project Repository:** https://github.com/cladkins/SIEMBOX

---

**End of Specification**
