# SIEMBox Community Parsers

This document contains community-contributed log parsers for SIEMBox. These parsers can be imported into your SIEMBox instance to parse various types of logs.

## Table of Contents
- [Parser Development Guide](#parser-development-guide)
  - [Understanding the Two-Stage Pipeline](#understanding-the-two-stage-pipeline)
  - [Step-by-Step Parser Creation](#step-by-step-parser-creation)
  - [Testing Your Parser](#testing-your-parser)
  - [Common Issues and Solutions](#common-issues-and-solutions)
- [Built-in Parsers](#built-in-parsers)
  - [SSH Authentication](#ssh-authentication)
  - [Apache/Nginx Access Log](#apachenginx-access-log)
  - [NGINX Custom Format](#nginx-custom-format)
  - [Linux Sudo](#linux-sudo)
  - [Generic Syslog](#generic-syslog)
  - [JSON Parser](#json-parser)
- [Standard Format Parsers](#standard-format-parsers)
  - [CEF (Common Event Format)](#cef-common-event-format)
- [Community Parsers](#community-parsers)
  - [Ubiquiti UniFi](#ubiquiti-unifi)
    - [Firewall Logs](#unifi-firewall)
    - [IDS/IPS Logs](#unifi-idsips)

---

## Parser Development Guide

### Understanding the Two-Stage Pipeline

SIEMBox processes syslog messages in two stages:

**Stage 1: Syslog Extraction** - The syslog server (`backend/src/services/syslog/syslogParser.ts`) receives messages like:
```
<134>Dec 09 20:36:20 webserver NGINX: [09/Dec/2025:20:35:53 +0000] - 200 200 - GET
```

It extracts the **message portion only** and stores it in `raw_logs.raw_message`:
```
[09/Dec/2025:20:35:53 +0000] - 200 200 - GET
```

**Stage 2: Application Parsing** - Your parser matches against the extracted message:
```regex
^\[(?<timestamp>[^\]]+)\]...
```

**Critical:** Parser patterns must NOT include the syslog wrapper (`<PRI>TIMESTAMP HOSTNAME TAG:`). They match only the extracted message content.

### Step-by-Step Parser Creation

#### 1. Analyze Your Log Format

First, query the database to see what your `raw_message` actually contains:

```sql
-- See actual message content that parsers will match against
SELECT
  id,
  LEFT(raw_message, 100) as message_preview,
  app_name,
  hostname
FROM raw_logs
WHERE app_name = 'YourApp'  -- or source_ip = 'x.x.x.x'
ORDER BY created_at DESC
LIMIT 10;
```

**Example output:**
```
message_preview: [09/Dec/2025:20:35:53 +0000] - 200 200 - GET
app_name: NGINX
hostname: webserver
```

#### 2. Design Your Regex Pattern

Create a pattern that matches the **extracted message** format:

**Good pattern:**
```regex
^\[(?<timestamp>[^\]]+)\]\s+(?:-\s+)?(?<status_code>\d{3})?...
```

**Bad pattern (includes syslog wrapper):**
```regex
^<\d+>\w+\s+\d+.*NGINX: \[(?<timestamp>...
```

**Tips for regex patterns:**
- Start with `^` to anchor to the beginning
- Use named groups: `(?<field_name>...)`
- Make optional fields optional: `(?<field>...)?`
- Test complex patterns incrementally
- Use non-greedy matching: `.*?` instead of `.*`

#### 3. Create a Test Script

Use `backend/test-nginx-patterns.js` as a template:

```javascript
const testSamples = [
  {
    name: 'Your log format',
    message: '[actual raw_message from database]',
    expectedFields: {
      field1: 'expected_value',
      field2: 'expected_value'
    }
  }
];

const pattern = /your-regex-pattern/;

testSamples.forEach(sample => {
  const match = sample.message.match(pattern);
  console.log(match ? match.groups : 'No match');
});
```

Run the test:
```bash
node backend/test-your-parser-patterns.js
```

#### 4. Set Parser Priority

Priority determines matching order (lower number = higher priority):

- **1-20:** Critical system parsers (SSH, auth logs)
- **30-50:** Application parsers (web servers, databases)
- **40-50:** Custom format variants (nginx-custom, custom apps)
- **100-500:** Generic parsers
- **1000+:** Fallback parsers (generic syslog)

**Priority Strategy:**
- Custom parsers should have **higher priority** than standard parsers
- Example: `nginx-custom-timestamp-first` (45) before `standard-nginx-access` (40)
- This prevents false matches on partial patterns

#### 5. Add Parser to Database

**Option A: Migration File (Recommended for production)**

Create `backend/migrations/00X_add_your_parser.sql`:

```sql
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, enabled)
VALUES (
    'your-parser-name',
    'Parses your custom log format',
    'regex',
    45,
    '^your-regex-pattern',
    '{"field1": "mapped_name1", "field2": "mapped_name2"}',
    true
)
ON CONFLICT (name) DO NOTHING;
```

Apply migration:
```bash
psql -U siembox -d siembox -f backend/migrations/00X_add_your_parser.sql
```

**Option B: Via API (for testing)**

```bash
curl -X POST http://localhost:8420/api/parsers \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "your-parser-name",
    "description": "Parses your custom log format",
    "parser_type": "regex",
    "priority": 45,
    "pattern": "^your-regex-pattern",
    "field_mappings": {
      "field1": "mapped_name1",
      "field2": "mapped_name2"
    },
    "enabled": true
  }'
```

#### 6. Verify Parser Works

Check if logs are being parsed:

```sql
-- Count parsed logs by parser
SELECT
  p.name,
  COUNT(*) as parsed_count
FROM parsed_logs pl
JOIN parsers p ON pl.parser_id = p.id
WHERE p.name = 'your-parser-name'
GROUP BY p.name;

-- View parsed data samples
SELECT
  pl.id,
  pl.parsed_data,
  rl.raw_message
FROM parsed_logs pl
JOIN raw_logs rl ON pl.raw_log_id = rl.id
JOIN parsers p ON pl.parser_id = p.id
WHERE p.name = 'your-parser-name'
LIMIT 5;
```

### Testing Your Parser

**Unit Testing - Test regex patterns in isolation:**

```javascript
// test-your-parser.js
const pattern = /your-pattern/;
const testCases = [
  { message: 'log sample 1', shouldMatch: true },
  { message: 'log sample 2', shouldMatch: true },
  { message: 'different log', shouldMatch: false }
];

testCases.forEach(test => {
  const matches = pattern.test(test.message);
  console.log(`${test.message}: ${matches === test.shouldMatch ? 'PASS' : 'FAIL'}`);
});
```

**Integration Testing - Test with actual database:**

```sql
-- Test against recent logs
SELECT
  id,
  raw_message,
  CASE
    WHEN raw_message ~ 'your-regex-pattern' THEN 'MATCH'
    ELSE 'NO MATCH'
  END as test_result
FROM raw_logs
WHERE app_name = 'YourApp'
LIMIT 10;
```

**Field Extraction Testing:**

```javascript
// Verify all expected fields are extracted
const match = logMessage.match(yourPattern);
const groups = match.groups;

// Check required fields
assert(groups.timestamp !== undefined, 'timestamp missing');
assert(groups.field1 !== undefined, 'field1 missing');

// Check field values
assert(/^\d{4}\/\d{2}\/\d{2}/.test(groups.timestamp), 'invalid timestamp format');
```

### Common Issues and Solutions

#### Issue 1: Parser Not Matching Logs

**Symptoms:**
- Logs appear in `raw_logs` but not `parsed_logs`
- Parser never shows up in statistics

**Diagnosis:**
```sql
-- Check what parsers see
SELECT LEFT(raw_message, 100) FROM raw_logs WHERE app_name = 'YourApp' LIMIT 5;

-- Test pattern manually
SELECT
  raw_message,
  raw_message ~ 'your-pattern' as matches
FROM raw_logs
WHERE app_name = 'YourApp'
LIMIT 10;
```

**Solutions:**
1. Verify pattern matches extracted message (not full syslog)
2. Check for hidden characters or encoding issues
3. Test with actual `raw_message` content from database
4. Simplify pattern and add complexity incrementally

#### Issue 2: Wrong Parser Matching Logs

**Symptoms:**
- Logs parsed by wrong parser
- Fields extracted incorrectly

**Diagnosis:**
```sql
-- Check parser priority ordering
SELECT name, priority, pattern
FROM parsers
WHERE enabled = true
ORDER BY priority ASC;
```

**Solutions:**
1. Adjust priority - lower numbers match first
2. Make patterns more specific to avoid false matches
3. Use anchors (`^` and `$`) to match exact formats
4. Add unique identifiers to patterns

#### Issue 3: Some Fields Not Extracted

**Symptoms:**
- Parser matches but some fields are null/missing
- `parsed_data` incomplete

**Diagnosis:**
```javascript
// Test field extraction
const match = message.match(pattern);
console.log('Matched:', match !== null);
console.log('Groups:', match?.groups);
```

**Solutions:**
1. Make optional fields optional: `(?<field>...)?`
2. Check regex group names match field_mappings
3. Verify field values aren't empty strings
4. Test against various log samples with different field combinations

#### Issue 4: Parser Performance Issues

**Symptoms:**
- Slow log processing
- High CPU usage
- Parser timeouts

**Solutions:**
1. Avoid catastrophic backtracking in regex
2. Use non-greedy matching: `.*?` instead of `.*`
3. Anchor patterns with `^` to fail fast on non-matches
4. Simplify complex nested groups
5. Consider parser priority - put most common parsers first

---

## Built-in Parsers

These parsers are automatically included with every SIEMBox installation.

### SSH Authentication

Parses SSH authentication logs for both successful and failed login attempts.

**Configuration:**
- **Name:** `SSH Authentication`
- **Description:** `Parses SSH authentication logs (success and failure)`
- **Parser Type:** `Regex`
- **Priority:** `10`

**Pattern:**
```regex
^(?<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?<hostname>\S+)\s+sshd\[(?<pid>\d+)\]:\s+(?<event>Failed password|Accepted password|Accepted publickey)\s+for\s+(?<user>\S+)\s+from\s+(?<src_ip>[\d.]+)\s+port\s+(?<src_port>\d+)
```

**Field Mappings (Named Groups):**
| Field Name | Description |
|------------|-------------|
| `timestamp` | Event timestamp |
| `hostname` | Server hostname |
| `pid` | SSH daemon process ID |
| `event` | Event type (Failed/Accepted password/publickey) |
| `user` | Username attempting authentication |
| `source_ip` | Source IP address |
| `source_port` | Source port number |

**Example Log:**
```
Nov 29 19:30:15 server1 sshd[12345]: Failed password for root from 192.0.2.100 port 54321
```

**Parsed Fields:**
```json
{
  "timestamp": "Nov 29 19:30:15",
  "hostname": "server1",
  "pid": "12345",
  "event": "Failed password",
  "user": "root",
  "source_ip": "192.0.2.100",
  "source_port": "54321"
}
```

**Use Cases:**
- Detect brute force attacks
- Monitor failed login attempts
- Track root login attempts
- Audit successful SSH connections

---

### Apache/Nginx Access Log

Parses standard Apache and Nginx combined access log format.

**Configuration:**
- **Name:** `Apache/Nginx Access Log`
- **Description:** `Parses standard Apache/Nginx access logs`
- **Parser Type:** `Regex`
- **Priority:** `20`

**Pattern:**
```regex
^(?<client_ip>[\d.]+)\s+-\s+-\s+\[(?<timestamp>[^\]]+)\]\s+"(?<method>\S+)\s+(?<path>\S+)\s+(?<protocol>[^"]+)"\s+(?<status>\d+)\s+(?<size>\d+)
```

**Field Mappings (Named Groups):**
| Field Name | Description |
|------------|-------------|
| `client_ip` | Client IP address |
| `timestamp` | Request timestamp |
| `method` | HTTP method (GET/POST/etc) |
| `path` | Request path/URI |
| `protocol` | HTTP protocol version |
| `status_code` | HTTP status code |
| `response_size` | Response size in bytes |

**Example Log:**
```
192.0.2.50 - - [29/Nov/2025:19:45:23 +0000] "GET /api/users HTTP/1.1" 200 1234
```

**Parsed Fields:**
```json
{
  "client_ip": "192.0.2.50",
  "timestamp": "29/Nov/2025:19:45:23 +0000",
  "method": "GET",
  "path": "/api/users",
  "protocol": "HTTP/1.1",
  "status_code": "200",
  "response_size": "1234"
}
```

**Use Cases:**
- Detect directory scanning (multiple 404s)
- Monitor server errors (5xx codes)
- Track API usage patterns
- Identify suspicious paths

---

### NGINX Custom Format

Parses custom NGINX log formats that use non-standard formatting.

**Background:**
This parser handles NGINX logs with custom `log_format` directives that don't follow the standard combined format. After syslog extraction, these logs start with timestamps instead of client IPs.

#### Parser 1: Timestamp-First Access Logs

**Configuration:**
- **Name:** `nginx-custom-timestamp-first`
- **Description:** `Parses custom NGINX access logs that start with timestamp`
- **Parser Type:** `Regex`
- **Priority:** `45` (higher than standard NGINX parser)

**Pattern:**
```regex
^\[(?<timestamp>[^\]]+)\]\s+(?:-\s+)?(?<status_code1>\d{3})?\s*(?<status_code2>\d{3})?\s*-?\s*(?<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)?\s*(?<protocol>https?|wss?)?\s*(?<request_uri>\S+)?
```

**Field Mappings:**
| Field Name | Description |
|------------|-------------|
| `timestamp` | Request timestamp in NGINX format |
| `status_code` | HTTP status code (primary) |
| `upstream_status` | Upstream/backend status code |
| `method` | HTTP method |
| `protocol` | Protocol (http/https/ws/wss) |
| `request_uri` | Request URI/path |
| `service` | Always "nginx-custom" |

**Example Logs:**
```
[09/Dec/2025:20:35:53 +0000] - 200 200 - GET
[09/Dec/2025:20:12:14 +0000] 301 - GET http w
```

**Parsed Fields:**
```json
{
  "timestamp": "09/Dec/2025:20:35:53 +0000",
  "status_code": "200",
  "upstream_status": "200",
  "method": "GET",
  "service": "nginx-custom"
}
```

#### Parser 2: Error Logs

**Configuration:**
- **Name:** `nginx-komodo-error`
- **Description:** `Parses NGINX error logs from komodo system`
- **Parser Type:** `Regex`
- **Priority:** `44`

**Pattern:**
```regex
^(?<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?<log_level>\w+)\]\s+(?<pid>\d+)#(?<worker_id>\d+):\s+\*(?<connection_id>\d+)\s*(?<message>.*)?
```

**Field Mappings:**
| Field Name | Description |
|------------|-------------|
| `timestamp` | Error timestamp (YYYY/MM/DD format) |
| `log_level` | Error level (error/warn/notice/info) |
| `pid` | NGINX process ID |
| `worker_id` | NGINX worker process ID |
| `connection_id` | Connection identifier |
| `error_message` | Full error message |
| `service` | Always "nginx-custom" |

**Example Logs:**
```
2025/12/08 19:37:36 [error] 1484#1484: *17597 upstream timed out
2025/12/09 19:57:00 [warn] 1484#1484: *24156 upstream server temporarily disabled
```

**Parsed Fields:**
```json
{
  "timestamp": "2025/12/08 19:37:36",
  "log_level": "error",
  "pid": "1484",
  "worker_id": "1484",
  "connection_id": "17597",
  "error_message": "upstream timed out",
  "service": "nginx-custom"
}
```

#### Parser 3: IP-Only Minimal Format

**Configuration:**
- **Name:** `nginx-komodo-ip-only`
- **Description:** `Parses minimal NGINX access logs from komodo with only IP address`
- **Parser Type:** `Regex`
- **Priority:** `43`

**Pattern:**
```regex
^(?<client_ip>[\d.]+)\s+-\s*(?<message>.*)?
```

**Field Mappings:**
| Field Name | Description |
|------------|-------------|
| `client_ip` | Client IP address |
| `message` | Additional content if present |
| `service` | Always "nginx-custom" |

**Example Logs:**
```
68.218.17.107 -
192.0.2.100 - some additional content
```

**Use Cases:**
- Monitor custom NGINX deployments with non-standard log formats
- Parse logs from systems with custom `log_format` directives
- Handle truncated or partial log entries
- Track both access and error logs from the same source

**Important Notes:**
- These parsers have **higher priority (45, 44, 43)** than standard NGINX parsers (40, 39)
- This ensures custom format logs match before falling back to standard parsers
- Designed for syslog-extracted messages (message portion only, no syslog headers)
- Reference: Migration `003_add_nginx_custom_parsers.sql`

---

### Linux Sudo

Parses Linux sudo command execution logs.

**Configuration:**
- **Name:** `Linux Sudo`
- **Description:** `Parses sudo command execution logs`
- **Parser Type:** `Regex`
- **Priority:** `15`

**Pattern:**
```regex
^(?<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?<hostname>\S+)\s+sudo:\s+(?<user>\S+)\s+:\s+TTY=(?<tty>\S+)\s+;\s+PWD=(?<pwd>\S+)\s+;\s+USER=(?<target_user>\S+)\s+;\s+COMMAND=(?<command>.+)$
```

**Field Mappings (Named Groups):**
| Field Name | Description |
|------------|-------------|
| `timestamp` | Event timestamp |
| `hostname` | Server hostname |
| `user` | User executing sudo |
| `tty` | Terminal identifier |
| `working_dir` | Current working directory |
| `target_user` | User being impersonated |
| `command` | Command being executed |

**Example Log:**
```
Nov 29 20:15:30 server1 sudo: john : TTY=/dev/pts/1 ; PWD=/home/john ; USER=root ; COMMAND=/usr/bin/apt update
```

**Parsed Fields:**
```json
{
  "timestamp": "Nov 29 20:15:30",
  "hostname": "server1",
  "user": "john",
  "tty": "/dev/pts/1",
  "working_dir": "/home/john",
  "target_user": "root",
  "command": "/usr/bin/apt update"
}
```

**Use Cases:**
- Monitor privilege escalation
- Track root command execution
- Audit administrative actions
- Detect unauthorized sudo usage

---

### Generic Syslog

Fallback parser for standard RFC 3164 syslog format. This parser has the lowest priority (1000) and catches any logs that don't match specific parsers.

**Configuration:**
- **Name:** `Generic Syslog`
- **Description:** `Fallback parser for standard syslog format`
- **Parser Type:** `Regex`
- **Priority:** `1000`

**Pattern:**
```regex
^(?<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?<hostname>\S+)\s+(?<process>\S+?)(?:\[(?<pid>\d+)\])?:\s+(?<message>.+)$
```

**Field Mappings (Named Groups):**
| Field Name | Description |
|------------|-------------|
| `timestamp` | Event timestamp |
| `hostname` | Server hostname |
| `process` | Process name |
| `pid` | Process ID (optional) |
| `message` | Log message |

**Example Log:**
```
Nov 29 20:30:45 server1 cron[9876]: (root) CMD (/usr/bin/backup.sh)
```

**Parsed Fields:**
```json
{
  "timestamp": "Nov 29 20:30:45",
  "hostname": "server1",
  "process": "cron",
  "pid": "9876",
  "message": "(root) CMD (/usr/bin/backup.sh)"
}
```

**Use Cases:**
- Catch-all for unmatched syslog messages
- General system log monitoring
- Baseline for creating specific parsers

---

### JSON Parser

Automatically parses logs that are already in JSON format. No field mappings required - all JSON fields are extracted automatically.

**Configuration:**
- **Name:** `JSON Parser`
- **Description:** `Parses logs already in JSON format`
- **Parser Type:** `JSON`
- **Priority:** `50`

**Example Log:**
```json
{"timestamp":"2025-11-29T20:45:00Z","level":"error","service":"api","message":"Database connection failed","user_id":123}
```

**Parsed Fields:**
All JSON fields are automatically extracted:
```json
{
  "timestamp": "2025-11-29T20:45:00Z",
  "level": "error",
  "service": "api",
  "message": "Database connection failed",
  "user_id": 123
}
```

**Use Cases:**
- Modern application logs
- Cloud service logs
- Container logs (Docker, Kubernetes)
- API gateway logs

---

## Standard Format Parsers

### CEF (Common Event Format)

CEF (Common Event Format) is a standard log format developed by ArcSight (now Micro Focus) and widely adopted by security vendors. SIEMBox includes built-in parsers for CEF logs.

#### CEF Format Overview

```
CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
```

**Example CEF Messages:**
```
CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232

CEF:0|Trend Micro|OSSEC HIDS|1.0.1|535|New ossec agent connected|4|src=192.168.1.100 suser=admin

CEF:0|Palo Alto Networks|PAN-OS|10.0|threat|THREAT|8|src=10.1.1.1 dst=8.8.8.8 act=block-url msg=Malware URL blocked
```

#### CEF Standard Parser

Parses basic CEF format logs.

**Configuration:**
- **Name:** `cef-standard`
- **Description:** `Parses Common Event Format (CEF) logs used by security products`
- **Parser Type:** `Regex`
- **Priority:** `5`
- **Event Type:** `cef_event`

**Pattern:**
```regex
^CEF:(?<cef_version>\d+)\|(?<device_vendor>[^|]*)\|(?<device_product>[^|]*)\|(?<device_version>[^|]*)\|(?<signature_id>[^|]*)\|(?<event_name>[^|]*)\|(?<severity>[^|]*)\|(?<extension>.*)$
```

**Extracted Fields:**
| Field | Description | Example |
|-------|-------------|---------|
| `cef_version` | CEF format version | `0` |
| `device_vendor` | Vendor name | `Palo Alto Networks` |
| `device_product` | Product name | `PAN-OS` |
| `device_version` | Product version | `10.0` |
| `signature_id` | Event/signature identifier | `threat` |
| `event_name` | Human-readable event name | `THREAT` |
| `severity` | Severity level (0-10) | `8` |
| `extension` | Key=value pairs | `src=10.1.1.1 dst=8.8.8.8` |

#### CEF with Syslog Header Parser

Parses CEF logs that include a syslog header prefix (common when CEF is transported via syslog).

**Configuration:**
- **Name:** `cef-syslog`
- **Description:** `Parses CEF logs with syslog header prefix`
- **Parser Type:** `Regex`
- **Priority:** `4`
- **Event Type:** `cef_event`

**Example Input:**
```
Jan 18 11:07:53 hostname CEF:0|Security|Product|1.0|100|Event|5|src=10.0.0.1
```

**Additional Fields:**
| Field | Description |
|-------|-------------|
| `syslog_timestamp` | Syslog timestamp |
| `syslog_host` | Syslog hostname |

#### CEF Extension Fields

Common CEF extension key=value pairs that may appear in the extension field:

| Key | Full Name | Description | Example |
|-----|-----------|-------------|---------|
| `src` | Source IP | Source IP address | `10.0.0.1` |
| `dst` | Destination IP | Destination IP address | `192.168.1.1` |
| `spt` | Source Port | Source port number | `45123` |
| `dpt` | Destination Port | Destination port number | `443` |
| `act` | Action | Action taken | `block`, `allow` |
| `msg` | Message | Human-readable message | `Malware detected` |
| `suser` | Source User | Source username | `admin` |
| `duser` | Destination User | Destination username | `root` |
| `fname` | Filename | File name involved | `malware.exe` |
| `request` | Request URL | HTTP request URL | `/api/login` |
| `outcome` | Outcome | Result of the action | `success`, `failure` |
| `reason` | Reason | Reason for the action | `policy violation` |
| `cs1-cs6` | Custom Strings | Vendor-specific strings | varies |
| `cn1-cn3` | Custom Numbers | Vendor-specific numbers | varies |

#### Products Using CEF Format

CEF is supported by many security products including:
- **ArcSight** (Micro Focus)
- **Trend Micro** (Deep Security, OSSEC)
- **Palo Alto Networks** (PAN-OS)
- **Fortinet** (FortiGate)
- **Check Point**
- **McAfee** (ESM)
- **Cisco** (Firepower, ASA)
- **CrowdStrike**
- **Carbon Black**
- **Symantec** (Endpoint Protection)

#### Configuring CEF Sources

To send CEF logs to SIEMBox:

1. Configure your security product to output CEF format
2. Set the syslog destination to your SIEMBox server (port 514)
3. CEF logs will be automatically detected and parsed

**Example: Palo Alto PAN-OS**
```
set shared log-settings syslog <profile> server <server> transport UDP
set shared log-settings syslog <profile> server <server> port 514
set shared log-settings syslog <profile> server <server> format BSD
set shared log-settings syslog <profile> server <server> facility LOG_USER
```

---

## Community Parsers

## Ubiquiti UniFi

### UniFi Firewall

Parses Ubiquiti UniFi (UCG-Max) firewall rule logs.

**Configuration:**
- **Name:** `Ubiquiti UniFi Firewall`
- **Description:** `Parser for Ubiquiti UniFi router firewall logs`
- **Parser Type:** `Regex`
- **Priority:** `50`

**Pattern:**
```regex
\[([^\]]+)\].*?DESCR="([^"]+)".*?IN=(\S+).*?OUT=(\S*).*?SRC=([\d\.]+).*?DST=([\d\.]+).*?PROTO=(\w+)
```

**Field Mappings:**
| Group | Field Name | Description |
|-------|------------|-------------|
| 1 | `rule_name` | Firewall rule name |
| 2 | `rule_description` | Rule description |
| 3 | `in_interface` | Input network interface |
| 4 | `out_interface` | Output network interface |
| 5 | `source_ip` | Source IP address |
| 6 | `dest_ip` | Destination IP address |
| 7 | `protocol` | Network protocol (TCP/UDP/etc) |

**Example Log:**
```
<13>Nov 29 19:44:35 UCG-Max [LAN_LOCAL-RET-2147483647] DESCR="no rule description" IN=br0 OUT= MAC=01:00:5e:00:00:fb:5e:07:7d:96:02:d7:08:00 SRC=192.0.2.158 DST=224.0.0.251 LEN=473 TOS=00 PREC=0x00 TTL=255 ID=62191 PROTO=UDP SPT=5353 DPT=5353 LEN=453 MARK=1a0000
```

**Parsed Fields:**
```json
{
  "rule_name": "LAN_LOCAL-RET-2147483647",
  "rule_description": "no rule description",
  "in_interface": "br0",
  "out_interface": "",
  "source_ip": "192.0.2.158",
  "dest_ip": "224.0.0.251",
  "protocol": "UDP"
}
```

---

### UniFi IDS/IPS

Parses Ubiquiti UniFi IDS/IPS daemon event logs.

**Configuration:**
- **Name:** `Ubiquiti UniFi IDS/IPS`
- **Description:** `Parser for Ubiquiti UniFi IDS/IPS daemon logs`
- **Parser Type:** `Regex`
- **Priority:** `50`

**Pattern:**
```regex
ubnt-idsips-daemon\[\d+\]:\s+[\d-]+T[\d:.-]+\s+(\w+):\s+(.+?):\s+ipset\[(\w+)\]\s+(\w+)\s+failed\s+ip1:([\d.]+),\s+port1:(\d+),\s+ip2:([\d.]+),\s+port2:(\d+),\s+proto:(\w+)
```

**Field Mappings:**
| Group | Field Name | Description |
|-------|------------|-------------|
| 1 | `severity` | Log severity level (Warn/Error/Info) |
| 2 | `event_type` | Type of event |
| 3 | `action_type` | IPS action type |
| 4 | `action` | Action taken |
| 5 | `external_ip` | External/source IP address |
| 6 | `external_port` | External/source port |
| 7 | `internal_ip` | Internal/destination IP |
| 8 | `internal_port` | Internal/destination port |
| 9 | `protocol` | Network protocol |

**Example Log:**
```
<28>Nov 29 15:51:19 UCG-Max UCG-Max ubnt-idsips-daemon[2402]: 2025-11-29T15:51:19.543-0600 Warn: error handling event: ipset[ips] add failed ip1:198.51.100.179, port1:52686, ip2:192.0.2.194, port2:80, proto:tcp, err1:ipset v7.10: Element cannot be added to the set: it's already added
```

**Parsed Fields:**
```json
{
  "severity": "Warn",
  "event_type": "error handling event",
  "action_type": "ips",
  "action": "add",
  "external_ip": "156.218.17.179",
  "external_port": "52686",
  "internal_ip": "192.0.2.194",
  "internal_port": "80",
  "protocol": "tcp"
}
```

---

## Contributing Parsers

We welcome community parser contributions! If you've created a parser for a log source not yet supported by SIEMBox, share it with the community.

### How to Contribute a Parser

1. **Develop and test your parser** using the guide in this document
2. **Create a pull request** with:
   - Parser configuration (name, type, pattern, field mappings)
   - Multiple example log samples showing different scenarios
   - Expected parsed output for each sample
   - Any relevant detection rules that work with this parser
3. **Include documentation** with:
   - What log source this parser handles
   - Required parser type (regex/grok/JSON)
   - Performance considerations (if any)
   - Special configuration notes

### Parser Guidelines

- **Naming**: Use descriptive names that include vendor/product (e.g., "nginx-custom-timestamp")
- **Priority**: Set appropriate priority (1-20 for critical, 30-50 for applications, 100+ for fallback)
- **Field Mappings**: Include comprehensive, consistent field names
- **Testing**: Test with multiple log samples covering edge cases
- **Documentation**: Clearly explain what the parser does and when to use it
- **Performance**: Avoid complex regex that could cause slowdowns
- **Compatibility**: Ensure pattern works with extracted messages (not full syslog lines)

### Submission Tips

- Include real log samples from your environment (sanitized if needed)
- Test that the parser doesn't interfere with existing parsers
- Document any dependencies or assumptions
- Provide examples of what the parser detects (e.g., "Detects SSH brute force")
- Be prepared to update based on feedback

---

## Detection Rules

Parsers work best when paired with detection rules. Check out the [Rules Documentation](./RULES.md) for examples of rules that work with these parsers.
