# Critical Application Parsers for SIEMBox

**Version:** 1.0
**Date:** 2025-12-03
**Purpose:** Critical application parsers for password management, file storage, and DNS security in homelab SIEM deployments

---

## Overview

### Why Critical Application Parsers Are MANDATORY

These applications store your most sensitive data and control critical infrastructure. They are the **highest-value targets** in your homelab:

1. **Vaultwarden (152 users)** - PASSWORD MANAGER
   - **Impact if compromised:** CATASTROPHIC - ALL credentials lost
   - Contains passwords to EVERY other service
   - Single point of total failure
   - Most valuable target for attackers

2. **Nextcloud (118 users)** - FILE SHARING/STORAGE
   - **Impact if compromised:** SEVERE - Personal data theft
   - Contains documents, photos, sensitive files
   - Privacy violation, identity theft risk
   - High-value data exfiltration target

3. **Pi-hole (50 users)** - DNS SECURITY
   - **Impact if compromised:** HIGH - Network surveillance
   - First line of defense against malicious domains
   - DNS poisoning can redirect all traffic
   - Indicator of compromised IoT devices

**Bottom Line:** These 3 parsers are NON-NEGOTIABLE. If attackers compromise Vaultwarden, your entire homelab (and beyond) is compromised. If they compromise Nextcloud, your personal data is stolen. If they compromise Pi-hole, they can redirect and monitor all your traffic.

### Threat Context

**Vaultwarden Threats (CRITICAL):**
- Master password brute force (PWDMGR-001)
- Vault export/mass download (credential theft)
- API token abuse (automated harvesting)
- Session hijacking (token theft)
- Database file theft (offline attacks)

**Nextcloud Threats (HIGH):**
- Bulk file download (EXFIL-001)
- Authentication brute force (AUTH-005)
- Share link abuse (data leakage)
- Sensitive file enumeration
- API abuse (automated scraping)

**Pi-hole Threats (MEDIUM-HIGH):**
- DNS tunneling (EXFIL-003)
- Query volume anomalies (malware C2)
- Blocked domain patterns (compromise indicators)
- DNSSEC validation failures (DNS poisoning)
- Query source anomalies (IoT compromise)

### What These Parsers Enable

With these parsers deployed, you can detect:

**Vaultwarden:**
- Failed master password attempts (very low threshold)
- Vault export operations
- Mass credential access
- API authentication failures
- Unusual device registrations
- Geographic access anomalies

**Nextcloud:**
- Bulk file downloads (exfiltration)
- Failed authentication attempts
- Mass file access patterns
- Public share creation
- Sensitive file access
- API abuse patterns

**Pi-hole:**
- DNS tunneling attempts
- Malware C2 beaconing
- Unusual query volumes
- Blocked domain clustering
- DNSSEC failures
- Compromised device indicators

---

## Table of Contents

1. [Parser 1: Vaultwarden](#parser-1-vaultwarden)
2. [Parser 2: Nextcloud](#parser-2-nextcloud)
3. [Parser 3: Pi-hole](#parser-3-pi-hole)
4. [Appendix A: Common Patterns](#appendix-a-common-patterns)
5. [Appendix B: Installation Guide](#appendix-b-installation-guide)
6. [Appendix C: Troubleshooting](#appendix-c-troubleshooting)

---

## Parser 1: Vaultwarden

### Overview

**Priority:** CRITICAL (55 - HIGHEST PRIORITY IN ENTIRE SYSTEM)

**About Vaultwarden:**
Vaultwarden is a lightweight, unofficial Bitwarden-compatible server written in Rust. It's the most popular password manager for homelabs (152 users) due to its minimal resource requirements and full Bitwarden compatibility. Vaultwarden stores ALL user credentials, making it the single highest-value target in any homelab.

**Security Relevance (CRITICAL PRIORITY):**
- **Single Point of Total Failure** - Compromise grants access to ALL stored passwords
- **Catastrophic Impact** - Loss of Vaultwarden = loss of every account password
- **High-Value Target** - Attackers specifically seek password managers
- **Master Password Critical** - Single password protects entire vault
- **Export = Total Theft** - Vault export provides all credentials at once
- **API Abuse Risk** - Automated credential harvesting possible
- **Session Hijacking** - Token theft provides temporary full access

**Default Log Locations:**
- Container logs: Docker stdout (text format by default)
- File logs: `/data/vaultwarden.log` (if configured)
- Format: Structured text with timestamps

**Log Format Characteristics:**
- Timestamp format: `[YYYY-MM-DD HH:MM:SS.mmm]`
- Module prefix: `[vaultwarden::api::*]`
- Log level: `[INFO]`, `[WARN]`, `[ERROR]`
- Contains IP addresses, usernames, and actions

### Log Format Examples

**Failed Master Password:**
```
[2025-12-03 12:34:56.789][vaultwarden::api::identity][WARN] Failed login attempt from IP: 192.168.1.100, Email: admin@example.com
```

**Successful Master Password:**
```
[2025-12-03 12:35:10.123][vaultwarden::api::identity][INFO] Successful login from IP: 192.168.1.100, Email: admin@example.com
```

**Vault Accessed:**
```
[2025-12-03 12:36:22.456][vaultwarden::api::core][INFO] Vault accessed by admin@example.com from 192.168.1.100
```

**Vault Export Attempt:**
```
[2025-12-03 12:37:45.789][vaultwarden::api::core][WARN] Vault export initiated by admin@example.com from 192.168.1.100
```

**Admin Action - User Deleted:**
```
[2025-12-03 12:38:30.012][vaultwarden::api::admin][INFO] Admin action: "User deleted" by admin@example.com from 192.168.1.10
```

**API Authentication Failed:**
```
[2025-12-03 12:39:15.345][vaultwarden::api::core][WARN] API authentication failed from IP: 203.0.113.50
```

**New Device Registration:**
```
[2025-12-03 12:40:00.678][vaultwarden::api::identity][INFO] New device registered for admin@example.com from 192.168.1.100, Device: Chrome/Desktop
```

### Parser Configuration

**Parser 1: Vaultwarden Authentication and Access**

```json
{
  "name": "vaultwarden-access",
  "description": "Parses Vaultwarden authentication and vault access logs for critical security monitoring",
  "enabled": true,
  "priority": 55,
  "parser_type": "regex",
  "pattern": "^\\[(?<timestamp>\\d{4}-\\d{2}-\\d{2}\\s+\\d{2}:\\d{2}:\\d{2}\\.\\d{3})\\]\\[(?<module>[^\\]]+)\\]\\[(?<log_level>\\w+)\\]\\s+(?<message>(?:(?!(?:\\s+(?:for|from(?:\\s+IP:)?|by)\\s+|,\\s+(?:Email|Device):)).)+?)(?:\\s+for\\s+(?<email>\\S+))?(?:\\s+by\\s+(?<admin_email>\\S+)\\s+from\\s+(?<admin_ip>[\\d.]+)|(?:\\s+from\\s+(?:IP:\\s+)?(?<client_ip>[\\d.]+)(?:,\\s+Email:\\s+(?<email>\\S+))?))(?:,\\s+Device:\\s+(?<device>[^,]+))?$",
  "field_mappings": {
    "timestamp": "timestamp",
    "module": "module",
    "log_level": "log_level",
    "message": "message",
    "client_ip": "client_ip",
    "email": "email",
    "admin_email": "admin_email",
    "admin_ip": "admin_ip",
    "device": "device"
  },
  "test_samples": [
    {
      "raw_message": "[2025-12-03 12:34:56.789][vaultwarden::api::identity][WARN] Failed login attempt from IP: 192.168.1.100, Email: admin@example.com",
      "expected_fields": {
        "timestamp": "2025-12-03 12:34:56.789",
        "module": "vaultwarden::api::identity",
        "log_level": "WARN",
        "message": "Failed login attempt",
        "client_ip": "192.168.1.100",
        "email": "admin@example.com"
      }
    },
    {
      "raw_message": "[2025-12-03 12:35:10.123][vaultwarden::api::identity][INFO] Successful login from IP: 192.168.1.100, Email: admin@example.com",
      "expected_fields": {
        "timestamp": "2025-12-03 12:35:10.123",
        "module": "vaultwarden::api::identity",
        "log_level": "INFO",
        "message": "Successful login",
        "client_ip": "192.168.1.100",
        "email": "admin@example.com"
      }
    },
    {
      "raw_message": "[2025-12-03 12:36:22.456][vaultwarden::api::core][INFO] Vault accessed by admin@example.com from 192.168.1.100",
      "expected_fields": {
        "timestamp": "2025-12-03 12:36:22.456",
        "module": "vaultwarden::api::core",
        "log_level": "INFO",
        "message": "Vault accessed by admin@example.com",
        "client_ip": "192.168.1.100"
      }
    },
    {
      "raw_message": "[2025-12-03 12:37:45.789][vaultwarden::api::core][WARN] Vault export initiated by admin@example.com from 192.168.1.100",
      "expected_fields": {
        "timestamp": "2025-12-03 12:37:45.789",
        "module": "vaultwarden::api::core",
        "log_level": "WARN",
        "message": "Vault export initiated by admin@example.com",
        "client_ip": "192.168.1.100"
      }
    },
    {
      "raw_message": "[2025-12-03 12:38:30.012][vaultwarden::api::admin][INFO] Admin action: \"User deleted\" by admin@example.com from 192.168.1.10",
      "expected_fields": {
        "timestamp": "2025-12-03 12:38:30.012",
        "module": "vaultwarden::api::admin",
        "log_level": "INFO",
        "message": "Admin action: \"User deleted\"",
        "admin_email": "admin@example.com",
        "admin_ip": "192.168.1.10"
      }
    }
  ]
}
```

### Fields Extracted

| Field Name | Type | Description | Security Value |
|-----------|------|-------------|----------------|
| `timestamp` | string | Event timestamp (YYYY-MM-DD HH:MM:SS.mmm) | Precise attack timeline |
| `module` | string | Vaultwarden module (api::identity, api::core, api::admin) | Attack vector identification |
| `log_level` | string | Log severity (INFO/WARN/ERROR) | Failure vs success |
| `message` | string | Human-readable event description | Attack type detection |
| `client_ip` | string | Client IP address | Attacker tracking (CRITICAL) |
| `email` | string | User email/username | Account targeting |
| `admin_email` | string | Admin performing action | Privilege monitoring |
| `admin_ip` | string | Admin IP address | Admin access tracking |
| `device` | string | Device information | Device enumeration |

### Installation

**SQL INSERT Statement:**

```sql
INSERT INTO parsers (name, description, enabled, priority, parser_type, pattern, field_mappings, test_samples, created_at, updated_at)
VALUES (
  'vaultwarden-access',
  'Parses Vaultwarden authentication and vault access logs for critical security monitoring',
  true,
  55,
  'regex',
  '^\[(?<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\]\[(?<module>[^\]]+)\]\[(?<log_level>\w+)\]\s+(?<message>(?:(?!(?:\s+(?:for|from(?:\s+IP:)?|by)\s+|,\s+(?:Email|Device):)).)+?)(?:\s+for\s+(?<email>\S+))?(?:\s+by\s+(?<admin_email>\S+)\s+from\s+(?<admin_ip>[\d.]+)|(?:\s+from\s+(?:IP:\s+)?(?<client_ip>[\d.]+)(?:,\s+Email:\s+(?<email>\S+))?))(?:,\s+Device:\s+(?<device>[^,]+))?$',
  '{"timestamp":"timestamp","module":"module","log_level":"log_level","message":"message","client_ip":"client_ip","email":"email","admin_email":"admin_email","admin_ip":"admin_ip","device":"device"}',
  '[{"raw_message":"[2025-12-03 12:34:56.789][vaultwarden::api::identity][WARN] Failed login attempt from IP: 192.168.1.100, Email: admin@example.com","expected_fields":{"timestamp":"2025-12-03 12:34:56.789","module":"vaultwarden::api::identity","log_level":"WARN","message":"Failed login attempt","client_ip":"192.168.1.100","email":"admin@example.com"}}]',
  NOW(),
  NOW()
);
```

### Testing

**Step 1: Enable Vaultwarden Logging**

Ensure Vaultwarden has logging enabled:

```bash
# Check Vaultwarden container logs
docker logs vaultwarden | tail -10

# Verify log format matches parser
```

**Step 2: Generate Test Events**

```bash
# Trigger failed login (wrong password)
curl -X POST https://vault.example.com/identity/connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&username=test@example.com&password=wrongpassword&scope=api&client_id=web"

# Check logs
docker logs vaultwarden | grep "Failed login"
```

**Step 3: Verify Parser**

In SIEMBox:
1. Navigate to Parsers → vaultwarden-access
2. Click "Test Parse"
3. Use real log line from container
4. Verify all fields extract correctly

**Step 4: CRITICAL - Test Detection Rules**

**Immediately after parser installation, test these CRITICAL rules:**

1. **PWDMGR-001: Master Password Failures** (3+ in 10 minutes)
2. **PWDMGR-002: Vault Export** (any export event)
3. **AUTH-005: Vaultwarden Brute Force** (5+ failures in 5 minutes)

### Troubleshooting

**Problem: Logs not appearing**

1. Verify Vaultwarden container is running:
   ```bash
   docker ps | grep vaultwarden
   ```

2. Check log output:
   ```bash
   docker logs vaultwarden --tail 20
   ```

3. Enable extended logging in Vaultwarden config:
   ```bash
   # In docker-compose.yml or environment
   RUST_LOG=debug
   ```

**Problem: Parser not matching**

1. Get actual log line:
   ```bash
   docker logs vaultwarden | head -1
   ```

2. Compare format with parser pattern
3. Vaultwarden log format may vary by version
4. Check for custom log configuration

**Problem: Email field not extracting**

- Some log entries don't include email (API calls)
- Admin actions use `admin_email` field instead
- Check message field for email if dedicated field is null

**Problem: Missing module or log_level**

- Verify full log line is being captured
- Check for log rotation issues
- Some events may use different format

---

## Parser 2: Nextcloud

### Overview

**Priority:** HIGH (70 - File storage and personal data)

**About Nextcloud:**
Nextcloud is a comprehensive file sharing and collaboration platform providing file storage, sharing, calendars, contacts, and more. With 118 homelab users, it's the primary personal data storage solution. Nextcloud stores documents, photos, and sensitive files, making it a high-value target for data theft and exfiltration attacks.

**Security Relevance:**
- **Personal Data Storage** - Contains documents, photos, financial records
- **Privacy Risk** - File access = identity theft, extortion potential
- **Share Abuse** - Public links can leak data
- **Bulk Download Detection** - Exfiltration indicator (EXFIL-001)
- **Authentication Target** - Password brute force attacks common
- **API Abuse** - Automated data harvesting
- **Sensitive File Access** - Passwords, keys, personal data

**Default Log Locations:**
- File logs: `/var/www/nextcloud/data/nextcloud.log`
- Container logs: Docker stdout (if configured)
- Format: JSON (default)

**Log Format Characteristics:**
- JSON structured logging
- Each request = one log entry
- Contains: user, IP, method, URL, response code
- Request ID for correlation

### Log Format Examples

**Successful File Access:**
```json
{"reqId":"abc123","level":2,"time":"2025-12-03T12:34:56+00:00","remoteAddr":"192.168.1.100","user":"admin","app":"core","method":"GET","url":"/remote.php/dav/files/admin/Documents/readme.txt","message":"File accessed","userAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64)","version":"28.0.1.0"}
```

**Failed Authentication:**
```json
{"reqId":"def456","level":2,"time":"2025-12-03T12:35:22+00:00","remoteAddr":"203.0.113.50","user":"admin","app":"core","method":"POST","url":"/login","message":"Login failed: Incorrect password","userAgent":"curl/7.68.0","version":"28.0.1.0"}
```

**Share Created:**
```json
{"reqId":"ghi789","level":1,"time":"2025-12-03T12:36:45+00:00","remoteAddr":"192.168.1.100","user":"admin","app":"files_sharing","method":"POST","url":"/ocs/v2.php/apps/files_sharing/api/v1/shares","message":"Shared folder with public link","userAgent":"Mozilla/5.0","version":"28.0.1.0"}
```

**Bulk File Download:**
```json
{"reqId":"jkl012","level":1,"time":"2025-12-03T12:37:10+00:00","remoteAddr":"192.168.1.100","user":"admin","app":"core","method":"GET","url":"/remote.php/dav/files/admin/Photos/photo001.jpg","message":"File downloaded","userAgent":"Mozilla/5.0","version":"28.0.1.0"}
```

**Sensitive File Access:**
```json
{"reqId":"mno345","level":1,"time":"2025-12-03T12:38:30+00:00","remoteAddr":"192.168.1.100","user":"admin","app":"core","method":"GET","url":"/remote.php/dav/files/admin/Documents/passwords.txt","message":"File accessed","userAgent":"Mozilla/5.0","version":"28.0.1.0"}
```

### Parser Configuration

```json
{
  "name": "nextcloud-access",
  "description": "Parses Nextcloud JSON logs for file access, authentication, and sharing monitoring",
  "enabled": true,
  "priority": 70,
  "parser_type": "json",
  "pattern": "",
  "field_mappings": {
    "time": "timestamp",
    "level": "log_level",
    "remoteAddr": "client_ip",
    "user": "username",
    "app": "app_name",
    "method": "http_method",
    "url": "request_uri",
    "message": "message",
    "userAgent": "user_agent",
    "reqId": "request_id",
    "version": "nextcloud_version"
  },
  "test_samples": [
    {
      "raw_message": "{\"reqId\":\"abc123\",\"level\":2,\"time\":\"2025-12-03T12:34:56+00:00\",\"remoteAddr\":\"192.168.1.100\",\"user\":\"admin\",\"app\":\"core\",\"method\":\"GET\",\"url\":\"/remote.php/dav/files/admin/Documents/readme.txt\",\"message\":\"File accessed\",\"userAgent\":\"Mozilla/5.0 (Windows NT 10.0; Win64; x64)\",\"version\":\"28.0.1.0\"}",
      "expected_fields": {
        "timestamp": "2025-12-03T12:34:56+00:00",
        "log_level": 2,
        "client_ip": "192.168.1.100",
        "username": "admin",
        "app_name": "core",
        "http_method": "GET",
        "request_uri": "/remote.php/dav/files/admin/Documents/readme.txt",
        "message": "File accessed",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "request_id": "abc123",
        "nextcloud_version": "28.0.1.0"
      }
    },
    {
      "raw_message": "{\"reqId\":\"def456\",\"level\":2,\"time\":\"2025-12-03T12:35:22+00:00\",\"remoteAddr\":\"203.0.113.50\",\"user\":\"admin\",\"app\":\"core\",\"method\":\"POST\",\"url\":\"/login\",\"message\":\"Login failed: Incorrect password\",\"userAgent\":\"curl/7.68.0\",\"version\":\"28.0.1.0\"}",
      "expected_fields": {
        "timestamp": "2025-12-03T12:35:22+00:00",
        "log_level": 2,
        "client_ip": "203.0.113.50",
        "username": "admin",
        "app_name": "core",
        "http_method": "POST",
        "request_uri": "/login",
        "message": "Login failed: Incorrect password",
        "user_agent": "curl/7.68.0"
      }
    },
    {
      "raw_message": "{\"reqId\":\"ghi789\",\"level\":1,\"time\":\"2025-12-03T12:36:45+00:00\",\"remoteAddr\":\"192.168.1.100\",\"user\":\"admin\",\"app\":\"files_sharing\",\"method\":\"POST\",\"url\":\"/ocs/v2.php/apps/files_sharing/api/v1/shares\",\"message\":\"Shared folder with public link\",\"userAgent\":\"Mozilla/5.0\",\"version\":\"28.0.1.0\"}",
      "expected_fields": {
        "timestamp": "2025-12-03T12:36:45+00:00",
        "log_level": 1,
        "client_ip": "192.168.1.100",
        "username": "admin",
        "app_name": "files_sharing",
        "http_method": "POST",
        "request_uri": "/ocs/v2.php/apps/files_sharing/api/v1/shares",
        "message": "Shared folder with public link",
        "user_agent": "Mozilla/5.0"
      }
    },
    {
      "raw_message": "{\"reqId\":\"jkl012\",\"level\":1,\"time\":\"2025-12-03T12:37:10+00:00\",\"remoteAddr\":\"192.168.1.100\",\"user\":\"admin\",\"app\":\"core\",\"method\":\"GET\",\"url\":\"/remote.php/dav/files/admin/Photos/photo001.jpg\",\"message\":\"File downloaded\",\"userAgent\":\"Mozilla/5.0\",\"version\":\"28.0.1.0\"}",
      "expected_fields": {
        "timestamp": "2025-12-03T12:37:10+00:00",
        "log_level": 1,
        "client_ip": "192.168.1.100",
        "username": "admin",
        "app_name": "core",
        "http_method": "GET",
        "request_uri": "/remote.php/dav/files/admin/Photos/photo001.jpg",
        "message": "File downloaded"
      }
    },
    {
      "raw_message": "{\"reqId\":\"mno345\",\"level\":1,\"time\":\"2025-12-03T12:38:30+00:00\",\"remoteAddr\":\"192.168.1.100\",\"user\":\"admin\",\"app\":\"core\",\"method\":\"GET\",\"url\":\"/remote.php/dav/files/admin/Documents/passwords.txt\",\"message\":\"File accessed\",\"userAgent\":\"Mozilla/5.0\",\"version\":\"28.0.1.0\"}",
      "expected_fields": {
        "timestamp": "2025-12-03T12:38:30+00:00",
        "log_level": 1,
        "client_ip": "192.168.1.100",
        "username": "admin",
        "app_name": "core",
        "http_method": "GET",
        "request_uri": "/remote.php/dav/files/admin/Documents/passwords.txt",
        "message": "File accessed"
      }
    }
  ]
}
```

### Fields Extracted

| Field Name | Type | Description | Security Value |
|-----------|------|-------------|----------------|
| `timestamp` | string | Event timestamp (ISO 8601) | Precise timing correlation |
| `log_level` | integer | Log level (0=DEBUG, 1=INFO, 2=WARN, 3=ERROR, 4=FATAL) | Failure indication |
| `client_ip` | string | Client IP address | Attacker tracking |
| `username` | string | Nextcloud username | Account targeting |
| `app_name` | string | Nextcloud app (core, files_sharing, etc) | Feature abuse detection |
| `http_method` | string | HTTP method (GET/POST/PUT/DELETE) | Action type |
| `request_uri` | string | Full request URI with path | File access patterns |
| `message` | string | Human-readable event description | Event classification |
| `user_agent` | string | Client user agent | Client identification |
| `request_id` | string | Unique request identifier | Correlation across logs |
| `nextcloud_version` | string | Nextcloud version | Version-specific attacks |

### Installation

**SQL INSERT Statement:**

```sql
INSERT INTO parsers (name, description, enabled, priority, parser_type, pattern, field_mappings, test_samples, created_at, updated_at)
VALUES (
  'nextcloud-access',
  'Parses Nextcloud JSON logs for file access, authentication, and sharing monitoring',
  true,
  70,
  'json',
  '',
  '{"time":"timestamp","level":"log_level","remoteAddr":"client_ip","user":"username","app":"app_name","method":"http_method","url":"request_uri","message":"message","userAgent":"user_agent","reqId":"request_id","version":"nextcloud_version"}',
  '[{"raw_message":"{\"reqId\":\"abc123\",\"level\":2,\"time\":\"2025-12-03T12:34:56+00:00\",\"remoteAddr\":\"192.168.1.100\",\"user\":\"admin\",\"app\":\"core\",\"method\":\"GET\",\"url\":\"/remote.php/dav/files/admin/Documents/readme.txt\",\"message\":\"File accessed\",\"userAgent\":\"Mozilla/5.0 (Windows NT 10.0; Win64; x64)\",\"version\":\"28.0.1.0\"}","expected_fields":{"timestamp":"2025-12-03T12:34:56+00:00","log_level":2,"client_ip":"192.168.1.100","username":"admin","app_name":"core","http_method":"GET","request_uri":"/remote.php/dav/files/admin/Documents/readme.txt","message":"File accessed"}}]',
  NOW(),
  NOW()
);
```

### Testing

**Step 1: Verify Nextcloud JSON Logging**

Check Nextcloud log configuration:

```bash
# Check log file
tail /var/www/nextcloud/data/nextcloud.log | jq .

# Or Docker logs
docker logs nextcloud | tail -5 | jq .
```

**Step 2: Generate Test Events**

```bash
# Trigger file access
curl -u admin:password https://nextcloud.example.com/remote.php/dav/files/admin/

# Trigger failed login
curl -u admin:wrongpass https://nextcloud.example.com/login

# Check logs
tail -5 /var/www/nextcloud/data/nextcloud.log | jq .
```

**Step 3: Verify Parser**

In SIEMBox:
1. Navigate to Parsers → nextcloud-access
2. Test with actual JSON log line
3. Verify all fields extracted correctly

**Step 4: Test Detection Rules**

Test these important rules:
1. **EXFIL-001: Bulk File Download** (100+ files in 10 minutes)
2. **AUTH-005: Nextcloud Brute Force** (5+ failures)
3. **APP-004: Mass File Access** (200+ files in 10 minutes)

### Troubleshooting

**Problem: Logs not in JSON format**

1. Verify Nextcloud config.php:
   ```php
   'log_type' => 'file',
   'logfile' => '/var/www/nextcloud/data/nextcloud.log',
   'loglevel' => 2,
   'log_type_audit' => 'file',
   ```

2. JSON is default format in Nextcloud 20+
3. Check for custom logging configuration

**Problem: Missing fields**

- Some fields are optional (message may vary)
- Request ID always present
- User may be empty for unauthenticated requests
- App name indicates which Nextcloud app generated log

**Problem: File path extraction**

- File path is embedded in `url` field
- Use regex on `request_uri` to extract file path
- Pattern: `/remote.php/dav/files/{username}/{filepath}`
- Parse filepath for sensitive file detection

**Problem: Log level confusion**

Nextcloud log levels:
- 0 = DEBUG
- 1 = INFO
- 2 = WARN
- 3 = ERROR
- 4 = FATAL

Failed logins typically level 2 (WARN)

---

## Parser 3: Pi-hole

### Overview

**Priority:** HIGH (72 - DNS security and network monitoring)

**About Pi-hole:**
Pi-hole is a network-wide ad blocker and DNS server that acts as a DNS sinkhole to block unwanted content. With 50 homelab users, it's the first line of defense against malicious domains and provides crucial visibility into network DNS activity. Pi-hole logs reveal malware C2 communication, DNS tunneling attempts, and compromised device indicators.

**Security Relevance:**
- **First Line of Defense** - Blocks malicious domains before connection
- **Network Visibility** - Sees ALL DNS queries from all devices
- **Malware C2 Detection** - Unusual query patterns indicate compromise
- **DNS Tunneling** - Data exfiltration via DNS (EXFIL-003)
- **IoT Compromise Indicators** - Unusual queries from smart devices
- **DNSSEC Validation** - DNS poisoning detection
- **Query Volume Anomalies** - DDoS or scanning activity

**Default Log Locations:**
- File logs: `/var/log/pihole/pihole.log`
- Query logs: `/var/log/pihole/FTL.log`
- Container logs: Docker stdout (dnsmasq format)
- Format: dnsmasq log format (text)

**Log Format Characteristics:**
- Standard dnsmasq format
- Timestamp: `Mon DD HH:MM:SS`
- Process: `dnsmasq[PID]:`
- Query types: `query[A]`, `query[AAAA]`, `query[PTR]`
- Actions: `reply`, `cached`, `forwarded`, `blocked`

### Log Format Examples

**DNS Query (Normal):**
```
Dec  3 12:34:56 dnsmasq[123]: query[A] example.com from 192.168.1.100
```

**DNS Reply:**
```
Dec  3 12:34:56 dnsmasq[123]: reply example.com is 93.184.216.34
```

**Blocked Domain:**
```
Dec  3 12:35:22 dnsmasq[123]: /etc/pihole/gravity.list malicious-ad.com is 0.0.0.0
```

**DNSSEC Validation Failure:**
```
Dec  3 12:36:45 dnsmasq[123]: validation result is BOGUS for suspicious-domain.com
```

**Cached Response:**
```
Dec  3 12:37:10 dnsmasq[123]: cached example.com is 93.184.216.34
```

**DNS Tunneling Pattern (High Query Volume):**
```
Dec  3 12:38:00 dnsmasq[123]: query[TXT] aGVsbG8gd29ybGQ.tunnel.example.com from 192.168.1.200
```

**PTR Query (Reverse DNS):**
```
Dec  3 12:39:30 dnsmasq[123]: query[PTR] 100.1.168.192.in-addr.arpa from 192.168.1.1
```

### Parser Configuration

```json
{
  "name": "pihole-dns",
  "description": "Parses Pi-hole/dnsmasq DNS query logs for security monitoring and anomaly detection",
  "enabled": true,
  "priority": 72,
  "parser_type": "regex",
  "pattern": "^(?<timestamp>\\w+\\s+\\d+\\s+\\d{2}:\\d{2}:\\d{2})\\s+dnsmasq\\[(?<pid>\\d+)\\]:\\s+(?:(?<action>query|reply|cached|forwarded|validation)\\[?(?<query_type>\\w+)?\\]?\\s+)?(?<domain>[\\w\\-\\.]+)(?:\\s+(?:is|from)\\s+(?<resolved_ip>[\\d\\.]+|(?:NODATA|NXDOMAIN|BOGUS)|(?<client_ip>[\\d\\.]+)))?",
  "field_mappings": {
    "timestamp": "timestamp",
    "pid": "pid",
    "action": "action",
    "query_type": "query_type",
    "domain": "domain",
    "resolved_ip": "resolved_ip",
    "client_ip": "client_ip"
  },
  "test_samples": [
    {
      "raw_message": "Dec  3 12:34:56 dnsmasq[123]: query[A] example.com from 192.168.1.100",
      "expected_fields": {
        "timestamp": "Dec  3 12:34:56",
        "pid": "123",
        "action": "query",
        "query_type": "A",
        "domain": "example.com",
        "client_ip": "192.168.1.100"
      }
    },
    {
      "raw_message": "Dec  3 12:34:56 dnsmasq[123]: reply example.com is 93.184.216.34",
      "expected_fields": {
        "timestamp": "Dec  3 12:34:56",
        "pid": "123",
        "action": "reply",
        "domain": "example.com",
        "resolved_ip": "93.184.216.34"
      }
    },
    {
      "raw_message": "Dec  3 12:35:22 dnsmasq[123]: /etc/pihole/gravity.list malicious-ad.com is 0.0.0.0",
      "expected_fields": {
        "timestamp": "Dec  3 12:35:22",
        "pid": "123",
        "domain": "malicious-ad.com",
        "resolved_ip": "0.0.0.0"
      }
    },
    {
      "raw_message": "Dec  3 12:36:45 dnsmasq[123]: validation result is BOGUS for suspicious-domain.com",
      "expected_fields": {
        "timestamp": "Dec  3 12:36:45",
        "pid": "123",
        "action": "validation",
        "domain": "suspicious-domain.com",
        "resolved_ip": "BOGUS"
      }
    },
    {
      "raw_message": "Dec  3 12:37:10 dnsmasq[123]: cached example.com is 93.184.216.34",
      "expected_fields": {
        "timestamp": "Dec  3 12:37:10",
        "pid": "123",
        "action": "cached",
        "domain": "example.com",
        "resolved_ip": "93.184.216.34"
      }
    }
  ]
}
```

### Fields Extracted

| Field Name | Type | Description | Security Value |
|-----------|------|-------------|----------------|
| `timestamp` | string | Event timestamp (Mon DD HH:MM:SS) | Attack timeline |
| `pid` | integer | dnsmasq process ID | Process tracking |
| `action` | string | DNS action (query/reply/cached/validation) | Request type |
| `query_type` | string | DNS query type (A/AAAA/TXT/PTR/etc) | Query analysis |
| `domain` | string | Queried domain name | Malicious domain detection |
| `resolved_ip` | string | Resolved IP or result (NODATA/NXDOMAIN/BOGUS/0.0.0.0) | Resolution tracking |
| `client_ip` | string | Source IP of query | Device tracking |

### Installation

**SQL INSERT Statement:**

```sql
INSERT INTO parsers (name, description, enabled, priority, parser_type, pattern, field_mappings, test_samples, created_at, updated_at)
VALUES (
  'pihole-dns',
  'Parses Pi-hole/dnsmasq DNS query logs for security monitoring and anomaly detection',
  true,
  72,
  'regex',
  '^(?<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+dnsmasq\[(?<pid>\d+)\]:\s+(?:(?<action>query|reply|cached|forwarded|validation)\[?(?<query_type>\w+)?\]?\s+)?(?<domain>[\w\-\.]+)(?:\s+(?:is|from)\s+(?<resolved_ip>[\d\.]+|(?:NODATA|NXDOMAIN|BOGUS)|(?<client_ip>[\d\.]+)))?',
  '{"timestamp":"timestamp","pid":"pid","action":"action","query_type":"query_type","domain":"domain","resolved_ip":"resolved_ip","client_ip":"client_ip"}',
  '[{"raw_message":"Dec  3 12:34:56 dnsmasq[123]: query[A] example.com from 192.168.1.100","expected_fields":{"timestamp":"Dec  3 12:34:56","pid":"123","action":"query","query_type":"A","domain":"example.com","client_ip":"192.168.1.100"}}]',
  NOW(),
  NOW()
);
```

### Testing

**Step 1: Verify Pi-hole Logging**

Check Pi-hole logs:

```bash
# Tail live query log
tail -f /var/log/pihole/pihole.log

# Or Docker logs
docker logs pihole | tail -20

# Generate test query
nslookup example.com $(hostname -I | awk '{print $1}')
```

**Step 2: Verify Parser**

In SIEMBox:
1. Navigate to Parsers → pihole-dns
2. Test with actual dnsmasq log line
3. Verify all fields extracted

**Step 3: Test Detection Rules**

Test these DNS security rules:
1. **EXFIL-003: DNS Tunneling** (50+ TXT queries in 5 minutes)
2. **APP-003: Unusual DNS Query Pattern** (500+ queries in 5 minutes)
3. **IOT-003: Unexpected IoT Communication** (blocked domains from IoT devices)

### Troubleshooting

**Problem: Logs not in expected format**

1. Pi-hole uses standard dnsmasq format
2. Check Pi-hole version (format may vary slightly)
3. Verify `/etc/dnsmasq.d/01-pihole.conf` for custom formats

**Problem: Missing client IP**

- Reply and cached entries don't include client IP
- Only query entries have `from {client_ip}`
- Use query entries for client tracking
- Correlate reply with previous query via domain

**Problem: Blocked domain detection**

- Blocked domains show resolved_ip as "0.0.0.0"
- May reference gravity list path
- Look for "/etc/pihole/gravity.list" in message
- Both indicators mean domain was blocked

**Problem: Timestamp without year**

- dnsmasq format: "Mon DD HH:MM:SS"
- No year included in log
- Assume current year for correlation
- Use log file timestamp for accurate year

**Problem: TXT query parsing**

DNS tunneling uses TXT queries:
- Long subdomain = base64 encoded data
- Pattern: `{encoded_data}.tunnel.domain.com`
- Track TXT query frequency per client
- High TXT query rate = tunneling indicator

---

## Appendix A: Common Patterns

### Reusable Detection Patterns

**Vaultwarden - Master Password Failures:**
```yaml
conditions:
  - field: message
    operator: contains
    value: "Failed login attempt"
  - field: module
    operator: contains
    value: "identity"

aggregation:
  field: client_ip
  timeframe: 10m
  threshold: 3  # VERY LOW - password manager compromise is critical
```

**Vaultwarden - Vault Export Detection:**
```yaml
conditions:
  - field: message
    operator: contains
    value: "export"
  - field: module
    operator: contains
    value: "core"

# Single event alert - ANY export is suspicious
```

**Nextcloud - Bulk File Download:**
```yaml
conditions:
  - field: http_method
    operator: equals
    value: "GET"
  - field: request_uri
    operator: contains
    value: "/remote.php/dav/files/"

aggregation:
  field: client_ip
  timeframe: 10m
  threshold: 100  # 100 file accesses in 10 minutes
```

**Nextcloud - Sensitive File Access:**
```yaml
conditions:
  - field: request_uri
    operator: regex
    value: "(password|key|secret|credential|ssh|\.pem)"
```

**Pi-hole - DNS Tunneling:**
```yaml
conditions:
  - field: query_type
    operator: equals
    value: "TXT"

aggregation:
  field: client_ip
  timeframe: 5m
  threshold: 50  # 50 TXT queries in 5 minutes
```

**Pi-hole - Blocked Domain Pattern:**
```yaml
conditions:
  - field: resolved_ip
    operator: equals
    value: "0.0.0.0"

aggregation:
  field: client_ip
  timeframe: 10m
  threshold: 20  # 20 blocked domains from same device
```

**Pi-hole - DNSSEC Validation Failure:**
```yaml
conditions:
  - field: resolved_ip
    operator: equals
    value: "BOGUS"

# Single event - DNSSEC failure indicates DNS poisoning
```

### Priority Rankings

These parsers have specific priorities based on criticality:

1. **Vaultwarden (55)** - HIGHEST PRIORITY
   - Password manager = catastrophic if compromised
   - Must parse before any generic parser
   - Critical detection rules depend on this

2. **Nextcloud (70)** - High Priority
   - Personal data storage
   - Exfiltration detection critical
   - Higher priority than generic web parsers

3. **Pi-hole (72)** - High Priority
   - Network-wide DNS visibility
   - Early compromise indicator
   - DNS security critical

### Severity Assignment

**Vaultwarden:**
- Failed master password (3+ attempts): **CRITICAL**
- Vault export: **CRITICAL**
- API auth failures: **HIGH**
- Admin actions: **MEDIUM**
- Normal vault access: **LOW** (informational)

**Nextcloud:**
- Bulk file download (100+): **HIGH**
- Failed auth (5+): **MEDIUM**
- Share creation: **LOW**
- Sensitive file access: **MEDIUM**
- Mass file access (200+): **HIGH**

**Pi-hole:**
- DNS tunneling pattern: **MEDIUM**
- DNSSEC failure: **MEDIUM**
- High blocked domain rate: **LOW**
- Unusual query volume: **MEDIUM**
- Malware C2 pattern: **HIGH**

---

## Appendix B: Installation Guide

### Quick Installation (All 3 Parsers)

**Step 1: Download Parser Definitions**

Save each parser JSON:
- `vaultwarden-access.json`
- `nextcloud-access.json`
- `pihole-dns.json`

**Step 2: Import via SQL**

```bash
# Connect to PostgreSQL
docker exec -it siembox-postgres psql -U siembox -d siembox

# Run SQL INSERT statements from each parser section
```

**Step 3: Import via API**

```bash
# Set SIEMBox URL and token
SIEMBOX_URL="http://localhost:8421"
TOKEN="your-api-token"

# Import each parser
for parser in vaultwarden-access.json nextcloud-access.json pihole-dns.json; do
  curl -X POST "${SIEMBOX_URL}/api/parsers" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN}" \
    -d @"${parser}"
  echo "Imported ${parser}"
done
```

### Log Shipper Configuration

**Vaultwarden (Docker Logs):**

```yaml
# In SIEMBox UI, add source:
Type: journald
Container: vaultwarden
Tag: vaultwarden
Facility: local0
Enabled: Yes
```

**Nextcloud (File Logs):**

```yaml
# In SIEMBox UI, add source:
Type: file
Path: /var/www/nextcloud/data/nextcloud.log
Tag: nextcloud
Facility: local1
Enabled: Yes
```

**Pi-hole (File Logs):**

```yaml
# In SIEMBox UI, add source:
Type: file
Path: /var/log/pihole/pihole.log
Tag: pihole
Facility: local2
Enabled: Yes
```

### Verification Checklist

After installation:

- [ ] All 3 parsers show "Enabled" in UI
- [ ] Test parse succeeds for each parser
- [ ] Logs appearing in SIEMBox logs page
- [ ] Fields extracting correctly
- [ ] Priority order: 55, 70, 72
- [ ] Log shipper forwarding all logs
- [ ] Vaultwarden priority is 55 (highest)
- [ ] Detection rules installed
- [ ] Test alerts generating correctly

### Critical Detection Rules

**MUST install these rules immediately:**

**Vaultwarden Rules (CRITICAL):**
1. **AUTH-005: Master Password Failures** - 3+ in 10 minutes (severity: CRITICAL)
2. **PWDMGR-001: Vault Export** - Any export event (severity: CRITICAL)
3. **PWDMGR-002: Multiple Device Registrations** - 3+ in 1 hour (severity: HIGH)
4. **PWDMGR-004: API Token Abuse** - 50+ API calls in 10 minutes (severity: HIGH)

**Nextcloud Rules (HIGH):**
1. **EXFIL-001: Bulk File Download** - 100+ files in 10 minutes (severity: HIGH)
2. **AUTH-005: Nextcloud Brute Force** - 5+ failures in 5 minutes (severity: HIGH)
3. **APP-004: Mass File Access** - 200+ files in 10 minutes (severity: MEDIUM)

**Pi-hole Rules (MEDIUM-HIGH):**
1. **EXFIL-003: DNS Tunneling** - 50+ TXT queries in 5 minutes (severity: MEDIUM)
2. **APP-003: Unusual DNS Pattern** - 500+ queries in 5 minutes (severity: MEDIUM)
3. **IOT-003: Unexpected Communication** - Blocked domains from IoT devices (severity: MEDIUM)

---

## Appendix C: Troubleshooting

### Common Issues Across All Parsers

**Issue: Parser not matching**

**Symptoms:**
- Logs in raw_logs but not parsed
- parsed_data is null
- No fields extracted

**Solutions:**
1. Verify log format matches parser pattern
2. Test parser with actual log line via UI
3. Check application version (format may change)
4. Review parser priority (ensure it's being tried)
5. Check for custom log configuration

**Issue: Some fields missing**

**Symptoms:**
- Parser matches but fields are null
- Only some fields populated

**Solutions:**
1. Some fields are optional (normal)
2. Check field_mappings accuracy
3. Verify field exists in log format
4. Test with multiple log samples

**Issue: High log volume**

**Symptoms:**
- Database growing rapidly
- Parser performance degrading
- Disk space concerns

**Solutions:**
1. Implement log retention policies
2. Filter non-security events at shipper
3. Use aggregation in detection rules
4. Consider separate log storage
5. Adjust log levels in applications

### Application-Specific Issues

**Vaultwarden:**

**Issue: Text log format not matching**

- Vaultwarden log format can vary by version
- Check actual log output format
- May need to adjust regex pattern
- Enable extended logging for more detail

**Issue: No IP address in logs**

- Verify Vaultwarden is behind reverse proxy
- Check `X-Forwarded-For` header configuration
- IP should appear in "from IP:" format
- May need reverse proxy configuration

**Nextcloud:**

**Issue: Not logging in JSON**

Ensure Nextcloud config.php:
```php
'log_type' => 'file',
'logfile' => 'nextcloud.log',
'loglevel' => 2,
```

JSON is default in Nextcloud 20+

**Issue: Too many logs**

- Nextcloud can be very verbose
- Adjust loglevel (0=DEBUG, 2=WARN, 3=ERROR)
- Filter at shipper level
- Focus on authentication and file access

**Pi-hole:**

**Issue: Different log format**

- Pi-hole uses dnsmasq format
- Format should be consistent
- Check Pi-hole version
- Verify dnsmasq configuration

**Issue: Missing blocked domain logs**

- Verify Pi-hole blocking is enabled
- Check gravity list is populated
- Blocked domains show "0.0.0.0" IP
- May reference gravity list path

**Issue: Query vs reply correlation**

- Query logs include client IP
- Reply logs do not include client IP
- Correlate by domain name and timestamp
- Use query logs for client tracking

### Performance Optimization

**Vaultwarden:**
- Low volume logs (authentication only)
- No special optimization needed
- Critical priority (55) ensures fast parsing

**Nextcloud:**
- High volume logs (every file access)
- Consider filtering non-security events
- Use aggregation for bulk detection
- Adjust log level to reduce volume

**Pi-hole:**
- VERY high volume (every DNS query)
- Consider sampling for non-security monitoring
- Focus on anomalies (blocked, DNSSEC failures)
- Use aggregation heavily in rules
- Consider separate Pi-hole log retention

### Getting Help

**Before requesting help:**

1. Verify application logging is working
2. Test parser with actual log line
3. Check log format matches parser
4. Verify log shipper forwarding logs
5. Review SIEMBox backend errors

**When reporting issues:**

Include:
- Parser configuration (JSON)
- Sample log line (sanitized)
- Expected vs actual extraction
- Application version
- SIEMBox version
- Parser test results

**Resources:**

- GitHub Issues: https://github.com/cladkins/SIEMBOX/issues
- Discussions: https://github.com/cladkins/SIEMBOX/discussions
- Documentation: https://github.com/cladkins/SIEMBOX

---

## Conclusion

### Parser Coverage Summary

These 3 critical application parsers provide protection for the highest-value assets in homelabs:

1. **Vaultwarden (Priority 55)** - 152 users
   - PASSWORD MANAGER - Highest security priority
   - Compromise = total credential loss
   - Detection: brute force, vault export, API abuse

2. **Nextcloud (Priority 70)** - 118 users
   - FILE STORAGE - Personal data protection
   - Compromise = privacy violation, data theft
   - Detection: bulk download, brute force, sensitive files

3. **Pi-hole (Priority 72)** - 50 users
   - DNS SECURITY - Network visibility
   - Compromise = traffic redirection, surveillance
   - Detection: DNS tunneling, query anomalies, DNSSEC failures

**Total Coverage:** 320 users across critical data applications

### Phase 2 Complete

With these parsers, Phase 2 parser development is COMPLETE:

**Phase 2 Total: 12 Parsers**
- **Reverse Proxies (6 parsers):** 90%+ coverage (access + error logs)
- **Authentication (3 parsers):** 817 users
- **Critical Apps (3 parsers):** 320 users

**Total Homelab Coverage:** 1,137+ users across highest-priority applications

### Security Capabilities Enabled

**Critical Threat Detection:**
- **PWDMGR-001:** Vaultwarden vault export
- **PWDMGR-002:** Multiple device registrations
- **AUTH-005:** Master password brute force
- **EXFIL-001:** Bulk file downloads
- **EXFIL-003:** DNS tunneling
- **APP-003:** DNS query anomalies
- **APP-004:** Mass file access

**Defense-in-Depth:**
- Reverse proxies: First line of defense
- Authentication: Credential protection
- Password manager: Ultimate target protection
- File storage: Data theft prevention
- DNS: Network-level visibility

### Next Steps

1. **Install parsers** for your critical applications
2. **Configure log shippers** to forward logs
3. **Test parsers** with sample logs
4. **Import detection rules** (PWDMGR-*, EXFIL-*, APP-*)
5. **Tune thresholds** for your environment
6. **Monitor alerts** closely for critical applications
7. **Test incident response** for password manager compromise

### Final Warning

**Vaultwarden compromise is the worst-case scenario for any homelab.**

If you monitor nothing else, monitor Vaultwarden. These parsers are your first line of defense against catastrophic credential loss. Set thresholds low, enable all detection rules, and treat any Vaultwarden alert as a potential emergency.

**Your entire digital life is protected by these parsers. Don't skip them.**

---

**Document Version:** 1.0
**Last Updated:** 2025-12-03
**Compatible with:** SIEMBox 1.0+
**Parsers Included:** 3 (Vaultwarden, Nextcloud, Pi-hole)
**Total Phase 2:** 12 parsers covering 1,137+ homelab users
**Priority Range:** 55-72 (critical applications)

---
