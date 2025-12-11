# SIEMBox API Documentation

Complete REST API reference for SIEMBox. All API endpoints are prefixed with `/api`.

## Table of Contents

- [Authentication](#authentication)
- [Response Format](#response-format)
- [Error Codes](#error-codes)
- [Rate Limiting](#rate-limiting)
- [API Endpoints](#api-endpoints)
  - [Authentication](#authentication-endpoints)
  - [Logs](#logs-endpoints)
  - [Parsers](#parsers-endpoints)
  - [Detection Rules](#detection-rules-endpoints)
  - [Alerts](#alerts-endpoints)
  - [Users](#users-endpoints)
  - [Settings](#settings-endpoints)
  - [Log Shippers](#log-shippers-endpoints)

---

## Authentication

Most API endpoints require authentication using JWT (JSON Web Token). After logging in, include the token in the `Authorization` header:

```http
Authorization: Bearer YOUR_JWT_TOKEN
```

**Session Duration:** Tokens are valid for 24 hours from login.

---

## Response Format

### Success Response
```json
{
  "data": { ... },
  "message": "Success message (optional)"
}
```

### Error Response
```json
{
  "error": "Error message",
  "code": 400,
  "details": "Additional error details (optional)"
}
```

---

## Error Codes

| Code | Meaning | Description |
|------|---------|-------------|
| 200 | OK | Request succeeded |
| 201 | Created | Resource created successfully |
| 400 | Bad Request | Invalid request parameters |
| 401 | Unauthorized | Missing or invalid authentication |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Resource already exists |
| 500 | Internal Server Error | Server error |

---

## Rate Limiting

- **Limit:** 100 requests per 15 minutes per IP address
- **Response Header:** `X-RateLimit-Remaining` shows remaining requests
- **Exceeded:** Returns `429 Too Many Requests`

---

## API Endpoints

## Authentication Endpoints

### POST /api/auth/login

Authenticate user and receive JWT token.

**Authentication:** None required

**Request Body:**
```json
{
  "username": "admin",
  "password": "changeme"
}
```

**Response (200):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "username": "admin",
    "email": "admin@example.com",
    "role": "admin",
    "enabled": true,
    "last_login": "2025-11-30T12:00:00Z"
  },
  "expiresAt": "2025-12-01T12:00:00Z"
}
```

**Errors:**
- `400` - Missing username or password
- `401` - Invalid credentials
- `403` - Account is disabled

---

### POST /api/auth/logout

Logout current user and invalidate session token.

**Authentication:** Required

**Request Body:** None

**Response (200):**
```json
{
  "message": "Logged out successfully"
}
```

---

### GET /api/auth/me

Get current authenticated user's profile.

**Authentication:** Required

**Response (200):**
```json
{
  "id": 1,
  "username": "admin",
  "email": "admin@example.com",
  "role": "admin",
  "enabled": true,
  "last_login": "2025-11-30T12:00:00Z",
  "created_at": "2025-01-01T00:00:00Z"
}
```

---

### PUT /api/auth/me/password

Change current user's password.

**Authentication:** Required

**Request Body:**
```json
{
  "currentPassword": "oldpassword",
  "newPassword": "newpassword123"
}
```

**Response (200):**
```json
{
  "message": "Password updated successfully. Please login again."
}
```

**Notes:**
- New password must be at least 8 characters
- All user sessions are invalidated after password change
- User must login again with new password

**Errors:**
- `400` - Missing passwords or password too short
- `401` - Current password is incorrect

---

### POST /api/auth/cleanup

Cleanup expired sessions (admin only).

**Authentication:** Required (Admin role)

**Request Body:** None

**Response (200):**
```json
{
  "message": "Cleaned up 15 expired sessions"
}
```

---

## Logs Endpoints

### GET /api/logs/raw

Retrieve raw syslog messages.

**Authentication:** Required

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 100 | Number of logs to return |
| `offset` | integer | 0 | Pagination offset |
| `source_ip` | string | - | Filter by source IP address |
| `search` | string | - | Search in raw message |
| `severity` | integer | - | Filter by syslog severity (0-7) |
| `start_date` | ISO 8601 | - | Start time filter |
| `end_date` | ISO 8601 | - | End time filter |

**Example Request:**
```http
GET /api/logs/raw?limit=50&source_ip=192.168.1.100&severity=3
```

**Response (200):**
```json
{
  "logs": [
    {
      "id": 12345,
      "timestamp": "2025-11-30T19:30:15Z",
      "source_ip": "192.168.1.100",
      "facility": 1,
      "severity": 3,
      "hostname": "server1",
      "raw_message": "<11>Nov 30 19:30:15 server1 sshd[1234]: Failed password for root from 192.168.1.100 port 54321"
    }
  ],
  "total": 1523,
  "limit": 50,
  "offset": 0
}
```

**Syslog Severity Levels:**
- 0: Emergency
- 1: Alert
- 2: Critical
- 3: Error
- 4: Warning
- 5: Notice
- 6: Informational
- 7: Debug

---

### GET /api/logs/parsed

Retrieve parsed logs with extracted fields.

**Authentication:** Required

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 100 | Number of logs to return |
| `offset` | integer | 0 | Pagination offset |
| `source_ip` | string | - | Filter by source IP |
| `event_type` | string | - | Filter by event type |
| `search` | string | - | Search in parsed data |
| `start_date` | ISO 8601 | - | Start time filter |
| `end_date` | ISO 8601 | - | End time filter |

**Example Request:**
```http
GET /api/logs/parsed?event_type=ssh_failed_auth&limit=20
```

**Response (200):**
```json
{
  "logs": [
    {
      "id": 6789,
      "raw_log_id": 12345,
      "parser_id": 1,
      "timestamp": "2025-11-30T19:30:15Z",
      "event_type": "ssh_failed_auth",
      "parsed_data": {
        "hostname": "server1",
        "event": "Failed password",
        "user": "root",
        "source_ip": "192.168.1.100",
        "source_port": "54321"
      }
    }
  ],
  "total": 423,
  "limit": 20,
  "offset": 0
}
```

---

### GET /api/logs/parsed/search

Search parsed logs by specific field and value.

**Authentication:** Required

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `field` | string | Yes | Field name to search |
| `value` | string | Yes | Value to search for |
| `limit` | integer | No (100) | Results limit |
| `offset` | integer | No (0) | Pagination offset |

**Example Request:**
```http
GET /api/logs/parsed/search?field=user&value=root&limit=10
```

**Response (200):**
```json
{
  "logs": [
    {
      "id": 6789,
      "parsed_data": {
        "user": "root",
        "source_ip": "192.168.1.100",
        "event": "Failed password"
      },
      "timestamp": "2025-11-30T19:30:15Z"
    }
  ],
  "total": 87,
  "limit": 10,
  "offset": 0
}
```

---

## Parsers Endpoints

### GET /api/parsers

Get all log parsers.

**Authentication:** Required

**Response (200):**
```json
[
  {
    "id": 1,
    "name": "SSH Authentication",
    "description": "Parses SSH authentication logs",
    "enabled": true,
    "priority": 10,
    "parser_type": "regex",
    "pattern": "^(?<timestamp>\\w+\\s+\\d+\\s+\\d+:\\d+:\\d+)\\s+(?<hostname>\\S+)\\s+sshd\\[(?<pid>\\d+)\\]...",
    "field_mappings": {
      "1": "timestamp",
      "2": "hostname",
      "3": "pid",
      "4": "event",
      "5": "user",
      "6": "source_ip",
      "7": "source_port"
    },
    "test_samples": null,
    "created_at": "2025-01-01T00:00:00Z",
    "updated_at": "2025-01-01T00:00:00Z"
  }
]
```

**Parser Types:**
- `regex` - Regular expression with capture groups
- `grok` - Grok patterns (similar to Logstash)
- `json` - JSON log parsing (auto-extracts all fields)

---

### GET /api/parsers/:id

Get single parser by ID.

**Authentication:** Required

**Response (200):**
```json
{
  "id": 1,
  "name": "SSH Authentication",
  "description": "Parses SSH authentication logs",
  "enabled": true,
  "priority": 10,
  "parser_type": "regex",
  "pattern": "...",
  "field_mappings": { ... },
  "created_at": "2025-01-01T00:00:00Z",
  "updated_at": "2025-01-01T00:00:00Z"
}
```

**Errors:**
- `404` - Parser not found

---

### POST /api/parsers

Create a new log parser.

**Authentication:** Required

**Request Body:**
```json
{
  "name": "Custom App Parser",
  "description": "Parses custom application logs",
  "enabled": true,
  "priority": 50,
  "parser_type": "regex",
  "pattern": "^(?<timestamp>\\d{4}-\\d{2}-\\d{2})\\s+(?<level>\\w+)\\s+(?<message>.+)$",
  "field_mappings": {
    "1": "timestamp",
    "2": "level",
    "3": "message"
  },
  "test_samples": [
    "2025-11-30 ERROR Database connection failed"
  ]
}
```

**Field Mapping Format:**
- **For regex:** `{ "1": "field_name", "2": "another_field" }` (capture group number → field name)
- **For grok:** `{ "FIELD_NAME": "output_name" }` (grok field → output field name)
- **For JSON:** Not required (all fields auto-extracted)

**Response (201):**
```json
{
  "id": 10,
  "name": "Custom App Parser",
  ...
}
```

**Errors:**
- `400` - Missing required fields

---

### PUT /api/parsers/:id

Update existing parser.

**Authentication:** Required

**Request Body:** (all fields optional)
```json
{
  "name": "Updated Parser Name",
  "enabled": false,
  "priority": 100
}
```

**Response (200):**
```json
{
  "id": 10,
  "name": "Updated Parser Name",
  ...
}
```

**Errors:**
- `404` - Parser not found

---

### DELETE /api/parsers/:id

Delete parser.

**Authentication:** Required

**Response (200):**
```json
{
  "message": "Parser deleted successfully"
}
```

**Errors:**
- `404` - Parser not found

---

### POST /api/parsers/:id/test

Test a saved parser against a sample log.

**Authentication:** Required

**Request Body:**
```json
{
  "sample": "Nov 30 19:30:15 server1 sshd[12345]: Failed password for root from 192.168.1.100 port 54321"
}
```

**Response (200):**
```json
{
  "matched": true,
  "fields": {
    "timestamp": "Nov 30 19:30:15",
    "hostname": "server1",
    "pid": "12345",
    "event": "Failed password",
    "user": "root",
    "source_ip": "192.168.1.100",
    "source_port": "54321"
  }
}
```

**If no match:**
```json
{
  "matched": false,
  "fields": null
}
```

---

### POST /api/parsers/test

Test parser configuration without saving (for parser builder).

**Authentication:** Required

**Request Body:**
```json
{
  "parser_type": "regex",
  "pattern": "^(?<level>\\w+):\\s+(?<message>.+)$",
  "field_mappings": {
    "1": "level",
    "2": "message"
  },
  "sample": "ERROR: Database connection timeout"
}
```

**Response (200):**
```json
{
  "matched": true,
  "fields": {
    "level": "ERROR",
    "message": "Database connection timeout"
  }
}
```

**Use Case:** Frontend parser builder to validate configurations before saving.

---

## Detection Rules Endpoints

### GET /api/rules

Get all detection rules.

**Authentication:** Required

**Response (200):**
```json
[
  {
    "id": 1,
    "name": "SSH Brute Force Detection",
    "description": "Detects multiple failed SSH login attempts",
    "enabled": true,
    "severity": "high",
    "rule_yaml": "name: SSH Brute Force Detection\n...",
    "rule_logic": {
      "conditions": [...],
      "aggregation": {...}
    },
    "tags": ["ssh", "brute-force", "authentication"],
    "created_at": "2025-01-01T00:00:00Z",
    "updated_at": "2025-01-01T00:00:00Z"
  }
]
```

**Severity Levels:** `low`, `medium`, `high`, `critical`

---

### GET /api/rules/:id

Get single detection rule.

**Authentication:** Required

**Response (200):**
```json
{
  "id": 1,
  "name": "SSH Brute Force Detection",
  "description": "Detects multiple failed SSH login attempts",
  "enabled": true,
  "severity": "high",
  "rule_yaml": "...",
  "rule_logic": {...},
  "tags": ["ssh", "brute-force"],
  "created_at": "2025-01-01T00:00:00Z"
}
```

**Errors:**
- `404` - Rule not found

---

### POST /api/rules

Create a new detection rule.

**Authentication:** Required

**Request Body:**
```json
{
  "name": "Database Connection Errors",
  "description": "Detects multiple database failures",
  "enabled": true,
  "severity": "medium",
  "tags": ["database", "availability"],
  "rule_yaml": "name: Database Connection Errors\ndescription: Detects multiple database failures\nseverity: medium\nenabled: true\ntags: [database, availability]\n\nconditions:\n  - field: message\n    operator: contains\n    value: \"database\"\n  - field: level\n    operator: equals\n    value: \"ERROR\"\n\naggregation:\n  field: service\n  timeframe: 5m\n  threshold: 10\n\nalert:\n  title: \"Database Errors in {service}\"\n  description: \"{count} database errors in 5 minutes\""
}
```

**YAML Rule Format:**
```yaml
name: Rule Name
description: What this rule detects
severity: low|medium|high|critical
enabled: true
tags: [tag1, tag2]

conditions:
  - field: field_name
    operator: equals|contains|not_contains|regex|greater_than|less_than
    value: "value_to_match"

aggregation: # Optional
  field: field_to_group_by
  timeframe: 1m|5m|10m|15m|30m|1h|24h
  threshold: 5

alert:
  title: "Alert title with {variable} substitution"
  description: "Description with {count} and other {variables}"
```

**Response (201):**
```json
{
  "id": 15,
  "name": "Database Connection Errors",
  ...
}
```

**Errors:**
- `400` - Missing fields or invalid YAML format

---

### PUT /api/rules/:id

Update detection rule.

**Authentication:** Required

**Request Body:** (all fields optional)
```json
{
  "enabled": false,
  "severity": "high"
}
```

**Response (200):**
```json
{
  "id": 15,
  "name": "Database Connection Errors",
  "enabled": false,
  ...
}
```

**Errors:**
- `400` - Invalid YAML format (if rule_yaml provided)
- `404` - Rule not found

---

### DELETE /api/rules/:id

Delete detection rule.

**Authentication:** Required

**Response (200):**
```json
{
  "message": "Rule deleted successfully"
}
```

**Errors:**
- `404` - Rule not found

---

## Alerts Endpoints

### GET /api/alerts

Get all alerts with filtering.

**Authentication:** Required

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 100 | Results limit |
| `offset` | integer | 0 | Pagination offset |
| `severity` | string | - | Filter by severity (low/medium/high/critical) |
| `status` | string | - | Filter by status (new/investigating/closed/false_positive) |
| `ruleId` | integer | - | Filter by rule ID |
| `startTime` | ISO 8601 | - | Start time filter |
| `endTime` | ISO 8601 | - | End time filter |

**Example Request:**
```http
GET /api/alerts?severity=high&status=new&limit=50
```

**Response (200):**
```json
{
  "alerts": [
    {
      "id": 123,
      "rule_id": 1,
      "severity": "high",
      "title": "SSH Brute Force Detected from 192.168.1.100",
      "description": "5 failed SSH login attempts detected in 5 minutes",
      "status": "new",
      "matched_data": {
        "source_ip": "192.168.1.100",
        "count": 5,
        "user": "root"
      },
      "assigned_to": null,
      "created_at": "2025-11-30T19:35:00Z",
      "updated_at": "2025-11-30T19:35:00Z"
    }
  ],
  "total": 87,
  "limit": 50,
  "offset": 0
}
```

**Alert Statuses:**
- `new` - Alert just created, not reviewed
- `investigating` - Being investigated
- `closed` - Resolved
- `false_positive` - Determined to be false positive

---

### GET /api/alerts/statistics

Get alert statistics and counts.

**Authentication:** Required

**Response (200):**
```json
{
  "total_alerts": 1523,
  "by_severity": {
    "low": 234,
    "medium": 567,
    "high": 589,
    "critical": 133
  },
  "by_status": {
    "new": 45,
    "investigating": 12,
    "closed": 1450,
    "false_positive": 16
  },
  "recent_24h": 67,
  "recent_7d": 234
}
```

---

### GET /api/alerts/:id

Get single alert details.

**Authentication:** Required

**Response (200):**
```json
{
  "id": 123,
  "rule_id": 1,
  "rule_name": "SSH Brute Force Detection",
  "severity": "high",
  "title": "SSH Brute Force Detected from 192.168.1.100",
  "description": "5 failed SSH login attempts detected in 5 minutes",
  "status": "new",
  "matched_data": {
    "source_ip": "192.168.1.100",
    "count": 5,
    "user": "root"
  },
  "assigned_to": null,
  "created_at": "2025-11-30T19:35:00Z",
  "updated_at": "2025-11-30T19:35:00Z"
}
```

**Errors:**
- `404` - Alert not found

---

### PUT /api/alerts/:id

Update alert (change status, assign user, add notes).

**Authentication:** Required

**Request Body:** (all fields optional)
```json
{
  "status": "investigating",
  "assigned_to": 2,
  "description": "Updated description with investigation notes"
}
```

**Response (200):**
```json
{
  "id": 123,
  "status": "investigating",
  "assigned_to": 2,
  ...
}
```

**Errors:**
- `404` - Alert not found

---

### DELETE /api/alerts/:id

Delete alert.

**Authentication:** Required

**Response (200):**
```json
{
  "message": "Alert deleted successfully"
}
```

**Errors:**
- `404` - Alert not found

---

## Users Endpoints

All user endpoints require authentication. Admin role required for all operations except viewing own profile.

### GET /api/users

Get all users (admin only).

**Authentication:** Required (Admin)

**Response (200):**
```json
[
  {
    "id": 1,
    "username": "admin",
    "email": "admin@example.com",
    "role": "admin",
    "enabled": true,
    "last_login": "2025-11-30T12:00:00Z",
    "created_at": "2025-01-01T00:00:00Z"
  },
  {
    "id": 2,
    "username": "analyst1",
    "email": "analyst@example.com",
    "role": "analyst",
    "enabled": true,
    "last_login": "2025-11-30T10:00:00Z",
    "created_at": "2025-01-15T00:00:00Z"
  }
]
```

**User Roles:**
- `admin` - Full system access
- `analyst` - View and manage alerts, logs, rules
- `viewer` - Read-only access

---

### GET /api/users/:id

Get single user (admin only).

**Authentication:** Required (Admin)

**Response (200):**
```json
{
  "id": 2,
  "username": "analyst1",
  "email": "analyst@example.com",
  "role": "analyst",
  "enabled": true,
  "last_login": "2025-11-30T10:00:00Z",
  "created_at": "2025-01-15T00:00:00Z"
}
```

**Errors:**
- `404` - User not found

---

### POST /api/users

Create new user (admin only).

**Authentication:** Required (Admin)

**Request Body:**
```json
{
  "username": "newuser",
  "email": "newuser@example.com",
  "password": "password123",
  "role": "analyst",
  "enabled": true
}
```

**Response (201):**
```json
{
  "id": 3,
  "username": "newuser",
  "email": "newuser@example.com",
  "role": "analyst",
  "enabled": true,
  "created_at": "2025-11-30T12:00:00Z"
}
```

**Validation:**
- Password must be at least 8 characters
- Username and email must be unique

**Errors:**
- `400` - Missing fields or password too short
- `409` - Username or email already exists

---

### PUT /api/users/:id

Update user (admin only).

**Authentication:** Required (Admin)

**Request Body:** (all fields optional)
```json
{
  "email": "updated@example.com",
  "role": "admin",
  "enabled": false,
  "password": "newpassword123"
}
```

**Response (200):**
```json
{
  "id": 3,
  "username": "newuser",
  "email": "updated@example.com",
  "role": "admin",
  "enabled": false,
  ...
}
```

**Errors:**
- `400` - Password too short
- `404` - User not found
- `409` - Email or username already taken

---

### DELETE /api/users/:id

Delete user (admin only).

**Authentication:** Required (Admin)

**Response (200):**
```json
{
  "message": "User deleted successfully"
}
```

**Notes:**
- Cannot delete your own account
- All user's sessions are invalidated

**Errors:**
- `400` - Attempting to delete own account
- `404` - User not found

---

## Settings Endpoints

### GET /api/settings/retention

Get log retention settings (admin only).

**Authentication:** Required (Admin)

**Response (200):**
```json
{
  "raw_logs_days": 30,
  "parsed_logs_days": 90,
  "alerts_days": 365,
  "auto_cleanup_enabled": true
}
```

---

### PUT /api/settings/retention

Update retention settings (admin only).

**Authentication:** Required (Admin)

**Request Body:**
```json
{
  "raw_logs_days": 60,
  "parsed_logs_days": 120,
  "alerts_days": 730,
  "auto_cleanup_enabled": true
}
```

**Response (200):**
```json
{
  "message": "Retention settings updated successfully"
}
```

---

### POST /api/settings/retention/cleanup

Manually trigger log cleanup (admin only).

**Authentication:** Required (Admin)

**Request Body:**
```json
{
  "raw_logs_days": 30,
  "parsed_logs_days": 90,
  "alerts_days": 365
}
```

**Response (200):**
```json
{
  "message": "Cleanup completed successfully",
  "results": {
    "raw_logs_deleted": 15234,
    "parsed_logs_deleted": 8765,
    "alerts_deleted": 234
  }
}
```

**Note:** This performs immediate cleanup based on provided retention days.

---

### GET /api/settings/retention/stats

Get cleanup statistics and database sizes (admin only).

**Authentication:** Required (Admin)

**Response (200):**
```json
{
  "total_raw_logs": 152340,
  "total_parsed_logs": 98765,
  "total_alerts": 5678,
  "raw_logs_older_30d": 45000,
  "parsed_logs_older_90d": 12000,
  "alerts_older_365d": 1200,
  "raw_logs_size": "2.5 GB",
  "parsed_logs_size": "1.8 GB",
  "alerts_size": "156 MB"
}
```

---

### GET /api/settings/syslog

Get syslog server settings.

**Authentication:** Required

**Response (200):**
```json
{
  "syslog_host": "192.168.1.76",
  "syslog_port": 514
}
```

**Note:** These settings are auto-injected into log shipper configurations.

---

### PUT /api/settings/syslog

Update syslog server settings (admin only).

**Authentication:** Required (Admin)

**Request Body:**
```json
{
  "syslog_host": "10.0.1.100",
  "syslog_port": 514
}
```

**Response (200):**
```json
{
  "message": "Syslog settings updated successfully"
}
```

**Errors:**
- `400` - Missing syslog_host

---

## Log Shippers Endpoints

### GET /api/shippers

Get all log shippers.

**Authentication:** Required

**Response (200):**
```json
[
  {
    "id": 1,
    "name": "Web Server Shipper",
    "description": "Nginx web server logs",
    "hostname": "webserver01",
    "ip_address": "192.168.1.100",
    "version": "1.0.0",
    "status": "online",
    "last_seen": "2025-11-30T12:34:56Z",
    "created_at": "2025-11-01T00:00:00Z"
  }
]
```

**Shipper Statuses:**
- `pending` - Created but never connected
- `online` - Active (seen within 3 minutes)
- `offline` - No heartbeat for 3+ minutes
- `error` - Error state

---

### GET /api/shippers/:id

Get single shipper with full configuration.

**Authentication:** Required

**Response (200):**
```json
{
  "id": 1,
  "name": "Web Server Shipper",
  "description": "Nginx web server logs",
  "hostname": "webserver01",
  "ip_address": "192.168.1.100",
  "version": "1.0.0",
  "status": "online",
  "api_key": "a1b2c3d4...",
  "last_seen": "2025-11-30T12:34:56Z",
  "config": {},
  "metadata": {},
  "created_at": "2025-11-01T00:00:00Z",
  "updated_at": "2025-11-30T12:34:56Z",
  "sources": [
    {
      "id": 1,
      "source_type": "file",
      "enabled": true,
      "file_path": "/var/log/nginx/access.log",
      "tag": "nginx-access",
      "facility": "local0"
    }
  ],
  "volumes": [
    {
      "id": 1,
      "host_path": "/var/log/nginx",
      "container_path": "/var/log/nginx",
      "mode": "ro"
    }
  ]
}
```

**Note:** Syslog settings are NOT included in this admin endpoint. They are only auto-injected in the public shipper endpoints (`/register` and `/config/:api_key`) for shipper consumption.

**Errors:**
- `404` - Shipper not found

---

### POST /api/shippers

Create new log shipper.

**Authentication:** Required

**Request Body:**
```json
{
  "name": "Database Server Shipper",
  "description": "PostgreSQL logs",
  "hostname": "dbserver01"
}
```

**Response (201):**
```json
{
  "id": 2,
  "name": "Database Server Shipper",
  "api_key": "f7e8d9c0b1a2...",
  "status": "pending",
  "created_at": "2025-11-30T12:00:00Z"
}
```

**IMPORTANT:** Save the `api_key` - it's only shown once on creation!

**Errors:**
- `400` - Missing shipper name

---

### PUT /api/shippers/:id

Update shipper details.

**Authentication:** Required

**Request Body:** (all fields optional)
```json
{
  "name": "Updated Shipper Name",
  "description": "New description"
}
```

**Response (200):**
```json
{
  "id": 2,
  "name": "Updated Shipper Name",
  ...
}
```

**Note:** Cannot update `api_key` directly - use regenerate endpoint.

**Errors:**
- `404` - Shipper not found

---

### DELETE /api/shippers/:id

Delete log shipper.

**Authentication:** Required

**Response (200):**
```json
{
  "message": "Shipper deleted successfully"
}
```

**Note:** Also deletes all associated sources, volumes, and activity logs.

**Errors:**
- `404` - Shipper not found

---

### GET /api/shippers/:id/sources

Get all log sources for shipper.

**Authentication:** Required

**Response (200):**
```json
[
  {
    "id": 1,
    "shipper_id": 1,
    "source_type": "file",
    "enabled": true,
    "file_path": "/var/log/nginx/access.log",
    "container_name": null,
    "journal_unit": null,
    "tag": "nginx-access",
    "facility": "local0",
    "created_at": "2025-11-01T00:00:00Z"
  }
]
```

**Source Types:**
- `file` - Tail log files
- `docker` - Docker container logs
- `journal` - Systemd journal logs

---

### POST /api/shippers/:id/sources

Add log source to shipper.

**Authentication:** Required

**Request Body (File Source):**
```json
{
  "source_type": "file",
  "enabled": true,
  "file_path": "/var/log/app/application.log",
  "tag": "app-logs",
  "facility": "local1"
}
```

**Request Body (Docker Source):**
```json
{
  "source_type": "docker",
  "enabled": true,
  "container_name": "nginx",
  "tag": "nginx-container",
  "facility": "local2"
}
```

**Request Body (Journal Source):**
```json
{
  "source_type": "journal",
  "enabled": true,
  "journal_unit": "nginx.service",
  "tag": "nginx-systemd",
  "facility": "local3"
}
```

**Response (201):**
```json
{
  "id": 5,
  "shipper_id": 1,
  "source_type": "file",
  "file_path": "/var/log/app/application.log",
  "tag": "app-logs",
  ...
}
```

**Syslog Facilities:**
`local0`, `local1`, `local2`, `local3`, `local4`, `local5`, `local6`, `local7`

**Errors:**
- `400` - Missing source_type or tag

---

### PUT /api/shippers/sources/:sourceId

Update log source.

**Authentication:** Required

**Request Body:** (all fields optional)
```json
{
  "enabled": false,
  "facility": "local4"
}
```

**Response (200):**
```json
{
  "id": 5,
  "enabled": false,
  "facility": "local4",
  ...
}
```

**Errors:**
- `404` - Source not found

---

### DELETE /api/shippers/sources/:sourceId

Delete log source.

**Authentication:** Required

**Response (200):**
```json
{
  "message": "Source deleted successfully"
}
```

**Errors:**
- `404` - Source not found

---

### GET /api/shippers/:id/volumes

Get volume mounts for shipper.

**Authentication:** Required

**Response (200):**
```json
[
  {
    "id": 1,
    "shipper_id": 1,
    "host_path": "/var/log/nginx",
    "container_path": "/var/log/nginx",
    "mode": "ro",
    "created_at": "2025-11-01T00:00:00Z"
  }
]
```

**Mount Modes:**
- `ro` - Read-only (recommended for log files)
- `rw` - Read-write

---

### POST /api/shippers/:id/volumes

Add volume mount to shipper.

**Authentication:** Required

**Request Body:**
```json
{
  "host_path": "/opt/application/logs",
  "container_path": "/app/logs",
  "mode": "ro"
}
```

**Response (201):**
```json
{
  "id": 3,
  "shipper_id": 1,
  "host_path": "/opt/application/logs",
  "container_path": "/app/logs",
  "mode": "ro"
}
```

**Errors:**
- `400` - Missing host_path or container_path

---

### DELETE /api/shippers/volumes/:volumeId

Delete volume mount.

**Authentication:** Required

**Response (200):**
```json
{
  "message": "Volume deleted successfully"
}
```

**Errors:**
- `404` - Volume not found

---

### GET /api/shippers/:id/activity

Get activity log for shipper.

**Authentication:** Required

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 50 | Number of activity entries |

**Response (200):**
```json
[
  {
    "id": 15,
    "shipper_id": 1,
    "activity_type": "source_added",
    "message": "Added file source: nginx-access",
    "timestamp": "2025-11-30T12:00:00Z"
  },
  {
    "id": 14,
    "shipper_id": 1,
    "activity_type": "config_updated",
    "message": "Shipper configuration updated",
    "timestamp": "2025-11-30T11:30:00Z"
  }
]
```

**Activity Types:**
- `created` - Shipper created
- `config_updated` - Configuration changed
- `source_added` - Log source added
- `source_updated` - Log source modified
- `volume_added` - Volume mount added
- `key_regenerated` - API key regenerated

---

### POST /api/shippers/:id/regenerate-key

Regenerate shipper API key (invalidates old key).

**Authentication:** Required

**Response (200):**
```json
{
  "api_key": "new_api_key_here_a1b2c3d4..."
}
```

**IMPORTANT:**
- Old API key is immediately invalidated
- Update shipper configuration with new key
- Shipper will go offline until reconfigured

**Errors:**
- `404` - Shipper not found

---

### POST /api/shippers/register

**PUBLIC ENDPOINT** - Shipper registration and heartbeat.

**Authentication:** None (uses API key)

**Request Body:**
```json
{
  "api_key": "shipper_api_key_here",
  "version": "1.0.0",
  "hostname": "webserver01",
  "metadata": {
    "os": "Ubuntu 22.04",
    "arch": "x86_64"
  }
}
```

**Response (200):**
```json
{
  "id": 1,
  "name": "Web Server Shipper",
  "description": "Nginx web server logs",
  "api_key": "a1b2c3d4...",
  "status": "online",
  "version": "1.0.0",
  "last_seen": "2025-11-30T12:34:56Z",
  "ip_address": "192.168.1.100",
  "hostname": "webserver01",
  "config": {},
  "metadata": {
    "os": "Ubuntu 22.04",
    "arch": "x86_64"
  },
  "created_at": "2025-11-01T00:00:00Z",
  "updated_at": "2025-11-30T12:34:56Z",
  "sources": [
    {
      "id": 1,
      "source_type": "file",
      "enabled": true,
      "file_path": "/var/log/nginx/access.log",
      "tag": "nginx-access",
      "facility": "local0"
    }
  ],
  "volumes": [
    {
      "host_path": "/var/log/nginx",
      "container_path": "/var/log/nginx",
      "mode": "ro"
    }
  ],
  "siem_host": "192.168.1.76",
  "siem_port": 514
}
```

**Important:** Syslog settings (`siem_host` and `siem_port`) are automatically injected at the top level of the response for shipper consumption.

**Use Case:** Called by shipper on startup and periodically for heartbeat.

**Errors:**
- `400` - Missing API key
- `404` - Invalid API key

---

### GET /api/shippers/config/:api_key

**PUBLIC ENDPOINT** - Get shipper configuration.

**Authentication:** None (uses API key in URL)

**Response (200):**
```json
{
  "id": 1,
  "name": "Web Server Shipper",
  "description": "Nginx web server logs",
  "api_key": "a1b2c3d4...",
  "status": "online",
  "version": "1.0.0",
  "last_seen": "2025-11-30T12:34:56Z",
  "ip_address": "192.168.1.100",
  "hostname": "webserver01",
  "config": {},
  "metadata": {},
  "created_at": "2025-11-01T00:00:00Z",
  "updated_at": "2025-11-30T12:34:56Z",
  "sources": [
    {
      "id": 1,
      "source_type": "file",
      "enabled": true,
      "file_path": "/var/log/nginx/access.log",
      "tag": "nginx-access",
      "facility": "local0"
    }
  ],
  "volumes": [
    {
      "host_path": "/var/log/nginx",
      "container_path": "/var/log/nginx",
      "mode": "ro"
    }
  ],
  "siem_host": "192.168.1.76",
  "siem_port": 514
}
```

**Important:**
- Syslog settings (`siem_host` and `siem_port`) are automatically injected at the top level
- Response structure is identical to `/shippers/register` for consistency
- Shipper scripts parse `sources`, `volumes`, `siem_host`, and `siem_port` from the top level

**Use Case:** Polled by shipper every 30 seconds to get latest configuration.

**Errors:**
- `404` - Invalid API key

---

## Integration Examples

### JavaScript/TypeScript (Axios)

```typescript
import axios from 'axios';

const api = axios.create({
  baseURL: 'http://siembox:3001/api',
  headers: {
    'Content-Type': 'application/json'
  }
});

// Login
const { data } = await api.post('/auth/login', {
  username: 'admin',
  password: 'password'
});

const token = data.token;

// Use token for authenticated requests
api.defaults.headers.common['Authorization'] = `Bearer ${token}`;

// Get alerts
const alerts = await api.get('/alerts', {
  params: { severity: 'high', status: 'new' }
});

console.log(alerts.data);
```

### Python (requests)

```python
import requests

BASE_URL = "http://siembox:3001/api"

# Login
response = requests.post(f"{BASE_URL}/auth/login", json={
    "username": "admin",
    "password": "password"
})
token = response.json()["token"]

# Use token
headers = {"Authorization": f"Bearer {token}"}

# Get alerts
alerts = requests.get(f"{BASE_URL}/alerts", headers=headers, params={
    "severity": "high",
    "status": "new"
})

print(alerts.json())
```

### cURL

```bash
# Login
TOKEN=$(curl -s -X POST http://siembox:3001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}' \
  | jq -r '.token')

# Get alerts
curl -H "Authorization: Bearer $TOKEN" \
  "http://siembox:3001/api/alerts?severity=high&status=new"
```

---

## Webhook Integration (Future)

Webhook notifications are on the roadmap. Planned features:

- Alert webhooks (POST to external URL when alert created)
- Custom headers and authentication
- Retry logic with exponential backoff
- Webhook delivery logs

---

## Support

- **Issues:** https://github.com/cladkins/SIEMBOX/issues
- **Discussions:** https://github.com/cladkins/SIEMBOX/discussions
- **Documentation:** https://github.com/cladkins/SIEMBOX

---

**Last Updated:** 2025-12-02
