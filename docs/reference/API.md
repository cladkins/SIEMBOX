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
  - [Catalog & AI Builder (v2)](#catalog--ai-builder-endpoints-v2)
  - [Alerts](#alerts-endpoints)
  - [Users](#users-endpoints)
  - [Settings](#settings-endpoints)
  - [Log Shippers](#log-shippers-endpoints)
  - [Assets](#assets-endpoints)
  - [Log Discovery](#log-discovery-endpoints)
  - [Vulnerabilities](#vulnerabilities-endpoints)
  - [Admin Dashboard](#admin-dashboard-endpoints)

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
| `app_name` | string | - | Filter by syslog tag/program (shown as "Source" in the UI) |
| `hostname` | string | - | Filter by syslog hostname |
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
      "app_name": "sshd",
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
| `app_name` | string | - | Filter by the originating raw log's syslog tag ("Source") |
| `parser_id` | integer | - | Filter by the parser that matched |
| `parse_status` | string | - | `parsed` (a parser matched) or `unparsed` (generic fallback record); omit for both |
| `search` | string | - | Search in parsed data |
| `start_date` | ISO 8601 | - | Start time filter |
| `end_date` | ISO 8601 | - | End time filter |

Logs that no parser matched are still stored in `parsed_logs` as a minimal
fallback record — `parser_id: null`, `event_type: "unparsed"` — so every log
stays searchable. Detection rules are **not** evaluated against them. Use
`parse_status=parsed` to exclude them, or `parse_status=unparsed` to review what
is missing parser coverage.

Note that `parsed_logs.parser_id` is `ON DELETE SET NULL`: deleting a parser
moves the events it produced into the `unparsed` population (their
`parsed_data` is retained; only the attribution is lost).

**Example Request:**
```http
GET /api/logs/parsed?event_type=ssh_failed_auth&limit=20
GET /api/logs/parsed?parse_status=unparsed&limit=20
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

### GET /api/logs/parse-coverage

How much of the last 24 hours of ingested logs was matched by a parser — i.e.
how much of the stream is visible to detection. Detection rules are only
evaluated on parser-matched logs; the unparsed fallback is stored but never
runs detections, so a low `parsed_pct` means rules are starved of input.

**Authentication:** Required

**Response (200):**
```json
{
  "window": "24h",
  "since": "2026-07-27T00:00:00.000Z",
  "total": 1250000,
  "parsed": 26000,
  "unparsed": 1224000,
  "parsed_pct": 2.1
}
```

`parsed_pct` is `null` when no logs were ingested in the window. Counts come
from incrementally-maintained hourly counters (`parser_match_hourly`), not a
`parsed_logs` scan; after an upgrade the 24h window fills over the first day,
and `since` marks where counter data begins.

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

### GET /api/parsers/match-stats

Per-parser production match counts over the last 24 hours, keyed by parser id,
plus the count of logs that fell through to the unparsed fallback. A parser
with zero matches is either unused or silently failing against the live log
format even though its self-tests pass.

**Authentication:** Required

**Response (200):**
```json
{
  "window": "24h",
  "since": "2026-07-27T00:00:00.000Z",
  "by_parser": { "1": 50608, "7": 12044 },
  "unparsed": 1224000
}
```

Counts come from the same hourly counters as parse-coverage (see above), so
this endpoint is O(1)-ish regardless of log volume.

---

### GET /api/parsers/recommendations

Recommends catalog parsers to install by dry-running every valid,
not-yet-installed catalog parser against a sample of recent **unparsed** logs
using the real parse pipeline. Sampling and ranking are severity-aware: lines
with syslog severity ≤ 4 (warning or worse) are sampled first, and the ranking
`score` counts a warning+ log 10× a routine one. Sources no candidate matches
are returned as `uncovered` — the top targets for authoring a parser (e.g. via
the AI builder).

Results are cached for 10 minutes; pass `?refresh=true` to recompute.

**Authentication:** Required

**Response (200):**
```json
{
  "window": "24h",
  "sampled_sources": 25,
  "candidates_considered": 27,
  "computed_at": "2026-07-27T00:00:00.000Z",
  "recommendations": [
    {
      "name": "unifi-hostapd",
      "description": "Parses hostapd WiFi station events...",
      "tags": ["wifi", "unifi"],
      "sources": [
        { "app_name": "hostapd", "matched": 11, "sampled": 12,
          "unparsed_daily": 168271, "unparsed_high_sev_daily": 3200 }
      ],
      "matched": 11,
      "sampled": 12,
      "est_daily_matches": 154248,
      "est_daily_high_severity": 2933,
      "score": 180645
    }
  ],
  "uncovered": [
    {
      "app_name": "homebox",
      "unparsed_daily": 80866,
      "unparsed_high_sev_daily": 120,
      "example": "level=INFO msg=\"request completed\" status=200"
    }
  ]
}
```

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

### GET /api/rules/recommendations

Recommends catalog detection rules to install by dry-running every valid,
not-yet-installed catalog rule's **conditions** against samples of recent
**parsed** logs using the real condition evaluator. A recommendation means
your live data actually satisfies the rule's conditions, so it would engage
rather than sit inert. Ranked by matching logs/day × rule-severity weight
(critical 10, high 5, medium 2, low 1). DB-backed operators
(`not_in_whitelist`, `on_threat_feed`, ...) count as satisfied when the field
is present, since their outcome is runtime context, not data shape.

Cached 10 minutes; `?refresh=true` recomputes.

**Authentication:** Required

**Response (200):**
```json
{
  "window": "24h",
  "sampled_parsers": 5,
  "candidates_considered": 40,
  "computed_at": "2026-07-27T00:00:00.000Z",
  "recommendations": [
    {
      "name": "SSH Brute Force Detection",
      "severity": "high",
      "tags": ["ssh", "brute-force"],
      "sources": [
        { "parser_name": "ssh-authentication", "matched": 8, "sampled": 12, "daily_volume": 3000 }
      ],
      "matched": 8,
      "sampled": 12,
      "est_daily_matches": 2000,
      "score": 10000,
      "aggregation": { "field": "source_ip", "timeframe": "5m", "threshold": 5 }
    }
  ]
}
```

`aggregation`, when present, tells the UI the rule only fires once its
threshold is met over the timeframe (the `est_daily_matches` is condition-
matching logs, not alerts).

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

## Catalog & AI Builder Endpoints (v2)

SIEMBox v2 treats parsers and detections as portable data. These endpoints back
the in-app catalog (browse / install / refresh), portable export & import, and
the AI builder. Parsers and detections expose parallel routes.

Install/import is never blind: every item is run through the validator and its
self-tests before it is stored. A failing item returns `422` (with the
validation / self-test details) unless you pass `force: true`.

### Catalog

| Method & Path | Purpose |
|---|---|
| `GET /api/parsers/catalog` | Browse the parser catalog, each entry annotated with `installed` and `update_available`. `?refresh=true` bypasses the ~5-minute cache. Returns `{ source, parsers }`. |
| `GET /api/parsers/catalog/source` | The configured catalog source (repo / ref) for display. |
| `POST /api/parsers/catalog/install` | Install or update a catalog parser by `name` (validate → self-test → upsert). Body: `{ "name": "nginx", "force": false }`. `201` created / `200` updated. |
| `POST /api/parsers/catalog/refresh` | Force a catalog cache refresh. Returns `{ refreshed, count }`. |
| `GET /api/rules/catalog` | Browse the detection catalog (same annotations). Returns `{ source, rules }`. |
| `GET /api/rules/catalog/source` | The configured catalog source. |
| `POST /api/rules/catalog/install` | Install or update a catalog detection by `name`. |
| `POST /api/rules/catalog/refresh` | Force a catalog cache refresh. |

Catalog source defaults to `cladkins/siembox-parsers` and is overridable via the
`SIEMBOX_CATALOG_REPO` / `SIEMBOX_CATALOG_REF` env vars (`GITHUB_TOKEN` raises the
GitHub API rate limit).

### Export / Import (portable parsers)

| Method & Path | Purpose |
|---|---|
| `GET /api/parsers/:id/export` | Export an installed parser as a portable `siembox.parser/v1` JSON document. |
| `POST /api/parsers/import` | Import a portable parser. Body: `{ "parser": { … }, "force": false }`. Validated + self-tested before upsert; `422` on failure unless `force`. |

### AI Builder

**Authentication:** Admin. Requires an AI provider to be configured (see
`PUT /api/settings/ai`). Each call runs a **generate → validate → auto-refine**
loop against the real engine (default ≤3 attempts) and returns the proposed
artifact together with its validation and self-test results — it never returns an
invalid parser/detection.

#### POST /api/parsers/ai/generate

Generate a parser from a sample log line.

**Request Body:**
```json
{
  "sample": "192.168.1.10 - - [10/Oct/2024:13:55:36 +0000] \"GET / HTTP/1.1\" 200 1234",
  "hints": "nginx access log",
  "maxAttempts": 3
}
```
`sample` is required; `hints` and `maxAttempts` are optional.

#### POST /api/rules/ai/generate

Generate a detection rule from a natural-language description.

**Request Body:**
```json
{
  "description": "Alert on 5 or more failed SSH logins from one IP in 5 minutes",
  "context": "fields available: source_ip, event_action, app",
  "maxAttempts": 3
}
```
`description` is required; `context` and `maxAttempts` are optional.

### AI Settings

**Authentication:** Admin.

| Method & Path | Purpose |
|---|---|
| `GET /api/settings/ai` | Current AI config (provider, model, base URL, and whether a key is set — the key itself is never returned). |
| `PUT /api/settings/ai` | Update AI config. Body: `{ "provider": "anthropic" \| "openai" \| "ollama", "model": "…", "baseUrl": "…", "apiKey": "…" }`. Pass `apiKey` to set it (encrypted at rest via `CREDENTIAL_ENCRYPTION_KEY`), or `""` to clear it. |

> Storing a key from the UI requires `CREDENTIAL_ENCRYPTION_KEY` to be set;
> alternatively provide the key via the `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`
> environment variable.

### AI Triage Settings

Automatic, agentic per-alert analysis — see [AI Security Analyst → Automated triage](../../wiki/AI-Security-Analyst.md#automated-triage). Off by default.

**Authentication:** Admin (`GET /api/ai/triage/health` below is available to any authenticated user — a non-secret subset used to gate the UI).

| Method & Path | Purpose |
|---|---|
| `GET /api/settings/ai-triage` | Current triage config: provider/model/baseUrl (inherits AI Analyst if unset), whether a key is configured, plus operational settings (`enabled`, `minSeverity`, `dailyCap`, `maxConcurrent`, `dedupeHours`, `maxToolCalls`, `wallBudgetSeconds`). Key itself is never returned. |
| `PUT /api/settings/ai-triage` | Update triage config. Body (all optional): `{ "provider": "anthropic" \| "openai" \| "ollama" \| "", "model": "…", "baseUrl": "…", "apiKey": "…", "enabled": true, "minSeverity": "medium", "dailyCap": 200, "maxConcurrent": 2, "dedupeHours": 6, "maxToolCalls": 6, "wallBudgetSeconds": 110 }`. Empty `provider` reverts to inheriting the AI Analyst config. `maxToolCalls` (1-12) and `wallBudgetSeconds` (20-280) bound how deep/long a single alert's analysis can go before it's forced to synthesize a verdict from whatever it has. |
| `GET /api/ai/triage/health` | `{ "configured": bool, "enabled": bool, "minSeverity": "…" }` — lets the Alerts/SOC Triage UI know whether to render triage state. |

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
| `triageStatus` | string | - | Filter by AI triage status (pending/analyzing/complete/failed/skipped) |
| `triageVerdict` | string | - | Filter by AI triage verdict (true_positive/false_positive/suspicious/inconclusive) |
| `minRiskScore` | integer | - | Minimum AI triage risk score (0-100) |
| `sortBy` | string | created_at | `risk_score` sorts highest-risk-first (used by the SOC Triage queue view); any other value sorts by `created_at` |

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
      "updated_at": "2025-11-30T19:35:00Z",
      "triage_status": "complete",
      "triage_verdict": "true_positive",
      "triage_risk_score": 82
    }
  ],
  "total": 87,
  "limit": 50,
  "offset": 0
}
```

`triage_status`/`triage_verdict`/`triage_risk_score` are `null` until [AI triage](../../wiki/AI-Security-Analyst.md#automated-triage) has run for an alert (or if it's disabled). Fetch the full verdict via `GET /api/alerts/:id/triage` below.

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

### GET /api/alerts/:id/triage

Get an alert's [AI triage](../../wiki/AI-Security-Analyst.md#automated-triage) verdict, or its pending/absent state. Always `200` (never `404` for "no run yet") so a frontend poll doesn't need special-case error handling.

**Authentication:** Required

**Response (200):**
```json
{
  "triage": {
    "alert_id": 123,
    "status": "complete",
    "verdict": "true_positive",
    "risk_score": 82,
    "confidence": "high",
    "summary": "Repeated failed SSH logins from an external IP.",
    "reasoning": "...(markdown)...",
    "evidence": [{ "claim": "12 failed logins in 5 minutes", "source": "alert" }],
    "suggested_queries": [{ "label": "Check IP reputation", "tool": "lookup_ip", "args": { "ip": "192.168.1.100" } }],
    "remediation": {
      "proposed_status": "investigating",
      "urgency": "high",
      "steps": ["Block 192.168.1.100 at the firewall"]
    },
    "provider": "anthropic",
    "model": "claude-sonnet-4-6",
    "created_at": "2025-11-30T19:35:10Z",
    "updated_at": "2025-11-30T19:36:40Z"
  },
  "enabled": true,
  "eligible": true
}
```

`triage` is `null` when no run has happened yet (not yet eligible, still queued, or triage disabled). `eligible` reflects whether the alert's severity meets the configured minimum for automatic triage.

**Errors:**
- `404` - Alert not found

---

### POST /api/alerts/:id/triage/rerun

Manually (re-)run AI triage for an alert, bypassing the severity and duplicate-alert gates (but not the daily cost cap or concurrency limit). Responds immediately; the analysis runs in the background (up to ~110s) — poll `GET /api/alerts/:id/triage` for the result.

**Authentication:** Required (admin, analyst, or operator role). Rate-limited per user (10 requests / 5 minutes).

**Response (202):**
```json
{ "status": "pending" }
```

**Errors:**
- `404` - Alert not found
- `429` - Too many re-run requests

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

**Response (202):** the purge runs as a **background job** (deleting millions
of rows takes minutes to hours, far past any HTTP timeout). Poll the status
endpoint below for live progress. Returns `409` if a job is already running.

```json
{
  "message": "Cleanup started",
  "job": {
    "status": "running",
    "started_at": "2026-07-27T01:00:00.000Z",
    "params": { "raw_logs_days": 30, "parsed_logs_days": 90, "alerts_days": 365 },
    "results": { "raw_logs_deleted": 0, "parsed_logs_deleted": 0, "alerts_deleted": 0 }
  }
}
```

---

### GET /api/settings/retention/cleanup/status

Live status of the current (or most recent) manual cleanup job (admin only).
`results` counts update after every delete batch; `status` becomes
`completed` or `failed` (with `error`) when the job ends. `job` is `null` if
no manual cleanup has run since the backend started.

**Authentication:** Required (Admin)

**Response (200):**
```json
{
  "job": {
    "status": "running",
    "started_at": "2026-07-27T01:00:00.000Z",
    "params": { "raw_logs_days": 30 },
    "results": { "raw_logs_deleted": 1250000, "parsed_logs_deleted": 0, "alerts_deleted": 0 }
  }
}
```

---

### GET /api/settings/retention/stats

Get cleanup statistics and database sizes (admin only). Table totals are
planner estimates (`pg_class.reltuples`) — exact counts required scanning
multi-million-row tables on every Settings view; the "older than" counts
remain exact (index-assisted).

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
  "alerts_size": "156 MB",
  "oldest_raw_log": "2025-11-15T10:30:00Z",
  "oldest_parsed_log": "2025-11-15T10:32:00Z",
  "oldest_alert": "2025-11-16T08:45:00Z"
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

### GET /api/settings/syslog/status

Get syslog server status and health information (admin only).

**Authentication:** Required (Admin)

**Response (200):**
```json
{
  "actual_listening_port": 514,
  "configured_port": 514,
  "ports_match": true,
  "last_log_received": "2025-12-15T20:35:42Z",
  "logs_received_last_5min": 1234,
  "unique_sources_last_5min": 5,
  "status": "healthy",
  "status_message": "Syslog receiver is active and receiving logs"
}
```

**Status Values:**
- `healthy` - Receiver active, ports match, logs being received
- `warning` - Port mismatch with logs, or no recent logs
- `error` - Port mismatch with no logs

**Note:** Used by the Settings UI to display syslog receiver health and activity.

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

### POST /api/shippers/:id/regenerate-key

Regenerate API key for log shipper (admin only).

**Authentication:** Required (Admin)

**Response (200):**
```json
{
  "api_key": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2"
}
```

**Security Behavior:**
- Immediately invalidates the old API key
- Generates a new 64-character hexadecimal API key
- Shipper must be reconfigured with the new key to continue operation
- Ghost shippers will be created if old key is not replaced (logs continue via syslog, but configuration updates blocked)

**Use Cases:**
- API key rotation for security compliance
- Response to potential key compromise
- Revoking access for decommissioned shipper instances

**Frontend Integration:**
- Auto-copies new key to clipboard
- Displays warning about immediate invalidation
- Shows confirmation dialog before regeneration

**Errors:**
- `404` - Shipper not found
- `403` - Insufficient permissions (requires admin role)

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

### POST /api/shippers/:id/http-push-key

Generate (or rotate) the HTTP log-push key for a shipper. This is a **separate key** from the syslog `api_key` above — it authenticates `POST /api/shippers/logs` only, and is never returned again after this call.

**Authentication:** Required (Admin)

**Response (200):**
```json
{
  "http_push_key": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2"
}
```

**Security Behavior:**
- Only a sha256 hash of the key is stored server-side — the plaintext is shown exactly once, in this response
- Rotating replaces the previous push key; the old one stops working immediately
- Unlike the syslog `api_key`, there is no "ghost shipper" grace period — a revoked or rotated-away push key is rejected on the very next request

**Errors:**
- `404` - Shipper not found
- `403` - Insufficient permissions (requires admin role)

---

### DELETE /api/shippers/:id/http-push-key

Revoke the HTTP log-push key for a shipper. `POST /api/shippers/logs` immediately starts rejecting requests for this shipper until a new key is generated.

**Authentication:** Required (Admin)

**Response (200):**
```json
{ "revoked": true }
```

**Errors:**
- `404` - Shipper not found
- `403` - Insufficient permissions (requires admin role)

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

### POST /api/shippers/logs

**PUBLIC ENDPOINT** (shipper-authenticated) — HTTP log-push ingestion. For homelab/self-hosted tools that can POST JSON but can't (or shouldn't) speak syslog. Complements syslog ingestion on port 514/UDP+TCP; both land in the same `raw_logs` table and go through the same parser engine.

**Authentication:** `Authorization: Bearer <http_push_key>` + `X-Shipper-ID: <shipper id>` (see `POST /api/shippers/:id/http-push-key` above — this is **not** the syslog `api_key` and **not** a JWT).

**Request Body — single entry:**
```json
{
  "message": "Failed password for root from 203.0.113.5 port 51515 ssh2",
  "hostname": "nas01",
  "app_name": "sshd",
  "timestamp": "2026-07-30T14:22:01Z",
  "facility": 4,
  "severity": 3,
  "event_id": "optional-client-dedup-key"
}
```

**Request Body — batch:**
```json
{ "logs": [ { "message": "..." }, { "message": "..." } ] }
```

Only `message` is required. It must be the **bare extracted message** — the same thing `syslogParser.ts` produces after stripping `<PRI>TIMESTAMP HOSTNAME TAG:` — not a full syslog-framed line; parsers match only the extracted message (see CLAUDE.md). All other fields are optional; invalid `facility` (0–23) or `severity` (0–7) values are stored as `null` rather than rejecting the entry. `event_id`, if supplied, dedupes retried/at-least-once deliveries — a repeated `event_id` from the same shipper is counted, not re-ingested. Batches are capped at 1000 entries per request.

**Response (202):**
```json
{ "accepted": 1, "duplicate": 0, "rejected": 0, "errors": [] }
```

A malformed entry in a batch doesn't fail the whole request — it's counted in `rejected`, with up to 20 `{index, error}` entries returned in `errors`.

**Errors:**
- `400` - Body isn't a single log object or `{ "logs": [...] }`, empty `logs` array, or batch exceeds 1000 entries
- `401` - Missing/invalid `X-Shipper-ID` or Bearer key, or HTTP push not provisioned for this shipper

---

## Assets Endpoints

### GET /api/assets/scans

Get all vulnerability scans with filtering and pagination.

**Authentication:** Required

**Query Parameters:**
- `status` (optional) - Filter by scan status: `queued`, `running`, `completed`, `failed`
- `scan_type` (optional) - Filter by scan type: `asset_discovery`, `vulnerability`
- `limit` (optional) - Results per page (default: 50)
- `offset` (optional) - Pagination offset (default: 0)

**Response (200):**
```json
{
  "scans": [
    {
      "id": 1,
      "scan_type": "asset_discovery",
      "target": "192.168.1.0/24",
      "status": "completed",
      "started_at": "2025-12-17T10:00:00Z",
      "completed_at": "2025-12-17T10:05:23Z",
      "duration_seconds": 323,
      "assets_discovered": 15,
      "vulnerabilities_found": 0,
      "initiated_by": 1,
      "initiated_by_username": "admin",
      "scan_options": {
        "scan_type": "port",
        "description": "Network scan"
      },
      "error_message": null,
      "results_summary": {},
      "created_at": "2025-12-17T10:00:00Z",
      "updated_at": "2025-12-17T10:05:23Z"
    }
  ],
  "total": 42,
  "limit": 50,
  "offset": 0,
  "hasMore": false
}
```

---

### GET /api/assets/scans/:scanId

Get detailed information about a specific scan.

**Authentication:** Required

**URL Parameters:**
- `scanId` - Scan ID

**Response (200):**
```json
{
  "id": 1,
  "scan_type": "asset_discovery",
  "target": "192.168.1.0/24",
  "status": "completed",
  "started_at": "2025-12-17T10:00:00Z",
  "completed_at": "2025-12-17T10:05:23Z",
  "duration_seconds": 323,
  "assets_discovered": 15,
  "vulnerabilities_found": 0,
  "initiated_by": 1,
  "initiated_by_username": "admin",
  "scan_options": {
    "scan_type": "port",
    "description": "Network scan"
  },
  "error_message": null,
  "results_summary": {},
  "created_at": "2025-12-17T10:00:00Z",
  "updated_at": "2025-12-17T10:05:23Z"
}
```

**Errors:**
- `404` - Scan not found

---

### GET /api/assets/scans/active

Get all active scans (queued or running).

**Authentication:** Required

**Response (200):**
```json
{
  "scans": [
    {
      "id": 5,
      "scan_type": "asset_discovery",
      "target": "192.168.2.0/24",
      "status": "running",
      "started_at": "2025-12-17T11:30:00Z",
      "completed_at": null,
      "duration_seconds": null,
      "assets_discovered": 0,
      "vulnerabilities_found": 0,
      "initiated_by": 2,
      "initiated_by_username": "analyst",
      "scan_options": {},
      "error_message": null,
      "results_summary": null,
      "created_at": "2025-12-17T11:30:00Z",
      "updated_at": "2025-12-17T11:30:00Z"
    }
  ],
  "total": 1
}
```

---

### GET /api/assets/scans/statistics

Get scan statistics and metrics.

**Authentication:** Required

**Response (200):**
```json
{
  "total_scans": "127",
  "completed_scans": "115",
  "failed_scans": "5",
  "active_scans": "2",
  "total_assets_discovered": "458",
  "total_vulnerabilities_found": "142",
  "avg_scan_duration": 285.7,
  "last_scan_time": "2025-12-17T11:30:00Z"
}
```

---

### GET /api/settings/auto-discovery

Get auto-discovery configuration settings.

**Authentication:** Required (Admin only)

**Response (200):**
```json
{
  "enabled": true,
  "interval_minutes": 360,
  "stale_threshold_days": 30
}
```

**Settings:**
- `enabled` - Whether auto-discovery is enabled
- `interval_minutes` - Time between auto-discovery runs (5-10080 minutes)
- `stale_threshold_days` - Days before marking assets as offline (1-365 days)

---

### PUT /api/settings/auto-discovery

Update auto-discovery configuration settings.

**Authentication:** Required (Admin only)

**Request Body:**
```json
{
  "enabled": true,
  "interval_minutes": 180,
  "stale_threshold_days": 14
}
```

**All fields are optional** - only include settings you want to update.

**Validation:**
- `interval_minutes` - Must be between 5 and 10080 (5 minutes to 7 days)
- `stale_threshold_days` - Must be between 1 and 365

**Response (200):**
```json
{
  "message": "Auto-discovery settings updated successfully",
  "settings": {
    "enabled": true,
    "interval_minutes": 180,
    "stale_threshold_days": 14
  }
}
```

**Errors:**
- `400` - Invalid parameter values
- `403` - Not authorized (admin only)

**Notes:**
- Changing `interval_minutes` causes the auto-discovery job to reschedule
- Setting `enabled: false` stops auto-discovery but preserves the interval setting
- Changes take effect immediately (no restart required)

---

### GET /api/settings/auto-discovery/stats

Get auto-discovery statistics.

**Authentication:** Required (Admin only)

**Response (200):**
```json
{
  "auto_discovered_assets": "342",
  "offline_assets": "28",
  "last_discovery_time": "2025-12-17T06:00:00Z",
  "assets_seen_24h": "298",
  "assets_seen_7d": "320",
  "new_assets_30d": "45"
}
```

---

## Log Discovery Endpoints

Find -> identify -> recommend -> onboard: scans the local network for
security-relevant log sources (firewalls, DNS filters, reverse proxies, etc.),
fingerprint-matches them against a community-extensible YAML library, ranks
them by security value, and hands back copy-paste onboarding instructions.
Discovery is read-only; only the `onboard/confirm` endpoint records a user
decision, and it never writes device or collector config itself (manual mode
only -- see `backend/src/services/logDiscovery/`).

### GET /api/log-discovery/scope

Preview the scan scope: the single-VLAN warning (SIEMBOX only sees its own
subnet by default -- computed from the host's network interfaces regardless of
what's below), and any manually-supplied CIDRs, validated and size-checked.

`cidrs` only ever reflects manually-supplied subnets -- it deliberately excludes
the auto-detected local interface CIDR, which in a Docker Compose deployment is
just the backend container's own bridge network, not the user's LAN. Every
CIDR that comes back here is exactly what an `active`/`full` scan will sweep
host-by-host (see `POST /scans` below); each must be a /22 or smaller (1024
addresses) to keep that sweep bounded -- larger or malformed entries land in
`rejected_cidrs` instead.

**Authentication:** Required

**Query Parameters:**
- `manual_cidrs` (optional) - Comma-separated CIDR list to preview, e.g. `192.168.20.0/24,10.10.4.0/24`

**Response (200):**
```json
{
  "cidrs": ["192.168.20.0/24"],
  "vlan_warning": "SIEMBOX only sees its own subnet by default. If your homelab spans more than one VLAN or subnet, add their CIDRs manually or this scan will miss them.",
  "rejected_cidrs": []
}
```

---

### GET /api/log-discovery/fingerprints

The loaded fingerprint library (read-only), so the UI can explain what each match means.

**Authentication:** Required

**Response (200):** Array of fingerprint entries (`id`, `name`, `category`, `security_value`, `confidence_floor`, `attack_data_sources`, `log_access`, `credentials`, ...).

---

### POST /api/log-discovery/scans

Trigger a scan. Runs asynchronously; returns immediately with the job id.

**Authentication:** Required

**Request Body:**
```json
{
  "mode": "full",
  "manual_cidrs": ["192.168.20.0/24"]
}
```
- `mode` - `passive` (ARP/mDNS/SSDP/DHCP-lease only), `active` (sweeps every approved manual CIDR for live hosts, then scoped port/HTTP/TLS probing of those plus whatever passive discovery found), or `full` (both passive and active)
- `manual_cidrs` (optional) - CIDRs to sweep on this scan (each /22 or smaller; see `GET /scope`)

**Response (202):**
```json
{
  "scan_id": 7,
  "cidrs": ["192.168.1.0/24", "192.168.20.0/24"],
  "vlan_warning": null,
  "rejected_cidrs": []
}
```

---

### GET /api/log-discovery/scans

Recent scan jobs, most recent first.

**Authentication:** Required

---

### GET /api/log-discovery/scans/:id

A single scan job's status.

**Authentication:** Required

**Response (200):**
```json
{
  "id": 7,
  "mode": "full",
  "cidrs": ["192.168.1.0/24"],
  "status": "completed",
  "started_at": "2025-12-17T10:00:00Z",
  "completed_at": "2025-12-17T10:00:42Z",
  "error_message": null,
  "results_summary": { "hosts_seen": 24, "hosts_matched": 9 }
}
```

---

### GET /api/log-discovery/sources

Ranked discovery results: sorted by `security_value`, deduped by host, grouped
into `top` and `advanced` (the long tail), each with a plain-language `reason`.

**Authentication:** Required

**Response (200):**
```json
{
  "top": [
    {
      "id": 3,
      "ip": "192.168.1.1",
      "mac": "aa:bb:cc:dd:ee:ff",
      "hostname": "opnsense.lan",
      "open_ports": [443, 22],
      "matched_fingerprint_id": "opnsense",
      "confidence": 80,
      "is_guess": false,
      "security_value": 10,
      "status": "candidate",
      "selected_log_access": null,
      "reason": "OPNsense can provide firewall logs, network traffic flow, dns queries."
    }
  ],
  "advanced": []
}
```

---

### POST /api/log-discovery/sources/:id/confirm

Confirm a candidate is what the matcher thinks it is.

**Authentication:** Required

---

### POST /api/log-discovery/sources/:id/ignore

Dismiss a source; it will not resurface in the ranked list.

**Authentication:** Required

---

### POST /api/log-discovery/sources/:id/onboard/preview

Render the copy-paste onboarding block for a confirmed source's matched
fingerprint. Read-only -- does not change the source's status.

**Authentication:** Required

**Request Body:**
```json
{ "method_index": 0 }
```
- `method_index` (optional, default `0`) - index into the fingerprint's `log_access` array (easiest-first order)

**Response (200):**
```json
{
  "instructions": "OPNsense at 192.168.1.1 — point it at SIEMBOX's syslog listener\n...",
  "log_access": { "method": "syslog_push", "target_port": 514, "format": "rfc5424", "auth": "none" }
}
```

---

### POST /api/log-discovery/sources/:id/onboard/confirm

Manual-mode onboarding, finalized: records the chosen `log_access` method and
marks the source `onboarded`. Requires an explicit `confirm: true` -- discovery
never onboards without user confirmation.

**Authentication:** Required

**Request Body:**
```json
{ "method_index": 0, "confirm": true }
```

**Response (200):**
```json
{
  "source": { "id": 3, "status": "onboarded", "selected_log_access": { "method": "syslog_push" } },
  "instructions": "OPNsense at 192.168.1.1 — point it at SIEMBOX's syslog listener\n..."
}
```

---

## Vulnerabilities Endpoints

### GET /api/vulnerabilities/summary

Get dashboard summary of vulnerabilities.

**Authentication:** Not required (read-only operation)

**Response (200):**
```json
{
  "critical_open": "5",
  "high_open": "12",
  "medium_open": "25",
  "low_open": "30",
  "info_open": "50",
  "affected_assets": "15",
  "unique_cves": "42"
}
```

---

### GET /api/vulnerabilities/templates

Get overview of available Nuclei vulnerability templates including categories and statistics.

**Authentication:** Not required (read-only operation)

**Response (200):**
```json
{
  "categories": [
    { "id": "cves", "name": "CVEs", "description": "Known CVE vulnerabilities from the National Vulnerability Database", "count": 5234, "path": "/root/nuclei-templates/cves" },
    { "id": "vulnerabilities", "name": "Vulnerabilities", "description": "General vulnerability detection templates", "count": 1420, "path": "/root/nuclei-templates/vulnerabilities" },
    { "id": "exposures", "name": "Exposures", "description": "Sensitive data exposure detection", "count": 892, "path": "/root/nuclei-templates/exposures" },
    { "id": "misconfiguration", "name": "Misconfigurations", "description": "Security misconfigurations", "count": 634, "path": "/root/nuclei-templates/misconfiguration" }
  ],
  "stats": {
    "totalTemplates": 9500,
    "categories": 15,
    "tags": 450,
    "severityCounts": {
      "critical": 1200,
      "high": 2800,
      "medium": 3500,
      "low": 1500,
      "info": 500
    }
  },
  "templatesDirectory": {
    "exists": true,
    "path": "/root/nuclei-templates"
  }
}
```

---

### GET /api/vulnerabilities/templates/categories

Get template categories.

**Authentication:** Not required (read-only operation)

**Response (200):**
```json
{
  "categories": [
    { "id": "cves", "name": "CVEs", "description": "Known CVE vulnerabilities", "count": 5234, "path": "/root/nuclei-templates/cves" },
    { "id": "vulnerabilities", "name": "Vulnerabilities", "description": "General vulnerability checks", "count": 1420, "path": "/root/nuclei-templates/vulnerabilities" }
  ]
}
```

---

### GET /api/vulnerabilities/templates/tags

Get available template tags with counts.

**Authentication:** Not required (read-only operation)

**Response (200):**
```json
{
  "tags": [
    { "name": "cve", "count": 5234 },
    { "name": "rce", "count": 890 },
    { "name": "sqli", "count": 456 },
    { "name": "xss", "count": 320 },
    { "name": "lfi", "count": 245 }
  ]
}
```

---

### GET /api/vulnerabilities/templates/search

Search templates by name, CVE, or description.

**Authentication:** Not required (read-only operation)

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `q` | string | required | Search query |
| `limit` | integer | 100 | Maximum results |

**Response (200):**
```json
{
  "templates": [
    {
      "id": "CVE-2021-44228",
      "name": "Apache Log4j RCE",
      "author": "pdteam",
      "severity": "critical",
      "description": "Apache Log4j2 JNDI RCE vulnerability",
      "tags": ["cve", "rce", "log4j", "critical"],
      "cveId": "CVE-2021-44228",
      "cvssScore": 10.0,
      "category": "cves"
    }
  ],
  "total": 1,
  "query": "log4j"
}
```

---

### GET /api/vulnerabilities/templates/category/:categoryId

Get templates by category.

**Authentication:** Not required (read-only operation)

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `categoryId` | string | Category ID (e.g., "cves", "vulnerabilities") |

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 100 | Maximum results |

**Response (200):**
```json
{
  "templates": [
    {
      "id": "CVE-2021-44228",
      "name": "Apache Log4j RCE",
      "severity": "critical",
      "tags": ["cve", "rce", "log4j"],
      "category": "cves"
    }
  ],
  "total": 5234,
  "category": "cves"
}
```

---

### GET /api/vulnerabilities/templates/tag/:tag

Get templates by tag.

**Authentication:** Not required (read-only operation)

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `tag` | string | Template tag (e.g., "rce", "sqli", "xss") |

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 100 | Maximum results |

**Response (200):**
```json
{
  "templates": [
    {
      "id": "CVE-2021-44228",
      "name": "Apache Log4j RCE",
      "severity": "critical",
      "tags": ["cve", "rce", "log4j"],
      "category": "cves"
    }
  ],
  "total": 890,
  "tag": "rce"
}
```

---

### POST /api/vulnerabilities/templates/refresh

Refresh the template cache.

**Authentication:** Required

**Response (200):**
```json
{
  "message": "Template cache refreshed",
  "stats": {
    "totalTemplates": 9500,
    "categories": 15,
    "tags": 450,
    "severityCounts": {
      "critical": 1200,
      "high": 2800,
      "medium": 3500,
      "low": 1500,
      "info": 500
    }
  }
}
```

---

### GET /api/vulnerabilities/scans

Get all vulnerability scans with filtering and pagination.

**Authentication:** Not required (read-only operation)

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 50 | Results per page |

**Response (200):**
```json
{
  "scans": [
    {
      "id": 1,
      "scan_type": "vulnerability",
      "target": "192.168.1.100",
      "status": "completed",
      "started_at": "2025-01-14T10:00:00Z",
      "completed_at": "2025-01-14T10:15:23Z",
      "duration_seconds": 923,
      "vulnerabilities_found": 15,
      "error_message": null,
      "created_at": "2025-01-14T10:00:00Z",
      "initiated_by_username": "admin"
    }
  ],
  "total": 42,
  "limit": 50,
  "offset": 0,
  "hasMore": false
}
```

---

### GET /api/vulnerabilities/scans/active

Get active vulnerability scans (queued or running).

**Authentication:** Not required (read-only operation)

**Response (200):**
```json
{
  "scans": [
    {
      "id": 5,
      "scan_type": "vulnerability",
      "target": "192.168.1.0/24",
      "status": "running",
      "started_at": "2025-01-14T11:30:00Z",
      "vulnerabilities_found": 0,
      "initiated_by_username": "analyst"
    }
  ],
  "total": 1
}
```

---

### GET /api/vulnerabilities/scans/:scanId

Get detailed information about a specific vulnerability scan.

**Authentication:** Not required (read-only operation)

**URL Parameters:**
- `scanId` - Scan ID

**Response (200):**
```json
{
  "id": 1,
  "scan_type": "vulnerability",
  "target": "192.168.1.100",
  "status": "completed",
  "started_at": "2025-01-14T10:00:00Z",
  "completed_at": "2025-01-14T10:15:23Z",
  "duration_seconds": 923,
  "vulnerabilities_found": 15,
  "error_message": null,
  "results_summary": {
    "vulnerabilitiesFound": 15,
    "severityCounts": {
      "critical": 2,
      "high": 5,
      "medium": 5,
      "low": 2,
      "info": 1
    },
    "completedAt": "2025-01-14T10:15:23Z"
  },
  "created_at": "2025-01-14T10:00:00Z"
}
```

**Errors:**
- `404` - Scan not found

---

### GET /api/vulnerabilities/scans/:scanId/status

Get vulnerability scan status (for polling).

**Authentication:** Not required (read-only operation)

**URL Parameters:**
- `scanId` - Scan ID

**Response (200):**
```json
{
  "id": 1,
  "status": "completed",
  "progress": 100,
  "vulnerabilities_found": 15,
  "started_at": "2025-01-14T10:00:00Z",
  "completed_at": "2025-01-14T10:15:23Z",
  "error_message": null
}
```

**Progress Values:**
- `0` - Queued
- `50` - Running
- `100` - Completed

**Errors:**
- `404` - Scan not found

---

### POST /api/vulnerabilities/scans

Trigger a new vulnerability scan using Nuclei.

**Authentication:** Required

**Request Body:**
```json
{
  "target": "192.168.1.100",
  "templates": "cves",
  "severity": ["critical", "high"],
  "description": "Weekly vulnerability scan",
  "timeout": 1800000,
  "rateLimit": 50
}
```

**Request Body Fields:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `target` | string | Yes | Target URL, IP address, or CIDR range |
| `templates` | string/array | No | Template selection: `all`, `cves`, `default`, or array of specific templates |
| `severity` | array | No | Filter by severity: `critical`, `high`, `medium`, `low`, `info` |
| `description` | string | No | Description for this scan |
| `timeout` | integer | No | Scan timeout in milliseconds (default: 30 minutes) |
| `rateLimit` | integer | No | Maximum requests per second |

**Template Selection Options:**
- `"all"` - Use all available templates
- `"cves"` - Use only CVE templates (default)
- `"default"` - Use default template set
- `["tag1", "tag2"]` - Use templates matching specific tags

**Response (202):**
```json
{
  "message": "Vulnerability scan initiated",
  "scanId": 15,
  "status": "queued",
  "target": "192.168.1.100",
  "templateSelection": {
    "cves": true,
    "severities": ["critical", "high"]
  }
}
```

**Errors:**
- `400` - Missing target

---

### POST /api/vulnerabilities/scans/:scanId/cancel

Cancel a running vulnerability scan.

**Authentication:** Required

**URL Parameters:**
- `scanId` - Scan ID

**Response (200):**
```json
{
  "message": "Scan cancelled successfully",
  "scanId": 15
}
```

**Errors:**
- `404` - Scan not found or not running

---

### GET /api/vulnerabilities

Get all vulnerabilities with filtering and pagination.

**Authentication:** Not required (read-only operation)

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `severity` | string | - | Filter by severity: `critical`, `high`, `medium`, `low`, `info` |
| `status` | string | - | Filter by status: `open`, `patched`, `false_positive`, `accepted` |
| `cve_id` | string | - | Filter by CVE ID |
| `search` | string | - | Search in vulnerability title and description |
| `limit` | integer | 50 | Results per page |
| `offset` | integer | 0 | Pagination offset |

**Response (200):**
```json
{
  "vulnerabilities": [
    {
      "id": 1,
      "cve_id": "CVE-2021-44228",
      "title": "Log4Shell RCE",
      "description": "Remote code execution vulnerability in Log4j",
      "severity": "critical",
      "cvss_score": 10.0,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
      "remediation": "Upgrade to Log4j 2.17.0 or later",
      "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
      "cwe_id": "CWE-917",
      "created_at": "2025-01-14T10:15:00Z"
    }
  ],
  "total": 42,
  "limit": 50,
  "offset": 0,
  "hasMore": false
}
```

---

### GET /api/vulnerabilities/:id

Get vulnerability by ID with affected assets.

**Authentication:** Not required (read-only operation)

**URL Parameters:**
- `id` - Vulnerability ID

**Response (200):**
```json
{
  "id": 1,
  "cve_id": "CVE-2021-44228",
  "title": "Log4Shell RCE",
  "description": "Remote code execution vulnerability in Log4j",
  "severity": "critical",
  "cvss_score": 10.0,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  "remediation": "Upgrade to Log4j 2.17.0 or later",
  "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
  "cwe_id": "CWE-917",
  "affected_assets": [
    {
      "asset_id": 5,
      "ip_address": "192.168.1.100",
      "hostname": "webserver01",
      "status": "open",
      "first_detected": "2025-01-14T10:15:00Z"
    }
  ],
  "created_at": "2025-01-14T10:15:00Z"
}
```

**Errors:**
- `404` - Vulnerability not found

---

### GET /api/vulnerabilities/asset/:assetId

Get vulnerabilities for a specific asset.

**Authentication:** Not required (read-only operation)

**URL Parameters:**
- `assetId` - Asset ID

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `status` | string | - | Filter by status: `open`, `patched`, `false_positive`, `accepted` |
| `severity` | string | - | Filter by severity |
| `limit` | integer | 50 | Results per page |
| `offset` | integer | 0 | Pagination offset |

**Response (200):**
```json
{
  "asset_id": 5,
  "vulnerabilities": [
    {
      "id": 1,
      "cve_id": "CVE-2021-44228",
      "title": "Log4Shell RCE",
      "severity": "critical",
      "cvss_score": 10.0,
      "status": "open",
      "evidence": "Template: CVE-2021-44228\nMatched at: http://192.168.1.100:8080/api",
      "first_detected": "2025-01-14T10:15:00Z",
      "last_detected": "2025-01-14T10:15:00Z",
      "remediation": "Upgrade to Log4j 2.17.0 or later"
    }
  ],
  "total": 5
}
```

**Errors:**
- `400` - Invalid asset ID

---

### PATCH /api/vulnerabilities/:assetId/:vulnId

Update vulnerability status for an asset.

**Authentication:** Required

**URL Parameters:**
- `assetId` - Asset ID
- `vulnId` - Vulnerability ID

**Request Body:**
```json
{
  "status": "patched",
  "notes": "Applied security patch on 2025-01-14"
}
```

**Valid Status Values:**
- `open` - Vulnerability is active and unaddressed
- `patched` - Vulnerability has been patched
- `false_positive` - Determined to be a false positive
- `accepted` - Risk accepted (with documentation)

**Response (200):**
```json
{
  "message": "Vulnerability status updated",
  "asset_id": 5,
  "vulnerability_id": 1,
  "status": "patched",
  "notes": "Applied security patch on 2025-01-14"
}
```

**Errors:**
- `400` - Invalid asset ID, vulnerability ID, or status
- `404` - Asset-vulnerability mapping not found

---

## Admin Dashboard Endpoints

All admin endpoints require authentication with the **admin** role.

### GET /api/admin/overview

Get system health status and aggregated metrics for the admin dashboard.

**Authentication:** Required (Admin)

**Response (200):**
```json
{
  "system": {
    "version": "0.1.0",
    "uptime": 86400,
    "nodeVersion": "v20.10.0",
    "environment": "production"
  },
  "health": {
    "database": "healthy",
    "syslog": "healthy",
    "shippers": {
      "online": 2,
      "offline": 0,
      "error": 0
    }
  },
  "metrics": {
    "totalUsers": 5,
    "activeUsers24h": 2,
    "alertsToday": 15,
    "criticalAlerts": 0,
    "totalAssets": 42,
    "openVulnerabilities": 3,
    "activeScans": 1,
    "dbSizeMB": 256,
    "recentErrors": 0
  }
}
```

**Health Status Values:**
- `healthy` - Component is working normally
- `warning` - Component has issues but is functional
- `unhealthy` - Component is not working

---

### GET /api/admin/users/search

Search users with recent activity metrics.

**Authentication:** Required (Admin)

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `q` | string | - | Search query (username or email) |
| `limit` | integer | 20 | Maximum results |

**Response (200):**
```json
{
  "users": [
    {
      "id": 1,
      "username": "admin",
      "email": "admin@example.com",
      "role": "admin",
      "enabled": true,
      "last_login": "2026-01-28T10:30:00Z",
      "created_at": "2025-01-01T00:00:00Z",
      "active_sessions": 1,
      "actions_24h": 45
    }
  ],
  "total": 1
}
```

---

### GET /api/admin/users/:id/activity

Get full activity log for a specific user.

**Authentication:** Required (Admin)

**URL Parameters:**
- `id` - User ID

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 50 | Maximum results |
| `offset` | integer | 0 | Pagination offset |

**Response (200):**
```json
{
  "user": {
    "id": 2,
    "username": "analyst1",
    "email": "analyst@example.com",
    "role": "analyst",
    "enabled": true,
    "last_login": "2026-01-28T09:00:00Z",
    "created_at": "2025-06-15T00:00:00Z"
  },
  "activity": [
    {
      "id": 1234,
      "timestamp": "2026-01-28T10:30:00Z",
      "action": "alert_update",
      "resource_type": "alert",
      "resource_id": 567,
      "ip_address": "192.168.1.100",
      "user_agent": "Mozilla/5.0...",
      "response_status": 200,
      "details": {}
    }
  ],
  "summary": {
    "totalActions": 1523,
    "actions24h": 45,
    "actions7d": 234,
    "errors": 2
  },
  "pagination": {
    "limit": 50,
    "offset": 0
  }
}
```

**Errors:**
- `400` - Invalid user ID
- `404` - User not found

---

### GET /api/admin/errors

Get recent application errors with human-readable messages.

**Authentication:** Required (Admin)

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `hours` | integer | 24 | Time window in hours |
| `limit` | integer | 50 | Maximum results |
| `offset` | integer | 0 | Pagination offset |

**Response (200):**
```json
{
  "errors": [
    {
      "id": 1,
      "timestamp": "2026-01-28T10:30:00Z",
      "error_type": "ECONNREFUSED",
      "message": "connect ECONNREFUSED 127.0.0.1:5432",
      "human_message": "Database connection refused",
      "category": "database",
      "severity": "error",
      "user_id": null,
      "endpoint": "/api/logs",
      "context": {
        "method": "GET"
      },
      "resolution": "Check PostgreSQL is running and accepting connections"
    }
  ],
  "summary": {
    "total": 5,
    "byCategory": {
      "database": 2,
      "auth": 3
    },
    "bySeverity": {
      "error": 4,
      "warning": 1
    }
  }
}
```

**Error Categories:**
- `database` - Database connection or query errors
- `auth` - Authentication and authorization errors
- `network` - Network connectivity issues
- `scanner` - Vulnerability scanner errors
- `parser` - Log parsing errors
- `application` - General application errors

**Severity Levels:**
- `critical` - System-breaking issues
- `error` - Errors that affect functionality
- `warning` - Issues that may need attention
- `info` - Informational messages

---

### GET /api/admin/jobs

Unified view of background work. Returns two lists:

- `jobs` — one-off jobs from every job table (vulnerability, asset-discovery,
  container-image and log-discovery scans), merged and paged as one list.
- `recurring` — the periodic in-process services (retention cleanup, asset
  auto-discovery, the scheduled-scan dispatcher, ingestion health, threat-feed
  refresh, YARA-Forge refresh). These own no rows, so their state is tracked in
  memory and **resets on backend restart** — `"status": "idle"` with
  `"lastRunAt": null` right after a restart is expected, not a fault.

**Authentication:** Required (Admin)

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `status` | string | - | Filter by status: `queued`, `running`, `completed`, `failed` |
| `limit` | integer | 50 | Maximum results |
| `offset` | integer | 0 | Pagination offset |

**Response (200):**
```json
{
  "jobs": [
    {
      "id": 15,
      "type": "vulnerability",
      "target": "192.168.1.0/24",
      "status": "running",
      "started_at": "2026-01-28T10:00:00Z",
      "completed_at": null,
      "duration_seconds": null,
      "assets_discovered": 0,
      "vulnerabilities_found": 3,
      "error_message": null,
      "initiated_by": 1,
      "initiated_by_username": "admin",
      "created_at": "2026-01-28T10:00:00Z",
      "source": "vulnerability_scans",
      "job_key": "vulnerability_scans:15",
      "results_summary": {
        "progress": {
          "percentComplete": 45
        }
      }
    }
  ],
  "recurring": [
    {
      "key": "retention-cleanup",
      "name": "Retention cleanup",
      "description": "Deletes raw logs, parsed logs and closed alerts past their retention window.",
      "intervalMs": 86400000,
      "status": "ok",
      "lastRunAt": "2026-01-28T09:00:00Z",
      "lastSuccessAt": "2026-01-28T09:00:12Z",
      "lastDurationMs": 12400,
      "lastResult": "1204 raw, 980 parsed, 0 alert row(s) deleted",
      "lastError": null,
      "nextRunAt": "2026-01-29T09:00:00Z",
      "runs": 3,
      "failures": 0
    }
  ],
  "counts": {
    "queued": 0,
    "running": 1,
    "completed": 42,
    "failed": 2
  },
  "total": 45,
  "pagination": {
    "limit": 50,
    "offset": 0
  }
}
```

`id` is only unique within a source table — use `job_key`
(`"<source>:<id>"`) as the stable identifier across the merged list.

**Job Types:**
- `asset_discovery` - Nmap network discovery scans
- `vulnerability` - Nuclei vulnerability scans
- `container` - Trivy container image scans
- `log-discovery` - Log source discovery scans

**Job Statuses:**
- `queued` - Waiting to start
- `running` - Currently executing
- `completed` - Finished successfully
- `failed` - Finished with errors
- `cancelled` - Cancelled by user

**Recurring Job Statuses:**
- `idle` - Registered, not yet run in this process
- `running` - Cycle in progress
- `ok` - Last cycle succeeded
- `failed` - Last cycle threw (see `lastError`)
- `skipped` - Ran but deliberately did nothing (switched off in settings, or nothing due)
- `disabled` - Not scheduled in this process at all

---

## Integration Examples

### JavaScript/TypeScript (Axios)

```typescript
import axios from 'axios';

const api = axios.create({
  baseURL: 'http://siembox:8421/api',
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

BASE_URL = "http://siembox:8421/api"

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
TOKEN=$(curl -s -X POST http://siembox:8421/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}' \
  | jq -r '.token')

# Get alerts
curl -H "Authorization: Bearer $TOKEN" \
  "http://siembox:8421/api/alerts?severity=high&status=new"
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

**Last Updated:** 2026-07-30
