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
  - [Notifications](#notifications-endpoints)
  - [Log Shippers](#log-shippers-endpoints)
  - [Assets](#assets-endpoints)
  - [Log Discovery](#log-discovery-endpoints)
  - [Vulnerabilities](#vulnerabilities-endpoints)
  - [Exposure Monitoring (Digital Risk)](#exposure-monitoring-digital-risk)
  - [Admin Dashboard](#admin-dashboard-endpoints)

---

## Authentication

Most API endpoints require authentication using JWT (JSON Web Token). After logging in, include the token in the `Authorization` header:

```http
Authorization: Bearer YOUR_JWT_TOKEN
```

**Session Duration:** Tokens are valid for 24 hours from login.

The only routes that take no login are `POST /api/auth/login`, the `/health` checks, the shipper-facing `/api/shippers` endpoints (authenticated by the shipper's API key or HTTP push key, see [Log Shippers](#log-shippers-endpoints)), and the EDR agent endpoints (enrollment token or per-agent key).

### Roles

Every signed-in user has one of four roles, each including the ones before it: `viewer` < `analyst` < `operator` < `admin` (see [User Management](../guides/USER-MANAGEMENT.md#user-roles)). A call a role may not make answers `403`. Viewers are read-only: the only non-GET calls open to them act on their own session or account, or compute an answer and store nothing (logout, `/api/auth/me/*`, `POST /api/parsers/:id/test`, `POST /api/ai/explain`, `POST /api/log-discovery/sources/:id/onboard/preview`, `POST /api/exposure/password-check`).

Detection content, alert triage and the AI Analyst:

| Route | Admin | Operator | Analyst | Viewer |
|---|---|---|---|---|
| `POST /api/parsers`, `PUT` / `DELETE /api/parsers/:id`, `POST /api/parsers/import` | yes | yes | yes | no |
| `POST /api/parsers/validate`, `POST /api/parsers/test` (they run a pattern the caller supplies) | yes | yes | yes | no |
| `POST /api/parsers/catalog/install`, `/catalog/install-all`, `/catalog/refresh` | yes | yes | yes | no |
| `POST /api/rules`, `PUT` / `DELETE /api/rules/:id` | yes | yes | yes | no |
| `POST /api/rules/catalog/install`, `/catalog/install-all`, `/catalog/refresh` | yes | yes | yes | no |
| `PUT /api/alerts/:id`, `POST /api/alerts/:id/triage/rerun` | yes | yes | yes | no |
| `DELETE /api/alerts/:id` | yes | no | no | no |
| `POST /api/ai/chat`, `PATCH` / `DELETE /api/ai/chat/sessions/:id` | yes | yes | yes | no |
| `POST /api/parsers/ai/generate`, `POST /api/rules/ai/generate`, `POST /api/rules/import/sigma`, `/import/sigma/preview`, `POST /api/packs/:id/install` | yes | no | no | no |

The reads under these routes stay open to every role, but only analyst and up can force a catalog refetch with `GET /api/parsers/catalog?refresh=true` or `GET /api/rules/catalog?refresh=true`: a viewer's `refresh` flag is ignored and the cached listing comes back. `GET /api/ai/chat/health` answers only `{ "configured": true }` or `false`; the AI Analyst's provider, model and base URL are in the admin-only `GET /api/settings/ai-chat`. A refusal on the parser, rule, alert and AI Analyst writes above (all but the triage re-run and the last row) is recorded in `audit_logs` like a refused scan write (below). User management, settings and notification changes, Endpoints (EDR) and the admin dashboard are admin-only; shipper management has its own table under [Log Shippers](#log-shippers-endpoints). Every route and the roles it allows are listed in `backend/src/routes/routeInventory.test.ts`, which the test suite checks against the running API.

(Earlier versions let any logged-in role, viewers included, make every call in this table except the triage re-run and the last row, deleting alerts included. A script that used a viewer's token for these writes needs an analyst's, or an admin's to delete alerts.)

### Roles for scan and asset writes

Reads under `/api/assets`, `/api/vulnerabilities`, `/api/scheduled-scans`, `/api/log-discovery` and `/api/containers` are open to every logged-in role. Each write requires the roles that can open the UI page that makes the call; any other role gets `403`.

| Route | Admin | Operator | Analyst | Viewer |
|---|---|---|---|---|
| `POST /api/assets`, `PUT /api/assets/:id`, `DELETE /api/assets/:id` | yes | yes | yes | no |
| `POST /api/assets/scan`, `POST /api/assets/discover` | yes | yes | yes | no |
| `POST /api/vulnerabilities/templates/refresh` | yes | yes | yes | no |
| `POST /api/vulnerabilities/templates/download` | yes | yes | no | no |
| `POST /api/vulnerabilities/scans`, `POST /api/vulnerabilities/scans/:scanId/cancel` | yes | yes | no | no |
| `PATCH /api/vulnerabilities/:assetId/:vulnId` | yes | yes | no | no |
| `POST /api/scheduled-scans`, `PUT` / `DELETE /api/scheduled-scans/:id`, `POST /api/scheduled-scans/:id/run` | yes | yes | no | no |
| `POST /api/log-discovery/scans`, `POST /api/log-discovery/scans/:id/cancel` | yes | yes | no | no |
| `POST /api/log-discovery/sources/:id/confirm`, `/ignore`, `/onboard/confirm` | yes | yes | no | no |
| `PUT /api/log-discovery/scope/cidrs`, `POST /api/log-discovery/sources/manual`, `DELETE /api/log-discovery/sources/:id`, the `/sources/:id/poller` writes | yes | no | no | no |
| `POST /api/containers/scan` | yes | yes | no | no |

A refused scan or asset write is also recorded in `audit_logs` (`action` `access.denied`, with the required and actual role); the admin-only log-discovery routes and the log-discovery source actions answer `403` without that audit entry. The entry's `ip_address` is the client address (see [Rate Limiting](#rate-limiting)): the browser's real address through the web UI, and the caller's TCP address on a direct call to port 8421, whatever `X-Forwarded-For` it sends. Only a proxy listed in `TRUSTED_PROXIES` can name another client; when what it forwards is not an IP address, the TCP peer address is stored instead, so the entry is always written, and when it connected over TCP its own address is kept in `details.peerAddress`. Shipper management has its own table under [Log Shippers](#log-shippers-endpoints). (Earlier versions let any logged-in role, viewers included, make these calls.)

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
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error |

A request body that isn't valid JSON is rejected with `400` (`"Malformed request
body: expected valid JSON"`), and an oversized one with `413`, before any route
runs. These rejections are never logged with the body's contents.

---

## Rate Limiting

Limits count per **client address** (IPv6 sign-in limits: per /64). Requests
through the web UI's nginx (port 8420) carry the browser's real address. A
direct caller on port 8421 is its TCP address: `X-Forwarded-For` and
`X-Real-IP` from it are ignored unless it is listed in `TRUSTED_PROXIES` (see
DEPLOYMENT.md, "Client addresses and reverse proxies"). Counters are kept in
memory and reset when the backend restarts.

| Limit | Default (per 15 minutes) | Applies to | Headers |
|-------|--------------------------|------------|---------|
| General | 1000 requests (`API_RATE_LIMIT_MAX`) | Every `/api` request, except the two exemptions below | `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` |
| Sign-in (interim) | 10 failed sign-ins per account, 100 per address across all accounts | `POST /api/auth/login`, per username (as typed, ignoring case and surrounding spaces) and address. Past 100 failures from an address, only accounts that already failed from it in their own current 15-minute window are refused, so people sharing an address don't lock each other out. Successful sign-ins, the "MFA code required" step and `5xx` answers are not counted | `RateLimit-*` (the per-account limit) |
| EDR agents | 30000 requests (`EDR_AGENT_RATE_MAX`) | Agent-key routes, which skip the general limit when they carry `X-Agent-ID` and use the route's own method: `POST` heartbeat, `GET` (or `HEAD`) config and YARA, `POST` inventory, events and vulnerabilities. Any other method, and enrollment, is under the general limit. | `RateLimit-*` |
| HTTP log push | 6000 requests (`SHIPPER_LOG_PUSH_MAX`) | `POST /api/shippers/logs`, which skips the general limit when it carries `X-Shipper-ID` (other methods on that path don't) | `RateLimit-*` |
| Password check | 30 requests | `POST /api/exposure/password-check` | `RateLimit-*` |

A limited request gets `429` with a `Retry-After` header (seconds) and a JSON
body in the usual error envelope:

```json
{
  "status": "error",
  "statusCode": 429,
  "code": "RATE_LIMITED",
  "message": "Too many requests from your address. Try again in 12 minutes.",
  "retryAfter": 702
}
```

`retryAfter` matches the `Retry-After` header. Request bodies sent to
`/api/auth/*` are limited to 16 kB (a larger one gets `413`); other routes
accept up to 10 MB.

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
- `413` - Request body larger than 16 kB
- `429` - Too many failed sign-ins: 10 per 15 minutes for this username from this address ("Too many failed sign-in attempts for this account from your address"), or, past 100 failures from this address across all usernames, this username already failed from it in its own 15-minute window ("Too many failed sign-in attempts from your address"; `retryAfter` is when that window or the address's ends, whichever is first, unless the username also reached its own 10). An IPv6 client's /64 counts as one address. Successful sign-ins and `5xx` answers don't count. JSON body with `code: "RATE_LIMITED"`, `message` and `retryAfter`, plus a `Retry-After` header; see [Rate Limiting](#rate-limiting)

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

**Authentication:** Required (Admin role; other roles get `403 Access denied. Required role: admin`)

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

**Authentication:** Required (admin, operator or analyst; viewers get `403`)

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

**Authentication:** Required (admin, operator or analyst; viewers get `403`)

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

**Authentication:** Required (admin, operator or analyst; viewers get `403`)

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

**Authentication:** Required (any role: it runs a saved parser, and stores nothing)

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

**Authentication:** Required (admin, operator or analyst; viewers get `403`)

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

**Use Case:** Frontend parser builder to validate configurations before saving. The pattern is compiled and run on the API's event loop with no ReDoS check, so like `POST /api/parsers/validate` this needs analyst or higher; anyone can test a saved parser with `POST /api/parsers/:id/test`.

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

**Authentication:** Required (admin, operator or analyst; viewers get `403`)

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

**Authentication:** Required (admin, operator or analyst; viewers get `403`)

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

**Authentication:** Required (admin, operator or analyst; viewers get `403`)

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

Browsing the catalogs and exporting are open to every role. Installing,
updating, refreshing, importing and validating need analyst or higher (viewers
get `403`, and their `?refresh=true` on a catalog listing is ignored); see
[Roles](#roles).

### Catalog

| Method & Path | Purpose |
|---|---|
| `GET /api/parsers/catalog` | Browse the parser catalog, each entry annotated with `installed` and `update_available`. `?refresh=true` bypasses the ~5-minute cache for analyst and up; a viewer gets the cached listing. Returns `{ source, parsers }`. |
| `GET /api/parsers/catalog/source` | The configured catalog source (repo / ref) for display. |
| `POST /api/parsers/catalog/install` | Install or update a catalog parser by `name` (validate → self-test → upsert). Body: `{ "name": "nginx", "force": false }`. `201` created / `200` updated. |
| `POST /api/parsers/catalog/install-all` | Install or update every catalog parser. Returns `{ total, installed, updated, failed }`. |
| `POST /api/parsers/catalog/refresh` | Force a catalog cache refresh. Returns `{ refreshed, count }`. |
| `GET /api/rules/catalog` | Browse the detection catalog (same annotations, same `?refresh=true`). Returns `{ source, rules }`. |
| `GET /api/rules/catalog/source` | The configured catalog source. |
| `POST /api/rules/catalog/install` | Install or update a catalog detection by `name`. |
| `POST /api/rules/catalog/install-all` | Install or update every catalog detection. |
| `POST /api/rules/catalog/refresh` | Force a catalog cache refresh. |

Catalog source defaults to `cladkins/siembox-parsers` and is overridable via the
`SIEMBOX_CATALOG_REPO` / `SIEMBOX_CATALOG_REF` env vars (`GITHUB_TOKEN` raises the
GitHub API rate limit). Each fetch of a catalog lists the repository through the
GitHub API, which allows 60 unauthenticated requests an hour per IP; requests
that arrive while a fetch is in progress wait for it rather than starting
another.

### Export / Import (portable parsers)

| Method & Path | Purpose |
|---|---|
| `GET /api/parsers/:id/export` | Export an installed parser as a portable `siembox.parser/v1` JSON document. |
| `POST /api/parsers/validate` | Validate a portable parser and run its self-tests without saving. Body: `{ "parser": { … }, "strict": false }`. |
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

**Authentication:** Required (admin, operator or analyst; viewers get `403`)

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

Delete alert. This destroys evidence, so it is admin-only; triage closes an alert as `closed` or `false_positive` instead.

**Authentication:** Required (admin; other roles get `403`)

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

**User Roles** (each includes the ones before it; see [Roles](#roles) and the
[permission table](../guides/USER-MANAGEMENT.md#permission-table)):
- `viewer` - Read-only
- `analyst` - Alert triage, the AI Analyst, parsers and detection rules (create, edit, delete, catalog installs)
- `operator` - Scans, Log Discovery and log shipper management
- `admin` - Full access: users, settings, Endpoints (EDR), deleting alerts

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

## Notifications Endpoints

Notification channels (where alerts are delivered: Slack, Email, NTFY) and the per-event preferences (which events fire, and at what minimum severity). All routes require authentication. Anything that changes delivery or sends a message is **admin-only**, because a lower role able to disable channels, raise the severity floor, or redirect a channel could silence alerting or capture alert contents.

| Method | Path | Access | Notes |
|---|---|---|---|
| GET | `/api/notifications/channels` | Any authenticated user | Only admins get each channel's `config` (Slack `webhook_url`, NTFY `token`, SMTP credentials). Other roles get the same list with `config: {}`. |
| POST | `/api/notifications/channels` | Admin | Body: `{ name, channel_type: "slack"\|"email"\|"ntfy", enabled?, config }` |
| PUT | `/api/notifications/channels/:id` | Admin | Partial update with the same fields |
| DELETE | `/api/notifications/channels/:id` | Admin | |
| POST | `/api/notifications/channels/:id/test` | Admin | Sends a test message through that channel |
| POST | `/api/notifications/test-alert` | Admin | Sends a sample new-alert message to every enabled channel and reports the result for each |
| GET | `/api/notifications/settings` | Any authenticated user | The non-secret preference flags (`notify_alerts_enabled`, `notify_alerts_min_severity`, `notify_vuln_*`, `notify_ingestion_*`) |
| PUT | `/api/notifications/settings` | Admin | Updates any of those preference keys |

Non-admin requests to admin-only routes get `403 Access denied. Required role: admin`.

---

## Log Shippers Endpoints

Two kinds of route live under `/api/shippers`:

- **Management routes** (the UI and API users) require a login (`Authorization: Bearer <token>`); without one the API answers `401`, and a role that may not use a route gets `403`. (Earlier versions answered these without a login; scripts that relied on that must now send a token.)
- **Shipper-facing routes** (`/register`, `/containers`, `/config/:api_key`, `/scan-jobs/:api_key`, `/scan-results`, `/discovery-results`, `/logs`) take no login. The shipper authenticates with its syslog `api_key` (or, for `/logs`, the HTTP push key), so these work exactly as before.

| Method | Path | Access |
|---|---|---|
| GET | `/api/shippers`, `/api/shippers/:id`, `/:id/sources`, `/:id/volumes`, `/:id/activity`, `/unknown-sources`, `/direct-syslog-sources` | Any role |
| POST / PUT / DELETE | `/api/shippers`, `/api/shippers/:id` | Admin or operator |
| POST / PUT / DELETE | `/:id/sources`, `/sources/:sourceId`, `/:id/volumes`, `/volumes/:volumeId` | Admin or operator |
| POST | `/:id/regenerate-key` | Admin |
| POST / DELETE | `/:id/http-push-key` | Admin |

**`api_key` redaction:** a shipper's syslog `api_key` is returned only to roles that can manage shippers (admin and operator), in every response that carries a shipper row (list, detail, create, update). Analysts and viewers get the same rows without the `api_key` field. The HTTP push key's hash is never returned to anyone (`http_push_enabled` says whether one is set).

### GET /api/shippers

Get all log shippers.

**Authentication:** Required (any role). Includes `api_key` for admin and operator only.

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

### GET /api/shippers/direct-syslog-sources

Hosts sending syslog directly to the listener (514/udp+tcp) **without a log shipper** — e.g. a firewall, NAS, switch, or UniFi device using its own remote-syslog setting. Shown in the "Direct Syslog Sources" section of the Shippers page, separate from installed shippers.

Rows counted: `raw_logs` with `shipper_id IS NULL AND discovery_source_id IS NULL`, grouped by `source_ip` over the **last 24 hours**. (Lines carrying an unregistered shipper id are the separate [unknown-sources](#post-apishipperslogs) list; API-polled sources have `discovery_source_id` set and appear in their own section.)

Served from a 30 s single-flight cache with the same statement-timeout / stale-on-busy behaviour as the unknown-sources list, so a page load can neither stack scans nor outrun the request.

**Authentication:** Required (any role; it is effectively a list of devices on the network).

**Response (200):**
```json
[
  {
    "source_ip": "203.0.113.10",
    "log_count": 14823,
    "first_seen": "2026-10-05T10:00:00Z",
    "last_seen": "2026-10-05T11:59:00Z",
    "hostnames": ["fw-edge"],
    "hostname_count": 1,
    "app_names": ["kernel", "pf"],
    "app_name_count": 2
  }
]
```

`hostnames` / `app_names` are capped at 25 entries each; `hostname_count` / `app_name_count` give the true totals. At most 500 senders are returned (most recently seen first).

**Errors:**
- `503` - The database was too busy to answer in time (try again shortly)

---

### GET /api/shippers/:id

Get single shipper with full configuration.

**Authentication:** Required (any role). Includes `api_key` for admin and operator only.

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

**Authentication:** Required (admin or operator)

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

The response carries the new shipper's `api_key`; admins and operators can read it again later from `GET /api/shippers/:id`.

**Errors:**
- `400` - Missing shipper name
- `403` - Analyst or viewer role

---

### PUT /api/shippers/:id

Update shipper details.

**Authentication:** Required (admin or operator)

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

**Note:** Only `name`, `description` and `hostname` can be changed; any other field in the body is ignored. Use the regenerate endpoint for `api_key` and the http-push-key endpoints for the push key; status, version and last-seen come from the shipper itself. The free-form `config` is not editable here: the shipper applies it (`siem_host`, `siem_port`, `sources`) when it registers, so changing it would redirect the shipper's logs. Manage sources with the source endpoints below.

**Errors:**
- `400` - The body contains none of the editable fields
- `403` - Analyst or viewer role
- `404` - Shipper not found

---

### DELETE /api/shippers/:id

Delete log shipper.

**Authentication:** Required (admin or operator)

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

**Authentication:** Required (Admin). An operator who needs a new key can delete the shipper and create it again (its sources and volumes then have to be added again). Admins and operators can read the current key at any time from `GET /api/shippers/:id`.

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

**Authentication:** Required (any role)

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

**Authentication:** Required (admin or operator)

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

**Authentication:** Required (admin or operator)

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

**Note:** Editable fields are `source_type`, `enabled`, `file_path`, `container_name`, `journal_unit`, `tag` and `facility`; anything else in the body (such as `id` or `shipper_id`) is ignored.

**Errors:**
- `400` - The body contains none of the editable fields
- `403` - Analyst or viewer role
- `404` - Source not found

---

### DELETE /api/shippers/sources/:sourceId

Delete log source.

**Authentication:** Required (admin or operator)

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

**Authentication:** Required (any role)

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

**Authentication:** Required (admin or operator)

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

**Authentication:** Required (admin or operator)

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

**Authentication:** Required (any role)

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

**Authentication:** Required (Admin; see the operator alternative above)

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
- `403` - Insufficient permissions (requires admin role)
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

**Example (curl):**
```bash
# The push key is shown once by POST /api/shippers/:id/http-push-key;
# X-Shipper-ID is that shipper's numeric id.
export SIEMBOX_PUSH_KEY=...   # the 64-hex-char key
export SIEMBOX_URL=https://siembox.example.com

# Single entry
curl -sS -X POST "$SIEMBOX_URL/api/shippers/logs" \
  -H "Authorization: Bearer $SIEMBOX_PUSH_KEY" \
  -H "X-Shipper-ID: 7" \
  -H "Content-Type: application/json" \
  -d '{"message":"Failed password for root from 203.0.113.5 port 51515 ssh2","hostname":"nas01","app_name":"sshd"}'

# Batch (up to 1000 entries per request)
curl -sS -X POST "$SIEMBOX_URL/api/shippers/logs" \
  -H "Authorization: Bearer $SIEMBOX_PUSH_KEY" \
  -H "X-Shipper-ID: 7" \
  -H "Content-Type: application/json" \
  -d '{"logs":[{"message":"line one"},{"message":"line two"}]}'
```

Only `message` is required. It must be the **bare extracted message** — the same thing `syslogParser.ts` produces after stripping `<PRI>TIMESTAMP HOSTNAME TAG:` — not a full syslog-framed line; parsers match only the extracted message (see CLAUDE.md). All other fields are optional; invalid `facility` (0–23) or `severity` (0–7) values are stored as `null` rather than rejecting the entry. `event_id`, if supplied, dedupes retried/at-least-once deliveries — a repeated `event_id` from the same shipper is counted, not re-ingested. Batches are capped at 1000 entries per request.

**Response (202):**
```json
{ "accepted": 1, "duplicate": 0, "rejected": 0, "errors": [] }
```

A malformed entry in a batch doesn't fail the whole request — it's counted in `rejected`, with up to 20 `{index, error}` entries returned in `errors`.

If the database can't be reached (including a connection pool that stays exhausted past the backend's 30-second retry window), the entry that hit the problem is rejected with `database unavailable` and **the rest of the batch is rejected with the same error without being attempted**, so the request returns in roughly that window rather than hanging. Entries stored before the outage are kept and counted in `accepted`. Resend the rejected entries later; include `event_id` so a retry can't create duplicates.

**Errors:**
- `400` - Body isn't a single log object or `{ "logs": [...] }`, empty `logs` array, or batch exceeds 1000 entries
- `401` - Missing/invalid `X-Shipper-ID` or Bearer key, or HTTP push not provisioned for this shipper
- `429` - Too many log-push requests from this address (see rate limit below; JSON body with `code: "RATE_LIMITED"` and `retryAfter`, plus a `Retry-After` header)

**Rate limit:** this endpoint has its own per-address limiter (default **6000 requests / 15 min**, override with the `SHIPPER_LOG_PUSH_MAX` env var) that runs *before* authentication, so unauthenticated or invalid-key traffic is throttled rather than hammering the auth lookup unbounded. It's well above the generic UI limit — batch your pushes (up to 1000 entries each) to stay comfortably under it. The address is the pushing host's TCP address; an `X-Forwarded-For` header it sends is ignored (see [Rate Limiting](#rate-limiting)).

---

### GET /api/shippers/scan-jobs/:api_key

**PUBLIC ENDPOINT** (shipper-authenticated by the syslog `api_key` in the path, like `/config/:api_key`). A shipper polls this to pick up scans dispatched to it. The GET itself **claims** the shipper's queued jobs atomically (`queued → running`, stamping `claimed_at`), so each job is handed out exactly once even under concurrent polls. Lets a scan run from a shipper out on the LAN, which the backend's own nmap/nuclei/discovery can't reach from inside the Docker network (see migrations `032`/`033`). Returns asset (nmap), vulnerability (nuclei), and log-discovery jobs, each tagged with `kind`.

**Response (200):**
```json
{
  "jobs": [
    { "scanId": 42, "kind": "nmap",      "nmapArgs": ["-sV", "-p", "1-1000"], "targets": ["192.168.1.0/24"] },
    { "scanId": 43, "kind": "nuclei",    "nucleiArgs": ["-jsonl", "-severity", "high,critical"], "targets": ["http://192.168.1.10"], "timeoutSeconds": 1800 },
    { "scanId": 7,  "kind": "discovery", "mode": "full", "cidrs": ["192.168.1.0/24"],
      "probePlan": { "ports": [443, 8443, ...], "httpPaths": ["/", ...], "mdnsServices": ["_home-assistant._tcp", ...] } }
  ]
}
```

The args/targets (or, for discovery, the probe plan) are **built and validated by the server** — the shipper chooses neither. It runs exactly `nmap <nmapArgs> <targets> -oX -` for a `kind: "nmap"` job, `nuclei <nucleiArgs> -target <t>…` for `kind: "nuclei"`, or its bundled Node discovery agent (fed the job on stdin) for `kind: "discovery"`. `nucleiArgs` carry only portable selection (tags/severity/IDs); the discovery `probePlan` carries the ports/HTTP paths/mDNS services extracted from the fingerprint library (so the shipper needs no fingerprint files). `jobs` is `[]` when nothing is queued. The `scanId` namespaces differ per `kind` (discovery ids come from `discovery_scans`), which is why discovery results post to a separate endpoint below.

**Errors:**
- `404` - Invalid API key

---

### POST /api/shippers/scan-results

**PUBLIC ENDPOINT** (shipper-authenticated by the syslog `api_key` in the body). A shipper posts back the outcome of a dispatched scan. The backend routes by the scan's own type (not by what the shipper claims): an **asset** scan sends raw `nmap -oX -` XML in `xml`; a **vulnerability** scan sends raw `nuclei -jsonl` output in `jsonl`. Either is parsed and ingested through the **same code path** as a backend-run scan (identical assets/services for nmap, vulnerabilities for nuclei). On failure it sends `error`.

**Request Body — asset (nmap) success:**
```json
{ "api_key": "<shipper api key>", "scan_id": 42, "xml": "<?xml version=\"1.0\"?>..." }
```

**Request Body — vulnerability (nuclei) success:**
```json
{ "api_key": "<shipper api key>", "scan_id": 43, "jsonl": "{\"template-id\":\"CVE-...\",\"info\":{...}}\n{...}" }
```

**Request Body — failure (either kind):**
```json
{ "api_key": "<shipper api key>", "scan_id": 42, "error": "nmap exited with code 1 on the shipper" }
```

**Ownership:** the `api_key` must own the scan (its `assigned_shipper_id`), so a shipper can't write results for another shipper's — or a backend-run — scan.

**Response (200):** `{ "status": "completed" }` or `{ "status": "failed" }`

**Errors:**
- `400` - Missing `api_key`, non-positive `scan_id`, or no output (`xml` for an asset scan / `jsonl` for a vuln scan) and no `error`
- `404` - Invalid API key, or the scan isn't assigned to this shipper
- `422` - the output could not be parsed/ingested (the scan is marked `failed`)

---

### POST /api/shippers/discovery-results

**PUBLIC ENDPOINT** (shipper-authenticated by the syslog `api_key` in the body). A shipper posts back the outcome of a dispatched **log-discovery** scan. Separate from `/scan-results` because discovery scans live in their own table (`discovery_scans`) with their own id sequence. On success the body carries `signals` — the observed per-host data the shipper's probe agent produced; the backend fingerprint-matches and upserts them into `discovery_sources` exactly like an in-process scan. On failure it sends `error`. Ownership is checked against `discovery_scans.assigned_shipper_id`.

**Request Body — success:**
```json
{ "api_key": "<shipper api key>", "scan_id": 7,
  "signals": [ { "ip": "192.168.1.10", "mac": "...", "hostname": "...",
                 "open_ports": [443], "http_responses": [...], "tls_subjects": [...],
                 "banners": [], "mdns_services": [...], "ssdp_services": [...],
                 "discovery_methods": ["arp","active_probe"] } ] }
```

**Request Body — failure:**
```json
{ "api_key": "<shipper api key>", "scan_id": 7, "error": "node runtime not available on the shipper" }
```

**Response (200):** `{ "status": "completed" }` or `{ "status": "failed" }`

**Errors:**
- `400` - Missing `api_key`, non-positive `scan_id`, or neither `signals` (array) nor `error`
- `404` - Invalid API key, or the discovery scan isn't assigned to this shipper
- `422` - signals could not be ingested (the scan is marked `failed`)

---

## Assets Endpoints

Every `/api/assets` route requires a login (`Authorization: Bearer <token>`); without one the API answers `401`. (Earlier versions answered the read routes without a login; scripts that relied on that must now send a token.)

| Method | Path | Access |
|---|---|---|
| GET | `/api/assets`, `/api/assets/statistics`, `/api/assets/:id`, `/api/assets/:id/related`, `/api/assets/:id/services` | Any role |
| GET | `/api/assets/scans`, `/api/assets/scans/active`, `/api/assets/scans/statistics`, `/api/assets/scans/:scanId` | Any role |
| POST / PUT / DELETE | `/api/assets`, `/api/assets/:id` | Admin, analyst or operator |
| POST | `/api/assets/discover` | Admin, analyst or operator |
| POST | `/api/assets/scan` | Admin, analyst or operator |

The writes take the roles that can open the Asset Inventory page; a viewer gets `403` (see [Roles for scan and asset writes](#roles-for-scan-and-asset-writes)).

### GET /api/assets/scans

Get all vulnerability scans with filtering and pagination.

**Authentication:** Required (any role)

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

**Authentication:** Required (any role)

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

**Authentication:** Required (any role)

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

**Authentication:** Required (any role)

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

For sources whose fingerprint declares an `api_pull` log-access method
(Authentik, Home Assistant, Pi-hole, AdGuard Home today), the poller endpoints
below are the alternative to the manual copy-paste recipe: save a token and
SIEMBOX pulls that source's events on a schedule instead. See
`backend/src/services/logDiscovery/apiPoll/`.

**Access:** every route requires a login. Reads (and the read-only `onboard/preview`) are open to any role. Starting or cancelling a scan and the source actions `confirm`, `ignore` and `onboard/confirm` require admin or operator, the roles that can open the Log Discovery page. Changing the scan scope, manual sources and poll credentials requires admin. See [Roles for scan and asset writes](#roles-for-scan-and-asset-writes).

### GET /api/log-discovery/scope

Preview the scan scope: the single-VLAN warning (SIEMBOX only sees its own
subnet by default -- computed from the host's network interfaces regardless of
what's below), and the scan-scope CIDRs, validated and size-checked.

`cidrs` is the **persisted standing scan scope** (see `GET`/`PUT /scope/cidrs`),
unioned with any ad-hoc subnets passed in `manual_cidrs` for a dry-run preview.
It deliberately excludes the auto-detected local interface CIDR, which in the
default bridge-networked Docker Compose deployment is just the backend
container's own bridge network, not the user's LAN. Every CIDR that comes back
here is exactly what an `active`/`full` scan will sweep host-by-host (see
`POST /scans` below); each must be a /22 or smaller (1024 addresses) to keep
that sweep bounded -- larger or malformed entries land in `rejected_cidrs`.

`detected_lan_cidr` is the host's real detected LAN subnet, offered as a
one-click scan-scope suggestion -- never auto-added to `cidrs`. It's `null`
unless the optional host-networking mode is active (see DEPLOYMENT.md's "Log
Discovery and Network Visibility" section); under the default bridge network
that detected interface is just the Docker bridge subnet, not the LAN, so it
would be misleading to suggest there.

**Authentication:** Required

**Query Parameters:**
- `manual_cidrs` (optional) - Comma-separated CIDR list to preview, e.g. `192.168.20.0/24,10.10.4.0/24`

**Response (200):**
```json
{
  "cidrs": ["192.168.20.0/24"],
  "vlan_warning": "SIEMBOX only sees its own subnet by default. If your homelab spans more than one VLAN or subnet, add their CIDRs manually or this scan will miss them.",
  "rejected_cidrs": [],
  "detected_lan_cidr": null
}
```

---

### GET /api/log-discovery/scope/cidrs

The **persisted standing scan scope** -- the manually-entered CIDRs stored
server-side in `system_settings` (shared across admins/devices, survives
restarts), rather than living only in the browser. The Log Discovery page loads
this on mount so an added subnet still shows after leaving the page, and
`POST /scans` falls back to it when a request omits `manual_cidrs`.

**Authentication:** Required

**Response (200):**
```json
{ "cidrs": ["192.168.20.0/24", "10.10.4.0/24"] }
```

---

### PUT /api/log-discovery/scope/cidrs

Replace the persisted standing scan scope. Each CIDR is validated (well-formed
**and** a /22 or smaller, same rule as `GET /scope`); accepted entries are
upserted, invalid/too-large entries are reported back in `rejected` rather than
silently dropped. An empty `cidrs` array clears the scope.

**Authentication:** Required (admin)

**Request Body:**
```json
{ "cidrs": ["192.168.20.0/24", "10.0.0.0/8"] }
```

**Response (200):**
```json
{ "cidrs": ["192.168.20.0/24"], "rejected": ["10.0.0.0/8"] }
```

---

### GET /api/log-discovery/fingerprints

The loaded fingerprint library (read-only), so the UI can explain what each match means.

**Authentication:** Required

**Response (200):** Array of fingerprint entries (`id`, `name`, `category`, `security_value`, `confidence_floor`, `attack_data_sources`, `log_access`, `credentials`, ...).

---

### POST /api/log-discovery/scans

Trigger a scan. Runs asynchronously; returns immediately with the job id.

**Authentication:** Required (admin or operator; other roles get `403`)

**Request Body:**
```json
{
  "mode": "full",
  "manual_cidrs": ["192.168.20.0/24"],
  "assignedShipperId": 3
}
```
- `mode` - `passive` (ARP/mDNS/SSDP/DHCP-lease only), `active` (sweeps every approved manual CIDR for live hosts, then scoped port/HTTP/TLS probing of those plus whatever passive discovery found), or `full` (both passive and active)
- `manual_cidrs` (optional) - CIDRs to sweep on this scan (each /22 or smaller; see `GET /scope`). When omitted, the scan falls back to the persisted standing scope (`GET /scope/cidrs`); an explicit array (including an empty one) is used as-is.
- `assignedShipperId` (optional) - run the whole probe pipeline on this log shipper (out on the LAN) instead of in-process on the backend. Must be an existing shipper id (400 otherwise). When set, the scan is created `queued` and waits for that shipper to claim it on its next job poll; omit (or `null`) to run on the backend. See the `/api/shippers/discovery-*` endpoints.

**Response (202):**
```json
{
  "scan_id": 7,
  "cidrs": ["192.168.1.0/24", "192.168.20.0/24"],
  "vlan_warning": null,
  "rejected_cidrs": [],
  "assigned_shipper_id": 3
}
```
- `assigned_shipper_id` - the shipper the scan was dispatched to, or `null` when it runs on the backend.

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
  "results_summary": { "hosts_seen": 24, "hosts_matched": 9 },
  "assigned_shipper_id": null,
  "assigned_shipper_name": null
}
```
- `status` - `queued` (dispatched to a shipper, awaiting claim), `running`, `completed`, or `failed`. An in-process scan starts straight at `running`.
- `assigned_shipper_id` / `assigned_shipper_name` - the shipper the scan ran on, or `null`/absent when it ran on the backend (the name is joined for display).

---

### POST /api/log-discovery/scans/:id/cancel

Stop a scan. Works on a `running` scan (interrupting its worker if one is live in
this process) and on a shipper-dispatched scan still `queued` — clearing one whose
shipper never came back to claim it. Also the remedy for a row orphaned `running`
by a previous process. Any other status is left untouched.

**Authentication:** Required (admin or operator; other roles get `403`)

**Response (200):**
```json
{
  "cancelled": true,
  "scan": { "id": 7, "status": "failed", "error_message": "Cancelled by user" }
}
```
- `cancelled` - `true` if this call transitioned the scan to `failed`; `false` if it was already in a terminal state (the current `scan` is returned either way).

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

### POST /api/log-discovery/sources/manual

Manually add an **api_pull** source for a device you already know about, without
waiting for a scan to discover and fingerprint it. Creates a scan-less
`discovery_sources` row (`confidence: 100`, `is_guess: false`, `status: confirmed`,
`last_scan_id: null`) and returns it. It is otherwise an **ordinary pollable
source**: save its credential and start polling through the existing
`POST /sources/:id/poller/credential` + `PATCH /sources/:id/poller` routes, using
the `id` returned here. The chosen port and scheme are stored in the source's
`evidence` (`{ "manual": true, "target_port": <port>, "tls": <bool> }`) and
`open_ports` is set to `[target_port]`; the poll adapter reads them to build its
base URL (overriding the default port/scheme it would otherwise derive for a
scan-discovered source). Re-posting the same `ip_address` upserts the existing
row (refreshing fingerprint/port/scheme and un-ignoring a previously dismissed
host) rather than creating a duplicate.

**Authentication:** Required (**admin**)

**Request Body:**
```json
{
  "ip_address": "192.168.1.50",
  "hostname": "authentik-box",
  "fingerprint_id": "authentik",
  "port": 9443,
  "tls": true
}
```
- `ip_address` (required) - a **literal** IPv4/IPv6 address (a DNS name is rejected with `400`; the column is `INET`)
- `fingerprint_id` (required) - a pollable device type: one of the ids from `GET /poller/supported-fingerprints` (currently `authentik`, `home-assistant`, `pihole`, `adguard-home`), and it must declare an `api_pull` log-access method
- `port` (optional) - integer `1`–`65535`; defaults to the fingerprint's `api_pull` `target_port`
- `tls` (optional) - boolean; defaults to `true` for `authentik`, `false` otherwise
- `hostname` (optional) - a display hostname

**Response (201):** the created/updated `discovery_sources` row (includes `id`).

**Error Responses:**
- `400` - invalid IP, non-pollable/unknown `fingerprint_id`, or out-of-range port
- `403` - caller is not an admin

---

### DELETE /api/log-discovery/sources/:id

Delete a **manually added** source (`evidence.manual === true`). Its poller row
cascades away via the `discovery_source_pollers` FK (`ON DELETE CASCADE`), and any
already-ingested `raw_logs` have their `discovery_source_id` set to `NULL`.
Scoped to manual rows on purpose: a scan-discovered source is removed by
re-scanning or ignoring it, never deleted here.

**Authentication:** Required (**admin**)

**Response (200):**
```json
{ "deleted": true }
```

**Error Responses:**
- `403` - the source is not a manual row (scan-discovered sources cannot be deleted here)
- `404` - no source with that id

---

### POST /api/log-discovery/sources/:id/confirm

Confirm a candidate is what the matcher thinks it is.

**Authentication:** Required (admin or operator)

---

### POST /api/log-discovery/sources/:id/ignore

Dismiss a source; it will not resurface in the ranked list.

**Authentication:** Required (admin or operator)

---

### POST /api/log-discovery/sources/:id/onboard/preview

Render the copy-paste onboarding block for a confirmed source's matched
fingerprint. Read-only -- does not change the source's status.

**Authentication:** Required (any role)

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

**Authentication:** Required (admin or operator)

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

### GET /api/log-discovery/poller/supported-fingerprints

Fingerprint ids with a real poll adapter (e.g. `["authentik", "home-assistant", "pihole", "adguard-home"]`) -- lets the UI know which sources can offer API polling without hardcoding the list.

**Authentication:** Required

---

### GET /api/log-discovery/sources/:id/poller

Poller status for a source. Never includes the credential itself.

**Authentication:** Required

**Response (200) — configured:**
```json
{
  "configured": true,
  "fingerprint_id": "authentik",
  "credential_username": null,
  "enabled": true,
  "poll_interval_minutes": 5,
  "last_polled_at": "2025-12-17T10:05:00Z",
  "last_status": "ok",
  "last_error": null,
  "last_event_count": 3
}
```
**Response (200) — not configured:** `{ "configured": false }`

---

### POST /api/log-discovery/sources/:id/poller/credential

Save (or replace) the token for this source's `api_pull` method and start polling it. Resolves the fingerprint's `api_pull` entry itself (not `method_index` -- most fingerprints list a `file`/`syslog_push` method first), so this always targets the right one regardless of what's shown in the onboarding dialog. Also sets `selected_log_access` and marks the source `onboarded`, same outcome as the manual `onboard/confirm` flow.

**Authentication:** Required (Admin)

**Request Body:**
```json
{ "username": null, "secret": "the-api-token-or-password" }
```
- `secret` (required) - the token/password. Encrypted at rest (AES-256-GCM); never returned again after this call.
- `username` (optional) - only used by HTTP Basic auth sources (AdGuard Home today)

**Response (200):** Same shape as `GET .../poller` above.

**Errors:**
- `400` - missing/empty `secret`, source has no matched fingerprint, or the fingerprint has no `api_pull` log-access method
- `404` - source or fingerprint not found

---

### DELETE /api/log-discovery/sources/:id/poller/credential

Full revoke: stops polling and forgets the credential, interval, and cursor (not just the secret) -- resuming later starts from scratch, not where it left off.

**Authentication:** Required (Admin)

**Response (200):** `{ "cleared": true }`

---

### PATCH /api/log-discovery/sources/:id/poller

Toggle polling on/off and/or change the poll interval.

**Authentication:** Required (Admin)

**Request Body:**
```json
{ "enabled": true, "poll_interval_minutes": 10 }
```
Both fields optional; `poll_interval_minutes` is clamped to `[1, 1440]`.

**Response (200):** Same shape as `GET .../poller` above.

**Errors:**
- `404` - no poller configured for this source yet (save a credential first)

---

### POST /api/log-discovery/sources/:id/poller/run-now

Poll immediately instead of waiting for the next scheduled cycle -- for UI feedback right after saving a credential.

**Authentication:** Required (Admin)

**Response (200):**
```json
{ "ok": true, "count": 3 }
```

**Errors:**
- `404` - no poller configured for this source yet

---

## Vulnerabilities Endpoints

Every route here requires a login (`Authorization: Bearer <token>`); without one the API answers `401`. The read routes are open to any role. (Earlier versions answered the read routes without a login; scripts that relied on that must now send a token.)

| Method | Path | Access |
|---|---|---|
| GET | every read route below | Any role |
| POST | `/api/vulnerabilities/templates/refresh` | Admin, analyst or operator |
| POST | `/api/vulnerabilities/templates/download` | Admin or operator |
| POST | `/api/vulnerabilities/scans`, `/api/vulnerabilities/scans/:scanId/cancel` | Admin or operator |
| PATCH | `/api/vulnerabilities/:assetId/:vulnId` | Admin or operator |

Each write takes the roles of the UI page that makes the call (Templates and Vulnerability Scanning for refresh; Vulnerability Scanning for download, scans and cancel; Vulnerability Management for status changes); other roles get `403`.

### GET /api/vulnerabilities/summary

Get dashboard summary of vulnerabilities.

**Authentication:** Required (any role)

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

**Authentication:** Required (any role)

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

**Authentication:** Required (any role)

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

**Authentication:** Required (any role)

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

**Authentication:** Required (any role)

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

**Authentication:** Required (any role)

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

**Authentication:** Required (any role)

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

**Authentication:** Required (admin, analyst or operator)

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

### POST /api/vulnerabilities/templates/download

Download the Nuclei templates (first run) or update them with `nuclei -update-templates`. Custom templates are kept.

**Authentication:** Required (admin or operator)

**Response (200):** `{ "message", "stats", "output" }`, with `stats` as for refresh. A failed download answers `500` with `{ "error", "details" }`.

---

### GET /api/vulnerabilities/scans

Get all vulnerability scans with filtering and pagination.

**Authentication:** Required (any role)

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

**Authentication:** Required (any role)

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

**Authentication:** Required (any role)

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

**Authentication:** Required (any role)

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

**Authentication:** Required (admin or operator)

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
- `403` - Analyst or viewer role

---

### POST /api/vulnerabilities/scans/:scanId/cancel

Cancel a running vulnerability scan.

**Authentication:** Required (admin or operator)

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
- `403` - Analyst or viewer role
- `404` - Scan not found or not running

---

### GET /api/vulnerabilities

Get all vulnerabilities with filtering and pagination.

**Authentication:** Required (any role)

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

**Authentication:** Required (any role)

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

**Authentication:** Required (any role)

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

**Authentication:** Required (admin or operator)

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
- `403` - Analyst or viewer role
- `404` - Asset-vulnerability mapping not found

---

## Exposure Monitoring (Digital Risk)

Watches for your organization's exposure **outside** your network:

- **Leaked credentials** — monitored email addresses (and whole email domains)
  are checked against [Have I Been Pwned](https://haveibeenpwned.com) (HIBP).
  Each breach an identity appears in becomes an **exposure finding** and, the
  first time it is seen, an **alert** (`alerts.source = "leaked-creds"`,
  `rule_id = null`) in the normal alert queue.
- **Password check** — a stateless, k-anonymous check of one password against
  HIBP's Pwned Passwords corpus.
- **Domain monitoring** — your own domains and brand names to protect are
  watched for new or mis-issued TLS certificates (Certificate Transparency),
  newly registered lookalike domains, registration (RDAP) changes and expiry,
  and DNS drift. Each change becomes a finding and alert with
  `source = "domain-monitor"`; see
  [How domain monitoring works](#how-domain-monitoring-works). No API key is
  needed.

HIBP is **bring-your-own-key** (an HIBP subscription; see
[HIBP API keys](https://haveibeenpwned.com/API/Key)). Nothing is checked until a
key is saved and the provider is enabled. The backend needs outbound HTTPS to
`haveibeenpwned.com` (breach searches) and `api.pwnedpasswords.com` (password
check; no key needed). Breach data is licensed CC BY 4.0:
every finding carries `detail.attribution = "https://haveibeenpwned.com"` and its
alert description names HIBP as the source — keep that attribution wherever the
data is shown.

**Authentication:** every endpoint requires a session. Reads (and the password
check) are open to any authenticated user; **all writes require the admin role**.

### How leaked-credential checks run

- A background job (`leaked-creds` in [`GET /api/admin/jobs`](#get-apiadminjobs))
  wakes every 15 minutes and checks the identities that are **due** — never
  checked, or last checked more than their own `interval_minutes` ago (daily by
  default) — one at a time.
- `email` identities use HIBP's breached-account search. `email_domain`
  identities use the domain search, which only works for domains you have
  **verified in your HIBP domain dashboard**; it yields one finding per
  alias + breach. An unverified domain is marked `last_status: "error"` with an
  explanation and retried after its interval.
- Calls are paced to the key's plan (requests per minute from HIBP's
  subscription status; 10/min until known). A `429` pauses all checks until
  HIBP's `retry-after` has passed; a rejected key (`401`) pauses them for an
  hour or until the key is changed. Neither retries in a loop; unchecked
  identities simply stay due.
- Findings are deduplicated on `sha256(kind:value:[alias:]breach)`: re-checks
  only update `last_seen`, never raise a second alert, and never reopen a
  resolved finding.
- **Severity:** `high` when the breach exposed credentials (Passwords,
  Historical passwords, Auth tokens), is a stealer log, or is a sensitive breach;
  `low` for spam lists and fabricated breaches without credentials; `medium`
  otherwise.
- **Notifications** are **opt-in**: `notify_exposure_enabled` defaults to
  `false` and `notify_exposure_min_severity` to `medium`. Once enabled, new
  findings go to the configured Slack / Email / NTFY channels, grouped into one
  message per identity per check (so a large email domain can't flood a channel).
  AI auto-triage is not run on these alerts.

### How domain monitoring works

- A background job (`domain-monitor` in [`GET /api/admin/jobs`](#get-apiadminjobs))
  wakes every 15 minutes (first run 2 minutes after startup) and checks the
  watched domains that are **due** — enabled, and `next_run_at` unset or passed —
  one at a time, at most 25 per cycle and within a 10-minute budget. A full run
  is due the domain's `interval_minutes` (daily by default) after the previous
  full run started; early retries (see below) can come sooner but never move it.
  The job is skipped, with the reason shown, when
  `exposure_domain_monitor_enabled` is `false` or nothing is due.
- **Collectors by scope.** `own` domains run all four; `brand` domains (names to
  protect from lookalikes, which you may not operate) run only `lookalike` and
  `ct` (certificates for the registered lookalikes, not for the brand domain
  itself). The domain's `collectors` object switches each one off individually.

| Collector | Source | Finding (`event_type`) | Severity |
|---|---|---|---|
| `ct` | crt.sh (`output=json`, unexpired, de-duplicated) — one query per name (`match=ILIKE` covers the name, its subdomains and wildcards) | `unexpected_ca`: a certificate for the domain from a CA not in `expected_cas` (only when that list is set) | high |
| | | `new_cert`: a certificate covering a host name never seen before, or from an issuer never seen before. Plain renewals are not findings | low |
| | | `new_cert`: a certificate for a registered lookalike (up to 3 lookalikes per run, rotating; 2 for run-now) | medium |
| `lookalike` | Built-in permutation engine (homoglyph, TLD swap, omission, transposition, repetition, QWERTY-adjacent replacement, hyphenation, vowel swap, addition, bitsquatting; plus `dnstwist` if installed), at most `exposure_lookalike_max_candidates` (default 300) candidates, checked with DNS | `lookalike_registered`: a candidate that was confirmed unregistered on an earlier run is now registered — high with an A/AAAA or MX record, else medium; a registered lookalike with no MX record gaining one — high | high / medium |
| `rdap` | IANA RDAP bootstrap → the registry's RDAP server (for the registered name) | `rdap_change`: nameservers or registrar — critical; status (e.g. a transfer lock removed) or DNSSEC — high | critical / high |
| | | `expiry_warning`: expires within `exposure_domain_expiry_warning_days` (default 30) — medium; already expired — high (one more finding if the date passes) | medium / high |
| `dns` | The system resolver: NS, MX, TXT, DMARC (`_dmarc.<domain>` TXT), A, AAAA | `dns_drift`: NS or MX changed — critical; TXT (titles call out SPF/DKIM) or DMARC policy — high; A/AAAA — medium | critical / high / medium |

- **The first run of each collector records a baseline silently** — the
  domain's existing certificates, lookalikes, registration and DNS are the
  starting point, not news. Two things are actionable at once: an expiry
  warning, and unexpired certificates from a CA outside `expected_cas` (one
  finding per offending CA; the same check re-runs whenever `expected_cas`
  changes).
- **Lookalikes are only "newly registered" when that was observed.** A
  candidate seen registered on its first definite DNS answer — the first run, a
  raised `exposure_lookalike_max_candidates`, `dnstwist` appearing, a lookup
  that kept failing until now — is recorded silently, because nobody knows when
  it was registered. So is one that comes back within 30 days of when it was
  last seen registered (a registry hold lifted): it is the same registration,
  and carries on from what was known about it — an MX record added during the
  hold alerts, and a re-registration keeps its own fingerprints and its pending
  certificate check. One that comes back later may have a new owner: it is
  reported as newly registered again, with its own fingerprints, so it is not
  deduplicated against the earlier owner's findings, and `ct` forgets what it
  recorded before then: its first certificate check is judged as a site going
  up, never the new owner's certificates as renewals. Under a TLD that answers
  for every name (a wildcard TLD such as `.ws`) only an NS delegation counts as
  a registration, and a candidate without one counts as confirmed unregistered
  — unless the resolver hides NS records altogether. A run in which `dnstwist`
  fails keeps what was known about its candidates. A failed A/AAAA/MX lookup
  counts as unknown, never as "no MX", and your other watched domains are
  never lookalikes (also when you start watching one that an older baseline
  listed). A newly registered lookalike's first certificate check is judged as
  a site going up however long crt.sh takes to answer for it: it stays pending
  until it has been checked, and is tried before the rotation (after 3 failed
  tries in a row it takes its turn with the others instead). A retry of it that
  fails again doesn't stop that run's other certificate checks.
- **Deduplication.** Every finding has a stable fingerprint (per certificate,
  per lookalike, per before→after change, per expiry date and phase), so re-runs
  only update `last_seen` and never raise a second alert. More than 10
  certificate findings of one kind in one run are grouped into one. New
  findings from one domain run go out as one grouped notification (opt-in, like
  leaked credentials).
- **Failures never look like changes.** A collector that fails keeps its
  baseline untouched; a failed DNS lookup is neither "unchanged" nor "removed",
  and a watched name that does not resolve at all (NXDOMAIN, e.g. a registry
  hold) fails the `dns` collector instead of reading as every record — DMARC
  included — removed. A resolver that answers NODATA for the domain's own NS
  records is filtering or broken, so none of its empty answers (MX, TXT, DMARC,
  A, AAAA) in that run are trusted either: they are warnings, and the baseline
  keeps the last good values. crt.sh 5xx/429/timeouts, DNS timeouts, registry
  outages and unexpected errors (e.g. a database blip) are *transient*: the
  domain comes back after 60 minutes (doubling per consecutive failure) and
  that early run repeats only the failed collectors. Early runs never move the
  regular schedule: the next full run is due `interval_minutes` after the last
  one started (`last_summary.full_run_at`), so a collector that keeps failing
  never holds the others back. A lookalike crt.sh can't answer for goes to the
  back of the rotation, except a newly registered one (see above); one whose
  answer is too large to monitor is left alone for a week. Each collector's
  outcome is in the domain's `last_summary`.
- **crt.sh's result limit.** crt.sh returns at most 10,000 matching
  (certificate, name) rows per query, picked in no particular order, and says so
  only in its HTML pages. A JSON answer that reaches the limit is refused ("too
  many to monitor reliably") rather than diffed, since new certificates could be
  missing from it. For the domain's own certificates that is a `ct` warning
  (also in `details.own_domain_error`; its baseline is kept), as is an answer
  over the 10 MB size cap: the certificate checks of its registered lookalikes
  still run (when crt.sh then times out or fails transiently on those too,
  nothing at all was checked, so `ct` fails and is retried early). Any other
  refusal, of the domain's own query or of a lookalike's (e.g. HTTP 403 from a
  proxy blocking crt.sh), fails `ct`, so it shows in `last_error`; no
  lookalike is left alone because of it.
- **A/AAAA rotation** among addresses seen in the last 90 days (CDNs) is not
  drift; a never-seen address, or every address vanishing, is. Fields an RDAP
  server leaves out of a response are "not reported", never "removed"; grace
  states such as `auto renew period` are ignored.
- **TLDs without RDAP** (or with only a plain-HTTP RDAP server, e.g. `.kg`)
  report `unsupported` for `rdap`, with the reason, and raise nothing.
- **Network access.** The backend needs outbound HTTPS to `crt.sh`,
  `data.iana.org` and the registries' RDAP servers, and DNS. Without it the
  collectors fail (see `last_summary`) rather than report "no findings".
  Lookalike checks cost about one DNS query per candidate (four for a
  registered one), at most 10 candidates in flight.
- **Optional second resolver** (`exposure_dns_secondary_resolver`, an IP
  address; off by default so no DNS traffic goes anywhere you didn't choose):
  when set and both resolvers answer, a DNS record set is only trusted when they
  agree. If one of them fails, the other's answer is used alone, with a warning
  in `last_summary`, and the finding's `detail.resolvers` says which one it came
  from (e.g. `"system only (9.9.9.9 failed)"`).

**Outbound-request guarantees.** Every request is a single HTTPS GET with a
descriptive User-Agent, a hard deadline and a response-size cap (crt.sh 10 MB,
RDAP 1 MB, the bootstrap file 2 MB), and **redirects are never followed**.
crt.sh and IANA are constant hosts; your domain only ever appears in an
encoded query parameter (crt.sh) or one encoded path segment (RDAP), never in a
host name. The RDAP server's URL comes from IANA's bootstrap file, so it is
validated before use — `https` only, no credentials or explicit port, no
IP-literal host, no internal-only names (`localhost`, `.local`, `.internal`,
`.lan`, `.home.arpa`, …) — and its host must resolve only to public addresses
(no private, loopback, link-local, CGNAT, ULA, multicast or reserved ranges).
The connection is pinned to the addresses vetted at connect time, so DNS
rebinding can't redirect it. crt.sh requests are spaced at least 3 seconds
apart.

### Privacy guarantees

- **The HIBP API key is write-only.** It is stored encrypted (AES-256-GCM via
  `CREDENTIAL_ENCRYPTION_KEY`, like the threat-intel provider keys) and no
  endpoint ever returns it — only `configured` / `enabled` booleans.
- **Passwords never leave the server and are never stored or logged.**
  `POST /password-check` hashes locally (SHA-1, as the range API requires) and
  sends only the first 5 hex characters to `api.pwnedpasswords.com` with
  response padding on; the match happens locally. The request body is dropped
  from the request as soon as it is read, and nothing — password, hash, prefix or
  response — is logged or persisted.
- **No secrets in findings or alerts.** Every finding's `detail` (also copied into
  the alert's `matched_data`) is scrubbed of any key matching
  `/pass(word)?|pwd|hash|secret|token|api[_-]?key|credential/i`, at any depth.
- **Malformed request bodies are never logged.** A JSON body that fails to
  parse gets a `400` (`"Malformed request body: expected valid JSON"`) without
  its contents reaching the logs or `application_errors` — this applies to every
  endpoint, so a malformed login or key-save request can't leak a secret either.
- The password check is rate limited to **30 requests per 15 minutes per client
  IP** (admins included), so it can't be used as a high-volume oracle.

### GET /api/exposure/status

Feature flags, provider state (never the key), counts and the last run.

**Authentication:** Required

**Response (200):**
```json
{
  "features": {
    "leaked_creds_enabled": true,
    "password_check_available": true,
    "domain_monitor_available": true,
    "domain_monitor_enabled": true
  },
  "notifications": { "enabled": false, "min_severity": "medium" },
  "providers": [
    {
      "name": "hibp",
      "label": "Have I Been Pwned",
      "docsUrl": "https://haveibeenpwned.com/API/v3",
      "signupUrl": "https://haveibeenpwned.com/API/Key",
      "attribution": "https://haveibeenpwned.com",
      "configured": true,
      "enabled": true,
      "usable": true
    }
  ],
  "counts": {
    "identities": 3,
    "identities_enabled": 3,
    "identities_due": 0,
    "domains": 1,
    "domains_enabled": 1,
    "domains_due": 0,
    "findings_total": 5,
    "findings_open": 4,
    "findings_open_by_severity": { "high": 3, "medium": 1 }
  },
  "leaked_creds": {
    "running": false,
    "paused_until": null,
    "pause_reason": null,
    "last_run": {
      "at": "2026-10-10T09:15:02Z",
      "trigger": "schedule",
      "summary": { "checked": 1, "newFindings": 2, "failed": 0, "remaining": 0, "skipped": false }
    },
    "job": {
      "status": "ok",
      "last_run_at": "2026-10-10T09:15:00Z",
      "last_result": "checked 1 identity, 2 new findings",
      "last_error": null,
      "next_run_at": "2026-10-10T09:30:00Z"
    }
  },
  "domain_monitor": {
    "running": false,
    "domains_in_progress": 0,
    "last_run": {
      "at": "2026-10-10T09:17:41Z",
      "trigger": "schedule",
      "summary": { "checked": 1, "newFindings": 0, "failed": 0, "down": 0, "crashed": 0, "remaining": 0, "skipped": false }
    },
    "job": {
      "status": "ok",
      "last_run_at": "2026-10-10T09:17:00Z",
      "last_result": "checked 1 domain, 0 new findings",
      "last_error": null,
      "next_run_at": "2026-10-10T09:32:00Z"
    }
  }
}
```
`last_run` and `job` describe this backend process only (they reset on restart);
`paused_until`/`pause_reason` are set while HIBP has asked us to back off or has
rejected the key. `domain_monitor.last_run` is the last scheduled cycle (a
manual `run-now` returns its own result instead): `failed` counts the domains
checked with at least one collector error, `down` those on which no collector
worked (`unsupported` doesn't count as working: it needs no network), and
`crashed` those whose run could not complete (they stay due).
`job.status` is `skipped` with the reason in `last_result` when monitoring is
off or no domain is due, and `failed` (with `last_error`) only when nothing
worked — no collector worked for any domain checked (e.g. no network or DNS),
or no domain run completed (e.g. the database). One collector failing (crt.sh
having a bad day, or a permanent problem with one domain) leaves the job `ok`;
each domain's own `last_error` says what failed.

---

### GET /api/exposure/settings

**Authentication:** Required

**Response (200):**
```json
{
  "notify_exposure_enabled": false,
  "notify_exposure_min_severity": "medium",
  "exposure_leaked_creds_enabled": true,
  "exposure_domain_monitor_enabled": true,
  "exposure_domain_expiry_warning_days": 30,
  "exposure_lookalike_max_candidates": 300,
  "exposure_dns_secondary_resolver": ""
}
```

### PUT /api/exposure/settings

Update any subset of the settings above.

**Authentication:** Required (Admin)

**Request Body:**
```json
{ "notify_exposure_enabled": true, "notify_exposure_min_severity": "high" }
```
- `notify_exposure_enabled`, `exposure_leaked_creds_enabled`,
  `exposure_domain_monitor_enabled` — JSON booleans
- `notify_exposure_min_severity` — `low` | `medium` | `high` | `critical`
- `exposure_domain_expiry_warning_days` — whole days, `1`-`365` (default `30`)
- `exposure_lookalike_max_candidates` — the hard cap on lookalike candidates
  generated and resolved per domain, `1`-`1000` (default `300`)
- `exposure_dns_secondary_resolver` — `""` (off, the default) or an IPv4/IPv6
  address (never a host name) of a second resolver that must agree with the
  system resolver before DNS drift is reported

**Response (200):** the full settings object.

**Errors:** `400` - a value of the wrong type or out of range, an unknown
severity, or a resolver that is not an IP address

---

### GET /api/exposure/providers

The breach-data providers, without keys: `[{ "name": "hibp", ..., "configured": true, "enabled": true, "usable": true }]`
(same objects as `providers` in `GET /status`). `configured` means a key is
saved; `usable` means this backend can also decrypt it. A saved key that isn't
usable (`CREDENTIAL_ENCRYPTION_KEY` missing, or changed since the key was saved)
makes every leaked-credential check skip: put the original
`CREDENTIAL_ENCRYPTION_KEY` back and restart the backend, or save the key again.

**Authentication:** Required

### PUT /api/exposure/providers/hibp

Save the HIBP API key and/or enable the provider. Saving (or re-enabling) also
lifts any rate-limit or rejected-key pause.

**Authentication:** Required (Admin)

**Request Body:**
```json
{ "api_key": "0123456789abcdef0123456789abcdef", "enabled": true }
```
- `api_key` (optional) - a 32-character hex HIBP key. Encrypted at rest; never
  returned. `""` or `null` clears it.
- `enabled` (optional) - boolean

**Response (200):** the public provider object (`configured` / `enabled` / `usable`, never the key).

**Errors:**
- `400` - `api_key` is not a 32-character hex key, `enabled` is not a boolean, or
  `CREDENTIAL_ENCRYPTION_KEY` is missing/invalid (the message says how to fix it)

### POST /api/exposure/providers/hibp/test

Validate a key with HIBP's cheapest authenticated call (`subscription/status`).
Tests the `api_key` in the body if given (so a key can be checked before it is
saved), otherwise the stored key. Nothing is saved.

**Authentication:** Required (Admin)

**Request Body:** `{ "api_key": "…" }` (optional)

**Response (200):**
```json
{
  "ok": true,
  "subscription": {
    "name": "Pwned 1",
    "description": "…",
    "subscribed_until": "2027-01-01T00:00:00",
    "rpm": 10,
    "domain_search_max_breached_accounts": 25,
    "includes_stealer_logs": false
  }
}
```

**Errors:**
- `400` - no key given or saved, a malformed key, or HIBP rejected the key
  (HIBP's public test key `000…0` fails here: `subscription/status` refuses it,
  although the breach searches accept it for HIBP's test accounts)
- `429` - HIBP rate-limited the test
- `502` - HIBP could not be reached

---

### GET /api/exposure/domains

All watched domains, alphabetically.

**Authentication:** Required

**Response (200):**
```json
[
  {
    "id": 1,
    "domain": "example.com",
    "scope": "own",
    "enabled": true,
    "interval_minutes": 1440,
    "collectors": { "ct": true, "lookalike": true, "rdap": true, "dns": true },
    "expected_cas": ["Let's Encrypt"],
    "last_checked_at": "2026-10-10T09:17:41Z",
    "next_run_at": "2026-10-11T09:17:41Z",
    "last_status": "ok",
    "last_error": null,
    "last_summary": { "trigger": "schedule", "status": "ok", "new_findings": 0, "collectors": { "...": "..." } },
    "created_at": "2026-10-10T09:00:00Z",
    "updated_at": "2026-10-10T09:00:00Z"
  }
]
```
- `next_run_at` — when the domain monitor checks the domain next (`null`: never
  checked, due now).
- `last_status` — `ok`, or `error` with `last_error` listing the failed
  collectors (`"ct: crt.sh is temporarily unavailable (HTTP 502); will retry"`).
- `last_summary` — the last run's outcome per collector, the same object
  [`POST /domains/:id/run-now`](#post-apiexposuredomainsidrun-now) returns
  (`null` before the first run).

### POST /api/exposure/domains

**Authentication:** Required (Admin)

**Request Body:**
```json
{ "domain": "example.com", "scope": "own", "expected_cas": ["Let's Encrypt"] }
```
- `domain` (required) - a bare DNS name with a real TLD, at most 253 characters
  (1-63 per label). Stored lowercase; a trailing root dot is dropped. **Rejected:**
  URLs and schemes, ports, paths/queries, `user@`, wildcards (`*.example.com`),
  IP addresses, and non-ASCII names (enter IDNs in punycode, `xn--…`).
- `scope` (optional, default `own`) - `own` (your domain) or `brand` (a name to
  protect from lookalikes)
- `enabled` (optional) - boolean, default `true`
- `interval_minutes` (optional) - whole minutes, `60`-`43200`, default `1440`
- `collectors` (optional) - any of `ct`, `lookalike`, `rdap`, `dns` → boolean;
  unspecified collectors stay on
- `expected_cas` (optional) - up to 50 CA names expected to issue for the domain.
  An entry matches a certificate when, ignoring case and punctuation, it is part
  of the issuer's O, OU or CN (`"Let's Encrypt"`, `"DigiCert"`, `"Sectigo"`).
  Empty (the default) turns the unexpected-CA check off.

**Response (201):** the created domain.

**Errors:**
- `400` - invalid domain (the message says why), scope, interval, collectors or CA list
- `409` - the domain is already watched

### PUT /api/exposure/domains/:id

Update `scope`, `enabled`, `interval_minutes`, `collectors` (merged over the
current values) and/or `expected_cas` (replaced). The domain itself can't be
changed — delete it and add the new one. A new `interval_minutes` takes effect
from the last full run (`next_run_at` = `last_summary.full_run_at`, else
`last_checked_at`, + the new interval); an early retry already scheduled
sooner keeps its time.

**Authentication:** Required (Admin)

**Response (200):** the updated domain.

**Errors:** `400` - invalid id or field, or an attempt to change `domain`;
`404` - not found

### DELETE /api/exposure/domains/:id

Deletes the domain, its findings and its collector baselines (their alerts stay
in the alert queue; if the domain is added back, a re-found change re-links its
existing alert instead of raising a new one).

**Authentication:** Required (Admin)

**Response (200):** `{ "message": "Watched domain deleted" }` · **Errors:** `404` - not found

### POST /api/exposure/domains/:id/run-now

Run the domain's collectors now instead of waiting for the job — every
collector its scope and `collectors` allow, whatever its schedule (also for a
domain that is switched off). Findings, baselines, `last_summary` and
`next_run_at` are updated exactly as for a scheduled run (a manual run is a full
run: `full_run_at` restarts the regular schedule). At most 2 registered
lookalikes get a certificate check per manual run (one crt.sh query each, plus
one for the domain). crt.sh can take 30-60 s per query, so allow a client
timeout of a few minutes.

**Authentication:** Required (Admin)

**Response (200):**
```json
{
  "domain_id": 1,
  "domain": "example.com",
  "scope": "own",
  "trigger": "manual",
  "started_at": "2026-10-11T02:29:22.000Z",
  "duration_ms": 39602,
  "status": "ok",
  "new_findings": 0,
  "retry": [],
  "retry_attempt": 0,
  "full_run_at": "2026-10-11T02:29:22.000Z",
  "next_run_in_minutes": 1440,
  "collectors": {
    "dns": {
      "status": "baseline",
      "note": "baseline recorded: NS 2, MX 1, TXT 2, DMARC 1, A 2, AAAA 2",
      "new_findings": 0,
      "at": "2026-10-11T02:29:22.000Z",
      "details": { "records": { "NS": 2, "MX": 1, "TXT": 2, "DMARC": 1, "A": 2, "AAAA": 2 }, "resolvers": "system" }
    },
    "rdap": {
      "status": "baseline",
      "note": "registrar RESERVED-Internet Assigned Numbers Authority (IANA 376); 2 nameservers; expires 2027-08-13 (306 days); baseline recorded",
      "new_findings": 0,
      "details": { "server": "rdap.verisign.com", "expires_at": "2027-08-13T04:00:00.000Z", "days_left": 306, "...": "..." }
    },
    "lookalike": {
      "status": "baseline",
      "note": "138 candidates checked, 18 registered (baseline recorded)",
      "new_findings": 0,
      "details": { "candidates": 138, "registered": 18, "registered_lookalikes": ["example.net", "exmple.com", "..."], "unresolved": 0, "dnstwist": false }
    },
    "ct": {
      "status": "baseline",
      "note": "baseline recorded: 12 unexpired certificates; 2 of 18 registered lookalikes checked this run",
      "new_findings": 0,
      "details": { "certificates": 12, "lookalikes_registered": 18, "lookalikes_checked": 2 }
    }
  }
}
```
Per-collector `status`: `baseline` (first run, recorded silently), `ok`,
`unsupported` (nothing to monitor, e.g. a TLD without RDAP — `note` says why),
`error` (with `error` and `transient`; transient ones are retried early and
listed in `retry`), `disabled` (switched off in `collectors`) or
`not_applicable` (not run for this scope). `warnings` lists partial failures
that did not stop a collector (e.g. one DNS record type timing out).

**Errors:**
- `404` - domain not found
- `409` - this domain is already being checked, or domain monitoring is
  disabled (`exposure_domain_monitor_enabled: false`)

---

### GET /api/exposure/identities

All monitored identities.

**Authentication:** Required

**Response (200):**
```json
[
  {
    "id": 3,
    "kind": "email",
    "value": "alice@example.com",
    "enabled": true,
    "interval_minutes": 1440,
    "last_checked_at": "2026-10-10T09:15:01Z",
    "last_status": "ok",
    "last_error": null,
    "created_at": "2026-10-09T18:00:00Z",
    "updated_at": "2026-10-09T18:00:00Z"
  }
]
```
`last_status` is `ok` or `error` (with `last_error` saying why, e.g. an unverified
domain).

### POST /api/exposure/identities

**Authentication:** Required (Admin)

**Request Body:**
```json
{ "kind": "email", "value": "alice@example.com" }
```
- `kind` (required) - `email` or `email_domain`
- `value` (required) - an email address (dot-atom local part; quoted local parts
  aren't supported) for `email`, or a domain (same rules as watched domains) for
  `email_domain`. Stored lowercase.
- `enabled` (optional) - boolean, default `true`
- `interval_minutes` (optional) - whole minutes, `60`-`43200`, default `1440`

**Response (201):** the created identity. It is due immediately, so the next job
tick (or `POST /run-now`) checks it.

**Errors:** `400` - invalid kind or value; `409` - already monitored

### PUT /api/exposure/identities/:id

Update `enabled` and/or `interval_minutes`. `kind` and `value` can't be changed
(findings are fingerprinted on them) — delete and re-add instead.

**Authentication:** Required (Admin)

**Response (200):** the updated identity · **Errors:** `400`, `404`

### DELETE /api/exposure/identities/:id

Deletes the identity and its findings. Their alerts stay in the alert queue; if
the identity is added back, a re-found breach re-links its existing alert rather
than raising a new one.

**Authentication:** Required (Admin)

**Response (200):** `{ "message": "Monitored identity deleted" }` · **Errors:** `404` - not found

---

### GET /api/exposure/findings

Findings, newest first.

**Authentication:** Required

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `source` | string | - | `leaked-creds` or `domain-monitor` |
| `unresolved` | boolean | `false` | `true` (or `1`) for open findings only |
| `severity` | string | - | `low`, `medium`, `high` or `critical` |
| `identity_id` | integer | - | Findings for one identity |
| `domain_id` | integer | - | Findings for one watched domain |
| `limit` | integer | 50 | 1-200 |
| `offset` | integer | 0 | Pagination offset |

**Response (200):**
```json
{
  "findings": [
    {
      "id": 12,
      "source": "leaked-creds",
      "identity_id": 3,
      "domain_id": null,
      "event_type": "breach",
      "title": "alice@example.com found in Adobe breach",
      "severity": "high",
      "detail": {
        "account": "alice@example.com",
        "breach_name": "Adobe",
        "breach_title": "Adobe",
        "breach_domain": "adobe.com",
        "breach_date": "2013-10-04",
        "added_date": "2013-12-04T00:00:00Z",
        "data_classes": ["Email addresses", "Password hints", "Passwords", "Usernames"],
        "is_verified": true,
        "is_sensitive": false,
        "is_stealer_log": false,
        "is_spam_list": false,
        "is_fabricated": false,
        "source": "hibp",
        "attribution": "https://haveibeenpwned.com"
      },
      "alert_id": 4711,
      "first_seen": "2026-10-10T09:15:01Z",
      "last_seen": "2026-10-11T09:15:03Z",
      "resolved_at": null,
      "identity_kind": "email",
      "identity_value": "alice@example.com",
      "domain": null
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0
}
```
Findings from an `email_domain` identity also carry `detail.alias` (the local part
that was found).

Domain-monitor findings have `source: "domain-monitor"`, `domain_id` set, an
`event_type` of `new_cert`, `unexpected_ca`, `lookalike_registered`,
`rdap_change`, `dns_drift` or `expiry_warning`, and a `detail` naming the
`collector` plus the change itself — e.g. a DNS drift:
```json
{
  "id": 31,
  "source": "domain-monitor",
  "identity_id": null,
  "domain_id": 1,
  "event_type": "dns_drift",
  "title": "Nameserver (NS) records changed for example.com",
  "severity": "critical",
  "detail": {
    "collector": "dns",
    "domain": "example.com",
    "record_type": "NS",
    "before": ["a.iana-servers.net", "b.iana-servers.net"],
    "after": ["ns1.attacker.example"],
    "added": ["ns1.attacker.example"],
    "removed": ["a.iana-servers.net", "b.iana-servers.net"],
    "resolvers": "system"
  },
  "alert_id": 4790,
  "first_seen": "2026-10-11T09:17:41Z",
  "last_seen": "2026-10-11T09:17:41Z",
  "resolved_at": null,
  "identity_kind": null,
  "identity_value": null,
  "domain": "example.com"
}
```
Certificate findings carry `crtsh_id` / `crtsh_url`, `issuer`, `issuer_org`,
`serial`, `names`, `not_before` / `not_after` (and `new_names` for a new host);
lookalike findings carry `lookalike`, `fuzzer`, `has_address` and `has_mx`; RDAP
changes carry `field`, `before`, `after`, `added` and `removed`; expiry warnings
carry `expires_at` and `days_left`.

**Errors:** `400` - unknown `source`/`severity`, or a malformed id/limit/offset

### POST /api/exposure/findings/:id/resolve

Mark a finding resolved (e.g. the password was changed). Idempotent: resolving
again keeps the first `resolved_at`. Re-checks never reopen it.

**Authentication:** Required (Admin)

**Response (200):** the finding · **Errors:** `404` - not found

---

### POST /api/exposure/run-now

Run the leaked-credential check now instead of waiting for the job.

**Authentication:** Required (Admin)

**Request Body:** `{ "force": true }` (optional) - check every enabled identity,
not just the due ones.

Stops starting new checks after ~90 seconds (HIBP calls are paced to the key's
plan, about 6 s apart on the smallest one); anything left stays due for the
scheduled job. Allow a client timeout of a couple of minutes.

**Response (200):**
```json
{ "checked": 3, "newFindings": 2, "failed": 0, "remaining": 0, "skipped": false }
```
- `skipped: true` with a `reason` when nothing ran (checks disabled, no provider
  configured, paused, or nothing due)
- `error` (and `rateLimitedUntil` for a `429`) when the run stopped early
- `remaining` - identities still due afterwards

**Errors:** `409` - a check is already running

---

### POST /api/exposure/password-check

Check one password against Pwned Passwords using k-anonymity (see
[Privacy guarantees](#privacy-guarantees)).

**Authentication:** Required · **Rate limit:** 30 requests / 15 minutes per client IP

**Request Body:**
```json
{ "password": "the password to check" }
```
At most 1024 characters.

**Response (200)** (sent with `Cache-Control: no-store`):
```json
{ "pwned": true, "count": 52256 }
```
`count` is how many times the password appears in the corpus (`0` when not pwned).

**Errors:**
- `400` - missing, empty or over-long password, or a malformed JSON body
- `429` - rate limit exceeded
- `502` - the Pwned Passwords service could not be reached

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
  refresh, YARA-Forge refresh, leaked-credential checks). These own no rows, so their state is tracked in
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

### GET /api/admin/client-address

How the API sees the caller, and how it is working out client addresses: for
checking a deployment's proxy setup (DEPLOYMENT.md, "Client addresses and
reverse proxies"). Sent with `Cache-Control: no-store`.

**Authentication:** Required (Admin)

**Response (200):**
```json
{
  "you": {
    "address": "192.168.1.50",
    "via": "proxy-socket",
    "peer": "proxy socket",
    "forwardedFor": "192.168.1.50",
    "rateLimitKey": "192.168.1.50",
    "signInKey": "192.168.1.50"
  },
  "proxySocket": { "state": "listening", "path": "/run/siembox/api.sock" },
  "trustedProxies": {
    "configured": "frontend",
    "entries": [
      { "entry": "frontend", "kind": "name", "addresses": ["172.18.0.3"], "status": "resolved", "resolvedAt": "2026-10-12T16:40:00.000Z" }
    ],
    "rejected": [],
    "nameLookup": { "enabled": true }
  },
  "hostNetworking": false,
  "gateways": ["172.18.0.1"],
  "ownNetworks": ["172.18.0.2/16"],
  "ignoredForwardedFor": { "peers": [], "untracked": 0 },
  "warnings": []
}
```

- `you.via`: `proxy-socket` (through the web UI's nginx), `trusted-proxy` (a
  `TRUSTED_PROXIES` peer supplied the address) or `direct` (the TCP address;
  any `X-Forwarded-For` was ignored). `you.peer` is the TCP peer, or
  `proxy socket`. `rateLimitKey` and `signInKey` are the keys the request
  limits and the sign-in limit count against (an IPv6 sign-in key is the /64).
- `proxySocket.state`: `listening`, `off` (`SIEMBOX_PROXY_SOCKET=off`),
  `no-volume` (its directory is missing, so the `api-socket` volume is not
  mounted) or `error` (with `error`). A socket listening anywhere but
  `/run/siembox/api.sock` is a warning: the bundled frontend's nginx never
  connects to another path.
- `trustedProxies.entries[].kind`: `address`, `range` or `name`. A name's
  `status` is `resolved`, `not-found`, `error` (the lookup failed; the last
  answer is kept), `pending` or `not-looked-up` (outside a container or with
  host networking; `nameLookup.reason` says which). `ignoredAnswers` lists DNS
  answers that were not trusted: not on the backend's own networks, the
  gateway, or not confirmed by Docker's DNS as a container on those networks
  (an answer from another DNS server).
- `gateways`: Docker gateway addresses, which are never trusted through a range.
- `ignoredForwardedFor.peers`: addresses whose `X-Forwarded-For` was ignored in
  the last hour (at most 100), each `{address, kind, requests, firstSeen,
  lastSeen, local, sustained}`. `kind` is `direct` (a caller of port 8421 that
  is not a trusted proxy) or `forwarded` (a proxy in front of the web UI's
  nginx, or of a trusted proxy, that passed on an `X-Forwarded-For` of its own
  but is not trusted itself, so it is taken for the client). `local` marks
  private, carrier-grade NAT, loopback, ULA and link-local addresses, which are
  usually a proxy that should be trusted. `requests` and `firstSeen` describe
  the current episode, and `sustained` is set once an episode has gone on for
  more than 45 s. With host networking, the frontend's address shows up for up
  to 30 s after a backend restart or a timed-out request while nginx uses its
  TCP fallback, which is expected: a `direct` peer's episode ends when it has
  been quiet for more than 30 s while the proxy socket served requests, so
  those windows don't add up. Requests to this endpoint are never counted.
- `warnings`: what to fix, in words. Ignored headers are only listed for
  `local`, `sustained` peers, and for this request itself (a direct call that
  carried `X-Forwarded-For`, or a request that came through a proxy that isn't
  trusted). A proxy on a public address is never listed for its own sake (any
  client could get its address counted), so check `you.address` through it.

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
