# API Reference

SIEMBox exposes a REST API on port **8421**. All endpoints are prefixed with **`/api`**.

> This page is an overview. The complete, endpoint-by-endpoint reference (request/response bodies, query params) is **[docs/reference/API.md](https://github.com/cladkins/SIEMBOX/blob/main/docs/reference/API.md)**.

## Authentication

Most endpoints require a **JWT**. Log in (`POST /api/auth/login`), then send the token on each request:

```http
Authorization: Bearer <YOUR_JWT_TOKEN>
```

Tokens are valid for **24 hours**. Role-based access applies (Admin / Analyst / Operator / Viewer) — viewers are read-only, changing parsers, detection rules and alerts and using the AI Analyst need **analyst** or higher, and some endpoints (user management, AI builders, threat-feed/provider config, Endpoint fleet, deleting alerts) are **admin-only**. Endpoint agents authenticate separately with a per-agent API key.

## Response & error format

```jsonc
// success
{ "data": { /* ... */ }, "message": "optional" }

// error
{ "error": "message", "code": 400, "details": "optional" }
```

| Code | Meaning |
|------|---------|
| 200 / 201 | OK / Created |
| 400 | Bad request |
| 401 | Unauthorized (missing/invalid token) |
| 403 | Forbidden (insufficient role) |
| 404 | Not found |
| 409 | Conflict (already exists) |
| 500 | Server error |

## Rate limiting

- **1000 requests / 15 minutes per client address** across `/api` (`API_RATE_LIMIT_MAX`). `X-RateLimit-Remaining` reports what's left.
- **10 failed sign-ins / 15 minutes per account per address** on `POST /api/auth/login`, and 100 per address across all accounts, past which only accounts that already failed from that address are refused (successful sign-ins don't count).
- EDR agent traffic and HTTP log pushes have their own, higher limits; EDR enrollment counts toward the general one.
- A `429` is JSON (`code: "RATE_LIMITED"`, `message`, `retryAfter`) with a `Retry-After` header.
- The address is the browser's real one through the web UI (port 8420). A direct caller on port 8421 is its TCP address: `X-Forwarded-For` from it is ignored unless it is in `TRUSTED_PROXIES` (see [Configuration](Configuration#client-addresses--reverse-proxies)).

## Endpoint areas

| Area | Base path | What it covers |
|------|-----------|----------------|
| Auth | `/api/auth` | Login, session, current user. |
| Logs | `/api/logs` | Raw + parsed logs, search, filters (incl. `parser_id`). |
| Parsers | `/api/parsers` | CRUD, validate/import, catalog browse/install, **AI generate**. |
| Detection Rules | `/api/rules` | CRUD, validate/import, catalog browse/install, **AI generate**. |
| AI | `/api/ai` | "Explain this" assistant **and the AI Security Analyst chat** (`/api/ai/chat`, per-user sessions). |
| Alerts | `/api/alerts` | List, acknowledge, manage. |
| Assets | `/api/assets` | Host inventory and findings. |
| Vulnerabilities | `/api/vulnerabilities` | Host scan results. |
| Containers | `/api/containers` | Image scans + Docker-host image discovery. |
| Scheduled Scans | `/api/scheduled-scans` | Scheduled host/container scans. |
| Endpoints | `/api/edr` | Endpoint agent enroll/heartbeat/config, YARA bundle delivery, inventory/events/vulns ingest, admin fleet + tokens. |
| Threat Intel | `/api/threat-intel` | IP detail (country, events, alerts), country IPs. |
| Threat Feeds | `/api/threat-feeds` | Feed status + reputation provider config (admin). |
| Shippers | `/api/shippers` | Log shipper registration/keys, ingest. |
| Notifications | `/api/notifications` | Email / Slack / NTFY config. |
| Settings | `/api/settings` | System, retention, syslog and AI settings (admin only, except reading the syslog host and port and the Getting Started state). Stored API keys are never returned. |
| Users | `/api/users` | User management (admin). |
| Admin | `/api/admin` | Admin dashboard data. |

See also the in-repo **[API quick reference](https://github.com/cladkins/SIEMBOX/blob/main/docs/reference/API_QUICK_REFERENCE.md)**.
