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
  - [Regex safety (parsers and rules)](#regex-safety-parsers-and-rules)
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
  - [Context Graph](#context-graph-endpoints)
  - [Endpoint Agent Updates (EDR)](#endpoint-agent-updates-edr)
  - [Display links (Big Display)](#display-links-big-display)
  - [Admin Dashboard](#admin-dashboard-endpoints)

---

## Authentication

Most API endpoints require authentication using JWT (JSON Web Token). After logging in, include the token in the `Authorization` header:

```http
Authorization: Bearer YOUR_JWT_TOKEN
```

**Session Duration:** Tokens are valid for 24 hours from login.

The only routes that take no login are `POST /api/auth/login`, the `/health` checks, the shipper-facing `/api/shippers` endpoints (authenticated by the shipper's API key or HTTP push key, see [Log Shippers](#log-shippers-endpoints)), the EDR agent endpoints (enrollment token or per-agent key), and a wall screen's `GET /api/display/snapshot` (its display link, see [Display link tokens](#display-link-tokens-x-display-token)).

### Password change required

An account that must choose a new password gets a session at sign-in as usual
(the answer has `"passwordChangeRequired": true`), but that session may call
only three routes:

- [`GET /api/auth/me`](#get-apiauthme): the profile, with why;
- [`PUT /api/auth/me/password`](#put-apiauthmepassword): the change itself
  (the current password is still required);
- [`POST /api/auth/logout`](#post-apiauthlogout).

Every other route that takes a login answers it with `403`, before any role
check, until the password is changed:

```json
{
  "status": "error",
  "statusCode": 403,
  "code": "PASSWORD_CHANGE_REQUIRED",
  "reason": "default",
  "message": "Choose a new password before doing anything else (PUT /api/auth/me/password): this account uses SIEMBox's default password."
}
```

`reason` is why (`null` only if it can't be told):

| `reason` | When | The end of `message` |
|---|---|---|
| `initial` | The `admin` account the first start created, with `DEFAULT_ADMIN_PASSWORD` (`changeme` when unset) | "this is the password the account was created with." |
| `default` | Found on SIEMBox's default password `changeme`: admin accounts at every start, any account at a correct sign-in with it | "this account uses SIEMBox's default password." |
| `admin` | An admin created the account or set its password ([`POST /api/users`](#post-apiusers), [`PUT /api/users/:id`](#put-apiusersid)) without `"mustChangePassword": false` | "an administrator set a temporary password for this account." |
| `cli` | `auth-admin reset-password` set it | "the password was reset from the command line." |

The requirement belongs to the account, not the session: it applies to all of
its sessions at once, including ones from before it was set. A successful
`PUT /api/auth/me/password` lifts it and signs every session out; sign in again
with the new password. MFA is still asked at sign-in first, and MFA can't be
set up or turned off while restricted. Refused requests are not audited or
logged one by one. Shipper and agent routes don't take a session and are not
affected.

### Display link tokens (X-Display-Token)

A wall screen or TV shows the Big Display without anyone signing in, with a
**display link** an admin creates ([Display links](#display-links-big-display)).
Each link has one secret: `sbd1_` followed by 43 base64url characters (256
bits). SIEMBox stores only its sha256 and shows the secret once, in the answer
to the create or rotate call. The screen opens `/display#k=<secret>`: the
secret is in the URL fragment, which browsers never send to a server or put in
a `Referer`, so it never reaches nginx's or SIEMBox's logs. The page sends it
on each request in its own header:

```http
GET /api/display/snapshot
X-Display-Token: sbd1_…
```

A display token is never a login, and a login is never a display token. The
token is accepted in this header on this one route only: never in
`Authorization`, a path or a query string. Every route that takes a login
answers a display token (in either header) as it answers no login, and
`GET /api/display/snapshot` ignores `Authorization` entirely, whatever the
session's role.

Every request re-reads the link, so pausing, rotating or revoking it takes
effect at the screen's next refresh. A link never expires unless an admin set
`expires_at`, and nothing about the admin who made it (a password change or
reset, a required password change, their sessions ending, their account being
deleted) affects it. A refusal is answered in the usual error envelope with a
`code`, with `Cache-Control: no-store`, and is neither audited nor written to
the error log (refusals are counted in memory and summed up in one log line
every 5 minutes):

| Status | `code` | When | The screen (BIG-DISPLAY.md §5.8) |
|---|---|---|---|
| 401 | `DISPLAY_TOKEN_REQUIRED` | No `X-Display-Token` header | "This page needs a display link" |
| 401 | `DISPLAY_LINK_INVALID` | Malformed, or no link has it (rotated, never issued). The same answer for both. | Asks for the new link; checks again every 10 min |
| 401 | `DISPLAY_LINK_REVOKED` | The link was revoked | Stops |
| 401 | `DISPLAY_LINK_EXPIRED` | `expires_at` has passed; the answer also has `expires_at` | Checks again every 10 min (an admin can extend it) |
| 403 | `DISPLAY_LINK_PAUSED` | An admin paused it | Checks every 60 s and resumes by itself |
| 403 | `DISPLAY_NETWORK_NOT_ALLOWED` | The client address is outside the link's `allowed_cidrs` | Checks again every 5 min |
| 503 | `DISPLAY_UNAVAILABLE` | The database couldn't be asked (with `Retry-After: 5`); never reported as an invalid link | Keeps the last data and retries |
| 429 | `RATE_LIMITED` | 30 failed (`401`) display lookups from the address in 15 minutes | Waits for `Retry-After` |

The checks run in that order, and the first that applies answers. A valid
secret used from outside its networks is the one refusal that is audited
(`display_link.refused_network`, at most once per link and address per hour):
it is a sign the link has leaked.

### Calling the API from a browser (CORS)

The web UI calls the API on its own origin (its nginx proxies `/api`), so by default the API sends no CORS headers: a page on another origin can't read its answers, and the preflight a browser sends before a JSON body or an `Authorization` header gets an empty `204` with no `Access-Control-Allow-*` headers, so the request itself is never sent. Every `OPTIONS` request is answered that way, before the rate limit and the routes. Scripts, shippers, agents and `curl` send no preflight and are unaffected.

To let pages on other origins call the API, list their exact origins in `CORS_ORIGIN`, comma-separated (`https://dash.example.com,http://localhost:5173`). A request whose `Origin` header is one of them gets `Access-Control-Allow-Origin: <that origin>` and `Access-Control-Allow-Credentials: true`, and its preflight also gets `Access-Control-Allow-Methods: GET,HEAD,PUT,PATCH,POST,DELETE` and the requested headers in `Access-Control-Allow-Headers`; with a list set, every answer carries `Vary: Origin`. `CORS_ORIGIN=*` answers every origin with `Access-Control-Allow-Origin: *` and logs a warning at every start. No response headers are exposed beyond the CORS-safelisted ones. See DEPLOYMENT.md, "Browser access from other origins (CORS)".

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
| `PUT /api/log-discovery/scope/cidrs`, `POST /api/log-discovery/sources/manual`, `PATCH` and `DELETE /api/log-discovery/sources/:id`, the `/sources/:id/poller` writes | yes | no | no | no |
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
| 403 | Forbidden | Insufficient permissions, a disabled account, or `code: "PASSWORD_CHANGE_REQUIRED"` (the account must change its password first, see [Password change required](#password-change-required)) |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Resource already exists |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error |
| 503 | Service Unavailable | Busy (the database, or a regex check worker): try again shortly. The [Context Graph](#context-graph-endpoints)'s `code: "GRAPH_BUSY"` says when, in `Retry-After`. `code: "DISPLAY_UNAVAILABLE"`: a display link couldn't be checked because the database is unreachable (see [Display link tokens](#display-link-tokens-x-display-token)) |

A request body that isn't valid JSON is rejected with `400` (`"Malformed request
body: expected valid JSON"`), and an oversized one with `413`, before any route
runs. These rejections are never logged with the body's contents.

---

## Rate Limiting

Limits count per **client address**. Requests through the web UI's nginx
(port 8420) carry the browser's real address. A direct caller on port 8421 is
its TCP address: `X-Forwarded-For` and `X-Real-IP` from it are ignored unless it
is listed in `TRUSTED_PROXIES` (see DEPLOYMENT.md, "Client addresses and reverse
proxies"). These request counters are kept in memory and reset when the backend
restarts. Failed sign-ins are counted separately, in the database: see
[Sign-in Protection](#sign-in-protection).

| Limit | Default (per 15 minutes) | Applies to | Headers |
|-------|--------------------------|------------|---------|
| General | 1000 requests (`API_RATE_LIMIT_MAX`) | Every `/api` request, except the two exemptions below | `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` |
| EDR agents | 30000 requests (`EDR_AGENT_RATE_MAX`) | Agent-key routes, which skip the general limit when they carry `X-Agent-ID` and use the route's own method: `POST` heartbeat, `GET` (or `HEAD`) config and YARA, `POST` inventory, events and vulnerabilities. Any other method, and enrollment, is under the general limit. | `RateLimit-*` |
| HTTP log push | 6000 requests (`SHIPPER_LOG_PUSH_MAX`) | `POST /api/shippers/logs`, which skips the general limit when it carries `X-Shipper-ID` (other methods on that path don't) | `RateLimit-*` |
| Password check | 30 requests | `POST /api/exposure/password-check` | `RateLimit-*` |
| Display link lookups | 30 failed lookups | `GET /api/display/snapshot`: only answers with `401` count (a working, paused or out-of-network screen never uses it up); the 31st gets `429` and no database work. Display requests also count towards the general limit: one screen refreshing every 30 s makes 30 requests per 15 minutes, so many screens behind one address may need a higher `API_RATE_LIMIT_MAX`. | `RateLimit-*` |

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
`/api/auth/*` are limited to 16 kB, and those sent to `/api/display/*` and
`/api/display-links/*` to 32 kB (a larger one gets `413`); other routes
accept up to 10 MB. A body may be compressed (`Content-Encoding: gzip`,
`deflate` or `br`); the limits apply to its decompressed size, and one that
does not decompress gets `400` (`"Invalid request body"`).

---

## Sign-in Protection

Failed password and MFA-code checks are counted in the database (table
`login_throttle`), per **key**. A key's T-th failure in a row **pauses** it for
30 seconds, and each further failure doubles the pause (1, 2, 4, 8, 16, 32
minutes) up to the key's cap. A key's streak starts over 24 hours after its
last failure. Nothing is ever locked for good.

| Key | Counts | T (default) | Longest pause | A full sign-in |
|-----|--------|-------------|---------------|----------------|
| Account + network | Wrong passwords for one username from one network (IPv4 address or IPv6 /64), from browsers SIEMBox doesn't recognize | 5 (`LOGIN_MAX_FAILURES`) | 15 min | resets it |
| Network | Wrong passwords from one network, for any username; while paused it refuses only usernames that failed from that network in the last 15 minutes | 20 (`LOGIN_MAX_FAILURES_PER_ADDRESS`) | 30 min | refunds its own attempt only |
| Account | Wrong passwords for one username from every network, from new browsers | 20 (`LOGIN_MAX_FAILURES_PER_ACCOUNT`; `0` turns it off) | 60 min | refunds its own attempt only |
| Recognized browser | Wrong passwords and MFA codes from one browser that signed in before; it replaces every key above | 10 | 15 min | resets it |
| MFA | Wrong MFA codes for one user (sign-in from new browsers, and `POST /me/mfa/disable`) | 5 | 60 min | resets it |
| Current password | Wrong current passwords on `PUT /me/password` | 5 | 60 min | resets it |

- **Checked before bcrypt.** Each attempt is charged to its keys before its
  password or code is checked, under row locks, and refunded when it was right.
  However many requests arrive at once, a key lets exactly T checks through;
  attempts while it is paused are refused without a check (the right password
  included).
- **Shared networks.** A paused network key refuses a username only for 15
  minutes after its account + network key last failed; any other attempt is
  checked (and charged) as usual. So one attacker behind a NAT or an outer
  proxy SIEMBox doesn't trust can't lock out everyone behind it: a user who
  mistypes there is refused while the network stays paused, for at most 15
  minutes after that failure, however long the attack goes on, and a sprayer
  gets at most one guess per username per network every 15 minutes (the
  account + network key's own slowest rate; the account key still bounds it
  across networks). Such a user's `retryAfter` is the earliest they might get
  in: the end of the network's current pause, or of their 15 minutes if that
  comes first. It is not a promise: the first failure from that network after
  its pause ends (an attacker's next guess) pauses it again, and their next
  attempt is then refused again with a new `retryAfter`, until the 15 minutes
  are up. The guesses a paused network lets through are counted but never
  start, extend or lengthen its pause, so there is one `auth.login.paused` row
  per pause; a wrong one is answered with a 429 (`reason: "network"`) for the
  rest of that pause or 15 minutes, whichever is shorter. The decision uses the
  account + network key alone, so it is the same for usernames that exist and
  those that don't.
- **Recognized browsers.** Every successful sign-in returns a `browserToken`;
  the web UI keeps it per username and sends it back. A sign-in with a valid
  token for that username counts against that browser's key only, so failed
  attempts from elsewhere never pause the owner's own browsers. The token never
  skips the password or MFA. It is valid for 90 days from its last use, and is
  forgotten after 20 failures in a row from it, on a password change or reset,
  and with the user (at most 20 per user). Only its sha256 is stored.
- **No enumeration.** An unknown username, a wrong password and a disabled
  account with a wrong password get the same `401` after the same work (one
  bcrypt compare, against a dummy hash for unknown usernames, which are counted
  under the same kind of keys). `"Account is disabled"` and `mfaRequired` are
  only answered after a correct password.
- **Codes.** A 6-digit code is only tried as a TOTP code (each one works once:
  a replay is refused), a 10-character code (`xxxxx-xxxxx`) only as a recovery
  code (used up in one statement, so a code can't be used twice at once).
- **Not counted:** a `5xx` (an attempt that couldn't be checked is refunded),
  the "MFA code required" step, and anything with `LOGIN_PROTECTION=off`. If
  the counter table is broken, sign-in goes ahead uncounted (fails open) and
  says so in the log and on the Admin dashboard; if the database can't be
  reached at all, sign-in answers `500`.

A paused attempt gets `429` with a `Retry-After` header (whole seconds, rounded
up) and:

```json
{
  "status": "error",
  "statusCode": 429,
  "code": "SIGNIN_PAUSED",
  "reason": "account_network",
  "message": "Too many failed sign-in attempts for this account from your network. Try again in 2 minutes.",
  "retryAfter": 102
}
```

`reason` is one of:

| `reason` | `message` |
|----------|-----------|
| `account_network` | Too many failed sign-in attempts for this account from your network. Try again in … |
| `network` | Too many failed sign-in attempts from your network. Try again in … |
| `account` | Sign-in to this account from new browsers is paused after many failed attempts. Try again in …, or use a browser you have signed in with before. |
| `browser` | Too many failed sign-in attempts from this browser. Try again in … |
| `mfa` | Too many incorrect codes. Try again in … (with `mfaRequired: true` on sign-in) |
| `current_password` | Too many incorrect current passwords. Try again in … |

On the failed attempt that starts a pause, the message begins with what was
wrong: `"Incorrect username or password. "`, `"Incorrect code. "` or
`"Current password is incorrect. "`. Several paused keys report the longest
wait. Admins see and clear the counters on Settings -> Sign-in protection (or
with [`POST /api/admin/sign-in-protection/clear`](#post-apiadminsign-in-protectionclear)
and [`POST /api/users/:id/unlock`](#post-apiusersidunlock)); see
TROUBLESHOOTING.md, "Locked out of SIEMBox", for the command line.

---

## API Endpoints

## Authentication Endpoints

### POST /api/auth/login

Sign in and receive a session token (valid for 24 hours). Counted by
[Sign-in Protection](#sign-in-protection). Every answer is sent with
`Cache-Control: no-store` (as is everything under `/api/auth`).

**Authentication:** None required

**Request Body:**
```json
{
  "username": "admin",
  "password": "changeme",
  "code": "123456",
  "browserToken": "dGhlLWJyb3dzZXItdG9rZW4tZnJvbS1hLXNpZ24taW4"
}
```

- `username`: a string of 1 to 255 characters (exact, case-sensitive).
- `password`: a string of 1 to 1024 characters.
- `code` (optional): the MFA code (a 6-digit TOTP code or a recovery code),
  for users with MFA. A string or number of at most 64 characters.
- `browserToken` (optional): the `browserToken` an earlier successful sign-in
  of this username returned to this browser. Anything not shaped like one is
  ignored.

**Response (200):**
```json
{
  "token": "4f9c2e...64 hex characters",
  "user": {
    "id": 1,
    "username": "admin",
    "email": "admin@example.com",
    "role": "admin",
    "enabled": true,
    "mfa_enabled": false,
    "last_login": "2025-11-30T12:00:00Z",
    "must_change_password": true,
    "must_change_password_reason": "initial",
    "must_change_password_since": "2025-11-30T11:59:00Z"
  },
  "expiresAt": "2025-12-01T12:00:00Z",
  "browserToken": "dGhlLWJyb3dzZXItdG9rZW4tZnJvbS1hLXNpZ24taW4",
  "passwordChangeRequired": true
}
```

`browserToken` is the presented token when it was valid (it is not rotated),
otherwise a new one. Keep it for this username and send it with later sign-ins.

`passwordChangeRequired: true` (only present then) means the account must
choose a new password before anything else: the session works only for
`GET /api/auth/me`, `PUT /api/auth/me/password` and `POST /api/auth/logout`
(see [Password change required](#password-change-required)). The `user` fields
`must_change_password`, `must_change_password_reason` and
`must_change_password_since` say whether, why and since when. A correct
sign-in with the default password `changeme` sets it (`reason: "default"`),
before the MFA step.

**Errors** (all in the `{status, statusCode, message}` envelope):
- `400` - `"Username and password are required"`: a field is missing or isn't
  what is described above (no database access, nothing counted)
- `401` - `"Invalid username or password"`: wrong password, unknown username,
  or a disabled account with a wrong password; also a right password that was
  changed or reset while this sign-in was being checked (no session is ever
  created for a password that is no longer the account's)
- `401` - `{ "message": "MFA code required", "mfaRequired": true }`: the
  password is right and the user has MFA; send the same request with `code`
  (not counted as a failure)
- `401` - `{ "message": "Invalid MFA code", "mfaRequired": true }`: wrong or
  already used code
- `403` - `"Account is disabled"`, only after a correct password
- `413` - Request body larger than 16 kB
- `429` - `code: "SIGNIN_PAUSED"`, with `reason`, `message`, `retryAfter` and a
  `Retry-After` header (and `mfaRequired: true` for `reason: "mfa"`, or a
  paused recognized browser at the code step); see
  [Sign-in Protection](#sign-in-protection). The general limit's `429`
  (`code: "RATE_LIMITED"`) also applies.
- `500` - The sign-in couldn't be checked (database unavailable); not counted

---

### POST /api/auth/logout

Logout current user and invalidate session token.

**Authentication:** Required (also works for a session that must change its
password)

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

**Authentication:** Required (also works for a session that must change its
password)

**Response (200):**
```json
{
  "id": 1,
  "username": "admin",
  "email": "admin@example.com",
  "role": "admin",
  "enabled": true,
  "last_login": "2025-11-30T12:00:00Z",
  "created_at": "2025-01-01T00:00:00Z",
  "mfa_enabled": false,
  "password_changed_at": "2025-11-30T11:58:00Z",
  "must_change_password": false,
  "must_change_password_reason": null,
  "must_change_password_since": null
}
```

`password_changed_at` is when the user last changed their own password with
[`PUT /api/auth/me/password`](#put-apiauthmepassword) (`null` if never; an
admin's reset or the recovery command line doesn't set it). Getting Started's
"Secure your account" step reads it.

`must_change_password` is `true` while the account must choose a new password
before anything else, with `must_change_password_reason` (`initial`,
`default`, `admin` or `cli`) and `must_change_password_since`; see
[Password change required](#password-change-required).

---

### PUT /api/auth/me/password

Change current user's password. This is how an account that must change its
password does it.

**Authentication:** Required (also works for a session that must change its
password)

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
  "message": "Password updated. Sign in again with the new password."
}
```

**Notes:**
- The new password must be 8 to 1024 characters, differ from the current one,
  and not be the default password `changeme` in any letter case
- On success every session of the user is revoked (this one included), their
  recognized browsers are forgotten and their sign-in counters cleared: sign in
  again with the new password. `password_changed_at` (`GET /api/auth/me`) is set,
  and a requirement to change the password is lifted (in the same update)
- Wrong current passwords are counted ([Sign-in Protection](#sign-in-protection),
  "Current password"): the 5th in a row pauses further attempts. A right one is
  never counted, even if saving the new password then fails (`500`)

**Errors:**
- `400` - `"Current password and new password are required"`,
  `"New password must be 8 to 1024 characters"`, `"New password must be
  different from the current one"`, `"The default password can't be used"`,
  or `"Current password is incorrect"` (a `400`, not a `401`: the session
  stays valid)
- `429` - `code: "SIGNIN_PAUSED"`, `reason: "current_password"`, with
  `Retry-After`

---

### POST /api/auth/me/mfa/setup

Start enrolling the caller in MFA (TOTP): stores a new secret as pending and
returns it with the `otpauth://` URI for an authenticator app. MFA stays off
until `/me/mfa/enable` confirms a code.

**Authentication:** Required

**Response (200):** `{ "secret": "JBSWY3DPEHPK3PXP...", "otpauthUrl": "otpauth://totp/SIEMBox:admin?..." }`

**Errors:** `400` - `CREDENTIAL_ENCRYPTION_KEY` is not usable; `409` - MFA is already enabled

---

### POST /api/auth/me/mfa/enable

Finish enrollment with a code from the authenticator app: enables MFA and
returns 10 one-time recovery codes, shown only this once. That code can't then
also be used to sign in. Not throttled: the code is only ever checked against
the pending secret `/me/mfa/setup` just returned, never once MFA is on.

**Authentication:** Required

**Request Body:** `{ "code": "123456" }`

**Response (200):** `{ "enabled": true, "recoveryCodes": ["abcde-fghij", "..."] }`

**Errors:**
- `400` - `code is required`, `Invalid code`, or no pending enrollment
- `409` - `MFA is already enabled; disable it first to re-enroll` (whatever the
  code), or the pending enrollment changed while it was being enabled (start
  setup again)

---

### POST /api/auth/me/mfa/disable

Turn the caller's MFA off with a current code (TOTP or recovery, used up as at
sign-in). Wrong codes count against the same MFA key as sign-in.

**Authentication:** Required

**Request Body:** `{ "code": "123456" }`

**Response (200):** `{ "enabled": false }` (also when MFA was already off)

**Errors:**
- `400` - `code is required` or `Invalid code` (never `401`: the session stays valid)
- `429` - `code: "SIGNIN_PAUSED"`, `reason: "mfa"`, with `Retry-After`

---

### POST /api/auth/cleanup

Cleanup expired sessions (admin only). The hourly sign-in housekeeping job
(`sign-in-housekeeping` in [`GET /api/admin/jobs`](#get-apiadminjobs)) does this
too.

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

## Regex safety (parsers and rules)

A parser's `pattern`, its derivation regexes (`derivations[].extract.*.pattern`,
`derivations[].when.*.matches`) and a detection rule's `regex` conditions run on
every incoming log, on the thread that also serves this API and syslog
ingestion. JavaScript regexes backtrack, and a pattern such as `^(a+)+$` can
run for minutes on a short crafted line. So:

**Every write that stores a regex checks it first** — `POST`/`PUT /api/parsers`,
`POST /api/parsers/import` (and the `/validate` preview), parser and rule catalog
installs and Install all, `POST`/`PUT /api/rules` (from `rule_yaml` or a
`rule_logic` sent directly), Sigma import and its preview, content-pack installs,
and the bundled-rule importer. The check is
[recheck](https://makenowjust-labs.github.io/recheck/) (the analyzer the catalog
CI runs, run the same way: its automaton backend and, when that says safe, its
fuzz backend, which also catches a large constant blowup such as
`^(?:a|a|a|a|a|a|a|a)(?:a|a|a|a|a|a|a|a)…$`; with the CI's parameters), with a
time budget per analysis pass (`REGEX_SAFETY_CHECK_TIMEOUT_MS`, default
10000 ms), in a worker thread.
Verdicts are cached per distinct regex in the `regex_safety_verdicts` table,
so a regex is analyzed once; a verdict that only ran out of time is kept in
memory for 10 minutes and never stored, so it is analyzed again. A save's
regexes are analyzed a few at a time (one per scan worker), so a save with
many new regexes takes longer rather than being refused as busy.

A regex must be a string. `PUT /api/parsers/:id` answers `400` for a
`pattern` that is not a string, or `derivations` that fail the import's
validation (a `when.*.matches` or `extract.*.pattern` that is not a string
included); `POST`/`PUT /api/rules` answer `400` for a `regex` condition whose
`flags` is not a string (`flags: [i]`) or whose `value` is a list or mapping.
The engines compile nothing else either: a stored non-string regex never
runs (a parser's matcher fails, a rule's condition logs an invalid-regex
error and never matches).

- **Proven vulnerable** (recheck found an attack string; exponential or
  polynomial): refused with `422` and nothing is saved. `force` does not
  override it. In a batch (Install all, Sigma import, a content pack) the item
  is listed in `failed` with the same sentence as `reason` (and
  `"code": "REGEX_UNSAFE"`), and the rest are installed.

  ```json
  {
    "code": "REGEX_UNSAFE",
    "message": "Parser \"my-app\" was not saved: ReDoS: regex at pattern is vulnerable (exponential) — rewrite it linear before saving",
    "errors": ["ReDoS: regex at pattern is vulnerable (exponential) — rewrite it linear before saving"],
    "warnings": [],
    "regex_safety": {
      "vulnerable": [
        { "location": "pattern", "source": "^(a+)+$", "flags": "", "status": "vulnerable",
          "complexity": "exponential", "attack": "'a' + 'a'.repeat(31) + '\\x00'" }
      ],
      "unknown": []
    }
  }
  ```

  `location` names the regex: `pattern`, `derivations[2].extract.user`,
  `derivations[0].when.message.matches`, or for a rule `conditions[1].value`.
  The sentence is the one `GET /api/parsers/:id/contribute` uses (there it ends
  "before contributing").
- **Unreadable and unbounded** (the analyzer cannot parse it, e.g. `\u{17}`
  without the `u` flag, which JavaScript reads as seventeen `u`s, and V8's
  linear-time fallback cannot bound it on a log line either: an `i` or `u` flag
  (every `when.*.matches` is case-insensitive), lookahead, a backreference, a
  counted repeat over 16, lookbehind on a backend built on Node 20, or `REGEX_LINEAR_FALLBACK=false`):
  refused with `422` and `"code": "REGEX_UNDECIDED"`, nothing saved, same body
  shape with the regex under `regex_safety.undecided`:
  `"ReDoS: regex at pattern could not be proven safe (unknown: the analyzer could not parse it (…)) and V8's linear-time fallback cannot run it (a counted repeat over 16), so nothing would bound it on a log line — rewrite it before saving"`.
  In a batch it is listed in `failed` with `"code": "REGEX_UNDECIDED"`.
- **Indeterminate** otherwise (the budget ran out, or the fallback bounds it):
  saved. The response carries
  `"warnings": ["ReDoS: regex at pattern could not be proven safe (unknown: the analysis hit its time budget)"]`
  (batch responses: `warnings: [{ name, warnings }]`). When the fallback cannot
  bound it, the warning adds that nothing bounds it on a log line until an
  analysis decides it.
- **Checker saturated**: `503` with `"code": "REGEX_BUSY"` — retry; a regex is
  never accepted unchecked.

**Every route that runs a caller's pattern or sample is time-bounded**:
`POST /api/parsers/test`, `POST /api/parsers/:id/test`, the self-tests of
`/validate`, `/import` and catalog installs, and the recommendation dry-runs run
in a pool of worker threads (`REGEX_TEST_WORKERS`, default 2) with a hard budget
(`REGEX_TEST_TIMEOUT_MS`, default 1000 ms). A run past the budget is stopped
(its worker is terminated and replaced) and answers:

```json
{ "code": "REGEX_TIMEOUT", "timeout_ms": 1000,
  "message": "The pattern did not finish within 1000 ms on this input and was stopped. It backtracks catastrophically (ReDoS): ..." }
```

| Status | `code` | When |
|---|---|---|
| `422` | `REGEX_UNSAFE` | A regex is proven ReDoS-vulnerable; nothing was saved. |
| `422` | `REGEX_TIMEOUT` | A test run outlived its budget and was stopped. |
| `422` | `REGEX_TEST_FAILED` | The pattern could not run, e.g. `Invalid regular expression: /(/: Unterminated group`. |
| `413` | `SAMPLE_TOO_LARGE` | A sample over 64 KB (the HTTP log-push message cap), or more than 100 `test_samples`. |
| `503` | `REGEX_BUSY` | The checker or test workers are saturated; retry shortly. |

**Stored regexes** saved before this check existed are analyzed once per start
(in the background). Each vulnerable one is logged as a `WARN` and reported on
the rows of `GET /api/parsers`, `GET /api/parsers/:id`, `GET /api/rules` and
`GET /api/rules/:id` (and on catalog entries) as:

```json
"regex_safety": { "status": "vulnerable", "vulnerable": [ { "location": "pattern", "source": "...", "complexity": "exponential" } ], "unknown": [] }
```

`status` is `none` (no regex), `safe`, `unknown`, `vulnerable` or `pending`
(not analyzed yet). Nothing is disabled automatically; an edit that does not
touch the regexes (enable/disable, rename) is never refused.

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
    "updated_at": "2025-01-01T00:00:00Z",
    "regex_safety": { "status": "safe", "vulnerable": [], "unknown": [] }
  }
]
```

`regex_safety` is the cached ReDoS verdict for the parser's regexes; see
[Regex safety](#regex-safety-parsers-and-rules).

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
  ...,
  "regex_safety": { "status": "safe", "vulnerable": [], "unknown": [] },
  "warnings": []
}
```

`warnings` lists regexes that could not be proven safe (saved anyway).

**Errors:**
- `400` - Missing required fields
- `422` `REGEX_UNSAFE` - The pattern is ReDoS-vulnerable; nothing saved ([Regex safety](#regex-safety-parsers-and-rules))
- `422` `REGEX_UNDECIDED` - The check cannot read the pattern and nothing would bound it at run time; nothing saved
- `503` `REGEX_BUSY` - The regex checker is saturated; retry

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
  ...,
  "warnings": []
}
```

A change to `pattern`, `derivations` or `parser_type` passes the regex check
for the parser as it will be saved (a vulnerable derivation left from before
the check must be fixed in the same edit). Other edits, enable/disable
included, are never refused for a regex they do not touch.

**Errors:**
- `400` - `pattern must be a string`, or `Invalid derivations: …` (the import's
  derivation checks; a `when.*.matches` or `extract.*.pattern` must be a string)
- `404` - Parser not found
- `422` `REGEX_UNSAFE` - A regex is ReDoS-vulnerable; nothing changed ([Regex safety](#regex-safety-parsers-and-rules))

**Errors:**
- `404` - Parser not found
- `422` `REGEX_UNSAFE` - A regex the update would store is ReDoS-vulnerable; nothing changed

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

The saved parser's regexes may predate the regex check, so the run is
time-bounded like `POST /api/parsers/test`.

**Errors:**
- `404` - Parser not found
- `413` `SAMPLE_TOO_LARGE` - Sample over 64 KB
- `422` `REGEX_TIMEOUT` - The parser did not finish within the budget on this sample and was stopped

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

**Use Case:** Frontend parser builder to validate configurations before saving. The pattern is the caller's and has not been through the regex check, so it runs in a worker thread with a hard time budget (`REGEX_TEST_TIMEOUT_MS`, default 1000 ms), never on the event loop; like `POST /api/parsers/validate` this needs analyst or higher, and anyone can test a saved parser with `POST /api/parsers/:id/test`.

**Errors:**
- `400` - Missing required fields
- `413` `SAMPLE_TOO_LARGE` - Sample over 64 KB
- `422` `REGEX_TIMEOUT` - The pattern did not finish within the budget on this sample and was stopped (e.g. `^(?:a|a){1,30}$` on `'a'.repeat(28) + '!'` answers in about 1 s). A pattern V8's linear-time fallback covers (`REGEX_LINEAR_FALLBACK`, on by default; no `i`/`u` flag, lookahead, backreference or counted repeat over 16, and on a backend built on Node 20 no lookbehind), such as `^(a+)+$`, finishes quickly with `"matched": false` instead
- `422` `REGEX_TEST_FAILED` - The pattern does not compile (the message quotes the compiler)
- `503` `REGEX_BUSY` - Every test worker is busy; retry

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
    "updated_at": "2025-01-01T00:00:00Z",
    "regex_safety": { "status": "none", "vulnerable": [], "unknown": [] }
  }
]
```

`regex_safety` covers the rule's `regex` conditions; see
[Regex safety](#regex-safety-parsers-and-rules).

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
- `400` - Missing fields, invalid YAML format, or `Invalid rule: conditions[0].flags must be a string (e.g. "i")` (a `regex` condition's `flags` must be a string and its `value` must not be a list or mapping)
- `422` `REGEX_UNSAFE` - A `regex` condition is ReDoS-vulnerable; nothing saved ([Regex safety](#regex-safety-parsers-and-rules))
- `422` `ATTACK_TAG_INVALID` - A `tags` entry is an unknown, malformed, revoked or deprecated ATT&CK technique, or an unknown tactic; nothing saved. Body: `{ "code": "ATTACK_TAG_INVALID", "message": "Rule \"…\" was not saved: attack.t1086: T1086 \"PowerShell\" was revoked in ATT&CK 20.0; use attack.t1059.001 (…)", "errors": [...], "warnings": [...] }` ([ATT&CK tagging](RULES.md#mitre-attck-tagging))

A `201` carries `warnings` (indeterminate regexes, and ATT&CK notes such as a
tactic tag that none of the rule's techniques belongs to).

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

New rule logic (from `rule_yaml`, or a `rule_logic` sent directly) passes the
regex check; an update that leaves the logic alone (enable/disable) is never
refused for it. New `tags` pass the ATT&CK tag check; a tag the stored rule
already had is not refused again.

**Errors:**
- `400` - Invalid YAML format (if rule_yaml provided), or `Invalid rule: …` (as for `POST`)
- `404` - Rule not found
- `422` `REGEX_UNSAFE` - A `regex` condition is ReDoS-vulnerable; nothing changed
- `422` `ATTACK_TAG_INVALID` - A tag the update adds is not a valid ATT&CK technique or tactic (as for `POST`); nothing changed

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

Install/import is never blind: every item is run through the validator, the
[regex safety check](#regex-safety-parsers-and-rules) and its self-tests before
it is stored. A failing item returns `422` (with the validation / self-test
details) unless you pass `force: true`; a ReDoS-vulnerable regex is refused
(`422 REGEX_UNSAFE`) whatever `force` says. Self-tests run in a time-bounded
worker (`422 REGEX_TIMEOUT`).

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
| `POST /api/parsers/catalog/install-all` | Install or update every catalog parser. Returns `{ total, installed, updated, failed, warnings }`; an item refused for a ReDoS-vulnerable regex is in `failed` with `code: "REGEX_UNSAFE"` and the refusal sentence as `reason`. |
| `POST /api/parsers/catalog/refresh` | Force a catalog cache refresh. Returns `{ refreshed, count }`. |
| `GET /api/rules/catalog` | Browse the detection catalog (same annotations, same `?refresh=true`). Returns `{ source, rules }`. |
| `GET /api/rules/catalog/source` | The configured catalog source. |
| `POST /api/rules/catalog/install` | Install or update a catalog detection by `name`. |
| `POST /api/rules/catalog/install-all` | Install or update every catalog detection. Same `failed` / `warnings` shape; a rule that fails validation (e.g. a revoked ATT&CK technique tag) is in `failed` with `reason: "failed validation: …"` and the validator's messages. |
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
| `POST /api/parsers/validate` | Validate a portable parser and run its self-tests without saving. Body: `{ "parser": { … }, "strict": false }`. Applies the import's regex check: `422 REGEX_UNSAFE` or `REGEX_UNDECIDED` for what the import would refuse, `422 REGEX_TIMEOUT` when a self-test outlives its budget, `413` for oversized samples; indeterminate regexes appear in `validation.warnings`. |
| `POST /api/parsers/import` | Import a portable parser. Body: `{ "parser": { … }, "force": false }`. Validated + regex-checked + self-tested before upsert; `422` on failure unless `force` (never for `REGEX_UNSAFE`). |

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
| `GET /api/settings/ai` | Current AI Builder config: `provider`, `model`, `baseUrl`, `configured`, `keySource` (`stored`, `env` or `none`: where the key it sends comes from), `keySaved` (a key is saved for this config), `keyMismatch` (that key was saved for another provider or base URL, so it isn't sent) and `keySavedFor`: `{ "provider": "…", "baseUrl": "…" }`, the provider and base URL (normalized) that saved key was saved for, or `null` when no key of its own is saved or it can't be read. A change of provider or base URL back to `keySavedFor` needs no `apiKey`. The key itself is never returned. |
| `PUT /api/settings/ai` | Update the AI Builder config. Body (all optional): `{ "provider": "anthropic" \| "openai" \| "ollama", "model": "…", "baseUrl": "…", "apiKey": "…" }`. Pass `apiKey` to set it (encrypted at rest via `CREDENTIAL_ENCRYPTION_KEY`), or `""` (or `null`) to clear it. `baseUrl` is at most 2048 characters (`400` otherwise). A change of `provider` or `baseUrl` while a key is saved needs `apiKey` in the same request, see [below](#a-saved-key-only-goes-where-it-was-saved-for). Answers with the same fields as the `GET`. |
| `GET /api/settings/ai-chat` | Current AI Analyst config: the fields of `GET /api/settings/ai`, plus `inheritsFrom` (`main` while it has no provider of its own) and `ownBaseUrl`: its own base URL setting, `""` when it has none (it then uses the AI Builder's on the same provider, else the provider's default). `baseUrl` is the one it uses. A form that edits the config sends `ownBaseUrl` back, so a blank one keeps following the AI Builder. |
| `PUT /api/settings/ai-chat` | Update the AI Analyst config. Body as for `PUT /api/settings/ai`; `"provider": ""` reverts to inheriting the AI Builder's provider. A model or base URL left blank is the AI Builder's when the provider is the same, else the provider's default. The Settings page sends `"model": ""` and `"baseUrl": ""` with `"provider": ""` (and `"apiKey": ""` when the analyst has a key of its own), so that inheriting takes everything from the AI Builder. |

> Storing a key from the UI requires `CREDENTIAL_ENCRYPTION_KEY` to be set;
> alternatively provide the key via the `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`
> environment variable.

#### A saved key only goes where it was saved for

A key saved through these routes, and through `PUT /api/settings/ai-triage`
below, is stored with its target: the provider and the base URL requests go to
(for Anthropic always `https://api.anthropic.com`, which doesn't use the base
URL). SIEMBox only sends it there.

- A `PUT` that changes the config's provider or base URL while it has a key
  saved needs `apiKey` in the same request: the key for the new provider or
  base URL, or `""` to remove the saved one (the `ANTHROPIC_API_KEY` or
  `OPENAI_API_KEY` environment variable is then used, if set). Without it the
  answer is `400` and nothing in the request is saved:

  ```json
  { "status": "error", "statusCode": 400, "message": "apiKey is required: this changes the AI Builder provider or base URL, and its saved API key is only sent to the provider and base URL it was saved for. Send the API key for the new one as apiKey, or apiKey \"\" to remove the saved key (the ANTHROPIC_API_KEY or OPENAI_API_KEY environment variable is then used, if set)." }
  ```

  Switching to Ollama, which uses no key, needs `"apiKey": ""` too; so does a
  move back to inheriting (`"provider": ""`) that changes where the config sends
  requests. A move back to the target the saved key was saved for needs nothing.
- Base URLs are compared normalized, so a value sent back unchanged is not a
  change, and neither are a trailing slash, the host's letter case or the
  default port written out. An empty base URL, or one of only spaces, is the
  provider's default (or the parent's, see above). `model` and `baseUrl` are
  saved without surrounding spaces. Changing only the model, or the Anthropic
  base URL, keeps the key.
- A config with no key of its own can change freely: the key it sends then
  comes from its parent or an environment variable. A parent's saved key (the
  AI Builder's for the AI Analyst, the AI Analyst's for AI Triage) is only used
  while the config sends requests where the parent does. The AI Analyst set to
  OpenAI at another base URL doesn't get the AI Builder's OpenAI key.
- An environment variable key is not bound: `OPENAI_API_KEY` is sent to
  whichever OpenAI base URL is configured.
- When the target of a config's own key moves with its parent (an AI Analyst
  on the same provider as the AI Builder, with no base URL of its own, after the
  AI Builder's base URL changes), the key stays saved but isn't sent:
  `keyMismatch` is `true` and the config uses its parent's key or the
  environment variable. Enter its key again, or point it back: `keySavedFor`
  says where (the Settings page shows it on the card), and a `PUT` with that
  provider and base URL needs no `apiKey`.
- The key itself is stored as earlier versions store it (`ai_api_key`,
  `ai_chat_api_key`, `ai_triage_api_key`, each encrypted on its own), and its
  target in a row next to it (`ai_api_key_target`, ...), encrypted together
  with a hash of the key so it only applies to that key. An earlier version
  rolled back to (`SIEMBOX_VERSION`) still uses the saved keys.
- A key with no target recorded (saved by an earlier version, or replaced by
  one after a rollback) counts as saved for where its config sends requests;
  the next save of any of the three configs records that target before it
  changes anything. A key an earlier version kept while it changed the
  config's provider or base URL stays bound to where it was saved
  (`keyMismatch`).
- Each save is one transaction, and saves of the three configs run one at a
  time, so no request is ever sent with a key and an address from different
  saves.
- `model` and `baseUrl` must be strings when sent, `apiKey` a string or `null`,
  and `baseUrl` at most 2048 characters (`400` otherwise; nothing in the
  request is saved).

### AI Triage Settings

Automatic, agentic per-alert analysis — see [AI Security Analyst → Automated triage](../../wiki/AI-Security-Analyst.md#automated-triage). Off by default.

**Authentication:** Admin (`GET /api/ai/triage/health` below is available to any authenticated user — a non-secret subset used to gate the UI).

| Method & Path | Purpose |
|---|---|
| `GET /api/settings/ai-triage` | Current triage config: provider/model/baseUrl (inherits AI Analyst if unset), `configured`, `keySource`, `keySaved`, `keyMismatch`, `keySavedFor`, `inheritsFrom` and `ownBaseUrl` as for `GET /api/settings/ai-chat` (the parent being the AI Analyst), plus operational settings (`enabled`, `minSeverity`, `dailyCap`, `maxConcurrent`, `dedupeHours`, `maxToolCalls`, `wallBudgetSeconds`). Key itself is never returned. |
| `PUT /api/settings/ai-triage` | Update triage config. Body (all optional): `{ "provider": "anthropic" \| "openai" \| "ollama" \| "", "model": "…", "baseUrl": "…", "apiKey": "…", "enabled": true, "minSeverity": "medium", "dailyCap": 200, "maxConcurrent": 2, "dedupeHours": 6, "maxToolCalls": 6, "wallBudgetSeconds": 110 }`. Empty `provider` reverts to inheriting the AI Analyst config. A change of provider or base URL while a key is saved needs `apiKey` in the same request ([A saved key only goes where it was saved for](#a-saved-key-only-goes-where-it-was-saved-for)); a refused request saves none of its fields, the operational ones included. `maxToolCalls` (1-12) and `wallBudgetSeconds` (20-280) bound how deep/long a single alert's analysis can go before it's forced to synthesize a verdict from whatever it has. |
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
| `technique` | string | - | ATT&CK technique ID (`T1110`, `T1110.001`, any case). A technique matches its sub-techniques too; a sub-technique matches only itself. `400` if malformed |
| `tactic` | string | - | ATT&CK tactic shortname (`credential_access` or `credential-access`): alerts with any technique under it. With `technique`, both must hold. `400` if unknown |
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
      "triage_risk_score": 82,
      "attack_techniques": ["T1110.001"]
    }
  ],
  "total": 87,
  "limit": 50,
  "offset": 0
}
```

`attack_techniques` are the raising rule's ATT&CK technique IDs when the alert
was created (from its `attack.t…` tags, upper case), kept if the rule is
re-tagged later; `[]` for untagged rules and non-rule alerts (EDR, exposure,
sign-in). `GET /api/alerts/export` accepts `technique` and `tactic` too.

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
    "created_at": "2025-01-01T00:00:00Z",
    "must_change_password": false,
    "must_change_password_reason": null,
    "must_change_password_since": null
  },
  {
    "id": 2,
    "username": "analyst1",
    "email": "analyst@example.com",
    "role": "analyst",
    "enabled": true,
    "last_login": "2025-11-30T10:00:00Z",
    "created_at": "2025-01-15T00:00:00Z",
    "must_change_password": true,
    "must_change_password_reason": "admin",
    "must_change_password_since": "2025-11-30T09:55:00.000Z",
    "signin_paused_until": "2025-11-30T12:12:00.000Z",
    "signin_pause_scopes": ["acct"],
    "password_change_paused_until": null
  }
]
```

`signin_paused_until` is when the account's last sign-in pause ends (`null`
when none is running), and `signin_pause_scopes` which of its keys are paused:
`aip` (from one network), `acct` (from new browsers on every network), `br`
(one of its recognized browsers, after that browser's own failures), `mfa`,
and `ip` when a paused network holds them back because they failed from it in
the last 15 minutes (until then, or until the network's current pause ends if
that is sooner; if it is paused again within those 15 minutes, they are listed
again; Unlock clears their own counters, which lets them in).
`password_change_paused_until` is when the pause on changing their own
password (`pwc`, wrong current passwords) ends: it doesn't stop them signing
in, so it is not a sign-in pause. See
[Sign-in Protection](#sign-in-protection) and
[`POST /api/users/:id/unlock`](#post-apiusersidunlock).
`must_change_password` (with `_reason` and `_since`) is `true` while the
account must choose a new password at its next sign-in before it can do
anything else (see [Password change required](#password-change-required)).

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
  "enabled": true,
  "mustChangePassword": true
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
  "must_change_password": true,
  "must_change_password_reason": "admin",
  "must_change_password_since": "2025-11-30T12:00:00Z",
  "created_at": "2025-11-30T12:00:00Z"
}
```

**Validation:**
- Password must be 8 to 1024 characters, and not the default password
  `changeme` in any letter case
- Username and email must be unique
- `mustChangePassword` (optional, default `true`): the password you set is
  temporary, and the user must choose their own at the first sign-in
  (`reason: "admin"`). `false` lets them keep it.

Audited as `user.created`, with `passwordChangeRequired` (`"admin"` or `null`).

**Errors:**
- `400` - Missing fields, `"Password must be 8 to 1024 characters"`,
  `"Password can't be the default password"`, or `"mustChangePassword must be
  true or false"`
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
  "password": "newpassword123",
  "mustChangePassword": true
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

**Notes:**
- Setting `password` is a reset: the user is signed out everywhere, their
  recognized browsers are forgotten and their sign-in counters cleared.
  Audited as `user.password_reset` (with `passwordChangeRequired`); other
  changes as `user.updated`.
- `mustChangePassword` (default `true`) applies only with `password`: the new
  password is temporary and the user must choose their own at the next
  sign-in (`reason: "admin"`, replacing any earlier reason). `false` lets them
  keep it, and lifts any earlier requirement. Without `password` the
  requirement is left as it is: it can't be lifted without replacing the
  password it is about, or set without handing over one the user knows.
- `"enabled": true` for a disabled account still required to change the
  default password `changeme` (`reason: "default"`, for example an admin the
  upgrade scan found while it was disabled) raises the default-password
  `siembox-auth` alert, once per requirement: from now on anyone could sign
  in as it and choose its password. Send a `password` in the same request to
  replace it instead.

**Errors:**
- `400` - `"Password must be 8 to 1024 characters"`, `"Password can't be the
  default password"`, `"mustChangePassword must be true or false"`, or
  `"mustChangePassword applies only when setting a password"`
- `404` - User not found
- `409` - Email or username already taken

---

### POST /api/users/:id/unlock

Clear every sign-in counter of the account (admin only): its pauses from every
network, from new browsers, of its recognized browsers, its MFA codes and its
password changes end at once. A network-wide pause is not the account's:
clear it with [`POST /api/admin/sign-in-protection/clear`](#post-apiadminsign-in-protectionclear).
Audited as `auth.unlock`.

**Authentication:** Required (Admin)

**Response (200):** `{ "cleared": 2 }` (how many counters were removed)

**Errors:** `404` - User not found

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
- All user's sessions, recognized browsers and sign-in counters are removed

**Errors:**
- `400` - Attempting to delete own account
- `404` - User not found

---

## Settings Endpoints

Every `/api/settings` route requires a login. The routes in this section and
under [AI Settings](#ai-settings) also require the **admin** role, except
`GET /api/settings/syslog` (the syslog host and port that shippers send to) and
[`GET /api/settings/onboarding`](#get-apisettingsonboarding) (whether Getting
Started setup is done). Other roles get `403 Access denied. Required role: admin`.

### GET /api/settings

Every row of `system_settings`, for scripts and troubleshooting (admin only).
The web UI doesn't call it: each settings page uses its own route below.

**Authentication:** Required (Admin)

Stored credentials are never returned, not even to an admin. These are the AI
builder, AI Analyst and AI Triage API keys (`ai_api_key`, `ai_chat_api_key`,
`ai_triage_api_key`), the AbuseIPDB and OTX keys (`ti_abuseipdb_key`,
`ti_otx_key`) and the Have I Been Pwned key (`exposure_hibp_key`). A withheld
row has `redacted: true`. Its `setting_value` is `"[redacted]"` when a value is
stored and `""` when none is, and `configured` gives the same answer as a boolean.

The rule fails closed. A value is returned only when all three of these hold:
- The key is on the reviewed list of plain settings (`READABLE_SETTING_KEYS` in
  `backend/src/services/settings/settingsRedaction.ts`). A key that isn't on
  it, such as a setting added after this release, is withheld until it's added.
- The key isn't named like a credential: none of its words is a word such as
  `key`, `token`, `secret`, `password`, `hash` or `credential` (the full list is
  `SECRET_KEY_WORDS` in the same file). That covers `*_key`, `*_api_key`,
  `*_token`, `*_secret`, `*_password` and `*_hash`.
- The value doesn't hold an encrypted credential (`{ "encrypted", "iv", "authTag" }`).

**Response (200):**
```json
[
  { "setting_key": "ai_api_key", "setting_value": "[redacted]", "redacted": true, "configured": true },
  { "setting_key": "ai_model", "setting_value": "claude-sonnet-4-6", "redacted": false },
  { "setting_key": "exposure_hibp_key", "setting_value": "", "redacted": true, "configured": false },
  { "setting_key": "retention_raw_logs_days", "setting_value": "30", "redacted": false }
]
```

(Earlier versions returned every row to any logged-in role, viewers included,
along with each stored key's encrypted envelope.)

---

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

### GET /api/settings/onboarding

Whether an administrator has marked the Getting Started setup done. It is
install-wide, stored in the `onboarding_completed` row of `system_settings`
(created on the first write). While it isn't done, administrators get a
reminder on the Dashboard; the Getting Started checklist itself stays in the
sidebar for everyone.

**Authentication:** Required (any role)

**Response (200):**
```json
{ "completed": true, "completed_at": "2026-10-12T09:30:00.000Z", "completed_by": "admin" }
```
- `completed_at` is when it was first marked done (`null` when not completed).
- `completed_by` is the admin who did, for admins only: it is `null` for every
  other role (it would reveal an admin's username), and for a completion
  migrated from a browser that couldn't say who.

### PUT /api/settings/onboarding

Mark setup done, or bring the Dashboard reminder back for every administrator.

**Authentication:** Required (Admin)

**Request Body:** `{ "completed": true }`, `{ "completed": false }` or
`{ "completed": true, "legacy": true }`. Unknown keys are ignored.
- `{ "completed": true }` is atomic and idempotent: the first completion's
  `completed_at` and `completed_by` are kept, whatever later or concurrent
  requests do.
- `{ "completed": false }` reopens it: the reminder is back for every admin, in
  every browser.
- `{ "completed": true, "legacy": true }` migrates a browser's pre-server-side
  dismissal (the `onboarding_dismissed` localStorage flag). It applies only when
  nothing was ever recorded, so a stale browser can never undo an admin's
  reopen; otherwise it changes nothing. It is recorded with `completed_by:
  null`: the flag doesn't say who dismissed the reminder, so the admin whose
  browser carried it over isn't credited. The web UI sends it once, from an
  admin's browser that still holds the flag.

**Response (200):** the state, as `GET` returns it to an admin.

**Errors:**
- `400` - not a JSON object (`"Expected a JSON object such as {\"completed\": true}"`),
  `completed` not a boolean, `legacy` not a boolean, or `legacy` with
  `"completed": false` (`"legacy applies only to {\"completed\": true}"`)
- `403` - not an admin; nothing changes

To bring the reminder back as if setup had never been recorded, delete the row:
`DELETE FROM system_settings WHERE key = 'onboarding_completed';`

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

Each `tls_subjects` entry is `{ "port": 8006, "subject_cn": "pve", "san": ["DNS:pve"] }`. `subject_cn` is an array of strings when the certificate's subject repeats CN (`["proxmox.local", "pve"]`); a fingerprint's TLS signal matches if any of them contains its text. Entries without an integer `port` are dropped.

**Request Body — failure:**
```json
{ "api_key": "<shipper api key>", "scan_id": 7, "error": "node runtime not available on the shipper" }
```

**Response (200):** `{ "status": "completed" }` or `{ "status": "failed" }`

**Errors:**
- `400` - Missing `api_key`, non-positive `scan_id`, or neither `signals` (array) nor `error`
- `404` - Invalid API key, or the discovery scan isn't assigned to this shipper
- `422` - the signals could not be ingested at all (the scan is marked `failed`). One host that can't be matched or saved doesn't cause this: it is skipped, the scan completes, and the host is counted in the scan's `results_summary.hosts_failed`.

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
SIEMBOX pulls that source's events on a schedule instead. How a source is
reached (address of a manual source, port, HTTPS, endpoint path) can be changed
later with [`PATCH /sources/:id`](#patch-apilog-discoverysourcesid). See
`backend/src/services/logDiscovery/apiPoll/`.

**Home Assistant** serves its log in one of two places, depending on the install:
`/api/error_log` returns the log file, which Container and Core installs write by
default (not with `HA_DISABLE_LOG_FILE=true`); Home Assistant OS and Supervised
installs write no log file (unless `HA_DUPLICATE_LOG_FILE` is set), so there
`/api/error_log` answers `404` and the log comes from the Supervisor through
`/api/hassio/core/logs`. The poller asks `/api/error_log` first and on a `404` uses
`/api/hassio/core/logs?no_colors` with a `Range: entries=…` header for the latest
journal entries (how many is described below). It remembers which endpoint works
for each source (in the poll cursor), so it doesn't send a doomed request every
poll, and re-probes `/api/error_log` every 6 hours and whenever the remembered
endpoint fails. An endpoint set with `PATCH /sources/:id` is used alone. Lines are stored in Home
Assistant's own format (colour codes removed), as the catalog parser expects. Both
endpoints are admin-only: the token must be a long-lived access token created by
a Home Assistant administrator.

Only the end of the log is read. The file is requested with a byte range for its
last 5 MB plus the lines the poll resumes after (`Range: bytes=-5242880` on a
first poll, and that plus their size after; a server that ignores the range sends
the whole file and the same last bytes are kept), so a log that has grown past
5 MB keeps being collected, and up to 5 MB logged since the last poll is
collected whole. When more was logged since the last poll, so that the lines the
poll resumes after are not all in the answer, every whole line of it is
collected, except those it starts with that the last poll collected already (it
began inside that record), and a warning is logged to the error log: the lines
before them were not collected, or, when the answer may have begun inside the
last record collected, may not have been. (When the whole file was read and lacks
those lines, it is a new file, started by a restart: its last 200 lines are
collected, as on a first poll.) A cursor stored by an earlier version, which
read only the first 5 MB (5,242,880 characters) of a longer log, ends where that
read ended, usually in a cut line. The first poll after an upgrade resumes
there: it collects that line whole (the earlier version stored only its start)
and every line after it. A cursor that holds a record's timestamped first line
is found wherever it is. In a traceback that repeats, every copy has the
cursor's lines, so the copy at the 5 MB mark is told from the others by where
the answer starts in the file (its `Content-Range`); if the log has grown more
than 5 MB past the mark, the copies in the answer are all later ones, so all of
it is collected and the warning is logged. This is exact for a log that is ASCII
up to the mark. The earlier version decoded the log in the pieces the network
delivered, so a character outside ASCII that fell across two of them counted as
two or three, and its mark fell up to that much earlier: with such characters in
the answer before the mark, the poll resumes at the earliest copy of the cut
line within that distance of the mark (a character for each UTF-8 byte beyond a
character's first), collecting the lines from there to the mark again, once. The
bytes before the answer are counted as characters to place the mark, so a
character outside ASCII there puts the real mark later than counted. When the
mark can't be placed (such a character before the answer, a split one when the
mark fell at a line's end, or a server that ignores the range), the poll resumes
at the first copy in the answer instead, or, when the mark seems to be before
the answer, collects all of it and logs the warning; lines from there to the
mark are collected again, once. None of these skips a line of the answer. A poll
resumes after the last record it saw, matched from that record's timestamped
first line to its end, so a traceback that repeats is not collected again; this
holds for a record of up to 2000 lines and about 256 KB (a longer one is matched
by its last 100 lines only). A last
line without its newline, which Home Assistant is still writing, is left for the
next poll. The Supervisor is asked for 500 new journal entries plus the lines the
poll resumes after (at least three: `Range: entries=:-502:503` after short
records); a first poll, which collects the last 200 lines, asks for 2500
(`entries=:-2499:2500`) so that it reaches the start of the last record. When
those lines are not in the answer, more than 500 lines arrived, and the
Supervisor is asked again for 5000 new entries plus them (`entries=:-5002:5003`).
If they are not in that answer either, more than 5000 lines arrived: the latest
5000 are collected and a warning is logged to the error log.

**Access:** every route requires a login. Reads (and the read-only `onboard/preview`) are open to any role. Starting or cancelling a scan and the source actions `confirm`, `ignore` and `onboard/confirm` require admin or operator, the roles that can open the Log Discovery page. Changing the scan scope, manual sources, a source's poll target and poll credentials requires admin. See [Roles for scan and asset writes](#roles-for-scan-and-asset-writes).

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
  "results_summary": {
    "hosts_seen": 24,
    "hosts_matched": 9,
    "hosts_failed": 1,
    "host_errors": [{ "ip": "192.168.1.20", "error": "..." }]
  },
  "assigned_shipper_id": null,
  "assigned_shipper_name": null
}
```
- `status` - `queued` (dispatched to a shipper, awaiting claim), `running`, `completed`, or `failed`. An in-process scan starts straight at `running`.
- `results_summary.hosts_failed` - hosts the scan saw but couldn't match or save. They are skipped and the rest of the scan completes; `host_errors` (present only when some failed) lists the first 20 with their error. Scans from before this field have no `hosts_failed`.
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
      "reason": "OPNsense can provide firewall logs, network traffic flow, dns queries.",
      "poller": {
        "configured": false,
        "enabled": false,
        "last_status": null,
        "last_polled_at": null,
        "last_error": null,
        "effective_url": null
      }
    }
  ],
  "advanced": []
}
```

`poller` summarizes API polling for the source: whether a credential is saved
(`configured`) and polling is on, the last poll's `last_status`, `last_polled_at`
and `last_error`, and `effective_url`, the URL being polled: scheme, host, port
and path, never a token or query string (for Home Assistant, the endpoint in use,
e.g. `http://192.168.1.50:8123/api/hassio/core/logs` after the automatic
fallback). `effective_url` is `null` when no credential is saved.

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
- `ip_address` (required) - a **literal** IPv4/IPv6 address (a DNS name, or an IPv6 zone index such as `fe80::1%eth0`, is rejected with `400`; the column is `INET`)
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

### PATCH /api/log-discovery/sources/:id

Change how SIEMBOX reaches an API-polled source: its port, HTTPS on/off, the API
endpoint path, and, for a **manually added** source only, its address. This is the
**Edit** action on the Log Discovery page and under Log Shippers → API-Polled
Sources.

- A **manual** source's settings are updated where `POST /sources/manual` keeps
  them: the row's `ip_address`, and `evidence` (`target_port`, `tls`, plus
  `endpoint` when one is set); `open_ports` follows the port. A re-scan of the
  host keeps these keys.
- A **scan-discovered** source's settings go to its `poll_overrides`
  (`{port, tls, endpoint}`, migration `036`), which a re-scan never touches. Its
  address is the one the scan found and cannot change. With no overrides it is
  polled at exactly the URL it always was.
- A new `endpoint` or address clears the poll cursor, so the next poll starts
  fresh. That poll reads the source's recent events again (for Home Assistant the
  last 200 lines, so lines already stored may be stored twice). A port or HTTPS
  change keeps the cursor.
- A saved token is never sent to a new address. Changing a manual source's
  address while it has a saved token requires the token again in `credential`;
  the move and the token swap are applied in one database update, and each poll
  reads the token and the address together when it starts, so no poll can pair
  the old token with the new address. Without `credential` the request is a
  `400` and nothing changes. A source with no saved token can move freely.
- With `expected_ip_address` (the address the client loaded; the Edit dialog
  always sends it), the change applies only while the source still has that
  address: if another admin moved it meanwhile, the request is a `409` and
  nothing changes. Reload the source and try again.
- The change is also only written if, at that moment, the source still has the
  address and the settings (port, HTTPS, endpoint) it was checked against and
  merged with (and, for a move without a token, still has no saved token): the
  source row is locked for the write, so a token save and a move never overlap,
  and two edits never combine or undo each other. If another admin's edit of
  this source got in first, or a token save got in before a move without a
  token, the request is a `409` and nothing changes. A token save for the
  source's current address does not conflict with a change that keeps the
  address: both apply. A poll that was already running when the source moved or
  its endpoint changed does not overwrite the cleared cursor; other changes made
  while a poll runs (the interval, polling on or off, a new token for the same
  address) don't change where the next poll resumes.
- Otherwise the saved credential, the schedule and the poll status are not
  changed, and no credential is ever returned.

**Authentication:** Required (**admin**)

**Request Body** (send only what changes; `null` returns a setting to its default):
```json
{ "port": 8123, "tls": false, "endpoint": "/api/hassio/core/logs", "ip_address": "192.168.1.60", "expected_ip_address": "192.168.1.50" }
```
- `port` - integer `1`–`65535`, or `null` for the default (a discovered source: the adapter's own port; a manual source: the fingerprint's `api_pull` `target_port`)
- `tls` - boolean, or `null` for the default (a manual source: `true` for `authentik`, `false` otherwise)
- `endpoint` - a path on the source itself, e.g. `/api/hassio/core/logs`, or `/ha/api/error_log` behind a reverse proxy. It must start with a single `/` (no scheme or host) and may not contain a query string or fragment, `.` or `..` segments, control characters, whitespace, backslashes or `%`-encoding; at most 256 characters. An endpoint that is set is the only one requested (Home Assistant's automatic fallback is off). `""` or `null` restores the fingerprint's endpoint.
- `ip_address` - manual sources only: a literal IPv4/IPv6 address, validated exactly like `POST /sources/manual`. Sending a discovered source's current address back is accepted and changes nothing; a different one is refused with `403`.
- `credential` - `{ "secret": "...", "username": "..." }`, required together with a changed `ip_address` when the source has a saved token, and accepted only then (otherwise `400`; to replace a token without moving the source use `POST /sources/:id/poller/credential`). `secret` is a non-blank string of at most 4096 characters; `username` (HTTP Basic sources such as AdGuard Home) at most 255. It is encrypted like any saved token and never returned.
- `expected_ip_address` (optional) - the source's address as the client loaded it, a literal IPv4/IPv6 address (however IPv6 is written). Not a change by itself. If the source no longer has it, the request is a `409` and nothing changes; without it, the change applies to the source wherever it is now.

**Response (200):**
```json
{
  "source": { "id": 94, "ip_address": "192.168.1.50", "evidence": { "manual": true, "target_port": 8123, "tls": false, "endpoint": "/api/hassio/core/logs" }, "poll_overrides": null },
  "poller": { "configured": true, "fingerprint_id": "home-assistant", "enabled": true, "poll_interval_minutes": 5, "last_status": "error", "last_error": "Home Assistant at http://192.168.1.50:8123 answered 404 for both log endpoints. ..." },
  "target": {
    "fingerprint_id": "home-assistant",
    "manual": true,
    "ip_address": "192.168.1.50",
    "port": 8123,
    "tls": false,
    "effective_url": "http://192.168.1.50:8123/api/hassio/core/logs",
    "overrides": { "port": 8123, "tls": false, "endpoint": "/api/hassio/core/logs" },
    "defaults": { "port": 8123, "tls": false, "endpoint": "/api/error_log" }
  }
}
```
`source` is the full `discovery_sources` row (abridged above); `poller` is the same
shape as `GET .../poller` (`{ "configured": false }` before a credential is saved);
`target` is described there. Call `POST /sources/:id/poller/run-now` to poll at once.

**Errors:**
- `400` - an invalid field (the message names it and the rule), an empty body, or a source whose device type has no API pull method
- `403` - caller is not an admin, or a new `ip_address` for a scan-discovered source
- `404` - no source with that id
- `409` - the new address already belongs to another source, the source no longer has `expected_ip_address`, or the source changed while this request was being checked (another admin's edit of it, or a token saved before a move without a token); nothing was changed

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

Poller status for a source, and how it is reached (`target`). Never includes the credential itself.

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
  "last_event_count": 3,
  "target": {
    "fingerprint_id": "authentik",
    "manual": false,
    "ip_address": "192.168.1.20",
    "port": 9443,
    "tls": true,
    "effective_url": "https://192.168.1.20:9443/api/v3/events/events/",
    "overrides": { "port": null, "tls": null, "endpoint": null },
    "defaults": { "port": 9443, "tls": true, "endpoint": "/api/v3/events/events/" }
  }
}
```
**Response (200) — not configured:** `{ "configured": false, "target": { ... } }`

`target` is what the edit dialog shows: `port` and `tls` in use (an override, else
the default), `effective_url` (the URL being polled: scheme, host, port and path,
never a token or query string), the stored `overrides` (for a scan-discovered
source `null` where the default applies; a manual source always has its port and
scheme), and the `defaults`. `manual` says whether the address can be changed.
`target` is `null` when the source's device type has no API pull method.

---

### POST /api/log-discovery/sources/:id/poller/credential

Save (or replace) the token for this source's `api_pull` method and start polling it. Resolves the fingerprint's `api_pull` entry itself (not `method_index` -- most fingerprints list a `file`/`syslog_push` method first), so this always targets the right one regardless of what's shown in the onboarding dialog. Also sets `selected_log_access` and marks the source `onboarded`, same outcome as the manual `onboard/confirm` flow.

**Authentication:** Required (Admin)

**Request Body:**
```json
{ "username": null, "secret": "the-api-token-or-password", "expected_ip_address": "192.168.1.50" }
```
- `secret` (required) - the token/password. Encrypted at rest (AES-256-GCM); never returned again after this call.
- `username` (optional) - only used by HTTP Basic auth sources (AdGuard Home today); at most 255 characters
- `expected_ip_address` (optional) - the source's address the token was entered for, a literal IPv4/IPv6 address. The token is saved only while the source still has it, checked again as it is written with the source row locked; if the source was moved meanwhile (`PATCH /sources/:id`), the request is a `409` and nothing is saved, so a token entered for one address never reaches another. The Log Discovery UI always sends it: the address it showed when the token was typed, even if it has shown another one since. Without it, the token is saved for the source at whatever address it has now.

**Response (200):** Same shape as `GET .../poller` above.

**Errors:**
- `400` - missing/empty `secret`, a `username` over 255 characters, an `expected_ip_address` that is not a literal IP address, source has no matched fingerprint, or the fingerprint has no `api_pull` log-access method
- `404` - source or fingerprint not found
- `409` - the source no longer has `expected_ip_address`; nothing was saved

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

Poll immediately instead of waiting for the next scheduled cycle -- for UI feedback right after saving a credential or editing the source.

**Authentication:** Required (Admin)

**Response (200):**
```json
{ "ok": true, "count": 3 }
```
A failed poll is still a `200`, with `ok: false` and `error`, the same text that is
stored as `last_error`. The text says what to do, for example (Home Assistant):
- `Home Assistant rejected the token (HTTP 401 from /api/error_log): it is invalid or revoked, or it belongs to a user who is not an administrator. ...`
- `Home Assistant at http://192.168.1.50:8123 answered 404 for both log endpoints. ...`
- `Home Assistant could not get its log from the Supervisor (HTTP 502 from /api/hassio/core/logs): ...`
- `Couldn't connect to http://192.168.1.50:8124/api/error_log: connection refused; check the address and port (...)`

See [Troubleshooting: API-polled sources](../operations/TROUBLESHOOTING.md#issue-an-api-polled-source-keeps-failing-home-assistant-http-404-from-error_log).

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
check; no key needed). HIBP's breach data is licensed
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/): every finding carries
`detail.source = "hibp"` and `detail.attribution = "https://haveibeenpwned.com"`,
and its alert description ends with
`Source: Have I Been Pwned (https://haveibeenpwned.com), licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/).`
(findings recorded before this licence line was added say
`Source: Have I Been Pwned (https://haveibeenpwned.com).`). When HIBP passes on
a credit the breach's provider asked for, the finding also carries it as
`detail.breach_attribution` (plain text: a handle, an address or a URL). Keep
that attribution wherever the data is shown; the UI credits HIBP on every
surface that lists leaked-credential alerts or findings. Pwned Passwords needs
no attribution, but the password check credits it anyway.

**Authentication:** every endpoint requires a session. Reads (and the password
check) are open to any authenticated user, except the HIBP account's own data
(its verified domains and plan, `GET /providers/hibp/verified-domains`), which,
like the key test, is admin-only; **all writes require the admin role**.

The UI shows these reads to every role on the **Digital Risk** page
(`/digital-risk`): monitoring health, [`GET /summary`](#get-apiexposuresummary)'s
tiles, trend, accounts and lookalikes, the findings queue and the password
check. Admins configure the feature under Settings → Digital Risk.

### How leaked-credential checks run

- A background job (`leaked-creds` in [`GET /api/admin/jobs`](#get-apiadminjobs))
  wakes every 15 minutes and checks the identities that are **due** — never
  checked, or last checked more than their own `interval_minutes` ago (daily by
  default) — one at a time.
- `email` identities use HIBP's breached-account search. `email_domain`
  identities use the domain search, which only works for domains **verified on
  the key's HIBP account** (in the
  [HIBP dashboard](https://haveibeenpwned.com/Dashboard/Redirect/Domains)); it
  yields one finding per alias + breach.
- **Verified domains.** Before searching a due email domain, a run makes sure
  it knows which domains the key's account has verified: HIBP's
  [`subscribeddomains`](https://haveibeenpwned.com/API/v3#SubscribedDomains)
  list (plus the plan from `subscription/status`), kept as one snapshot. It is
  re-read only by a run with a due email domain, when there is no list for the
  saved key, the last success is 6 hours old (1 hour when a due domain would be
  skipped, or after HIBP refused a listed domain), or the last attempt failed 30
  minutes ago (6 hours after a `401`; after a `429`, once its `retry-after` has
  passed); and by an admin's re-check
  ([`POST /providers/hibp/verified-domains/refresh`](#post-apiexposureprovidershibpverified-domainsrefresh),
  at most once a minute). **No page load or `GET` ever calls HIBP.**
- **Unverified domains are skipped, not failed.** A domain a complete list
  doesn't include is not searched (HIBP would refuse it with a `403`): it gets
  `last_status: "unverified"` with an explanation in `last_error`, waits its
  interval, and counts in the run summary's `unverified`, never in `failed`.
  When a re-check lists it as verified it is due again straight away. If the
  list couldn't be read (a `401`, `5xx`, network error, or an unexpected answer
  such as a `404`), or is incomplete (more than 2,000 domains, or unreadable
  entries) and doesn't include the domain, the domain is searched as before, and
  a `403` on that search also reads as `unverified`. A `403` from the
  `subscribeddomains` call itself means the plan has no domain search (High RPM
  plans): email domains are then skipped and email addresses still checked. A
  `403` for a domain the list shows **as verified** is recorded as an error
  (`last_status: "error"`): the plan may not cover that many domains, or the
  domain was just removed from the dashboard.
- **Plan size.** A verified domain larger than the plan covers is not refused:
  HIBP answers with only its subscription-free breaches. SIEMBox compares the
  domain's breached-address count (at the last renewal, else the current one)
  with the plan's `DomainSearchMaxBreachedAccounts` and reports the domain as
  `verified_limited` ("may be limited"; the count includes breaches HIBP
  doesn't charge for, so this can over-warn near the limit).
- **Names.** Matching is exact: each subdomain is a separate HIBP domain in both
  directions (`example.com` verified doesn't cover `mail.example.com`, nor the
  other way round), and internationalized names are matched in punycode.
- HIBP asks that domain searches be made "infrequently, usually only after a new
  breach is loaded": the default daily interval is fine, while an hourly
  `interval_minutes` on an email domain works against that guidance.
- Calls are paced to the key's plan (requests per minute from HIBP's
  subscription status; 10/min until known), and a run and an admin's re-check
  share one pacer, so they never burst. A `429` (from any keyed call, the
  verified-domain list included) pauses all checks until HIBP's `retry-after`
  has passed, a run already in progress included. HIBP's limit belongs to the
  key: saving the same key again doesn't lift the wait, nor does removing it and
  saving it back; a different key does (until the limited key is saved again).
  A rejected key (`401`) pauses them
  for an hour or until the key is saved again (a successful verified-domain
  listing also lifts that pause: the key just worked). Neither retries in a
  loop; unchecked identities simply stay due.
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
      "license": "CC BY 4.0",
      "licenseUrl": "https://creativecommons.org/licenses/by/4.0/",
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
      "summary": { "checked": 1, "newFindings": 2, "failed": 0, "unverified": 1, "remaining": 0, "skipped": false }
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
rejected the key. `leaked_creds.last_run.summary.unverified` counts the email
domains skipped because they aren't verified on the HIBP account (or that HIBP
refused with a `403` while that was unknown); they are not failures. `domain_monitor.last_run` is the last scheduled cycle (a
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

### GET /api/exposure/summary

What the Digital Risk page aggregates: open findings, what is new in a window,
the trend, the accounts to act on and the registered lookalikes. Read-only: it
reads findings, identities, domains and the domain-monitor baselines, and never
calls HIBP, crt.sh or DNS.

**Authentication:** Required (any role)

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `days` | string | `90` | The window: exactly `30`, `90`, `180` or `365` |

Anything else — `7`, `90abc`, `1e2`, `-90`, a padded value or the key given
twice — is `400 { "message": "days must be one of 30, 90, 180, 365" }`.

| `days` | Bucket | Buckets returned |
|---|---|---|
| `30` | day | 31 |
| `90` | week | 13-14 |
| `180` | week | 26-27 |
| `365` | month | 13 |

All bucketing is **UTC** and weeks start on **Monday**. The window starts on a
bucket boundary (`window.since` = the start of the bucket holding
`now − days`; for `365`, `now − 12 months`, so a year is always the current
month and the 12 before it, leap days included), so it can reach a few days
(up to a month for `365`) further back than `days`, and the trend sums exactly
to the window's counts.

Everything is read in **one database snapshot** (a `REPEATABLE READ READ ONLY`
transaction, with one `NOW()`), so the parts agree with each other while the
jobs write:
- Σ `open.by_severity` = `open.total` = the last bucket's `open_at_end`
- Σ `trend[].new.*` = `in_window.new`; Σ `trend[].resolved` = `in_window.resolved`
- the buckets are contiguous, oldest first

**Response (200)** (trend shortened):
```json
{
  "generated_at": "2026-10-15T09:00:00.000Z",
  "window": { "days": 90, "bucket": "week", "since": "2026-07-13T00:00:00.000Z" },
  "open": {
    "total": 71,
    "by_severity": { "critical": 1, "high": 31, "medium": 35, "low": 4 },
    "by_source": { "leaked-creds": 30, "domain-monitor": 41 },
    "oldest_critical_high_first_seen": "2026-03-30T02:19:09.893Z"
  },
  "in_window": {
    "new": 59,
    "new_by_severity": { "critical": 2, "high": 26, "medium": 25, "low": 6 },
    "resolved": 28,
    "prev_new": 54
  },
  "by_type": [
    {
      "source": "leaked-creds", "event_type": "breach", "category": "credentials",
      "open": 30, "open_by_severity": { "critical": 0, "high": 26, "medium": 3, "low": 1 },
      "new": 21, "resolved": 9
    },
    {
      "source": "domain-monitor", "event_type": "new_cert", "category": "impersonation",
      "open": 6, "open_by_severity": { "critical": 0, "high": 2, "medium": 4, "low": 0 },
      "new": 4, "resolved": 3
    }
  ],
  "trend": [
    {
      "start": "2026-07-13T00:00:00.000Z",
      "new": { "credentials": 1, "impersonation": 1, "domain_changes": 4 },
      "resolved": 1,
      "open_at_end": 49,
      "monitoring_added": { "identities": 0, "domains": 0 }
    }
  ],
  "accounts": {
    "total": 14,
    "to_reset": 12,
    "top": [
      {
        "account": "carol@example.com",
        "identity_id": 4,
        "open": 5,
        "credential_exposures": 5,
        "stealer_log": true,
        "worst_severity": "high",
        "breaches": [
          { "title": "Naz.API", "date": "2023-09-20" },
          { "title": "Twitter (200M)", "date": "2021-01-01" },
          { "title": "Dropbox", "date": "2012-07-01" }
        ],
        "breach_count": 4,
        "last_detected": "2026-06-28T02:28:19.000Z"
      }
    ]
  },
  "lookalikes": {
    "state": "checked",
    "candidates_checked": 720,
    "registered": 32,
    "with_mx": 8,
    "with_address": 17,
    "with_current_cert": 5,
    "top": [
      {
        "lookalike": "examp1e.com",
        "domain_id": 1,
        "watched_domain": "example.com",
        "scope": "own",
        "technique": "homoglyph",
        "has_mx": true,
        "has_address": true,
        "certs": "current",
        "reported_at": null,
        "open_findings": { "count": 1, "worst_severity": "medium" }
      }
    ]
  }
}
```

- `open` counts every open finding; `oldest_critical_high_first_seen` is the
  first-seen time of the oldest open critical or high one (`null` if none).
- `in_window.new` counts findings **first seen** in the window,
  `in_window.resolved` those resolved in it, and `prev_new` those first seen in
  the window of the same length just before it. Detection time, not the
  breach date: adding an identity whose first check reports all its past
  breaches puts them all in one bucket, which `monitoring_added` explains.
- `by_type` has one row per (`source`, `event_type`, `category`); the eight
  kinds the collectors write are always present (zero-filled), anything else
  follows them. `category` is derived from the stored finding:
  `credentials` (a breach), `impersonation` (a lookalike's registration, or a
  certificate for a lookalike: `detail.lookalike` is set) or `domain_changes`
  (a change to the watched domain itself).
- `trend[].open_at_end` is the open backlog when the bucket ended (for the
  last bucket, now).
- `accounts` covers **open** breach findings, grouped by account
  (case-insensitive): `to_reset` counts the accounts with at least one breach
  that exposed passwords, historical passwords or auth tokens, or came from a
  stealer log. `top` lists at most 10, those first, then the worst severity;
  each with at most 3 distinct breaches, newest breach date first. `open`
  counts the account's open breach findings and `breach_count` its distinct
  breaches (by HIBP breach name): an account monitored as an address and
  through its email domain gets one finding per identity for the same breach,
  so `open` can be larger.
- `lookalikes` reads the lookalike and CT baselines of every **enabled**
  domain that runs the lookalike check, so it includes the lookalikes that
  were already registered at the domain's first check (recorded silently,
  without a finding: `reported_at` is `null`). `state` is `not_watched` (no
  such domain), `not_checked` (none checked yet) or `checked`. `has_mx` /
  `has_address` are `null` while every lookup so far failed; `certs` is
  `current` (a certificate that hasn't expired), `none` or `not_checked`.
  `registered`, `with_mx`, `with_address` and `with_current_cert` count
  **distinct lookalike domains**: one that imitates two watched domains
  (`acme.co` for both `acme.com` and `acme.net`) counts once, with a flag set
  when any domain's checks saw it. `top` has one row per (watched domain,
  lookalike) and lists at most 25: mail first, then a current certificate,
  then an address, then the worst open finding, then the newest report.
- No raw `detail` is returned, and no field holds a secret.

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

The breach-data providers, without keys: `[{ "name": "hibp", ..., "license": "CC BY 4.0", "licenseUrl": "https://creativecommons.org/licenses/by/4.0/", "configured": true, "enabled": true, "usable": true }]`
(same objects as `providers` in `GET /status`). `license` / `licenseUrl` are the
licence the provider's data must be credited under wherever it is shown. `configured` means a key is
saved; `usable` means this backend can also decrypt it. A saved key that isn't
usable (`CREDENTIAL_ENCRYPTION_KEY` missing, or changed since the key was saved)
makes every leaked-credential check skip: put the original
`CREDENTIAL_ENCRYPTION_KEY` back and restart the backend, or save the key again.

**Authentication:** Required

### PUT /api/exposure/providers/hibp

Save the HIBP API key and/or enable the provider. Saving a different key (or
clearing it) resets the verified-domain list (it belongs to the old key's
account):
[`GET /providers/hibp/verified-domains`](#get-apiexposureprovidershibpverified-domains)
reads `not_checked` until the next run or re-check lists the new key's domains.
Both lift a rejected-key pause. A rate-limit pause belongs to the key HIBP
answered `429` to: clearing the key keeps it (nothing is sent without a key),
and a different key starts afresh, but saving the limited key again, after
clearing it or after another key, brings the pause back until HIBP's
`retry-after` has passed. The list then reads `error` with `kind:
"rate_limited"` and that `retry_after`. Re-entering the key that is already
saved, or only changing `enabled`, keeps the stored key and its list and lifts
only a rejected-key pause: after a `429`, checks and re-checks stay paused
until HIBP's `retry-after` has passed. (The wait of a key that was replaced or
cleared is remembered in memory only, by an HMAC of the key under a
per-process secret: a restart after the key was replaced or cleared forgets
it.)

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
    "name": "Core 1",
    "description": "…",
    "subscribed_until": "2027-01-01T00:00:00",
    "rpm": 10,
    "domain_search_max_breached_accounts": 25,
    "max_breached_domains": 1,
    "includes_stealer_logs": false
  }
}
```
`max_breached_domains` is how many domains the plan can verify (`null`: no
maximum).

**Errors:**
- `400` - no key given or saved, a malformed key, or HIBP rejected the key
  (HIBP's public test key `000…0` fails here: `subscription/status` refuses it,
  although the breach searches accept it for HIBP's test accounts)
- `429` - HIBP rate-limited the test
- `502` - HIBP could not be reached

### GET /api/exposure/providers/hibp/verified-domains

The domains verified on the saved key's HIBP account (HIBP's
`subscribeddomains`), the plan, and how the latest listing went: the account
view behind the Digital Risk page's Domain search section. Read from the
snapshot the leaked-credential job and the re-check keep; **never calls HIBP**.
The snapshot is bound to the saved key, so a list fetched for another key is
never shown.

**Authentication:** Required (Admin)

**Response (200):**
```json
{
  "state": "listed",
  "checked_at": "2026-10-12T09:41:07Z",
  "listed_at": "2026-10-12T09:41:07Z",
  "stale": false,
  "error": null,
  "plan": { "name": "Core 2", "domain_search_max_breached_accounts": 100, "max_breached_domains": 3,
            "subscribed_until": "2027-01-01T00:00:00" },
  "domains": [
    { "domain": "example.com", "pwn_count": 40, "pwn_count_excluding_spam_lists": 38,
      "pwn_count_excluding_spam_lists_at_last_subscription_renewal": 35,
      "next_subscription_renewal": "2027-01-01T00:00:00",
      "within_plan": true, "identity_id": 12 }
  ],
  "truncated": false,
  "skipped_entries": 0,
  "next_refresh_allowed_at": null,
  "attribution": "https://haveibeenpwned.com"
}
```
- `state` is `no_key` (no usable key; `domains` is `null`), `not_checked` (never
  listed for the saved key), `listed` (`domains` is set; `error` may describe a
  later failed attempt, and the list is the last good one, as of `listed_at`)
  or `error` (no list for this key yet; see `error.kind`).
- `checked_at` is the latest attempt, `listed_at` the latest success. `stale`
  means HIBP refused a domain search (`403`) since the list was fetched; the
  next run re-reads it.
- `error` is `{ kind, status, message, retry_after }`. `kind` is `auth` (`401`:
  HIBP's public test key always gets it here), `forbidden` (`403`: the plan has
  no domain search, so email domains are skipped), `rate_limited` (`429`; no
  listing before `retry_after`), `network` (haveibeenpwned.com unreachable),
  `hibp_unavailable` (`5xx`) or `bad_response` (anything else, a `404`
  included: only a `200` with a JSON array counts as an answer).
- Domain names are normalized (lowercase punycode, no trailing dot). The counts
  are HIBP's (`null` before HIBP's first search of the domain). `within_plan`
  compares the at-renewal count (else the current one) with the plan's
  `domain_search_max_breached_accounts`; `null` when either is unknown.
  `identity_id` is the monitored `email_domain` identity, or `null`.
- `truncated` (more than 2,000 domains are listed; monitored ones are kept
  first) or `skipped_entries > 0` (entries that couldn't be read) make the list
  incomplete: a domain it doesn't include is then searched, not skipped.
- `next_refresh_allowed_at` is the earliest time a re-check will call HIBP (the
  end of the one-minute cooldown, or of a rate-limit pause); `null` means now.
- `attribution`: the counts are HIBP data; credit HIBP where they are shown.

**Errors:** `403` - not an admin

### POST /api/exposure/providers/hibp/verified-domains/refresh

Re-check with HIBP now: reads `subscription/status` (so a plan change shows at
once) and `subscribeddomains`, paced with every other HIBP call. At most once a
minute install-wide; concurrent re-checks share one call. Identities skipped as
`unverified` that are now listed become due straight away (their
`last_checked_at`, `last_status` and `last_error` are cleared), including while
a check runs: the run decides each skip on the list as it is at that moment, so
it searches such a domain instead of marking it `unverified` again. The
provider's `enabled` flag is not required, as for the key test.

**Authentication:** Required (Admin)

**Request Body:** none

**Response (200):** the view above, plus:
```json
{ "refreshed": true, "became_due": [12] }
```
- `refreshed: false` means HIBP was asked less than a minute ago: the cached
  view comes back and nothing is sent.
- A failed attempt still answers `200`, with the failure in `error`. A `429`
  from HIBP is recorded there and pauses every breach check until its
  `retry-after` has passed, a run in progress included.
- `became_due` lists the enabled identities that turned verified and were made
  due again.

**Errors:**
- `400` - no usable HIBP key is saved (`"No usable HIBP API key is saved; save one first"`)
- `403` - not an admin
- `429` - a rate-limit pause is active; nothing is sent to HIBP. Comes with a
  `Retry-After` header (seconds) and the message
  `"HIBP rate limit reached; try again after <ISO time>"`.

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

All monitored identities. Each email domain carries `hibp_domain`: whether HIBP
will search it for the saved key, from the stored verified-domain list (never a
call to HIBP).

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
    "hibp_domain": null,
    "created_at": "2026-10-09T18:00:00Z",
    "updated_at": "2026-10-09T18:00:00Z"
  },
  {
    "id": 4,
    "kind": "email_domain",
    "value": "example.org",
    "enabled": true,
    "interval_minutes": 1440,
    "last_checked_at": "2026-10-12T09:41:09Z",
    "last_status": "unverified",
    "last_error": "Skipped: example.org isn't verified on your HIBP account (as of 2026-10-12T09:41:07Z). Verify it in the HIBP dashboard, then re-check verification.",
    "hibp_domain": {
      "state": "not_verified",
      "reason": null,
      "verified_parent": null,
      "listed_at": "2026-10-12T09:41:07Z",
      "message": "Not verified on your HIBP account, so HIBP won't search it and SIEMBox skips it. Verify it in the HIBP dashboard (https://haveibeenpwned.com/Dashboard/Redirect/Domains), then re-check verification."
    },
    "created_at": "2026-10-09T18:00:00Z",
    "updated_at": "2026-10-09T18:00:00Z"
  }
]
```
- `last_status` is `ok`, `error` (with `last_error` saying why) or
  `unverified`; `null` means not checked yet. **`unverified`** means the email
  domain was skipped, not failed: it isn't verified on the HIBP account (or
  HIBP refused it with a `403` while that was unknown). Scripts that treat
  anything but `ok` as a failure should read it as "needs verifying at HIBP".
- `hibp_domain` is `null` for an `email`. Its `state` is `verified`,
  `verified_limited` (verified, but it may be larger than the plan covers: HIBP
  then returns only subscription-free breaches), `not_verified` (skipped;
  `verified_parent` names a listed parent domain, since HIBP verifies each
  subdomain separately), `unavailable` (the plan has no domain search: skipped)
  or `unknown` (searched as before). `reason` is set only for `unknown`:
  `no_key`, `not_checked`, `auth`, `rate_limited`, `network`,
  `hibp_unavailable`, `bad_response` or `list_incomplete`. `listed_at` is when
  the list used was fetched, and `message` explains the state in a sentence.

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

**Response (201):** the created identity, with `hibp_domain` as in
`GET /identities`. It is due immediately, so the next job tick (or
`POST /run-now`) checks it (or skips it, if it is an email domain HIBP won't
search).

**Errors:** `400` - invalid kind or value; `409` - already monitored

### PUT /api/exposure/identities/:id

Update `enabled` and/or `interval_minutes`. `kind` and `value` can't be changed
(findings are fingerprinted on them) — delete and re-add instead.

**Authentication:** Required (Admin)

**Response (200):** the updated identity (with `hibp_domain`) · **Errors:** `400`, `404`

### DELETE /api/exposure/identities/:id

Deletes the identity and its findings. Their alerts stay in the alert queue; if
the identity is added back, a re-found breach re-links its existing alert rather
than raising a new one.

**Authentication:** Required (Admin)

**Response (200):** `{ "message": "Monitored identity deleted" }` · **Errors:** `404` - not found

---

### GET /api/exposure/findings

Findings, newest first (or most severe first with `sort=severity`).

**Authentication:** Required

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `source` | string | - | `leaked-creds` or `domain-monitor` |
| `unresolved` | boolean | `false` | `true` (or `1`) for open findings only |
| `severity` | string | - | `low`, `medium`, `high` or `critical` |
| `identity_id` | integer | - | Findings for one identity |
| `domain_id` | integer | - | Findings for one watched domain |
| `event_type` | string | - | `breach`, `new_cert`, `unexpected_ca`, `lookalike_registered`, `rdap_change`, `dns_drift` or `expiry_warning` |
| `category` | string | - | `credentials`, `impersonation` or `domain_changes` (see [`GET /summary`](#get-apiexposuresummary)); tells a certificate for a lookalike from one for your own domain |
| `since_days` | integer | - | First seen in the last N days, `1`-`365` |
| `since` | string | - | First seen at or after this ISO 8601 time (e.g. the summary's `window.since`), such as `2026-07-13T00:00:00.000Z` |
| `alert_id` | integer | - | The finding that raised this alert |
| `search` | string | - | Case-insensitive text in the title, identity, watched domain, account, lookalike or breach; at most 200 characters, matched literally (`%`, `_` and regex characters are plain text) |
| `account` | string | - | One breached account, the whole value (case-insensitive); at most 254 characters |
| `lookalike` | string | - | One lookalike domain, the whole value (case-insensitive); at most 253 characters |
| `sort` | string | `newest` | `newest` (`first_seen`, then `id`, descending) or `severity` (most severe first, then newest) |
| `limit` | integer | 50 | 1-200 |
| `offset` | integer | 0 | Pagination offset |

Each new parameter is `400` when its value isn't allowed (e.g.
`"event_type must be one of: breach, new_cert, …"`,
`"since_days must be a whole number from 1 to 365"`,
`"search must be at most 200 characters"`, `"Invalid alert id"`) or when it is
given twice (`"<name> must be given once"`). A call with none of them returns
the same rows in the same order as before.

Each finding also carries `category` (as above) and `alert_status`: the linked
alert's status (`new`, `investigating`, `closed`, `false_positive`), or `null`
when there is no alert any more (deleted, or removed by retention:
`alert_id` is then `null` too).

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
      "category": "credentials",
      "identity_kind": "email",
      "identity_value": "alice@example.com",
      "domain": null,
      "alert_status": "new"
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0
}
```
Findings from an `email_domain` identity also carry `detail.alias` (the local part
that was found). A breach whose provider asked HIBP to credit them also carries
`detail.breach_attribution` (plain text, at most 300 characters, control
characters removed; show it as text, never as a link or HTML). New findings'
alert descriptions end with the licence line quoted at the top of this section.

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
not just the due ones. With `force`, a due email domain also re-reads the
verified-domain list if it is more than a minute old.

Stops starting new checks after ~90 seconds (HIBP calls are paced to the key's
plan, about 6 s apart on the smallest one); anything left stays due for the
scheduled job. Allow a client timeout of a couple of minutes.

**Response (200):**
```json
{ "checked": 3, "newFindings": 2, "failed": 0, "unverified": 1, "remaining": 0, "skipped": false }
```
- `unverified` - email domains skipped because they aren't verified on the HIBP
  account (or refused with a `403` while that was unknown); not part of `failed`
- `skipped: true` with a `reason` when nothing ran (checks disabled, no provider
  configured, paused, or nothing due)
- `error` (and `rateLimitedUntil` for a `429`) when the run stopped early. For
  a `429`, when checks resume is given by `rateLimitedUntil` (ISO) only, not in
  `error`, e.g.
  `"Have I Been Pwned rate limit reached (it answered 429 to another request)"`
  when an admin's re-check drew it while the run was going
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

## Context Graph Endpoints

The Context Graph answers "what is linked to this?" for one thing SIEMBox
knows: an alert, an IP, a user or host named in alerts, a domain, an asset, a
vulnerability, a Digital Risk finding or identity, a log shipper (or a ghost
shipper's tag), a detection rule, and, for admins, a SIEMBox account or an
endpoint agent. Each call returns that entity (the **centre**), its nearest
neighbours per relation, and a count of the rest, so a client expands the
graph one hop at a time. The graph page that uses it comes in a later release.

These answers come from SIEMBox's own records: alerts, the asset inventory and
vulnerability management, Digital Risk, log shippers, detection rules and the
sign-in audit log, plus, for an alert, the device and shipper of the log it
was raised on. Relationships seen across all logs (which users an IP signed
in as, which hosts it reached) are a later release too.

**Authentication:** every route requires a session and is a `GET`, open to
every role. What each role's graph holds never goes beyond what the role can
already read elsewhere in the API (see [Roles](#roles-in-the-graph)). No call
changes anything, and nothing here calls an external service.

### Entities

An entity is written `type:key`, the same string used as the node `id`:

| Type | Key | Example |
|---|---|---|
| `ip` | IPv4 dotted, or IPv6 in its lower-case canonical form (RFC 5952); `::ffff:a.b.c.d` is the IPv4 address | `ip:198.51.100.7` |
| `host` | spaces trimmed, lower-cased; 1-253 characters, no whitespace, control or bidi characters | `host:nas` |
| `user` | spaces trimmed, case kept; 1-128 characters, no control or bidi characters; `-`, `unknown`, `null`, `none`, `(null)`, `n/a`, `nobody` and `?` are refused | `user:root` |
| `domain` | spaces trimmed, lower-cased, trailing dots removed, at least one dot | `domain:example.com` |
| `alert`, `rule`, `asset`, `vuln`, `finding`, `identity`, `shipper`, `account` | the record's id (`vuln` is `vulnerabilities.id`, `account` is `users.id`) | `alert:812` |
| `shipper_tag` | the 8 hex characters of a `raw_logs.shipper_id` that no shipper matches (a ghost shipper) | `shipper_tag:1a2b3c4d` |
| `endpoint` | an endpoint agent's id (UUID) | `endpoint:3f2504e0-4f89-11d3-9a0c-0305e82c3301` |

The type is everything before the first `:`, so IPv6 keys keep their colons.
Alerts are found by the same rules applied to their `matched_data` (an alert
naming `Example.COM.` is found from `domain:example.com`), and by an IP in its
usual spellings: IPv4 also as `::ffff:a.b.c.d`, IPv6 compressed, uncompressed
or zero-padded, in lower or upper case. A `matched_data` value longer than
2,000 bytes is never matched (the lookup indexes leave such values out). Entity
values appear in the request URL, and so in browser history and proxy logs, as
Threat Intel's `?ip=` already does.

### Time window

`window=24h|7d|30d|90d` (default `7d`) ends at the current minute, rounded up.
`around=<ISO 8601 time with a zone>` is that time minus 24 hours to plus 1
hour (its end at most an hour from now): the window for an alert's own time.
Give one or the other. Alerts, sign-ins and resolved findings are windowed;
inventory relations (an asset's IP, host name, vulnerabilities, shipper and
agent) are current state; open findings always count.

### Responses and limits

| Status | When |
|---|---|
| `200` | Success, including partial answers (a source that timed out; see `groups[].status` and `sources`) and entities nothing links to (`center.exists: false`) |
| `400` | `code: "GRAPH_BAD_ENTITY"` (the entity isn't a valid `type:key`) or `"GRAPH_BAD_PARAM"` (any other parameter) |
| `401` | Only a missing or expired session; never bad input |
| `403` | Only `PASSWORD_CHANGE_REQUIRED` |
| `404` | `code: "GRAPH_NOT_AVAILABLE"`: the relation isn't one of this entity type, or the role can't expand this type (accounts and endpoint agents, for non-admins) |
| `429` | The general [rate limit](#rate-limiting) |
| `503` | `code: "GRAPH_BUSY"` with `Retry-After: 2` and `retryAfter: 2`: no slot within a second, no database connection, or every source timed out |

Errors use the usual envelope plus a `code`:

```json
{ "status": "error", "statusCode": 400, "code": "GRAPH_BAD_ENTITY", "message": "that is not a valid ip" }
```

So that the graph can't crowd out the rest of SIEMBox:

- At most 4 graph requests run at a time in the backend, and 2 per user. A
  request that gets no slot within 1 second is answered `503 GRAPH_BUSY`.
- Each request runs on one database connection, in a read-only transaction:
  1.5 seconds per statement, no new statement after 3.5 seconds, 4 seconds in
  all. A source (one relation, or one type's facts) that runs out of time is
  left out and marked `timeout`; the rest of the answer stands.
- Answers are cached for 20 seconds, shared only between roles that see the
  same graph (`cached: true`). Partial answers are not cached.
- Per relation, totals are counted over at most 1,001 rows: `total` is then
  `1000` with `total_capped: true` ("1,000+"). Alert relations rank the latest
  1,000 alerts in the window, by severity and then recency.
- An answer holds at most 300 nodes and 600 edges.

### Nodes, edges and groups

```json
{
  "id": "ip:198.51.100.7",
  "type": "ip",
  "key": "198.51.100.7",
  "label": "198.51.100.7",
  "facts": { "country": "Netherlands", "country_code": "NL", "private": false, "threat_feeds": "Blocklist.de" },
  "flags": ["threat_feed", "foreign"],
  "expandable": true
}
```

- `label` is at most 64 characters, with control and bidi characters removed;
  string facts at most 256. Labels and facts come from logs and alerts, so a
  client must render them as text, never as HTML.
- `facts` per type: `ip` country, country_code, private, threat_feeds (the
  local feeds that list it); `user` is_email; `domain` watched (`own` or
  `brand`) and unicode (an IDN's Unicode form); `alert` title, severity,
  status, source, rule_id, created_at, verdict, risk_score (never
  `matched_data`); `rule` name, severity, enabled; `asset` hostname, ip,
  asset_type, criticality, status, last_seen, open_vulns, agent_status,
  agent_version, agent_last_seen; `vuln` cve_id, severity, cvss, title;
  `finding` title, source, event_type, severity, first_seen, last_seen,
  resolved; `identity` kind, value; `shipper` name, status, hostname,
  ip_address, version, last_seen (never a key); `shipper_tag` tag; `endpoint`
  hostname, os, agent_version, status, last_seen; `account` username, and for
  admins role, enabled, mfa_enabled, last_login.
- A shipper's and an endpoint agent's `status` is the live one, worked out
  from `last_seen` as the rest of SIEMBox does: a shipper is `pending` (never
  heard from), `offline` (no heartbeat for 3 minutes), `error` or `online`, as
  [`GET /api/shippers/:id`](#get-apishippersid) says; an agent is `online`
  when seen in the last 5 minutes, else `offline`, as the Endpoints page and
  the asset's `agent_status` say. The stored status column is never shown: it
  says `online` long after a shipper (a revoked or ghost one, say) or an agent
  has stopped reporting.
- `flags`: `threat_feed`, `foreign` (outside `GEOIP_HOME_COUNTRIES`), `private`,
  `critical` (asset criticality), `open_vulns`, `closed` (a closed or
  false-positive alert).
- An **edge** is `{id, source, target, rel, origin, style}`, plus `role` on
  `alert_ips` (`source`, `dest`, or `sender`: the IP equals the log's
  `observer_ip`, the device that sent it) and `count`, `failures`,
  `successes`, `first_seen`, `last_seen` on `account_signins`. Its id is
  `rel|source|target`, and its direction is fixed (an alert points at the IP
  it names, whichever side was expanded), so the same fact reached from
  either side is one edge.
- `origin` is `alerts`, `logs`, `inventory`, `risk` or `accounts`. `style` is
  `recorded` (SIEMBox's own record: solid), `logs` (what a log said: dashed)
  or `heuristic` (a match by name or address: dotted).
- A **group** describes one relation of the centre: `{rel, label,
  neighbor_type, origin, total, total_capped, shown, very_common, status,
  note?}`. `neighbor_type` is the type of the neighbours it holds; for
  `alert_device` that is `host` (the log's syslog header host) or `ip` (its
  sender, when the header named no host), and `host` when there is none to
  show. `shown` of `total` neighbours are in `nodes`; `very_common` means
  200 or more ("likely infrastructure"). `status` is `ok`, `timeout` or
  `unavailable`. `note: "log_expired"`: the log an alert was raised on has
  been deleted by retention.

### Relations

| `rel` | From | To | Origin, style | Source |
|---|---|---|---|---|
| `alert_ips` | alert | ip | alerts, solid | `matched_data` `source_ip`, `client_ip`, `dest_ip`, with `role` |
| `alert_users` | alert | user | alerts, solid | `matched_data` `user`, `target_user` |
| `alert_hosts` | alert | host | alerts, solid | `matched_data.host` ("host named in the log") |
| `alert_domains` | alert | domain | alerts, solid | `matched_data.domain`; and `matched_data.lookalike` on Digital Risk lookalike alerts (`source` `domain-monitor`) only, the same rule as finding the alerts from the domain |
| `alert_rule` | alert | rule | alerts, solid | `rule_id` |
| `alert_asset` | alert | asset | alerts, solid | `asset_id` (endpoint detections) |
| `alert_finding` | alert, finding | finding, alert | risk, solid | the finding that raised the alert |
| `alert_same_event` | alert | alert | alerts, solid | alerts on the same parsed log |
| `alert_account` | alert | account | alerts, solid | a sign-in protection alert's account |
| `alert_endpoint` | alert | endpoint (admin) | alerts, solid | an endpoint detection's agent |
| `alert_device` | alert | host or ip, and its shipper | logs, dashed | the log's syslog header host, else its sender IP, and the shipper (or ghost `shipper_tag`) its tag names, while the log is retained; the second edge is `shipped_by` |
| `entity_alerts` | ip, user, host, domain, asset, account (admin), endpoint (admin) | alert | alerts, solid | alerts in the window naming it; for an asset, by `asset_id` (solid) or naming its current IP (dotted) |
| `rule_alerts` | rule | alert | alerts, solid | the rule's alerts in the window |
| `asset_ip` / `ip_asset` | asset / ip | ip / asset | inventory, solid | the asset's current IP |
| `asset_host` / `host_assets` | asset / host | host / asset | inventory, solid | the asset's host name |
| `asset_vulns` / `vuln_assets` | asset / vuln | vuln / asset | inventory, solid | open findings, or all with `vuln_status=all`, by risk score |
| `asset_shipper` / `shipper_assets` | asset / shipper | shipper / asset | inventory, dotted | a shipper with the asset's host name or IP |
| `asset_endpoint` | asset, endpoint (admin) | endpoint, asset | inventory, solid | the asset's agent |
| `shipper_address` | shipper | ip, host | inventory, solid | the address and host name it reported |
| `ip_shipper` / `host_shipper` | ip / host | shipper | inventory, solid | shippers at that address or host |
| `finding_identity` / `identity_findings` | finding / identity | identity / finding | risk, solid | the monitored identity |
| `finding_domain` / `domain_findings` | finding / domain | domain / finding | risk, solid | the watched domain and the lookalike it names |
| `identity_user` | identity (email), user | user, identity | risk, dotted | users in alerts that are that address (compared in lower case) |
| `identity_domain` | identity (email domain), domain | domain, identity | risk, solid | the email domain |
| `account_signins` / `ip_signins` | account / ip (admin) | ip / account | accounts, solid | sign-ins in `audit_logs`, with successes and failures |

### Roles in the graph

| Nodes and relations | Admin | Operator | Analyst | Viewer |
|---|---|---|---|---|
| ip, host, user, domain, alert, rule, asset (with its agent status), vuln, finding, identity, shipper, shipper_tag | yes | yes | yes | yes |
| account nodes a sign-in alert names: the username the alert shows, not expandable | yes | yes | yes | yes |
| account details, expanding an account, `account_signins` / `ip_signins` | yes | no | no | no |
| endpoint nodes, `alert_endpoint`, `asset_endpoint` | yes | no | no | no |

Relations a role can't see don't run and aren't listed, and nothing says how
many were left out. Each row mirrors routes the role can already call
(`backend/src/services/graph/visibility.ts`; the test suite checks it against
`routeInventory.test.ts`).

### GET /api/graph/search

What a typed string could mean, as at most 10 candidates. It reads only small
tables (assets, shippers, watched domains, rules, identities, vulnerabilities)
and counts alerts, never logs.

**Query:** `q` (1-200 characters).

Resolution: a literal `type:key` gives just that entity (if valid and, for
records, existing); an IP gives `ip:` and the asset with that address; `#123`
or `alert 123` the alert; `CVE-...` or `NUCLEI-...` the vulnerability; a string
with `@` the user and a monitored email identity; a host- or domain-like word
assets and shippers by name prefix, watched domains, `host:`, `domain:` (with a
dot) or `user:` (without) and rules by name; anything else `user:` and rules.

**Response:**

```json
{
  "candidates": [
    { "entity": "ip:10.0.0.5", "type": "ip", "label": "10.0.0.5", "hint": "1 alert in 30 d" },
    { "entity": "asset:12", "type": "asset", "label": "nas", "hint": "asset · 10.0.0.5 · critical" }
  ],
  "cached": false,
  "elapsed_ms": 5
}
```

### GET /api/graph/neighborhood

An entity and its nearest neighbours.

**Query:**

| Parameter | Default | |
|---|---|---|
| `entity` | required | `type:key`, given once |
| `window` or `around` | `window=7d` | see [Time window](#time-window) |
| `limit` | `5` | neighbours per relation, 1-25 |
| `include` | every origin the role sees | comma-separated origins to run: `alerts,logs,inventory,risk,accounts` |
| `vuln_status` | `open` | `all` adds patched and accepted vulnerabilities |

**Response:**

```json
{
  "center": { "id": "alert:812", "type": "alert", "key": "812", "label": "#812 SSH brute force from 198.51.100.7",
              "facts": { "severity": "high", "status": "new", "...": "..." }, "flags": [], "expandable": true, "exists": true },
  "window": { "from": "2026-10-08T14:03:00.000Z", "to": "2026-10-15T14:03:00.000Z", "preset": "7d" },
  "nodes": [ { "id": "alert:812", "...": "..." }, { "id": "ip:198.51.100.7", "...": "..." } ],
  "edges": [
    { "id": "alert_ips|alert:812|ip:198.51.100.7", "source": "alert:812", "target": "ip:198.51.100.7",
      "rel": "alert_ips", "origin": "alerts", "style": "recorded", "role": "source" }
  ],
  "groups": [
    { "rel": "alert_ips", "label": "IPs", "neighbor_type": "ip", "origin": "alerts", "total": 1,
      "total_capped": false, "shown": 1, "very_common": false, "status": "ok" }
  ],
  "sources": { "alerts": { "status": "ok" }, "risk": { "status": "ok" }, "logs": { "status": "ok" } },
  "generated_at": "2026-10-15T14:02:31.120Z",
  "cached": false,
  "elapsed_ms": 18
}
```

`center.exists` is `false` (still `200`) for a record that doesn't exist, an
IP, user, host or domain nothing links to in the window, or a ghost shipper
tag no retained log carries. `sources` has one entry per origin that ran:
`ok`, `partial` (a group timed out, or some facts are missing) or `timeout`.
For `logs`, the rollup behind the relationships seen in logs (migration 044)
adds `building` (still processing existing logs after the upgrade),
`behind` (not caught up for over 5 minutes) or `disabled` (switched off in
Settings → Context Graph), plus `covered_from` (first day), `covered_until`
(newest log consumed) and `incomplete_days` (days in the window the daily cap
cut short).

**Relationships seen in logs** (dashed, `origin: "logs"`; counts per whole
ingest day, a few minutes behind ingestion). Edges carry the a → b relation;
the b side names the group:

| a → b (edge `rel`) | Group from the b side | Notes |
|---|---|---|
| ip → user (`signed_in_as`) | `signed_in_from` | `failures`, `successes`; `new` (first seen in the window, when the rollup covers the time before it); `success_after_failures` |
| ip → device (`seen_on`) | `actors_seen` (host, ip, asset) | the device is the syslog header host, else the sender IP |
| user → device (`user_on`) | `users_seen` (host, ip, asset) | |
| ip → ip (`connected_to`) | `connected_from` | |
| ip → domain (`queried`) | `queried_by` | |
| host → ip (`sent_by`) | `sent_hosts` | every log with a header host, parsed or not |
| device → shipper or shipper_tag (`shipped_by`) | `shipped_devices` (shipper, shipper_tag) | every log with a shipper tag |

The actor IP is used only when the log was parsed and its `source_ip` differs
from `observer_ip`.

### GET /api/graph/relation

One relation of an entity, paged and searchable: the table behind a group.

**Query:** `entity`, `rel` (a `groups[].rel` of that entity), the window,
`limit` (1-50, default 50), `offset` (0-1000), `q` (at most 100 characters,
no control or bidi characters, matched anywhere in the neighbour's label,
case-insensitively, among all the neighbours in the window: a rule by its
name, an asset by its host name, an alert by its title; `%` and `_` are
literal; `total` then counts the matches), `sort`
(`count`, `last_seen` or `first_seen`; default: the relation's own order, for
alerts severity then recency), `order` (`desc` or `asc`), `vuln_status`.

**Response:**

```json
{
  "rel": "entity_alerts",
  "total": 7,
  "total_capped": false,
  "items": [
    { "node": { "id": "alert:9001", "type": "alert", "...": "..." },
      "edge": { "id": "alert_ips|alert:9001|ip:198.51.100.7", "rel": "alert_ips", "role": "source", "...": "..." } }
  ],
  "next_offset": 4,
  "status": "ok",
  "window": { "from": "...", "to": "...", "preset": "7d" },
  "generated_at": "2026-10-15T14:02:31.120Z",
  "cached": false,
  "elapsed_ms": 7
}
```

`next_offset` is `null` on the last page. A relation that times out is
`503 GRAPH_BUSY`.

### GET /api/graph/evidence

The logs behind one relationship seen in logs, on one ingest day (**Show
logs** on a dashed link). Every role.

**Query:** `rel` (an edge `rel` of the table above: `signed_in_as`,
`seen_on`, `user_on`, `connected_to`, `queried`, `sent_by`, `shipped_by`),
`a` and `b` (the edge's `source` and `target` entity keys; a type the
relation doesn't join is `400 GRAPH_BAD_PARAM`), `day` (`YYYY-MM-DD`;
default: the pair's latest day), `limit` (1-20, default 20).

**Response:**

```json
{
  "day": "2026-10-19",
  "days": ["2026-10-19", "2026-09-29"],
  "logs": [
    { "id": 812345, "created_at": "2026-10-19T09:12:01.000Z", "timestamp": "2026-10-19T09:12:00.000Z",
      "event_type": "ssh_auth", "parser": "ssh", "service": "sshd", "hostname": "nas",
      "sender_ip": "10.0.0.5", "message": "Failed password for root from 198.51.100.7 port 52144 ssh2" }
  ],
  "partial": false,
  "expired": false,
  "elapsed_ms": 14
}
```

`days` lists the pair's days, newest first (at most 90). `message` is at
most 500 characters with control and bidi characters removed. `partial: true`
when that day's lookup ran out of its 2 s (too many events to list);
`expired: true` when the day is older than the log retention (its logs are
deleted).

---

### GET/PUT /api/settings/context-graph

Admin only. The log-relationship rollup behind the Context Graph.

**GET response:**

```json
{
  "log_edges": { "enabled": true, "retention_days": 0, "backfill_days": 7, "daily_new_cap": 500000 },
  "status": { "status": "ok", "covered_from": "2026-10-12", "covered_until": "2026-10-19T09:10:00.000Z",
              "effective_retention_days": 30, "raw_logs_retention_days": 30, "rows": 182000, "bytes": 41000000 }
}
```

**PUT body:** `{ "log_edges": { ... } }` with any of `enabled` (boolean),
`retention_days` (0-3650; 0 = as long as raw logs), `backfill_days` (0-90;
used only before the rollup's first run), `daily_new_cap` (10,000 -
10,000,000). Answers as GET; an out-of-range value is `400`. The job applies
a change at its next minute.

---

## Endpoint Agent Updates (EDR)

Console-triggered updates for SIEMBox Endpoint agents (see [Endpoint agent](../edr.md#agent-updates)). All routes below are under `/api/edr`, admin-only, and every write is recorded in `audit_logs` (`edr.agent_update.*`, `resource_type` `edr_agent`). `GET /api/edr/agents` and `GET /api/edr/agents/:id` also return the update columns: `update_request_id`, `update_target_version`, `update_state`, `update_error`, `update_requested_at`, `update_updated_at`.

`update_state` is `pending` (requested, not yet seen), `downloading`, `installing`, `succeeded` or `failed` (`update_error` holds the agent's message). `update_request_id` is set only while a request is outstanding; after success or a cancel it is `null` and the other fields stay for display (a cancel clears them).

Versions are plain `X.Y.Z`. An agent on any other version string (`dev`, `a8922f4-dirty`) is a development build: it can be updated by hand, never by auto-update or `update-outdated`. A downgrade or same-version update is never requested.

### GET /api/edr/agent-updates

The latest known release and the auto-update switch.

```json
{ "latest_version": "1.4.0", "checked_at": "2026-10-16T08:00:00.000Z", "error": null, "auto_update": false }
```

`latest_version` is `null` until a check has accepted a release; `error` is the last check's failure (kept alongside the previous good `latest_version`).

### POST /api/edr/agent-updates/check

Runs the GitHub release check now (also run every 6 hours by the `edr-agent-release` job). Returns the same shape as above. A network failure is not an HTTP error: it comes back in `error`. A release is accepted only when its tag is `vX.Y.Z` and it has an asset named exactly `SHA256SUMS`.

### PUT /api/edr/agent-updates/settings

Body `{ "auto_update": true }` (a boolean, else `400`). Returns the status object. Turning it on immediately requests the latest version for every outdated agent without an outstanding request for it.

### POST /api/edr/agents/:id/update

Requests an update to the latest version. Gives the agent a new `request_id` and bumps its `config_version`. Returns `{ "requested": true, "target_version": "1.4.0" }`. `404` unknown agent; `409` when no latest version is known yet, or the agent is already at or above it.

### DELETE /api/edr/agents/:id/update

Cancels an outstanding request (including a failed one the agent keeps reporting). Returns `{ "cancelled": true }`. `404` unknown agent; `409` when there is no request.

### POST /api/edr/agents/update-outdated

Requests the latest version for every agent on a lower `X.Y.Z` version, retrying failed requests and leaving in-flight ones alone. Returns `{ "requested": 3 }`.

### Agent-facing changes

`GET /api/edr/agents/:id/config` carries `"agent_update": { "version": "1.4.0", "request_id": "<uuid>" }`, or `null` when no update is requested. `POST /api/edr/agents/:id/heartbeat` accepts an optional

```json
"update": { "request_id": "<uuid>", "version": "1.4.0", "state": "installing", "error": "" }
```

with `state` one of `downloading`, `installing`, `succeeded`, `failed` and `error` (kept for `failed` only) cut to 500 characters. A malformed `update` is ignored, as is one whose `request_id` is not the agent's current request. The request completes when the agent reports `succeeded` or the heartbeat's `agent_version` reaches or passes the target (numeric X.Y.Z compare).

---

## Display links (Big Display)

A display link is a read-only credential for one wall screen or TV: it shows
a board of aggregate panels, with no user signed in, until an admin pauses,
rotates or revokes it (design: docs/architecture/BIG-DISPLAY.md). Links are
managed by **admins only** (`/api/display-links`, any other role gets `403`);
the screen itself calls `GET /api/display/snapshot` with the link's secret in
`X-Display-Token` (see [Display link tokens](#display-link-tokens-x-display-token)).
Use one link per screen: to cut one screen off, rotate its link.

Links belong to the install, like shipper and agent keys: they survive
restarts, upgrades and backup restores (only the hash is stored), and nothing
about the admin who created one changes it. At most 50 links are live (not
revoked) at once.

Errors are the usual envelope plus a `code`, and `field` (the path of the
first bad field, such as `config.views[0].panels[2].id`) on a `400`:

| Status | `code` | When |
|---|---|---|
| 400 | `DISPLAY_CONFIG_INVALID` | The board layout (`config`) is invalid: an unknown key, a value out of range, a panel a link can't show |
| 400 | `DISPLAY_LINK_BAD_REQUEST` | Another field: `name`, `expires_at`, `allowed_cidrs`, `enabled`, or a field the route doesn't take |
| 404 | `DISPLAY_LINK_NOT_FOUND` | No link with that id |
| 409 | `DISPLAY_LINK_NAME_TAKEN` | Another live link has this name (names compare case-insensitively; a revoked link's name is free) |
| 409 | `DISPLAY_LINK_LIMIT` | 50 links are live already |
| 409 | `DISPLAY_LINK_REVOKED` | The link was revoked: it can't be changed, rotated or revoked again |

Every answer under `/api/display-links` and `/api/display` has
`Cache-Control: no-store`. Request bodies are limited to 32 kB.

### The board layout (`config`)

```json
{
  "privacy": "operations",
  "refresh_seconds": 30,
  "rotation": { "enabled": true, "seconds": 20 },
  "timezone": null,
  "clock": true,
  "burn_in_shift": true,
  "views": [
    { "title": "SOC overview", "panels": [{ "id": "open_alerts" }, { "id": "recent_alerts", "min_severity": "high" }, { "id": "ingest" }] },
    { "title": "Threats", "panels": [{ "id": "threat_map", "window_days": 7 }, { "id": "top_sources" }] }
  ]
}
```

Only `views` is required; every other field has the default shown. The
stored config has every default filled in.

| Field | Values |
|---|---|
| `privacy` | `operations` (the default: rule names, shipper and host names, IP addresses) or `public` (counts only). Alert titles and descriptions, usernames, email addresses, breach names and raw log text are never shown in either. |
| `refresh_seconds` | `15`, `30`, `60` or `120` |
| `rotation` | `enabled` (boolean) and `seconds` (whole, 10 to 600): how long each view shows; ignored with one view |
| `timezone` | An IANA zone such as `"Europe/London"` (or `"UTC"`) for the clock, or `null` for the screen's own |
| `clock`, `burn_in_shift` | Booleans |
| `views` | 1 to 6 views, each a `title` (1 to 40 characters) and 1 to 6 `panels`. A panel appears at most once per view, and a config shows at most 12 different panels. |

Panels (`id`, plus the one option some have):

| `id` | Option (default) | In `public` |
|---|---|---|
| `open_alerts`, `alert_pulse`, `ingest`, `shippers`, `digital_risk`, `vulnerabilities` | — | yes |
| `recent_alerts` | `min_severity`: `critical`, `high` (default) or `medium` | yes |
| `sources` | `silent_after_minutes`: `5`, `15` (default), `30` or `60` | yes |
| `threat_map` | `window_days`: `1` (default), `7` or `30` | yes |
| `top_rules` | `window_hours`: `1` or `24` (default) | no |
| `top_sources` | — | no |
| `endpoints` | — | Never on a link: endpoint health is admin-only (`"Endpoint health is admin-only and can't be shown on a display link in this version."`) |

A panel's **key** is its id plus its option, as the snapshot names it:
`recent_alerts:high`, `top_rules:24`, `sources:15`, `threat_map:7`; panels
without an option are bare (`open_alerts`). The serialized config may be at
most 16 kB.

### GET /api/display/snapshot

**Who:** a display link (`X-Display-Token`), never a login.

What the screen draws: its layout (from the link's own row, never from the
request), the server's clock (for the screen's clock offset) and version (the
screen reloads when it changes), and each panel's data.

```json
{
  "generated_at": "2026-10-16T03:43:55.258Z",
  "server_time": "2026-10-16T03:43:55.258Z",
  "app_version": "4.0.0",
  "display": {
    "name": "NOC wall left",
    "config_version": 1,
    "privacy": "operations",
    "refresh_seconds": 30,
    "rotation": { "enabled": true, "seconds": 20 },
    "timezone": null,
    "clock": true,
    "burn_in_shift": true,
    "views": [{ "title": "SOC overview", "panels": ["open_alerts", "recent_alerts:high", "ingest"] }]
  },
  "alarms": [{ "key": "new_critical", "level": "critical", "text": "◆ 2 NEW CRITICAL", "panel": "open_alerts" }],
  "attributions": [],
  "panels": {
    "open_alerts": {
      "state": "ok",
      "as_of": "2026-10-16T03:43:50.112Z",
      "data": {
        "total": 7,
        "by_severity": {
          "critical": { "open": 2, "untouched": 2, "oldest_at": "2026-10-16T01:12:09.000Z" },
          "high": { "open": 5, "untouched": 1, "oldest_at": "2026-10-15T22:40:31.000Z" },
          "medium": { "open": 0, "untouched": 0, "oldest_at": null },
          "low": { "open": 0, "untouched": 0, "oldest_at": null }
        }
      }
    },
    "recent_alerts:high": {
      "state": "ok",
      "as_of": "2026-10-16T03:43:50.112Z",
      "data": {
        "min_severity": "high", "more": false,
        "items": [{ "severity": "critical", "status": "new", "category": "rule", "label": "SSH brute force", "at": "2026-10-16T03:41:02.000Z" }]
      }
    },
    "ingest": { "state": "stale", "as_of": "2026-10-16T03:43:20.004Z", "reason": "busy", "data": { "…": "…" } }
  }
}
```

`config_version` goes up whenever an admin changes the layout, so a screen
applies the new one at its next refresh. Refusals: see
[Display link tokens](#display-link-tokens-x-display-token). `Cache-Control: no-store`.

#### Panels

`panels` has one entry per distinct panel key in `display.views` (a key is the
panel id plus its option: `recent_alerts:high`, `top_rules:24`, `sources:15`,
`threat_map:7`). Each is an envelope:

| `state` | Fields | Meaning |
|---|---|---|
| `ok` | `as_of`, `data` | Current data, fetched at `as_of` |
| `stale` | `as_of`, `reason` (`busy` or `error`), `data` | The last data: a refresh failed, or didn't finish within the snapshot's 8 s budget |
| `unavailable` | `reason` | No data to show (also when a panel failed the privacy check below) |
| `not_configured` | `message` | Nothing to show yet: "No shippers registered", "No endpoint agents enrolled", "Digital Risk is not set up", "No scans yet" |
| `forbidden` | — | Signed-in board only: the user's role may not see it (the screen drops it) |

A failing panel never fails the response: it is still `200`. Panel data is
cached per panel key and shared by every screen (15 s to 5 min depending on
the panel), so many screens cost the database what one does.

Every string in `data` is an enum, an ISO timestamp, or a label. Labels are
rule names (operations only; otherwise the alert's category label:
"Detection rule", "Sign-in protection", "Leaked credentials", "Domain
monitoring", "Endpoint detection", "Other"), shipper names, host names and IP
addresses (operations only), and ISO 3166 country codes. **Never in any
mode:** alert titles or descriptions, usernames, email addresses, account or
breach names, lookalike domains, raw log text. Each panel is checked against
its declared shape before it is sent; one holding anything else goes out
`unavailable` (and the server logs which field).

| Key | `data` |
|---|---|
| `open_alerts` | `total`; `by_severity.{critical,high,medium,low}`: `{ open, untouched (still new), oldest_at }`. Open = `new` or `investigating`. |
| `alert_pulse` | `total_24h`, `prev_24h` (the 24 h before), `last_hour`, `by_severity_24h`, `hourly`: 24 `{ total, critical }`, oldest first, the last is the current hour |
| `recent_alerts:*` | `min_severity`, `more`, `items` (≤ 6, newest first, open alerts in 24 h at or above the floor): `{ severity, status, category, label, at }` |
| `top_rules:*` | `window_hours`, `total` (alerts in the window), `items` (≤ 6): `{ category, label, worst_severity, count }` |
| `ingest` | `state` (`flowing`, `slow`, `stalled`, `idle`), `last_log_at`, `stall_minutes`, `logs_last_minute`, `per_minute` (60, oldest first, the last is the current minute; `null` until the per-minute counter holds 2 minutes), `rate_15m_per_minute`, `baseline_per_minute` (the 24 h median; `null` under an hour of data), `hourly` (24 `{ total, unparsed }` from the parser counters), `parsed_pct_24h`, `udp_dropped_15m` (`null` without a syslog receiver), `rollup_since` |
| `sources:*` | `silent_after_minutes`, counts `active`, `silent`, `quiet`, `unknown`, `unknown_shippers` (ghost shippers: information, never an alarm), `since` (set while the counter holds under 24 h: "collecting since"), `more_active`, `rows` (≤ 8, silent first, then unknown, then the busiest; `[]` in public): `{ kind, label, state, logs_per_minute, last_seen_at, silent_minutes }` |
| `shippers` | `total`, `online`, `offline`, `pending`, `error` (as the Shippers page works them out), `unknown_shippers_24h`, `offline_list` (≤ 6, longest offline first; `[]` in public): `{ name, last_seen_at }` |
| `endpoints` | Signed-in admins only: `total`, `online`, `offline`, `detections_24h`, `offline_list` (≤ 6): `{ hostname, last_seen_at }` |
| `threat_map:*` | `window_days`, `located`, `total_in_window` ("N of M alerts had a public address"), `countries` (≤ 50): `{ code, count }` |
| `top_sources` | `items` (≤ 6, 24 h): `{ ip, country_code, alerts, worst_severity, last_at }` |
| `digital_risk` | `configured`, `open_total`, `open_by_severity`, `new_7d`, `accounts_to_reset` (a count), `impersonation_open` |
| `vulnerabilities` | `scanned`, `open_by_severity`, `affected_assets` |

**Sources.** A source is a shipper, a Log Discovery poller or a direct syslog
sender, from the per-minute ingest counter. It is **silent** when it averaged
at least a log a minute over 24 h, logged in at least half of those minutes
(a source that writes in occasional batches is exempt), and has logged
nothing for `silent_after_minutes`; **quiet** when it is lower-volume or
bursty and between writes (never alarmed); **unknown** when, since its last
log, the counter had to put some sources' logs into its shared overflow row
while this source wasn't sure of a row of its own, so its silence can't be
told. Nothing is called silent until the counter holds an hour.

**Alarms** (at most 4, critical first), only from panels in the display's
views: `new_critical` ("◆ 2 NEW CRITICAL"), `ingest_stalled` ("✕ NO LOGS FOR
18 MIN"), `udp_drops`, `ingest_slow`, `sources_silent`, `shippers_offline`,
`endpoints_offline` (signed-in admins), `data_delayed` (a panel is `stale` or
`unavailable`). `panel` is the key it came from.

**Attributions:** `dbip` when a view shows `threat_map` or `top_sources`
("IP Geolocation by DB-IP (db-ip.com)"), `hibp` when one shows
`digital_risk` ("Breach data: Have I Been Pwned (CC BY 4.0)").

A screen's use is recorded at most once a minute per device: the link's
`last_used_at`, and the device's address and user agent (the 20 most recently
seen are kept). An address new to the link writes `display_link.client_first_seen`
to the audit log (at most 10 per link per hour). None of this ever refuses a
request.

### GET /api/display-links

**Who:** admin. `?include_revoked=true` adds revoked links (after the live ones).

```json
{
  "links": [
    {
      "id": 7,
      "name": "NOC wall left",
      "token_hint": "x9Qa",
      "status": "live",
      "privacy": "operations",
      "view_count": 2,
      "panel_keys": ["open_alerts", "recent_alerts:high", "ingest", "threat_map:7", "top_sources"],
      "enabled": true,
      "expires_at": null,
      "revoked_at": null,
      "allowed_cidrs": ["10.20.0.0/16"],
      "created_by": { "id": 1, "username": "admin" },
      "created_at": "2026-10-16T03:40:00.000Z",
      "updated_at": "2026-10-16T03:40:00.000Z",
      "token_rotated_at": "2026-10-16T03:40:00.000Z",
      "last_used_at": "2026-10-16T03:43:55.913Z",
      "last_client": { "ip": "10.20.30.12", "user_agent": "Mozilla/5.0 (X11; Linux aarch64) ..." },
      "clients_24h": 1
    }
  ],
  "limit": 50
}
```

- `token_hint` is the secret's last 4 characters. No answer ever contains the
  secret or its hash.
- `status`: `revoked`, `expired` (`expires_at` passed), `paused`, `never_used`,
  `live` (used within three refresh intervals, and never less than a minute
  plus two refreshes, since uses are written once a minute) or `idle` (used
  before, not recently).
- `created_by` is `null` when the admin who created it was deleted ("deleted
  user"); the link keeps working.
- `clients_24h` is the number of distinct addresses that used it in the last
  24 hours: more than one for a one-screen link is worth a look.

### POST /api/display-links

**Who:** admin.

```json
{
  "name": "NOC wall left",
  "config": { "views": [{ "title": "SOC overview", "panels": [{ "id": "open_alerts" }] }] },
  "expires_at": null,
  "allowed_cidrs": ["10.20.0.0/16"]
}
```

- `name`: 1 to 80 characters, trimmed; unique among live links whatever its case.
- `config`: [the board layout](#the-board-layout-config).
- `expires_at` (optional): `null` (the default) for never, or an ISO 8601
  date in the future.
- `allowed_cidrs` (optional): up to 32 addresses or networks (IPv4 or IPv6);
  `[]` (the default) is any network. Stored in network form
  (`10.20.30.12/16` is `10.20.0.0/16`, an address alone its `/32` or `/128`).
  They are compared with the client address SIEMBox sees, so behind another
  reverse proxy set `TRUSTED_PROXIES` (DEPLOYMENT.md, "Client addresses and
  reverse proxies").

**Response:** `201`, **the only time the secret is shown** (and again after a rotation):

```json
{
  "link": { "id": 7, "name": "NOC wall left", "status": "never_used", "...": "the fields above", "config": { "...": "..." }, "config_version": 1, "clients": [] },
  "token": "sbd1_3q2V...43 characters",
  "path": "/display#k=sbd1_3q2V..."
}
```

The screen's URL is your SIEMBox address followed by `path`, for example
`https://siembox.example/display#k=sbd1_…`. Audit: `display_link.created`.

### GET /api/display-links/:id

**Who:** admin. `{ "link": … }`: the list's fields plus `config` (the stored
layout), `config_version` and `clients` (the devices seen, at most 20, most
recent first: `ip`, `user_agent`, `first_seen`, `last_seen`).

### PUT /api/display-links/:id

**Who:** admin. Any of `name`, `config`, `enabled`, `expires_at` (`null` for
never; a date must be in the future), `allowed_cidrs`; at least one.
`{ "enabled": false }` pauses the link and `{ "enabled": true }` resumes it.
Extending `expires_at` brings back a link whose expiry passed, with the same
secret. `config_version` goes up only when the layout actually changes.

**Response:** `{ "link": … }`. `409 DISPLAY_LINK_REVOKED` for a revoked link.
Audit: `display_link.paused` or `display_link.resumed` when only `enabled`
changed, `display_link.updated` otherwise.

### DELETE /api/display-links/:id

**Who:** admin. Revokes the link: `{ "revoked": true }`. Its screens show
"revoked" at their next refresh and stop. This can't be undone: create a new
link. The row stays (without a usable secret) for the audit trail, and its
name is free again. Audit: `display_link.revoked`.

### POST /api/display-links/:id/rotate

**Who:** admin. A new secret for the link; the old one stops at once (its
screen shows "not valid any more" at its next refresh). The devices seen and
`last_used_at` belonged to the old secret and are cleared. **Response:**
`{ "link", "token", "path" }`, as on create; the new secret is shown only
here. Audit: `display_link.rotated`.

### POST /api/display-links/preview

**Who:** admin. **Body:** `{ "config": { … } }` (validated as on create). The
snapshot that layout would show, exactly as a screen would get it
(`display.name` is `"Preview"`). Nothing is stored and no link is used.

### GET /api/display-links/:id/snapshot

**Who:** admin. The saved link's snapshot, exactly as its screen gets it,
without the secret. It doesn't count as the link's use (`last_used_at` and
the devices seen are untouched). `404` for no such link, `409
DISPLAY_LINK_REVOKED` for a revoked one.

### GET /api/big-display/snapshot

**Who:** any signed-in role (`Authorization: Bearer`; a session that must
change its password gets `403 PASSWORD_CHANGE_REQUIRED`). Big Display on the
user's own session: the default views SOC overview, Threats and Health,
rotating every 30 s, in `operations` privacy (`display.name` is `"Big
Display"`). `endpoints` (in Health) is `forbidden` for every role but admin,
and no alarm comes from it.

### Audit and recovery

Every change writes an `audit_logs` row with `resource_type` `display_link`
and the link's id: `display_link.created`, `.updated`, `.paused`, `.resumed`,
`.rotated`, `.revoked`, and from screens `.client_first_seen` and
`.refused_network`. `details` names the link and the changed fields, with old
and new values for `enabled`, `privacy`, `expires_at` and `allowed_cidrs`. No
row ever holds a secret or its hash.

When the web UI can't be used, the backend's `auth-admin` CLI lists and
revokes links (it writes `display_link.revoked` with no user and
`details.by = "cli"`):

```bash
docker exec siembox-backend node dist/scripts/auth-admin.js display-links [--all]
docker exec siembox-backend node dist/scripts/auth-admin.js revoke-display-link <id|all>
```

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

### GET /api/admin/sign-in-protection

Everything Settings -> Sign-in protection shows (see
[Sign-in Protection](#sign-in-protection)). Sent with `Cache-Control: no-store`.

**Authentication:** Required (Admin)

**Response (200):**
```json
{
  "clientAddress": { "you": { "address": "192.168.1.50", "via": "proxy-socket", "signInKey": "192.168.1.50" }, "warnings": [] },
  "counters": [
    {
      "key": "acct:9f86d0...",
      "scope": "acct",
      "scopeLabel": "Account from new browsers (all networks)",
      "user_id": 1,
      "username": "admin",
      "network": null,
      "failures": 21,
      "pauses": 2,
      "paused_until": "2025-11-30T12:12:00.000Z",
      "paused_seconds": 95,
      "first_failure_at": "2025-11-30T11:40:00.000Z",
      "last_failure_at": "2025-11-30T12:11:00.000Z",
      "last_user_agent": "python-requests/2.31",
      "refusedSinceStart": 340
    }
  ],
  "last24h": { "failures": 412, "unknownUsernames": 380 },
  "refused": { "sinceStart": 1290, "byReason": { "account": 340, "network": 950 } },
  "settings": {
    "protection": true,
    "alerts": true,
    "failureAuditRetentionDays": 90,
    "firstPauseSeconds": 30,
    "streakResetHours": 24,
    "browserRevokeFailures": 20,
    "scopes": [{ "scope": "aip", "label": "Account from one network", "threshold": 5, "capSeconds": 900, "resetOnSuccess": true }]
  }
}
```

- `clientAddress`: the whole [`GET /api/admin/client-address`](#get-apiadminclient-address) report.
- `counters`: keys that are paused or failed in the last 24 hours, paused ones
  first (at most 500). `username` is `null` for a username that doesn't exist
  (stored only as a hash) and for network keys. `refusedSinceStart` counts the
  attempts turned away while paused since the backend started.
- `last24h`: `auth.login.failure` audit rows in the last 24 hours, and how many
  of them were for usernames that don't exist.
- `settings`: in effect, from the environment (read-only).

### POST /api/admin/sign-in-protection/clear

Delete sign-in counters, which ends their pauses at once. Audited as `auth.unlock`.

**Authentication:** Required (Admin)

**Request Body:** exactly one of

```json
{ "key": "ip:203.0.113.7" }
{ "userId": 2 }
{ "network": "203.0.113.7" }
{ "all": true }
```

`network` is an address (an IPv6 address stands for its /64), an IPv6 `/64`,
or `unknown` (requests that had no address).

**Response (200):** `{ "cleared": 3 }`

**Errors:** `400` - not exactly one target, or an invalid key or network; `404` - no such user

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
