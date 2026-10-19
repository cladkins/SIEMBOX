# Big Display and read-only display links — Design

A full-screen, dark, auto-refreshing board for a NOC wall or an office TV,
readable from across the room, that can rotate through views. Two ways open
it:

1. **A display link**: a read-only link for an unattended screen. No user
   signs in on the screen, the link never expires on its own, and it never
   touches a signed-in user's session in the same browser.
2. **Signed-in Big Display** (`/big-display`): the same board for any signed-in
   user, with their own session and role.

This is the internal design record. The API is in
[API.md](../reference/API.md#display-links-big-display) ("Display link
tokens" and "Display links (Big Display)"), the security notes in
[SECURITY.md](../reference/SECURITY.md#display-links-wall-screens).

## Status

The feature ships in five pull requests; each leaves `main` working.

| PR | Contents | State |
|---|---|---|
| 1. Ingest rollup | Migration 041 `ingest_source_minute`, kept at ingest by `services/ingest/ingestCounter.ts`; the UDP drop accessor | Merged |
| 2. Display links and their auth | Migration 042; `services/display/{token,config,linkStatus}.ts`; `models/DisplayLink.ts`; `middleware/displayAuth.ts` (gate, failed-lookup limiter, use tracking); `routes/displayLinks.ts` (admin CRUD, pause, rotate, revoke); `routes/display.ts` (`GET /api/display/snapshot` with the layout and **empty panels**); audit; the route inventory's `DISPLAY` kind; `auth-admin display-links` / `revoke-display-link` | This document's first version |
| 3. Snapshot builder | The panel registry, SQL and shared caches; privacy redaction; alarms; fills `panels`; adds `/api/big-display/snapshot`, `/api/display-links/:id/snapshot` and `/api/display-links/preview` | Merged |
| 4. Display page | `frontend/display.html` and `src/display/**`, a separate Vite entry served by nginx at `/display`; isolation lint rules; bundle check; `frontend/scripts/verify-display.mjs` (Playwright) | Built |
| 5. Admin UI and signed-in Big Display | Settings → Display links (editor with live preview, shown-once dialog with QR code, devices seen); `/big-display`; the Dashboard button | Planned |

## Owner decisions

- **Both**: display links for unattended screens *and* a signed-in Big
  Display button.
- **Default privacy: Operations room** (rule names, collector and host names,
  IPs). Public area (numbers only) stays selectable per link. Never shown in
  any mode: alert titles and descriptions, usernames, email addresses, breach
  names, raw log text.
- **One display-link mechanism for the whole product.** Other features (the
  Context Graph among them) don't get their own: a future graph panel or view
  on a board is a new panel kind in the same config, never a second token
  system ([Adding a panel kind](#adding-a-panel-kind)).
- Endpoint (EDR) health is not on display links in v1 (signed-in admins
  only); the network allow-list is optional per link; one link per screen,
  with no pairing step.
- **Display links never expire unless an admin sets a date**, and survive
  restarts, upgrades, password changes and the creating admin leaving.
  Pause, rotate and revoke act at the screen's next refresh.

## A display link

### The secret

- `'sbd1_' + crypto.randomBytes(32).toString('base64url')`: 48 characters, 256
  bits (`services/display/token.ts`). The versioned prefix lets secret
  scanners recognise a leaked one and can never be mistaken for a session
  token (64 hex).
- Checked against `^sbd1_[A-Za-z0-9_-]{43}$` (and its length) before anything
  is hashed or queried.
- Stored as `sha256hex(token)` (`models/EdrAgent.ts`), like EDR keys and shipper
  push keys: a fast hash is right for a high-entropy random secret. Looked up
  through the `UNIQUE` index on `token_hash`, so no constant-time compare is
  needed. `token_hint` (the last 4 characters) lets an admin match a screen to
  its row.
- Returned only by the create and rotate calls (`Cache-Control: no-store`).
  List and get never return it or its hash; no audit row holds either. Tests
  assert all of this.

### Where it travels

- The admin UI builds `${location.origin}/display#k=${token}`, so the server
  never needs to know its own public URL (the API returns the `path`).
- The fragment is never sent to nginx, the backend, outer proxies or a
  `Referer`, so it never lands in an access log or in `application_errors`
  (which records `originalUrl`). It deliberately stays in the address bar:
  reloads, kiosk restarts and TV-browser bookmarks keep working with no
  browser storage.
- The display page sends it as `X-Display-Token` on
  `GET /api/display/snapshot`. Never in `Authorization`, a path or a query
  string.

### The server's check (`middleware/displayAuth.ts`)

`router.get('/snapshot', displayTokenLimiter, authenticateDisplay, handler)`:

| Order | Condition | Answer |
|---|---|---|
| 1 | No `X-Display-Token` | 401 `DISPLAY_TOKEN_REQUIRED` |
| 2 | Malformed (never hashed or looked up) | 401 `DISPLAY_LINK_INVALID` |
| 3 | The lookup throws (database down) | 503 `DISPLAY_UNAVAILABLE`, `Retry-After: 5`, never "invalid" |
| 4 | No link has the hash (rotated, never issued) | 401 `DISPLAY_LINK_INVALID`, the same answer as 2 |
| 5 | `revoked_at` set | 401 `DISPLAY_LINK_REVOKED` |
| 6 | `expires_at` passed | 401 `DISPLAY_LINK_EXPIRED`, with `expires_at` |
| 7 | Paused (`enabled = false`) | 403 `DISPLAY_LINK_PAUSED` |
| 8 | The client address is outside `allowed_cidrs` | 403 `DISPLAY_NETWORK_NOT_ALLOWED` |

- **One statement per request** (`DisplayLinkModel.findForAuth`), through the
  unique index, re-read every time: nothing about authorization is cached, so
  pause, rotate and revoke act at the next refresh. Measured: an Index Scan on
  `display_links_token_hash_key`, 0.03 ms with 5,000 rows; 300 sequential
  authenticated snapshots through the real app took 1.7 ms p50, 3.0 ms p95.

  ```sql
  SELECT id, name, config, config_version, enabled, expires_at, revoked_at,
         COALESCE(cardinality(allowed_cidrs) = 0 OR $2::inet <<= ANY (allowed_cidrs), false) AS address_allowed
    FROM display_links WHERE token_hash = $1;
  ```

  The `COALESCE` matters: with no client address, `NULL::inet <<= ANY(...)` is
  NULL, which must read as "not allowed" when there is a list.
- **Refusals are answered, not thrown**, like `PASSWORD_CHANGE_REQUIRED`: the
  standard envelope plus `code`, `Cache-Control: no-store`, no "API Error" line,
  no `application_errors` row, no audit row. A revoked TV in a corner can't
  fill the error log. They are counted in memory and summed up in one log line
  every 5 minutes (in the style of `authEvents.noteRefusal`).
- **The one audited refusal** is a valid secret used from outside its
  networks (`display_link.refused_network`, at most once per link and address
  per hour, in a map of at most 5,000 entries): a leak signal.
- **A display token is never a login.** `authenticate` never reads
  `X-Display-Token`, and `authenticateDisplay` never reads `Authorization`.
  The route inventory proves both directions (below).

### The failed-lookup limiter (`displayTokenLimiter`)

- 15-minute window, 30 per client address (`requestLimitKey`), counting only
  answers with status 401 (`skipSuccessfulRequests` with `requestWasSuccessful:
  status !== 401`). A working, paused, out-of-network or database-down screen
  never uses it up.
- The 31st gets 429 `RATE_LIMITED` with `Retry-After`, from
  `rateLimitedHandler`, before `authenticateDisplay`: guessing costs no
  database work after 30 misses.
- Display requests also count towards the general `/api` limit and are not
  exempt: one screen at 30 s makes 30 of the 1,000 requests per 15 minutes; ten
  screens behind one address make 300.
- Display refusals never touch `login_throttle`, recognized browsers or
  `auth.*` audit rows (`displayIndependence.db.test.ts`).

### Lifetime

| Action | On the screen | Reversible |
|---|---|---|
| **Pause** (`PUT {enabled:false}`) | 403 `DISPLAY_LINK_PAUSED`: "Paused by an administrator", rechecks every 60 s and resumes by itself | Yes (`{enabled:true}`) |
| **Rotate** (`POST /:id/rotate`) | The old secret gets 401 `DISPLAY_LINK_INVALID` at its next refresh. A new secret, shown once; the old hash is replaced; the devices seen and `last_used_at` are cleared (they belonged to the old secret) | No, for the old secret |
| **Revoke** (`DELETE /:id`) | 401 `DISPLAY_LINK_REVOKED`; the screen stops polling. The row stays (without a usable secret) for the audit trail; its name is free again; it can't be changed, rotated or revoked again (409) | No: create a new link |
| **Expiry** (`expires_at`, default NULL = never) | 401 `DISPLAY_LINK_EXPIRED`, rechecks every 10 min; extending the date revives the same link | Yes |
| **Network allow-list** (`allowed_cidrs`, empty = any) | 403 `DISPLAY_NETWORK_NOT_ALLOWED`, rechecks every 5 min | Yes |

What does **not** stop a link (each one tested): the creator changing or
resetting their password (`auth-admin reset-password` included); the creator
being required to change their password; the creator's sessions expiring or
being cleaned up; the creator being deleted (`created_by` and `updated_by`
become NULL, shown as "deleted user"); server restarts and redeploys; a
database restore (the hash is in the backup). Links belong to the install,
like shipper and agent keys.

### Devices seen (`display_link_clients`)

- The address and user agent of each device that used a link, with first and
  last seen, written by `touchUsed()` without holding up the response: at most
  once a minute per (link, address), from an in-memory map of at most 5,000
  entries (cleared when full). A use with no client address only updates
  `last_used_at`. The write is conditioned on the secret the request
  authenticated with still being the link's live one, so a use in flight
  when an admin rotates or revokes the link records nothing.
- An address new to the link (`RETURNING (xmax = 0)` on the upsert) trims the
  link to its 20 most recently seen addresses and writes
  `display_link.client_first_seen` (at most 10 per link per hour).
- Informational only: "seen from 3 addresses in 24 h" on a one-screen link is
  worth a look. It never refuses a request.

### The admin list's status (`services/display/linkStatus.ts`)

`revoked`, then `expired`, then `paused`; otherwise `never_used`, `live` or
`idle`. `live` means a use within `max(3 × refresh, 60 s + 2 × refresh)`:
uses are written once a minute, so a 15 s screen would otherwise read `idle`
between writes.

### Recovery from the command line

`auth-admin display-links [--all]` lists id, name, status, last use and
creator; `auth-admin revoke-display-link <id|all>` revokes and writes
`display_link.revoked` with no user and `details.by = 'cli'`, as the CLI's
other audited actions do. Revoking a leaked link must work when the UI
doesn't.

## Data model (migration 042)

```sql
display_links (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
  token_hash CHAR(64) NOT NULL UNIQUE, token_hint CHAR(4) NOT NULL,
  config JSONB NOT NULL, config_version INTEGER NOT NULL DEFAULT 1,
  enabled BOOLEAN NOT NULL DEFAULT TRUE, allowed_cidrs CIDR[] NOT NULL DEFAULT '{}',
  expires_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ,
  created_by / updated_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at, updated_at, token_rotated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMPTZ)
idx_display_links_live_name UNIQUE (lower(name)) WHERE revoked_at IS NULL
display_link_clients (link_id → display_links ON DELETE CASCADE, ip INET, user_agent, first_seen, last_seen,
                      PRIMARY KEY (link_id, ip))
idx_alerts_open_severity ON alerts (severity, status, created_at) WHERE status IN ('new', 'investigating')
```

- Creates take a transaction-level advisory lock, so two at once can't both
  pass the 50-live-link limit. Live names are unique case-insensitively
  through the partial index (409 `DISPLAY_LINK_NAME_TAKEN`).
- `config_version` goes up only when the config changes (JSONB equality, so
  key order doesn't count); every snapshot carries it, so a screen applies a
  new layout at its next refresh.
- `idx_alerts_open_severity` makes the Open alerts panel (PR 3) an index-only
  scan. Measured on PG 16 with 200 k alerts, 80 k open: Index Only Scan, 12.5
  ms, against 23.0 ms for a parallel sequential scan without it; it built in
  0.10 s and takes 1.3 MB. It is written only when an alert is inserted or
  changes status. A plain `CREATE INDEX`: migrations finish before the API
  starts, and `scripts/migrate.ts` runs each file as one query, which rules out
  `CONCURRENTLY`. It does not duplicate the Context Graph's `idx_graph_*`
  indexes on `alerts`, which are expressions on `matched_data`, `rule_id` and
  `asset_id` for lookups.

## The board layout (`services/display/config.ts`)

A pure, unit-tested validator in the style of `exposure/validation.ts`. Unknown
keys and out-of-range values are refused with the path of the field
(`config.views[0].panels[2].id`), never ignored; the stored config has every
default filled in. The server always reads the config from the link's row:
the token never selects what is queried, and a config holds no free-form
filters, JSON paths or SQL.

```ts
interface DisplayConfig {
  privacy: 'operations' | 'public';                  // default 'operations'
  refresh_seconds: 15 | 30 | 60 | 120;               // default 30
  rotation: { enabled: boolean; seconds: number };   // 10..600, default { true, 20 }; ignored with one view
  timezone: string | null;                           // IANA (canonicalized), 'UTC', or null = the screen's own
  clock: boolean;                                    // default true
  burn_in_shift: boolean;                            // default true
  views: Array<{ title: string; panels: PanelSpec[] }>; // 1..6 views; title 1..40; 1..6 panels; no repeated key in a view
}
```

Limits: at most 12 distinct panel keys per config (it bounds the work per
snapshot), 16 kB serialized, 32 kB request bodies, 50 live links, 32
`allowed_cidrs` (normalized to network form with `node:net`; an
IPv4-mapped IPv6 network becomes its IPv4 network, as client addresses are
compared in IPv4 form).

### Panel kinds (`PANEL_KINDS`)

| Kind | Option (default) | `minRole` | Public area |
|---|---|---|---|
| `open_alerts`, `alert_pulse`, `ingest`, `shippers`, `digital_risk`, `vulnerabilities` | — | viewer | yes |
| `recent_alerts` | `min_severity`: critical, high (default), medium | viewer | yes |
| `sources` | `silent_after_minutes`: 5, 15 (default), 30, 60 | viewer | yes |
| `threat_map` | `window_days`: 1 (default), 7, 30 | viewer | yes |
| `top_rules` | `window_hours`: 1, 24 (default) | viewer | no |
| `top_sources` | — | viewer | no |
| `endpoints` | — | admin | no (and refused on any link) |

A panel's **key** is its id plus its option (`recent_alerts:high`,
`top_rules:24`, `sources:15`, `threat_map:7`); variant-free ids are bare.
Display links may only use `minRole: 'viewer'` kinds: a link never shows what
some signed-in role can't read. The route inventory test checks the registry
(`services/display/panels.ts`): each viewer kind's `viewerRoutes` must be
ANY_ROLE rows, and every other kind must be refused in a link's config.

### Adding a panel kind

One row in `PANEL_KINDS` in `config.ts` (its option, `minRole`, whether a
public display may show it); its `viewerRoutes`, TTL, fixed SQL and fold in
`panels.ts`; its declared shape in `redact.ts`; and its component on
the board. A future **graph** view on a board (the Context Graph) is such a
kind: it rides on the same links, secret, gate, audit trail and admin UI, with
no second token system. Its `minRole` and privacy rules decide where it may
appear, the same way as for every other kind.

## Privacy

| Label | Source | Operations | Public |
|---|---|---|---|
| Rule label | `detection_rules.name` (every role reads it via `GET /api/rules`) | yes | no ("Detection rule") |
| Category label | A closed map of `alerts.source` ("Sign-in protection", "Leaked credentials", ...) | yes | yes |
| Shipper name | `log_shippers.name` | yes | no |
| Source host | `discovery_sources.hostname` / `assets.hostname`, if it is a plain host name; else the IP | yes | no |
| IP address | `raw_logs.source_ip`, `matched_data.source_ip`, only if `net.isIP()` | yes | no |
| Country | ISO code only (`^[A-Z]{2}$`) | yes | yes |

Never read for a display: `alerts.title` and `.description` (titles embed
usernames and email addresses), any `matched_data` key but `source_ip` and
`country_code`, raw or parsed log text, usernames, account names, breach
names, lookalike domains. The config validator refuses `endpoints` on a link
and `top_rules` and `top_sources` on a public one; the panels' fixed SQL never
selects those columns; `safeLabel()` cleans labels; and `assertDisplaySafe()`
makes a panel `unavailable` rather than send a string outside its declared
shape. `routes/displayPrivacy.db.test.ts` seeds canaries in every one of those
places and checks no display, in either mode, carries them.

## Roles

| | admin | operator / analyst / viewer | must change password | display link |
|---|---|---|---|---|
| `/api/display-links` (manage links) | yes | 403 | 403 `PASSWORD_CHANGE_REQUIRED` | 401 `Authentication required` |
| `GET /api/display/snapshot` | only with a display token | only with a display token | only with a display token | yes |
| Signed-in `/big-display` (PR 3/5) | every panel, `endpoints` included | every panel but `endpoints` | 403 `PASSWORD_CHANGE_REQUIRED` | — |
| Affected by the creator's account | — | — | — | No |

The route inventory (`routeInventory.test.ts`) has a `DISPLAY` kind ("display
link token, never a login"). For `GET /api/display/snapshot` it checks the
anonymous answer (401 `DISPLAY_TOKEN_REQUIRED`, never `Authentication
required`), malformed and unknown tokens (401 `DISPLAY_LINK_INVALID`), every
role's session and both restricted sessions as `Authorization` and as
`X-Display-Token` (exactly the anonymous and invalid outcomes: never 403,
never reached), a live, a paused and a revoked stubbed link, and that no
refusal is audited or logged. A second test sends a valid display token, as
`X-Display-Token` and as a Bearer token, to every route that takes a login
(401 `Authentication required` / `Invalid or expired session`), every agent
route (the stranger's outcome) and every public route (reached).

## The board (PRs 3–5, as designed)

- **Snapshot**: `{ generated_at, server_time, app_version, display, alarms,
  attributions, panels }`, one `GET` per screen per refresh (30 s by
  default), 5–15 kB of JSON. Panels are built from per-kind caches every screen
  shares (`createSnapshotCache`, single-flight, stale on failure), with at most
  3 display queries at once, a 4 s statement timeout per panel and an 8 s soft
  budget, so ten screens cost the database what one does. Each panel arrives
  `ok`, `stale`, `unavailable`, `not_configured` or (signed-in only)
  `forbidden`.
- **Display page**: a separate Vite entry (`display.html` → `src/display/main.ts`)
  served by nginx at `location = /display`, with its own `fetch` client. It
  never loads the main app's router guard, Pinia, the auth or theme stores,
  axios or Element Plus, reads and writes no localStorage, and never sends
  `Authorization`, so opening a link in a browser where an admin is signed in
  can't sign them out or change their theme. ESLint rules enforce this; a
  Playwright run proves it.
- **Signed-in Big Display**: `/big-display` with the user's session and
  role (`endpoints` comes back `forbidden` for non-admins), and admins can open
  any link's layout there (`?link=<id>`).

## Code map

| File | Role |
|---|---|
| `backend/migrations/042_display_links.sql` | Tables, the live-name index, `idx_alerts_open_severity` |
| `backend/src/services/display/token.ts` | Secret format, hint, hash, path |
| `backend/src/services/display/config.ts` | `PANEL_KINDS`, the config and request-body validators, CIDR and time-zone normalization, the snapshot's `display` block |
| `backend/src/services/display/linkStatus.ts` | The admin list's status |
| `backend/src/models/DisplayLink.ts` | create (with the limit lock), list, findById, update, rotate, revoke, findForAuth, touch, trimClients |
| `backend/src/middleware/displayAuth.ts` | `authenticateDisplay`, `displayTokenLimiter`, use and leak signals, refusal counts |
| `backend/src/routes/display.ts` | `GET /api/display/snapshot` |
| `backend/src/routes/displayLinks.ts` | Admin CRUD, pause, rotate, revoke, audit |
| `backend/src/scripts/auth-admin.ts` | `display-links`, `revoke-display-link` |
| `backend/src/app.ts` | 32 kB body caps on `/api/display` and `/api/display-links`; the mounts (`/api/display-links` behind `authenticate, requireAdmin`) |

Tests: `services/display/{token,config}.test.ts` (pure), `middleware/displayAuth.test.ts`
(stubbed model: refusal order, 503, the address NULL case, nothing logged,
the limiter), `routes/routeInventory.test.ts` (the `DISPLAY` rows and the
never-a-login sweep), `routes/displayLinks.db.test.ts` (the lifecycle, limits,
networks, devices, audit, CLI) and `routes/displayIndependence.db.test.ts`
(the creator's account never matters; display refusals never touch sign-in
protection).

## Decisions made while building PR 2

- **`live` window**: `max(3 × refresh, 60 s + 2 × refresh)` instead of 3 ×
  refresh, because uses are written at most once a minute.
- **Rotate clears `last_used_at`** as well as the devices seen: both describe
  the old secret, so the list reads "never opened" until the new link is on
  the screen.
- **Revoking twice, or changing a revoked link**, is 409
  `DISPLAY_LINK_REVOKED` (the API and the CLI alike).
- **`DISPLAY_LINK_EXPIRED` carries `expires_at`**, so the screen can say when.
- **The 32 kB cap covers `/api/display` too**, and form bodies as well as
  JSON, as `/api/auth` does.
- **`auth-admin display-links --all`** also lists revoked links.
