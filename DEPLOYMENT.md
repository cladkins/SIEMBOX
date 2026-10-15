# SIEMBox Deployment Guide

## Prerequisites
- Docker and Docker Compose installed
- Ports 514, 8420, 8421, and 5432 available

## Deployment Options

SIEMBox can be deployed in two ways:
1. **Pre-built Images** (Recommended) - Use images from GitHub Container Registry
2. **Build from Source** - Clone repo and build containers locally

---

## Option 1: Pre-built Images (Recommended)

### 1. Download Compose File

```bash
# Create a directory for SIEMBox
mkdir siembox && cd siembox

# Download the production compose file
curl -O https://raw.githubusercontent.com/cladkins/SIEMBOX/main/compose.prod.yaml

# Download the rules directory (required for detection rules)
curl -L https://github.com/cladkins/SIEMBOX/archive/main.tar.gz | tar -xz --strip-components=1 SIEMBOX-main/rules
```

### 2. Create Environment File

Create a `.env` file:

```bash
# Database Configuration
DB_NAME=siembox
DB_USER=siembox
DB_PASSWORD=your_secure_password_here

# Backend Configuration
JWT_SECRET=your_jwt_secret_key_here
DEFAULT_ADMIN_PASSWORD=your_admin_password_here
NODE_ENV=production
LOG_LEVEL=info

# Optional: Specify version (default: latest)
# SIEMBOX_VERSION=2.0.0
```

> **Optional v2 features.** The AI builder, parser/detection catalog, and GeoIP
> enrichment are all configured with additional (optional) environment variables —
> `CREDENTIAL_ENCRYPTION_KEY`, `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`,
> `SIEMBOX_CATALOG_REPO` / `SIEMBOX_CATALOG_REF` / `GITHUB_TOKEN`, and
> `GEOIP_HOME_COUNTRIES`. All have safe defaults; see
> [`.env.example`](./.env.example) for the full annotated list. You can also set the
> AI key from the UI (*Settings → AI Builder*), stored encrypted at rest.

### 3. Start SIEMBox

```bash
docker compose -f compose.prod.yaml up -d
```

### 4. Verify Deployment

```bash
# Check containers are running
docker compose -f compose.prod.yaml ps

# Check backend health
curl http://localhost:8421/health
```

---

## Option 2: Build from Source

### 1. Clone and Configure

```bash
git clone https://github.com/cladkins/SIEMBOX.git
cd SIEMBOX
```

### 2. Create Environment File

Create a `.env` file in the project root:

```bash
# Database Configuration
DB_NAME=siembox
DB_USER=siembox
DB_PASSWORD=your_secure_password_here

# Backend Configuration
JWT_SECRET=your_jwt_secret_key_here
DEFAULT_ADMIN_PASSWORD=your_admin_password_here
NODE_ENV=production
LOG_LEVEL=info

# Frontend Configuration
VITE_API_URL=/api

# Optional: Cleanup Service
CLEANUP_INTERVAL_HOURS=24
```

### 3. Build and Deploy

```bash
docker compose up -d --build
```

---

## Container Images

SIEMBox containers are available on GitHub Container Registry:

| Image | Description |
|-------|-------------|
| `ghcr.io/cladkins/siembox-backend` | Backend API + Syslog server |
| `ghcr.io/cladkins/siembox-frontend` | Vue.js web interface |
| `ghcr.io/cladkins/siembox-log-shipper` | Log forwarding agent |

### Available Tags
- `latest` - Most recent build from main branch
- `1.0.0`, `1.0`, `1` - Semantic version tags from releases

---

## Services Overview

The compose file defines these services:
- **PostgreSQL** - Database (port 5432, internal)
- **Backend** - API server (port 8421) + Syslog (port 514/UDP+TCP)
- **Frontend** - Web interface (port 8420)

### 4. Verify Database Initialization

The database migrations run automatically when the backend container starts. This includes:
- Running all database migrations
- Creating the `admin` account, when the database has no users yet

A fresh install is **catalog-only**: no parsers or detection rules are seeded, so
the deployment starts empty and you install exactly what you want. The process is
fully automated and requires no manual intervention. Monitor your deployment logs
to verify completion.

On first startup, SIEMBox automatically:
- Runs all database migrations
- Creates the `admin` account, which must choose a new password at its first sign-in

**No manual steps required to boot.** Once you log in, populate parsers and
detections from the in-app catalog — open *Parsers → Browse Catalog* and
*Detection Rules → Browse Catalog* and click **Install all** (or pick individual
items). The same catalog is the update path later.

### 5. Access the Application

Once SIEMBox is running:

- **Frontend (Web UI):** http://your-server-ip:8420
- **Backend API:** http://your-server-ip:8421
- **Syslog Listener:** your-server-ip:514 (UDP and TCP)
- **First sign-in:** `admin`, with the `DEFAULT_ADMIN_PASSWORD` from `.env`
  (`changeme` if it is unset). SIEMBox then asks for a new password before
  anything else works, and signs you out so you sign in again with it. The
  `.env` value is used only this once: it creates the account on the first
  start, and changing it later has no effect.

> ⚠️ Until that first sign-in, whoever reaches the web UI first with that
> password chooses the admin's new password. Keep ports 8420 and 8421 off
> untrusted networks until you have signed in, or set a `DEFAULT_ADMIN_PASSWORD`
> only you know before the first start.

### 6. Send Test Syslog

To verify logs are being ingested correctly, send a test syslog message from any machine on your network:

```bash
# Using logger utility
logger -n your-server-ip -P 514 "Test message from logger"

# Or using netcat (if available)
echo "<134>$(date '+%b %d %H:%M:%S') testhost test: This is a test message" | nc -u your-server-ip 514
```

Check the SIEMBox UI to confirm the test message appears in the log viewer.

## Troubleshooting

### Database Connection Errors

**Symptoms:** Backend container fails to start or reports "Connection refused"

**Root Cause:** Usually PostgreSQL hasn't finished initializing

**Solution:**
1. Check that PostgreSQL container is running and healthy
2. Wait 10-15 seconds and check again
3. Review deployment logs for initialization progress

### Port Conflicts

**Symptoms:** Containers won't start or "port already in use" errors

**Ports Required by SIEMBox:**
- **8420:** Frontend web interface (HTTP)
- **8421:** Backend API (HTTP)
- **514:** Syslog listener (UDP and TCP)
- **5432:** PostgreSQL database (bound to `127.0.0.1` on the Docker host in both compose files, so it is not reachable from the LAN)

**Solution:**
1. Verify no other services are using these ports
2. Ensure firewall rules allow traffic on these ports
3. Check your deployment platform's port mappings

### Logs Not Being Received

**Symptoms:** Syslog listener is running but no logs appear in the UI

**Solutions:**
1. Verify source machine can reach your-server-ip:514
2. Confirm firewall allows UDP/TCP on port 514
3. Test with manual syslog message (see section 6 above)
4. Check SIEMBox logs for parsing errors

### Container Won't Start

Review your deployment platform's logs for the specific error message. Common issues:
- Database not ready (wait 10-15 seconds)
- Port already in use (check for conflicts)
- Insufficient disk space
- Network connectivity issues

### Authentication Issues

**Problem:** Can't log in with admin credentials

**Solution:**
1. Verify DEFAULT_ADMIN_PASSWORD is set correctly. It only counts on the very
   first start, when the account is created; after you changed the password
   at the first sign-in, use that one
2. Wait for first-run initialization to complete
3. Check database is running and initialized
4. Review backend logs for authentication errors (`Login failed` lines carry
   the reason and address)
5. "Too many failed sign-in attempts" with a countdown: sign-in is paused after
   failed attempts. Wait, use a browser you signed in with before, or unlock it
   (see [Sign-in protection](#sign-in-protection))

**Problem:** Every page sends me to "Choose a new password"

**Solution:** The account signed in with a password it has to replace: the
initial `admin` password, SIEMBox's default `changeme`, or a temporary one an
admin (or `auth-admin reset-password`) set. Enter the password you just signed
in with and a new one; you are signed out, and the new one works everywhere.
Scripts that sign in get `403` with `code: "PASSWORD_CHANGE_REQUIRED"` until
then. See [TROUBLESHOOTING.md](docs/operations/TROUBLESHOOTING.md#issue-every-page-sends-me-to-choose-a-new-password--api-answers-403-password_change_required).

### Need Help?

If you encounter issues not covered here:
1. Check [GitHub Issues](https://github.com/cladkins/SIEMBOX/issues)
2. Review [Troubleshooting Guide](./docs/operations/TROUBLESHOOTING.md)
3. Search [GitHub Discussions](https://github.com/cladkins/SIEMBOX/discussions)

## Updating

To update SIEMBox to the latest version:

1. Pull latest code from the repository
2. Review any changes to `.env.example` and update your `.env` if needed
3. Rebuild and restart containers (through your deployment platform)
4. Migrations run automatically on backend startup

Note: Do not run docker-compose commands directly. Your deployment environment will handle container updates.

**Updating to the release with the proxy socket:** update the compose file
too, not only the images. The new one adds the `api-socket` volume (backend
`/run/siembox`, frontend `/run/siembox:ro`) and passes `TRUSTED_PROXIES`,
`API_RATE_LIMIT_MAX`, `EDR_AGENT_RATE_MAX`, `SHIPPER_LOG_PUSH_MAX` and
`SIEMBOX_PROXY_SOCKET` from your `.env`. An older compose file keeps working:
nginx falls back to TCP and logs `connect() to unix:/run/siembox/api.sock
failed` about every 30 s. But with host networking every web UI user then
shares one address.

> ⚠️ **Running with host networking?** The shipped compose files have
> `network_mode: host` commented out. If you replace your file with the new
> one, make your [host-networking edits](#optional-host-networking-linux-only)
> again before you deploy it: with `DB_HOST=localhost` still in your `.env`, a
> bridge-mode backend dials its own container instead of Postgres and restarts
> in a loop. Alternatively keep your file and add only the new lines: the
> `api-socket:/run/siembox` volume on the backend, `api-socket:/run/siembox:ro`
> on the frontend, the top-level `api-socket` volume, and the environment
> entries above.

Other changes in that release:
- `X-Forwarded-For` from direct callers on port 8421 is ignored. A reverse
  proxy in front of SIEMBox needs `TRUSTED_PROXIES` (see [Client addresses and
  reverse proxies](#client-addresses-and-reverse-proxies)); until then every
  user behind it shares its address. The backend logs which proxy it is
  ignoring only for a proxy on a private or other local address; check a
  proxy on a public address (such as Cloudflare's) with
  `GET /api/admin/client-address` through it.
- A `429` from the general limit is JSON with `Retry-After`.
- Failed sign-ins were limited by an interim in-memory limit (10 per account
  per address, 100 per address per 15 minutes); the next release replaces it
  with sign-in protection (below).
- EDR agent enrollment counts toward the general limit, even with an
  `X-Agent-ID` header.

**Updating to the release with sign-in protection** (migration
`038_sign_in_protection.sql` runs on its own):
- Failed sign-ins pause further attempts per account and network, per network
  and per account, in Postgres, with recognized browsers exempt from the
  account and network pauses (see [Sign-in protection](#sign-in-protection)).
  The compose files pass the new `LOGIN_*` and `AUTH_*` settings from `.env`;
  an older compose file runs with the defaults.
- A paused sign-in is a `429` with `code: "SIGNIN_PAUSED"`, `reason`,
  `retryAfter` and a `Retry-After` header.
- `PUT /api/auth/me/password` answers a wrong current password with `400`
  instead of `401`.
- TOTP codes work once each: two sign-ins within the same 30 seconds need two
  different codes.
- The login page no longer shows "Default credentials: admin / changeme".
- An admin's password reset signs the user out everywhere.
- Recovery without the web UI: `docker exec siembox-backend node
  dist/scripts/auth-admin.js ...` (unlock, reset-password, disable-mfa).

**Updating to the release with same-origin CORS:** `CORS_ORIGIN` now defaults
to empty, which means same-origin only: the API sends no CORS headers, so a
page on another origin can no longer call it from a browser (see [Browser
access from other origins (CORS)](#browser-access-from-other-origins-cors)).
- **Not affected:** the bundled web UI (nginx serves it and proxies `/api`),
  the Vite dev server's proxy, log shippers, endpoint agents, scripts and
  `curl`.
- **Affected:** browser code on another origin that calls the API: a UI built
  with an absolute `VITE_API_URL` such as `http://<host>:8421/api`, a frontend
  dev setup with that in `.env.local`, your own dashboard or tool on another
  host. Its requests now fail with "blocked by CORS policy" in the browser
  console. **The fix is one line in `.env`**, the origin that page is served
  from, then `docker compose up -d`:
  `CORS_ORIGIN=https://dash.example.com` (several: comma-separated).
- **A `.env` copied from the old `.env.example` still says `CORS_ORIGIN=*`**,
  which keeps the old behaviour and now logs a warning at every start. Unless
  you need it, change it to `CORS_ORIGIN=` (empty) or list your origins.
- `CORS_ORIGIN` takes a comma-separated list now; an entry that isn't an exact
  origin (a path, a wildcard, no scheme) is ignored with a warning.

**Updating to the release with required password changes** (migration
`039_password_change_required.sql` runs on its own; no `.env` or compose
change):
1. **An admin account still on `changeme` is restricted at the first start.**
   It can then only change its password or sign out. The backend log has a
   `still uses the default password "changeme"` warning, and a critical
   `siembox-auth` alert reaches your notification channels. Browser tabs
   opened before the upgrade still run the old web UI: they show "You do not
   have permission to perform this action." on every page until you reload
   them (Ctrl+Shift+R), which brings up the "Choose a new password" screen.
   (Or use **Settings -> Account -> Password**, which works while
   restricted.) Sign in right away and choose a new password: until you do,
   anyone who reaches the web UI with `changeme` could choose it instead.
   Other accounts on `changeme` are restricted at their next sign-in. A
   disabled admin account on `changeme` is restricted too, with a warning of
   its own. Its alert is raised when it is enabled again, since from then on
   anyone could choose its password: sign in as it right away, or send a new
   `password` in the same `PUT /api/users/:id` that enables it.
2. **Log shippers, endpoint agents and their enrollment are not affected**:
   they use API keys, not sign-in sessions.
3. **Scripts that sign in with a session** get `403` with
   `code: "PASSWORD_CHANGE_REQUIRED"` from every route until the account
   changes its password through `PUT /api/auth/me/password` (which works
   while restricted) and signs in again. See
   [API.md](docs/reference/API.md#password-change-required).
4. **Passwords an admin sets are temporary by default.** A user created on
   the Users page, or whose password an admin sets, must choose their own at
   the next sign-in (untick "Require a password change", or send
   `"mustChangePassword": false`, to opt out). `auth-admin reset-password`
   always requires a change. `changeme` (in any letter case) is refused as a
   new password everywhere.
5. **An admin still on a non-default `DEFAULT_ADMIN_PASSWORD` is not forced**
   on upgrade, so a scripted install keeps working. That password sits in
   `.env` and the container environment in plain text: change it under
   Settings -> Account.
6. **A deleted or renamed `admin` is no longer re-created.** The account is
   created only when the database has no users at all; before, a missing
   `admin` came back with the bootstrap password at the next start (and a
   renamed one that kept its email stopped every start). To get back into an
   account, use `auth-admin reset-password <username>`.

## Database Migrations and Seeding

### Automatic Initialization

When the backend container starts, it automatically:

1. **Runs all database migrations** from `/backend/migrations/`:
   - Creates database schema (tables, indexes, constraints)
   - Configures retention policies
   - Sets up system tables

2. **Creates the `admin` account, only when the database has no users**, after
   every migration has run: username `admin`, email `admin@siembox.local`,
   password `DEFAULT_ADMIN_PASSWORD` (`changeme` when unset), already required
   to choose a new password at its first sign-in. On every later start the
   account is left alone: changing `DEFAULT_ADMIN_PASSWORD` has no effect, and
   deleting or renaming `admin` doesn't bring it back (recover an account with
   `auth-admin reset-password <username>`, see [Sign-in
   protection](#sign-in-protection)). Each start also checks admin accounts
   against the default password `changeme` and restricts any that still use
   it until it is changed.

Migrations are idempotent and run on every startup. A fresh install is
**catalog-only**: no parsers or detection rules are seeded — you install exactly
what you want from the in-app catalog after first login (*Parsers / Detection
Rules → Browse Catalog → Install all*).

**This entire process is automatic and requires no manual intervention to boot.**

> **Opting back into legacy seeding.** Set `SEED_BUNDLED_CONTENT=true` to have the
> backend auto-import the bundled detection rules on startup (the old behaviour).
> Left unset, the install stays catalog-only. This affects detections only;
> parsers always come from the catalog.

### Verify Initialization Completed

You can verify that initialization was successful by checking the health endpoint:

```bash
curl http://your-server-ip:8421/health/seed-status
```

On a fresh catalog-only install the counts start at zero and climb as you install
from the catalog:
```json
{
  "parsers": 0,
  "rules": 0,
  "seeded": true
}
```

### Advanced: Manual Operations

For advanced users, if you need to manually run migrations or reimport rules, refer to the backend container documentation. These operations should rarely be needed in normal operation.

## Container Scanning and Docker Image Discovery

**Container Scanning** (under *Assets & Vulnerabilities*) scans a container image
for known OS and library vulnerabilities with Trivy. Type any image reference
(for example `nginx:latest` or `ghcr.io/cladkins/siembox-backend:latest`) and
Trivy pulls the image itself — **no Docker socket required** for manual scans.

### Optional: discover images from the Docker host

To skip typing references, you can let SIEMBox list the images already running on
the host and scan them in one click ("Images on this Docker host" on the Container
Scanning page). This requires mounting the Docker socket into the backend
container. It is **opt-in** and **off by default**.

Uncomment this volume in `compose.prod.yaml` under the `backend` service:

```yaml
    volumes:
      # ...
      - /var/run/docker.sock:/var/run/docker.sock:ro
```

> ⚠️ **Security tradeoff.** Mounting the Docker socket grants the backend
> container control of the Docker daemon, which is effectively **root on the
> host**. The `:ro` flag only marks the socket *file* read-only — it does **not**
> make the Docker API read-only. SIEMBox itself only issues read-only `GET`
> requests (`/containers/json`, `/images/json`) for discovery, but you are still
> widening the trust boundary. Enable this only if you accept that risk; leave it
> commented out otherwise. The feature degrades gracefully — when the socket is
> absent, the UI shows a short explanation instead of an error.

If your Docker socket lives somewhere non-standard, set `DOCKER_SOCKET_PATH` on
the backend to point at it (defaults to `/var/run/docker.sock`).

## Log Discovery and Network Visibility

**Log Discovery** (under *Assets & Vulnerabilities*) finds security log sources
on your network -- firewalls, DNS filters, reverse proxies, hypervisors, etc.
-- fingerprints them, ranks them by security value, and hands back copy-paste
onboarding instructions. It never writes device or collector config itself.

By default the backend container only sees whatever subnet its own Docker
bridge network is on (`siembox-network` in `compose.prod.yaml`), so a passive
scan (ARP table read, mDNS, SSDP) only discovers hosts on that one subnet. If
your homelab spans more than one VLAN, the Log Discovery page surfaces this as
a warning and lets an admin add the other CIDRs manually (operators can run
scans and see the scope, but changing it needs an admin). An `active`/`full` scan
already sweeps those manually-added CIDRs for real LAN hosts from the default
bridge network -- Docker's outbound NAT rewrites the container's source IP
before packets reach your LAN, so active/vulnerability scanning isn't actually
limited by network mode. What manual CIDRs can't fix is *passive* discovery
itself (ARP/mDNS/SSDP) -- those techniques are inherently scoped to whatever
network the container is attached to and cannot cross the Docker bridge.

### Optional: host networking (Linux only)

To let passive discovery see your real LAN directly -- and make the
single-VLAN warning above actually reflect your host's real interfaces -- run
the backend with `network_mode: host` instead of the default bridge network.
This applies to the **backend container only**; the frontend and Postgres stay
on the bridge network as usual.

> ⚠️ **Security tradeoff.** This is a bigger change than the Docker socket
> mount above: the backend container shares the host's entire network stack
> and is no longer network-isolated from it -- treat it the same as running
> the backend process directly on the host. It's Linux-only (Docker Desktop on
> Mac/Windows does not support host networking the same way). Left at the
> default, discovery still works -- it's just scoped to whatever subnet(s) you
> add manually.

**Before you start**, confirm nothing on the host already holds the ports the
backend will now bind directly -- there's no Docker publish layer left to
remap them:

```bash
netstat -tuln | grep -E "514|8421"
```

If that returns nothing, you're clear to proceed.

**1. Edit `compose.prod.yaml`'s `backend` service** -- comment out its `ports:`
block and `networks:`, uncomment `network_mode: host`:

```yaml
    # ports:
    #   - "8421:8421"
    #   - "514:514/udp"
    #   - "514:514/tcp"
    depends_on:
      postgres:
        condition: service_healthy
    network_mode: host
    # networks:
    #   - siembox-network
    restart: unless-stopped
```

**2. Edit `.env`** -- set these three (uncomment/change the existing lines
near the bottom of `.env.example`):

```bash
DB_HOST=localhost
BACKEND_UPSTREAM=host.docker.internal:8421
SIEMBOX_HOST_NETWORKING=true
```

Leave the `api-socket` volume on both containers: in host networking mode it
is what lets the web UI's requests keep their users' real addresses (see
[Client addresses and reverse proxies](#client-addresses-and-reverse-proxies)).
`BACKEND_UPSTREAM` is now only nginx's fallback route, but it is still
required: nginx resolves it at startup, and `backend` does not resolve once
the backend has left `siembox-network`.

> ⚠️ **Apply steps 1 and 2 together.** `DB_HOST=localhost` (or `127.0.0.1`) is
> only correct once `network_mode: host` is actually active on the backend. Set
> on its own, the backend dials its *own* container instead of Postgres and
> crash-loops on `connect ECONNREFUSED 127.0.0.1:5432` while Postgres shows
> healthy. The backend's log now spells this out. Changing the environment also
> needs a redeploy -- a plain `docker restart` keeps the old values. See
> [TROUBLESHOOTING.md](docs/operations/TROUBLESHOOTING.md#issue-backend-cant-reach-postgres-on-127001).

**3. Redeploy:**

```bash
docker compose -f compose.prod.yaml up -d
```

**4. Verify:**
- `docker compose -f compose.prod.yaml logs backend` shows a successful
  database connection (no `ECONNREFUSED` errors).
- The frontend loads normally with no `502` errors on `/api/*` requests.
- The Log Discovery page's "Detected LAN" suggestion (or `GET
  /api/log-discovery/scope`'s `detected_lan_cidr` field) now shows a real LAN
  subnet instead of `null`.
- A passive scan's results show real LAN IPs with `arp`, `mdns`, or `ssdp`
  among their discovery methods, not `172.x.x.x` bridge addresses.
- Syslog ingestion still works from another machine on the LAN.

**To revert:** re-comment `network_mode: host`, uncomment the `ports:` block
and `networks:`, and either remove the three `.env` lines or set
`DB_HOST=postgres` and leave `BACKEND_UPSTREAM`/`SIEMBOX_HOST_NETWORKING`
unset -- then `docker compose -f compose.prod.yaml up -d` again. This cleanly
restores today's default behavior.

**What this does *not* improve:** DHCP lease parsing and LLDP capture are
unaffected by network mode -- lease parsing reads host files that neither
compose file mounts today, and LLDP capture has no implementation yet. Only
ARP/mDNS/SSDP passive discovery and the single-VLAN warning's accuracy benefit
from host networking.

## Threat Intelligence Feeds

The **Threat Intel** page enriches an IP lookup with external intelligence: which
blocklists flag it, plus on-demand reputation from keyed providers.

### Free blocklists (automatic)

A few well-known, no-auth IP blocklists are seeded and refreshed on a schedule
(every few hours):

- **Feodo Tracker** & **SSLBL** (abuse.ch) — active botnet C2 IPs
- **Tor exit nodes** — current Tor exit list
- **blocklist.de** — IPs reported for attacks on fail2ban-protected services

These only require the backend to have **outbound HTTPS egress**. If egress is
blocked, each feed simply records `last_status = error` and the rest of the app
is unaffected. Enable/disable feeds or trigger a manual refresh from the *Threat
Feeds & Reputation Providers* panel on the Threat Intel page.

### Reputation providers (bring your own key)

For richer per-IP reputation you can plug in keyed providers — **AbuseIPDB** and
**AlienVault OTX** (both have free API keys). Paste an API key into the same panel
(admin only). Keys are encrypted at rest using `CREDENTIAL_ENCRYPTION_KEY`
(set it, or key storage is refused), and are queried **only on demand** when you
look up an IP — results are cached briefly to respect rate limits. Nothing is
stored from these providers.

## Backup and Restore

### Backup Your Database

Regular backups are essential. Your deployment platform should provide backup capabilities.

**To backup manually:**

You can execute backup commands in your PostgreSQL container through your deployment platform's exec/shell interface:

```bash
# Create SQL backup
pg_dump -U siembox siembox > backup_$(date +%Y%m%d).sql

# Or use custom format (recommended for compression)
pg_dump -U siembox -Fc siembox > backup_$(date +%Y%m%d).dump
```

Copy the backup file to secure storage.

### Restore from Backup

To restore from a backup:

1. Ensure the backend container is stopped (through your deployment platform)
2. Access the PostgreSQL container
3. Run restore command:

```bash
# From SQL backup
psql -U siembox siembox < backup_20240101.sql

# From custom format backup
pg_restore -U siembox -d siembox -c < backup_20240101.dump
```

4. Restart the backend container

**Note:** Restores will overwrite existing data. Verify you have multiple backup copies before restoring.

## Performance Tuning

### PostgreSQL Tuning

Create a custom PostgreSQL config:

```yaml
# In docker-compose.yml under postgres service, add:
command:
  - "postgres"
  - "-c"
  - "shared_buffers=256MB"
  - "-c"
  - "effective_cache_size=1GB"
  - "-c"
  - "max_connections=100"
```

### Log Ingestion Capacity

Log ingestion has its own database connection pool and a bounded queue, so a
slow web page or scan can't starve it. When the database genuinely can't keep
up, **TCP syslog and HTTP push are slowed down and nothing is lost, but UDP
syslog can only drop** (the backend counts the drops and logs a summary every
10 seconds). Use TCP for sources you can't afford to lose. The defaults need no
tuning for typical homelab volumes; if you do see drops, start with
[Logs are dropped or ingestion is slow](./docs/operations/TROUBLESHOOTING.md#issue-logs-are-dropped-or-ingestion-is-slow),
which also lists the tuning variables (`DB_INGEST_POOL_MAX`, `INGEST_CONCURRENCY`,
`INGEST_QUEUE_MAX`, ...).

### Regex safety checks

Every parser and rule regex is checked for catastrophic backtracking (ReDoS)
before it is saved, and pattern tests run in worker threads with a time limit
([PARSERS.md, Regex Safety](./docs/reference/PARSERS.md#regex-safety)). The
defaults need no tuning; on a slow host (a Raspberry Pi) the first check of a
big catalog takes longer, and each verdict is kept in the database, so it is
paid once. Settings (in `.env`; both compose files pass them on; empty means
the default):

| Variable | Default | |
|---|---|---|
| `REGEX_SAFETY_CHECK_TIMEOUT_MS` | `5000` | Time budget for analyzing one regex when it is saved. A regex not decided within it is saved with a warning; a longer budget decides more of them but makes a first save or install slower. Changing it re-checks stored regexes at the next start |
| `REGEX_SAFETY_WORKERS` | `2` | Worker threads for those analyses |
| `REGEX_TEST_TIMEOUT_MS` | `1000` | Wall-clock limit for one pattern test (Test buttons, import self-tests); past it the run is stopped and answers `422 REGEX_TIMEOUT` |
| `REGEX_TEST_WORKERS` | `2` | Worker threads for pattern tests |

At every start the backend checks the regexes already stored in the background
and logs a `[regex-safety]` WARN for each unsafe one (see
[TROUBLESHOOTING.md](./docs/operations/TROUBLESHOOTING.md#issue-a-parser-or-rule-shows-an-unsafe-regex-tag)).

### Log Retention

Configure in the UI under **Settings → Data Retention**:
- Raw logs: 30 days (default)
- Parsed logs: 90 days (default)
- Alerts: 365 days (default)
- Auto cleanup: Runs every 24 hours

## Security Recommendations

1. **Sign in as `admin` right after the first start** (SIEMBox makes you choose a new password), and change `DB_PASSWORD` from `changeme`
2. **Use strong JWT secret** (32+ random characters)
3. **Run behind reverse proxy** (nginx/traefik) with SSL, and list it in `TRUSTED_PROXIES` (see [Client addresses and reverse proxies](#client-addresses-and-reverse-proxies))
4. **Leave `CORS_ORIGIN` empty** (same-origin only) unless a page of yours on another origin needs the API, and then list just that origin; avoid `*` (see [Browser access from other origins (CORS)](#browser-access-from-other-origins-cors))
5. **Restrict port 514** to trusted networks only
6. **Regular backups** of PostgreSQL database
7. **Monitor disk space** - logs can grow quickly
8. **Update regularly** - `git pull && docker compose build --pull && docker compose up -d` (`--pull` also refreshes the `node:20-alpine` and `nginx:alpine` base images, which a plain `up -d --build` keeps reusing)

## Network Configuration

SIEMBox requires these ports:
- **8420**: Frontend web interface
- **8421**: Backend API, for log shippers, endpoint agents and scripts (the web UI reaches the API through 8420). Callers here are identified by their TCP address; see [Client addresses and reverse proxies](#client-addresses-and-reverse-proxies)
- **514/UDP**: Syslog ingestion (UDP)
- **514/TCP**: Syslog ingestion (TCP)
- **5432**: PostgreSQL. Both compose files publish it on `127.0.0.1` only. To query it from another machine, open an SSH tunnel to the Docker host (`ssh -L 5432:127.0.0.1:5432 user@docker-host`) instead of publishing it on the LAN.

If you've enabled the optional host networking mode (see "Log Discovery and
Network Visibility" above), the backend's ports bind directly to the host
instead of going through Docker's publish layer -- the port list above is
unchanged, but firewall rules now apply to them directly rather than to a
Docker-managed mapping.

### Firewall Rules Example (UFW)

```bash
# Allow web traffic
sudo ufw allow 80/tcp

# Allow syslog from local network only
sudo ufw allow from 192.168.1.0/24 to any port 514

# Optional: API access
sudo ufw allow 8420/tcp
```

## Client addresses and reverse proxies

SIEMBox's rate limits, audit rows, error log and shipper records all use the
client's address. It works that address out like this:

- **The web UI (port 8420).** The frontend's nginx reaches the backend over a
  unix socket, `/run/siembox/api.sock`, on the `api-socket` volume that only
  the backend and frontend containers mount. The backend believes the
  `X-Forwarded-For` of requests on that socket, where nginx has put the address
  it saw, so every browser keeps its real address.
- **Direct callers on port 8421** (log shippers, endpoint agents, scripts,
  anyone else) are their TCP address. `X-Forwarded-For` and `X-Real-IP` sent
  to 8421 are ignored, unless the sender is listed in `TRUSTED_PROXIES`.
- **`TRUSTED_PROXIES`** (default `frontend`) lists other proxies whose
  `X-Forwarded-For` is believed: IP addresses, CIDR ranges and Compose service
  names, comma-separated. The value replaces the default, so keep `frontend`
  when you add one: `TRUSTED_PROXIES=frontend,192.168.1.20`. `none` trusts only
  the socket.
  - Names are looked up in Docker's own DNS only (never in host networking
    mode), and an answer only counts when it is on one of the backend's
    networks and Docker confirms it as a container there (its reverse lookup
    names `<container>.<network>`). Docker passes names it doesn't know on to
    your LAN's DNS server, so this is what keeps a LAN host that calls itself
    `frontend` from being trusted when the backend sits on the LAN itself
    (a macvlan or ipvlan network). In such setups listing IP addresses, or
    `none`, is clearest.
  - Values that would trust everyone (`*`, `true`, `0.0.0.0/0`, `::/0`),
    Express's `loopback`/`linklocal`/`uniquelocal` presets, hop counts and
    malformed entries are rejected with an error in the backend log. Ranges
    wider than /24 (IPv4) or /64 (IPv6) work, with a warning.
  - Docker's network gateway address is never trusted through a range: Docker
    presents IPv6 and loopback clients of published ports with that address.
- **`SIEMBOX_PROXY_SOCKET`** (in `.env`): leave it unset, or set `off` to run
  without the socket. The bundled frontend's nginx only ever connects to
  `/run/siembox/api.sock`, so another path leaves the web UI on its TCP
  fallback (only a proxy of your own could use it). The backend only listens
  when the directory already exists, i.e. when the volume is mounted.

### By deployment mode

| Mode | Web UI (8420) | Direct callers on 8421 | What to do |
|---|---|---|---|
| Bridge network, current compose file (the default) | Over the socket: each user's real address | Their TCP address; `X-Forwarded-For` ignored | Nothing |
| Bridge network, older compose file (images updated only) | nginx falls back to TCP; `frontend` is trusted through Docker DNS, so addresses stay correct | Same | Nothing urgent. Update the compose file: until then the backend logs a hint at startup and nginx logs one `connect() to unix:/run/siembox/api.sock failed` line about every 30 s |
| Host networking, current compose file | Over the socket | Their real address | Keep `BACKEND_UPSTREAM=host.docker.internal:8421` |
| Host networking, older compose file | TCP from the frontend container, which can't be trusted by name here: every UI user shares one address (it can't be forged) | Their real address | Update the compose file |
| Reverse proxy on another machine, in front of 8420 | nginx sees the proxy | — | `TRUSTED_PROXIES=frontend,<proxy IP>`; the proxy must append to `X-Forwarded-For` |
| Proxy container (Nginx Proxy Manager, Traefik, Caddy, cloudflared) | Attach it to `siembox-network` and point it at `http://frontend:80` | — | `TRUSTED_PROXIES=frontend,<its service name>`; with host networking, give it a fixed `ipv4_address` and list that |
| Proxy installed on the Docker host | Proxy to `http://<host LAN IP>:8420`, not `127.0.0.1` (Docker rewrites loopback clients of published ports to the gateway address) | — | `TRUSTED_PROXIES=frontend,<host LAN IP>` |
| Host-networking backend, host proxy pointed straight at 8421 | — | The proxy is `127.0.0.1` | `TRUSTED_PROXIES=frontend,127.0.0.1` (only safe with host networking) |
| IPv6 or loopback clients of published ports, Docker Desktop, rootless Docker's default port driver | These clients share the gateway address, which is never trusted | — | Reach SIEMBox over IPv4 on the host's LAN address, or switch rootless Docker to `slirp4netns`. (Enabling IPv6 on `siembox-network` doesn't help: the bundled nginx only listens on IPv4, so IPv6 browsers would be refused.) |
| Kubernetes, Unraid and other templates | Every user shares one address until configured | — | Share the socket's directory between the two containers (an `emptyDir`), or list the frontend's address (`127.0.0.1` inside one pod). On a macvlan or ipvlan network, list addresses rather than names |
| Development (`npm run dev`) | The Vite dev server connects from `127.0.0.1` | — | Nothing |

Without any configuration a reverse proxy in front of SIEMBox makes every user
look like the proxy, as before: one shared address that can't be forged. It
shares the general limit of `API_RATE_LIMIT_MAX` (default 1000) requests per 15
minutes, and one network for [sign-in protection](#sign-in-protection) (20
failures from anyone pause it; then each user gets one checked attempt from new
browsers, and after a wrong one waits up to 15 minutes), so set
`TRUSTED_PROXIES` (or raise the general limit). Until you do, a proxy on a
private, carrier-grade NAT, loopback, ULA or link-local address gets an hourly
`Ignored X-Forwarded-For from <proxy>` warning in the backend log, and
`GET /api/admin/client-address` lists it under `warnings`. A proxy on a public
address (Cloudflare's proxy in front of a forwarded port, a VPS proxying over
the internet) gets neither, because any client could get its own public
address listed that way: it only appears in `ignoredForwardedFor.peers` (with
`local: false`). So after putting a proxy in front of SIEMBox, request
`GET /api/admin/client-address` through it and check that `you.address` is
your own address.

### Check what SIEMBox sees

1. Sign in as an admin and request `GET /api/admin/client-address` through the
   web UI's address (with your session token from the browser, or one from
   `POST /api/auth/login`):

   ```bash
   curl -s -H "Authorization: Bearer $TOKEN" http://<host>:8420/api/admin/client-address
   ```

   `you.address` should be your machine's address and `you.via`
   `proxy-socket`. `warnings` lists anything to fix: a missing volume, a
   `TRUSTED_PROXIES` name that doesn't resolve, a proxy on a private address
   whose `X-Forwarded-For` keeps being ignored, and the proxy your own request
   came through if it isn't trusted (whatever its address). Right after the
   backend restarts, nginx stays on its TCP fallback for up to 30 s before it
   tries the socket again, so check again after that if `via` is not
   `proxy-socket` yet.
2. Confirm a direct caller can't choose its address:

   ```bash
   curl -s -H "Authorization: Bearer $TOKEN" -H 'X-Forwarded-For: 1.2.3.4' \
     http://<host>:8421/api/admin/client-address
   ```

   `you.address` is still your real address, `you.via` is `direct`, and a
   warning says the header was ignored. This check is not counted as a proxy
   whose header was ignored, so it leaves no warning behind. Never add your own
   machine to `TRUSTED_PROXIES` because of it: only proxies belong there.
3. The backend's startup log sums it up in one line, e.g. `Client addresses:
   proxy socket /run/siembox/api.sock (listening); X-Forwarded-For trusted from
   frontend -> 172.18.0.3; direct callers on :8421 use their TCP address.`
   A local address whose `X-Forwarded-For` keeps being ignored for more than
   45 s (a proxy in front of the web UI, or a caller of port 8421) also shows
   up as an hourly `Ignored X-Forwarded-For from ...` warning. With host
   networking, the frontend's own address is expected for up to 30 s after a
   backend restart or a request that timed out, while nginx uses its TCP
   fallback. Each such window counts on its own once the socket has served
   requests again, so separate windows don't add up and are not reported.

## Sign-in protection

Failed sign-ins pause further attempts for a while; nothing is ever locked for
good. The counters live in Postgres (table `login_throttle`), so a restart
doesn't reset them and the recovery command line can clear them.

| Counter | Counts | Pauses after | Longest pause |
|---|---|---|---|
| Account from one network | Wrong passwords for one username from one network (an IPv4 address or an IPv6 /64) | 5 (`LOGIN_MAX_FAILURES`) | 15 min |
| Network | Wrong passwords from one network, any username. While paused, it holds back only usernames that failed from that network in the last 15 minutes | 20 (`LOGIN_MAX_FAILURES_PER_ADDRESS`) | 30 min |
| Account from new browsers | Wrong passwords for one username from every network | 20 (`LOGIN_MAX_FAILURES_PER_ACCOUNT`, `0` = off) | 60 min |
| Recognized browser | Wrong passwords and MFA codes from one browser that signed in before | 10 | 15 min |
| MFA codes | Wrong codes for one user | 5 | 60 min |
| Current password | Wrong current passwords when changing your own password | 5 | 60 min |

The first pause is 30 seconds, and each further failure doubles it (1, 2, 4,
8, 16, 32 minutes) up to the limit; a counter starts over 24 hours after its
last failure. A successful sign-in clears the account's counter for that
network (the network and account-wide counters only take back that one
attempt, so a run of guesses can't be hidden between two good sign-ins).

**Recognized browsers.** Every successful sign-in gives the browser a token
(kept per username in the browser's local storage, only its hash on the
server). A browser with one signs in through its own counter, so someone else
guessing an account's password, from anywhere, pauses sign-in from new
browsers only: the owner keeps signing in from the browsers they used before.
Tokens last 90 days from their last use and are forgotten after 20 failures
in a row, on a password change or reset, or with the user.

**What the user sees.** The login page shows why and for how long, and its
button counts down ("Try again in 1:43"). Usernames that don't exist get the
same answers as real ones, so the login page doesn't reveal which accounts
exist.

**Settings** (in `.env`; both compose files pass them on; empty means the
default):

| Variable | Default | |
|---|---|---|
| `LOGIN_MAX_FAILURES` | `5` | Failures for an account from one network before it pauses |
| `LOGIN_MAX_FAILURES_PER_ADDRESS` | `20` | Failures from one network, any username |
| `LOGIN_MAX_FAILURES_PER_ACCOUNT` | `20` | Failures for an account from new browsers on every network; `0` turns this counter off |
| `LOGIN_PROTECTION` | on | `off` stops all counting and pausing. Only to get back in after a lockout: every start logs a warning while it is set |
| `AUTH_ALERTS` | on | `off` stops the sign-in alerts below |
| `AUTH_FAILURE_AUDIT_RETENTION_DAYS` | `90` | How long `auth.login.failure` audit rows are kept; `0` keeps them |

These depend on correct client addresses: behind a reverse proxy SIEMBox
doesn't trust, everyone shares one network. A paused network only holds back
usernames that failed from it in the last 15 minutes, so 20 failures from one
person don't lock everyone out: a user who hasn't mistyped from that network
is still checked, and one who does is refused while the network stays paused,
for at most 15 minutes after that mistake, however long an attacker keeps the
network paused. The login page counts down to the end of the network's current
pause; if an attacker pauses it again by then, the next attempt gets another
countdown, never past those 15 minutes. A browser that signed in before isn't
held back at all, and an admin's Unlock on the Users page lets them in at
once. The guesses a paused network lets through are counted, but don't extend
its pause. Set
`TRUSTED_PROXIES` (see [Client addresses and reverse
proxies](#client-addresses-and-reverse-proxies)).

**Alerts.** Attacks on sign-in raise alerts (source `siembox-auth`): a network
paused (medium), an existing account paused (high; critical for an admin), MFA
codes paused after correct passwords (critical), a new browser signing in
during an attack (high), a success after 5 or more failures (medium), a
recognized browser forgotten (high), and more than 100 failed checks in 10
minutes (high). One per streak. An account found on the default password
`changeme`, at startup or at a sign-in, raises one alert (critical for an
admin, high otherwise) for as long as it hasn't changed it; a disabled one's is
raised when it is enabled. The network-pause and success-after-failures
alerts, which anyone can set off cheaply, are capped at 20 an hour together, so
they can't crowd out the account, MFA and browser alerts. They reach your
notification channels like any alert (Settings -> Notifications; the default
minimum severity is high).

**Seeing and clearing pauses.** Settings -> **Sign-in protection** (admins)
lists every counter that is paused or failed in the last 24 hours, with the
network and user agent, and clears one, a whole network or everything; it
also shows how SIEMBox sees your own address. Users -> **Unlock** clears one
account. Without the web UI:

```bash
docker exec siembox-backend node dist/scripts/auth-admin.js status
docker exec siembox-backend node dist/scripts/auth-admin.js unlock <username>
docker exec siembox-backend node dist/scripts/auth-admin.js unlock --network <ip, or an IPv6 /64 as status prints it>
docker exec siembox-backend node dist/scripts/auth-admin.js unlock --all
docker exec siembox-backend node dist/scripts/auth-admin.js reset-password <username>
docker exec siembox-backend node dist/scripts/auth-admin.js disable-mfa <username>
```

`reset-password` prints a random temporary password once; the account must
choose its own at its next sign-in (after its MFA code, if MFA is on).
`status <username>` says whether a password change is still required.

See [TROUBLESHOOTING.md, "Locked out of SIEMBox"](docs/operations/TROUBLESHOOTING.md#issue-locked-out-of-siembox)
for every way back in. An hourly job (`sign-in-housekeeping` on the Admin
dashboard) removes idle counters, unused browsers, expired sessions and old
failed sign-in audit rows.

**Check it** (from another machine, against the published API port; the
usernames don't need to exist):

```bash
# Different usernames with a forged X-Forwarded-For: 401 nineteen times, then
# 429 from the 20th (the forged header is ignored, so they all count against
# your one address)
for i in $(seq 1 25); do
  curl -s -o /dev/null -w '%{http_code} ' -X POST http://<host>:8421/api/auth/login \
    -H 'Content-Type: application/json' -H "X-Forwarded-For: 198.51.100.$i" \
    -d "{\"username\":\"probe-$i\",\"password\":\"x\"}"
done; echo
```

Then clear it on Settings -> Sign-in protection ("Clear network") or with
`auth-admin.js unlock --network <your IP>`.

## Browser access from other origins (CORS)

By default the API answers browsers on its own origin only: it sends no CORS
headers (`Access-Control-Allow-*`), so a web page on any other origin can't
read its answers, and the browser won't even send it a JSON request or one
carrying a token. That is all SIEMBox itself needs:

- **The web UI** on port 8420 calls `/api` on its own origin; its nginx proxies
  that to the backend. A reverse proxy in front of 8420 keeps the UI and its
  `/api` on one origin, so it needs nothing either.
- **The Vite dev server** (`npm run dev` in `frontend/`) proxies `/api` the same
  way, to `http://localhost:8421` or to `API_PROXY_TARGET`.
- **Log shippers, endpoint agents, scripts and `curl`** aren't browsers and
  ignore CORS: they work the same whatever `CORS_ORIGIN` says.

Why not `*`, the old default: the API takes a Bearer token, not a cookie, so
with `Access-Control-Allow-Origin: *` any page one of your users opens (an ad,
a compromised site, a link in a phishing mail) can script calls to
`http://<host>:8421` from their browser, inside your network, and read the
answers: password guessing against sign-in that never crosses your firewall,
and probing whatever the API answers without a login.

**`CORS_ORIGIN`** (in `.env`; both compose files pass it on, empty by default):

| Value | What a browser page on another origin gets |
|---|---|
| empty or unset (default) | Nothing: same-origin only. Its preflight gets an empty `204` with no allow headers, so the browser stops there. |
| `https://dash.example.com,http://localhost:5173` | Exact origins, comma-separated. A request whose `Origin` is one of them gets it back in `Access-Control-Allow-Origin`, with `Access-Control-Allow-Credentials: true`; every answer carries `Vary: Origin`. Other origins get nothing. |
| `*` | Every origin (`Access-Control-Allow-Origin: *`). Still works, and every start logs a warning that names the risk. |

An origin is `scheme://host[:port]`, as the browser sends it in the `Origin`
header: no path, no wildcard. Entries are normalized (lowercase host, default
port and trailing `/` dropped), and the `Origin` header must match one
exactly. An entry that isn't an exact `http://` or `https://` origin
(`siem.example.com`, `https://siem.example.com/app`, `https://*.example.com`,
`null`) is ignored with a warning naming it, and the others still apply. That
fails closed (the bad entry allows nothing), and the backend, which also takes
your syslog, shipper and agent traffic, keeps collecting logs instead of
refusing to start over a setting only browsers read. Startup logs the result:

```bash
docker logs siembox-backend 2>&1 | grep CORS
# CORS: same-origin only (CORS_ORIGIN is empty). The web UI does not need CORS.
```

**When to set it:** only for a page or app of your own, on another origin, that
calls the API from a browser: a dashboard on another host, a web UI built with
an absolute `VITE_API_URL` (`https://api.example.com/api` behind a proxy on a
second hostname), or a frontend dev server pointed straight at
`http://localhost:8421/api` instead of using its proxy. List exactly the
origins those pages are served from, then apply the change with
`docker compose up -d` (a restart keeps the old environment).

**Check it** (from any machine; `curl` shows the headers a browser would get):

```bash
# The default: prints nothing (no Access-Control-* headers at all)
curl -si -X OPTIONS http://<host>:8421/api/auth/login \
  -H 'Origin: http://evil.example' -H 'Access-Control-Request-Method: POST' | grep -i '^access-control'
# A listed origin gets itself back
curl -si http://<host>:8421/health -H 'Origin: https://dash.example.com' | grep -i '^access-control-allow-origin'
```

## Monitoring

Monitor SIEMBox to ensure smooth operation and capacity planning.

### Container Health

Your deployment platform should provide container monitoring. Check:
- All containers are running and healthy
- CPU and memory usage is reasonable
- No restart loops (indicates errors)

### Database Monitoring

You can access the PostgreSQL container to check database statistics.

**Check database size:**
```bash
# From PostgreSQL container
psql -U siembox -d siembox -c "
SELECT
  pg_size_pretty(pg_total_relation_size('raw_logs')) as raw_logs_size,
  pg_size_pretty(pg_total_relation_size('parsed_logs')) as parsed_logs_size,
  pg_size_pretty(pg_total_relation_size('alerts')) as alerts_size;
"
```

**Check log counts:**
```bash
psql -U siembox -d siembox -c "
SELECT
  (SELECT COUNT(*) FROM raw_logs) as raw_logs,
  (SELECT COUNT(*) FROM parsed_logs) as parsed_logs,
  (SELECT COUNT(*) FROM alerts) as alerts;
"
```

### Log Retention

SIEMBox automatically cleans old logs according to retention policies. Configure retention in the web UI under **Settings → Data Retention**:
- Raw logs: Default 30 days
- Parsed logs: Default 90 days
- Alerts: Default 365 days

## Log Shipper Management

### Setting Up Log Shippers

Log shippers forward logs from remote sources to SIEMBox. Each shipper requires an API key for authentication.

**To add a new shipper:**
1. In SIEMBox UI, navigate to Shippers page
2. Click "Add Shipper" and generate an API key
3. Note the Shipper ID (8-character identifier)
4. Deploy the shipper container with this API key
5. Verify logs appear in SIEMBox

See [Log Shipper README](./log-shipper/README.md) for detailed setup instructions.

### HTTP Log Push (for tools that can't run the managed shipper)

Some homelab/self-hosted tools can't speak syslog but can POST JSON — a webhook notifier, a small script, a cron job. For these, provision an HTTP log-push key instead of deploying a shipper container:

1. In the SIEMBox UI, open (or create) a shipper on the Shippers page and click **Generate Key** under "HTTP Log Push". The plaintext key is shown once — copy it now.
2. POST logs to the existing API port (8421) — no new firewall rule needed, unlike syslog's port 514:
   ```bash
   curl -X POST http://<siembox-host>:8421/api/shippers/logs \
     -H "Authorization: Bearer <push_key>" \
     -H "X-Shipper-ID: <shipper id>" \
     -H "Content-Type: application/json" \
     -d '{"message":"hello from my homelab tool"}'
   ```
3. `message` must be the bare log line (not syslog-framed) for catalog parsers to match it — see [PARSERS.md](./PARSERS.md).

This key is separate from the syslog `api_key` above and revokes cleanly: unlike a ghost shipper, a revoked push key is rejected on the very next request, with no cached-config grace period. See [API.md](./docs/reference/API.md#post-apishipperslogs) for the full request/response shape.

### API Key Rotation

When rotating shipper API keys:

1. Generate new API key in SIEMBox UI (**Shippers** → **View** → **Regenerate**; admin role). An operator can delete the shipper and add it again instead, then re-add its sources and volumes. Admins and operators can view a shipper's current key in its details at any time.
2. Update the shipper's API key environment variable
3. Restart the shipper container

The shipper will briefly operate with cached configuration, then re-register with the new key.

**Important:** Update shippers promptly after rotating keys to avoid losing log configuration updates.

### Ghost Shipper Detection

**What is a Ghost Shipper?**

A "ghost shipper" is a log shipper with an invalid or expired API key that continues sending logs but cannot receive configuration updates. This can occur when:
- API key was deleted
- API key was rotated but shipper wasn't updated
- Shipper container was cloned/copied with old credentials

**Why Ghost Shippers Exist:**

SIEMBox uses configuration caching so that temporary API key issues don't cause log loss. This provides:
- **Resilience**: Logs continue flowing even if API key is invalid
- **Visibility**: Administrators can identify misconfigured shippers in the UI
- **Continuity**: Network/API issues don't disrupt log collection

**How to Detect Ghost Shippers:**

In the SIEMBox UI, navigate to the **Shippers** page. If unknown sources are detected, you'll see:
- A yellow warning banner: "Unknown sources detected"
- Details showing shipper ID, log count, timestamps, and source IPs

The list covers the **last 24 hours**: log count, first/last seen and the
IP/hostname/app lists are computed over that window, and a source that hasn't
sent anything in the last 24 hours drops off the list. It is refreshed at most
every 30 seconds (and immediately when you create, delete, or re-key a shipper),
so a brand-new ghost can take up to half a minute to appear. If the database is
too busy to answer, the Shippers page keeps showing the last good result.

**How to Remediate:**

1. **Identify the source IP** from the ghost shipper details in the UI
2. **Locate the shipper** on your network
3. **Update the API key** to a current valid key from SIEMBox
4. **Restart the shipper** container
5. **Verify** it no longer appears as an unknown source

**Best Practices:**

1. Monitor Shippers page regularly for unknown sources
2. Update shipper API keys immediately after rotation
3. Use unique API keys for each shipper for easier tracking
4. Document all shipper locations and configurations
5. Test API key rotation in non-production first

For detailed shipper diagnostics and troubleshooting, see [Log Shipper Diagnostics](./docs/operations/SHIPPER-DIAGNOSTICS.md).
