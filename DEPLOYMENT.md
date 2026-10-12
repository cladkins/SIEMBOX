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
- Creating the default admin user

A fresh install is **catalog-only**: no parsers or detection rules are seeded, so
the deployment starts empty and you install exactly what you want. The process is
fully automated and requires no manual intervention. Monitor your deployment logs
to verify completion.

On first startup, SIEMBox automatically:
- Runs all database migrations
- Creates the default admin user

**No manual steps required to boot.** Once you log in, populate parsers and
detections from the in-app catalog — open *Parsers → Browse Catalog* and
*Detection Rules → Browse Catalog* and click **Install all** (or pick individual
items). The same catalog is the update path later.

### 5. Access the Application

Once SIEMBox is running:

- **Frontend (Web UI):** http://your-server-ip:8420
- **Backend API:** http://your-server-ip:8421
- **Syslog Listener:** your-server-ip:514 (UDP and TCP)
- **Default Credentials:** admin / (password from DEFAULT_ADMIN_PASSWORD environment variable)

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
1. Verify DEFAULT_ADMIN_PASSWORD is set correctly
2. Wait for first-run initialization to complete
3. Check database is running and initialized
4. Review backend logs for authentication errors

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
  reverse proxies](#client-addresses-and-reverse-proxies)); until then the
  backend logs which proxy it is ignoring.
- A `429` from the general limit is JSON with `Retry-After`.
- Failed sign-ins are limited: 10 per account per address, and 100 per address
  across all accounts, per 15 minutes. People who share an address (behind an
  office NAT, or a reverse proxy SIEMBox doesn't trust) don't lock each other
  out: past the 100, only accounts that already failed from that address are
  refused.
- EDR agent enrollment counts toward the general limit, even with an
  `X-Agent-ID` header.

## Database Migrations and Seeding

### Automatic Initialization

When the backend container starts, it automatically:

1. **Runs all database migrations** from `/backend/migrations/`:
   - Creates database schema (tables, indexes, constraints)
   - Configures retention policies
   - Sets up system tables

2. **Creates the default admin user** with credentials from environment variables

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

### Log Retention

Configure in the UI under **Settings → Data Retention**:
- Raw logs: 30 days (default)
- Parsed logs: 90 days (default)
- Alerts: 365 days (default)
- Auto cleanup: Runs every 24 hours

## Security Recommendations

1. **Change default passwords immediately**
2. **Use strong JWT secret** (32+ random characters)
3. **Run behind reverse proxy** (nginx/traefik) with SSL, and list it in `TRUSTED_PROXIES` (see [Client addresses and reverse proxies](#client-addresses-and-reverse-proxies))
4. **Restrict port 514** to trusted networks only
5. **Regular backups** of PostgreSQL database
6. **Monitor disk space** - logs can grow quickly
7. **Update regularly** - `git pull && docker compose up -d --build`

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
- **`SIEMBOX_PROXY_SOCKET`** (in `.env`) sets the socket path (default
  `/run/siembox/api.sock`; `off` disables it). The backend only listens when
  the directory already exists, i.e. when the volume is mounted.

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
minutes and the sign-in limit's 100 failures per address, so set
`TRUSTED_PROXIES` (or raise the general limit). Until you do, the backend logs
an hourly `Ignored X-Forwarded-For from <proxy>` warning and
`GET /api/admin/client-address` lists it under `warnings`.

### Check what SIEMBox sees

1. Sign in as an admin and request `GET /api/admin/client-address` through the
   web UI's address (with your session token from the browser, or one from
   `POST /api/auth/login`):

   ```bash
   curl -s -H "Authorization: Bearer $TOKEN" http://<host>:8420/api/admin/client-address
   ```

   `you.address` should be your machine's address and `you.via`
   `proxy-socket`. `warnings` lists anything to fix: a missing volume, a
   `TRUSTED_PROXIES` name that doesn't resolve, a proxy whose `X-Forwarded-For`
   is being ignored (yours, if your request came through one). Right after the
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
   up as an hourly `Ignored X-Forwarded-For from ...` warning. Shorter bursts
   are expected with host networking for up to 30 s after a backend restart,
   while nginx uses its TCP fallback, and are not reported.

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
