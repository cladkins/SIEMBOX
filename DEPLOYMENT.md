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
- **5432:** PostgreSQL database (internal only unless exposed)

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

### Log Retention

Configure in Settings UI:
- Raw logs: 30 days (default)
- Parsed logs: 90 days (default)
- Alerts: 365 days (default)
- Auto cleanup: Runs every 24 hours

## Security Recommendations

1. **Change default passwords immediately**
2. **Use strong JWT secret** (32+ random characters)
3. **Run behind reverse proxy** (nginx/traefik) with SSL
4. **Restrict port 514** to trusted networks only
5. **Regular backups** of PostgreSQL database
6. **Monitor disk space** - logs can grow quickly
7. **Update regularly** - `git pull && docker compose up -d --build`

## Network Configuration

SIEMBox requires these ports:
- **8420**: Frontend web interface
- **8421**: Backend API
- **514/UDP**: Syslog ingestion (UDP)
- **514/TCP**: Syslog ingestion (TCP)
- **5432**: PostgreSQL (only needed if accessing externally)

### Firewall Rules Example (UFW)

```bash
# Allow web traffic
sudo ufw allow 80/tcp

# Allow syslog from local network only
sudo ufw allow from 192.168.1.0/24 to any port 514

# Optional: API access
sudo ufw allow 8420/tcp
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

SIEMBox automatically cleans old logs according to retention policies. Configure retention via the Settings page in the web UI:
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

### API Key Rotation

When rotating shipper API keys:

1. Generate new API key in SIEMBox UI
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
