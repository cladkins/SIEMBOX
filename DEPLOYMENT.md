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
# SIEMBOX_VERSION=1.0.0
```

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

The database migrations and seed data import run automatically when the backend container starts. This includes:
- Running all database migrations
- Importing 19 pre-built parsers
- Seeding 40+ detection rules
- Creating default admin user

The process is fully automated and requires no manual intervention. Monitor your deployment logs to verify completion.

On first startup, SIEMBox automatically:
- Runs all database migrations (including 18+ parsers)
- Seeds 40+ detection rules from YAML files
- Creates default admin user

**No manual steps required!**

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

When the backend container starts for the first time, it automatically:

1. **Runs all database migrations** from `/backend/migrations/`:
   - Creates database schema (tables, indexes, constraints)
   - Imports 19 built-in parsers
   - Configures retention policies
   - Sets up system tables

2. **Seeds detection rules** (on first run only):
   - Checks if rules table is empty
   - If empty, imports 40+ detection rules from `/rules/` directory
   - If rules already exist, skips import (prevents duplication)

3. **Creates default admin user** with credentials from environment variables

**This entire process is automatic and requires no manual intervention.**

### Verify Initialization Completed

You can verify that initialization was successful by checking the health endpoint:

```bash
curl http://your-server-ip:8421/health/seed-status
```

Expected response:
```json
{
  "parsers": 19,
  "rules": 40,
  "seeded": true
}
```

### Advanced: Manual Operations

For advanced users, if you need to manually run migrations or reimport rules, refer to the backend container documentation. These operations should rarely be needed in normal operation.

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
