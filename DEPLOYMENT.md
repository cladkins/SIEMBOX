# SIEMBox Deployment Guide

## Prerequisites
- Docker and Docker Compose installed
- Port 80, 514, 3000, and 5432 available

## Initial Deployment

### 1. Clone and Configure

```bash
git clone https://github.com/cladkins/SIEMBOX.git
cd SIEMBOX
git checkout develop
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

### 3. Build and Start Services

```bash
# Build images
docker-compose build

# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

### 4. Initialize Database and Seed Data

The database migrations and seed data import run automatically when the backend starts. Wait for the backend to be healthy:

```bash
# Check backend logs to ensure migrations and seeding completed
docker-compose logs backend | grep -i migration
docker-compose logs backend | grep -i seed

# You should see messages about:
# - Migrations being applied (including parser imports)
# - Detection rules being seeded from YAML files
# - Successful import counts
```

On first startup, SIEMBox automatically:
- Runs all database migrations (including 18+ parsers)
- Seeds 40+ detection rules from YAML files
- Creates default admin user

**No manual steps required!**

### 5. Access the Application

- Frontend: http://your-server-ip:3000
- API: http://your-server-ip:3001
- Default login: `admin` / (password from DEFAULT_ADMIN_PASSWORD)

### 6. Send Test Syslog

```bash
# From any machine, send a test syslog message
logger -n your-server-ip -P 514 "Test message from logger"

# Or using netcat
echo "<134>$(date '+%b %d %H:%M:%S') testhost test: This is a test message" | nc -u your-server-ip 514
```

## Troubleshooting

### Error: "init-minimal-db.sql" mounting issue

If you see an error about `init-minimal-db.sql`, you have a local docker-compose override file that needs to be removed:

```bash
# Remove any override files
rm -f docker-compose.override.yml

# Or check what's trying to mount it
grep -r "init-minimal-db.sql" .
```

**Important:** The database initialization happens through the backend migration system, NOT through mounted SQL files.

### Backend won't start / Database connection errors

```bash
# Check if postgres is healthy
docker-compose ps postgres

# Restart postgres if needed
docker-compose restart postgres

# Wait 10 seconds, then restart backend
docker-compose restart backend
```

### Port 514 permission errors

Port 514 requires elevated privileges. The docker-compose handles this through container port mapping.

If you still have issues:
```bash
# On the host, ensure no other service is using port 514
sudo netstat -tulpn | grep :514

# Restart the backend service
docker-compose restart backend
```

### View Application Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f backend
docker-compose logs -f frontend
docker-compose logs -f postgres

# Last 100 lines
docker-compose logs --tail=100 backend
```

### Reset Everything

```bash
# Stop and remove all containers, volumes, and networks
docker-compose down -v

# Remove images
docker-compose down --rmi all

# Start fresh
docker-compose up -d --build
```

## Updating

```bash
# Pull latest code
git pull origin develop

# Rebuild and restart
docker-compose down
docker-compose up -d --build

# Migrations run automatically on backend startup
```

## Database Migrations and Seeding

### Automatic Process

Migrations and seeding happen automatically on backend startup:

1. **Migrations** (run in order from `backend/migrations/`):
   - `001_initial_schema.sql` - Core tables
   - `002_seed_data.sql` - Default admin user
   - `003_system_settings.sql` - Retention settings
   - `004_*.sql` through `006_*.sql` - Additional schema updates
   - `007_import_phase2_parsers.sql` - **11 Phase 2 parsers** (reverse proxy, auth, apps)

2. **Seed Data** (automatic on first run):
   - Checks if detection_rules table is empty
   - If empty, imports **40+ YAML rules** from `rules/` directory
   - If rules exist, skips import (idempotent)

3. **Health Check**:
   ```bash
   # Check seed status
   curl http://localhost:3001/health/seed-status

   # Expected response:
   # {
   #   "parsers": 18,
   #   "rules": 48,
   #   "seeded": true
   # }
   ```

### Manual Operations (if needed)

```bash
# Access the backend container
docker-compose exec backend sh

# Run migrations manually
npm run migrate

# Re-seed detection rules (only imports new rules)
npm run seed-data

# Import specific rules from YAML
npm run import-rules
```

### Verify Automatic Seeding

```bash
# Check backend startup logs
docker-compose logs backend | tail -50

# You should see:
# [info] Starting database migrations...
# [info] Migration completed: 007_import_phase2_parsers.sql
# [info] All migrations completed successfully!
# [info] Initializing seed data...
# [info] Seeding detection rules from YAML files...
# [info] Successfully seeded 40 detection rules
# [info] Seed data initialization complete
```

## Backup and Restore

### Backup Database

```bash
# Create backup
docker-compose exec postgres pg_dump -U siembox siembox > backup_$(date +%Y%m%d).sql

# Backup with custom format (recommended)
docker-compose exec postgres pg_dump -U siembox -Fc siembox > backup_$(date +%Y%m%d).dump
```

### Restore Database

```bash
# Stop backend to prevent connections
docker-compose stop backend

# Restore from SQL backup
cat backup_20231125.sql | docker-compose exec -T postgres psql -U siembox siembox

# Restore from custom format
docker-compose exec -T postgres pg_restore -U siembox -d siembox -c < backup_20231125.dump

# Start backend
docker-compose start backend
```

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
7. **Update regularly** - `git pull && docker-compose up -d --build`

## Network Configuration

SIEMBox requires these ports:
- **80**: Frontend web interface
- **514/UDP**: Syslog ingestion (UDP)
- **514/TCP**: Syslog ingestion (TCP)
- **3000**: Backend API
- **5432**: PostgreSQL (only needed if accessing externally)

### Firewall Rules Example (UFW)

```bash
# Allow web traffic
sudo ufw allow 80/tcp

# Allow syslog from local network only
sudo ufw allow from 192.168.1.0/24 to any port 514

# Optional: API access
sudo ufw allow 3000/tcp
```

## Monitoring

### Check Container Health

```bash
docker-compose ps
docker stats
```

### Database Size

```bash
docker-compose exec postgres psql -U siembox -d siembox -c "
SELECT
  pg_size_pretty(pg_total_relation_size('raw_logs')) as raw_logs_size,
  pg_size_pretty(pg_total_relation_size('parsed_logs')) as parsed_logs_size,
  pg_size_pretty(pg_total_relation_size('alerts')) as alerts_size;
"
```

### Log Counts

```bash
docker-compose exec postgres psql -U siembox -d siembox -c "
SELECT
  (SELECT COUNT(*) FROM raw_logs) as raw_logs,
  (SELECT COUNT(*) FROM parsed_logs) as parsed_logs,
  (SELECT COUNT(*) FROM alerts) as alerts;
"
```

## Log Shipper Management

### API Key Rotation

Log shippers use API keys for authentication and configuration management. When rotating API keys:

**Safe Rotation Process:**

1. **Generate New API Key** in SIEMBox UI (Shippers page → Edit shipper → Generate new key)
2. **Note the Shipper ID** - This 8-character hash identifies the shipper in logs
3. **Update Environment Variable** on the shipper host:
   ```bash
   # Update docker-compose.yml or .env file
   SHIPPER_API_KEY=new_api_key_here
   ```
4. **Restart Shipper** to apply new API key:
   ```bash
   docker-compose restart log-shipper
   ```

**What Happens During Rotation:**

- ✅ **No log gaps**: Shipper continues using cached configuration until restart
- ✅ **Automatic recovery**: After restart with new key, shipper re-registers and updates cache
- ⚠️ **Ghost shipper period**: Between key rotation and shipper restart, shipper operates with old cached config

### Ghost Shipper Detection

**What is a Ghost Shipper?**

A "ghost shipper" is a log shipper that continues sending logs but cannot fetch configuration updates due to an invalid API key. This occurs when:
- API key was deleted in SIEMBox
- API key was rotated but shipper wasn't updated
- Shipper was copied/cloned with old credentials

**How Ghost Shippers Work:**

The managed log shipper (`shipper-managed.sh`) uses **configuration caching** for operational resilience:

1. **Valid API Key**: Shipper fetches config from API, caches it locally, sends logs normally
2. **Invalid API Key**: Shipper cannot fetch new config, but continues using cached config
3. **Result**: Logs keep flowing (no gaps), but shipper appears as "unknown source" in UI

**Detecting Ghost Shippers:**

Navigate to **Shippers** page in the UI. If ghost shippers exist, you'll see:
- **Yellow alert banner** at the top: "Unknown sources detected"
- **"View Unknown Sources" button** to see details
- **Table showing**: Shipper ID, log count, first/last seen, source IPs, hostnames, app names

**Via Database Query:**

```bash
docker-compose exec postgres psql -U siembox -d siembox -c "
SELECT
  shipper_id,
  COUNT(*) as log_count,
  MIN(created_at) as first_seen,
  MAX(created_at) as last_seen,
  array_agg(DISTINCT source_ip) as source_ips,
  array_agg(DISTINCT hostname) as hostnames
FROM raw_logs
WHERE shipper_id IS NOT NULL
  AND shipper_id NOT IN (
    SELECT SUBSTRING(ENCODE(SHA256(api_key::bytea), 'hex'), 1, 8)
    FROM log_shippers
  )
GROUP BY shipper_id;
"
```

**Remediating Ghost Shippers:**

**Option 1: Re-register the shipper**
```bash
# On the ghost shipper host:
# 1. Get new API key from SIEMBox UI (Shippers page → Add Shipper)
# 2. Update environment variable
export SHIPPER_API_KEY=new_valid_key

# 3. Restart shipper
docker-compose restart log-shipper
```

**Option 2: Stop unauthorized shipper**
```bash
# If the ghost shipper is unauthorized/unknown:
# 1. Identify the source IP from ghost shipper details
# 2. Locate the physical/virtual machine
# 3. Stop the shipper container
docker-compose stop log-shipper  # or docker stop <container_name>
```

**Option 3: Clean up historical data**
```sql
-- Delete logs from specific ghost shipper (use with caution!)
DELETE FROM raw_logs WHERE shipper_id = 'a1b2c3d4';
```

**Why Ghost Shippers Exist:**

This design balances **security** with **operational resilience**:
- ✅ **Prevents log gaps**: API key issues don't stop log collection
- ✅ **Visibility**: Administrators can identify misconfigured/unauthorized shippers
- ✅ **Continuity**: Temporary network/API issues don't disrupt logging
- ⚠️ **Trade-off**: Shippers with invalid keys continue operating until detected

**Best Practices:**

1. **Monitor regularly**: Check Shippers page for "Unknown Sources" alert
2. **Rotate carefully**: Update shipper credentials immediately after rotation
3. **Unique API keys**: Use different API keys for each shipper (easier to track)
4. **Document shippers**: Maintain inventory of authorized shippers and their locations
5. **Automate cleanup**: Set up alerts for ghost shipper detection
