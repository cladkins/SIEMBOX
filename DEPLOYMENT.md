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

### 4. Initialize Database

The database migrations run automatically when the backend starts. Wait for the backend to be healthy:

```bash
# Check backend logs to ensure migrations completed
docker-compose logs backend | grep -i migration

# You should see messages about migrations being applied
```

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

## Database Migrations

Migrations are located in `backend/migrations/` and run automatically on startup in order:
- `001_initial_schema.sql` - Core tables
- `002_seed_data.sql` - Default parsers, rules, and admin user
- `003_system_settings.sql` - Retention settings

### Manual Migration (if needed)

```bash
# Access the backend container
docker-compose exec backend sh

# Run migrations manually
npm run migrate
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
