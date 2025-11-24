# SIEM BOX - Quick Start Guide

## Rapid Deployment for Homelab

This guide will get you up and running in 5 minutes.

### Prerequisites

- Docker and Docker Compose installed
- Ports 3000, 8000, and 5432 available
- At least 2GB RAM available

### 1. One-Command Deploy

```bash
docker compose up -d
```

That's it! The system will:
- Initialize the PostgreSQL database
- Start the backend API
- Build and serve the frontend

### 2. Access the Dashboard

1. Open your browser: **http://localhost:3000**
2. Login with default credentials:
   - **Username**: `admin`
   - **Password**: `admin123`

### 3. Send Your First Log

```bash
curl -X POST http://localhost:8000/api/v1/logs/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    "hostname": "test-server",
    "source_ip": "192.168.1.100",
    "app_name": "test-app",
    "raw_message": "Test log message from homelab",
    "severity": "info",
    "log_type": "application"
  }'
```

### 4. View Your Logs

- Go to **Logs** page in the web interface
- You should see your test log appear
- Refresh the dashboard to see updated statistics

### 5. Configure Log Forwarding

#### For Linux/macOS Systems

Add to your rsyslog configuration (`/etc/rsyslog.d/siembox.conf`):

```bash
# Forward all logs to SIEM BOX
*.* action(type="omhttp"
    server="your-siembox-ip"
    serverport="8000"
    restpath="api/v1/logs/ingest")
```

#### For Docker Containers

Add logging driver to your docker-compose.yaml:

```yaml
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
```

Then use a log shipper (Fluent Bit, Logstash, etc.) to forward to SIEM BOX.

### 6. Set Up Alerts (Optional)

1. Go to **Detection Rules** page
2. Click "Initialize Default Rules"
3. Rules will automatically trigger alerts on suspicious activity

### 7. Next Steps

- **Change default password**: Settings → Users
- **Configure notifications**: Settings → Notifications
- **Add detection rules**: Detection Rules → Create Rule
- **Schedule vulnerability scans**: Vulnerabilities → Scan Schedules
- **Review full deployment guide**: See DEPLOYMENT.md

## Monitoring Your SIEM BOX

### Check Service Status

```bash
docker compose ps
```

All services should show "healthy" status.

### View Logs

```bash
# All services
docker compose logs -f

# Just backend
docker compose logs -f backend

# Just frontend
docker compose logs -f frontend
```

### Restart Services

```bash
docker compose restart
```

### Stop Everything

```bash
docker compose down
```

## Common Issues

### "Connection refused" when accessing frontend

Wait 30 seconds for all services to fully start, then refresh your browser.

### No logs showing up

1. Check backend is receiving logs:
   ```bash
   docker compose logs backend | grep "ingest"
   ```

2. Verify database has logs:
   ```bash
   docker exec siembox-postgres psql -U siembox -d siembox \
     -c "SELECT COUNT(*) FROM processed_logs;"
   ```

3. Make sure you're logged in to the frontend

### Can't login

Default credentials are:
- Username: `admin`
- Password: `admin123`

If you changed them and forgot, you'll need to reset the database.

## Production Deployment

For production deployment with:
- Custom passwords
- SSL/TLS
- Email notifications
- Backups
- Monitoring

See the detailed **DEPLOYMENT.md** guide.

## Getting Help

1. Check the logs: `docker compose logs`
2. Review DEPLOYMENT.md for troubleshooting
3. Check CLAUDE.md for architecture details

## What's Running?

- **Frontend (port 3000)**: React web application
- **Backend (port 8000)**: FastAPI application with REST API
- **Database (port 5432)**: PostgreSQL database
- **Log Ingestion**: HTTP endpoint at `/api/v1/logs/ingest`
- **API Documentation**: http://localhost:8000/docs

Start exploring your SIEM! 🚀
