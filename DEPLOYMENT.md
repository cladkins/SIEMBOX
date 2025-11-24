# SIEM BOX - Production Deployment Guide

## Pre-Deployment Checklist

### Required Changes
- [ ] Generate secure SECRET_KEY: `openssl rand -hex 32`
- [ ] Change default database password
- [ ] Update admin default credentials (username: admin, password: admin123)
- [ ] Review and configure CORS_ORIGINS for your domain

### Optional Configuration
- [ ] Configure email notifications (SMTP settings)
- [ ] Set up Discord webhook for alerts
- [ ] Set up Slack webhook for alerts
- [ ] Configure SMS notifications (Twilio)
- [ ] Adjust log retention settings

## Quick Start

### 1. Clone and Configure

```bash
cd ~/homelab  # or your preferred directory
git clone <your-repo-url> SIEMBox
cd SIEMBox
```

### 2. Create Environment File

Create a `.env` file in the project root:

```bash
# Generate secure secret key
SECRET_KEY=$(openssl rand -hex 32)

# Create .env file
cat > .env << EOF
# Database Configuration
POSTGRES_DB=siembox
POSTGRES_USER=siembox
POSTGRES_PASSWORD=$(openssl rand -base64 32)
DATABASE_URL=postgresql://siembox:YOUR_PASSWORD_HERE@postgres:5432/siembox

# Security
SECRET_KEY=${SECRET_KEY}
DEBUG=false
LOG_LEVEL=INFO

# CORS - Update with your domain
CORS_ORIGINS=http://localhost:3000,http://your-domain:3000

# Optional: Email Notifications
# SMTP_SERVER=smtp.gmail.com
# SMTP_PORT=587
# SMTP_USERNAME=your-email@gmail.com
# SMTP_PASSWORD=your-app-password
# EMAIL_FROM=siembox@yourdomain.com

# Optional: Discord Notifications
# DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR_WEBHOOK

# Optional: Slack Notifications
# SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR_WEBHOOK
EOF
```

**IMPORTANT**: Edit the `.env` file and update `DATABASE_URL` with the generated password.

### 3. Deploy with Docker Compose

```bash
# Start all services
docker compose up -d

# View logs
docker compose logs -f

# Check service status
docker compose ps
```

### 4. Verify Deployment

1. **Backend Health Check**:
   ```bash
   curl http://localhost:8000/api/v1/health/
   ```
   Expected response: `{"status":"healthy","database":"connected"}`

2. **Frontend Access**:
   - Open browser: http://localhost:3000
   - Login with default credentials:
     - Username: `admin`
     - Password: `admin123`

3. **Change Default Password**:
   - Navigate to Settings page
   - Update admin password immediately

## Log Ingestion Setup

### Option 1: Direct HTTP Ingestion

Send logs directly to the ingestion endpoint:

```bash
curl -X POST http://localhost:8000/api/v1/logs/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2025-01-01T12:00:00Z",
    "hostname": "web-server-01",
    "source_ip": "192.168.1.100",
    "app_name": "nginx",
    "raw_message": "GET /api/users HTTP/1.1 200",
    "severity": "info",
    "log_type": "access",
    "fields": {
      "http_method": "GET",
      "http_status": 200,
      "uri": "/api/users"
    }
  }'
```

### Option 2: Fluent Bit Agent

Install Fluent Bit on your systems and configure to send to SIEM BOX:

```ini
[OUTPUT]
    Name http
    Match *
    Host your-siembox-host
    Port 8000
    URI /api/v1/logs/ingest
    Format json
    json_date_key timestamp
    json_date_format iso8601
```

### Option 3: Vector Agent

Configure Vector to forward logs:

```toml
[sinks.siembox]
type = "http"
inputs = ["your_source"]
uri = "http://your-siembox-host:8000/api/v1/logs/ingest"
encoding.codec = "json"
```

## Port Configuration

By default, SIEM BOX uses these ports:

- **3000**: Frontend web interface
- **8000**: Backend API
- **5432**: PostgreSQL database

To change ports, update the `compose.yaml` file:

```yaml
services:
  frontend:
    ports:
      - "8080:80"  # Change 3000 to 8080

  backend:
    ports:
      - "9000:8000"  # Change 8000 to 9000
```

## Monitoring and Maintenance

### View Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f backend
docker compose logs -f frontend
docker compose logs -f postgres
```

### Backup Database

```bash
# Create backup
docker exec siembox-postgres pg_dump -U siembox siembox > backup_$(date +%Y%m%d).sql

# Restore backup
docker exec -i siembox-postgres psql -U siembox siembox < backup_20250101.sql
```

### Update Deployment

```bash
# Pull latest changes
git pull

# Rebuild and restart services
docker compose down
docker compose build --no-cache
docker compose up -d
```

### Reset Data (Development Only)

**WARNING**: This will delete all data!

```bash
docker compose down -v
docker compose up -d
```

## Troubleshooting

### Frontend Not Loading

1. Check if all containers are running:
   ```bash
   docker compose ps
   ```

2. Check frontend logs:
   ```bash
   docker compose logs frontend
   ```

3. Verify backend is accessible from frontend container:
   ```bash
   docker exec siembox-frontend curl -f http://backend:8000/api/v1/health/
   ```

### Backend Database Connection Issues

1. Check PostgreSQL is healthy:
   ```bash
   docker compose ps postgres
   ```

2. Verify database connectivity:
   ```bash
   docker exec siembox-backend curl -f http://localhost:8000/api/v1/health/
   ```

3. Check backend logs for errors:
   ```bash
   docker compose logs backend | grep ERROR
   ```

### No Data Displaying

1. Verify logs are being ingested:
   ```bash
   docker exec siembox-postgres psql -U siembox -d siembox -c "SELECT COUNT(*) FROM processed_logs;"
   ```

2. Check authentication:
   - Ensure you're logged in
   - Check browser console for API errors (F12)
   - Verify JWT token is being sent with requests

3. Test API directly:
   ```bash
   # Login
   TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"admin123"}' | jq -r '.access_token')

   # Get logs
   curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/logs
   ```

## Security Hardening

### Production Security Checklist

- [ ] Change all default passwords
- [ ] Use strong SECRET_KEY (32+ characters, random)
- [ ] Enable HTTPS with reverse proxy (nginx/Caddy)
- [ ] Configure firewall rules
- [ ] Restrict database port (5432) to localhost only
- [ ] Set up automated backups
- [ ] Configure log rotation
- [ ] Review and limit CORS_ORIGINS
- [ ] Enable rate limiting on ingestion endpoint
- [ ] Set up monitoring and alerting

### Reverse Proxy Example (nginx)

```nginx
server {
    listen 443 ssl http2;
    server_name siembox.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /api/ {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /ws/ {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

## Performance Tuning

### For High Log Volume

Update `compose.yaml` backend service:

```yaml
environment:
  # Increase worker processes
  WORKERS: 4

  # Database connection pool
  DB_POOL_SIZE: 20
  DB_MAX_OVERFLOW: 10
```

### Database Optimization

```sql
-- Connect to database
docker exec -it siembox-postgres psql -U siembox -d siembox

-- Create indexes for common queries
CREATE INDEX idx_processed_logs_timestamp ON processed_logs(timestamp DESC);
CREATE INDEX idx_processed_logs_severity ON processed_logs(severity);
CREATE INDEX idx_processed_logs_source_ip ON processed_logs(source_ip);
CREATE INDEX idx_alerts_triggered_at ON alerts(triggered_at DESC);
CREATE INDEX idx_alerts_severity ON alerts(severity);
```

## Support and Updates

- **Documentation**: See README.md and CLAUDE.md
- **Issues**: Check logs first, then review troubleshooting section
- **Updates**: Pull latest changes and rebuild containers

## Next Steps

After successful deployment:

1. Change default admin password
2. Create additional user accounts (Settings page)
3. Configure detection rules (Detection Rules page)
4. Set up notification channels (Settings page)
5. Start sending logs to the ingestion endpoint
6. Configure scheduled vulnerability scans
7. Review and customize alert thresholds
