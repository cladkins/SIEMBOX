# SIEM BOX

**A lightweight, self-hosted SIEM for your homelab**

Stop manually checking logs. SIEM BOX collects, analyzes, and alerts on security events from all your homelab systems in one place.

## What Does It Do?

- **Collects logs** from all your systems (firewalls, servers, containers)
- **Detects threats** with pre-built security rules
- **Sends alerts** via email, Discord, or Slack when shit happens
- **Scans for vulnerabilities** in your network and containers
- **Shows everything** in a clean web dashboard

## Quick Start

```bash
git clone https://github.com/cladkins/SIEMBOX.git
cd SIEMBOX
docker compose up -d
```

Open http://localhost:3000 and login with `admin`/`admin123`

**That's it.** See [QUICK_START.md](QUICK_START.md) for more.

## Why Use This?

**For Homelabs:**
- Runs on a Raspberry Pi or any machine with 2GB RAM
- No expensive enterprise licenses
- Actually works without a PhD in cybersecurity
- Self-contained - no cloud dependencies

**What You Get:**
- Real-time log monitoring from all your systems
- 20+ pre-configured detection rules (brute force, port scans, etc.)
- Automatic vulnerability scanning
- Alert notifications to Discord/Email/Slack
- Full REST API for automation

## Architecture

```
Your Systems → Log Agents → SIEM BOX → Alerts
                (Fluent Bit)   (Docker)    (You)
```

**Components:**
- **Frontend**: React dashboard (port 3000)
- **Backend**: FastAPI service (port 8000)
- **Database**: PostgreSQL (port 5432)
- **Ingestion**: HTTP endpoint for logs

See [CLAUDE.md](CLAUDE.md) for technical details.

## Sending Logs

### Option 1: Direct HTTP

```bash
curl -X POST http://localhost:8000/api/v1/logs/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2025-01-01T12:00:00Z",
    "hostname": "my-server",
    "source_ip": "192.168.1.100",
    "app_name": "nginx",
    "raw_message": "GET /api/users HTTP/1.1 200",
    "severity": "info",
    "log_type": "access"
  }'
```

### Option 2: Fluent Bit (Recommended)

Install Fluent Bit on your systems:

```ini
[OUTPUT]
    Name http
    Match *
    Host your-siembox-ip
    Port 8000
    URI /api/v1/logs/ingest
    Format json
```

### Option 3: Vector

```toml
[sinks.siembox]
type = "http"
uri = "http://your-siembox-ip:8000/api/v1/logs/ingest"
encoding.codec = "json"
```

More examples in [ingestion_agents/](ingestion_agents/)

## Features

### ✅ Log Management
- Collect from any source (syslog, Docker, apps)
- Search and filter with web UI
- Real-time log streaming

### ✅ Threat Detection
- 20+ pre-configured security rules
- Custom rule creation via UI
- Pattern matching, thresholds, correlation
- Automatic alert generation

### ✅ Alerting
- Multi-channel notifications (Email, Discord, Slack, SMS)
- Configurable severity levels
- Alert acknowledgment and tracking
- Historical alert timeline

### ✅ Vulnerability Scanning
- Network scanning with Nmap
- Container scanning with Trivy
- Scheduled scans
- CVE tracking and remediation workflow

### ✅ Dashboard
- Real-time statistics
- Log volume charts
- Alert trends
- Top sources by activity

## Configuration

All configuration is done through the web UI after deployment:

1. **Settings** → Configure notifications
2. **Detection Rules** → Customize or add rules
3. **Vulnerabilities** → Set up scan schedules
4. **Users** → Manage access (change default password!)

For production deployment with custom passwords, SSL, etc., see [DEPLOYMENT.md](DEPLOYMENT.md)

## Ports

- **3000**: Web interface
- **8000**: API and log ingestion
- **5432**: PostgreSQL (internal)

## Documentation

- **[QUICK_START.md](QUICK_START.md)** - 5-minute setup guide
- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Production deployment guide
- **[CLAUDE.md](CLAUDE.md)** - Architecture and technical details
- **API Docs**: http://localhost:8000/docs (when running)

## Common Commands

```bash
# Start everything
docker compose up -d

# View logs
docker compose logs -f

# Stop everything
docker compose down

# Update to latest
git pull && docker compose up -d --build
```

## Troubleshooting

### No logs showing up?

1. Check backend is receiving logs:
   ```bash
   docker compose logs backend | grep ingest
   ```

2. Test the ingestion endpoint:
   ```bash
   curl -X POST http://localhost:8000/api/v1/logs/ingest \
     -H "Content-Type: application/json" \
     -d '{"timestamp":"2025-01-01T12:00:00Z","hostname":"test","source_ip":"192.168.1.1","app_name":"test","raw_message":"test","severity":"info","log_type":"test"}'
   ```

3. Check database:
   ```bash
   docker exec siembox-postgres psql -U siembox -d siembox \
     -c "SELECT COUNT(*) FROM processed_logs;"
   ```

### Frontend won't load?

Wait 30 seconds for all services to start, then refresh. Check service health:

```bash
docker compose ps
```

All services should show "healthy".

### Other issues?

See [DEPLOYMENT.md](DEPLOYMENT.md#troubleshooting) for more troubleshooting steps.

## Security

**Default Credentials:**
- Username: `admin`
- Password: `admin123`

**🚨 CHANGE THESE IMMEDIATELY AFTER FIRST LOGIN 🚨**

For production:
1. Change default password (Settings → Users)
2. Generate secure SECRET_KEY: `openssl rand -hex 32`
3. Use strong database password in `.env` file
4. Set up reverse proxy with SSL (nginx/Caddy)
5. Restrict database port to localhost only

See [DEPLOYMENT.md](DEPLOYMENT.md#security-hardening) for full security checklist.

## Requirements

- Docker & Docker Compose
- 2GB+ RAM
- 10GB+ disk space
- Linux, macOS, or Windows with WSL2

## Support

- **Issues**: https://github.com/cladkins/SIEMBOX/issues
- **Docs**: Read DEPLOYMENT.md and QUICK_START.md first
- **Questions**: Check existing issues before opening new ones

## License

MIT License - see LICENSE file

## Contributing

PRs welcome! Please:
1. Test your changes with `docker compose up`
2. Update docs if needed
3. Keep it simple - this is for homelabbers, not enterprises

---

**SIEM BOX** - Because manually checking logs sucks 🔒
