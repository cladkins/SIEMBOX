# SIEM BOX

**A lightweight, self-hosted SIEM for your homelab**

Stop manually checking logs. SIEM BOX collects, analyzes, and alerts on security events from all your homelab systems in one place.

## What Does It Do?

- **Collects syslog** from all your systems (firewalls, servers, routers)
- **Stores logs** in PostgreSQL for searching and analysis
- **Shows everything** in a clean React dashboard
- **Real-time monitoring** with auto-refreshing log display

**Simple and focused. Just syslog ingestion and display.**

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
- Simple and lightweight - ~350 lines of Python
- Self-contained - no cloud dependencies

**What You Get:**
- Real-time log monitoring from all your systems via syslog
- Clean React dashboard for viewing logs
- PostgreSQL storage for log history
- Full REST API for automation
- JWT authentication for security

## Architecture

```
Your Systems → UDP 514 → SIEM BOX → React UI
   (Syslog)              (Docker)      (You)
```

**Components:**
- **Frontend**: React dashboard on Nginx (port 3000)
- **Backend**: FastAPI + Syslog server (port 8000, UDP 514)
- **Database**: PostgreSQL (port 5432)
- **Ingestion**: Syslog UDP 514 (primary) + HTTP API

See [SIMPLE-DEPLOY.md](SIMPLE-DEPLOY.md) for deployment details.

## Sending Logs

### Option 1: Syslog (Recommended - Works Out of the Box)

Point your devices to send syslog to your SIEM BOX IP on UDP port 514.

**Firewall/Router Configuration:**
```
Syslog Server: 192.168.1.x
Port: 514
Protocol: UDP
```

**Works with:**
- OPNsense/pfSense firewalls
- Unifi devices
- Cisco/Juniper routers
- Linux servers (rsyslog/syslog-ng)
- Any device that supports syslog

**Test it:**
```bash
# Send a test syslog message
echo "<134>Nov 24 12:34:56 firewall kernel: Test syslog" | nc -u localhost 514
```

### Option 2: Fluent Bit/Vector (Advanced)

For custom log parsing:

**Fluent Bit:**
```ini
[OUTPUT]
    Name syslog
    Match *
    Host your-siembox-ip
    Port 514
    Mode udp
```

**Vector:**
```toml
[sinks.siembox]
type = "socket"
mode = "udp"
address = "your-siembox-ip:514"
encoding.codec = "syslog"
```

More examples in [ingestion_agents/](ingestion_agents/)

## Features

### ✅ Syslog Ingestion
- UDP 514 syslog receiver
- RFC 3164 syslog parsing (legacy format)
- Automatic hostname and timestamp extraction
- Works with any syslog-compatible device

### ✅ Log Storage
- PostgreSQL database for all logs
- Indexed for fast queries
- Stores raw syslog + parsed fields

### ✅ Web Dashboard
- React-based UI
- View recent logs with pagination
- Dashboard stats (total logs, 24h logs)
- JWT authentication

### ✅ REST API
- `/api/v1/auth/login` - Authentication
- `/api/v1/logs` - Get logs with pagination
- `/api/v1/dashboard/stats` - Dashboard statistics
- Full API docs at `/docs` when running

## Configuration

**Default Login:**
- Username: `admin`
- Password: `admin123`

**Environment Variables** (optional):
- `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASS` - Database connection
- `SECRET_KEY` - JWT secret (change in production!)
- `SYSLOG_HOST`, `SYSLOG_PORT` - Syslog server settings

All configuration is in `compose.yaml`. For production deployment with SSL, custom passwords, etc., see [SIMPLE-DEPLOY.md](SIMPLE-DEPLOY.md)

## Ports

- **514/UDP**: Syslog ingestion (primary method)
- **3000**: Web interface
- **8000**: API and HTTP log ingestion
- **5432**: PostgreSQL (internal)

## Documentation

- **[SIMPLE-DEPLOY.md](SIMPLE-DEPLOY.md)** - Complete deployment guide
- **[TESTING.md](TESTING.md)** - Testing and verification guide
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

1. Check backend is receiving syslogs:
   ```bash
   docker logs siembox-backend | grep SYSLOG
   ```

2. Send a test syslog:
   ```bash
   echo "<134>Nov 24 12:34:56 test-host Test message" | nc -u localhost 514
   ```

3. Check database:
   ```bash
   docker exec siembox-postgres psql -U siembox -d siembox \
     -c "SELECT COUNT(*) FROM logs;"
   ```

4. Check API returns logs:
   ```bash
   # Login first
   TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"admin123"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

   # Get logs
   curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/logs | python3 -m json.tool
   ```

### Frontend won't load?

Wait 30 seconds for all services to start, then refresh. Check service health:

```bash
docker compose ps
```

All services should show "healthy".

### Other issues?

See [SIMPLE-DEPLOY.md](SIMPLE-DEPLOY.md) for more troubleshooting steps.

## Security

**Default Credentials:**
- Username: `admin`
- Password: `admin123`

**🚨 CHANGE THESE IMMEDIATELY AFTER FIRST LOGIN 🚨**

For production:
1. Change default password after first login
2. Generate secure SECRET_KEY: `openssl rand -hex 32` (update in compose.yaml)
3. Use strong database password in compose.yaml
4. Set up reverse proxy with SSL (nginx/Caddy)
5. Restrict database port to localhost only

The simple backend has hardcoded credentials for simplicity. For production, you'll need to implement proper user management.

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
