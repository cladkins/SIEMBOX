# SIEMBox Frequently Asked Questions (FAQ)

Common questions and answers about SIEMBox installation, configuration, and usage.

## Table of Contents

- [General Questions](#general-questions)
- [Installation & Deployment](#installation--deployment)
- [Configuration](#configuration)
- [Log Shipping & Ingestion](#log-shipping--ingestion)
- [Parsers & Detection Rules](#parsers--detection-rules)
- [Alerts & Monitoring](#alerts--monitoring)
- [Performance & Scaling](#performance--scaling)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [Development](#development)

---

## General Questions

### What is SIEMBox?

SIEMBox is a lightweight, self-hosted Security Information and Event Management (SIEM) system. It collects, parses, analyzes, and alerts on security events from your infrastructure.

### Is SIEMBox free?

Yes! SIEMBox is open-source and released under the MIT License. It's completely free to use, modify, and distribute.

### What are the system requirements?

**Minimum:**
- 2 CPU cores
- 4GB RAM
- 20GB disk space
- Docker & Docker Compose

**Recommended for production:**
- 4+ CPU cores
- 8GB+ RAM
- 100GB+ SSD storage
- PostgreSQL tuning for your log volume

### How is SIEMBox different from commercial SIEMs?

**Advantages:**
- ✅ Free and open-source
- ✅ Self-hosted (full data control)
- ✅ Simple deployment (Docker Compose)
- ✅ Easy to customize
- ✅ No per-GB pricing or licensing costs

**Limitations:**
- ❌ Smaller community compared to commercial options
- ❌ No enterprise support (community-driven)
- ❌ Fewer pre-built integrations
- ❌ Scaling requires manual configuration

### What log sources does SIEMBox support?

SIEMBox can receive logs from any source that can send syslog:
- Web servers (Nginx, Apache, Traefik, Caddy)
- Authentication systems (Authelia, Keycloak)
- DNS servers (Pi-hole, Unbound)
- Containers (Docker logs via log shipper)
- System logs (via journald)
- Custom applications (via syslog library)

See [PARSERS.md](./PARSERS.md) for pre-built parsers.

---

## Installation & Deployment

### How do I install SIEMBox?

The easiest way is using Docker Compose:

```bash
git clone https://github.com/cladkins/SIEMBOX.git
cd SIEMBOX
cp .env.example .env
nano .env  # Configure your settings
docker compose up -d
```

See [DEPLOYMENT.md](./DEPLOYMENT.md) for detailed instructions.

### Do I need to know Docker?

Basic Docker knowledge is helpful but not required. The deployment guide provides step-by-step instructions for complete beginners.

### Can I run SIEMBox without Docker?

Yes, but it's more complex. You'll need to:
1. Install PostgreSQL 15+
2. Install Node.js 18+
3. Build backend and frontend manually
4. Configure environment variables
5. Set up a reverse proxy (Nginx)

See backend and frontend READMEs for manual setup instructions.

### What ports does SIEMBox use?

- **514** (UDP/TCP): Syslog ingestion
- **3000** (HTTP): Frontend web interface
- **3001** (HTTP): Backend API
- **5432** (internal): PostgreSQL database

Ports 3000 and 3001 should be accessible from your browser. Port 514 should be accessible from log sources. Port 5432 should be internal-only.

### Can I use an existing PostgreSQL database?

Yes! Configure the database connection in your `.env` file:

```bash
DB_HOST=your-postgres-host
DB_PORT=5432
DB_NAME=siembox
DB_USER=your_user
DB_PASSWORD=your_password
```

Run the migration script to create tables: `cd backend && npm run migrate`

### How do I upgrade SIEMBox?

**Pre-v1.0 (current):**
```bash
git pull origin develop
docker compose down
docker compose build
docker compose up -d
```

**Note:** May require database reset (see `docs/guides/PRE-V1-DATABASE.md`)

**Post-v1.0:** Upgrades will use proper database migrations without data loss.

---

## Configuration

### Where do I configure SIEMBox?

Configuration is primarily done through:
1. **`.env` file**: Environment variables (secrets, database, ports)
2. **Web UI**: Parsers, rules, users, settings
3. **YAML files**: Detection rules in `/rules` directory

### How do I change the default admin password?

**During installation:**
Set `DEFAULT_ADMIN_PASSWORD` in `.env` before first startup.

**After installation:**
1. Log in as admin
2. Go to User Management
3. Click on admin user
4. Change password

### How do I add more users?

1. Log in as admin
2. Navigate to **User Management**
3. Click **Add User**
4. Fill in username, password, role
5. Click **Create**

### What are the different user roles?

- **Admin**: Full system access (users, settings, all logs)
- **Analyst**: View and manage logs, alerts, rules, parsers
- **Viewer**: Read-only access to logs and alerts
- **Operator**: Manage assets and scans

### How do I configure log retention?

1. Log in as admin
2. Go to **Settings**
3. Configure retention periods:
   - Raw logs retention (days)
   - Parsed logs retention (days)
   - Alerts retention (days)
4. Click **Save**

Cleanup runs automatically every 24 hours (configurable via `CLEANUP_INTERVAL_HOURS` in `.env`).

### Can I use HTTPS instead of HTTP?

Yes! Place a reverse proxy (Nginx, Traefik, Caddy) in front of SIEMBox with SSL/TLS termination.

**Example with Nginx:**
```nginx
server {
    listen 443 ssl;
    server_name siembox.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## Log Shipping & Ingestion

### How do I send logs to SIEMBox?

**Option 1: Use the log shipper** (recommended)
- Install the log shipper on source systems
- Configure log sources in the SIEMBox UI
- Shipper automatically forwards logs

See [log-shipper/README.md](./log-shipper/README.md).

**Option 2: Direct syslog**
- Configure applications to send syslog to SIEMBox:514
- Example: `logger -n siembox.local -P 514 "Test message"`

**Option 3: Rsyslog/Syslog-ng**
- Configure existing syslog infrastructure to forward to SIEMBox

### What is the log shipper?

A lightweight agent that:
- Tails log files and Docker containers
- Formats logs as syslog messages
- Sends to SIEMBox via UDP/TCP
- Fetches configuration from SIEMBox API
- Continues working if API is unavailable (cached config)

### How do I install the log shipper?

```bash
docker run -d \
  --name siembox-log-shipper \
  -e SIEMBOX_API_URL=http://your-siembox:3001/api \
  -e SHIPPER_API_KEY=your-64-char-api-key \
  -v /var/log:/var/log:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  siembox-log-shipper
```

See [log-shipper/README.md](./log-shipper/README.md) for detailed setup.

### Why aren't my logs appearing?

**Checklist:**
1. ✅ Is the syslog server running? Check `docker logs siembox-backend`
2. ✅ Can the log source reach port 514? Test with `nc -u siembox.local 514`
3. ✅ Are logs in `raw_logs` table? Check database: `SELECT COUNT(*) FROM raw_logs;`
4. ✅ Are parsers enabled? Check parsers in UI or database
5. ✅ Do logs match parser patterns? Use parser test endpoint

See [docs/operations/TROUBLESHOOTING.md](./docs/operations/TROUBLESHOOTING.md) for detailed debugging.

### What is a "ghost shipper"?

A log shipper with an invalid or expired API key that continues sending logs using cached configuration. Ghost shippers are visible in the UI under "Unknown Sources" so admins can fix them.

**To fix:**
1. Go to Shippers page in UI
2. Check "Unknown Sources" section
3. Regenerate API key or delete old shipper
4. Update shipper configuration with new key

---

## Parsers & Detection Rules

### What is a parser?

A parser transforms raw log messages into structured data with named fields. Parsers use regex patterns, grok patterns, or JSON parsing.

**Example:**
```
Input:  "192.168.1.100 - GET /api 200"
Parser: (?<client_ip>\d+\.\d+\.\d+\.\d+).*(?<method>\w+)\s+(?<path>\S+)\s+(?<status>\d+)
Output: {client_ip: "192.168.1.100", method: "GET", path: "/api", status: "200"}
```

### How do I create a parser?

1. Go to **Parsers** in the UI
2. Click **Add Parser**
3. Fill in:
   - Name (e.g., "nginx-access")
   - Description
   - Pattern (regex with named groups)
   - Priority (lower = higher priority)
4. Test with sample logs
5. Click **Create**

See [PARSERS.md](./PARSERS.md) for detailed guide and examples.

### Why aren't my logs being parsed?

**Common issues:**
1. ❌ Parser pattern doesn't match log format
2. ❌ Parser is disabled
3. ❌ Parser priority is too low (another parser matched first)
4. ❌ Log is in `raw_logs` but parser expects different format

**Debug steps:**
1. Check raw log in `raw_logs` table: `SELECT raw_message FROM raw_logs LIMIT 10;`
2. Test pattern using parser test endpoint
3. Verify parser is enabled and has appropriate priority
4. Check backend logs for parsing errors

### What is a detection rule?

A rule that identifies security events by evaluating parsed log fields against conditions. Rules can detect patterns like:
- Failed login attempts (brute force)
- Unusual access patterns
- Error spikes
- Unauthorized actions

### How do I create a detection rule?

**Option 1: Web UI**
1. Go to **Detection Rules**
2. Click **Add Rule**
3. Configure conditions, aggregations, severity
4. Test against historical logs
5. Enable rule

**Option 2: YAML file**
Create a file in `/rules/<category>/`:

```yaml
name: SSH Brute Force
description: Detects multiple failed SSH attempts
severity: high
enabled: true
conditions:
  - field: app_name
    operator: equals
    value: sshd
  - field: message
    operator: contains
    value: "Failed password"
aggregation:
  type: threshold
  field: source_ip
  threshold: 5
  timeframe: 300  # 5 minutes
```

See [RULES.md](./RULES.md) for detailed guide.

### Can I contribute parsers and rules?

Yes! We welcome community contributions. See [PARSERS.md](./PARSERS.md) and [RULES.md](./RULES.md) for submission guidelines.

---

## Alerts & Monitoring

### How do I view alerts?

1. Log in to the web UI
2. Navigate to **Alerts** or check the Dashboard
3. Click on an alert to view details
4. Acknowledge alerts once investigated

### How do I acknowledge an alert?

1. Go to **Alerts** page
2. Find the alert
3. Click **Acknowledge**
4. Optionally add notes about your investigation

Acknowledged alerts are marked as reviewed but remain visible in the UI.

### Can I get email notifications for alerts?

Not yet. Email/webhook notifications are on the roadmap. For now, monitor alerts via:
- Dashboard (shows recent alerts)
- Alerts page (filterable by severity, rule)
- API polling (for custom integrations)

### How do I reduce false positives?

1. **Tune rule thresholds**: Increase count/timeframe requirements
2. **Add exclusion conditions**: Filter out known-good patterns
3. **Adjust severity**: Downgrade non-critical alerts
4. **Disable noisy rules**: Temporarily disable problematic rules
5. **Refine parsers**: Ensure accurate field extraction

### How do I export alerts?

**Via UI:**
- Click "Export" on Alerts page (future feature)

**Via API:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://siembox:3001/api/alerts?limit=1000" > alerts.json
```

**Via Database:**
```sql
COPY (SELECT * FROM alerts WHERE created_at > NOW() - INTERVAL '7 days')
TO '/tmp/alerts.csv' CSV HEADER;
```

---

## Performance & Scaling

### How many logs can SIEMBox handle?

**Current architecture (single node):**
- **Small**: <1,000 logs/minute
- **Medium**: 1,000-10,000 logs/minute
- **Large**: 10,000+ logs/minute (requires tuning)

Performance depends on:
- Hardware (CPU, RAM, disk I/O)
- Parser complexity
- Rule count
- PostgreSQL tuning

### How do I improve performance?

**Database tuning:**
1. Increase `shared_buffers` in PostgreSQL
2. Add indexes on frequently queried fields
3. Tune `work_mem` and `maintenance_work_mem`
4. Enable query caching

**Application tuning:**
1. Disable unused parsers and rules
2. Reduce parser regex complexity
3. Implement log filtering at shipper level
4. Increase retention cleanup frequency

**Infrastructure:**
1. Use SSD storage for PostgreSQL
2. Increase backend memory limit
3. Use dedicated database server
4. Consider read replicas for queries

See [docs/operations/PERFORMANCE.md](./docs/operations/PERFORMANCE.md) (future doc).

### Can SIEMBox scale horizontally?

Currently, SIEMBox is designed for single-node deployment. Horizontal scaling requires:
- Load balancer for backend replicas
- Shared database or PostgreSQL replication
- Redis for session storage
- Message queue for async processing

These features are planned for post-v1.0 releases.

### How much disk space do I need?

**Estimate:** `logs_per_day * average_log_size * retention_days`

**Example:**
- 100,000 logs/day
- 500 bytes average size
- 30 days retention
- = ~1.5GB log data

Add overhead for:
- Database indexes
- Parsed log JSONB fields
- Alerts and metadata
- Database WAL files

**Recommendation:** 2-3x your calculated log data size.

---

## Security

### How secure is SIEMBox?

SIEMBox implements security best practices:
- ✅ Parameterized SQL queries (no SQL injection)
- ✅ bcrypt password hashing
- ✅ JWT authentication
- ✅ Role-based access control
- ✅ Rate limiting on sensitive endpoints
- ✅ Security headers (X-Frame-Options, etc.)

See [SECURITY.md](./SECURITY.md) for comprehensive security guidance.

### Should I change the default passwords?

**YES!** Always change default credentials before exposing SIEMBox to a network.

In `.env`:
```bash
JWT_SECRET=your-random-secret-key-here
DEFAULT_ADMIN_PASSWORD=your-secure-password
CREDENTIAL_ENCRYPTION_KEY=32-byte-hex-key
DB_PASSWORD=strong-database-password
```

### Can I use LDAP/Active Directory authentication?

Not yet. LDAP/SAML authentication is planned for future releases. Current authentication is database-based with bcrypt hashing.

### How do I secure the API?

1. **Use HTTPS**: Place reverse proxy with SSL/TLS
2. **Restrict access**: Firewall rules or network segmentation
3. **Strong secrets**: Change default JWT_SECRET
4. **Rate limiting**: Already configured (can adjust limits)
5. **Monitor access**: Check audit logs for suspicious activity

### Are logs encrypted at rest?

Database logs are stored in PostgreSQL without encryption by default. To enable encryption at rest:

**Option 1:** Use PostgreSQL with encryption-enabled storage
**Option 2:** Full disk encryption on the host
**Option 3:** PostgreSQL transparent data encryption (TDE) extensions

### How do I rotate API keys?

**Log shipper API keys:**
1. Go to **Shippers** page in UI
2. Click on shipper
3. Click **Regenerate Key**
4. Copy new key (shown only once)
5. Update shipper environment variable: `SHIPPER_API_KEY=new-key`
6. Restart shipper

Old key is immediately invalidated.

---

## Troubleshooting

### Logs show "raw_logs table" but not in "parsed_logs"

**Cause:** Parser not matching log format

**Solution:**
1. Check `raw_logs` table: `SELECT raw_message FROM raw_logs LIMIT 10;`
2. Compare to parser pattern
3. Use parser test endpoint to debug
4. Adjust pattern or create new parser

### Frontend shows "Network Error" or "API connection failed"

**Cause:** Backend not accessible or not running

**Solution:**
1. Check backend is running: `docker ps | grep siembox-backend`
2. Check backend logs: `docker logs siembox-backend`
3. Verify API_URL in frontend: Check `.env` file
4. Test API directly: `curl http://localhost:3001/health`

### Port 514 "Permission Denied"

**Cause:** Ports <1024 require root privileges

**Solution:**

**Development:**
```bash
SYSLOG_PORT=5514 npm run dev
```

**Production (Docker):**
Docker automatically handles privileged port binding.

**Production (manual):**
```bash
# Option 1: Use authbind
authbind --deep node dist/server.js

# Option 2: Set capabilities
sudo setcap 'cap_net_bind_service=+ep' $(which node)
```

### High memory usage

**Causes:**
- Large log volume
- Memory leak (report bug)
- Insufficient PostgreSQL tuning

**Solutions:**
1. Check log volume: `SELECT COUNT(*) FROM raw_logs;`
2. Reduce retention periods
3. Increase Docker memory limits
4. Tune PostgreSQL `shared_buffers`
5. Restart services periodically

See [docs/operations/TROUBLESHOOTING.md](./docs/operations/TROUBLESHOOTING.md) for more issues.

---

## Development

### How do I contribute to SIEMBox?

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make changes and test
4. Commit: `git commit -m "feat: add my feature"`
5. Push: `git push origin feature/my-feature`
6. Create Pull Request targeting `develop` branch

See [CONTRIBUTING.md](./CONTRIBUTING.md) and [docs/guides/GETTING_STARTED_DEVELOPMENT.md](./docs/guides/GETTING_STARTED_DEVELOPMENT.md).

### How do I set up a development environment?

See [docs/guides/GETTING_STARTED_DEVELOPMENT.md](./docs/guides/GETTING_STARTED_DEVELOPMENT.md) for complete setup instructions.

**Quick start:**
```bash
# Backend
cd backend
npm install
npm run dev

# Frontend (new terminal)
cd frontend
npm install
npm run dev
```

### Where can I find API documentation?

See [API.md](./API.md) for complete REST API reference.

### How do I run tests?

**Backend:**
```bash
cd backend
npm test
npm run test:coverage
```

**Frontend:**
```bash
cd frontend
npm test
```

### Can I add custom features?

Yes! SIEMBox is open-source. You can:
- Modify the code for your needs
- Add custom parsers and rules
- Integrate with other tools via the API
- Contribute improvements back to the project

---

## Still Have Questions?

- **Documentation**: [docs/README.md](./docs/README.md)
- **Issues**: [GitHub Issues](https://github.com/cladkins/SIEMBOX/issues)
- **Discussions**: [GitHub Discussions](https://github.com/cladkins/SIEMBOX/discussions)
- **Glossary**: [GLOSSARY.md](./GLOSSARY.md)
- **Troubleshooting**: [docs/operations/TROUBLESHOOTING.md](./docs/operations/TROUBLESHOOTING.md)
