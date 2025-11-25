# Deploy Minimal SIEM on Your Docker Server

## What You're Deploying

**A dead-simple syslog SIEM:**
- Receives syslog on UDP 514
- Stores in PostgreSQL
- Shows logs in web interface
- ~300 lines of code total
- **No complexity. Just works.**

## On Your Docker Server

### Step 1: Clone and Checkout

```bash
cd ~
git clone https://github.com/cladkins/SIEMBOX.git
cd SIEMBOX
git checkout develop  # Important: use develop branch
git pull  # Get latest changes
```

### Step 2: Start the Minimal SIEM

```bash
docker compose -f compose-minimal.yaml up -d
```

Watch it start:
```bash
docker compose -f compose-minimal.yaml logs -f
```

Wait for these messages:
- `[DB] ✅ Connected to database`
- `[SYSLOG] ✅ Listening on UDP 0.0.0.0:514`

Press `Ctrl+C` to stop watching.

### Step 3: Verify Services

```bash
docker compose -f compose-minimal.yaml ps
```

Should show 4 services running:
```
siembox-minimal-postgres   running
siembox-minimal-syslog     running
siembox-minimal-api        running
siembox-minimal-frontend   running
```

### Step 4: Send Test Syslog

```bash
echo "<134>Nov 24 12:34:56 test-firewall This is a test from my homelab" | nc -u -w1 localhost 514
```

### Step 5: Verify It Worked

**Option A: Check Database**
```bash
docker exec siembox-minimal-postgres psql -U siembox -d siembox -c "SELECT * FROM logs ORDER BY id DESC LIMIT 1;"
```

Should show your test log.

**Option B: Check API**
```bash
curl http://localhost:8000/logs | python3 -m json.tool | head -30
```

Should return JSON with your log.

**Option C: Check Web Interface**

Open browser: `http://YOUR-DOCKER-SERVER-IP:3000`

Should see a green terminal-style interface with your test log.

## Configure Your Firewall

Now that it works, point your firewall at it:

### OPNsense/pfSense

```
System → Settings → Logging / Targets
  Enable Remote Logging: ✓
  Remote Syslog Server: YOUR-DOCKER-SERVER-IP
  Port: 514
  Protocol: UDP/IPv4
  Log Level: Informational
```

Click "Save" then "Test Remote Logging"

### Unifi

```
Settings → System → Advanced
  Remote Syslog Server: YOUR-DOCKER-SERVER-IP:514
```

### Unraid/TrueNAS

Add to syslog configuration:
```
*.* @YOUR-DOCKER-SERVER-IP:514
```

## Watch Logs Flow In

```bash
# Watch syslog server receiving logs
docker logs -f siembox-minimal-syslog

# Should see:
# [RECV] 192.168.1.1 → <134>Nov 24 12:45:01 firewall kernel: DROP...
# [STORE] ✅ firewall → DROP IN=eth0 SRC=1.2.3.4...
```

Press `Ctrl+C` to stop.

## Check the Web Interface

Open: `http://YOUR-DOCKER-SERVER-IP:3000`

Features:
- **Auto-refresh** every 5 seconds
- **Limit selector** (50/100/200/500 logs)
- **Color coded**: Timestamp (cyan), Hostname (orange), IP (magenta), Message (green)
- **Keyboard shortcuts**: `r` to refresh, `a` to toggle auto-refresh

## Troubleshooting

### No logs appearing?

```bash
# Check syslog server logs
docker logs siembox-minimal-syslog | tail -50

# Check for errors
docker logs siembox-minimal-syslog | grep ERROR
```

### "Connection refused" from frontend?

The frontend makes AJAX calls to `http://localhost:8000/logs`

If accessing from a different machine, you need to edit the frontend:

```bash
# Edit minimal-frontend.html
nano minimal-frontend.html

# Change line 160:
const API_URL = 'http://YOUR-DOCKER-SERVER-IP:8000';

# Restart
docker compose -f compose-minimal.yaml restart frontend
```

### Database connection error?

```bash
# Check postgres is running
docker logs siembox-minimal-postgres | tail -20

# Check postgres is healthy
docker exec siembox-minimal-postgres pg_isready -U siembox
```

### Port 514 in use?

```bash
# Check what's using port 514
sudo netstat -ulnp | grep 514

# Stop conflicting service (e.g., rsyslog)
sudo systemctl stop rsyslog
```

## View Logs

**Web Interface:**
```
http://YOUR-DOCKER-SERVER-IP:3000
```

**API Endpoints:**
```bash
# Get logs
curl http://localhost:8000/logs

# Get specific number
curl http://localhost:8000/logs?limit=100

# Get count
curl http://localhost:8000/logs/count

# Health check
curl http://localhost:8000/health
```

**Database Direct:**
```bash
docker exec -it siembox-minimal-postgres psql -U siembox -d siembox

SELECT COUNT(*) FROM logs;
SELECT * FROM logs ORDER BY id DESC LIMIT 10;
\q
```

## Performance Check

After running for a while:

```bash
# Check log count
docker exec siembox-minimal-postgres psql -U siembox -d siembox -c "
SELECT
  COUNT(*) as total_logs,
  COUNT(DISTINCT source_ip) as unique_sources,
  COUNT(DISTINCT hostname) as unique_hosts,
  pg_size_pretty(pg_total_relation_size('logs')) as table_size
FROM logs;
"
```

## Stop/Start/Restart

```bash
# Stop
docker compose -f compose-minimal.yaml stop

# Start
docker compose -f compose-minimal.yaml start

# Restart
docker compose -f compose-minimal.yaml restart

# Stop and remove (keeps data)
docker compose -f compose-minimal.yaml down

# Remove everything including data
docker compose -f compose-minimal.yaml down -v
```

## Success Checklist

- [ ] All 4 Docker containers running
- [ ] Test syslog appears in database
- [ ] API returns logs at http://localhost:8000/logs
- [ ] Web interface shows logs at http://YOUR-IP:3000
- [ ] Real firewall logs appear
- [ ] Auto-refresh works on frontend

**If all checked → You have a working SIEM!**

## What's Next?

Once you verify logs are flowing:

1. Let it run for a day
2. Verify performance is good
3. Check disk usage
4. Report back what you see

Then we can add:
- Log filtering/search
- Simple detection rules
- Basic alerting
- Whatever you actually need

But first: **verify this minimal version works perfectly**.

---

**This is as simple as a SIEM can be. If this doesn't work, we need to debug at the network level.**
