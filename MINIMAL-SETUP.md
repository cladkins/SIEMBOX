# SIEM BOX - Minimal Setup Guide

**Goal:** Get syslog working in 5 minutes. No complexity.

## What You Get

- Syslog listener on UDP 514
- PostgreSQL database
- Simple API (GET /logs)
- Basic web interface
- **That's it.**

## Quick Start

### 1. Start Everything

```bash
docker compose -f compose-minimal.yaml up -d
```

Wait 10 seconds for services to start.

### 2. Check It's Running

```bash
# Check services
docker compose -f compose-minimal.yaml ps

# Should see 4 services: postgres, syslog, api, frontend
```

### 3. Send a Test Syslog

```bash
# Send test syslog message
echo "<134>Nov 24 12:34:56 test-host This is a test message" | nc -u -w1 localhost 514
```

### 4. Verify It Worked

**Check Database:**
```bash
docker exec siembox-minimal-postgres psql -U siembox -d siembox -c "SELECT COUNT(*) FROM logs;"
```

Should show: `1` (or more)

**Check API:**
```bash
curl http://localhost:8000/logs | python3 -m json.tool
```

Should return JSON with your log.

**Check Frontend:**

Open browser: http://localhost:3000

Should see your test log in the table.

## It Works? Good.

Now configure your firewall to send logs:

### OPNsense/pfSense

```
System → Settings → Logging / Targets
  Remote Syslog Server: <your-server-ip>
  Port: 514
  Protocol: UDP/IPv4
```

### Unifi

```
Settings → System → Advanced
  Remote Syslog Server: <your-server-ip>
  Port: 514
```

### Linux (rsyslog)

```bash
# Add to /etc/rsyslog.d/siembox.conf
*.* @<your-server-ip>:514

# Restart
sudo systemctl restart rsyslog
```

## Troubleshooting

### No logs appearing?

**1. Check syslog server logs:**
```bash
docker logs siembox-minimal-syslog
```

Should see:
```
[SYSLOG] ✅ Listening on UDP 0.0.0.0:514
```

**2. Check database connection:**
```bash
docker logs siembox-minimal-syslog | grep "DB"
```

Should see:
```
[DB] ✅ Connected to database
```

**3. Send test again and watch logs:**
```bash
# In one terminal
docker logs -f siembox-minimal-syslog

# In another
echo "<134>$(date '+%b %d %H:%M:%S') test-host test message" | nc -u -w1 localhost 514
```

Should see:
```
[RECV] 127.0.0.1 → <134>Nov 24 12:34:56 test-host test message
[STORE] ✅ test-host → test message
```

### API not responding?

```bash
# Check API logs
docker logs siembox-minimal-api

# Test health endpoint
curl http://localhost:8000/health
```

Should return:
```json
{"status": "healthy", "database": "connected"}
```

### Frontend showing error?

Make sure API is accessible from your browser. The frontend calls:
```
http://localhost:8000/logs
```

If you're accessing from a different machine, update `minimal-frontend.html`:

```javascript
const API_URL = 'http://YOUR-SERVER-IP:8000';
```

## View Logs

**Web Interface:**
```
http://localhost:3000
```

**API:**
```bash
# Get last 50 logs
curl http://localhost:8000/logs

# Get last 100 logs
curl http://localhost:8000/logs?limit=100

# Get log count
curl http://localhost:8000/logs/count
```

**Database Direct:**
```bash
docker exec -it siembox-minimal-postgres psql -U siembox -d siembox

SELECT * FROM logs ORDER BY id DESC LIMIT 10;
```

## Stop Everything

```bash
docker compose -f compose-minimal.yaml down
```

## Delete Everything (Fresh Start)

```bash
docker compose -f compose-minimal.yaml down -v
```

This deletes all data.

## Success Criteria

✅ Docker services running
✅ Test syslog appears in database
✅ API returns logs
✅ Frontend displays logs
✅ Real firewall logs appear

**If all 5 work → You have a working SIEM.**

## Next Steps

Once this minimal version works:

1. Add authentication
2. Add log filtering
3. Add simple detection rules
4. Add alerts
5. Build from there

But first: **get logs flowing**.

---

**This is as simple as it gets. If this doesn't work, something fundamental is broken.**
