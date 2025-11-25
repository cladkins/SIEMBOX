# Deploy Simple SIEM with React UI

## What This Is

**Simple backend + Full React UI**
- Syslog ingestion on UDP 514
- FastAPI backend with endpoints React expects
- Your existing React dashboard (logs, dashboard, etc.)
- Minimal auth (admin/admin123)

## Deploy on Docker Server

### 1. Clone and Start

```bash
cd ~
git clone https://github.com/cladkins/SIEMBOX.git
cd SIEMBOX
git checkout develop
git pull

# Start everything
docker compose -f compose-simple.yaml up -d
```

### 2. Watch Startup

```bash
docker compose -f compose-simple.yaml logs -f
```

Wait for:
- `[DB] ✅ Connected to database`
- `[SYSLOG] ✅ Listening on UDP 0.0.0.0:514`
- Frontend build completes

Press `Ctrl+C` when ready.

### 3. Test Syslog Ingestion

```bash
# Send test syslog
echo "<134>Nov 24 12:34:56 firewall kernel: Test syslog from my homelab" | nc -u localhost 514

# Check it was received
docker logs siembox-backend | grep SYSLOG
```

Should see:
```
[SYSLOG] ✅ firewall from 127.0.0.1
```

### 4. Access React UI

Open browser: `http://YOUR-DOCKER-SERVER-IP:3000`

Login:
- **Username**: `admin`
- **Password**: `admin123`

### 5. Verify Logs Appear

After logging in:

1. **Dashboard** - Should show log count
2. **Logs page** - Should see your test log
3. Send more logs - they should appear in real-time

## Configure Firewall

Point your firewall to send syslogs:

### OPNsense/pfSense

```
System → Settings → Logging / Targets
  Remote Syslog Server: YOUR-DOCKER-SERVER-IP
  Port: 514
  Protocol: UDP/IPv4
```

### Unifi

```
Settings → System → Advanced
  Remote Syslog Server: YOUR-DOCKER-SERVER-IP:514
```

### Watch Logs Flow

```bash
# Watch backend receive logs
docker logs -f siembox-backend | grep SYSLOG
```

Should see:
```
[SYSLOG] ✅ firewall from 192.168.1.1
[SYSLOG] ✅ unifi from 192.168.1.2
```

## Troubleshooting

### Can't login?

Credentials are hardcoded:
- Username: `admin`
- Password: `admin123`

If not working, check browser console (F12) for API errors.

### No logs showing in UI?

**1. Check backend is receiving syslogs:**
```bash
docker logs siembox-backend | grep SYSLOG | tail -20
```

**2. Check database has logs:**
```bash
docker exec siembox-postgres psql -U siembox -d siembox -c "SELECT COUNT(*) FROM logs;"
```

**3. Check API returns logs:**
```bash
# Login first
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Get logs
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/logs | python3 -m json.tool | head -50
```

Should return JSON with logs.

**4. Check frontend can reach backend:**

The frontend makes API calls to `/api/v1/...` which nginx proxies to the backend.

Check nginx logs:
```bash
docker logs siembox-frontend | tail -20
```

### Frontend build fails?

```bash
# Check frontend logs
docker logs siembox-frontend

# Rebuild frontend
docker compose -f compose-simple.yaml up -d --build frontend
```

### Port 514 permission error?

Port 514 requires privileged access. The docker container should handle this, but if you see errors:

```bash
# Check backend logs
docker logs siembox-backend | grep -i permission

# May need to add to compose-simple.yaml under backend service:
# privileged: true
```

## What Works

✅ Syslog ingestion (UDP 514)
✅ Login (admin/admin123)
✅ Dashboard page
✅ Logs page
✅ Real-time log display

## What Doesn't Work Yet

❌ Detection rules
❌ Alerts
❌ Notifications
❌ Vulnerability scanning
❌ User management

**But logs are flowing and displaying. That's the foundation.**

## Next Steps

Once logs are flowing:

1. Let it run for a day
2. Check performance
3. Report what you see

Then we add ONE feature at a time:
1. Simple detection (SSH brute force)
2. Basic alerts
3. Simple notifications
4. Build from there

## Stop/Restart

```bash
# Stop
docker compose -f compose-simple.yaml stop

# Start
docker compose -f compose-simple.yaml start

# Restart
docker compose -f compose-simple.yaml restart

# Remove everything
docker compose -f compose-simple.yaml down -v
```

## Success Checklist

- [ ] All 3 containers running
- [ ] Can login to React UI
- [ ] Dashboard shows log count
- [ ] Logs page displays syslogs
- [ ] Real firewall logs appear

**If all checked → React UI is working with syslog backend!**

---

**This uses your React UI with a simple backend. No minimal HTML, full dashboard experience.**
