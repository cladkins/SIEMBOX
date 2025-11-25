# SIEM BOX - Testing Guide

## Deploy on Docker Server

### 1. Clone Repository

```bash
git clone https://github.com/cladkins/SIEMBOX.git
cd SIEMBOX
git checkout develop  # Use develop branch
```

### 2. Start SIEM BOX

```bash
# Start all services
docker compose up -d

# Watch logs during startup
docker compose logs -f
```

Wait for this message:
```
✅ Syslog server started on UDP 514
```

Press `Ctrl+C` to stop watching logs.

### 3. Verify Services Are Running

```bash
docker compose ps
```

All services should show "healthy":
- siembox-postgres
- siembox-backend
- siembox-frontend

### 4. Test Syslog Ingestion

```bash
# Send test syslog messages
python3 test_syslog.py
```

You should see:
```
📤 Sent: <133>Nov 24 12:34:56 test-firewall kernel: FIREWALL: BLOCK...
📤 Sent: <84>Nov 24 12:34:56 test-firewall sshd: Failed password...
...
✅ Test syslogs sent!
```

### 5. Verify Detection Flow

```bash
# Run comprehensive test
python3 test_detection_flow.py
```

Expected output:
```
✅ Logged in successfully
✅ Found 20 enabled detection rules
✅ Sent 10 test logs
✅ Found 22 total logs in database
✅ Found 2 alerts!
🎉 BASIC SIEM FLOW IS FUNCTIONAL!
```

### 6. Check the Web Interface

Open browser: `http://<your-docker-server-ip>:3000`

Login:
- Username: `admin`
- Password: `admin123`

Check these pages:
- **Dashboard** - Should show log and alert statistics
- **Logs** - Should see test logs from syslog
- **Alerts** - Should see 2 alerts (SSH brute force, port scan)
- **Detection Rules** - Should show ~20 enabled rules

## Troubleshooting

### No syslog server message in logs

```bash
# Check backend logs for errors
docker compose logs backend | grep -i syslog

# Check if port 514 is bound
docker exec siembox-backend netstat -ulnp | grep 514
```

### Port 514 permission error

If you see:
```
⚠️  Cannot bind to port 514 (requires root/CAP_NET_BIND_SERVICE)
```

The backend needs NET_BIND_SERVICE capability. This should be automatic in Docker, but check:

```bash
docker inspect siembox-backend | grep -A 5 CapAdd
```

Should show `NET_ADMIN` and `NET_RAW`.

### No alerts generated

```bash
# Check if detection rules exist
docker exec -it siembox-postgres psql -U siembox -d siembox \
  -c "SELECT COUNT(*) FROM detection_rules WHERE is_enabled = true;"

# Should show ~20 rules
```

If 0 rules, initialize them:
```bash
docker exec siembox-backend python -c "
from app.services.detection_service import detection_service
import asyncio
asyncio.run(detection_service.initialize_default_rules())
"
```

### Can't connect to web interface

```bash
# Check frontend logs
docker compose logs frontend | tail -20

# Check if port 3000 is accessible
curl http://localhost:3000

# Check firewall on Docker host
sudo ufw status
# May need: sudo ufw allow 3000/tcp
```

### Logs not appearing

```bash
# Check processed_logs table
docker exec -it siembox-postgres psql -U siembox -d siembox \
  -c "SELECT COUNT(*), log_type, source FROM processed_logs GROUP BY log_type, source;"

# Check backend logs for ingestion errors
docker compose logs backend | grep -i "ingest\|syslog"
```

## Test from Firewall/Router

Once basic tests pass, configure your firewall:

### OPNsense/pfSense

```
System → Settings → Logging / Targets
  Remote Syslog Server: <docker-server-ip>
  Port: 514
  Protocol: UDP/IPv4
```

### Unifi

```
Settings → System → Advanced
  Remote Syslog Server: <docker-server-ip>
  Port: 514
```

### Test from Linux System

```bash
# Test with logger command
logger -n <docker-server-ip> -P 514 -t test "Test message from my system"

# Or configure rsyslog
echo '*.* @<docker-server-ip>:514' | sudo tee /etc/rsyslog.d/siembox.conf
sudo systemctl restart rsyslog
```

### Verify Logs Arriving

```bash
# Watch logs in real-time
docker compose logs -f backend | grep "Syslog ingested"

# Should see:
# ✅ Syslog ingested from 192.168.1.x: sshd - authentication
# ✅ Syslog ingested from 192.168.1.x: kernel - firewall
```

## Performance Check

### After 1 Hour of Logging

```bash
# Check database size
docker exec -it siembox-postgres psql -U siembox -d siembox -c "
SELECT
  COUNT(*) as total_logs,
  pg_size_pretty(pg_total_relation_size('processed_logs')) as table_size
FROM processed_logs;
"

# Check alert counts by severity
docker exec -it siembox-postgres psql -U siembox -d siembox -c "
SELECT severity, COUNT(*) FROM alerts GROUP BY severity ORDER BY COUNT(*) DESC;
"
```

### Check for Errors

```bash
# Backend errors
docker compose logs backend | grep -i error | tail -20

# Database errors
docker compose logs postgres | grep -i error | tail -20
```

## Clean Slate (Reset Everything)

```bash
# Stop and remove volumes (DESTROYS ALL DATA)
docker compose down -v

# Restart fresh
docker compose up -d
```

## Success Criteria

Your SIEM BOX is working if:

✅ All services show "healthy"
✅ `test_syslog.py` sends logs without errors
✅ `test_detection_flow.py` shows alerts generated
✅ Web dashboard shows logs and alerts
✅ Real firewall logs appear in the interface
✅ Alerts trigger for SSH brute force / port scans

## Next Steps After Testing

1. **Change default password** (Settings → Users)
2. **Configure notifications** (Settings → Notifications)
3. **Review detection rules** (Detection Rules page)
4. **Set up vulnerability scans** (Vulnerabilities page)
5. **Configure all devices** to send syslog

---

**Need help?** Check backend logs: `docker compose logs backend`
