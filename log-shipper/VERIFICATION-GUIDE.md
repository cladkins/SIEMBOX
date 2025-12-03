# Log Shipper Verification Guide

**Navigation:** [Main README](../README.md) > [Log Shipper](./README.md) > Verification Guide

**Related Documentation:**
- [Quick Reference](./QUICK-REFERENCE.md) - Common commands
- [Deployment Verification](./DEPLOYMENT-VERIFICATION.md) - Full deployment guide
- [Troubleshooting](../TROUBLESHOOTING.md) - General troubleshooting

---

## How to Verify Logs are Being Sent and Received

This guide helps you verify that the log shipper is:
1. Successfully tailing log sources
2. Sending logs via syslog
3. SIEM is receiving and storing logs

---

## Prerequisites

- SSH access to your Docker host
- Log shipper and SIEMBox backend containers running
- At least one log source configured

---

## Step-by-Step Verification

### 1. Check Log Shipper Container Status

```bash
# Check if container is running
docker ps | grep log-shipper

# Should show:
# CONTAINER ID   IMAGE                    STATUS
# abc123def456   siembox-log-shipper     Up 2 minutes
```

### 2. Check Log Shipper Logs

```bash
# View shipper logs
docker logs log-shipper

# Look for these SUCCESS indicators:
# [INFO] SIEMBox Managed Log Shipper Starting
# [INFO] Successfully registered with SIEMBox
# [INFO] Applying configuration (SIEM: <host>:<port>)
# [INFO] Found N source(s)
# [INFO] Tailing file: /path/to/file (tag: sometag)
# [DEBUG] Tail PID: 123 - Tracked successfully
# [DEBUG] Reader PID: 124 - Tracked successfully
```

**❌ ERROR Indicators:**
```bash
# If you see these, something is wrong:
[ERROR] Failed to register (HTTP 404)  # Invalid API key
[ERROR] Failed to fetch config         # Network issue
[WARN] No sources configured           # Configuration problem
[WARN] File not found: /path           # Volume mount issue
```

### 3. Check That Tail Processes Are Running

```bash
# Enter the shipper container
docker exec -it log-shipper sh

# Check for tail processes
ps aux | grep tail

# You should see entries like:
# 123 root  tail -F /var/log/syslog
# 125 root  tail -F /var/log/auth.log
# (count should match number of file sources × 2)

# Check for docker log processes (if using docker sources)
ps aux | grep "docker logs"

# Exit container
exit
```

**Expected Process Count:**
- **File sources:** 2 processes per file (tail + reader)
- **Docker sources:** 2 processes per container (docker logs + reader)
- **Total:** sources × 2

### 4. Verify Network Connectivity to SIEM

```bash
# Test syslog port is reachable from shipper container
docker exec log-shipper nc -zv <SIEM_HOST> 514

# Success looks like:
# Connection to 192.168.1.76 514 port [tcp/syslog] succeeded!

# If it fails:
# nc: connect to 192.168.1.76 port 514 (tcp) failed: Connection refused
```

### 5. Monitor Syslog Traffic (BEST VERIFICATION)

**Method A: Using tcpdump on Docker Host**

```bash
# Capture syslog traffic (UDP port 514)
sudo tcpdump -i any port 514 -A -n

# You should see output like:
# <134>Dec 03 10:23:45 shipper-hostname mytag: This is a log message
# <134>Dec 03 10:23:46 shipper-hostname mytag: Another log message

# Press Ctrl+C to stop
```

**Method B: Inside Backend Container**

```bash
# Monitor syslog traffic inside backend container
docker exec -it siembox-backend sh

# Install tcpdump if needed
apk add --no-cache tcpdump

# Capture on port 514
tcpdump -i any port 514 -A -n

# Exit when done
exit
```

### 6. Check SIEM Backend Syslog Server

```bash
# Check backend container logs for syslog server
docker logs siembox-backend | grep -i syslog

# Look for:
# [INFO] Syslog server listening on UDP port 514
# [INFO] Syslog server listening on TCP port 514
```

### 7. Verify Logs in PostgreSQL Database

```bash
# Connect to PostgreSQL
docker exec -it siembox-db psql -U siembox -d siembox

# Check recent logs
SELECT id, timestamp, hostname, source_ip, LEFT(raw_message, 80) as message
FROM raw_logs
ORDER BY timestamp DESC
LIMIT 10;

# Count logs by hostname
SELECT hostname, COUNT(*)
FROM raw_logs
GROUP BY hostname
ORDER BY COUNT(*) DESC;

# Check logs from last 5 minutes
SELECT COUNT(*) as recent_logs
FROM raw_logs
WHERE timestamp > NOW() - INTERVAL '5 minutes';

# Check total log count
SELECT COUNT(*) as total_logs FROM raw_logs;

# Exit
\q
```

**✅ Success:** You should see logs with timestamps within the last few minutes

**❌ Problem:** If count is 0 or logs are old, shipper isn't sending or SIEM isn't receiving

**Note:** Logs are stored in the `raw_logs` table, not `logs`. The raw syslog messages are parsed separately into `parsed_logs` if parsers are configured.

### 8. Verify in SIEMBox Web UI

1. Open browser to `http://<your-host>:3000`
2. Login (default: admin / changeme)
3. Navigate to **Logs** page
4. Check:
   - Recent logs appearing in real-time
   - Tags match your shipper configuration
   - Hostnames match your shippers
   - Timestamps are current

### 9. Test with a New Log Entry

**Create a test log entry:**

```bash
# If tailing /var/log/syslog
docker exec log-shipper sh -c 'echo "TEST_LOG_ENTRY_$(date +%s)" >> /var/log/syslog'

# Watch shipper logs
docker logs -f log-shipper

# Should see debug output showing the log being sent

# Check SIEMBox UI or database for the TEST_LOG_ENTRY
```

---

## Troubleshooting Common Issues

### Issue: No Processes Running in Shipper

```bash
docker exec log-shipper ps aux | grep tail
# Returns nothing
```

**Causes:**
- Files don't exist at specified paths
- Volume mounts incorrect
- Configuration has no enabled sources

**Fix:**
```bash
# Check volume mounts
docker inspect log-shipper | grep -A 10 Mounts

# Check configuration
docker exec log-shipper cat /config/config.yml

# Verify files exist
docker exec log-shipper ls -la /var/log/
```

### Issue: Processes Running but No Logs in SIEM

```bash
# Tail processes exist but database is empty
```

**Causes:**
- Network connectivity issue
- Wrong SIEM host/port
- Syslog server not running in backend

**Fix:**
```bash
# Test network connectivity
docker exec log-shipper nc -zv <SIEM_HOST> 514

# Check syslog settings in database
docker exec -it siembox-db psql -U siembox -d siembox -c \
  "SELECT key, value FROM system_settings WHERE key IN ('syslog_host', 'syslog_port');"

# Restart backend to ensure syslog server is running
docker compose restart siembox-backend
```

### Issue: "Connection Refused" to Syslog Port

```bash
nc: connect to 192.168.1.76 port 514 (tcp) failed: Connection refused
```

**Causes:**
- Backend syslog server not listening
- Firewall blocking port 514
- Wrong host address

**Fix:**
```bash
# Check if backend is listening on 514
docker exec siembox-backend netstat -tuln | grep 514

# Check firewall (on Docker host)
sudo iptables -L -n | grep 514

# Verify SIEM host setting
docker exec log-shipper env | grep SIEM
```

### Issue: "Invalid API key" Error

```bash
[ERROR] Failed to register (HTTP 404)
```

**Causes:**
- API key doesn't exist in database
- Typo in SHIPPER_API_KEY environment variable

**Fix:**
```bash
# Check API key in database
docker exec -it siembox-db psql -U siembox -d siembox -c \
  "SELECT id, name, api_key FROM log_shippers;"

# Verify environment variable matches
docker exec log-shipper env | grep SHIPPER_API_KEY

# Update if needed via SIEMBox UI or regenerate key
```

---

## Quick Health Check Script

Save this as `check-shipper-health.sh`:

```bash
#!/bin/bash

echo "=== SIEMBox Log Shipper Health Check ==="
echo ""

echo "1. Container Status:"
docker ps | grep log-shipper || echo "❌ Container not running"
echo ""

echo "2. Recent Shipper Logs:"
docker logs --tail 20 log-shipper | grep -E '\[(INFO|ERROR|WARN)\]'
echo ""

echo "3. Process Count:"
PROCESS_COUNT=$(docker exec log-shipper ps aux | grep -E '(tail|docker logs)' | grep -v grep | wc -l)
echo "   Processes: $PROCESS_COUNT"
echo ""

echo "4. Network Connectivity:"
docker exec log-shipper nc -zv siembox-backend 514 2>&1 | tail -1
echo ""

echo "5. Recent Logs in Database:"
docker exec siembox-db psql -U siembox -d siembox -t -c \
  "SELECT COUNT(*) FROM raw_logs WHERE timestamp > NOW() - INTERVAL '5 minutes';" | xargs echo "   Logs (last 5 min):"
echo ""

echo "=== Health Check Complete ==="
```

Run it:
```bash
chmod +x check-shipper-health.sh
./check-shipper-health.sh
```

---

## Success Indicators Checklist

Use this checklist to verify everything is working:

- [ ] Log shipper container is running
- [ ] Shipper logs show "Successfully registered"
- [ ] Shipper logs show "Tailing file" messages
- [ ] Tail processes visible in `ps aux` (count = sources × 2)
- [ ] Network connectivity test succeeds (nc -zv)
- [ ] tcpdump shows syslog packets being sent
- [ ] Backend syslog server is listening on port 514
- [ ] PostgreSQL database contains recent logs (< 5 min old)
- [ ] SIEMBox web UI shows real-time logs
- [ ] Test log entry appears end-to-end

If all checkboxes are ✅, your log shipper is fully operational!

---

## Getting Help

If you're still having issues:

1. Collect diagnostics:
   ```bash
   docker logs log-shipper > shipper.log
   docker logs siembox-backend > backend.log
   docker exec siembox-db psql -U siembox -d siembox -c \
     "SELECT * FROM raw_logs ORDER BY timestamp DESC LIMIT 50;" > recent-logs.txt
   ```

2. Review documentation:
   - `DEPLOYMENT-VERIFICATION.md` - Deployment guide
   - `INCIDENT-REPORT-PROCESS-MANAGEMENT.md` - Technical details
   - `QUICK-REFERENCE.md` - Common commands

3. Check GitHub issues: https://github.com/cladkins/SIEMBOX/issues
