# Log Shipper Deployment Verification Guide

**Navigation:** [Main README](../README.md) > [Log Shipper](./README.md) > Deployment Verification

**Related Documentation:**
- [Verification Guide](./VERIFICATION-GUIDE.md) - How to verify logs are flowing
- [Quick Reference](./QUICK-REFERENCE.md) - Common commands
- [Technical Details](./INCIDENT-REPORT-PROCESS-MANAGEMENT.md) - Complete technical analysis
- [Log Shipper README](./README.md) - Setup and configuration

---

## Critical Fix Summary

This deployment includes a CRITICAL fix for process management that completely prevented log forwarding. Without this fix, the log shipper is non-functional.

**Commit:** e8537b8 - fix: Resolve critical log shipper process management failure

## Pre-Deployment Checklist

- [ ] Review incident report: `log-shipper/INCIDENT-REPORT-PROCESS-MANAGEMENT.md`
- [ ] Ensure Docker images will be rebuilt with latest code
- [ ] Plan monitoring for log ingestion rates
- [ ] Prepare to verify no orphaned processes

## Deployment Steps

### 1. Build New Log Shipper Image

```bash
# On remote Docker host
cd /path/to/SIEMBox
git pull origin develop

# Rebuild log shipper
docker compose build log-shipper

# Or if using standalone shipper
cd log-shipper
docker build -t siembox-log-shipper .
```

### 2. Stop Existing Shipper

```bash
# Stop current shipper container
docker compose stop log-shipper
# or
docker stop <shipper_container_name>

# Check for orphaned tail processes from old version
docker exec <container_name> ps aux | grep -E "tail|docker logs|journalctl" || echo "Container stopped"

# If orphaned processes exist on host, note PIDs for cleanup
ps aux | grep -E "tail.*siembox|docker logs.*siembox"
```

### 3. Deploy New Shipper

```bash
# Start new shipper
docker compose up -d log-shipper
# or
docker run -d --name log-shipper \
  -e SIEMBOX_API_URL=http://siembox:3001/api \
  -e SHIPPER_API_KEY=your_api_key \
  -v /var/log:/var/log:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  siembox-log-shipper
```

## Post-Deployment Verification

### 1. Check Container Startup

```bash
# View logs
docker logs -f log-shipper

# Look for:
# - "SIEMBox Managed Log Shipper Starting" or "SIEMBox Log Shipper Starting"
# - "Tailing file: ..." messages
# - "Started tail process <PID> for ..." messages (debug mode)
# - "Started reader process <PID> for ..." messages (debug mode)
# - No error messages about named pipes
```

Expected output:
```
[INFO] =========================================
[INFO] SIEMBox Managed Log Shipper Starting
[INFO] =========================================
[INFO] Performing initial registration...
[INFO] Applying configuration (SIEM: 192.168.1.76:514)
[INFO] Found 2 source(s)
[INFO] Tailing file: /var/log/nginx/access.log (tag: nginx-access)
[DEBUG] Started tail process 123 for /var/log/nginx/access.log
[DEBUG] Started reader process 124 for /var/log/nginx/access.log
[INFO] Log shipper running. Polling for configuration updates...
```

### 2. Verify Process Management

```bash
# Enter container
docker exec -it log-shipper sh

# Check tail processes are running
ps aux | grep tail
# Should show active tail processes with valid PIDs

# Example:
# 123 root      0:00 tail -F /var/log/nginx/access.log
# 125 root      0:00 tail -F /var/log/app.log

# Exit container
exit
```

### 3. Verify Log Forwarding

#### Option A: Using tcpdump on SIEM host

```bash
# On SIEMBox host
tcpdump -i any port 514 -A -n

# Generate test log
echo "Test log entry" >> /var/log/test.log

# You should see syslog messages:
# <134>Dec  3 10:52:00 hostname nginx-access: Test log entry
```

#### Option B: Check SIEMBox UI

1. Login to SIEMBox UI: http://your-siem:3000
2. Navigate to Logs page
3. Look for recent logs from shipper sources
4. Verify timestamps are current
5. Check log ingestion rate is non-zero

#### Option C: Query SIEMBox API

```bash
# Get recent logs
curl -s http://your-siem:3001/api/logs?limit=10 \
  -H "Authorization: Bearer your_token" | jq

# Check shipper status
curl -s http://your-siem:3001/api/shippers \
  -H "Authorization: Bearer your_token" | jq
```

### 4. Test Graceful Shutdown

```bash
# Send SIGTERM to container
docker kill --signal=SIGTERM log-shipper

# Watch logs for clean shutdown
docker logs log-shipper | tail -20

# Expected:
# [INFO] Shutting down log shipper...
# [INFO] Stopping all tailing processes (4 processes)...
# [DEBUG] Killing process 123
# [DEBUG] Killing process 124
# ...
# [DEBUG] All tailing processes stopped

# Check for orphaned processes
docker exec log-shipper ps aux | grep -E "tail|docker logs|journalctl" || echo "No processes found (expected)"
```

### 5. Test Config Changes (Managed Mode Only)

```bash
# In SIEMBox UI:
# 1. Go to Log Shippers page
# 2. Select your shipper
# 3. Add or modify a log source
# 4. Save configuration

# Watch shipper logs
docker logs -f log-shipper

# Expected output within CONFIG_POLL_INTERVAL (default 30s):
# [INFO] Configuration changed, applying new configuration...
# [INFO] Stopping all tailing processes (4 processes)...
# [DEBUG] All tailing processes stopped
# [INFO] Applying configuration (SIEM: 192.168.1.76:514)
# [INFO] Found 3 source(s)
# [INFO] Tailing file: /new/log/file.log (tag: new-source)
# [DEBUG] Started tail process 456 for /new/log/file.log
```

### 6. Monitor for Issues

#### Check for Orphaned Processes

```bash
# Inside container
docker exec log-shipper sh -c 'ps aux | grep -E "tail|docker logs|journalctl" | wc -l'

# Should match number of configured sources × 2 (tail + reader processes)
# Example: 2 sources = 4 processes (2 tail, 2 reader)
```

#### Check Named Pipe Cleanup

```bash
# Inside container
docker exec log-shipper sh -c 'ls -la /tmp/shipper-*pipe* 2>/dev/null || echo "No stray pipes (expected)"'

# Should see no stray pipes after startup completes
```

#### Monitor Log Ingestion Rate

```bash
# Query SIEMBox for log rate
curl -s http://your-siem:3001/api/logs/stats \
  -H "Authorization: Bearer your_token" | jq '.logs_per_minute'

# Should be non-zero if logs are being generated
```

## Troubleshooting

### Issue: No logs appearing in SIEMBox

**Check:**
1. Shipper container is running: `docker ps | grep shipper`
2. Tail processes are active: `docker exec log-shipper ps aux | grep tail`
3. Network connectivity: `docker exec log-shipper nc -zv your-siem 514`
4. Log files exist: `docker exec log-shipper ls -la /var/log/your-log.log`
5. SIEM syslog server is listening: `netstat -tuln | grep 514`

**Enable debug logging:**
```bash
# Restart with debug output
docker restart log-shipper

# Watch detailed logs
docker logs -f log-shipper

# Look for:
# - "Started tail process <PID>" messages
# - "Started reader process <PID>" messages
# - Any error messages
```

### Issue: Orphaned processes

**Check:**
```bash
# Inside container
docker exec log-shipper ps aux

# Look for multiple tail processes for same file
# Or processes with stale PIDs
```

**Fix:**
```bash
# Restart container (should not happen with fix)
docker restart log-shipper

# If persistent, rebuild image
docker compose build log-shipper
docker compose up -d log-shipper
```

### Issue: Config changes not applied (Managed mode)

**Check:**
1. API connectivity: `docker exec log-shipper curl -s $SIEMBOX_API_URL/health`
2. API key valid: Check shipper logs for 401/403 errors
3. Poll interval: Wait for CONFIG_POLL_INTERVAL seconds (default 30s)
4. Config actually changed: Check timestamp in SIEMBox UI

### Issue: High CPU usage

**Check:**
```bash
# Check number of processes
docker exec log-shipper ps aux | grep -E "tail|docker logs" | wc -l

# Should be: (number of sources) × 2
```

**If excessive processes:**
This indicates the old bug is still present or config loop. Should NOT occur with fix.

## Success Criteria

- [ ] Log shipper container starts without errors
- [ ] Tail processes running with correct PIDs tracked
- [ ] Logs appearing in SIEMBox UI with current timestamps
- [ ] Log ingestion rate is non-zero
- [ ] Graceful shutdown terminates all processes cleanly
- [ ] No orphaned tail processes
- [ ] Config changes apply correctly (managed mode)
- [ ] No stray named pipes accumulating in /tmp

## Rollback Plan

If critical issues occur:

```bash
# Stop current version
docker compose stop log-shipper

# Revert to previous commit
git checkout <previous_commit>

# Rebuild and deploy
docker compose build log-shipper
docker compose up -d log-shipper
```

**Note:** Previous versions are also broken (non-functional). If rollback needed, temporarily disable log shipper and use alternative log ingestion method (direct syslog, manual API calls, etc.) until fix can be debugged.

## Monitoring Recommendations

### Set up alerts for:

1. **Log ingestion rate drops to zero**
   - Query: `SELECT COUNT(*) FROM logs WHERE timestamp > NOW() - INTERVAL 5 MINUTE`
   - Alert if count = 0

2. **Shipper heartbeat missed**
   - Check shipper last_seen timestamp
   - Alert if > HEARTBEAT_INTERVAL + grace period

3. **High process count in container**
   - Query: `docker exec log-shipper ps aux | wc -l`
   - Alert if > (sources × 2) + base processes

4. **Container restart loop**
   - Monitor Docker events
   - Alert on repeated restarts

## Additional Resources

- Incident Report: `/log-shipper/INCIDENT-REPORT-PROCESS-MANAGEMENT.md`
- Test Script: `/log-shipper/test-process-management.sh`
- Log Shipper Documentation: `/log-shipper/README.md`
- Troubleshooting Guide: `/TROUBLESHOOTING.md`

## Contact

If issues persist after following this guide:
- Review incident report for technical details
- Check GitHub issues: https://github.com/cladkins/SIEMBOX/issues
- Run test script locally: `./log-shipper/test-process-management.sh`
