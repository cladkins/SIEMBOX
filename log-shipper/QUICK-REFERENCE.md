# Log Shipper Process Management - Quick Reference

**Navigation:** [Main README](../README.md) > [Log Shipper](./README.md) > Quick Reference

**Related Documentation:**
- [Verification Guide](./VERIFICATION-GUIDE.md) - How to verify logs are flowing
- [Deployment Verification](./DEPLOYMENT-VERIFICATION.md) - Full deployment guide
- [Technical Details](./INCIDENT-REPORT-PROCESS-MANAGEMENT.md) - Complete technical analysis

---

## What Was Fixed

### The Bug
```bash
# BROKEN (Old Code)
tail -F "$file" | while read line; do
    send_log "$line"
done &
PID=$!  # Wrong! Captures subshell PID, not tail PID
```

**Problem:** Pipeline creates subshell. `$!` captures subshell PID. Subshell exits immediately. Tail process becomes orphaned. No process tracking. Can't kill processes. Logs never forwarded.

### The Fix
```bash
# FIXED (New Code)
pipe="/tmp/shipper-pipe-$$-$RANDOM"
mkfifo "$pipe"

tail -F "$file" > "$pipe" 2>/dev/null &
tail_pid=$!  # Correct! Captures tail PID
TAILING_PIDS+=($tail_pid)

(while read line; do send_log "$line"; done < "$pipe") &
reader_pid=$!  # Capture reader PID
TAILING_PIDS+=($reader_pid)

(sleep 1; rm -f "$pipe") &
```

**Solution:** Named pipes (FIFOs) separate tail from reader. Background processes directly. Capture correct PIDs. Track in array. Clean shutdown possible.

## Quick Verification Commands

### Check Processes Running
```bash
docker exec log-shipper ps aux | grep tail
```
Expected: One tail process per log source

### Check Logs Forwarding
```bash
# On SIEM host
tcpdump -i any port 514 -A | head -20
```
Expected: See syslog messages

### Check SIEMBox UI
```bash
# Navigate to http://your-siem:3000/logs
# Look for recent logs from shipper
```

### Test Graceful Shutdown
```bash
docker kill --signal=SIGTERM log-shipper
docker exec log-shipper ps aux | grep tail
```
Expected: No tail processes after shutdown

## Key Files Modified

- `log-shipper/shipper-managed.sh` - Managed shipper (API-driven)
- `log-shipper/shipper.sh` - Standalone shipper (config file)
- `log-shipper/test-process-management.sh` - Verification tests
- `log-shipper/INCIDENT-REPORT-PROCESS-MANAGEMENT.md` - Full details

## Testing

```bash
# Run verification tests
cd /Users/chrisadkins/Projects/SIEMBox/log-shipper
./test-process-management.sh
```

Expected: All tests PASS

## Common Issues & Solutions

### No Logs in SIEMBox
- Check: `docker logs log-shipper`
- Look for: "Tailing file: ..." messages
- Verify: `docker exec log-shipper ps aux | grep tail`

### Orphaned Processes
- Should NOT happen with fix
- If seen: `docker restart log-shipper`
- Report as bug if persists

### High CPU
- Check process count: `docker exec log-shipper ps aux | wc -l`
- Should be: base + (sources × 2)
- If excessive: Indicates config loop bug

## Success Criteria

- [x] Tail processes have valid PIDs
- [x] TAILING_PIDS array accurate
- [x] Logs forwarded to SIEMBox
- [x] Graceful shutdown works
- [x] No orphaned processes
- [x] Config changes applied (managed mode)

## Emergency Rollback

```bash
docker compose stop log-shipper
git revert HEAD
docker compose build log-shipper
docker compose up -d log-shipper
```

**Note:** Previous versions also broken. Consider alternative log ingestion if rollback needed.

## Links

- Full Incident Report: `INCIDENT-REPORT-PROCESS-MANAGEMENT.md`
- Deployment Guide: `DEPLOYMENT-VERIFICATION.md`
- Test Script: `test-process-management.sh`
