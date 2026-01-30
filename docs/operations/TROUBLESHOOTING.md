# SIEMBox Troubleshooting Guide

Comprehensive troubleshooting guide for diagnosing and resolving common issues in SIEMBox.

## Table of Contents

- [Quick Diagnostics](#quick-diagnostics)
- [Deployment Issues](#deployment-issues)
- [Syslog & Log Ingestion](#syslog--log-ingestion)
- [Log Shipper Issues](#log-shipper-issues)
- [Parser Problems](#parser-problems)
- [Detection Rules](#detection-rules)
- [Database Issues](#database-issues)
- [Authentication Problems](#authentication-problems)
- [Performance Issues](#performance-issues)
- [Network & Connectivity](#network--connectivity)
- [Frontend Issues](#frontend-issues)
- [Container Issues](#container-issues)
- [Data Cleanup](#data-cleanup)
- [Advanced Diagnostics](#advanced-diagnostics)

---

## Quick Diagnostics

### Health Check Steps

Run these steps to identify which component is failing:

1. **Check container status** - Verify all containers are running (use your deployment platform)
2. **Review container logs** - Check logs for PostgreSQL, backend API, and frontend
3. **Test API health** - Try accessing: `http://your-siembox-ip:3001/api/health`
4. **Verify port access** - Ensure ports 3000, 3001, 514 are accessible from expected networks
5. **Check database connection** - Try connecting to PostgreSQL if accessible
6. **Verify syslog reception** - Send test syslog message and check for receipt

**For Docker deployments specifically:**
```bash
# Check container status
docker ps | grep siembox

# View logs
docker logs siembox-backend
docker logs siembox-postgres
docker logs siembox-frontend

# Test API endpoint
curl http://localhost:3001/api/health
```

### Common Error Patterns

| Error Message | Likely Cause | Quick Fix |
|---------------|--------------|-----------|
| `ECONNREFUSED` | Service not running | `docker-compose restart <service>` |
| `Error: connect ECONNREFUSED 127.0.0.1:5432` | Backend can't reach database | Check postgres health |
| `401 Unauthorized` | Invalid/expired token | Login again |
| `Port 514: Permission denied` | Insufficient privileges | Run backend as root or use authbind |
| `FATAL: password authentication failed` | Wrong database password | Check .env DB_PASSWORD |
| `Module not found` | Missing dependencies | `docker-compose build --no-cache` |

---

## Deployment Issues

### Issue: Container Won't Start

**Symptoms:**
- Containers are in a failed state
- Service is unreachable or repeatedly restarting
- Logs show startup errors

**Common Causes and Solutions:**

**Port Already in Use**
- Check what's using ports 3000, 3001, or 514 on your system
- Either stop the conflicting service or change SIEMBox ports
- Verify port mappings in your deployment configuration

**Missing or Invalid Environment Variables**
- Verify `.env` file exists and is readable
- Check that all required variables are set:
  - `DB_PASSWORD` - Database password
  - `JWT_SECRET` - JWT signing key
  - `DEFAULT_ADMIN_PASSWORD` - Admin credentials
- Use `.env.example` as a template
- Invalid values (e.g., empty passwords) will cause startup failures

**Database Connection Issues**
- Ensure PostgreSQL container/service is healthy and responding
- Verify database name, user, and password in `.env` match your configuration
- Check network connectivity between backend and database
- For remote databases, verify firewall rules allow access on port 5432

**Insufficient System Resources**
- Check available disk space (logs grow quickly)
- Verify sufficient RAM (minimum 2GB recommended)
- Check system CPU isn't overloaded

**Permission Errors**
- Ensure the deployment user has proper permissions for volumes/directories
- Verify Docker/container engine has permission to access mounted paths
- Check file permissions on log directories

---

### Issue: Database Initialization Failures

**Symptoms:**
- Backend logs show migration or initialization errors
- Tables don't exist in database
- "Relation does not exist" errors in API responses
- Parsers or rules not loading

**Common Causes:**

1. **PostgreSQL not ready** - Database hasn't finished initializing
   - Solution: Wait 15-20 seconds and check if backend recovers

2. **Database connection issues** - Backend can't connect to database
   - Verify database is running and accessible
   - Check DB_HOST, DB_USER, DB_PASSWORD in .env
   - Verify network connectivity between containers/services

3. **Corrupted database state** - Previous failed migration left database in bad state
   - Solution: Back up data, then reset database and re-run migrations
   - Check database logs for corruption indicators

4. **Insufficient permissions** - Database user lacks required permissions
   - Verify database user has CREATE TABLE, INSERT, UPDATE permissions
   - May need to run migrations as database superuser

**How Initialization Works:**

On first start, the backend automatically:
1. Checks if database is ready
2. Runs all pending migrations (in order)
3. Imports seed data (parsers, rules)
4. Creates indexes and constraints

This should complete in 30-60 seconds. If not:
- Check backend container logs for specific error message
- Verify database container is healthy
- Ensure sufficient disk space
cd src/scripts
node migrate.js
```

**Database Not Ready:**
**Recovery Steps:**

1. Verify PostgreSQL is running and healthy
2. Wait 15-30 seconds for initialization
3. Check backend logs for initialization progress
4. If migrations are stuck, restart the backend service
5. As a last resort, reset database and re-run all migrations

**Important:** Database reset should only be done if:
- This is a test/development environment
- You have backed up all important data
- You understand the data will be permanently deleted

---

## Syslog & Log Ingestion

### Issue: No Logs Appearing in SIEMBox

**Diagnosis Checklist:**

1. **Verify syslog server is running** - Check backend logs for syslog initialization message
2. **Test network connectivity** - Verify you can reach port 514 from log source
3. **Send test log** - Manually send test syslog and check if received
4. **Check UI and database** - Verify log appears in SIEMBox

**Diagnostic Tests:**

**Test 1: Verify Backend Connectivity**
```bash
curl http://your-siembox-ip:3001/api/health
# Should return: {"status": "ok"}
```

**Test 2: Send Manual Syslog**
From any machine on your network:
```bash
# Method 1: Using logger (if available)
logger -n your-siembox-ip -P 514 "Test message"

# Method 2: Using netcat
echo "<134>$(date '+%b %d %H:%M:%S') testhost test: Test message" | nc -u your-siembox-ip 514
```

**Test 3: Check for Received Logs**
In SIEMBox UI:
- Go to Logs page
- Look for log with your test message
- If not visible, check filters/time range

**Common Causes and Solutions:**

**Firewall Blocking Port 514**
- Verify port 514 is open for UDP and TCP traffic
- Check firewall rules on both source and destination
- Test from local network first, then external

# Allow syslog from specific network
sudo ufw allow from 192.168.1.0/24 to any port 514

# Or allow all (less secure)
sudo ufw allow 514/udp
sudo ufw allow 514/tcp
```

**Backend Not Binding to Port 514:**
```bash
# Port 514 requires elevated privileges
# Check if backend is running as root in container

# View docker-compose settings
docker-compose config | grep -A5 backend

# Ensure backend has CAP_NET_BIND_SERVICE
# Add to docker-compose.yml if missing:
services:
  backend:
    cap_add:
      - NET_BIND_SERVICE
```

**Syslog Format Issues:**
```bash
# Backend expects RFC 3164 or RFC 5424 format
# Test with valid syslog message
echo "<14>Nov 30 12:00:00 server1 test[1234]: Test message" | nc -u <siembox-ip> 514

# Check backend logs for parsing errors
docker-compose logs backend | grep -i "error\|invalid"
```

---

### Issue: Logs Received But Not Parsed

**Symptoms:**
- Raw logs visible in SIEMBox UI
- No parsed fields extracted
- Parsed logs table is empty

**Root Cause:** No parser matches your log format

**Diagnosis:**

1. View a sample raw log in SIEMBox UI to see the format
2. Check Parsers page to see available parsers
3. Verify parser is enabled and has correct pattern
4. Test parser pattern against sample log

**Solutions:**

**Create New Parser:**

1. Go to Parsers page in SIEMBox UI
2. Click "Add Parser"
3. Choose parser type (regex/grok/JSON)
4. Enter pattern that matches your log format
5. Map extracted fields to field names
6. Test with sample log
7. Set appropriate priority (lower = matches first)
8. Save and enable

See [PARSERS.md](../../PARSERS.md) for detailed parser creation guide.

**Enable Existing Parser:**

1. Go to Parsers page
2. Find parser for your log type
3. Check "Enabled" checkbox
4. Save
5. New logs will be parsed on next ingestion

**Adjust Parser Priority:**

1. Go to Parsers page
2. Look at "Priority" column (lower number = higher priority)
3. If multiple parsers match, first one (lowest priority) wins
4. Adjust priorities to ensure correct parser matches
5. Save changes

---

## Log Shipper Issues

### Issue: Shipper Shows as "Offline" or "Unknown Source"

**Symptoms:**
- Shipper appears offline in SIEMBox UI
- Shipper shows as "Unknown Source" (ghost shipper)
- No logs being received from shipper

**Common Causes:**

1. **Invalid API Key** - Shipper API key is incorrect or expired
2. **Network Connectivity** - Shipper can't reach SIEMBox API
3. **Backend Down** - SIEMBox API is not responding
4. **Shipper Misconfiguration** - Log sources not configured

**Solutions:**

**Check Shipper Configuration:**
1. In SIEMBox UI, go to Shippers page
2. Find the offline shipper
3. Verify API key hasn't expired or been deleted
4. Verify log sources are configured and enabled
5. Note the Shipper ID (8-character hash)

**Verify Network Connectivity:**
1. From the shipper host, test:
   ```bash
   curl http://your-siembox-ip:3001/api/health
   ```
2. Should return `{"status": "ok"}`
3. If not reachable:
   - Check SIEMBox is running
   - Verify firewall allows port 3001
   - Check routing between networks

**Update Shipper API Key:**
1. In SIEMBox UI, generate new API key for shipper
2. Update shipper's SHIPPER_API_KEY environment variable
3. Restart shipper container
4. Wait 30-60 seconds for re-registration
5. Shipper should no longer show as offline

**Investigate Ghost Shipper:**

If shipper shows as "Unknown Source":
- Shipper is sending logs with invalid API key
- Logs continue due to cached configuration
- This is normal during API key rotation
- Once shipper is updated and restarted, it will re-register with correct key

See [SHIPPER-DIAGNOSTICS.md](./SHIPPER-DIAGNOSTICS.md) for detailed shipper troubleshooting.

# Check DNS resolution
docker exec siembox-log-shipper nslookup <siembox-hostname>

# Test syslog connectivity
docker exec siembox-log-shipper nc -zv <siembox-ip> 514
```

**Heartbeat Not Working:**
```bash
# Shipper sends heartbeat every 60 seconds
# Wait 2-3 minutes and check last_seen

# Check shipper script is running
docker exec siembox-log-shipper ps aux | grep shipper

# Check for errors in logs
docker logs siembox-log-shipper | grep -i error
```

---

### Issue: Logs Not Being Forwarded

**Symptoms:**
- Shipper shows online
- No logs appearing in SIEMBox
- Shipper logs show "File not found" warnings

**Diagnosis:**
```bash
# Check shipper logs for file access errors
docker logs siembox-log-shipper | grep -E "File not found|Permission denied"

# List shipper configuration
curl http://localhost:3001/api/shippers/<shipper-id> \
  -H "Authorization: Bearer $TOKEN" | jq '.sources, .volumes'

# Check if files exist on HOST
ls -la /var/log/nginx/access.log  # Example path
```

**Solutions:**

**Volume Not Mounted:**
```bash
# Problem: Shipper can't access log files because volume not mounted
# Check shipper's docker-compose.yml

# Add volume mount:
volumes:
  - /var/log/nginx:/var/log/nginx:ro  # HOST:CONTAINER:MODE

# Restart shipper
docker-compose down
docker-compose up -d

# Verify mount
docker inspect siembox-log-shipper | jq '.[0].Mounts'
```

**File Path Mismatch:**
```bash
# Source path in UI must match CONTAINER path, not HOST path

# Example:
# HOST path: /var/log/nginx/access.log
# Volume mount: /var/log/nginx:/logs:ro
# Source path in UI: /logs/access.log  (NOT /var/log/nginx/access.log)

# Update source path in UI or API:
curl -X PUT http://localhost:3001/api/shippers/sources/<source-id> \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"file_path": "/logs/access.log"}'
```

**Permission Denied:**
```bash
# Check file permissions on HOST
ls -la /var/log/nginx/access.log

# If not readable, add shipper user to group
# Or make file readable
sudo chmod +r /var/log/nginx/access.log
```

**Source Disabled:**
```bash
# Check if source is enabled
curl http://localhost:3001/api/shippers/<shipper-id>/sources \
  -H "Authorization: Bearer $TOKEN" | jq '.[] | {id, enabled, tag}'

# Enable source
curl -X PUT http://localhost:3001/api/shippers/sources/<source-id> \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"enabled": true}'
```

---

## Parser Problems

### Issue: "Invalid regular expression: Invalid group" Error

**Symptoms:**
- Backend logs show repeated errors: `Regex parser <name> error: Invalid regular expression: Invalid group`
- Parser appears in database but fails at runtime
- Error mentions `(?P` in the pattern

**Root Cause:**
Parser contains Python-style regex syntax `(?P<name>...)` instead of JavaScript syntax `(?<name>...)`. JavaScript's RegExp doesn't support Python's named group syntax.

**Example Error:**
```
Regex parser vaultwarden-access error: Invalid regular expression: /^\[(?P\d{4}-\d{2}-\d{2}...: Invalid group
```

**Diagnosis:**
```bash
# Check for Python-style regex in database
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT id, name, substring(pattern, 1, 100) as pattern_preview
   FROM parsers
   WHERE pattern LIKE '%(?P<%'
   ORDER BY priority;"

# Run comprehensive validation
npx ts-node backend/scripts/validate-parsers.ts
```

**Solution:**

**Option 1: SQL Fix Script (Recommended for existing databases)**
```bash
# Fix vaultwarden parser specifically
docker exec -i siembox-postgres psql -U siembox -d siembox < backend/scripts/fix_vaultwarden_parser.sql

# Or connect interactively
docker exec -it siembox-postgres psql -U siembox -d siembox

# Then update the parser
UPDATE parsers
SET pattern = '<corrected-javascript-pattern>',
    updated_at = NOW()
WHERE name = 'vaultwarden-access';
```

**Option 2: Fix Migration (For fresh deployments)**
If you haven't deployed yet, fix the migration file:
- Edit `backend/migrations/005_add_vaultwarden_parser.sql`
- Replace all `(?P<name>` with `(?<name>`
- Ensure pattern uses negative lookahead instead of non-greedy quantifiers for complex extractions

**Option 3: Validation & Batch Fix**
```bash
# Validate all parsers and get detailed report
cd backend
npx ts-node scripts/validate-parsers.ts

# View SQL validation report
docker exec -i siembox-postgres psql -U siembox -d siembox \
  < scripts/validate_all_parsers_and_rules.sql
```

**Prevention:**
- Always use JavaScript regex syntax: `(?<name>...)` not `(?P<name>...)`
- Test regex patterns at https://regex101.com with flavor "ECMAScript (JavaScript)"
- Run `npx ts-node backend/scripts/validate-parsers.ts` before deployment
- Include parser validation in your CI/CD pipeline

**Related Files:**
- `backend/scripts/fix_vaultwarden_parser.sql` - Fix script for vaultwarden parser
- `backend/scripts/validate-parsers.ts` - Comprehensive parser validation
- `backend/scripts/validate_all_parsers_and_rules.sql` - SQL-based validation report
- `backend/scripts/README.md` - Documentation for all validation scripts

---

### Issue: Parser Not Matching Logs

**Diagnosis:**
```bash
# Test parser with sample log
curl -X POST http://localhost:3001/api/parsers/<parser-id>/test \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"sample": "your actual log message here"}'

# Check response:
# {"matched": true, "fields": {...}}  = Success
# {"matched": false, "fields": null}  = No match
```

**Common Issues:**

**Regex Syntax Error:**
```bash
# Test regex pattern separately
# Use https://regex101.com with flavor "ECMAScript (JavaScript)"

# Common mistakes:
# ❌ Single backslash: \d+
# ✅ Double backslash: \\d+

# ❌ Named groups with brackets: (?<name>[A-Z]+)
# ✅ Escaped backslashes: (?<name>[A-Z]+)
```

**Field Mapping Wrong:**
```json
// For regex parsers, map capture group NUMBER to field name
{
  "1": "timestamp",
  "2": "hostname",
  "3": "message"
}

// NOT:
{
  "timestamp": "timestamp"  // ❌ Wrong
}
```

**Grok Pattern Issues:**
```bash
# SIEMBox uses node-grok library
# Built-in patterns: https://github.com/Beh01der/node-grok/tree/master/patterns

# Example grok pattern:
%{TIMESTAMP_ISO8601:timestamp} %{LOGLEVEL:level} %{GREEDYDATA:message}

# Field mappings for grok:
{
  "timestamp": "timestamp",
  "level": "level",
  "message": "message"
}
```

---

### Issue: Parser Matches Wrong Logs

**Symptoms:**
- Parser designed for SSH logs matches Apache logs
- Multiple parsers matching same log

**Diagnosis:**
```bash
# Check parser priorities
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT id, name, priority, enabled FROM parsers ORDER BY priority;"

# View which parser matched a log
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT pl.id, pl.parser_id, p.name, pl.parsed_data
   FROM parsed_logs pl
   JOIN parsers p ON pl.parser_id = p.id
   ORDER BY pl.timestamp DESC LIMIT 10;"
```

**Solution:**
```bash
# Make parser pattern more specific
# Add additional constraints to regex

# Before (too generic):
# (?<timestamp>\\w+\\s+\\d+\\s+\\d+:\\d+:\\d+)\\s+(?<message>.+)

# After (specific to SSH):
# (?<timestamp>\\w+\\s+\\d+\\s+\\d+:\\d+:\\d+)\\s+(?<hostname>\\S+)\\s+sshd\\[(?<pid>\\d+)\\]:

# Update parser priority (lower = higher precedence)
# Specific parsers: 1-50
# Application-specific: 51-100
# Generic parsers: 100-500
# Fallback parser: 1000
```

---

## Detection Rules

### Issue: Rule Not Triggering Alerts

**Diagnosis:**
```bash
# Check if rule is enabled
curl http://localhost:3001/api/rules \
  -H "Authorization: Bearer $TOKEN" | jq '.[] | {id, name, enabled}'

# Check parsed logs match rule conditions
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT parsed_data FROM parsed_logs
   WHERE parsed_data->>'event' = 'Failed password'
   ORDER BY timestamp DESC LIMIT 5;"

# Check backend logs for rule evaluation
docker-compose logs backend | grep -i "rule\|alert"
```

**Common Issues:**

**Field Name Mismatch:**
```yaml
# Rule looks for 'source_ip' but parser extracts 'src_ip'
conditions:
  - field: source_ip  # ❌ Field doesn't exist in parsed data
    operator: equals
    value: "192.168.1.100"

# Fix: Use correct field name from parser
conditions:
  - field: src_ip  # ✅ Matches parser output
    operator: equals
    value: "192.168.1.100"
```

**Threshold Not Met:**
```yaml
# Rule requires 5 events but only 3 occurred
aggregation:
  field: source_ip
  timeframe: 5m
  threshold: 5  # Needs 5 events

# Solution: Lower threshold or extend timeframe
aggregation:
  field: source_ip
  timeframe: 10m  # Longer window
  threshold: 3    # Lower threshold
```

**Condition Operator:**
```yaml
# Using wrong operator
conditions:
  - field: status_code
    operator: equals  # ❌ Expects exact string match
    value: "404"

# For numeric comparisons:
conditions:
  - field: status_code
    operator: equals  # ✅ Works if status_code is string "404"
    value: "404"
```

---

### Issue: Too Many False Positive Alerts

**Solution:**
```yaml
# Add more specific conditions
conditions:
  - field: event
    operator: equals
    value: "Failed password"
  - field: user
    operator: not_contains  # ✅ Exclude test accounts
    value: "test"

# Increase threshold
aggregation:
  threshold: 10  # Up from 5

# Extend timeframe
aggregation:
  timeframe: 10m  # Up from 5m

# Add exclusion conditions
conditions:
  - field: source_ip
    operator: not_contains
    value: "10.0.0"  # Exclude internal network
```

---

## Database Issues

### Issue: "Too Many Connections" Error

**Symptoms:**
```
FATAL: sorry, too many clients already
Error: connect ETIMEDOUT
```

**Diagnosis:**
```bash
# Check current connections
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT COUNT(*) as connection_count FROM pg_stat_activity;"

# Check max connections setting
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SHOW max_connections;"

# View active connections
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT pid, usename, application_name, client_addr, state
   FROM pg_stat_activity WHERE state != 'idle';"
```

**Solutions:**

**Increase Max Connections:**
```bash
# Edit docker-compose.yml
services:
  postgres:
    command:
      - "postgres"
      - "-c"
      - "max_connections=200"  # Increased from 100

# Restart
docker-compose restart postgres
```

**Fix Connection Leaks:**
```bash
# Kill idle connections
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT pg_terminate_backend(pid)
   FROM pg_stat_activity
   WHERE state = 'idle' AND state_change < NOW() - INTERVAL '10 minutes';"

# Restart backend to reset connection pool
docker-compose restart backend
```

---

### Issue: Database Disk Space Full

**Symptoms:**
```
ERROR: could not extend file: No space left on device
database disk quota exceeded
```

**Diagnosis:**
```bash
# Check disk usage
df -h /var/lib/docker/volumes/

# Check database size
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT pg_size_pretty(pg_database_size('siembox'));"

# Check table sizes
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
   FROM pg_tables
   WHERE schemaname = 'public'
   ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;"
```

**Solutions:**

**Emergency Cleanup:**
```bash
# Delete old logs manually
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "DELETE FROM raw_logs WHERE timestamp < NOW() - INTERVAL '7 days';"

docker exec siembox-postgres psql -U siembox -d siembox -c \
  "DELETE FROM parsed_logs WHERE timestamp < NOW() - INTERVAL '7 days';"

# Vacuum to reclaim space
docker exec siembox-postgres psql -U siembox -d siembox -c "VACUUM FULL;"
```

**Configure Retention:**
```bash
# Set retention policies via API
curl -X PUT http://localhost:3001/api/settings/retention \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "raw_logs_days": 14,
    "parsed_logs_days": 30,
    "alerts_days": 90,
    "auto_cleanup_enabled": true
  }'

# Trigger manual cleanup
curl -X POST http://localhost:3001/api/settings/retention/cleanup \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "raw_logs_days": 7,
    "parsed_logs_days": 14,
    "alerts_days": 30
  }'
```

---

## Authentication Problems

### Issue: Unable to Login

**Symptoms:**
- "Invalid username or password" error
- Login form doesn't respond

**Diagnosis:**
```bash
# Check if backend is running
docker-compose ps backend

# Check backend logs for auth errors
docker-compose logs backend | grep -i "auth\|login"

# Verify user exists
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT id, username, email, enabled FROM users;"
```

**Solutions:**

**Wrong Password:**
```bash
# Reset admin password (requires database access)
docker exec siembox-postgres psql -U siembox -d siembox

# Generate new password hash (use bcrypt online tool or Node.js)
# Then update:
UPDATE users SET password_hash = '$2b$10$NEW_HASH_HERE' WHERE username = 'admin';
```

**Account Disabled:**
```bash
# Enable account
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "UPDATE users SET enabled = true WHERE username = 'admin';"
```

**CORS Error:**
```bash
# Check browser console for CORS errors
# Update backend .env:
CORS_ORIGIN=http://your-frontend-domain.com

# Restart backend
docker-compose restart backend
```

---

### Issue: Session Expired Immediately

**Symptoms:**
- Login successful but redirected back to login
- Token expires within seconds

**Diagnosis:**
```bash
# Check system time synchronization
docker exec siembox-backend date
docker exec siembox-postgres date
date  # Host system time

# Check session expiration
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT user_id, created_at, expires_at, NOW()
   FROM sessions ORDER BY created_at DESC LIMIT 5;"
```

**Solution:**
```bash
# Synchronize system clocks
sudo ntpdate -s time.nist.gov

# Or install NTP daemon
sudo apt install ntp
sudo systemctl enable ntp
sudo systemctl start ntp
```

---

## Performance Issues

### Issue: Slow Query Response

**Diagnosis:**
```bash
# Check database load
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT pid, query, state, query_start
   FROM pg_stat_activity
   WHERE state != 'idle'
   ORDER BY query_start;"

# Check slow queries (if enabled)
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT query, mean_exec_time, calls
   FROM pg_stat_statements
   ORDER BY mean_exec_time DESC LIMIT 10;"

# Check index usage
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT schemaname, tablename, indexname, idx_scan
   FROM pg_stat_user_indexes
   ORDER BY idx_scan ASC;"
```

**Solutions:**

**Missing Indexes:**
```sql
-- Add index on frequently queried fields
CREATE INDEX idx_parsed_logs_timestamp ON parsed_logs(timestamp);
CREATE INDEX idx_parsed_logs_source_ip ON parsed_logs((parsed_data->>'source_ip'));
CREATE INDEX idx_raw_logs_source_ip ON raw_logs(source_ip);
```

**Increase Resources:**
```yaml
# docker-compose.yml
services:
  postgres:
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 8G
    shm_size: 512MB
```

**Optimize Queries:**
```bash
# Use pagination (limit/offset)
curl "http://localhost:3001/api/logs/parsed?limit=50&offset=0"

# Use specific time ranges
curl "http://localhost:3001/api/logs/parsed?start_date=2025-11-30T00:00:00Z&end_date=2025-11-30T23:59:59Z"
```

---

### Issue: High Memory Usage

**Diagnosis:**
```bash
# Check container memory
docker stats --no-stream

# Check PostgreSQL memory
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT pg_size_pretty(pg_total_relation_size('parsed_logs'));"
```

**Solutions:**
```yaml
# Tune PostgreSQL memory settings
services:
  postgres:
    command:
      - "postgres"
      - "-c"
      - "shared_buffers=512MB"
      - "-c"
      - "effective_cache_size=2GB"
      - "-c"
      - "work_mem=8MB"
```

---

## Network & Connectivity

### Issue: Can't Access Web UI

**Diagnosis:**
```bash
# Check if frontend is running
docker-compose ps frontend

# Check frontend logs
docker-compose logs frontend

# Test locally
curl -I http://localhost:3000

# Test from remote
curl -I http://<server-ip>:3000
```

**Solutions:**

**Firewall Blocking:**
```bash
sudo ufw allow 3000/tcp
```

**Wrong Port:**
```bash
# Check docker-compose.yml ports mapping
docker-compose config | grep -A2 "frontend:" | grep ports

# Access on correct port
```

**Reverse Proxy Configuration:**
```bash
# If using nginx, check config
sudo nginx -t
sudo systemctl status nginx

# Check nginx logs
sudo tail -f /var/log/nginx/error.log
```

---

## Frontend Issues

### Issue: Blank Page or JavaScript Errors

**Diagnosis:**
```bash
# Check browser console (F12)
# Look for errors

# Check if API is accessible
curl http://localhost:3001/api/auth/me \
  -H "Authorization: Bearer $TOKEN"

# Check frontend build
docker-compose logs frontend | grep -i error
```

**Solutions:**

**Rebuild Frontend:**
```bash
docker-compose down
docker-compose build --no-cache frontend
docker-compose up -d frontend
```

**API URL Misconfigured:**
```bash
# Check VITE_API_URL in .env
grep VITE_API_URL .env

# Should be:
VITE_API_URL=/api  # If using same domain
# Or:
VITE_API_URL=http://backend-server:3001/api  # If separate
```

---

## Container Issues

### Issue: Container Keeps Restarting

**Diagnosis:**
```bash
# Check restart count
docker ps -a | grep siembox

# View last crash logs
docker-compose logs --tail=100 <service-name>

# Check exit code
docker inspect <container-id> | jq '.[0].State'
```

**Solutions:**

**Out of Memory:**
```bash
# Increase memory limit
# docker-compose.yml
services:
  backend:
    deploy:
      resources:
        limits:
          memory: 2G
```

**Dependency Not Ready:**
```bash
# Ensure proper depends_on with healthcheck
services:
  backend:
    depends_on:
      postgres:
        condition: service_healthy
```

---

## Data Cleanup

### Issue: Cleanup Service Not Running

**Diagnosis:**
```bash
# Check if cleanup is enabled
curl http://localhost:3001/api/settings/retention \
  -H "Authorization: Bearer $TOKEN"

# Check backend logs for cleanup
docker-compose logs backend | grep -i cleanup
```

**Solution:**
```bash
# Enable auto cleanup
curl -X PUT http://localhost:3001/api/settings/retention \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "auto_cleanup_enabled": true,
    "raw_logs_days": 30,
    "parsed_logs_days": 90,
    "alerts_days": 365
  }'

# Restart backend
docker-compose restart backend
```

---

## Advanced Diagnostics

### Full System Health Check Script

```bash
#!/bin/bash
echo "=== SIEMBox Health Check ==="
echo ""

echo "1. Container Status:"
docker-compose ps
echo ""

echo "2. Port Listening:"
netstat -tuln | grep -E "514|3000|3001|5432"
echo ""

echo "3. Database Connectivity:"
docker exec siembox-postgres psql -U siembox -d siembox -c "SELECT 1;"
echo ""

echo "4. Log Counts:"
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT
    (SELECT COUNT(*) FROM raw_logs) as raw_logs,
    (SELECT COUNT(*) FROM parsed_logs) as parsed_logs,
    (SELECT COUNT(*) FROM alerts) as alerts;"
echo ""

echo "5. Disk Usage:"
df -h /var/lib/docker/volumes/ | grep siembox
echo ""

echo "6. Recent Errors:"
docker-compose logs --tail=50 | grep -i error
echo ""

echo "Health check complete!"
```

---

## Getting Help

If you've tried everything and still have issues:

1. **Gather Information:**
```bash
# Collect logs
docker-compose logs > siembox-logs-$(date +%Y%m%d).txt

# System info
docker version > system-info.txt
docker-compose version >> system-info.txt
uname -a >> system-info.txt
```

2. **Check Documentation:**
- [README.md](./README.md)
- [DEPLOYMENT.md](./DEPLOYMENT.md)
- [API.md](./API.md)

3. **Search Existing Issues:**
https://github.com/cladkins/SIEMBOX/issues

4. **Open New Issue:**
https://github.com/cladkins/SIEMBOX/issues/new

Include:
- System information
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs
- Configuration (sanitized)

---

**Last Updated:** 2025-12-02
