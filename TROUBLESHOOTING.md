# SIEMBox Troubleshooting Guide

This guide covers common issues and their solutions when running SIEMBox.

## Table of Contents

- [Log Shipper Issues](#log-shipper-issues)
- [Database Issues](#database-issues)
- [Parser Issues](#parser-issues)
- [Authentication Issues](#authentication-issues)
- [Performance Issues](#performance-issues)

## Log Shipper Issues

### Ghost Shippers Detected

**Symptom:** Yellow alert banner on Shippers page showing "Unknown sources detected"

**What it means:** Log shippers are sending logs but their API keys are no longer valid in the system.

**Common Causes:**
1. API key was rotated in SIEMBox UI but shipper wasn't updated
2. Shipper was cloned/copied with old credentials
3. API key was manually deleted from database
4. Shipper was unregistered but container is still running

**How to Identify:**

Navigate to **Shippers** page → Click **"View Unknown Sources"** to see:
- Shipper ID (8-character hash)
- Number of logs sent
- First and last seen timestamps
- Source IP addresses
- Hostnames
- Application names

**Solution Options:**

**Option 1: Re-register legitimate shipper**
```bash
# 1. On the shipper host, get the current shipper ID
docker logs <shipper_container> | grep "Shipper ID"

# 2. In SIEMBox UI: Shippers → Add Shipper → Note the new API key

# 3. Update shipper environment variable
# Edit docker-compose.yml or .env:
SHIPPER_API_KEY=new_api_key_from_ui

# 4. Restart shipper
docker-compose restart log-shipper
```

**Option 2: Stop unauthorized shipper**
```bash
# If you don't recognize the shipper:
# 1. Note the source IP from "Unknown Sources" dialog
# 2. SSH to that machine
# 3. Stop the shipper
docker-compose stop log-shipper
# or
docker stop <container_name>
```

**Option 3: Clean up historical logs**
```sql
-- Delete logs from specific ghost shipper (use with caution!)
-- Connect to database:
docker-compose exec postgres psql -U siembox -d siembox

-- Delete logs:
DELETE FROM raw_logs WHERE shipper_id = 'a1b2c3d4';
```

**Prevention:**
- Use unique API keys for each shipper (easier to track)
- Update shipper credentials immediately after rotation
- Document authorized shippers and their locations
- Monitor Shippers page regularly for unknown sources

---

### Shipper Not Sending Logs

**Symptom:** Shipper shows "online" in UI but no logs appearing in Raw Logs

**Diagnosis Steps:**

1. **Check shipper container logs:**
```bash
docker logs <shipper_container> --tail 50
```

Look for:
- `[ERROR]` messages indicating connection issues
- `Failed to fetch configuration` - API key may be invalid
- `No files found matching pattern` - file path incorrect
- `Container not found` - Docker container name wrong

2. **Verify shipper can reach SIEMBox:**
```bash
# From shipper host:
docker exec <shipper_container> nc -zv <siembox_host> 514
# Should show: Connection to <host> 514 port [tcp/syslog] succeeded!
```

3. **Check configuration:**
```bash
# View current shipper configuration
docker exec <shipper_container> cat /tmp/siembox-cached-config.json | jq .
```

4. **Verify sources exist:**
```bash
# For file sources:
docker exec <shipper_container> ls -la /path/to/log/file

# For Docker sources:
docker ps --filter "name=monitored_container"
```

**Common Solutions:**

**Issue: Network connectivity**
```bash
# Verify firewall allows UDP 514
sudo ufw allow 514/udp  # Ubuntu/Debian
sudo firewall-cmd --add-port=514/udp --permanent  # CentOS/RHEL
```

**Issue: Invalid API key**
- Check for "Failed to fetch configuration (HTTP 404)" in logs
- See [Ghost Shippers Detected](#ghost-shippers-detected) section

**Issue: File not found**
```bash
# Mount the log file directory into shipper container
# In docker-compose.yml:
volumes:
  - /var/log/nginx:/var/log/nginx:ro
```

**Issue: Docker socket not accessible**
```bash
# Mount Docker socket for container monitoring
# In docker-compose.yml:
volumes:
  - /var/run/docker.sock:/var/run/docker.sock:ro
```

---

### Shipper Shows Offline

**Symptom:** Shipper appears as "offline" in Shippers page

**Diagnosis:**

1. **Check if container is running:**
```bash
docker ps | grep shipper
```

2. **Check heartbeat logs:**
```bash
docker logs <shipper_container> | grep -i heartbeat
```

**Causes:**
- Container stopped
- API key invalid (cannot send heartbeat)
- Network connectivity issues
- SIEMBox backend not reachable

**Solution:**
```bash
# Restart shipper
docker-compose restart log-shipper

# Check logs for errors
docker-compose logs -f log-shipper
```

---

### Shipper Configuration Not Updating

**Symptom:** Changed configuration in UI but shipper still using old settings

**How Configuration Works:**
- Shipper polls for config every 30 seconds (default)
- New config is cached locally at `/tmp/siembox-cached-config.json`
- If API key is valid, config updates automatically
- If API key is invalid, shipper continues with cached config

**Solution:**

1. **Verify API key is valid:**
```bash
# Check for 404 errors in logs
docker logs <shipper_container> | grep "HTTP 404"
```

2. **Force config refresh:**
```bash
# Restart shipper to force immediate config fetch
docker-compose restart log-shipper
```

3. **Check cached config:**
```bash
# View currently cached configuration
docker exec <shipper_container> cat /tmp/siembox-cached-config.json | jq .
```

4. **Clear cache and restart:**
```bash
# Remove cached config
docker exec <shipper_container> rm /tmp/siembox-cached-config.json

# Restart
docker-compose restart log-shipper
```

---

## Database Issues

### Migration Errors on Startup

**Symptom:** Backend fails to start with "Migration failed" errors

**Common Errors:**

**Error: "INSERT has more target columns than expressions"**
```
Solution: This is a SQL syntax error in migration files.
Check backend/migrations/*.sql for INSERT statements with mismatched column counts.
See: https://github.com/cladkins/SIEMBOX/issues
```

**Error: "relation already exists"**
```bash
# For pre-v1.0: Reset database and re-run migrations
docker-compose down -v  # WARNING: Destroys all data
docker-compose up -d
```

---

## Parser Issues

### Logs Not Being Parsed

**Symptom:** Logs appear in Raw Logs but not in Parsed Logs

**Diagnosis:**

1. **Check if parsers are enabled:**
```sql
-- Connect to database
docker-compose exec postgres psql -U siembox -d siembox

-- List enabled parsers
SELECT name, priority, enabled FROM parsers ORDER BY priority;
```

2. **Test parser pattern:**
```bash
# Use test scripts in backend/test-*-patterns.js
# Example:
node backend/test-nginx-patterns.js
```

3. **Check parser engine logs:**
```bash
docker-compose logs backend | grep -i parser
```

**Common Solutions:**

**Issue: No parsers match the log format**
- Create a custom parser for your log format
- See `PARSERS.md` for parser creation guide

**Issue: Parser priority too low**
- Lower priority numbers match first
- Increase priority (lower number) for your parser

**Issue: Parser pattern incorrect**
- Remember: Parsers match against `raw_message` (NOT full syslog line)
- Test with actual `raw_message` content from database

---

## Authentication Issues

### Cannot Login

**Symptom:** Login fails with "Invalid credentials"

**Solution:**

1. **Reset admin password:**
```bash
docker-compose exec postgres psql -U siembox -d siembox -c "
UPDATE users
SET password = '\$2a\$10\$...'  -- Use bcrypt hash of new password
WHERE username = 'admin';
"
```

2. **Or reset database:**
```bash
# Pre-v1.0 only - destroys all data
docker-compose down -v
docker-compose up -d
# Default credentials: admin / changeme
```

---

## Performance Issues

### Slow Log Search

**Symptom:** Raw Logs page takes long time to load

**Solutions:**

1. **Reduce time range:**
- Use smaller time windows (last hour vs. last 24 hours)

2. **Apply filters:**
- Filter by source IP, hostname, or app name

3. **Check database size:**
```bash
docker-compose exec postgres psql -U siembox -d siembox -c "
SELECT pg_size_pretty(pg_database_size('siembox')) as database_size;
"
```

4. **Enable log retention policies:**
- Configure in Settings → Log Retention
- Automatically delete old logs

---

## Getting Help

If you encounter issues not covered in this guide:

1. **Check GitHub Issues:** https://github.com/cladkins/SIEMBOX/issues
2. **GitHub Discussions:** https://github.com/cladkins/SIEMBOX/discussions
3. **Review Logs:**
   ```bash
   docker-compose logs backend
   docker-compose logs frontend
   docker-compose logs postgres
   ```
4. **Check Documentation:**
   - `README.md` - Project overview
   - `DEPLOYMENT.md` - Installation and configuration
   - `API.md` - API reference
   - `PARSERS.md` - Parser documentation
   - `RULES.md` - Detection rules
