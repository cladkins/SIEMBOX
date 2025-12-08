# SIEMBox Deployment Fix Guide

## Issue: Rules Directory Not Found & Login Failure

### Problem Summary

The backend was crashing during startup with the error:
```
siembox-backend | 2025-12-08 20:19:27 [error]: Rules directory not found {"service":"siembox-backend","rulesDir":"/rules"}
```

This caused a cascading failure:
1. Import-rules script couldn't find `/app/rules` directory
2. Script called `process.exit(1)` crashing the backend
3. API server never started, making login impossible

### Root Cause

The `/rules` directory containing YAML detection rules was:
- Present on the host machine at `./rules/`
- **NOT mounted** into the Docker container
- **NOT copied** during Docker build
- Required by the backend startup sequence

### Solution Applied

**1. Docker Compose Configuration (docker-compose.yml)**
```yaml
backend:
  volumes:
    - ./rules:/app/rules:ro  # Mount rules directory as read-only
```

**2. Graceful Error Handling (backend/src/scripts/import-rules.ts)**
```typescript
if (!fs.existsSync(rulesDir)) {
  logger.warn('Rules directory not found - skipping rule import', { rulesDir });
  logger.warn('Detection rules will need to be created manually or rules directory must be mounted');
  return; // Exit gracefully instead of crashing
}
```

**3. Startup Protection (backend/src/server.ts)**
```typescript
try {
  await importRules();
} catch (error) {
  logger.error('Failed to import rules, but continuing startup:', error);
  logger.warn('Detection rules may need to be created manually');
}
```

## Deployment Steps for Remote Server

### Prerequisites
- SSH access to your remote server
- Git repository updated with the fixes
- Existing SIEMBox installation

### Step 1: Update Code on Remote Server

```bash
# SSH into your remote server
ssh user@your-remote-server

# Navigate to SIEMBox directory
cd /path/to/SIEMBox

# Pull latest changes
git fetch origin
git pull origin develop

# Verify the rules directory exists
ls -la rules/
# Should show directories: authentication, password-manager, reverse-proxy, etc.
```

### Step 2: Stop Existing Containers

```bash
# Stop all SIEMBox services
docker compose down

# Optional: Remove old backend image to force rebuild
docker rmi siembox-backend 2>/dev/null || true
```

### Step 3: Rebuild and Start Services

```bash
# Build fresh images
docker compose build backend

# Start all services
docker compose up -d

# Or combine both steps
docker compose up -d --build
```

### Step 4: Verify Successful Startup

```bash
# Check container status (should all show "Up")
docker compose ps

# View backend logs
docker compose logs -f backend

# Look for these SUCCESS indicators:
# ✓ "Database connection successful"
# ✓ "Rule import completed: X imported, Y skipped, Z failed"
# ✓ "SIEMBox API server running on http://0.0.0.0:3001"
# ✓ "Syslog server listening on port 514"

# Should NOT see:
# ✗ "Rules directory not found" (error level)
# ✗ Container exit status
```

### Step 5: Test Login

```bash
# Test API health check
curl http://localhost:3001/health

# Should return: {"status":"ok"}

# Test login (replace with your credentials)
curl -X POST http://localhost:3001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"changeme"}'

# Should return JWT token and user info
```

### Step 6: Verify Rules Were Imported

```bash
# Check how many rules were imported
docker compose logs backend | grep "Rule import completed"

# Or check the database directly
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT COUNT(*) as total_rules FROM detection_rules;"

# Should show the number of imported rules (e.g., 40+)
```

## Expected Behavior After Fix

### ✅ Successful Startup Logs
```
siembox-backend | Database connection successful
siembox-backend | Checking for detection rules to import...
siembox-backend | Starting rule import from YAML files...
siembox-backend | Scanning for YAML rule files
siembox-backend | Found 47 YAML rule files
siembox-backend | Rule import completed: 47 imported, 0 skipped, 0 failed
siembox-backend | Syslog server listening on port 514 (UDP and TCP)
siembox-backend | SIEMBox API server running on http://0.0.0.0:3001
siembox-backend | Cleanup service running (interval: 24 hours)
```

### ✅ Login Should Work
- Frontend loads at `http://your-server:3000`
- Login form accepts credentials
- Default admin credentials: `admin` / `changeme`
- After login, dashboard displays

## Troubleshooting

### Issue: Still seeing "Rules directory not found"

**Check 1: Volume Mount**
```bash
# Verify volume is mounted in container
docker exec siembox-backend ls -la /app/rules

# Should show authentication/, password-manager/, etc.
```

**Fix:** If directory is empty or missing:
```bash
# Ensure host directory exists
ls -la rules/

# Stop and remove containers
docker compose down -v  # -v removes volumes

# Start again
docker compose up -d
```

### Issue: "Permission denied" on rules directory

**Check:**
```bash
# Check permissions on host
ls -ld rules/
# Should be readable (at minimum: dr-xr-xr-x)

# Check files
ls -la rules/*/*.yaml
```

**Fix:**
```bash
# Make readable by all (if needed)
chmod -R a+rX rules/
```

### Issue: Backend still won't start

**Check logs:**
```bash
# Full backend logs
docker compose logs backend --tail=100

# Check for other errors
docker compose logs backend | grep -i "error\|fatal\|exception"
```

**Common issues:**
- Database not ready: Wait for postgres health check
- Port 514 permission: Requires NET_BIND_SERVICE capability (already in compose)
- Out of memory: Check `docker stats`

### Issue: Rules not importing even though directory exists

**Check:**
```bash
# See if rules import is being attempted
docker compose logs backend | grep -i "rule import"

# Check if YAML files are valid
cd rules/authentication
head -n 20 *.yaml
```

**Fix:**
```bash
# Force reimport by rebuilding
docker compose down
docker compose up -d --build

# Or manually import (if needed)
docker exec siembox-backend node dist/scripts/import-rules.js
```

## Rollback Procedure (If Needed)

If the fix causes issues:

```bash
# Stop services
docker compose down

# Revert to previous commit
git log --oneline -n 5  # Find previous commit
git checkout <previous-commit-hash>

# Rebuild and start
docker compose up -d --build
```

## Validation Checklist

After deployment, verify:

- [ ] All containers are running (`docker compose ps`)
- [ ] No error logs in backend (`docker compose logs backend`)
- [ ] Health check responds (`curl http://localhost:3001/health`)
- [ ] Login works via frontend (`http://localhost:3000`)
- [ ] Login works via API (`POST /api/auth/login`)
- [ ] Detection rules loaded (`SELECT COUNT(*) FROM detection_rules;`)
- [ ] Rules directory mounted (`docker exec siembox-backend ls /app/rules`)
- [ ] Syslog server listening (`netstat -uln | grep 514`)

## Changes Made

### Files Modified
1. **docker-compose.yml**: Added volume mount for rules directory
2. **backend/src/scripts/import-rules.ts**: Graceful handling of missing directory
3. **backend/src/server.ts**: Try-catch around importRules to prevent startup failure

### Behavioral Changes
- **Before**: Missing rules directory crashed the entire backend
- **After**: Missing rules directory logs warning but allows startup
- **Before**: No volume mount for rules
- **After**: Rules mounted from `./rules` to `/app/rules` (read-only)

## Long-term Recommendations

1. **Add Health Check Endpoint**: Create `/health/rules` endpoint showing:
   - Rules directory status
   - Number of rules loaded
   - Last import timestamp

2. **Add Startup Validation Script**: Create script to verify deployment:
   ```bash
   #!/bin/bash
   # scripts/validate-deployment.sh
   echo "Checking containers..."
   docker compose ps

   echo "Checking rules mount..."
   docker exec siembox-backend ls /app/rules

   echo "Testing API..."
   curl -f http://localhost:3001/health || exit 1

   echo "✓ Deployment validated successfully"
   ```

3. **Update CI/CD Pipeline**: Add validation step to ensure rules directory is present before deployment

4. **Monitor Startup**: Add alerting for container restart loops or startup failures

## Support

If issues persist after following this guide:
1. Collect logs: `docker compose logs > siembox-logs.txt`
2. Check container status: `docker compose ps`
3. Verify rules directory: `ls -la rules/`
4. Open GitHub issue with logs and output

## References

- Main documentation: `README.md`
- Troubleshooting: `docs/operations/TROUBLESHOOTING.md`
- Detection rules guide: `docs/RULES.md`
- Docker documentation: https://docs.docker.com/compose/
