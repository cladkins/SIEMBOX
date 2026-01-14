# SIEMBox Fresh Installation Fix

## Problem Summary

You are experiencing persistent errors after redeploying SIEMBox:
1. **Vaultwarden parser regex error**: "Duplicate capture group name" - JavaScript regex doesn't allow duplicate `(?<email>)` groups
2. **Detection rules not showing**: Rules not visible in the UI
3. **Fresh install not working**: Despite shutting down, pruning, and redeploying

**UPDATE (2025-12-08)**: The regex error was caused by TWO `(?<email>)` capture groups in the pattern. This has been fixed in commit d8ad0d5.

## Root Cause

**The PostgreSQL volume is persisting between deployments.**

When you run:
```bash
docker compose down
```

This stops and removes the containers, but **DOES NOT** remove the volumes. The PostgreSQL database volume continues to exist with the old corrupted data.

The logs confirm this:
```
PostgreSQL Database directory appears to contain a database; Skipping initialization
```

This means:
- Migrations don't run again
- The old corrupted vaultwarden parser remains
- Detection rules from the old database are still there (or missing)

## Solution: Complete Fresh Start

### Step 1: Remove ALL Docker Resources (Including Volumes)

On your remote Docker server, run:

```bash
# Navigate to SIEMBox directory
cd /path/to/SIEMBox

# Stop containers AND remove volumes (the -v flag is critical)
docker compose down -v

# Optional: Verify volumes are gone
docker volume ls | grep siembox
# Should return nothing
```

**IMPORTANT**: The `-v` flag is what removes volumes. Without it, the postgres data persists.

### Step 2: Pull Latest Code (if not already done)

```bash
# Ensure you have the latest fixes
git fetch origin
git pull origin develop

# Verify you're on the correct commit
git log --oneline -1
# Should show: dae53ae fix: Resolve backend startup failure due to missing rules directory
```

### Step 3: Start Fresh

```bash
# Build and start all services
docker compose up -d --build

# Or if you prefer to watch the logs
docker compose up --build
```

### Step 4: Verify Successful Startup

```bash
# Check all containers are running
docker compose ps
# All should show "Up"

# Watch backend logs for success messages
docker compose logs -f backend

# Look for these SUCCESS indicators:
# ✓ "Database connection successful"
# ✓ "Starting rule import from YAML files..."
# ✓ "Found X YAML rule files"
# ✓ "Rule import completed: X imported, 0 skipped, 0 failed"
# ✓ "Syslog server listening on port 514 (UDP and TCP)"
# ✓ "SIEMBox API server running on http://0.0.0.0:3001"
```

### Step 5: Verify Vaultwarden Parser

```bash
# Check the database for the vaultwarden parser
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT name, parser_type, enabled, LEFT(pattern, 50) as pattern_preview FROM parsers WHERE name = 'vaultwarden-access';"

# Should show:
# name              | parser_type | enabled | pattern_preview
# vaultwarden-access| regex       | t       | ^\[(?<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}
```

**IMPORTANT**: The pattern should show `(?<timestamp>` NOT `(?` or `(?P<timestamp>`.

### Step 6: Verify Detection Rules

```bash
# Count detection rules in database
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT COUNT(*) as total_rules FROM detection_rules;"

# Should show 40+ rules

# List vaultwarden-specific rules
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT name, severity FROM detection_rules WHERE tags::text LIKE '%vaultwarden%' ORDER BY severity DESC;"
```

### Step 7: Test Login and UI

```bash
# Test API health
curl http://localhost:3001/health
# Should return: {"status":"ok"}

# Access frontend
# Open browser: http://your-server:3000
# Login: admin / changeme
# Navigate to: Parsers page - should see vaultwarden-access
# Navigate to: Detection Rules page - should see 40+ rules
```

## What This Fresh Start Does

1. **Removes the old database**: `docker compose down -v` deletes the postgres volume
2. **Creates fresh database**: PostgreSQL initializes a new empty database
3. **Runs ALL migrations**: All migration files execute in order
4. **Imports detection rules**: Rules from `./rules/` directory are imported
5. **Correct regex patterns**: Vaultwarden parser has proper JavaScript syntax

## Why Your Previous Attempts Didn't Work

Previous attempts used:
```bash
docker compose down  # Missing the -v flag!
```

Without `-v`, the postgres volume persists, and you get:
- ❌ Same old database
- ❌ Migrations don't run (already marked as executed)
- ❌ Corrupted parser patterns remain
- ❌ Old or missing rules

With `-v`:
```bash
docker compose down -v  # Removes volumes!
```

You get:
- ✅ Brand new database
- ✅ All migrations run fresh
- ✅ Correct parser patterns
- ✅ All detection rules imported

## Expected Results After Fresh Start

### ✅ Backend Logs Should Show

```
siembox-backend | Database connection successful
siembox-backend | Checking for detection rules to import...
siembox-backend | Starting rule import from YAML files...
siembox-backend | Scanning for YAML rule files
siembox-backend | Found 47 YAML rule files
siembox-backend | Importing: authentication/AUTH-001-failed-ssh-login.yaml
siembox-backend | Rule imported successfully
siembox-backend | ... (repeated for all rules)
siembox-backend | Rule import completed: 47 imported, 0 skipped, 0 failed
siembox-backend | ✓ Successfully imported 47 new rules
siembox-backend | Syslog server listening on port 514 (UDP and TCP)
siembox-backend | SIEMBox API server running on http://0.0.0.0:3001
```

### ✅ No Errors Should Appear

You should NOT see:
- ❌ "Invalid regular expression: Duplicate capture group name"
- ❌ "Invalid group" errors
- ❌ Pattern showing `(?` without group names
- ❌ Container exit status or crash loops

### ✅ UI Should Show

- **Parsers page**: All parsers including vaultwarden-access (priority 55)
- **Detection Rules page**: 40+ rules across various categories
- **Rules working**: When logs are received, rules should evaluate correctly

## Troubleshooting If Issues Persist

### Issue: Still seeing "Invalid regular expression" after fresh start

**Diagnosis:**
```bash
# Check what's actually in the database
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT name, LEFT(pattern, 100) as pattern FROM parsers WHERE name = 'vaultwarden-access';"
```

**If pattern shows duplicate email groups or other issues:**

Ensure you have the latest code (commit d8ad0d5 or later) and try:

```bash
# Force remove everything
docker compose down
docker volume rm siembox_postgres-data 2>/dev/null || true
docker compose up -d --build
```

### Issue: Rules still not showing

**Check rules were imported:**
```bash
docker compose logs backend | grep -i "rule import"
```

**If you see "0 imported":**

Check the rules directory is mounted:
```bash
docker exec siembox-backend ls -la /app/rules
# Should show: authentication/, password-manager/, reverse-proxy/, etc.
```

**If directory is empty or missing:**
```bash
# Check host has rules
ls -la rules/
# Should show subdirectories with YAML files

# Restart with fresh mount
docker compose restart backend
```

### Issue: Database migration errors

**Check migration status:**
```bash
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT version FROM schema_migrations ORDER BY version;"
```

Should show migrations 001 through 006 (or higher).

**If migrations are missing or failed:**
```bash
# Check migration logs
docker compose logs backend | grep -i migration

# Force rebuild and restart
docker compose down -v
docker compose up -d --build
```

## Validation Checklist

After completing the fresh start, verify:

- [ ] `docker compose ps` - All containers show "Up"
- [ ] `docker compose logs backend` - No error messages
- [ ] `curl http://localhost:3001/health` - Returns {"status":"ok"}
- [ ] Database has vaultwarden parser with correct pattern `(?<timestamp>`
- [ ] Database has 40+ detection rules
- [ ] Frontend accessible at http://localhost:3000
- [ ] Can login with admin/changeme
- [ ] Parsers page shows vaultwarden-access
- [ ] Detection Rules page shows 40+ rules
- [ ] Rules directory mounted: `docker exec siembox-backend ls /app/rules`

## Files Changed in Latest Fixes (Commit dae53ae)

1. **docker-compose.yml**: Added rules directory volume mount
2. **backend/src/scripts/import-rules.ts**: Graceful handling if rules directory missing
3. **backend/src/server.ts**: Try-catch around rule import to prevent startup crashes
4. **DEPLOYMENT-FIX-GUIDE.md**: Comprehensive deployment documentation

## Why This Approach Works for Fresh Installs

A new user downloading SIEMBox and running `docker compose up -d` will get:

1. ✅ Fresh PostgreSQL database (no old volume)
2. ✅ All migrations run correctly
3. ✅ Vaultwarden parser with correct JavaScript regex
4. ✅ All detection rules imported from `./rules/` directory
5. ✅ Backend starts successfully
6. ✅ Rules and parsers visible in UI

The previous issues you experienced were due to:
- Old database volume persisting between deployments
- Volume containing corrupted parser patterns from earlier development
- Migrations not re-running because database already existed

## Support

If you still experience issues after following this guide:

1. **Collect logs:**
   ```bash
   docker compose logs > siembox-fresh-install-logs.txt
   ```

2. **Check database state:**
   ```bash
   docker exec siembox-postgres psql -U siembox -d siembox -c \
     "SELECT name, parser_type, LEFT(pattern, 50) FROM parsers;" > parsers-state.txt
   ```

3. **Verify rules:**
   ```bash
   docker exec siembox-postgres psql -U siembox -d siembox -c \
     "SELECT COUNT(*), severity FROM detection_rules GROUP BY severity;" > rules-state.txt
   ```

4. **Open GitHub issue** with the log files attached

## Key Takeaway

**Always use `docker compose down -v` when you want a TRUE fresh start.**

- `docker compose down` - Stops containers, keeps volumes ❌
- `docker compose down -v` - Stops containers AND removes volumes ✅

The `-v` flag is essential for a complete fresh installation.
