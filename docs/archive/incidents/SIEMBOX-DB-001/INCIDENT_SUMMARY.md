# SIEMBox Database Error - Quick Reference

**Issue**: Database INSERT queries failing with empty error objects
**Impact**: Log ingestion broken, parsers/rules not appearing in UI
**Status**: Hotfixes implemented, awaiting deployment and diagnostics

---

## What Was Fixed

### 1. Error Logging (CRITICAL FIX)
**File**: `/backend/src/config/database.ts`

**Problem**: PostgreSQL error objects don't serialize with JSON.stringify(), resulting in empty `{}` in logs.

**Solution**: Explicitly extract error properties (message, code, detail, hint, etc.) before logging.

**Impact**: Database errors now show full details for diagnosis.

---

### 2. Migration Numbering Conflict (CRITICAL FIX)
**Files**: `/backend/migrations/*`

**Problem**: Two migrations had "003" prefix causing unpredictable execution order:
- `003_log_shippers.sql`
- `003_system_settings.sql`

**Solution**: Renumbered migrations:
```
001_initial_schema.sql       (unchanged)
002_seed_data.sql            (unchanged)
003_log_shippers.sql         (unchanged)
004_system_settings.sql      (renamed from 003)
005_add_vaultwarden_parser.sql (renamed from 004)
006_add_ip_whitelist.sql     (renamed from 005)
```

**Impact**: Migrations now execute in correct sequential order.

---

## Files Created

1. **DIAGNOSTIC_SCRIPT.md** - Comprehensive step-by-step diagnostic commands
2. **INCIDENT_ANALYSIS.md** - Detailed root cause analysis and technical report
3. **HOTFIX_PLAN.md** - Implementation guide for all hotfixes
4. **diagnose-db.sh** - Automated diagnostic script for Docker host
5. **INCIDENT_SUMMARY.md** - This quick reference

---

## Next Steps

### On Docker Host (Remote Server)

**Option A: Run automated diagnostic script**
```bash
cd /path/to/siembox
./backend/scripts/diagnose-db.sh > diagnostic-output.txt
```

**Option B: Run manual diagnostics**
Follow step-by-step instructions in `DIAGNOSTIC_SCRIPT.md`

---

### After Getting Diagnostics

Based on diagnostic output, you may need to:

1. **If database tables are missing or incorrect**:
   ```bash
   docker exec siembox-backend npm run migrate
   ```

2. **If parsers/rules are missing (count = 0)**:
   - Check if migration 002 (seed data) ran successfully
   - May need to re-run migrations

3. **If specific errors appear**:
   - Reference PostgreSQL error codes in `INCIDENT_ANALYSIS.md` Appendix A
   - Error details will now be visible in logs (after hotfix deployment)

---

## Deployment Steps

### Step 1: Pull Latest Code
```bash
cd /path/to/siembox
git pull origin develop
```

### Step 2: Rebuild Backend
```bash
docker compose build backend
```

### Step 3: Restart Backend
```bash
docker compose restart backend
```

### Step 4: Watch Logs
```bash
docker logs -f siembox-backend
```

### Step 5: Run Diagnostics
```bash
./backend/scripts/diagnose-db.sh > diagnostic-output.txt
```

---

## Verification Checklist

After deployment:

- [ ] Backend container restarts successfully
- [ ] No error logs on startup
- [ ] Database connection established (check logs)
- [ ] Error logs show full details (if errors occur)
- [ ] Diagnostic script completes successfully
- [ ] All tables exist (13 tables expected)
- [ ] Parser count = 40+ (check diagnostics)
- [ ] Rule count = 40+ (check diagnostics)
- [ ] Can manually INSERT into raw_logs
- [ ] Parsers appear in UI
- [ ] Rules appear in UI
- [ ] New logs ingest successfully

---

## Quick Diagnostic Commands

```bash
# Check container status
docker ps --filter name=siembox

# Check backend logs
docker logs siembox-backend --tail 100

# Check database connectivity
docker exec siembox-backend node -e "const {Pool}=require('pg'); const p=new Pool({host:process.env.DB_HOST,port:process.env.DB_PORT,database:process.env.DB_NAME,user:process.env.DB_USER,password:process.env.DB_PASSWORD}); p.query('SELECT NOW()').then(r=>console.log('OK:',r.rows[0])).catch(e=>console.error('FAIL:',e.message))"

# Check table count
docker exec siembox-database psql -U siembox -d siembox -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public'"

# Check parser count
docker exec siembox-database psql -U siembox -d siembox -c "SELECT COUNT(*) FROM parsers"

# Check rule count
docker exec siembox-database psql -U siembox -d siembox -c "SELECT COUNT(*) FROM detection_rules"
```

---

## Expected Results

### Table Count
Should have 13 tables:
- users
- sessions
- raw_logs
- parsed_logs
- parsers
- detection_rules
- alerts
- log_shippers
- shipper_sources
- shipper_volumes
- shipper_activity
- system_settings
- ip_whitelist

### Data Counts
- **Parsers**: 40+ (seed data) + 1 (Vaultwarden) = 41+
- **Rules**: 40+ (seed data)
- **Raw logs**: 12M+ (based on error logs showing ID 12052775)
- **Parsed logs**: Should have data if parsers are working

---

## Rollback Plan

If issues occur after deployment:

```bash
# Rollback code changes
git checkout HEAD~1

# Rebuild and restart
docker compose build backend
docker compose restart backend
```

---

## Support Resources

- **Full Analysis**: `INCIDENT_ANALYSIS.md`
- **Diagnostic Guide**: `DIAGNOSTIC_SCRIPT.md`
- **Implementation Guide**: `HOTFIX_PLAN.md`
- **Diagnostic Script**: `backend/scripts/diagnose-db.sh`

---

## Contact

If issues persist after fixes:
1. Provide diagnostic output
2. Share backend/database logs
3. Describe specific error messages
4. Note any schema discrepancies

---

**Report Generated**: 2025-12-03
**Incident ID**: SIEMBOX-DB-001
**Severity**: CRITICAL
**Priority**: P0 (Immediate)
