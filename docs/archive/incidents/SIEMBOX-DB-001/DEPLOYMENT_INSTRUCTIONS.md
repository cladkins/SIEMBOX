# URGENT: SIEMBox Database Hotfix Deployment

**Date**: 2025-12-03
**Incident**: SIEMBOX-DB-001 - Critical Database Errors
**Commit**: c8e85c1 - Critical database error logging and migration numbering hotfixes

---

## Quick Deployment Guide

### On Remote Docker Host

```bash
# 1. Navigate to SIEMBox directory
cd /path/to/siembox

# 2. Pull latest fixes from develop branch
git pull origin develop

# 3. Rebuild backend container with fixes
docker compose build backend

# 4. Restart backend container
docker compose restart backend

# 5. Watch logs for 30 seconds (Ctrl+C to exit)
docker logs -f siembox-backend

# 6. Run diagnostic script
./backend/scripts/diagnose-db.sh > diagnostic-output.txt

# 7. View diagnostic results
less diagnostic-output.txt
```

---

## What These Fixes Do

### Fix 1: Error Logging
PostgreSQL errors will now show full details instead of empty `{}`:

**Before**:
```json
{
  "service": "siembox-backend",
  "text": "INSERT INTO raw_logs ...",
  "error": {}
}
```

**After**:
```json
{
  "service": "siembox-backend",
  "query": "INSERT INTO raw_logs ...",
  "error": {
    "message": "column 'nonexistent_column' does not exist",
    "code": "42703",
    "detail": null,
    "hint": "Perhaps you meant to reference column 'id'",
    "position": "25"
  }
}
```

### Fix 2: Migration Numbering
Migrations now execute in correct order:
1. 001_initial_schema.sql
2. 002_seed_data.sql
3. 003_log_shippers.sql
4. 004_system_settings.sql (was 003)
5. 005_add_vaultwarden_parser.sql (was 004)
6. 006_add_ip_whitelist.sql (was 005)

---

## Expected Behavior After Deployment

### 1. Backend Starts Successfully
```
[timestamp] [info]: Starting SIEMBox Backend Server
[timestamp] [info]: Database connection established
[timestamp] [info]: Syslog server listening on UDP 0.0.0.0:514
[timestamp] [info]: Syslog server listening on TCP 0.0.0.0:514
[timestamp] [info]: Server listening on port 5000
```

### 2. No Immediate Errors
If database schema is correct, no errors should appear.

### 3. Errors Show Full Details
If errors do occur, you'll now see:
- Error code (e.g., 42P01, 23505)
- Error message
- Error detail
- Error hint
- Query that failed
- Parameters used

---

## Diagnostic Checklist

After running `diagnose-db.sh`, verify:

**Container Health**:
- [ ] siembox-backend: Status = Up
- [ ] siembox-database: Status = Up
- [ ] siembox-frontend: Status = Up
- [ ] No containers restarting

**Database Connectivity**:
- [ ] Connection test shows "✓ DATABASE CONNECTION SUCCESSFUL"
- [ ] Current database = "siembox"
- [ ] Current user = "siembox"

**Tables Exist** (Should see 13 tables):
- [ ] users
- [ ] sessions
- [ ] raw_logs
- [ ] parsed_logs
- [ ] parsers
- [ ] detection_rules
- [ ] alerts
- [ ] log_shippers
- [ ] shipper_sources
- [ ] shipper_volumes
- [ ] shipper_activity
- [ ] system_settings
- [ ] ip_whitelist

**Data Exists**:
- [ ] Parsers count >= 41 (40 seed + 1 Vaultwarden)
- [ ] Rules count >= 40
- [ ] Raw logs count > 0
- [ ] Users count >= 1 (admin)

**INSERT Test**:
- [ ] Manual INSERT into raw_logs succeeds
- [ ] Returns inserted row with ID

---

## Troubleshooting

### If Backend Won't Start

**Check logs**:
```bash
docker logs siembox-backend --tail 100
```

**Look for**:
- Database connection errors (code: 08006)
- Migration errors
- Port conflicts

**Fix**:
```bash
# Restart database first
docker compose restart database

# Wait 10 seconds
sleep 10

# Then restart backend
docker compose restart backend
```

---

### If Tables Are Missing

**Symptom**: Diagnostic shows fewer than 13 tables

**Cause**: Migrations didn't run or failed

**Fix**:
```bash
# Check if migrations ran
docker exec siembox-backend ls -la /app/migrations

# Re-run migrations
docker exec siembox-backend npm run migrate

# Check logs for migration errors
docker logs siembox-backend --tail 100
```

---

### If Parsers/Rules Count Is Zero

**Symptom**: Diagnostic shows 0 parsers or 0 rules

**Cause**: Seed data migration (002) didn't run or failed

**Fix**:
```bash
# Check if seed data exists in migration file
docker exec siembox-backend cat /app/migrations/002_seed_data.sql | grep "INSERT INTO parsers"

# Re-run migrations (will skip already-run migrations)
docker exec siembox-backend npm run migrate
```

---

### If INSERT Test Fails

**Symptom**: "ERROR: ..." when trying manual INSERT

**Check error code**:
- **42P01** (undefined_table): Table doesn't exist → Re-run migrations
- **42703** (undefined_column): Column doesn't exist → Schema mismatch
- **23502** (not_null_violation): Missing required field → Check INSERT statement
- **23503** (foreign_key_violation): Invalid reference → Check related tables

**Get more details**:
```bash
docker exec -i siembox-database psql -U siembox -d siembox <<EOF
\d raw_logs
EOF
```

Compare output to expected schema in `/backend/migrations/001_initial_schema.sql`

---

### If Errors Still Show Empty Objects

**Symptom**: Logs still show `"error": {}`

**Cause**: Old backend code still running (didn't rebuild/restart)

**Fix**:
```bash
# Force rebuild and restart
docker compose down backend
docker compose build --no-cache backend
docker compose up -d backend
```

---

## Verification Commands

```bash
# Check backend version (should show recent build time)
docker inspect siembox-backend --format='{{.Created}}'

# Verify code changes deployed
docker exec siembox-backend cat /app/src/config/database.ts | grep "errorDetails"

# Should show: const errorDetails = {

# Check migration files
docker exec siembox-backend ls -la /app/migrations/
# Should show: 004_system_settings.sql, 005_add_vaultwarden_parser.sql, 006_add_ip_whitelist.sql
```

---

## Success Criteria

All of the following should be true:

1. **Backend runs without errors**
2. **Database connection established**
3. **All 13 tables exist**
4. **Parsers count >= 41**
5. **Rules count >= 40**
6. **Manual INSERT succeeds**
7. **If errors occur, they show full details** (message, code, detail)
8. **Parsers appear in UI** (http://your-server:3000)
9. **Rules appear in UI**

---

## If Issues Persist

### Collect Diagnostic Information

```bash
# On Docker host
cd /path/to/siembox

# Run full diagnostics
./backend/scripts/diagnose-db.sh > diagnostic-output.txt

# Collect logs
docker logs siembox-backend > backend-logs.txt
docker logs siembox-database > database-logs.txt

# Package everything
tar -czf siembox-diagnostics.tar.gz \
  diagnostic-output.txt \
  backend-logs.txt \
  database-logs.txt
```

### Provide the Following

1. **Diagnostic output** (`diagnostic-output.txt`)
2. **Backend logs** (`backend-logs.txt`)
3. **Database logs** (`database-logs.txt`)
4. **Error messages** (specific error codes and messages)
5. **Unexpected behavior** (what you expected vs. what happened)

---

## Rollback Procedure

If deployment causes problems:

```bash
cd /path/to/siembox

# Rollback code
git checkout HEAD~1

# Rebuild and restart
docker compose build backend
docker compose restart backend

# Verify rollback
git log --oneline -1
# Should show previous commit, not c8e85c1
```

---

## Post-Deployment Monitoring

Watch these for 24 hours:

```bash
# Monitor error rate
docker logs -f siembox-backend | grep -i error

# Monitor database queries
docker logs -f siembox-backend | grep "Database query error"

# Check ingestion rate
docker exec siembox-database psql -U siembox -d siembox -c "
SELECT COUNT(*) as logs_last_hour
FROM raw_logs
WHERE created_at > NOW() - INTERVAL '1 hour'
"
```

---

## Support Documentation

- **Quick Reference**: `/backend/INCIDENT_SUMMARY.md`
- **Full Analysis**: `/backend/INCIDENT_ANALYSIS.md`
- **Implementation Guide**: `/backend/HOTFIX_PLAN.md`
- **Diagnostic Commands**: `/backend/DIAGNOSTIC_SCRIPT.md`

---

## Timeline

1. **Deploy fixes**: 10 minutes
2. **Run diagnostics**: 5 minutes
3. **Verify results**: 10 minutes
4. **Test UI**: 5 minutes
5. **Monitor**: 24 hours

**Total immediate effort**: ~30 minutes

---

## Questions?

If unclear on any step:
1. Reference the support documentation listed above
2. Check diagnostic output for specific errors
3. Share logs and error codes for assistance

---

**Priority**: P0 (Critical)
**Estimated Deploy Time**: 10 minutes
**Estimated Verification Time**: 20 minutes
**Risk Level**: Low (simple fixes, easily rolled back)

Deploy immediately. Parsers and rules depend on database functioning correctly.
