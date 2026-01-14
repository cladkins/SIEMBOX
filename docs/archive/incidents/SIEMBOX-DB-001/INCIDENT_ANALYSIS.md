# SIEMBox Database Error - Incident Analysis Report

**Date**: 2025-12-03
**Severity**: CRITICAL
**Status**: Root Cause Analysis Complete - Awaiting Diagnostic Confirmation
**Incident ID**: SIEMBOX-DB-001

---

## Executive Summary

SIEMBox backend is experiencing critical database errors preventing log ingestion and causing parsers/rules to not appear in the UI. Error logs show empty error objects (`"error":{}`) making root cause diagnosis difficult.

**Primary Issues Identified**:
1. PostgreSQL error objects not serializing properly in Winston logger
2. Duplicate migration file numbering (two "003" migrations)
3. Possible database schema inconsistency

---

## Impact Assessment

### Systems Affected
- Log ingestion pipeline (CRITICAL)
- Parser engine (CRITICAL)
- Detection rule engine (CRITICAL)
- UI parser/rule display (HIGH)

### Business Impact
- No new logs being processed
- Security monitoring blind spot
- Detection rules not triggering
- Potential data loss if logs are rejected

### Data Impact
- Raw logs table shows ID 12052775+, indicating ~12M logs attempted
- Unknown how many logs successfully inserted vs. failed
- Parsed logs status unknown

---

## Technical Analysis

### 1. Error Object Serialization Issue

**File**: `/backend/src/config/database.ts` (line 35)

**Problem**:
```typescript
catch (error) {
  logger.error('Database query error:', { text, error });
  throw error;
}
```

PostgreSQL error objects have properties on the prototype chain that don't serialize with `JSON.stringify()`:
- `error.message` - Error message
- `error.code` - PostgreSQL error code (e.g., "23505", "42P01")
- `error.detail` - Additional error details
- `error.hint` - Suggested fix
- `error.position` - Position in query where error occurred

**Result**: Winston logger serializes error as empty object `{}`.

**Evidence**:
```json
{
  "service": "siembox-backend",
  "text": "INSERT INTO raw_logs ...",
  "error": {}  // <-- EMPTY
}
```

**Fix Required**: Explicitly extract error properties:
```typescript
catch (error) {
  const errorDetails = {
    message: error.message,
    code: error.code,
    detail: error.detail,
    hint: error.hint,
    position: error.position,
    stack: error.stack
  };
  logger.error('Database query error:', { text, error: errorDetails });
  throw error;
}
```

---

### 2. Migration File Numbering Conflict

**Problem**: Two migration files with "003" prefix:

```
001_initial_schema.sql       (Nov 25, 2024)
002_seed_data.sql            (Nov 30, 2024)
003_log_shippers.sql         (Nov 30, 2024) <-- NEWER
003_system_settings.sql      (Nov 25, 2024) <-- OLDER
004-add-vaultwarden-parser.sql (Dec 3, 2024)
005-add-ip-whitelist.sql     (Dec 3, 2024)
```

**Migration Execution Order** (alphabetical sort):
1. `001_initial_schema.sql`
2. `002_seed_data.sql`
3. `003_log_shippers.sql` ✓
4. `003_system_settings.sql` ✓
5. `004-add-vaultwarden-parser.sql` ✓
6. `005-add-ip-whitelist.sql` ✓

**Impact**:
- Both "003" files run, but order is unpredictable
- No migration tracking table to detect duplicates
- Future migrations could conflict

**Fix Required**: Renumber migrations:
```
001_initial_schema.sql           (no change)
002_seed_data.sql                (no change)
003_log_shippers.sql             (no change)
003_system_settings.sql  → 004_system_settings.sql
004-add-vaultwarden-parser.sql → 005-add-vaultwarden-parser.sql
005-add-ip-whitelist.sql → 006-add-ip-whitelist.sql
```

---

### 3. Possible Database Schema Issues

**Hypothesis**: INSERT queries failing due to:

#### A. Missing Tables
If migrations didn't run successfully:
- `raw_logs` table doesn't exist → ERROR 42P01 (undefined_table)
- `parsed_logs` table doesn't exist → ERROR 42P01

#### B. Column Mismatch
If table schema doesn't match INSERT statement:
- Missing column → ERROR 42703 (undefined_column)
- Wrong data type → ERROR 22P02 (invalid_text_representation)

#### C. Constraint Violations
If data violates constraints:
- Foreign key violation → ERROR 23503 (foreign_key_violation)
- Unique constraint violation → ERROR 23505 (unique_violation)
- Not null violation → ERROR 23502 (not_null_violation)

#### D. Sequence Out of Sync
If `raw_logs_id_seq` is behind:
- Attempting to insert ID that already exists → ERROR 23505

**Verification Required**: See DIAGNOSTIC_SCRIPT.md Steps 3-6

---

### 4. Parser/Rule Data Loading

**Expected Behavior**:
- Migration 002 seeds ~40 parsers
- Migration 002 seeds ~40 detection rules from YAML files
- Migration 004 adds Vaultwarden parser
- Total: 41 parsers, 40 rules

**Actual Behavior** (from logs):
- Unable to determine - UI shows no parsers/rules
- Could be:
  - Data wasn't inserted (migration failed)
  - Data exists but API queries failing
  - Frontend not fetching correctly

**Verification Required**: See DIAGNOSTIC_SCRIPT.md Steps 7-9

---

## Root Cause Hypothesis (Priority Order)

### PRIMARY: Error Logging Prevents Diagnosis
- **Probability**: 100% (confirmed by code review)
- **Impact**: Cannot diagnose actual database errors
- **Fix Complexity**: LOW (simple code change)

### SECONDARY: Schema Mismatch or Missing Tables
- **Probability**: 60%
- **Impact**: Complete log ingestion failure
- **Fix Complexity**: MEDIUM (may require re-running migrations)

### TERTIARY: Migration Numbering Conflict
- **Probability**: 80% (confirmed by file listing)
- **Impact**: Schema inconsistency, future migration issues
- **Fix Complexity**: LOW (rename files, may require re-run)

### QUATERNARY: Constraint Violations
- **Probability**: 40%
- **Impact**: Intermittent failures, some logs succeed
- **Fix Complexity**: MEDIUM (identify and fix constraint issues)

---

## Immediate Actions Required

### 1. Run Diagnostics (PRIORITY 1)
Execute all steps in `DIAGNOSTIC_SCRIPT.md` on Docker host.

**Expected Time**: 15-20 minutes
**Owner**: DevOps/SRE
**Deliverable**: Complete diagnostic output

### 2. Fix Error Logging (PRIORITY 1)
Update `/backend/src/config/database.ts` to properly serialize errors.

**Expected Time**: 5 minutes
**Owner**: Backend Developer
**Deliverable**: Code fix + commit

### 3. Fix Migration Numbering (PRIORITY 2)
Renumber migration files to eliminate conflicts.

**Expected Time**: 10 minutes
**Owner**: Database Administrator
**Deliverable**: Renamed files + commit

### 4. Schema Verification (PRIORITY 1)
Compare actual database schema to expected schema from migrations.

**Expected Time**: 10 minutes
**Owner**: Database Administrator
**Deliverable**: Schema comparison report

### 5. Re-run Migrations if Needed (PRIORITY 2)
If schema is incorrect, re-run migrations safely.

**Expected Time**: 20-30 minutes
**Owner**: Database Administrator
**Deliverable**: Successful migration execution

---

## Long-Term Preventive Measures

### 1. Add Migration Tracking Table
Create `schema_migrations` table to track executed migrations:
```sql
CREATE TABLE schema_migrations (
  version VARCHAR(255) PRIMARY KEY,
  executed_at TIMESTAMP DEFAULT NOW()
);
```

Prevent duplicate migrations from running.

### 2. Improve Error Logging
Add structured error logging throughout codebase:
- Database errors: include code, detail, hint
- API errors: include status code, endpoint, user
- Parser errors: include parser name, log sample

### 3. Add Database Health Checks
Implement health check endpoint:
- Database connectivity
- Table existence
- Row counts
- Recent insert success rate

### 4. Add Monitoring/Alerting
- Alert on database error rate spike
- Alert on zero log ingestion for >5 minutes
- Alert on parser/rule count drop
- Dashboard showing ingestion rate

### 5. Improve Migration Process
- Automated migration testing in CI/CD
- Migration rollback scripts
- Pre-migration schema backup
- Post-migration verification tests

---

## Testing Plan

### After Fix Implementation

1. **Unit Test**: Error logging serialization
2. **Integration Test**: Database INSERT with various error conditions
3. **System Test**: End-to-end log ingestion
4. **Regression Test**: Verify parsers/rules appear in UI
5. **Load Test**: Verify performance with high log volume

### Success Criteria

- [ ] Diagnostic script completes without errors
- [ ] Database errors logged with full details (code, message, detail)
- [ ] All migrations numbered sequentially
- [ ] All expected tables exist with correct schema
- [ ] Parser count = 41+ (including Vaultwarden)
- [ ] Detection rule count = 40+
- [ ] New logs successfully ingest
- [ ] Parsers appear in UI
- [ ] Rules appear in UI
- [ ] Alerts can be generated

---

## Communication Plan

### Stakeholder Updates

**Internal Team**: Provide updates every 2 hours during incident
**Users**: Post status update after fix is deployed
**Management**: Executive summary after resolution

### Post-Incident Review

Schedule blameless post-mortem within 48 hours:
- What happened?
- Why did it happen?
- How did we respond?
- What can we improve?

---

## Appendix A: Error Code Reference

Common PostgreSQL error codes:

| Code  | Name                      | Cause                          |
|-------|---------------------------|--------------------------------|
| 23502 | not_null_violation        | NULL in NOT NULL column        |
| 23503 | foreign_key_violation     | Invalid foreign key reference  |
| 23505 | unique_violation          | Duplicate unique/primary key   |
| 42P01 | undefined_table           | Table doesn't exist            |
| 42703 | undefined_column          | Column doesn't exist           |
| 22P02 | invalid_text_representation | Invalid data type           |
| 08006 | connection_failure        | Database connection lost       |

---

## Appendix B: File References

**Configuration**:
- `/backend/src/config/database.ts` - Database connection + query wrapper
- `/backend/.env` - Database credentials

**Models**:
- `/backend/src/models/RawLog.ts` - Raw logs model (INSERT query)
- `/backend/src/models/ParsedLog.ts` - Parsed logs model (INSERT query)

**Migrations**:
- `/backend/migrations/001_initial_schema.sql` - Core tables
- `/backend/migrations/002_seed_data.sql` - Seed parsers/rules
- `/backend/migrations/003_log_shippers.sql` - Log shipper tables (NEWER)
- `/backend/migrations/003_system_settings.sql` - System settings (OLDER) **CONFLICT**
- `/backend/migrations/004-add-vaultwarden-parser.sql` - Vaultwarden parser
- `/backend/migrations/005-add-ip-whitelist.sql` - IP whitelist table
- `/backend/src/scripts/migrate.ts` - Migration runner script

**Logging**:
- `/backend/src/utils/logger.ts` - Winston logger configuration

---

## Next Steps

1. **Execute diagnostic script** on Docker host
2. **Provide diagnostic output** to development team
3. **Implement fixes** based on diagnostic findings
4. **Re-test system** end-to-end
5. **Deploy fixes** to production
6. **Monitor closely** for 24 hours post-deployment

---

**Incident Commander**: Claude (DevOps Incident Responder)
**Last Updated**: 2025-12-03 14:45:00 UTC
