# SIEMBox Database Diagnostic Script
## CRITICAL DATABASE ERROR INVESTIGATION

**Date**: 2025-12-03
**Issue**: Database INSERT queries failing with empty error objects
**Impact**: Log ingestion broken, parsers/rules not appearing in UI

---

## CRITICAL ISSUE IDENTIFIED: DUPLICATE MIGRATION FILES

**Problem**: Two migration files have the same "003" prefix:
- `003_log_shippers.sql` (Nov 30, 2024 - NEWER)
- `003_system_settings.sql` (Nov 25, 2024 - OLDER)

**Impact**: When migrations run in alphabetical order, `003_log_shippers.sql` runs before `003_system_settings.sql`, causing unpredictable behavior.

---

## STEP 1: Check Container Status

Run these commands on the Docker host:

```bash
# Check all SIEMBox containers
docker ps --filter name=siembox --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Check for container restart loops (exit codes)
docker ps -a --filter name=siembox --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Check backend logs (last 100 lines)
docker logs siembox-backend --tail 100

# Check database logs (last 100 lines)
docker logs siembox-database --tail 100

# Check for backend container restarts
docker inspect siembox-backend --format='{{.RestartCount}}'
```

**Expected**: All containers should be "Up" with 0 restarts.

---

## STEP 2: Verify Database Connectivity

```bash
# Test database connection from backend container
docker exec siembox-backend node -e "
const { Pool } = require('pg');
const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME || 'siembox',
  user: process.env.DB_USER || 'siembox',
  password: process.env.DB_PASSWORD || 'changeme'
});
pool.query('SELECT NOW() as current_time, current_database(), current_user')
  .then(r => {
    console.log('=== DATABASE CONNECTION SUCCESSFUL ===');
    console.log(JSON.stringify(r.rows[0], null, 2));
    process.exit(0);
  })
  .catch(e => {
    console.error('=== DATABASE CONNECTION FAILED ===');
    console.error('Error:', e.message);
    console.error('Code:', e.code);
    console.error('Detail:', e.detail);
    process.exit(1);
  });
"
```

**Expected**: Should print current time, database name "siembox", and user "siembox".

---

## STEP 3: Check Database Schema (Tables)

```bash
# Connect to database and check schema
docker exec -it siembox-database psql -U siembox -d siembox -c "
SELECT
  table_name,
  (SELECT COUNT(*) FROM information_schema.columns WHERE table_name = t.table_name) as column_count
FROM information_schema.tables t
WHERE table_schema = 'public'
  AND table_type = 'BASE TABLE'
ORDER BY table_name;
"
```

**Expected Tables**:
- alerts
- detection_rules
- ip_whitelist (from migration 005)
- log_shippers (from migration 003)
- parsed_logs
- parsers
- raw_logs
- sessions
- shipper_activity
- shipper_sources
- shipper_volumes
- system_settings (from migration 003)
- users

---

## STEP 4: Verify raw_logs Table Schema

```bash
# Check raw_logs table structure
docker exec -it siembox-database psql -U siembox -d siembox -c "\d raw_logs"
```

**Expected Columns** (from 001_initial_schema.sql):
- id (SERIAL PRIMARY KEY)
- timestamp (TIMESTAMP NOT NULL)
- raw_message (TEXT NOT NULL)
- source_ip (VARCHAR(45) NOT NULL)
- facility (INTEGER)
- severity (INTEGER)
- hostname (VARCHAR(255))
- created_at (TIMESTAMP DEFAULT NOW())

---

## STEP 5: Verify parsed_logs Table Schema

```bash
# Check parsed_logs table structure
docker exec -it siembox-database psql -U siembox -d siembox -c "\d parsed_logs"
```

**Expected Columns** (from 001_initial_schema.sql):
- id (SERIAL PRIMARY KEY)
- raw_log_id (INTEGER REFERENCES raw_logs(id))
- parser_id (INTEGER REFERENCES parsers(id))
- parsed_data (JSONB NOT NULL)
- timestamp (TIMESTAMP NOT NULL)
- source_ip (VARCHAR(45) NOT NULL)
- event_type (VARCHAR(100))
- created_at (TIMESTAMP DEFAULT NOW())

---

## STEP 6: Test Manual INSERT Queries

```bash
# Test INSERT into raw_logs
docker exec -it siembox-database psql -U siembox -d siembox -c "
INSERT INTO raw_logs (timestamp, raw_message, source_ip, facility, severity, hostname)
VALUES (NOW(), 'test message', '192.168.1.1', 1, 6, 'test-host')
RETURNING id, timestamp, raw_message, source_ip;
"
```

**Expected**: Should return the inserted row with an ID.

**If this fails**, capture the FULL error message including:
- ERROR code (e.g., 23505, 42P01, 42703)
- Error detail
- Error hint

---

## STEP 7: Check Current Data Counts

```bash
# Count all data in critical tables
docker exec -it siembox-database psql -U siembox -d siembox -c "
SELECT
  'users' as table_name, COUNT(*) as count FROM users
UNION ALL
SELECT 'parsers', COUNT(*) FROM parsers
UNION ALL
SELECT 'detection_rules', COUNT(*) FROM detection_rules
UNION ALL
SELECT 'raw_logs', COUNT(*) FROM raw_logs
UNION ALL
SELECT 'parsed_logs', COUNT(*) FROM parsed_logs
UNION ALL
SELECT 'alerts', COUNT(*) FROM alerts
ORDER BY table_name;
"
```

**Expected**:
- users: At least 1 (admin user)
- parsers: Should be 40+ (from seed data + Vaultwarden parser)
- detection_rules: Should be 40+ (from YAML files)
- raw_logs: 12M+ (based on error logs)
- parsed_logs: Should have data if parsers are working
- alerts: May be 0 or have data

---

## STEP 8: Check Parser Details

```bash
# List all parsers
docker exec -it siembox-database psql -U siembox -d siembox -c "
SELECT
  id,
  name,
  parser_type,
  enabled,
  priority,
  LEFT(description, 50) as description_preview
FROM parsers
ORDER BY priority, name;
"
```

**Expected**: Should see multiple parsers including "vaultwarden-access" from migration 004.

---

## STEP 9: Check Detection Rules

```bash
# List all detection rules
docker exec -it siembox-database psql -U siembox -d siembox -c "
SELECT
  id,
  name,
  severity,
  enabled,
  tags
FROM detection_rules
ORDER BY severity DESC, name
LIMIT 20;
"
```

**Expected**: Should see multiple rules with various severities.

---

## STEP 10: Check for Database Constraints Issues

```bash
# Check all constraints on raw_logs and parsed_logs
docker exec -it siembox-database psql -U siembox -d siembox -c "
SELECT
  conname AS constraint_name,
  conrelid::regclass AS table_name,
  contype AS constraint_type,
  pg_get_constraintdef(oid) AS constraint_definition
FROM pg_constraint
WHERE conrelid IN ('raw_logs'::regclass, 'parsed_logs'::regclass)
ORDER BY table_name, constraint_type;
"
```

**Look for**:
- Foreign key constraints that might fail
- Check constraints that might reject data
- Unique constraints that might cause conflicts

---

## STEP 11: Check Recent Raw Logs for Errors

```bash
# Check the most recent raw_logs entries (around the error ID 12052775)
docker exec -it siembox-database psql -U siembox -d siembox -c "
SELECT
  id,
  timestamp,
  LEFT(raw_message, 80) as message_preview,
  source_ip,
  facility,
  severity,
  hostname
FROM raw_logs
WHERE id >= 12052775
ORDER BY id
LIMIT 10;
"
```

**Check if**: The query succeeds or fails. If it succeeds, data WAS being inserted despite the errors.

---

## STEP 12: Check PostgreSQL Error Log

```bash
# Check PostgreSQL error log
docker exec siembox-database cat /var/lib/postgresql/data/log/postgresql-*.log | tail -100
```

**OR if log location is different**:

```bash
docker exec siembox-database psql -U siembox -d siembox -c "SHOW log_destination;"
docker exec siembox-database psql -U siembox -d siembox -c "SHOW log_directory;"
docker exec siembox-database psql -U siembox -d siembox -c "SHOW log_filename;"
```

---

## STEP 13: Check Backend Error Object Serialization

The issue is in `/backend/src/config/database.ts` line 35:
```typescript
logger.error('Database query error:', { text, error });
```

The `error` object might not serialize properly with Winston's JSON formatter. Check what the actual error type is:

```bash
# Create a test script to check error serialization
docker exec siembox-backend node -e "
const { Pool } = require('pg');
const pool = new Pool({
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD
});

// Try to insert with a deliberate error (non-existent column)
pool.query('INSERT INTO raw_logs (nonexistent_column) VALUES (\$1)', ['test'])
  .then(r => console.log('Unexpected success'))
  .catch(e => {
    console.log('=== ERROR OBJECT ANALYSIS ===');
    console.log('Type:', typeof e);
    console.log('Constructor:', e.constructor.name);
    console.log('Message:', e.message);
    console.log('Code:', e.code);
    console.log('Detail:', e.detail);
    console.log('Hint:', e.hint);
    console.log('Position:', e.position);
    console.log('Stack:', e.stack);
    console.log('');
    console.log('=== JSON.stringify(error) ===');
    console.log(JSON.stringify(e, null, 2));
    console.log('');
    console.log('=== Object.keys(error) ===');
    console.log(Object.keys(e));
    console.log('');
    console.log('=== Object.getOwnPropertyNames(error) ===');
    console.log(Object.getOwnPropertyNames(e));
  })
  .finally(() => process.exit());
"
```

---

## EXPECTED FINDINGS

Based on the symptoms, likely causes are:

### 1. ERROR OBJECT SERIALIZATION ISSUE (MOST LIKELY)
PostgreSQL Error objects don't serialize properly with `JSON.stringify()`. The properties (message, code, detail) are on the prototype chain, not own properties.

**Fix Required**: Update error logging to explicitly extract error properties.

### 2. MIGRATION NUMBERING CONFLICT (CONFIRMED)
Two "003" migrations will cause issues. Need to renumber:
- Rename `003_system_settings.sql` to `004_system_settings.sql`
- Rename `004-add-vaultwarden-parser.sql` to `005-add-vaultwarden-parser.sql`
- Rename `005-add-ip-whitelist.sql` to `006-add-ip-whitelist.sql`

### 3. POSSIBLE FOREIGN KEY CONSTRAINT VIOLATION
If `parsers` table doesn't have the expected parsers, INSERT into `parsed_logs` with `parser_id` will fail.

### 4. POSSIBLE SEQUENCE ISSUE
If `raw_logs` sequence is out of sync, INSERTs might fail with unique constraint violations.

---

## IMMEDIATE ACTION PLAN

1. **Run diagnostics** (Steps 1-13 above) and capture ALL output
2. **Fix error logging** to properly capture PostgreSQL errors
3. **Fix migration numbering** to resolve conflicts
4. **Re-run migrations** if schema is incorrect
5. **Test log ingestion** with sample data
6. **Verify UI** shows parsers and rules

---

## OUTPUT TEMPLATE

Please provide output in this format:

```
=== STEP 1: Container Status ===
[paste output]

=== STEP 2: Database Connectivity ===
[paste output]

=== STEP 3: Database Schema ===
[paste output]

[continue for all steps...]
```

**Focus on capturing**:
- Any ERRORS or WARNINGS
- Unexpected results
- Missing tables or columns
- Data counts that seem wrong
