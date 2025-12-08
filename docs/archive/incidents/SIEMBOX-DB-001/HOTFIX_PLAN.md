# SIEMBox Database Error - Hotfix Implementation Plan

**Date**: 2025-12-03
**Issue**: SIEMBOX-DB-001
**Priority**: CRITICAL

---

## Hotfix 1: Fix Error Logging (IMMEDIATE)

**File**: `/backend/src/config/database.ts`
**Problem**: PostgreSQL errors not serializing properly, showing empty `{}` in logs
**Impact**: Cannot diagnose database failures

### Current Code (Line 27-37):
```typescript
export const query = async (text: string, params?: any[]) => {
  const start = Date.now();
  try {
    const res = await pool.query(text, params);
    const duration = Date.now() - start;
    logger.debug('Executed query', { text, duration, rows: res.rowCount });
    return res;
  } catch (error) {
    logger.error('Database query error:', { text, error });
    throw error;
  }
};
```

### Fixed Code:
```typescript
export const query = async (text: string, params?: any[]) => {
  const start = Date.now();
  try {
    const res = await pool.query(text, params);
    const duration = Date.now() - start;
    logger.debug('Executed query', { text, duration, rows: res.rowCount });
    return res;
  } catch (error: any) {
    // Extract PostgreSQL error details for proper logging
    const errorDetails = {
      message: error.message || 'Unknown error',
      code: error.code || 'UNKNOWN',
      detail: error.detail || null,
      hint: error.hint || null,
      position: error.position || null,
      where: error.where || null,
      schema: error.schema || null,
      table: error.table || null,
      column: error.column || null,
      dataType: error.dataType || null,
      constraint: error.constraint || null,
    };

    logger.error('Database query error:', {
      query: text,
      params: params,
      error: errorDetails,
      stack: error.stack,
    });

    throw error;
  }
};
```

### Benefits:
- Captures all PostgreSQL error details
- Includes error code for quick diagnosis
- Shows query and parameters that caused error
- Maintains stack trace for debugging

---

## Hotfix 2: Fix Migration Numbering (HIGH PRIORITY)

**Problem**: Two migrations have "003" prefix
**Impact**: Unpredictable migration order, potential schema inconsistency

### Current State:
```
/backend/migrations/
  001_initial_schema.sql
  002_seed_data.sql
  003_log_shippers.sql       (Nov 30 - NEWER)
  003_system_settings.sql    (Nov 25 - OLDER) ← CONFLICT
  004-add-vaultwarden-parser.sql
  005-add-ip-whitelist.sql
```

### Target State:
```
/backend/migrations/
  001_initial_schema.sql
  002_seed_data.sql
  003_log_shippers.sql
  004_system_settings.sql    ← RENAMED from 003
  005_add_vaultwarden_parser.sql ← RENAMED from 004 + underscore
  006_add_ip_whitelist.sql   ← RENAMED from 005 + underscore
```

### Commands to Execute:
```bash
cd /Users/chrisadkins/Projects/SIEMBox/backend/migrations

# Rename in reverse order to avoid conflicts
mv 005-add-ip-whitelist.sql 006_add_ip_whitelist.sql
mv 004-add-vaultwarden-parser.sql 005_add_vaultwarden_parser.sql
mv 003_system_settings.sql 004_system_settings.sql
```

### Git Commands:
```bash
cd /Users/chrisadkins/Projects/SIEMBox

# Add renamed files
git add backend/migrations/

# Check status
git status
```

---

## Hotfix 3: Add Migration Tracking (MEDIUM PRIORITY)

**Problem**: No tracking of which migrations have run
**Impact**: Cannot detect duplicate runs, no rollback capability

### New File: `/backend/migrations/000_migration_tracking.sql`

```sql
-- Migration Tracking System
-- Run this FIRST before any other migrations

-- Create migration tracking table
CREATE TABLE IF NOT EXISTS schema_migrations (
  version VARCHAR(255) PRIMARY KEY,
  description TEXT,
  executed_at TIMESTAMP DEFAULT NOW(),
  execution_time_ms INTEGER,
  success BOOLEAN DEFAULT true
);

-- Create index for quick lookups
CREATE INDEX IF NOT EXISTS idx_migrations_executed ON schema_migrations(executed_at DESC);

-- Add comment
COMMENT ON TABLE schema_migrations IS 'Tracks executed database migrations to prevent duplicates';

-- Record this migration
INSERT INTO schema_migrations (version, description, execution_time_ms)
VALUES ('000', 'Migration tracking system', 0)
ON CONFLICT (version) DO NOTHING;
```

### Update Migration Script: `/backend/src/scripts/migrate.ts`

Add migration tracking logic:

```typescript
const runMigrations = async () => {
  try {
    logger.info('Starting database migrations...');

    // Ensure migration tracking table exists
    await pool.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version VARCHAR(255) PRIMARY KEY,
        description TEXT,
        executed_at TIMESTAMP DEFAULT NOW(),
        execution_time_ms INTEGER,
        success BOOLEAN DEFAULT true
      );
    `);

    const migrationsDir = path.join(__dirname, '../../migrations');
    const migrationFiles = fs
      .readdirSync(migrationsDir)
      .filter((file) => file.endsWith('.sql'))
      .sort();

    for (const file of migrationFiles) {
      const version = file.replace('.sql', '');

      // Check if migration already ran
      const checkResult = await pool.query(
        'SELECT version FROM schema_migrations WHERE version = $1',
        [version]
      );

      if (checkResult.rows.length > 0) {
        logger.info(`Skipping migration (already executed): ${file}`);
        continue;
      }

      logger.info(`Running migration: ${file}`);
      const filePath = path.join(migrationsDir, file);
      let sql = fs.readFileSync(filePath, 'utf8');

      // Replace placeholder password hash with actual hashed password
      if (file === '002_seed_data.sql') {
        const defaultPassword = process.env.DEFAULT_ADMIN_PASSWORD || 'changeme';
        const passwordHash = await bcrypt.hash(defaultPassword, 10);
        sql = sql.replace('$2b$10$placeholder', passwordHash);
      }

      const start = Date.now();
      try {
        await pool.query(sql);
        const duration = Date.now() - start;

        // Record successful migration
        await pool.query(
          `INSERT INTO schema_migrations (version, description, execution_time_ms, success)
           VALUES ($1, $2, $3, true)`,
          [version, file, duration]
        );

        logger.info(`Migration completed: ${file} (${duration}ms)`);
      } catch (error: any) {
        // Record failed migration
        await pool.query(
          `INSERT INTO schema_migrations (version, description, execution_time_ms, success)
           VALUES ($1, $2, $3, false)`,
          [version, file, Date.now() - start]
        );
        throw error;
      }
    }

    logger.info('All migrations completed successfully!');

    // Show migration history
    const history = await pool.query(
      'SELECT version, executed_at, execution_time_ms, success FROM schema_migrations ORDER BY version'
    );
    logger.info('Migration history:', history.rows);

    // Display default admin credentials
    logger.warn('===============================================');
    logger.warn('DEFAULT ADMIN CREDENTIALS:');
    logger.warn('Username: admin');
    logger.warn(`Password: ${process.env.DEFAULT_ADMIN_PASSWORD || 'changeme'}`);
    logger.warn('PLEASE CHANGE THE PASSWORD AFTER FIRST LOGIN!');
    logger.warn('===============================================');

    process.exit(0);
  } catch (error: any) {
    logger.error('Migration failed:', {
      message: error.message,
      code: error.code,
      detail: error.detail,
      hint: error.hint,
    });
    process.exit(1);
  }
};
```

---

## Hotfix 4: Add Database Health Check Endpoint (OPTIONAL)

**File**: `/backend/src/routes/health.ts` (NEW)

```typescript
import { Router } from 'express';
import { query } from '../config/database';
import { logger } from '../utils/logger';

const router = Router();

router.get('/health/database', async (req, res) => {
  try {
    const checks = {
      connectivity: false,
      tables: {
        raw_logs: false,
        parsed_logs: false,
        parsers: false,
        detection_rules: false,
      },
      counts: {
        parsers: 0,
        rules: 0,
        raw_logs: 0,
        parsed_logs: 0,
      },
      recent_ingestion: false,
    };

    // Check connectivity
    const timeResult = await query('SELECT NOW() as current_time');
    checks.connectivity = true;

    // Check tables exist
    const tablesResult = await query(`
      SELECT table_name
      FROM information_schema.tables
      WHERE table_schema = 'public'
        AND table_type = 'BASE TABLE'
        AND table_name IN ('raw_logs', 'parsed_logs', 'parsers', 'detection_rules')
    `);

    tablesResult.rows.forEach((row: any) => {
      checks.tables[row.table_name as keyof typeof checks.tables] = true;
    });

    // Get counts
    const countResult = await query(`
      SELECT
        (SELECT COUNT(*) FROM parsers) as parsers,
        (SELECT COUNT(*) FROM detection_rules) as rules,
        (SELECT COUNT(*) FROM raw_logs) as raw_logs,
        (SELECT COUNT(*) FROM parsed_logs) as parsed_logs
    `);
    checks.counts = countResult.rows[0];

    // Check recent ingestion (last 5 minutes)
    const recentResult = await query(`
      SELECT COUNT(*) as count
      FROM raw_logs
      WHERE created_at > NOW() - INTERVAL '5 minutes'
    `);
    checks.recent_ingestion = parseInt(recentResult.rows[0].count) > 0;

    // Determine overall health
    const healthy =
      checks.connectivity &&
      checks.tables.raw_logs &&
      checks.tables.parsed_logs &&
      checks.tables.parsers &&
      checks.tables.detection_rules &&
      checks.counts.parsers > 0 &&
      checks.counts.rules > 0;

    res.status(healthy ? 200 : 503).json({
      status: healthy ? 'healthy' : 'unhealthy',
      timestamp: new Date().toISOString(),
      checks,
    });
  } catch (error: any) {
    logger.error('Health check failed:', {
      message: error.message,
      code: error.code,
    });

    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: error.message,
    });
  }
});

export default router;
```

**Update** `/backend/src/index.ts` to include health routes:

```typescript
import healthRoutes from './routes/health';

// ... existing code ...

app.use('/api', healthRoutes);
```

---

## Deployment Plan

### Phase 1: Immediate (Can deploy separately)
1. **Fix error logging** (Hotfix 1)
   - Update `database.ts`
   - Restart backend container
   - Verify errors now show details

### Phase 2: Migration Fix (Requires care)
1. **Backup database** first
   ```bash
   docker exec siembox-database pg_dump -U siembox siembox > backup.sql
   ```

2. **Rename migration files** (Hotfix 2)
   - Execute rename commands
   - Commit to Git

3. **Optional: Re-run migrations** (if schema is broken)
   ```bash
   docker exec siembox-backend npm run migrate
   ```

### Phase 3: Enhanced Tracking (Optional)
1. **Add migration tracking** (Hotfix 3)
   - Update migration script
   - Add tracking table
   - Re-run migrations to populate tracking

2. **Add health check** (Hotfix 4)
   - Add health route
   - Update index.ts
   - Test endpoint

---

## Testing Checklist

After deploying hotfixes:

- [ ] Backend container restarts successfully
- [ ] Database errors show full details in logs
- [ ] Can manually INSERT into raw_logs
- [ ] Can manually INSERT into parsed_logs
- [ ] Parser count is 41+ (including Vaultwarden)
- [ ] Detection rule count is 40+
- [ ] Parsers appear in UI
- [ ] Rules appear in UI
- [ ] New logs successfully ingest
- [ ] Health check endpoint returns 200 OK
- [ ] No error logs during normal operation

---

## Rollback Plan

If hotfixes cause issues:

### Rollback Hotfix 1 (Error Logging)
```bash
git checkout HEAD~1 backend/src/config/database.ts
docker compose restart backend
```

### Rollback Hotfix 2 (Migration Rename)
```bash
git checkout HEAD~1 backend/migrations/
docker compose restart backend
```

### Rollback Database
```bash
# Restore from backup
docker exec -i siembox-database psql -U siembox siembox < backup.sql
```

---

## Monitoring After Deployment

Watch these metrics for 24 hours:
- Backend error rate
- Database connection errors
- Log ingestion rate
- Parser success rate
- Rule evaluation rate
- Alert generation rate

---

**Prepared by**: Claude (DevOps Incident Responder)
**Reviewed by**: [Pending]
**Approved by**: [Pending]
