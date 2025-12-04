# SIEMBox Auto-Import System Guide

**Date:** 2025-12-04
**Purpose:** Document automatic parser and detection rule import system
**Status:** ✅ Fully Implemented - Zero Configuration Required

---

## Overview

SIEMBox now features **automatic parser and detection rule import** on first startup. No manual import steps are required.

**What gets imported automatically:**
- **18 Parsers** - Phase 2 log parsers (NGINX Proxy Manager, Traefik, Caddy, Authelia, Vaultwarden, Pi-hole, Nextcloud, etc.)
- **40+ Detection Rules** - Phase 3 security rules (AUTH-*, PROXY-*, ACCESS-*, INFRA-*, EXFIL-*, APP-*, IOT-*, PWDMGR-*)

**How it works:**
1. **Migration 007** imports 11 Phase 2 parsers via SQL INSERT statements
2. **Seed Data Script** imports 40 YAML detection rules on first run
3. Both operations are **idempotent** (safe to re-run)
4. All imports happen **automatically** during `docker compose up`

---

## Zero-Configuration Deployment

### Step 1: Pull Latest Code

```bash
cd /path/to/siembox
git pull origin develop
```

### Step 2: Rebuild and Start

```bash
docker compose build
docker compose up -d
```

**That's it!** Parsers and rules are imported automatically.

### Step 3: Verify Import

Check counts:

```bash
docker exec siembox-postgres psql -U siembox -d siembox -c "
SELECT
  (SELECT COUNT(*) FROM parsers) as parser_count,
  (SELECT COUNT(*) FROM detection_rules) as rule_count;
"
```

**Expected output:**
```
 parser_count | rule_count
--------------+------------
           18 |         40+
```

Or check via health endpoint:

```bash
curl http://localhost:8080/health/seed-status
```

**Expected response:**
```json
{
  "parsers": 18,
  "rules": 40,
  "seeded": true
}
```

---

## How Auto-Import Works

### Parser Import (Migration 007)

**File:** `backend/migrations/007_import_phase2_parsers.sql`

- Runs during database migration sequence (001 → 007)
- Deletes existing parsers by name (idempotent)
- Inserts 11 Phase 2 parsers with regex patterns and field mappings
- Parsers include: NGINX Proxy Manager, Traefik, Caddy, Standard NGINX, Authelia, Authentik, Keycloak, Nextcloud, Pi-hole

**Parsers added:**
1. nginx-proxy-manager-access
2. nginx-proxy-manager-error
3. traefik-access
4. caddy-access
5. standard-nginx-access
6. standard-nginx-error
7. authelia-access
8. authentik-audit
9. keycloak-event
10. nextcloud-access
11. pihole-query

### Rule Import (Seed Data)

**File:** `backend/src/scripts/seed-data.ts`

- Runs after migrations during server startup
- Checks if `detection_rules` table is empty
- If empty, imports all YAML files from `rules/` directory
- Skips import if rules already exist (idempotent)

**Rules imported:**
- **11 AUTH rules** - Authentication attack detection
- **8 PROXY rules** - Reverse proxy security monitoring
- **4 ACCESS rules** - Unauthorized access detection
- **4 INFRA rules** - Infrastructure security monitoring
- **3 EXFIL rules** - Data exfiltration detection
- **4 APP rules** - Application security monitoring
- **2 IOT rules** - IoT device security
- **4 PWDMGR rules** - Password manager security

---

## Verifying Auto-Import

### 1. Check Logs

During startup, you'll see:

```
[info]: Running migration: 007_import_phase2_parsers.sql
[info]: Migration complete
[info]: Checking if seed data is needed...
[info]: Seeding detection rules from YAML files...
[info]: Starting rule import from YAML files...
[info]: Found 40 YAML rule files
[info]: Rule imported successfully { id: 11, name: 'SSH Brute Force Detection', severity: 'high' }
...
[info]: ✓ Successfully imported 38 new rules
[info]: - Skipped 2 existing rules
[info]: Seed data initialization complete
```

### 2. Check Parser Count

```bash
docker exec siembox-postgres psql -U siembox -d siembox -c "
SELECT COUNT(*) as total, COUNT(*) FILTER (WHERE enabled = true) as enabled
FROM parsers;
"
```

**Expected:** 18 total, 18 enabled

### 3. Check Rule Count by Category

```bash
docker exec siembox-postgres psql -U siembox -d siembox -c "
SELECT
  SUBSTRING(name FROM '^[A-Z]+-') as category,
  COUNT(*) as rule_count,
  COUNT(CASE WHEN enabled = true THEN 1 END) as enabled_count
FROM detection_rules
GROUP BY SUBSTRING(name FROM '^[A-Z]+-')
ORDER BY category;
"
```

**Expected output:**
```
 category | rule_count | enabled_count
----------+------------+---------------
 ACCESS-  |          4 |             4
 APP-     |          4 |             4
 AUTH-    |         11 |            11
 EXFIL-   |          3 |             3
 INFRA-   |          4 |             4
 IOT-     |          2 |             2
 PROXY-   |          8 |             8
 PWDMGR-  |          4 |             4
```

### 4. Verify in UI

1. Navigate to http://your-server:3000
2. Log in with admin credentials
3. Go to **Parsers** page → should see 18 parsers
4. Go to **Detection Rules** page → should see 40+ rules
5. All rules should be **enabled** by default

---

## Troubleshooting

### Migration 006 Error: "idx_ip_whitelist_cidr already exists"

**Status:** ✅ Fixed in latest commit

**Solution:** Migration 006 now uses `CREATE INDEX IF NOT EXISTS` for idempotency.

**If you see this error:**
1. Pull latest code: `git pull origin develop`
2. Rebuild backend: `docker compose build backend`
3. Restart: `docker compose up -d`

### Migration 007 Takes Long Time

**Normal behavior:** Migration 007 inserts 11 large parser records with regex patterns. This can take 10-30 seconds.

**Watch logs:**
```bash
docker logs -f siembox-backend
```

Look for: `[info]: Running migration: 007_import_phase2_parsers.sql`

### Seed Data Not Importing Rules

**Check logs:**
```bash
docker logs siembox-backend | grep "seed"
```

**Possible causes:**
1. Rules already exist → Script skips import (normal behavior)
2. Database connectivity issue → Check postgres logs
3. YAML file errors → Check specific error messages

**Force re-import (if needed):**
```bash
# Delete all rules
docker exec siembox-postgres psql -U siembox -d siembox -c "DELETE FROM detection_rules;"

# Restart backend to trigger auto-import
docker compose restart backend
```

### Parsers Not Showing in UI

**Verify parsers exist:**
```bash
docker exec siembox-postgres psql -U siembox -d siembox -c "SELECT id, name, enabled FROM parsers ORDER BY priority LIMIT 20;"
```

**If parsers exist but not in UI:**
1. Clear browser cache
2. Check browser console for API errors
3. Verify backend is running: `docker ps | grep backend`
4. Check backend logs: `docker logs siembox-backend --tail 100`

### Rules Not Showing in UI

**Verify rules exist:**
```bash
docker exec siembox-postgres psql -U siembox -d siembox -c "SELECT COUNT(*) FROM detection_rules;"
```

**If rules exist but not in UI:**
1. Clear browser cache and refresh
2. Check browser console for JavaScript errors
3. Verify API endpoint: `curl http://localhost:8080/api/rules`
4. Check backend logs for API errors

---

## Success Criteria

✅ **Auto-Import Successful When:**
1. Backend container starts without errors
2. Database has 18 parsers
3. Database has 40+ detection rules
4. All parsers visible in **Parsers** UI page
5. All rules visible in **Detection Rules** UI page
6. Health endpoint returns `"seeded": true`

---

## Manual Import (If Needed)

If for any reason auto-import doesn't work, you can manually trigger imports:

### Manual Parser Import

Parsers are imported via migration 007. To re-run:

```bash
# Drop and recreate parsers (WARNING: destructive)
docker exec siembox-postgres psql -U siembox -d siembox -c "DELETE FROM parsers;"

# Restart to trigger migrations
docker compose restart backend
```

### Manual Rule Import

```bash
docker compose run --rm backend npm run import-rules
```

**Expected output:**
```
[info]: Starting rule import from YAML files...
[info]: Found 40 YAML rule files
[info]: Rule import complete { total: 40, imported: 40, skipped: 0, failed: 0 }
[info]: ✓ Successfully imported 40 new rules
```

---

## Architecture Details

### Database Migration Sequence

```
001_init_tables.sql          - Core schema (users, logs, parsers, rules, alerts)
002_seed_demo_data.sql        - Demo user and initial parsers
003_syslog_settings.sql       - Syslog server configuration
004_log_severity_filtering.sql - Log filtering enhancements
005_vaultwarden_parser.sql    - Vaultwarden password manager parser
006_add_ip_whitelist.sql      - IP whitelist for admin access control
007_import_phase2_parsers.sql - 11 Phase 2 parsers (NGINX, Traefik, etc.)
```

### Seed Data Flow

```
server.ts startup
  ↓
runMigrations() - Executes 001-007
  ↓
seedData() - Checks if rules needed
  ↓
importRules() - Imports YAML files from rules/
  ↓
Server ready with parsers and rules
```

### Idempotency Design

**Migration 007:**
```sql
-- Delete existing parsers before inserting
DELETE FROM parsers WHERE name IN ('nginx-proxy-manager-access', ...);

-- Insert parsers
INSERT INTO parsers (name, ...) VALUES (...);
```

**Seed Data:**
```typescript
// Check if rules already exist
const result = await query('SELECT COUNT(*) FROM detection_rules');
if (count > 0) {
  logger.info('Rules already present, skipping seed');
  return true;
}

// Import only if empty
await importRules();
```

**Import Rules:**
```typescript
// Check for duplicate before inserting
const existing = await DetectionRuleModel.findByName(yamlRule.name);
if (existing) {
  logger.info('Rule already exists, skipping');
  return false;
}

// Insert only if not exists
await DetectionRuleModel.create({...});
```

---

## Next Steps After Auto-Import

1. **Verify Alert Generation** - Send test logs to trigger rules
2. **Monitor False Positives** - First 24 hours will show baseline patterns
3. **Tune Thresholds** - Adjust rule thresholds based on environment
4. **Configure IP Whitelist** - Add trusted admin IPs to reduce alerts
5. **Review Parser Priority** - Adjust parser order if needed
6. **Enable/Disable Rules** - Turn off rules not relevant to your environment

---

## Test Rule Triggering

Send a test SSH brute force log:

```bash
for i in {1..6}; do
  echo "<13>Dec  4 12:34:56 testhost sshd[12345]: Failed password for admin from 192.168.1.100 port 22 ssh2" | nc -u -w1 your-siembox-server 514
  sleep 1
done
```

Check if alert was created:

```bash
docker exec siembox-postgres psql -U siembox -d siembox -c "
SELECT title, severity, created_at
FROM alerts
WHERE title LIKE '%SSH Brute Force%'
ORDER BY created_at DESC
LIMIT 1;
"
```

---

## Support

**Documentation:**
- `README.md` - Project overview and quick start
- `DEPLOYMENT.md` - Full deployment guide
- `docs/reference/RULES.md` - Detection rule documentation
- `docs/reference/PARSERS.md` - Parser creation guide

**Troubleshooting:**
- `docs/operations/TROUBLESHOOTING.md` - Common issues
- GitHub Issues: https://github.com/cladkins/SIEMBOX/issues

**Git Repository:**
- https://github.com/cladkins/SIEMBOX

---

## Rollback Procedure

If auto-import causes issues:

### 1. Stop backend

```bash
docker compose stop backend
```

### 2. Delete imported data

```bash
# Delete all parsers and rules
docker exec siembox-postgres psql -U siembox -d siembox -c "
DELETE FROM parsers WHERE name IN (
  'nginx-proxy-manager-access',
  'nginx-proxy-manager-error',
  'traefik-access',
  'caddy-access',
  'standard-nginx-access',
  'standard-nginx-error',
  'authelia-access',
  'authentik-audit',
  'keycloak-event',
  'nextcloud-access',
  'pihole-query'
);

DELETE FROM detection_rules WHERE name LIKE 'AUTH-%'
   OR name LIKE 'PROXY-%'
   OR name LIKE 'ACCESS-%'
   OR name LIKE 'INFRA-%'
   OR name LIKE 'EXFIL-%'
   OR name LIKE 'APP-%'
   OR name LIKE 'IOT-%'
   OR name LIKE 'PWDMGR-%';
"
```

### 3. Restart backend

```bash
docker compose start backend
```

### 4. Verify

```bash
docker exec siembox-postgres psql -U siembox -d siembox -c "
SELECT
  (SELECT COUNT(*) FROM parsers) as parser_count,
  (SELECT COUNT(*) FROM detection_rules) as rule_count;
"
```

Should return to original counts (7 parsers, 10 rules).

---

**Ready?** Just run `docker compose up -d` and everything imports automatically! 🚀
