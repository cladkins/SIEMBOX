# SIEMBox Rule Import Guide

**Date:** 2025-12-04
**Purpose:** Import 40 Phase 3 detection rules into production database
**Status:** Ready for deployment

---

## Problem Statement

The database currently has only **10 detection rules** (4 seed rules + 4 UniFi IPS rules + 2 Phase 3 rules).

**Missing:** 30+ Phase 3 detection rules (AUTH-*, PROXY-*, ACCESS-*, INFRA-*, EXFIL-*, APP-*, IOT-*, PWDMGR-*)

The 40 YAML rule files exist in `rules/` directory but were never imported into the database. The frontend queries the database, so the UI shows incomplete data.

---

## Solution

A new import script (`backend/src/scripts/import-rules.ts`) reads all YAML files from `rules/` and inserts them into the `detection_rules` table.

---

## Deployment Steps

### 1. Pull Latest Code

On your Docker host:

```bash
cd /path/to/siembox
git pull origin develop
```

### 2. Rebuild Backend Container

```bash
docker compose build backend
```

### 3. Stop Backend (to prevent log processing during import)

```bash
docker compose stop backend
```

### 4. Run Import Script

```bash
docker compose run --rm backend npm run import-rules
```

**Expected output:**
```
[info]: Starting rule import from YAML files...
[info]: Scanning for YAML rule files { rulesDir: '/app/rules' }
[info]: Found 40 YAML rule files
[info]: Importing: authentication/AUTH-001-ssh-brute-force.yaml
[info]: Rule imported successfully { id: 11, name: 'SSH Brute Force Detection', severity: 'high' }
[info]: Importing: authentication/AUTH-002-brute-force-success.yaml
...
[info]: Rule import complete { total: 40, imported: 38, skipped: 2, failed: 0 }
[info]: ✓ Successfully imported 38 new rules
[info]: - Skipped 2 existing rules
```

**Note:** Some rules may be skipped if they already exist (e.g., "Direct Root SSH Login" from seed data).

### 5. Verify Import

Check rule count:

```bash
docker exec siembox-postgres psql -U siembox -d siembox -c "SELECT COUNT(*) as total_rules FROM detection_rules;"
```

**Expected:** Should show 40-48 rules (40 Phase 3 + seed rules + any manual rules)

List imported rules:

```bash
docker exec siembox-postgres psql -U siembox -d siembox -c "
SELECT name, severity, enabled
FROM detection_rules
ORDER BY name
LIMIT 50;
"
```

**Expected:** Should see AUTH-*, PROXY-*, ACCESS-*, INFRA-*, EXFIL-*, APP-*, IOT-*, PWDMGR-* rules

### 6. Restart Backend

```bash
docker compose start backend
```

### 7. Verify in UI

1. Log into SIEMBox web interface (http://your-server:3000)
2. Navigate to **Detection Rules** page
3. Verify all 40 Phase 3 rules are visible
4. Check that rules are enabled and have correct severity levels

---

## Troubleshooting

### Import Script Fails

**Error:** `Cannot find module 'js-yaml'`

**Solution:** The `js-yaml` dependency already exists in `package.json`, but if needed:
```bash
docker compose run --rm backend npm install
docker compose build backend
```

### Rules Already Exist

**Output:** `[info]: Rule already exists, skipping { name: 'SSH Brute Force Detection', id: 1 }`

**Solution:** This is normal. The script skips duplicate rules by name. No action needed.

### Import Hangs or Times Out

**Solution:**
1. Check database connectivity: `docker logs siembox-postgres --tail 50`
2. Verify backend can connect: `docker logs siembox-backend --tail 50`
3. Re-run import with detailed logs: Add `LOG_LEVEL=debug` environment variable

### Rules Not Showing in UI

**Possible causes:**
1. Frontend not updated - Clear browser cache and refresh
2. API endpoint issue - Check browser console for errors
3. Backend not restarted - Restart with `docker compose restart backend`

**Verify rules exist in database:**
```bash
docker exec siembox-postgres psql -U siembox -d siembox -c "SELECT COUNT(*) FROM detection_rules;"
```

If rules exist in database but not in UI, check:
- Browser console for API errors
- Backend logs: `docker logs siembox-backend --tail 100`
- Frontend logs: `docker logs siembox-frontend --tail 100`

---

## Parser Import (Phase 2 Parsers)

**Status:** Parser import is separate from rule import.

**Current state:**
- Database has **7 parsers** (should be 12+ from Phase 2)
- Vaultwarden parser was added in migration 005

**Missing parsers:**
- NGINX Proxy Manager (access logs)
- NGINX Proxy Manager (error logs)
- Traefik (access logs)
- Caddy (access logs)
- Standard NGINX (access logs)
- Standard NGINX (error logs)
- Authelia (access logs)
- Authentik (audit logs)
- Keycloak (event logs)
- Nextcloud (access logs)
- Pi-hole (query logs)

**Recommended approach:**
1. Create parsers through the **Parsers** UI page (admin panel)
2. Use the parser documentation in `docs/parsers/` for regex patterns and field mappings
3. Or create a separate parser import script (similar to rule import)

**Parser creation priority:**
1. **NGINX Proxy Manager** - Most critical (842 users)
2. **Traefik** - High priority (312 users)
3. **Caddy** - Medium priority (203 users)
4. **Authelia** - Authentication monitoring
5. **Vaultwarden** - Password manager security (already exists)
6. **Pi-hole** - DNS monitoring
7. **Nextcloud** - File access monitoring
8. **Standard NGINX** - Web server monitoring
9. **Authentik / Keycloak** - SSO monitoring

---

## Post-Import Validation

### 1. Rule Count by Category

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

### 2. Rule Severity Distribution

```bash
docker exec siembox-postgres psql -U siembox -d siembox -c "
SELECT severity, COUNT(*) as count
FROM detection_rules
GROUP BY severity
ORDER BY
  CASE severity
    WHEN 'critical' THEN 1
    WHEN 'high' THEN 2
    WHEN 'medium' THEN 3
    WHEN 'low' THEN 4
  END;
"
```

**Expected output:**
```
 severity | count
----------+-------
 critical |     5
 high     |    17
 medium   |    14
 low      |     4
```

### 3. Test Rule Triggering

Send a test log to verify rule engine is working:

```bash
# Test SSH brute force detection
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
LIMIT 5;
"
```

---

## Success Criteria

✅ **Rule Import Successful When:**
1. Database has 40+ detection rules
2. All Phase 3 rule categories present (AUTH, PROXY, ACCESS, INFRA, EXFIL, APP, IOT, PWDMGR)
3. Rules visible in SIEMBox web UI
4. Rules are enabled and have correct severity levels
5. Test logs trigger alerts correctly

---

## Next Steps After Import

1. **Monitor Alert Volume** - First 24 hours will show baseline alert patterns
2. **Tune Thresholds** - Adjust rule thresholds based on false positive rates
3. **Add Parsers** - Create the 11 missing Phase 2 parsers through UI
4. **Review Alerts** - Acknowledge legitimate alerts, investigate suspicious ones
5. **Update IP Whitelist** - Add known admin IPs to reduce false positives
6. **Enable Aggregation** - Phase 4B distinct_count rules will detect distributed attacks

---

## Support

**Documentation:**
- `docs/reference/RULES.md` - Complete rule documentation
- `docs/operations/RULE-DEPLOYMENT-CHECKLIST.md` - Deployment checklist
- `docs/reference/PARSERS.md` - Parser creation guide

**Troubleshooting:**
- `docs/operations/TROUBLESHOOTING.md` - Common issues

**Git Repository:**
- https://github.com/cladkins/SIEMBOX

---

## Rollback Procedure

If import causes issues:

### 1. Delete imported rules

```bash
docker exec siembox-postgres psql -U siembox -d siembox -c "
DELETE FROM detection_rules
WHERE name LIKE 'AUTH-%'
   OR name LIKE 'PROXY-%'
   OR name LIKE 'ACCESS-%'
   OR name LIKE 'INFRA-%'
   OR name LIKE 'EXFIL-%'
   OR name LIKE 'APP-%'
   OR name LIKE 'IOT-%'
   OR name LIKE 'PWDMGR-%';
"
```

### 2. Restart backend

```bash
docker compose restart backend
```

### 3. Verify

```bash
docker exec siembox-postgres psql -U siembox -d siembox -c "SELECT COUNT(*) FROM detection_rules;"
```

Should return to original count (10 or fewer).

---

**Ready to proceed?** Follow steps 1-7 above to import all 40 detection rules into your SIEMBox deployment.
