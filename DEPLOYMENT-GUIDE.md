# SIEMBox Deployment Guide

**Date:** 2025-12-04
**Purpose:** Simple deployment instructions for parsers and detection rules
**Status:** ✅ Production Ready

---

## Quick Deployment

### Prerequisites
- Docker and Docker Compose installed
- SIEMBox repository cloned
- PostgreSQL container running

### Steps

```bash
# 1. Pull latest code
git pull origin develop

# 2. Build backend
docker compose build backend

# 3. Insert 11 parsers into database
docker compose run --rm backend npm run direct-insert

# 4. Import 40+ detection rules
docker compose run --rm backend npm run import-rules

# 5. Start backend
docker compose up -d backend
```

### Verify

```bash
# Check counts
curl http://localhost:8080/health/database-status

# Expected response:
# {
#   "parsers": 18,
#   "rules": 40,
#   "ready": true
# }
```

---

## What Gets Installed

### 18 Parsers

**Reverse Proxies (Priority 40-50):**
1. nginx-proxy-manager-access (priority 50)
2. nginx-proxy-manager-error (priority 49)
3. traefik-access (priority 48, JSON)
4. caddy-access (priority 42, JSON)
5. standard-nginx-access (priority 40)
6. standard-nginx-error (priority 39)

**Authentication Services (Priority 20-25):**
7. authelia-access (priority 25)
8. authentik-audit (priority 24, JSON)
9. keycloak-event (priority 23)

**Applications (Priority 30-55):**
10. nextcloud-access (priority 35)
11. pihole-query (priority 30)
12. vaultwarden (priority 55) - *Already exists from migration 005*

**Plus existing seed parsers** (SSH, UniFi IPS, etc.)

### 40+ Detection Rules

**Authentication (11 rules):**
- AUTH-001: SSH Brute Force Detection
- AUTH-002: Brute Force Success After Failures
- AUTH-003: Password Spray Attack
- AUTH-004: Distributed Authentication Attack
- AUTH-005: Multiple Failed Logins (Single IP)
- AUTH-006: Failed Root Login Attempts
- AUTH-007: Authentication from Suspicious Countries
- AUTH-008: Off-Hours Authentication
- AUTH-009: Impossible Travel Detection
- AUTH-010: Account Lockout Pattern
- AUTH-011: Direct Root SSH Login

**Proxy Security (8 rules):**
- PROXY-001: SQL Injection Attempt
- PROXY-002: XSS Attack Pattern
- PROXY-003: Path Traversal Attack
- PROXY-004: Command Injection Attempt
- PROXY-005: Proxy Error Rate Spike
- PROXY-006: Unusual HTTP Methods
- PROXY-007: Large Response Size
- PROXY-008: Suspicious User Agent

**Access Control (4 rules):**
- ACCESS-001: Unauthorized Admin Access
- ACCESS-002: Access from Unknown IP
- ACCESS-003: Privilege Escalation Attempt
- ACCESS-004: Service Account Misuse

**Infrastructure (4 rules):**
- INFRA-001: Port Scan Detection
- INFRA-002: Multiple Services Targeted
- INFRA-003: High Volume of Requests
- INFRA-004: Unusual Outbound Traffic

**Data Exfiltration (3 rules):**
- EXFIL-001: Large Data Transfer
- EXFIL-002: Multiple File Downloads
- EXFIL-003: Data Upload to External Site

**Application Security (4 rules):**
- APP-001: File Upload Attack
- APP-002: Sensitive File Access
- APP-003: API Rate Limit Exceeded
- APP-004: Application Error Spike

**IoT Devices (2 rules):**
- IOT-001: IoT Device Compromise
- IOT-002: Unusual IoT Traffic Pattern

**Password Manager (4 rules):**
- PWDMGR-001: Failed Password Manager Login
- PWDMGR-002: Vault Access from New Device
- PWDMGR-003: Mass Password Export
- PWDMGR-004: Admin Console Access

---

## Troubleshooting

### "direct-insert command not found"

**Solution:** Build first, then run:
```bash
docker compose run --rm backend npm run build
docker compose run --rm backend npm run direct-insert
```

### "import-rules command not found"

**Solution:** Build first, then run:
```bash
docker compose run --rm backend npm run build
docker compose run --rm backend npm run import-rules
```

### Database connection errors

**Check PostgreSQL is running:**
```bash
docker ps | grep postgres
```

**Check backend can connect:**
```bash
docker logs siembox-backend --tail 50
```

### Parsers/Rules already exist

**This is normal.** Both scripts are idempotent:
- `direct-insert` deletes existing parsers before inserting
- `import-rules` skips duplicate rules by name

**To force re-import:**
```bash
# Delete all parsers
docker exec siembox-postgres psql -U siembox -d siembox -c "DELETE FROM parsers WHERE name IN ('nginx-proxy-manager-access', 'nginx-proxy-manager-error', 'traefik-access', 'caddy-access', 'standard-nginx-access', 'standard-nginx-error', 'authelia-access', 'authentik-audit', 'keycloak-event', 'nextcloud-access', 'pihole-query');"

# Delete all rules
docker exec siembox-postgres psql -U siembox -d siembox -c "DELETE FROM detection_rules WHERE name LIKE 'AUTH-%' OR name LIKE 'PROXY-%' OR name LIKE 'ACCESS-%' OR name LIKE 'INFRA-%' OR name LIKE 'EXFIL-%' OR name LIKE 'APP-%' OR name LIKE 'IOT-%' OR name LIKE 'PWDMGR-%';"

# Re-run imports
docker compose run --rm backend npm run direct-insert
docker compose run --rm backend npm run import-rules
```

---

## Verification

### Check Database Counts

```bash
docker exec siembox-postgres psql -U siembox -d siembox -c "
SELECT
  (SELECT COUNT(*) FROM parsers) as parser_count,
  (SELECT COUNT(*) FROM detection_rules) as rule_count;
"
```

**Expected:** 18 parsers, 40+ rules

### Check Rule Categories

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

### Check Parser Priority Order

```bash
docker exec siembox-postgres psql -U siembox -d siembox -c "
SELECT id, name, priority, enabled, parser_type
FROM parsers
ORDER BY priority DESC
LIMIT 20;
"
```

### Verify in UI

1. Navigate to http://your-server:3000
2. Log in (default: admin / changeme)
3. Go to **Parsers** page → should see 18 parsers
4. Go to **Detection Rules** page → should see 40+ rules
5. All parsers and rules should be **enabled** by default

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

## Architecture

### Deployment Flow

```
Pull code → Build backend → Direct insert parsers → Import rules → Start backend
```

### Scripts

1. **direct-insert-parsers.ts** - Inserts 11 Phase 2 parsers
   - Uses parameterized queries for safety
   - Idempotent (deletes before inserting)
   - Direct database connection via pg

2. **import-rules.ts** - Imports YAML rules from `rules/` directory
   - Reads all .yaml files recursively
   - Checks for duplicates by name
   - Stores original YAML and parsed logic

### Database Migrations

```
001_initial_schema.sql      - Core schema (users, logs, parsers, rules, alerts)
002_seed_data.sql            - Demo user and initial parsers
003_log_shippers.sql         - Log shipper management
004_system_settings.sql      - System configuration
005_add_vaultwarden_parser.sql - Vaultwarden password manager parser
006_add_ip_whitelist.sql     - IP whitelist for admin access control
```

**Note:** Migration 007 was removed. Parsers are now inserted via direct script.

---

## Success Criteria

✅ **Deployment Successful When:**
1. Backend container starts without errors
2. Database has 18 parsers
3. Database has 40+ detection rules
4. All parsers visible in UI
5. All rules visible in UI
6. Health endpoint returns `"ready": true`
7. Test logs trigger alerts correctly

---

## Next Steps After Deployment

1. **Configure Log Sources** - Point syslog to port 514
2. **Monitor Alerts** - Check initial alert volume
3. **Tune Thresholds** - Adjust based on false positive rate
4. **Add IP Whitelist** - Whitelist known admin IPs
5. **Customize Rules** - Enable/disable rules for your environment
6. **Review Parsers** - Adjust parser priority if needed

---

## Support

**Documentation:**
- `README.md` - Project overview
- `API.md` - REST API reference
- `docs/reference/RULES.md` - Rule documentation
- `docs/reference/PARSERS.md` - Parser documentation

**Troubleshooting:**
- `docs/operations/TROUBLESHOOTING.md` - Common issues

**Git Repository:**
- https://github.com/cladkins/SIEMBOX

---

## Rollback

If deployment causes issues:

```bash
# Stop backend
docker compose stop backend

# Delete imported data
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

# Restart backend
docker compose start backend
```

---

**Ready to deploy?** Just 3 commands and you're live! 🚀
