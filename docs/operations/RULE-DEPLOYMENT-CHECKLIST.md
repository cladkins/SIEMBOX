# Rule Deployment Checklist - 36 Ready Rules

**Status:** Ready for deployment (90% of total rules)
**Date:** 2025-12-03
**Blocked Rules:** 4 rules pending Phase 4 completion

---

## Deployment-Ready Rules (36 rules)

### Reverse Proxy Rules (8 rules) ✅
All PROXY rules are deployment-ready:

- ✅ **PROXY-001** - SQL Injection Detection (HIGH)
- ✅ **PROXY-002** - Command Injection Attempt (HIGH)
- ✅ **PROXY-003** - Path Traversal Attempt (MEDIUM)
- ✅ **PROXY-004** - Directory Enumeration Detection (MEDIUM)
- ✅ **PROXY-005** - Malicious User Agent Detection (MEDIUM)
- ✅ **PROXY-006** - HTTP Method Abuse (MEDIUM)
- ✅ **PROXY-007** - Large Request Body DoS (MEDIUM)
- ✅ **PROXY-008** - High Request Rate DoS (HIGH)

**Parser Dependencies:** NGINX Proxy Manager, Traefik, Caddy, Standard NGINX

---

### Data Exfiltration Rules (3 rules) ✅
All EXFIL rules are deployment-ready:

- ✅ **EXFIL-001** - Bulk File Download Detection (HIGH)
- ✅ **EXFIL-002** - Large Outbound Transfer (HIGH)
- ✅ **EXFIL-003** - DNS Tunneling Detection (HIGH)

**Parser Dependencies:** Reverse proxy parsers, Pi-hole parser

---

### Application Rules (4 rules) ✅
All APP rules are deployment-ready:

- ✅ **APP-001** - Suspicious Home Assistant API Activity (MEDIUM)
- ✅ **APP-002** - Media Server Unusual Access Pattern (LOW)
- ✅ **APP-003** - Pi-hole DNS Query Anomaly (MEDIUM)
- ✅ **APP-004** - Nextcloud Bulk Download (HIGH)

**Parser Dependencies:** Application-specific parsers

---

### IoT & Smart Home Rules (2 rules) ✅
All IOT rules are deployment-ready:

- ✅ **IOT-001** - Unusual Smart Home Automation Trigger (MEDIUM)
- ✅ **IOT-002** - Smart Lock Repeated Failures (HIGH)

**Parser Dependencies:** Home Assistant, smart home integration parsers

---

### Authentication Rules (5 of 11 ready) ✅
Ready rules:

- ✅ **AUTH-001** - SSH Brute Force Detection (HIGH)
- ✅ **AUTH-006** - Authentication Outside Hours (LOW)
- ✅ **AUTH-007** - Multiple Failed SSO Attempts (HIGH)
- ✅ **AUTH-008** - Root SSH Login Attempt (CRITICAL)
- ✅ **AUTH-009** - API Authentication Failures (MEDIUM)

**Blocked rules:**
- ⏳ **AUTH-002** - Requires event correlation (Phase 4D)
- ⏳ **AUTH-003** - Requires distinct_count (Phase 4B) ✅ NOW READY
- ⏳ **AUTH-004** - Requires distinct_count (Phase 4B) ✅ NOW READY
- ⏳ **AUTH-005** - Requires Vaultwarden parser (Phase 4A) ✅ NOW READY
- ⏳ **AUTH-010** - Requires distinct_count (Phase 4B) ✅ NOW READY
- ⏳ **AUTH-011** - Requires IP whitelist (Phase 4C) ✅ NOW READY

**Update:** Phase 4A and 4B complete! AUTH-003, AUTH-004, AUTH-005, AUTH-010 are now ready (originally 5, now 9 ready)

---

### Access Control Rules (3 of 4 ready) ✅
Ready rules:

- ✅ **ACCESS-001** - Sudo to Root by Non-Admin (HIGH)
- ✅ **ACCESS-003** - Unusual Process Execution via Sudo (HIGH)
- ✅ **ACCESS-004** - Privilege Escalation Attempt (LOW)

**Blocked rules:**
- ⏳ **ACCESS-002** - Requires IP whitelist (Phase 4C) ✅ NOW READY

**Update:** Phase 4C complete! ACCESS-002 is now ready (originally 3, now 4 ready)

---

### Infrastructure Rules (3 of 4 ready) ✅
Ready rules:

- ✅ **INFRA-002** - Container Escape Attempt (CRITICAL)
- ✅ **INFRA-003** - Resource Exhaustion Attack (MEDIUM)
- ✅ **INFRA-004** - Cryptomining Detection (HIGH)

**Blocked rules:**
- ⏳ **INFRA-001** - Requires distinct_count (Phase 4B) ✅ NOW READY

**Update:** Phase 4B complete! INFRA-001 is now ready (originally 3, now 4 ready)

---

### Password Manager Rules (0 of 4 ready) ⏳
All blocked by Vaultwarden parser:

- ⏳ **PWDMGR-001** - Vault Export (CRITICAL) - ✅ NOW READY (Phase 4A)
- ⏳ **PWDMGR-002** - Multiple Device Registrations (HIGH) - ✅ NOW READY (Phase 4A)
- ⏳ **PWDMGR-003** - Unusual Vault Geolocation (HIGH) - ⏳ Still needs GeoIP (Phase 4E)
- ⏳ **PWDMGR-004** - API Token Abuse (HIGH) - ✅ NOW READY (Phase 4A)

**Update:** Phase 4A complete! 3 of 4 PWDMGR rules now ready (PWDMGR-003 still needs Phase 4E)

---

## Actual Deployment Status After Phase 4A/4B/4C

**Originally Ready:** 36 of 40 rules (90%)
**After Phase 4A (Vaultwarden):** +5 rules = 41 would be 100%, but only 40 exist
**After Phase 4B (Distinct Count):** +4 rules
**After Phase 4C (IP Whitelist):** +2 rules

**Corrected Count:**
- **AUTH rules:** 5 → 9 ready (+4 from 4A/4B/4C)
- **ACCESS rules:** 3 → 4 ready (+1 from 4C)
- **INFRA rules:** 3 → 4 ready (+1 from 4B)
- **PWDMGR rules:** 0 → 3 ready (+3 from 4A)

**New Total:** 38 of 40 rules ready (95%)

**Still Blocked:**
- **AUTH-002** - Requires event correlation (Phase 4D)
- **PWDMGR-003** - Requires GeoIP enrichment (Phase 4E)

---

## Deployment Strategy

### Phase 1: Deploy 38 Ready Rules (Recommended)

**Staging Testing** (6-8 hours):
- Import 38 rules to staging database
- Replay 1 week of historical logs
- Verify parser compatibility
- Check false positive rates
- Validate alert generation

**Production Rollout** (Phased):
1. **Day 1**: Deploy CRITICAL + HIGH severity (22 rules)
2. **Day 2**: Add MEDIUM severity (14 rules)
3. **Day 3**: Add LOW severity (2 rules)

**Monitoring Period:**
- Collect 1-2 weeks of alert data
- Tune thresholds based on real traffic
- Document false positives
- Adjust rule sensitivity

---

### Phase 2: Complete Remaining Rules

**Week 2-3**: Implement Phase 4D (Event Correlation)
- Unblocks AUTH-002 (1 CRITICAL rule)
- Real-time correlation for brute force success

**Week 3-4**: Implement Phase 4E (GeoIP Enrichment)
- Unblocks PWDMGR-003 (1 HIGH rule)
- Geographic anomaly detection

**Week 4**: Deploy final 2 rules
- 100% deployment achieved

---

## Rule Import SQL

### Rules to Import (38 rules)

Use this SQL to verify ready rules in database:

\`\`\`sql
-- Count rules by category
SELECT
  SUBSTRING(name FROM '^[A-Z]+-') as category,
  COUNT(*) as rule_count,
  COUNT(CASE WHEN enabled = true THEN 1 END) as enabled_count
FROM detection_rules
GROUP BY SUBSTRING(name FROM '^[A-Z]+-')
ORDER BY category;

-- List all deployment-ready rules
SELECT
  name,
  severity,
  enabled,
  CASE
    WHEN name LIKE 'AUTH-002%' THEN 'Blocked: Needs correlation'
    WHEN name LIKE 'PWDMGR-003%' THEN 'Blocked: Needs GeoIP'
    ELSE 'Ready'
  END as deployment_status
FROM detection_rules
ORDER BY
  CASE severity
    WHEN 'critical' THEN 1
    WHEN 'high' THEN 2
    WHEN 'medium' THEN 3
    WHEN 'low' THEN 4
  END,
  name;
\`\`\`

---

## Pre-Deployment Checklist

### Database
- [ ] All 40 rules imported to database
- [ ] Rules table schema verified
- [ ] Parser compatibility confirmed
- [ ] Test samples validated

### Parsers
- [ ] All required parsers deployed (Phase 2: 12 parsers)
- [ ] Parser priority configured correctly
- [ ] Test logs parse successfully
- [ ] Field extraction verified

### Backend
- [ ] Phase 4A: Vaultwarden parser operational ✅
- [ ] Phase 4B: Distinct count aggregation operational ✅
- [ ] Phase 4C: IP whitelist system operational ✅
- [ ] Rule engine handles all operators
- [ ] Alert creation tested

### Monitoring
- [ ] Alert dashboard configured
- [ ] Email/webhook notifications set up
- [ ] Alert acknowledgment workflow tested
- [ ] False positive tracking in place

---

## Post-Deployment Tasks

### Week 1
- Monitor alert volume daily
- Identify high-frequency false positives
- Tune thresholds for noisy rules
- Document legitimate patterns

### Week 2
- Analyze alert patterns
- Adjust rule sensitivity
- Update IP whitelists
- Configure user baselines (if GeoIP ready)

### Week 3-4
- Complete Phase 4D and 4E
- Deploy final 2 rules
- Achieve 100% deployment
- Final tuning and optimization

---

## Success Criteria

**Deployment Successful When:**
- [ ] All 38 rules enabled in production
- [ ] Alert generation working correctly
- [ ] False positive rate < 10% (before tuning)
- [ ] Zero false negatives for CRITICAL rules
- [ ] Rule evaluation < 1 second per log
- [ ] Documentation complete

**Tuning Complete When:**
- [ ] False positive rate < 5% for all rules
- [ ] CRITICAL rules have < 1% false positive rate
- [ ] All legitimate patterns whitelisted
- [ ] Thresholds optimized for homelab traffic

---

## Rollback Plan

If issues occur during deployment:

1. **Disable problematic rule category** (not all rules)
2. **Review logs** for parsing errors or exceptions
3. **Check parser compatibility** with rule conditions
4. **Verify field extraction** matches rule expectations
5. **Re-enable rules** after fixing issues

**Emergency Rollback:**
\`\`\`sql
-- Disable all rules temporarily
UPDATE detection_rules SET enabled = false;

-- Re-enable specific rules
UPDATE detection_rules SET enabled = true WHERE name IN ('AUTH-008', 'INFRA-002', ...);
\`\`\`

---

## Documentation References

- **Phase 4 Plan:** `docs/phase-planning/PHASE-4-IMPLEMENTATION-PLAN.md`
- **Rule Documentation:** `RULES.md`
- **Parser Documentation:** `PARSERS.md`
- **Deployment Guide:** `DEPLOYMENT.md`

---

**Status:** Ready for 38-rule deployment (95% complete)
**Next Step:** Begin staging testing
**Target:** Production deployment Week 1, 100% completion Week 4
