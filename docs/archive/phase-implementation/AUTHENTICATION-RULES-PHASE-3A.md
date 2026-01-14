# Authentication & Password Manager Detection Rules - Phase 3A

## Overview

This document contains 14 detection rules for Phase 3A of the SIEMBox parser/rule redesign project. These rules focus on authentication attacks and password manager security - two of the most critical security domains for homelab environments.

**Status:** ✅ Complete - 14 rules implemented
**Date:** 2025-12-03
**Categories:** Authentication (10 rules) + Password Manager (4 rules)

---

## Implementation Summary

### Files Created

All rules are stored in `/Users/chrisadkins/Projects/SIEMBox/rules/` with organized subdirectories:

#### Authentication Rules (`/rules/authentication/`)
1. `AUTH-001-ssh-brute-force.yaml`
2. `AUTH-002-successful-login-after-failures.yaml`
3. `AUTH-003-distributed-brute-force.yaml`
4. `AUTH-004-account-enumeration.yaml`
5. `AUTH-005-vaultwarden-master-password-failures.yaml`
6. `AUTH-006-authentication-outside-hours.yaml`
7. `AUTH-007-sso-authentication-failures.yaml`
8. `AUTH-008-root-ssh-login.yaml`
9. `AUTH-009-api-authentication-failures.yaml`
10. `AUTH-010-cross-service-authentication-failures.yaml`
11. `AUTH-011-admin-interface-unusual-ip.yaml` (bonus rule for admin access control)

#### Password Manager Rules (`/rules/password-manager/`)
1. `PWDMGR-001-vaultwarden-vault-export.yaml`
2. `PWDMGR-002-multiple-device-registrations.yaml`
3. `PWDMGR-003-unusual-vault-geolocation.yaml`
4. `PWDMGR-004-api-token-abuse.yaml`

---

## Rule Details by Severity

### CRITICAL Severity (4 rules)

#### AUTH-005: Vaultwarden Master Password Failures
- **Threshold:** 3 failures in 10 minutes
- **Rationale:** VERY LOW threshold because Vaultwarden compromise is catastrophic
- **Parser Dependency:** Vaultwarden parser (service, message fields)
- **Fields Used:** `service`, `message`, `source_ip`
- **Aggregation:** Group by source_ip
- **Ready for Testing:** ⚠️ Requires Vaultwarden parser field validation

#### AUTH-008: Root SSH Login Attempt
- **Threshold:** Single event (no aggregation)
- **Rationale:** Direct root SSH should NEVER occur
- **Parser Dependency:** SSH Authentication parser
- **Fields Used:** `event`, `user`, `service`
- **Aggregation:** None (immediate alert)
- **Ready for Testing:** ✅ Yes - SSH parser validated in Phase 2

#### PWDMGR-001: Vaultwarden Vault Export
- **Threshold:** Single event (no aggregation)
- **Rationale:** Vault exports are rare and high-risk operations
- **Parser Dependency:** Vaultwarden parser
- **Fields Used:** `service`, `action`
- **Aggregation:** None (immediate alert)
- **Ready for Testing:** ⚠️ Requires Vaultwarden parser action field validation

#### AUTH-002: Successful Login After Failed Attempts
- **Threshold:** 1 success after 3+ failures in 10 minutes
- **Rationale:** Success after multiple failures indicates brute force success
- **Parser Dependency:** SSH Authentication parser (or generic auth parser)
- **Fields Used:** `event`, `source_ip`
- **Aggregation:** Complex - requires correlation with prior failures
- **Ready for Testing:** ⚠️ Requires custom correlation logic implementation
- **Implementation Note:** This rule requires backend support to correlate successful login with prior failures from same IP

---

### HIGH Severity (7 rules)

#### AUTH-001: SSH Brute Force Detection
- **Threshold:** 5 failures in 5 minutes
- **Rationale:** Balance between detection and false positives
- **Parser Dependency:** SSH Authentication parser
- **Fields Used:** `event`, `service`, `source_ip`
- **Aggregation:** Group by source_ip
- **Ready for Testing:** ✅ Yes

#### AUTH-003: Distributed Brute Force Attack
- **Threshold:** 10 failures from 3+ distinct IPs in 15 minutes
- **Rationale:** Indicates botnet/distributed attack
- **Parser Dependency:** SSH Authentication parser
- **Fields Used:** `event`, `user`, `source_ip`
- **Aggregation:** Group by user, count distinct source_ip
- **Ready for Testing:** ⚠️ Requires distinct_count implementation
- **Implementation Note:** Backend must support distinct_count aggregation

#### AUTH-007: Multiple Failed SSO Authentication Attempts
- **Threshold:** 5 failures in 5 minutes
- **Rationale:** SSO protects multiple downstream services
- **Parser Dependency:** Authelia, authentik, Keycloak parsers
- **Fields Used:** `service`, `event`, `source_ip`
- **Aggregation:** Group by source_ip
- **Ready for Testing:** ✅ Yes (Phase 2B parsers validated)

#### AUTH-010: Cross-Service Authentication Failures
- **Threshold:** 15 failures across 3+ services in 15 minutes
- **Rationale:** Indicates credential stuffing attack
- **Parser Dependency:** Multiple authentication parsers
- **Fields Used:** `message`, `service`, `source_ip`
- **Aggregation:** Group by source_ip, count distinct service
- **Ready for Testing:** ⚠️ Requires distinct_count implementation
- **Implementation Note:** Backend must support distinct_count aggregation

#### PWDMGR-002: Multiple Device Registrations
- **Threshold:** 3 registrations in 1 hour
- **Rationale:** Unusual pattern - users rarely register many devices at once
- **Parser Dependency:** Vaultwarden parser
- **Fields Used:** `service`, `event`, `user`
- **Aggregation:** Group by user
- **Ready for Testing:** ⚠️ Requires Vaultwarden parser event field validation

#### PWDMGR-003: Unusual Vault Access Geolocation
- **Threshold:** Single event outside home country
- **Rationale:** Geographic anomaly detection
- **Parser Dependency:** Vaultwarden parser + GeoIP enrichment
- **Fields Used:** `service`, `event`, `country`, `source_ip`
- **Aggregation:** None (immediate alert)
- **Ready for Testing:** ⚠️ Requires GeoIP enrichment implementation
- **Implementation Note:** Requires GeoIP lookup and user home country baseline

#### PWDMGR-004: API Token Abuse
- **Threshold:** 50 API calls in 10 minutes
- **Rationale:** Exceeds normal client sync behavior
- **Parser Dependency:** Vaultwarden parser
- **Fields Used:** `service`, `path`, `source_ip`
- **Aggregation:** Group by source_ip
- **Ready for Testing:** ⚠️ Requires Vaultwarden parser path field validation

---

### MEDIUM Severity (3 rules)

#### AUTH-004: Account Enumeration Attempt
- **Threshold:** 10 attempts testing 5+ usernames in 10 minutes
- **Rationale:** Reconnaissance to discover valid accounts
- **Parser Dependency:** SSH Authentication parser
- **Fields Used:** `event`, `user`, `source_ip`
- **Aggregation:** Group by source_ip, count distinct user
- **Ready for Testing:** ⚠️ Requires distinct_count implementation

#### AUTH-009: API Authentication Failures
- **Threshold:** 10 failures in 10 minutes
- **Rationale:** APIs have higher failure tolerance than interactive auth
- **Parser Dependency:** Application parsers with API logging
- **Fields Used:** `message`, `status_code`, `source_ip`
- **Aggregation:** Group by source_ip
- **Ready for Testing:** ✅ Yes

#### AUTH-011: Admin Interface from Unusual IP
- **Threshold:** Single event from non-whitelisted IP
- **Rationale:** Admin access should be restricted to known IPs
- **Parser Dependency:** Reverse proxy parsers (NGINX, Traefik, Caddy)
- **Fields Used:** `path`, `client_ip`
- **Aggregation:** None (immediate alert)
- **Ready for Testing:** ⚠️ Requires IP whitelist configuration
- **Implementation Note:** Requires backend support for IP whitelist management

---

### LOW Severity (1 rule)

#### AUTH-006: Authentication Outside Normal Hours
- **Threshold:** Single event between 00:00-06:00
- **Rationale:** Informational tracking, pattern analysis
- **Parser Dependency:** SSH Authentication parser (or generic auth)
- **Fields Used:** `event`, `timestamp`, `user`, `source_ip`
- **Aggregation:** None (immediate alert)
- **Ready for Testing:** ✅ Yes

---

## Parser Dependencies

### Validated in Phase 2 (Ready to Use)
- **SSH Authentication Parser** - Provides: event, user, source_ip, hostname, timestamp
- **Authelia Parser** - Provides: service, event, user, source_ip, timestamp
- **authentik Parser** - Provides: service, event, user, source_ip, timestamp
- **Keycloak Parser** - Provides: service, event, user, source_ip, timestamp
- **Reverse Proxy Parsers** - Provide: path, client_ip, status_code, method

### Requires Validation from Phase 2C
- **Vaultwarden Parser** - Must provide:
  - `service` field: "vaultwarden"
  - `message` field: Contains "Invalid password" for failed auth
  - `action` field: "vault_export" for export detection
  - `event` field: "device registered" for device tracking
  - `path` field: "/api/" for API calls
  - `source_ip` field: Source IP address

### Missing Implementations
- **GeoIP Enrichment** - Required for PWDMGR-003
- **IP Whitelist Management** - Required for AUTH-011
- **Correlation Engine** - Required for AUTH-002
- **Distinct Count Aggregation** - Required for AUTH-003, AUTH-004, AUTH-010

---

## Implementation Notes

### Custom Logic Required

Several rules require backend enhancements beyond basic YAML rule evaluation:

1. **AUTH-002 (Successful Login After Failures)**
   - Requires correlation: Check for 3+ "Failed password" events from same source_ip within 10 minutes BEFORE the current "Accepted" event
   - Implementation: Pre-query failed attempts when "Accepted" event is processed

2. **AUTH-003, AUTH-004, AUTH-010 (Distinct Count Rules)**
   - Requires `distinct_count` parameter in aggregation
   - Implementation: `SELECT COUNT(DISTINCT field) GROUP BY aggregation_field`
   - Example: Count distinct source_ip values per user for distributed attacks

3. **AUTH-011 (IP Whitelist)**
   - Requires IP whitelist configuration in settings
   - Implementation: Check client_ip against whitelist table/configuration
   - Should support CIDR notation (192.168.1.0/24)

4. **PWDMGR-003 (GeoIP Enrichment)**
   - Requires GeoIP database integration (MaxMind GeoLite2)
   - Implementation: Enrich logs with country code from source_ip
   - Requires user home country baseline (configuration per user)

### Field Validation Checklist

Before testing, validate these fields exist in parsers:

**Vaultwarden Parser:**
- [ ] `service` = "vaultwarden"
- [ ] `message` contains authentication failure text
- [ ] `action` for vault operations (export, import, etc.)
- [ ] `event` for device registration
- [ ] `path` for API endpoints
- [ ] `source_ip` for client identification

**All Authentication Parsers:**
- [ ] `event` or `message` for success/failure indication
- [ ] `user` for targeted account
- [ ] `source_ip` for attacker/client identification
- [ ] `service` for service identification

---

## Testing Requirements

### Test Cases Per Rule

Each rule should be tested with:

1. **Positive Test:** Log samples that SHOULD trigger the rule
2. **Negative Test:** Log samples that should NOT trigger the rule
3. **Threshold Test:** Logs just below threshold (should not trigger)
4. **Timeframe Test:** Events outside timeframe window (should not trigger)

### Sample Test Data Structure

```json
{
  "rule_id": "AUTH-001",
  "test_cases": [
    {
      "name": "SSH brute force - should trigger",
      "logs": [
        // 5 failed password events within 5 minutes from same IP
      ],
      "expected_alert": true
    },
    {
      "name": "SSH legitimate failures - should not trigger",
      "logs": [
        // 4 failed password events (below threshold)
      ],
      "expected_alert": false
    }
  ]
}
```

---

## Integration Requirements

### Backend API Endpoints Needed

1. **Rule Management**
   - `POST /api/rules` - Import rules from YAML
   - `GET /api/rules` - List all rules
   - `PUT /api/rules/:id` - Update rule (enable/disable, tune thresholds)
   - `DELETE /api/rules/:id` - Delete rule

2. **Configuration Management**
   - `POST /api/settings/ip-whitelist` - Manage admin IP whitelist
   - `POST /api/settings/user-baseline` - Set user home country for GeoIP
   - `GET /api/settings/geoip` - Check GeoIP enrichment status

3. **Testing Endpoints**
   - `POST /api/rules/test` - Test rule with sample logs
   - `POST /api/rules/validate` - Validate YAML syntax

### Database Schema Updates

**Rules Table:**
```sql
CREATE TABLE detection_rules (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  severity VARCHAR(20) NOT NULL,
  enabled BOOLEAN DEFAULT true,
  conditions JSONB NOT NULL,
  aggregation JSONB,
  alert JSONB NOT NULL,
  tags TEXT[],
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);
```

**IP Whitelist Table:**
```sql
CREATE TABLE ip_whitelist (
  id SERIAL PRIMARY KEY,
  ip_address CIDR NOT NULL,
  description TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);
```

**User Baseline Table:**
```sql
CREATE TABLE user_baseline (
  id SERIAL PRIMARY KEY,
  username VARCHAR(255) NOT NULL,
  home_country VARCHAR(2),
  normal_hours_start TIME,
  normal_hours_end TIME,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);
```

---

## Deployment Checklist

### Pre-Deployment
- [ ] All 14 rules validated syntactically
- [ ] Parser dependencies confirmed
- [ ] Backend aggregation support verified (distinct_count)
- [ ] Database schema updated
- [ ] API endpoints implemented

### Deployment
- [ ] Import rules via API or direct database import
- [ ] Configure IP whitelist for admin interfaces
- [ ] Set user home countries for GeoIP alerts
- [ ] Enable GeoIP enrichment (MaxMind GeoLite2)
- [ ] Test with sample logs for each severity level

### Post-Deployment
- [ ] Monitor false positive rate
- [ ] Tune thresholds based on homelab traffic
- [ ] Document any whitelist additions
- [ ] Review alert volume and adjust as needed

---

## Tuning Guide

### Common Adjustments

**Too Many Alerts (False Positives):**
- Increase threshold values
- Extend timeframe windows
- Add IP whitelists for known sources
- Disable low-severity rules if too noisy

**Missing Alerts (False Negatives):**
- Decrease threshold values
- Shorten timeframe windows
- Review parser field extraction
- Verify logs are being parsed correctly

### Per-Rule Tuning Recommendations

| Rule | If Too Noisy | If Missing Threats |
|------|--------------|-------------------|
| AUTH-001 | Increase to 8-10 attempts | Decrease to 3m timeframe |
| AUTH-003 | Increase to 5+ distinct IPs | Decrease to 7 attempts |
| AUTH-005 | Whitelist known user IPs | DO NOT increase threshold |
| AUTH-006 | Disable or adjust hours | Extend to 00:00-07:00 |
| AUTH-007 | Increase to 8 attempts | Decrease to 3m timeframe |
| AUTH-008 | Document/whitelist emergency access | Never tune - always alert |
| PWDMGR-002 | Increase to 5 devices | Decrease to 30m timeframe |
| PWDMGR-004 | Increase to 100 calls | Decrease to 5m timeframe |

---

## Next Steps

### Phase 3B: Reverse Proxy Exploitation Rules (8 rules)
- PROXY-001: SQL Injection Attempt
- PROXY-002: Command Injection Attempt
- PROXY-003: Path Traversal Attempt
- PROXY-004: Directory Enumeration Detection
- PROXY-005: Malicious User Agent Detection
- PROXY-006: HTTP Method Abuse
- PROXY-007: Large Request Body (DoS)
- PROXY-008: High Request Rate (DoS)

### Phase 3C: Access Control & Infrastructure Rules (remaining rules)
- Access control violations
- Data exfiltration detection
- Infrastructure attacks
- Application-specific threats

### Phase 4: Documentation & Integration
- Update RULES.md with new rules
- Create rule testing guide
- Write tuning playbook
- Integration documentation

---

## Summary Statistics

| Category | Count | Status |
|----------|-------|--------|
| **Total Rules** | 14 | ✅ Complete |
| **Critical Severity** | 4 | ✅ Implemented |
| **High Severity** | 7 | ✅ Implemented |
| **Medium Severity** | 3 | ✅ Implemented |
| **Low Severity** | 1 | ✅ Implemented |
| **Ready for Testing** | 6 | ✅ No custom logic needed |
| **Requires Backend Enhancements** | 8 | ⚠️ Needs correlation/distinct_count |

---

## Validation Summary Table

| Rule ID | Rule Name | Severity | Parser Dependency | Threshold | Ready for Testing |
|---------|-----------|----------|-------------------|-----------|-------------------|
| AUTH-001 | SSH Brute Force Detection | High | SSH Auth | 5 in 5m | ✅ Yes |
| AUTH-002 | Successful Login After Failures | Critical | SSH Auth | 1 after 3+ failures | ⚠️ Needs correlation |
| AUTH-003 | Distributed Brute Force | High | SSH Auth | 10 from 3+ IPs | ⚠️ Needs distinct_count |
| AUTH-004 | Account Enumeration | Medium | SSH Auth | 10 testing 5+ users | ⚠️ Needs distinct_count |
| AUTH-005 | Vaultwarden Password Failures | Critical | Vaultwarden | 3 in 10m | ⚠️ Validate parser |
| AUTH-006 | Authentication Outside Hours | Low | SSH Auth | Single event | ✅ Yes |
| AUTH-007 | SSO Authentication Failures | High | SSO parsers | 5 in 5m | ✅ Yes |
| AUTH-008 | Root SSH Login | Critical | SSH Auth | Single event | ✅ Yes |
| AUTH-009 | API Authentication Failures | Medium | App parsers | 10 in 10m | ✅ Yes |
| AUTH-010 | Cross-Service Auth Failures | High | Multiple | 15 across 3+ services | ⚠️ Needs distinct_count |
| AUTH-011 | Admin Interface Unusual IP | Medium | Reverse Proxy | Single event | ⚠️ Needs whitelist |
| PWDMGR-001 | Vault Export | Critical | Vaultwarden | Single event | ⚠️ Validate parser |
| PWDMGR-002 | Multiple Device Registrations | High | Vaultwarden | 3 in 1h | ⚠️ Validate parser |
| PWDMGR-003 | Unusual Vault Geolocation | High | Vaultwarden + GeoIP | Single event | ⚠️ Needs GeoIP |
| PWDMGR-004 | API Token Abuse | High | Vaultwarden | 50 in 10m | ⚠️ Validate parser |

---

**Document Status:** Complete
**Rules Implemented:** 14/14 (100%)
**Next Phase:** Phase 3B - Reverse Proxy Exploitation Rules
**Date:** 2025-12-03
