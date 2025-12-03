# Phase 4: Backend Implementation & Deployment
**Date:** 2025-12-03
**Status:** In Progress
**Branch:** develop

---

## Overview

Phase 4 focuses on implementing backend enhancements required to enable all 40 detection rules created in Phase 3. Currently, 13 out of 40 rules require backend features that don't yet exist.

**Blocked Rules:** 13 rules waiting for backend features
**Deployment Ready Rules:** 27 rules ready for immediate deployment
**Priority:** CRITICAL - Vaultwarden parser blocks 5 rules including 2 CRITICAL severity

---

## Backend Requirements Summary

### Priority 1: CRITICAL (Blocks 5 rules - 2 CRITICAL severity)

#### 1.1 Vaultwarden Parser Implementation
**Blocks:** AUTH-005, PWDMGR-001, PWDMGR-002, PWDMGR-003, PWDMGR-004
**Severity:** 2 CRITICAL, 3 HIGH
**Impact:** Password manager security is the highest priority in homelab threat model

**Required Fields:**
- `service`: "vaultwarden"
- `message`: Full log message
- `event`: Event type (login, device_registered, vault_export, api_call)
- `action`: Specific action (vault_export, vault_import)
- `path`: URL path for API calls
- `source_ip`: Client IP address
- `user`: Username/email
- `status_code`: HTTP status (for API monitoring)
- `timestamp`: Event timestamp

**Implementation Location:** `backend/src/models/parser.ts`

**Log Format Analysis Needed:**
```
# Sample Vaultwarden logs to analyze:
- Authentication logs (login success/failure)
- Vault operation logs (export, import, sync)
- Device registration logs
- API access logs
```

**Acceptance Criteria:**
- [ ] Parser extracts all required fields
- [ ] Successfully parses authentication failures
- [ ] Detects vault export operations
- [ ] Tracks device registrations
- [ ] Monitors API calls
- [ ] Test with 5+ real Vaultwarden log samples

---

### Priority 2: HIGH (Blocks 4 rules - all HIGH severity)

#### 2.1 Distinct Count Aggregation
**Blocks:** AUTH-003, AUTH-004, AUTH-010, INFRA-001
**Severity:** 1 HIGH, 3 MEDIUM
**Impact:** Distributed attack detection and advanced threat identification

**Use Cases:**
- **AUTH-003**: Count distinct source IPs attacking same user (distributed brute force)
- **AUTH-004**: Count distinct usernames tested by same IP (account enumeration)
- **AUTH-010**: Count distinct services with failures from same IP (credential stuffing)
- **INFRA-001**: Count distinct IPs performing port scans on same host

**Implementation Requirements:**
1. Extend rule aggregation YAML schema:
```yaml
aggregation:
  field: source_ip          # Primary aggregation field
  distinct_field: user      # Count distinct values of this field
  timeframe: 15m
  threshold: 3              # Alert if distinct_field has 3+ unique values
```

2. Backend SQL Implementation:
```sql
SELECT
  ${aggregation.field} as agg_key,
  COUNT(DISTINCT ${aggregation.distinct_field}) as distinct_count,
  COUNT(*) as total_count
FROM logs
WHERE
  timestamp >= NOW() - INTERVAL '${timeframe}'
  AND ${conditions}
GROUP BY ${aggregation.field}
HAVING COUNT(DISTINCT ${aggregation.distinct_field}) >= ${threshold}
```

**Implementation Location:** `backend/src/services/ruleEngine.ts`

**Acceptance Criteria:**
- [ ] YAML schema supports distinct_field parameter
- [ ] Rule engine executes DISTINCT COUNT queries
- [ ] Works with existing aggregation logic
- [ ] Performance acceptable (< 1s query time)
- [ ] Test with AUTH-003, AUTH-004, AUTH-010, INFRA-001

---

### Priority 3: MEDIUM (Blocks 2 rules - 1 HIGH, 1 MEDIUM)

#### 3.1 IP Whitelist Management System
**Blocks:** AUTH-011, ACCESS-002
**Severity:** 2 MEDIUM
**Impact:** Reduces false positives for admin access from known IPs

**Requirements:**

1. **Database Schema:**
```sql
CREATE TABLE ip_whitelist (
  id SERIAL PRIMARY KEY,
  ip_address CIDR NOT NULL,
  description TEXT,
  rule_id VARCHAR(50),        -- Optional: whitelist per rule
  created_by INTEGER REFERENCES users(id),
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_ip_whitelist_ip ON ip_whitelist USING GIST (ip_address inet_ops);
```

2. **API Endpoints:**
```typescript
POST   /api/settings/ip-whitelist       // Add IP/CIDR to whitelist
GET    /api/settings/ip-whitelist       // List all whitelisted IPs
DELETE /api/settings/ip-whitelist/:id   // Remove IP from whitelist
PUT    /api/settings/ip-whitelist/:id   // Update description
```

3. **Rule Integration:**
```yaml
conditions:
  - field: client_ip
    operator: not_in_whitelist
    whitelist: "admin_ips"
```

**Implementation Locations:**
- Database: `backend/migrations/`
- Routes: `backend/src/routes/settings.ts`
- Model: `backend/src/models/settings.ts`
- Rule Engine: `backend/src/services/ruleEngine.ts`

**Acceptance Criteria:**
- [ ] Database table created with CIDR support
- [ ] API endpoints functional (CRUD operations)
- [ ] Rule engine supports not_in_whitelist operator
- [ ] IPv4 and IPv6 support
- [ ] CIDR notation support (192.168.1.0/24)
- [ ] Frontend UI for whitelist management
- [ ] Test with AUTH-011 and ACCESS-002

---

### Priority 4: MEDIUM (Blocks 1 rule - HIGH severity)

#### 4.1 Event Correlation Engine
**Blocks:** AUTH-002 (Successful Login After Failed Attempts)
**Severity:** CRITICAL
**Impact:** Detects successful brute force attacks

**Requirements:**

AUTH-002 needs to correlate two event types:
1. Multiple "Failed password" events from source_ip (3+ in 10 minutes)
2. Single "Accepted" event from same source_ip

**Implementation Approach:**

Option A: **Real-time Correlation (Recommended)**
```typescript
// When processing "Accepted" event
async function checkBruteForceSuccess(event: LogEvent) {
  if (event.event !== 'Accepted') return;

  // Look back 10 minutes for failed attempts from same IP
  const failedAttempts = await db.query(`
    SELECT COUNT(*) as failures
    FROM logs
    WHERE source_ip = $1
      AND event LIKE '%Failed password%'
      AND timestamp >= NOW() - INTERVAL '10 minutes'
      AND timestamp < $2
  `, [event.source_ip, event.timestamp]);

  if (failedAttempts.rows[0].failures >= 3) {
    // Trigger AUTH-002 alert
    await createAlert({
      rule_id: 'AUTH-002',
      severity: 'critical',
      ...
    });
  }
}
```

Option B: **Sliding Window Analysis**
- Run periodic job (every 30 seconds)
- Check for pattern: failures followed by success
- More resource intensive but catches missed events

**Implementation Location:** `backend/src/services/correlationEngine.ts`

**Acceptance Criteria:**
- [ ] Detects 3+ failures followed by success
- [ ] Respects 10-minute timeframe
- [ ] Groups by source_ip correctly
- [ ] Alert includes failure count context
- [ ] Performance acceptable (< 100ms per event)
- [ ] Test with AUTH-002

---

### Priority 5: MEDIUM (Blocks 1 rule - HIGH severity)

#### 5.1 GeoIP Enrichment
**Blocks:** PWDMGR-003 (Unusual Vault Access Geolocation)
**Severity:** HIGH
**Impact:** Detects geographic anomalies in password manager access

**Requirements:**

1. **GeoIP Database Integration:**
- Use MaxMind GeoLite2 (free) or GeoIP2 (commercial)
- Database file: `/backend/geoip/GeoLite2-Country.mmdb`
- Library: `maxmind` npm package

2. **Log Enrichment:**
```typescript
import maxmind, { CountryResponse } from 'maxmind';

async function enrichWithGeoIP(log: LogEvent) {
  const lookup = await maxmind.open<CountryResponse>('./geoip/GeoLite2-Country.mmdb');
  const geo = lookup.get(log.source_ip);

  if (geo) {
    log.country = geo.country?.iso_code;          // "US", "GB", etc.
    log.country_name = geo.country?.names?.en;    // "United States"
    log.continent = geo.continent?.code;           // "NA", "EU", etc.
  }

  return log;
}
```

3. **User Baseline Configuration:**
```sql
CREATE TABLE user_baseline (
  id SERIAL PRIMARY KEY,
  username VARCHAR(255) NOT NULL UNIQUE,
  home_country VARCHAR(2) NOT NULL,           -- ISO country code
  allowed_countries TEXT[],                    -- Additional allowed countries
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);
```

4. **API Endpoints:**
```typescript
POST   /api/settings/user-baseline       // Set user home country
GET    /api/settings/user-baseline/:user  // Get user baseline
PUT    /api/settings/user-baseline/:user  // Update allowed countries
```

5. **Rule Condition:**
```yaml
conditions:
  - field: country
    operator: not_equals
    value_from_baseline: home_country
```

**Implementation Locations:**
- GeoIP Service: `backend/src/services/geoip.ts`
- Database: `backend/migrations/`
- Routes: `backend/src/routes/settings.ts`
- Rule Engine: `backend/src/services/ruleEngine.ts`

**Acceptance Criteria:**
- [ ] GeoLite2 database downloaded and integrated
- [ ] All incoming logs enriched with country code
- [ ] User baseline table created
- [ ] API endpoints functional
- [ ] Rule engine supports value_from_baseline
- [ ] Test with PWDMGR-003
- [ ] Performance acceptable (< 10ms per lookup)

---

## Implementation Phases

### Phase 4A: Vaultwarden Parser (Week 1)
**Priority:** CRITICAL
**Time Estimate:** 2-3 days
**Unblocks:** 5 rules (2 CRITICAL, 3 HIGH)

**Tasks:**
1. Analyze Vaultwarden log format
2. Create parser definition
3. Add to parser database
4. Test with real Vaultwarden logs
5. Validate all 5 rules work correctly

**Deliverables:**
- Vaultwarden parser YAML or database entry
- Test log samples
- Parser validation report

---

### Phase 4B: Distinct Count Aggregation (Week 1-2)
**Priority:** HIGH
**Time Estimate:** 3-4 days
**Unblocks:** 4 rules (1 HIGH, 3 MEDIUM)

**Tasks:**
1. Extend YAML schema for distinct_field
2. Update rule engine to handle DISTINCT COUNT
3. Add PostgreSQL query generation
4. Optimize with appropriate indexes
5. Test with AUTH-003, AUTH-004, AUTH-010, INFRA-001

**Deliverables:**
- Updated rule engine code
- Database migrations (indexes)
- Unit tests for distinct count
- Performance benchmarks

---

### Phase 4C: IP Whitelist System (Week 2)
**Priority:** MEDIUM
**Time Estimate:** 2-3 days
**Unblocks:** 2 rules (2 MEDIUM)

**Tasks:**
1. Create database migration
2. Implement CRUD API endpoints
3. Add not_in_whitelist operator to rule engine
4. Create frontend UI (optional)
5. Test with AUTH-011 and ACCESS-002

**Deliverables:**
- Database migration file
- API routes and controllers
- Frontend UI components (optional)
- Integration tests

---

### Phase 4D: Event Correlation Engine (Week 2-3)
**Priority:** MEDIUM
**Time Estimate:** 3-4 days
**Unblocks:** 1 rule (CRITICAL)

**Tasks:**
1. Design correlation architecture (real-time vs. batch)
2. Implement correlation logic
3. Integrate with rule engine
4. Add correlation result caching (optional)
5. Test with AUTH-002

**Deliverables:**
- Correlation engine service
- Integration with alert system
- Performance optimization
- Correlation tests

---

### Phase 4E: GeoIP Enrichment (Week 3)
**Priority:** MEDIUM
**Time Estimate:** 2-3 days
**Unblocks:** 1 rule (HIGH)

**Tasks:**
1. Download GeoLite2 database
2. Implement GeoIP lookup service
3. Add log enrichment to ingestion pipeline
4. Create user baseline system
5. Test with PWDMGR-003

**Deliverables:**
- GeoIP service with caching
- User baseline database and API
- Log enrichment integration
- GeoIP tests

---

## Deployment Strategy

### Stage 1: Deploy Ready Rules (Immediate)
Deploy 27 rules that require no backend changes:
- All PROXY rules (8 rules)
- Most ACCESS rules (2 of 4)
- Most AUTH rules (6 of 11)
- Most INFRA rules (3 of 4)
- All EXFIL rules (3 rules)
- All APP rules (4 rules)
- All IOT rules (2 rules)

### Stage 2: Deploy After Vaultwarden Parser
Deploy 5 password manager rules after parser is ready

### Stage 3: Deploy After Backend Enhancements
Deploy remaining 8 rules as backend features complete

---

## Testing Strategy

### Unit Testing
- Each backend feature has unit tests
- Parser tests with real log samples
- Rule engine tests for new operators

### Integration Testing
- End-to-end log ingestion to alert generation
- Multi-rule triggering scenarios
- Performance testing with high log volume

### Real-World Testing
- Deploy to staging environment
- Ingest real homelab logs
- Monitor false positive rates
- Tune thresholds based on real data

---

## Documentation Requirements

### Technical Documentation
- [ ] API documentation for new endpoints
- [ ] Database schema documentation
- [ ] Rule engine operator documentation
- [ ] GeoIP setup guide

### User Documentation
- [ ] Vaultwarden integration guide
- [ ] IP whitelist management guide
- [ ] User baseline configuration guide
- [ ] Rule tuning guide (update RULES.md)

### Deployment Documentation
- [ ] Phase 4 deployment guide
- [ ] Migration guide from Phase 3
- [ ] Troubleshooting guide updates
- [ ] Performance tuning guide

---

## Success Metrics

### Implementation Complete When:
- [ ] All 40 rules can be deployed
- [ ] No rules blocked by missing features
- [ ] All unit tests passing
- [ ] Integration tests passing
- [ ] Performance benchmarks met
- [ ] Documentation complete

### Performance Targets:
- Log ingestion: < 100ms per log (with enrichment)
- Rule evaluation: < 1s per log
- GeoIP lookup: < 10ms per lookup
- Distinct count query: < 1s with 1M logs
- Alert generation: < 500ms from trigger to database

### Quality Targets:
- Unit test coverage: > 80%
- Integration test coverage: > 70%
- False positive rate: < 5% (after tuning)
- Zero false negatives for CRITICAL rules

---

## Risk Assessment

### High Risk Items
1. **Vaultwarden Log Format Uncertainty**
   - Mitigation: Analyze real logs early, adjust parser as needed

2. **Distinct Count Performance**
   - Mitigation: Add database indexes, implement query optimization

3. **Correlation Engine Complexity**
   - Mitigation: Start with simple real-time approach, iterate if needed

### Medium Risk Items
1. **GeoIP Database Updates**
   - Mitigation: Automate monthly updates, use MaxMind GeoUpdate

2. **IP Whitelist Management UX**
   - Mitigation: CLI-first approach, frontend optional

### Low Risk Items
1. **Database Migrations**
   - Mitigation: Test migrations in staging first

---

## Resource Requirements

### Development Environment
- PostgreSQL 14+ (for CIDR support)
- Node.js 18+
- GeoLite2 database (free download)
- Real Vaultwarden instance for testing

### External Dependencies
- MaxMind GeoLite2 database
- npm package: `maxmind`
- npm package: `ip-cidr` (for whitelist)

---

## Next Steps

### Immediate Actions (Today)
1. ✅ Review Phase 3 requirements
2. ✅ Create Phase 4 implementation plan
3. 🔄 Start Vaultwarden parser research
4. Gather real Vaultwarden log samples

### Week 1 Priorities
1. Implement Vaultwarden parser
2. Begin distinct count aggregation
3. Deploy 27 ready rules to staging

### Week 2 Priorities
1. Complete distinct count aggregation
2. Implement IP whitelist system
3. Begin event correlation engine

### Week 3 Priorities
1. Complete correlation engine
2. Implement GeoIP enrichment
3. Deploy all 40 rules
4. Begin real-world testing and tuning

---

## Appendix: Rule Deployment Readiness

### Deployment Ready (27 rules)
✅ AUTH-001, AUTH-006, AUTH-007, AUTH-008, AUTH-009
✅ PROXY-001 through PROXY-008 (all 8)
✅ ACCESS-003, ACCESS-004
✅ INFRA-002, INFRA-003, INFRA-004
✅ EXFIL-001, EXFIL-002, EXFIL-003 (all 3)
✅ APP-001, APP-002, APP-003, APP-004 (all 4)
✅ IOT-001, IOT-002 (all 2)

### Blocked by Vaultwarden Parser (5 rules)
⚠️ AUTH-005 (CRITICAL)
⚠️ PWDMGR-001 (CRITICAL)
⚠️ PWDMGR-002 (HIGH)
⚠️ PWDMGR-003 (HIGH)
⚠️ PWDMGR-004 (HIGH)

### Blocked by Distinct Count (4 rules)
⚠️ AUTH-003 (HIGH)
⚠️ AUTH-004 (MEDIUM)
⚠️ AUTH-010 (HIGH)
⚠️ INFRA-001 (MEDIUM)

### Blocked by IP Whitelist (2 rules)
⚠️ AUTH-011 (MEDIUM)
⚠️ ACCESS-002 (MEDIUM)

### Blocked by Correlation Engine (1 rule)
⚠️ AUTH-002 (CRITICAL)

### Blocked by GeoIP (1 rule)
⚠️ PWDMGR-003 (already counted above with Vaultwarden)

---

**Document Status:** Complete
**Phase Status:** Phase 4 implementation starting
**Next Milestone:** Vaultwarden parser completion
**Target Date:** Week 1 completion by 2025-12-10
