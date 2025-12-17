# Asset Discovery & Vulnerability Management - Database Schema Implementation

**Status:** ✅ COMPLETE
**Date:** December 17, 2025
**Schema File:** `/backend/migrations/001_initial_schema.sql`
**Commit:** d6a5ea8 - "feat: implement comprehensive security foundation for scanning features"

---

## Summary

The complete database schema for Asset Discovery and Vulnerability Management has been successfully implemented in `001_initial_schema.sql`. All 7 required tables, indexes, triggers, and materialized views are in place.

---

## Implemented Tables

### Phase 0: Security Foundation

#### 1. **audit_logs**
- Security audit trail for all scan operations
- Tracks user actions, IP addresses, request/response data
- 1-year retention minimum
- Indexed on: timestamp, user_id, action, resource_type/id

#### 2. **scan_credentials**
- AES-256-GCM encrypted credentials for vulnerability scanning
- Supports SSH, Windows, SNMP, HTTP credential types
- Automatic rotation policy tracking (90-day default)
- Indexed on: is_active, last_rotated_at

### Phase 1: Asset Management

#### 3. **assets**
- Discovered network assets from NMAP scans and log correlation
- Fields: IP address (INET), hostname, MAC address, OS info
- Asset classification: type (server/workstation/network/iot), criticality (low/medium/high/critical)
- Status tracking: active, inactive, offline
- Discovery methods: nmap, log_correlation, manual
- JSONB metadata for flexible storage
- Text array for tags
- Indexed on: ip_address, hostname, status, criticality, last_seen, tags (GIN), metadata (GIN)

#### 4. **asset_services**
- Services and ports discovered on assets
- Fields: port, protocol, service_name, service_version, state, banner
- Linked to assets with CASCADE delete
- Unique constraint: (asset_id, port, protocol)
- Indexed on: asset_id, port, service_name

### Phase 3: Vulnerability Management

#### 5. **vulnerabilities**
- CVE vulnerability database from Nuclei scans
- Fields: cve_id (unique), cvss_score, cvss_vector, severity
- Includes title, description, remediation, references (array)
- CWE classification support
- JSONB metadata for additional CVE data
- Indexed on: cve_id, severity, cvss_score (DESC), published_date (DESC)

#### 6. **asset_vulnerabilities**
- Junction table mapping vulnerabilities to specific assets
- Remediation workflow: status (open/patched/false_positive/accepted)
- **Automatic risk score calculation** (trigger: criticality × CVSS)
- Evidence storage for scan proof
- Tracking: first_detected, last_detected, patched_at, patched_by
- Unique constraint: (asset_id, vulnerability_id)
- Indexed on: asset_id, vulnerability_id, status, risk_score (DESC), first_detected (DESC)

#### 7. **vulnerability_scans**
- History of all asset discovery and vulnerability scans
- Scan types: asset_discovery, vulnerability
- Status workflow: queued → running → completed/failed
- **Automatic duration calculation** (trigger: completed_at - started_at)
- Tracks: assets_discovered, vulnerabilities_found, scan_options (JSONB)
- Linked to scan_credentials and users
- Indexed on: status, started_at (DESC), scan_type, initiated_by

---

## Triggers & Functions

### 1. Auto-Calculate Scan Duration
```sql
CREATE TRIGGER trg_scan_duration
BEFORE UPDATE ON vulnerability_scans
EXECUTE FUNCTION update_scan_duration()
```
- Automatically calculates `duration_seconds` when scan completes
- Extracts seconds from (completed_at - started_at)

### 2. Auto-Calculate Risk Score
```sql
CREATE TRIGGER trg_risk_score
BEFORE INSERT OR UPDATE ON asset_vulnerabilities
EXECUTE FUNCTION calculate_risk_score()
```
- Calculates risk_score = asset.criticality × vulnerability.cvss_score
- Multipliers: critical (1.5), high (1.2), medium (1.0), low (0.8)
- Capped at 10.0 maximum

### 3. Dashboard Materialized View
```sql
CREATE MATERIALIZED VIEW dashboard_vulnerability_summary AS
SELECT
    COUNT(*) FILTER (WHERE av.status = 'open' AND v.severity = 'critical') as critical_open,
    COUNT(*) FILTER (WHERE av.status = 'open' AND v.severity = 'high') as high_open,
    COUNT(*) FILTER (WHERE av.status = 'open' AND v.severity = 'medium') as medium_open,
    COUNT(*) FILTER (WHERE av.status = 'open' AND v.severity = 'low') as low_open,
    COUNT(DISTINCT av.asset_id) as affected_assets
FROM asset_vulnerabilities av
JOIN vulnerabilities v ON av.vulnerability_id = v.id
WHERE av.status = 'open';
```
- Optimized for dashboard queries (<50ms response time)
- Refresh function: `refresh_dashboard_summary()` (call every 5 minutes from backend)

---

## Performance Optimizations

### Index Strategy
- **B-Tree indexes**: IP addresses, timestamps, foreign keys (fast equality/range queries)
- **GIN indexes**: JSONB fields (metadata), text arrays (tags)
- **Partial indexes**: hostname (WHERE NOT NULL), last_rotated_at (WHERE is_active = true)
- **Covering indexes**: Optimized for common query patterns

### Query Performance Targets
- Asset inventory dashboard: <50ms
- Vulnerability dashboard: <100ms
- Asset detail view: <100ms
- Search queries: <200ms

### Estimated Storage
- Small deployment (50 assets): ~5-10MB
- Medium deployment (500 assets): ~50-100MB
- Large deployment (5000 assets): ~500MB-1GB

---

## Schema Compliance

### ✅ All Mission Requirements Met

1. **Seven Tables Implemented**
   - audit_logs (Phase 0) ✓
   - scan_credentials (Phase 0) ✓
   - assets (Phase 1) ✓
   - asset_services (Phase 1) ✓
   - vulnerabilities (Phase 3) ✓
   - asset_vulnerabilities (Phase 3) ✓
   - vulnerability_scans (Phase 3) ✓

2. **Automatic Calculations**
   - Scan duration trigger ✓
   - Risk score trigger ✓

3. **Performance Optimizations**
   - All required indexes ✓
   - Materialized view for dashboard ✓
   - JSONB for flexible metadata ✓
   - Text arrays for tags ✓

4. **Documentation**
   - Table comments ✓
   - Column comments ✓
   - Security documentation ✓

---

## Database Reset Instructions

For existing SIEMBox installations (pre-v1.0 development):

```bash
# WARNING: This will destroy all data
docker compose down
docker volume rm siembox_postgres_data
docker compose up -d

# Backend auto-runs migrations on startup
# Re-import any saved parsers and detection rules
```

---

## Next Steps

### Phase 1: Scanner Integration
- [ ] Implement NMAP wrapper service
- [ ] Implement Nuclei wrapper service
- [ ] Create API endpoints for asset discovery
- [ ] Create API endpoints for vulnerability scanning

### Phase 2: Frontend UI
- [ ] Asset inventory page
- [ ] Asset detail page (with logs and vulnerabilities)
- [ ] Vulnerability dashboard
- [ ] Scan management UI
- [ ] Credential management UI

### Phase 3: Background Jobs
- [ ] Auto-discovery from logs (15-60 minute intervals)
- [ ] Materialized view refresh (5 minute intervals)
- [ ] Credential rotation reminders
- [ ] Scan scheduling

---

## References

- **Feasibility Study:** `/analysis/ASSET_DISCOVERY_DATABASE_SCHEMA.md`
- **Security Documentation:** `/docs/security/SCANNING_SECURITY.md`
- **Schema File:** `/backend/migrations/001_initial_schema.sql`
- **Pre-v1.0 Database Guide:** `/docs/guides/PRE-V1-DATABASE.md`

---

**Generated by:** Database Optimizer Agent
**Implementation Method:** Pre-v1.0 single migration file
**Status:** Ready for Phase 1 (Scanner Integration)
