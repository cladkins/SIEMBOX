# Security Foundation Implementation Summary

## Overview

This document summarizes the comprehensive security foundation implemented for SIEMBox's Asset Discovery and Vulnerability Management features (Phase 0).

**Implementation Date:** 2024-12-17
**Status:** Complete - Ready for Phase 1 (Scanner Integration)

---

## Implementation Summary

### 1. Role-Based Access Control (RBAC)

**File:** `/backend/src/middleware/scanPermissions.ts`

Implemented four-tier role hierarchy:

| Role | Permissions | Use Case |
|------|-------------|----------|
| **Viewer** | Read-only access to assets, vulnerabilities, scan history | Security visibility |
| **Analyst** | Viewer + trigger asset discovery scans | Network discovery |
| **Operator** | Analyst + trigger vuln scans, mark remediation | Daily security ops |
| **Admin** | All permissions + credential management | Security admin |

**Key Features:**
- Hierarchical permission model (each role inherits from lower)
- Automatic audit logging of access denials
- Middleware-enforced authorization checks
- Contextual error messages with role requirements

**Usage Example:**
```typescript
// Protect asset scan endpoint
app.post('/api/scans/assets',
  authenticate,
  requireAssetScanPermission,  // Requires Analyst+
  assetScanRateLimiter,
  validateAssetScanRequest,
  handleValidationErrors,
  createAssetScan
);
```

---

### 2. Audit Logging System

**File:** `/backend/src/services/audit/auditService.ts`

**Database Table:** `audit_logs`

Comprehensive audit trail for all security-sensitive operations:

**Logged Actions:**
- `scan.asset.create` - Asset discovery initiated
- `scan.vuln.create` - Vulnerability scan initiated
- `credential.create/read/update/delete` - Credential operations
- `vuln.remediated/false_positive` - Vulnerability status changes
- `access.denied` - Authorization failures
- `user.role_changed` - Role modifications

**Security Features:**
- Automatic sensitive field redaction (passwords, keys, tokens)
- Recursive redaction for nested objects
- User context (ID, IP, user agent)
- Request/response logging
- 1-year retention policy (configurable)

**Query API:**
```typescript
// Get failed access attempts
await AuditService.getFailedAccessAttempts(24); // Last 24 hours

// Get user activity
await AuditService.getUserActivity(userId, 50);

// Custom query
await AuditService.getAuditLogs({
  action: 'credential.read',
  startDate: new Date('2024-12-01'),
  limit: 100
});
```

---

### 3. Credential Encryption

**File:** `/backend/src/services/credentials/credentialEncryption.ts`

**Database Table:** `scan_credentials`

**Encryption Specification:**
- Algorithm: AES-256-GCM (Authenticated Encryption)
- Key Size: 256 bits (32 bytes)
- IV Size: 96 bits (12 bytes, randomly generated)
- Authentication Tag: 128 bits (16 bytes)

**Security Features:**
- Encryption key stored in `CREDENTIAL_ENCRYPTION_KEY` env var
- Key validation on application startup
- Test encryption/decryption to verify key integrity
- Separate IV per encryption operation
- Auth tag verification on decryption prevents tampering

**Key Generation:**
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

**Usage Example:**
```typescript
// Encrypt credential
const encrypted = CredentialEncryption.encrypt(password);
// Store: encrypted.encrypted, encrypted.iv, encrypted.authTag

// Decrypt credential
const password = CredentialEncryption.decrypt(
  encrypted.encrypted,
  encrypted.iv,
  encrypted.authTag
);
```

**Rotation Support:**
- 90-day rotation policy (configurable)
- `last_rotated_at` tracking
- Dashboard alerts for due rotations
- Re-encryption with new IV without changing credential

---

### 4. Rate Limiting

**File:** `/backend/src/middleware/rateLimiter.ts`

Prevents abuse and resource exhaustion:

| Limiter | Window | Max Requests | Bypass Role |
|---------|--------|--------------|-------------|
| Asset Scans | 10 min | 15 | Admin |
| Vulnerability Scans | 30 min | 5 | Admin |
| Credential Operations | 1 hour | 20 | None (even Admin) |
| Audit Log Queries | 5 min | 30 | Admin |
| General Scans | 15 min | 10 | Admin |

**Features:**
- Per-user rate limiting (by user ID)
- Standard `RateLimit-*` response headers
- Customizable limits per operation type
- Admin bypass for most operations
- Credential operations rate-limited for all users

**Rate Limit Response:**
```json
{
  "error": "Too many scan requests",
  "message": "You have exceeded the rate limit of 10 scans per 15 minutes.",
  "retryAfter": "600"
}
```

---

### 5. Input Validation

**File:** `/backend/src/middleware/scanValidation.ts`

Comprehensive input validation using `express-validator`:

**Asset Scan Validation:**
- IP/CIDR format validation
- CIDR mask restrictions (/16 minimum)
- Blocked ranges (loopback, multicast)
- Max 100 targets per scan
- Port specification validation
- Timeout range checking (1-3600s)

**Vulnerability Scan Validation:**
- Asset ID or IP validation
- Max 50 targets per scan
- Credential ID validation
- Scan template validation
- Vulnerability type filtering

**Credential Validation:**
- Name format (alphanumeric, underscore, hyphen)
- Credential type validation (ssh, windows, snmp, http, database)
- SSH private key format validation
- Rotation policy range (1-365 days)

**Validation Error Response:**
```json
{
  "error": "Validation failed",
  "details": [
    {
      "field": "targets",
      "message": "Cannot scan loopback addresses (127.x.x.x)",
      "value": "127.0.0.1"
    }
  ]
}
```

---

### 6. Database Schema

**File:** `/backend/migrations/001_initial_schema.sql`

**New Tables:**

1. **`audit_logs`** - Security audit trail
   - User context, action, resource type/ID
   - Request body (redacted), response status
   - IP address, user agent, timestamp

2. **`scan_credentials`** - Encrypted credentials
   - Name, type, username
   - Encrypted password, IV, auth tag
   - Encrypted private key (SSH)
   - Rotation tracking, active status

3. **`assets`** - Discovered network assets
   - IP, hostname, MAC, OS info
   - Asset type, criticality, status
   - Discovery method, first/last seen
   - Metadata (JSONB), tags

4. **`asset_services`** - Services on assets
   - Port, protocol, service name/version
   - Banner, state, last seen

5. **`vulnerabilities`** - CVE database
   - CVE ID, CVSS score, severity
   - Title, description, remediation
   - References, published date, CWE

6. **`asset_vulnerabilities`** - Asset-vuln mapping
   - Asset and vulnerability references
   - Status, risk score, evidence
   - First/last detected, remediation tracking

7. **`vulnerability_scans`** - Scan history
   - Scan type, target, status
   - Duration, results summary
   - Credential reference, initiator

**Advanced Features:**
- Automatic risk score calculation (trigger)
- Scan duration auto-calculation (trigger)
- Materialized view for dashboard performance
- Comprehensive indexing for performance
- GIN indexes for JSONB and array columns

---

### 7. User Model Updates

**Files:**
- `/backend/src/models/User.ts`
- `/backend/src/middleware/auth.ts`

**Changes:**
- Added `operator` role to type definitions
- Updated role hierarchy in authorization middleware
- Added `requireOperator` middleware function

---

### 8. Environment Configuration

**File:** `.env.example`

**Added:**
```bash
# Credential Encryption (for scanning credentials)
# Generate with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
CREDENTIAL_ENCRYPTION_KEY=changeme_generate_a_new_64_character_hex_key
```

---

### 9. Security Documentation

**File:** `/docs/security/SCANNING_SECURITY.md`

Comprehensive 400+ line security documentation covering:

1. **RBAC System**
   - Role definitions and permissions
   - Implementation examples
   - Unauthorized access handling

2. **Credential Management**
   - Encryption architecture
   - Key management procedures
   - Storage schema
   - CRUD operations security flow
   - Rotation procedures
   - Best practices (least privilege, isolation, monitoring)

3. **Audit Logging**
   - Schema and logged actions
   - Sensitive data redaction
   - Retention policy
   - Query API
   - Security incident detection

4. **Rate Limiting**
   - Configuration table
   - Custom limits
   - Response format

5. **Input Validation**
   - Target validation rules
   - Parameter validation
   - Error responses

6. **Security Best Practices**
   - For administrators
   - For operators
   - For analysts

7. **Incident Response**
   - Unauthorized scanning detection
   - Credential compromise procedures
   - Container escape response
   - Legal considerations (CFAA)

8. **Compliance Considerations**
   - Legal authorization requirements
   - Data protection
   - Regulatory frameworks (PCI DSS, HIPAA, SOC 2)

9. **Configuration Reference**
   - Environment variables
   - Database backup procedures
   - Security monitoring metrics
   - Alerting thresholds

---

## Security Controls Checklist

- [x] RBAC with 4-tier role hierarchy
- [x] Comprehensive audit logging with 1-year retention
- [x] AES-256-GCM credential encryption
- [x] Per-user rate limiting (5 different limiters)
- [x] Input validation for all scan operations
- [x] Automatic sensitive field redaction
- [x] Failed access attempt logging
- [x] Credential rotation tracking
- [x] Database schema with security constraints
- [x] Comprehensive security documentation

---

## Testing Recommendations

### Unit Tests (TODO - Phase 1)

1. **RBAC Middleware:**
   - Test each role can access appropriate endpoints
   - Test unauthorized access returns 403
   - Test access denial logging

2. **Credential Encryption:**
   - Test encrypt/decrypt round-trip
   - Test invalid key detection
   - Test auth tag verification
   - Test re-encryption

3. **Audit Service:**
   - Test sensitive field redaction
   - Test recursive redaction
   - Test query filters
   - Test cleanup function

4. **Input Validation:**
   - Test valid inputs pass
   - Test invalid IPs rejected
   - Test CIDR restrictions
   - Test blocked ranges

5. **Rate Limiting:**
   - Test limit enforcement
   - Test admin bypass
   - Test per-user isolation

### Integration Tests (TODO - Phase 2)

1. **End-to-End Scan Flow:**
   - Asset scan with Analyst role
   - Vuln scan with Operator role
   - Credential operations with Admin role
   - Verify audit logs created

2. **Unauthorized Access:**
   - Viewer attempts scan
   - Analyst attempts credential access
   - Verify 403 and audit logs

3. **Rate Limit Exhaustion:**
   - Trigger rate limit
   - Verify 429 response
   - Verify headers

---

## Deployment Checklist

### Pre-Deployment

- [ ] Generate `CREDENTIAL_ENCRYPTION_KEY`
- [ ] Update `.env` with encryption key
- [ ] Review and customize rate limits if needed
- [ ] Plan database migration strategy
- [ ] Review audit log retention policy

### Database Migration

```bash
# Backup existing database
docker exec siembox-postgres pg_dump -U siembox siembox > backup.sql

# Apply new schema (pre-v1.0 - drops and recreates)
# See docs/guides/PRE-V1-DATABASE.md for instructions
```

### Post-Deployment

- [ ] Verify encryption key is set: `CredentialEncryption.validateEncryptionKey()`
- [ ] Test RBAC with each role
- [ ] Verify audit logging captures operations
- [ ] Test rate limiting
- [ ] Review security monitoring dashboard
- [ ] Configure alerts for security incidents

---

## Dependencies Added

```json
{
  "dependencies": {
    "express-validator": "^7.0.1"
  }
}
```

**Already Installed:**
- `express-rate-limit` (v7.1.5)
- `bcrypt` (v5.1.1)
- `crypto` (Node.js built-in)

---

## File Summary

### New Files Created

1. `/backend/src/middleware/scanPermissions.ts` (217 lines)
   - RBAC enforcement middleware

2. `/backend/src/services/audit/auditService.ts` (283 lines)
   - Audit logging service

3. `/backend/src/services/credentials/credentialEncryption.ts` (211 lines)
   - AES-256-GCM encryption service

4. `/backend/src/middleware/rateLimiter.ts` (149 lines)
   - Rate limiting middleware

5. `/backend/src/middleware/scanValidation.ts` (267 lines)
   - Input validation middleware

6. `/docs/security/SCANNING_SECURITY.md` (686 lines)
   - Comprehensive security documentation

### Modified Files

1. `/backend/migrations/001_initial_schema.sql`
   - Added `operator` role to users table
   - Added 7 new tables for asset/vuln management
   - Added comprehensive indexes
   - Added triggers for auto-calculation
   - Added materialized view for dashboard

2. `/backend/src/models/User.ts`
   - Added `operator` to role type definitions

3. `/backend/src/middleware/auth.ts`
   - Added `operator` to role types
   - Added `requireOperator` middleware

4. `.env.example`
   - Added `CREDENTIAL_ENCRYPTION_KEY` with generation instructions

5. `/backend/package.json`
   - Added `express-validator` dependency

---

## Next Steps (Phase 1)

1. **Scanner Integration:**
   - Implement NMAP wrapper for asset discovery
   - Implement Nuclei wrapper for vulnerability scanning
   - Create scan orchestration service

2. **API Endpoints:**
   - `POST /api/scans/assets` - Initiate asset scan
   - `POST /api/scans/vulnerabilities` - Initiate vuln scan
   - `GET /api/scans/:id` - Get scan status
   - `DELETE /api/scans/:id` - Cancel scan
   - `GET /api/assets` - List assets
   - `GET /api/vulnerabilities` - List vulnerabilities
   - `POST /api/credentials` - Create credential
   - `GET /api/audit-logs` - Query audit logs

3. **Frontend UI:**
   - Asset inventory dashboard
   - Vulnerability dashboard
   - Scan configuration interface
   - Credential management (Admin only)
   - Audit log viewer

4. **Testing:**
   - Unit tests for all security components
   - Integration tests for scan flows
   - Security testing (RBAC bypass attempts)

---

## Security Posture

This implementation provides:

1. **Defense in Depth:**
   - Multiple layers of security (RBAC, rate limiting, validation, encryption)
   - Fail-secure design (errors don't expose sensitive data)

2. **Least Privilege:**
   - Role-based access with clear boundaries
   - Operators can scan but not manage credentials
   - Analysts can discover but not exploit

3. **Audit Trail:**
   - Complete visibility into security operations
   - Cannot be bypassed (middleware-enforced)
   - 1-year retention for compliance

4. **Credential Protection:**
   - Military-grade encryption (AES-256-GCM)
   - Authentication prevents tampering
   - Never logged in plaintext

5. **Abuse Prevention:**
   - Rate limiting prevents resource exhaustion
   - Input validation prevents injection attacks
   - Blocked ranges prevent unauthorized scanning

---

## Compliance Readiness

This implementation supports:

- **CFAA Compliance:** Authorization tracking, approved targets
- **PCI DSS:** Quarterly scanning, credential protection, audit trails
- **HIPAA:** Risk assessments, access controls, audit logs
- **SOC 2:** Security controls, monitoring, documentation

---

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Controls](https://www.cisecurity.org/controls)
- [Express Rate Limit](https://github.com/express-rate-limit/express-rate-limit)
- [Express Validator](https://express-validator.github.io/)

---

**Implementation Status:** ✅ Complete

**Ready for Phase 1:** Scanner Integration and API Development
