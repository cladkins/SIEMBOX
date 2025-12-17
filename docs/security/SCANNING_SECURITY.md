# Scanning Security Documentation

## Overview

This document outlines the security architecture, controls, and procedures for SIEMBox's asset discovery and vulnerability management features. These security measures are designed to prevent unauthorized scanning, protect credentials, ensure audit trail completeness, and comply with security best practices.

## Table of Contents

- [Role-Based Access Control](#role-based-access-control)
- [Credential Management](#credential-management)
- [Audit Logging](#audit-logging)
- [Rate Limiting](#rate-limiting)
- [Input Validation](#input-validation)
- [Security Best Practices](#security-best-practices)
- [Incident Response](#incident-response)
- [Compliance Considerations](#compliance-considerations)

---

## Role-Based Access Control

### Role Hierarchy

SIEMBox implements a four-tier role hierarchy for scanning operations:

```
Viewer < Analyst < Operator < Admin
```

**Each role inherits permissions from lower roles.**

### Role Definitions

#### 1. Viewer (Read-Only)

**Permissions:**
- View assets and asset details
- View vulnerabilities and vulnerability reports
- View scan history and results
- View dashboards and statistics

**Restrictions:**
- Cannot initiate any scans
- Cannot access credentials (even encrypted)
- Cannot modify vulnerability status
- Cannot manage scan configurations

**Use Case:** Security team members who need visibility into the security posture without operational responsibilities.

#### 2. Analyst (Limited Scanning)

**Permissions:**
- All Viewer permissions
- Trigger asset discovery scans on approved targets
- View scan configurations and templates
- Export asset inventory reports

**Restrictions:**
- Cannot perform vulnerability scans (requires credential access)
- Cannot manage credentials
- Cannot modify vulnerability remediation status
- Cannot configure scan targets or whitelists

**Use Case:** Junior security analysts who perform network discovery and asset inventory management.

#### 3. Operator (Operational Scanning)

**Permissions:**
- All Analyst permissions
- Trigger vulnerability scans using pre-configured credentials
- Manage scan schedules and automation
- Mark vulnerabilities as remediated or false positive
- View credential metadata (names, types, last rotation)

**Restrictions:**
- Cannot create or modify credentials
- Cannot view plaintext credentials
- Cannot configure target whitelists
- Cannot manage user roles

**Use Case:** Security operators responsible for routine vulnerability scanning and remediation tracking.

#### 4. Admin (Full Access)

**Permissions:**
- All Operator permissions
- Create, modify, and delete scan credentials
- Configure scan targets and IP whitelists
- Manage user roles and permissions
- Access all audit logs
- Configure scan policies and automation

**Restrictions:**
- Still subject to rate limiting on credential operations
- All actions are logged in audit trail

**Use Case:** Security administrators and team leads responsible for security configuration and credential management.

### Implementation

RBAC is enforced through middleware in `/backend/src/middleware/scanPermissions.ts`:

```typescript
// Require Analyst role or higher for asset scans
app.post('/api/scans/assets',
  authenticate,
  requireAssetScanPermission,
  assetScanRateLimiter,
  validateAssetScanRequest,
  handleValidationErrors,
  createAssetScan
);

// Require Operator role or higher for vulnerability scans
app.post('/api/scans/vulnerabilities',
  authenticate,
  requireVulnScanPermission,
  vulnScanRateLimiter,
  validateVulnScanRequest,
  handleValidationErrors,
  createVulnScan
);

// Require Admin role for credential management
app.post('/api/credentials',
  authenticate,
  requireCredentialPermission,
  credentialRateLimiter,
  validateCredentialCreation,
  handleValidationErrors,
  createCredential
);
```

### Unauthorized Access Handling

When a user attempts an action without sufficient permissions:

1. **403 Forbidden** response is returned
2. Attempt is logged to `audit_logs` table with action `access.denied`
3. Details include: user ID, requested resource, user role, required role
4. Security team can monitor failed access attempts via audit log dashboard

---

## Credential Management

### Encryption Architecture

All scanning credentials are encrypted at rest using **AES-256-GCM** (Galois/Counter Mode):

- **Algorithm:** AES-256-GCM
- **Key Size:** 256 bits (32 bytes)
- **IV Size:** 96 bits (12 bytes, randomly generated per encryption)
- **Authentication Tag:** 128 bits (16 bytes)

### Key Management

The encryption key is stored in the `CREDENTIAL_ENCRYPTION_KEY` environment variable:

1. **Generation:**
   ```bash
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```

2. **Storage:**
   - Store in `.env` file (never commit to version control)
   - Use secrets management in production (Vault, AWS Secrets Manager, etc.)
   - Rotate annually or on suspected compromise

3. **Validation:**
   - Key length validated on application startup
   - Test encryption/decryption performed to verify key integrity

### Credential Storage Schema

```sql
CREATE TABLE scan_credentials (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    credential_type VARCHAR(50) NOT NULL,
    username VARCHAR(255),
    encrypted_password TEXT NOT NULL,      -- AES-256-GCM encrypted
    encryption_iv TEXT NOT NULL,           -- Base64-encoded IV
    encryption_auth_tag TEXT NOT NULL,     -- Base64-encoded auth tag
    encrypted_private_key TEXT,            -- For SSH keys (optional)
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_rotated_at TIMESTAMPTZ,
    rotation_policy_days INTEGER DEFAULT 90,
    is_active BOOLEAN DEFAULT true,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

### Credential Operations

#### Creating Credentials (Admin Only)

```typescript
// API: POST /api/credentials
{
  "name": "prod-ssh-scanner",
  "credentialType": "ssh",
  "username": "scanner",
  "password": "secret-password",
  "privateKey": "-----BEGIN PRIVATE KEY-----...",
  "rotationPolicyDays": 90
}
```

**Security Flow:**
1. Validate user has Admin role
2. Apply rate limiting (20 ops/hour)
3. Validate input format
4. Encrypt password and private key with AES-256-GCM
5. Store encrypted data with IV and auth tag
6. Log operation to audit trail
7. **Never return plaintext credentials in response**

#### Using Credentials (Operator+)

Operators can trigger scans with credentials but cannot view plaintext values:

```typescript
// API: POST /api/scans/vulnerabilities
{
  "targets": ["192.168.1.0/24"],
  "credentialId": 5,  // Reference to encrypted credential
  "scanTemplate": "standard"
}
```

**Security Flow:**
1. Validate user has Operator role or higher
2. Retrieve encrypted credential from database
3. Decrypt credential **in memory only** (never log plaintext)
4. Pass decrypted credential to scanner
5. Zero out credential from memory after use
6. Log scan operation to audit trail (credential ID logged, not plaintext)

#### Rotating Credentials

Credentials should be rotated based on `rotation_policy_days` (default: 90 days):

1. **Manual Rotation:**
   - Admin updates credential with new password
   - `last_rotated_at` timestamp updated
   - Previous credential marked inactive

2. **Automated Rotation Monitoring:**
   - Dashboard alerts when credentials are due for rotation
   - Query credentials needing rotation:
     ```sql
     SELECT * FROM scan_credentials
     WHERE is_active = true
       AND last_rotated_at < NOW() - INTERVAL '90 days';
     ```

### Credential Security Best Practices

1. **Least Privilege:**
   - Create dedicated scanner accounts with minimal permissions
   - SSH: read-only access, no shell access
   - Windows: local user with audit permissions only
   - SNMP: read-only community strings

2. **Network Isolation:**
   - Scanner accounts should only be accessible from SIEMBox server IP
   - Use firewall rules to restrict scanner account access

3. **Account Monitoring:**
   - Monitor scanner account usage in target systems
   - Alert on unexpected scanner account activity
   - Correlate scan jobs with scanner account logins

4. **Key vs Password:**
   - Prefer SSH keys over passwords when possible
   - Use passphrase-protected keys (passphrase stored encrypted)
   - Rotate SSH keys along with passwords

---

## Audit Logging

### Audit Log Schema

```sql
CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id INTEGER,
    ip_address INET,
    user_agent TEXT,
    request_body JSONB,
    response_status INTEGER,
    details JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

### Logged Actions

All security-sensitive operations are logged:

| Action | Description | Required Role |
|--------|-------------|---------------|
| `scan.asset.create` | Asset discovery scan initiated | Analyst+ |
| `scan.vuln.create` | Vulnerability scan initiated | Operator+ |
| `scan.cancelled` | Scan cancelled by user | Initiator |
| `credential.create` | Credential created | Admin |
| `credential.read` | Credential metadata accessed | Admin |
| `credential.update` | Credential modified | Admin |
| `credential.delete` | Credential deleted | Admin |
| `credential.decrypt` | Credential decrypted for scan | System |
| `vuln.remediated` | Vulnerability marked remediated | Operator+ |
| `vuln.false_positive` | Vulnerability marked false positive | Operator+ |
| `access.denied` | Unauthorized access attempt | Any |
| `user.role_changed` | User role modified | Admin |
| `config.scan_target` | Scan target configuration changed | Admin |

### Sensitive Data Redaction

The audit service automatically redacts sensitive fields from logged request bodies:

**Redacted Fields:**
- `password`
- `secret`
- `token`
- `api_key`
- `private_key`
- `encrypted_password`
- `credential`

**Example:**
```json
// Original request
{
  "name": "ssh-prod",
  "username": "scanner",
  "password": "super-secret"
}

// Logged request body
{
  "name": "ssh-prod",
  "username": "scanner",
  "password": "[REDACTED]"
}
```

### Audit Log Retention

- **Default Retention:** 1 year (365 days)
- **Compliance Retention:** Configurable per regulatory requirements
- **Cleanup:** Automated cleanup job runs daily
  ```typescript
  await AuditService.cleanupOldLogs(365);
  ```

### Querying Audit Logs

**Admin API Endpoint:** `GET /api/audit-logs`

**Query Parameters:**
```typescript
{
  userId?: number,
  action?: string,
  resourceType?: 'asset' | 'vulnerability' | 'credential' | 'scan',
  startDate?: string,  // ISO 8601
  endDate?: string,    // ISO 8601
  limit?: number,      // Max 1000
  offset?: number
}
```

**Example Queries:**

1. **Find all failed access attempts in last 24 hours:**
   ```typescript
   GET /api/audit-logs?action=access.denied&startDate=2024-12-16T00:00:00Z
   ```

2. **View all credential operations by a user:**
   ```typescript
   GET /api/audit-logs?userId=5&resourceType=credential
   ```

3. **Audit all vulnerability scans this month:**
   ```typescript
   GET /api/audit-logs?action=scan.vuln.create&startDate=2024-12-01T00:00:00Z
   ```

### Security Incident Detection

Monitor audit logs for:

1. **Repeated Access Denials:**
   - Threshold: 5+ denials in 15 minutes from same user
   - Action: Alert security team, temporarily disable account

2. **Unexpected Credential Access:**
   - Non-admin accessing credential endpoints
   - Off-hours credential operations
   - Action: Alert and investigate

3. **Mass Scanning Activity:**
   - Large number of scans from single user
   - Scanning outside approved target ranges
   - Action: Review scan targets, verify authorization

4. **Privilege Escalation Attempts:**
   - User role changes (especially to Admin)
   - Action: Verify with authorized administrator

---

## Rate Limiting

### Rate Limit Configuration

Rate limiting prevents abuse and resource exhaustion:

| Operation | Window | Limit | Bypass Role |
|-----------|--------|-------|-------------|
| Asset Scans | 10 minutes | 15 requests | Admin |
| Vulnerability Scans | 30 minutes | 5 requests | Admin |
| Credential Operations | 1 hour | 20 requests | None |
| Audit Log Queries | 5 minutes | 30 requests | Admin |
| General Scans | 15 minutes | 10 requests | Admin |

### Rate Limit Headers

Responses include standard rate limit headers:

```
RateLimit-Limit: 15
RateLimit-Remaining: 12
RateLimit-Reset: 1702839600
```

### Rate Limit Exceeded Response

```json
{
  "error": "Too many scan requests",
  "message": "You have exceeded the rate limit of 10 scans per 15 minutes. Please try again later.",
  "retryAfter": "600"
}
```

### Customizing Rate Limits

Modify limits in `/backend/src/middleware/rateLimiter.ts`:

```typescript
export const scanRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // Time window
  max: 10,                    // Max requests
  skip: (req) => req.user?.role === 'admin'
});
```

---

## Input Validation

### Target Validation

**Asset Scan Targets:**
- IP addresses: `192.168.1.10`
- CIDR ranges: `192.168.1.0/24` (minimum /16, maximum /32)
- Maximum targets per scan: 100
- Blocked ranges: loopback (127.x.x.x), multicast (224.x - 239.x)

**Vulnerability Scan Targets:**
- Only single IP addresses (no CIDR)
- Maximum targets per scan: 50
- Must reference existing assets or provide valid IPs

### Scan Parameter Validation

**Port Specifications:**
- Format: `80,443,8000-9000`
- Valid ports: 1-65535
- Maximum port ranges: validated for reasonableness

**Timeout Values:**
- Minimum: 1 second
- Maximum: 3600 seconds (1 hour)
- Default: 300 seconds (5 minutes)

**Scan Types:**
- Asset Discovery: `ping`, `port`, `service`, `os`, `full`
- Vulnerability: `quick`, `standard`, `thorough`, `compliance`

### Credential Validation

**Name Requirements:**
- Length: 3-255 characters
- Characters: alphanumeric, underscore, hyphen only
- Must be unique

**Credential Types:**
- Valid types: `ssh`, `windows`, `snmp`, `http`, `database`

**Password Requirements:**
- Minimum length: 1 character (external system enforces strength)
- Maximum length: 1000 characters
- Stored encrypted, never validated for strength by SIEMBox

### Validation Error Responses

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

## Security Best Practices

### For Administrators

1. **Credential Management:**
   - Rotate credentials every 90 days
   - Use dedicated scanner accounts with minimal privileges
   - Never share credentials between environments
   - Store encryption key in secure secrets manager

2. **Access Control:**
   - Review user roles quarterly
   - Remove unused accounts immediately
   - Use least privilege principle for role assignments
   - Monitor role changes in audit logs

3. **Scan Target Management:**
   - Maintain whitelist of approved scan targets
   - Document business justification for all scanning
   - Verify legal authorization before scanning external IPs
   - Use internal-only scanning in most cases

4. **Monitoring:**
   - Review audit logs weekly for anomalies
   - Set up alerts for failed access attempts
   - Monitor credential rotation status
   - Track scan frequency and patterns

### For Operators

1. **Scanning Operations:**
   - Only scan approved target ranges
   - Use appropriate scan templates (don't use "thorough" unnecessarily)
   - Schedule intensive scans during maintenance windows
   - Document scan purpose in description field

2. **Vulnerability Management:**
   - Triage vulnerabilities promptly
   - Verify false positives before marking
   - Document remediation steps in notes
   - Coordinate with asset owners before remediation

3. **Incident Response:**
   - Report suspicious scan activity immediately
   - Don't attempt to troubleshoot credential issues (escalate to admin)
   - Document any unexpected scan results
   - Follow escalation procedures for critical vulnerabilities

### For Analysts

1. **Asset Discovery:**
   - Use least intrusive scan types when possible
   - Verify target ranges before scanning
   - Review discovered assets for accuracy
   - Report unknown assets to security team

2. **Documentation:**
   - Maintain accurate asset inventory
   - Document asset classifications
   - Update asset metadata when changes detected
   - Report asset discovery errors

---

## Incident Response

### Unauthorized Scanning Detected

**Symptoms:**
- Scan activity from unauthorized user
- Scans targeting unapproved ranges
- Excessive failed access attempts

**Response Procedure:**

1. **Immediate Actions:**
   - Disable user account via UI or database
   - Cancel any running scans from that user
   - Review audit logs for full activity history

2. **Investigation:**
   - Determine if account was compromised or insider threat
   - Check for credential access attempts
   - Review scan targets and results
   - Identify potential data exfiltration

3. **Remediation:**
   - Reset account password if compromised
   - Review and update access control policies
   - Implement additional monitoring if needed
   - Document incident and lessons learned

4. **Legal Considerations:**
   - Determine if scanning violated CFAA or other laws
   - Consult legal team if external systems were scanned
   - Preserve audit logs for potential investigation
   - Notify affected parties if required

### Credential Compromise

**Symptoms:**
- Unexpected credential access in audit logs
- Scanner account lockouts on target systems
- Unauthorized changes to credentials
- Credential decryption errors

**Response Procedure:**

1. **Immediate Actions:**
   - Disable compromised credential in SIEMBox
   - Disable scanner account on target systems
   - Cancel any running scans using that credential
   - Review all recent scans using that credential

2. **Investigation:**
   - Determine scope of compromise
   - Check if encryption key was accessed
   - Review audit logs for credential access
   - Identify how compromise occurred

3. **Remediation:**
   - Rotate affected credentials immediately
   - Create new scanner accounts if needed
   - Review and strengthen credential storage
   - Consider rotating encryption key if compromised
   - Update security procedures

4. **Prevention:**
   - Review admin access controls
   - Enhance monitoring of credential operations
   - Consider multi-factor authentication for admin operations
   - Implement alerts for off-hours credential access

### Container Escape / Privilege Escalation

**Symptoms:**
- Unexpected file system access
- Scanner container accessing host resources
- Unusual network traffic from scanner
- Scanner process running with elevated privileges

**Response Procedure:**

1. **Immediate Actions:**
   - Stop all scanner containers
   - Isolate affected hosts from network
   - Preserve logs and disk state for forensics
   - Disable scanning functionality

2. **Investigation:**
   - Review container configuration and security settings
   - Check for privilege escalation vulnerabilities
   - Analyze container and host logs
   - Determine if data was exfiltrated

3. **Remediation:**
   - Patch container escape vulnerabilities
   - Harden container security settings
   - Implement additional container isolation
   - Review and update security architecture

4. **Prevention:**
   - Regular security updates for container runtime
   - Implement container security scanning
   - Use least privilege container configurations
   - Network segmentation for scanner containers

---

## Compliance Considerations

### Legal Authorization

**Computer Fraud and Abuse Act (CFAA) Compliance:**

1. **Written Authorization Required:**
   - Obtain written authorization before scanning any systems
   - Document scope of authorized scanning
   - Maintain authorization records with scan history

2. **Authorized Targets Only:**
   - Only scan systems you own or have explicit permission to scan
   - Maintain whitelist of approved IP ranges
   - Verify authorization before adding new targets

3. **Defensive Scanning:**
   - Scanning your own systems is generally authorized
   - Ensure scanning doesn't violate service agreements
   - Be cautious with cloud-hosted systems

### Data Protection

**Credential Data:**
- Encrypted at rest (AES-256-GCM)
- Access restricted by RBAC
- Audit trail for all access
- Regular rotation policy

**Vulnerability Data:**
- May contain sensitive system information
- Access restricted by RBAC
- Consider data retention policies
- Implement secure export mechanisms

**Audit Logs:**
- Contain user activity and system access
- 1-year retention minimum
- Secure from tampering
- Export for long-term archival

### Regulatory Frameworks

**PCI DSS (Payment Card Industry):**
- Quarterly vulnerability scanning required
- Maintain scanning tool security
- Document scanning procedures
- Retain scan results

**HIPAA (Healthcare):**
- Regular risk assessments required
- Document scanning as part of risk assessment
- Protect audit logs as they may contain PHI references
- Implement access controls

**SOC 2:**
- Vulnerability management required
- Audit trail completeness
- Access control documentation
- Security monitoring

---

## Configuration Reference

### Environment Variables

```bash
# Required for credential encryption
CREDENTIAL_ENCRYPTION_KEY=<64-character-hex-string>

# Generate with:
# node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### Database Backup

**Critical Tables for Security:**
- `scan_credentials` - Contains encrypted credentials
- `audit_logs` - Contains audit trail
- `users` - Contains role assignments

**Backup Procedures:**
- Daily encrypted backups
- Store backups in secure location
- Test restore procedures quarterly
- Maintain 90-day retention

### Security Monitoring

**Key Metrics to Monitor:**
- Failed access attempts per user
- Credential access frequency
- Scan frequency and patterns
- Role changes
- High-severity vulnerabilities discovered

**Alerting Thresholds:**
- 5+ failed access attempts in 15 minutes
- Any credential creation/deletion
- Any Admin role assignments
- Critical vulnerabilities discovered
- Off-hours credential access

---

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Controls](https://www.cisecurity.org/controls)
- [Computer Fraud and Abuse Act](https://www.justice.gov/criminal-ccips/computer-fraud-and-abuse-act)
- [PCI DSS Requirements](https://www.pcisecuritystandards.org/)

---

## Change Log

| Date | Version | Changes | Author |
|------|---------|---------|--------|
| 2024-12-17 | 1.0 | Initial security documentation | Security Team |

---

## Contact

For security questions or incident reporting:
- **Security Team:** security@siembox.local
- **On-Call:** [See incident response procedures]
- **Emergency:** [Escalation procedure]
