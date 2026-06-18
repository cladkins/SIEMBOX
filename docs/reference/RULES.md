# SIEMBox Detection Rules

**Version:** 1.0
**Status:** Complete
**Last Updated:** December 2025
**Total Rules:** 40 (CRITICAL: 5, HIGH: 17, MEDIUM: 14, LOW: 4)

---

## Quick Reference

### Severity Level Guide

Detection rules in SIEMBox are organized by severity to help you prioritize response actions.

| Severity | Meaning | Response Time | Alert Color | Examples |
|----------|---------|----------------|------------|----------|
| **CRITICAL** | Immediate action required | Within 5 minutes | Red | Password manager compromise, Root access gained, Container escape |
| **HIGH** | Serious threat, investigate today | Within 2 hours | Orange | SSH brute force success, SQL injection, Data exfiltration |
| **MEDIUM** | Suspicious activity, review soon | Within 24 hours | Yellow | Failed auth attempts, Directory scanning, Policy violations |
| **LOW** | Informational, archive for analysis | As convenient | Blue | After-hours access by known user, Service restart patterns |

### Rule Statistics

- **Total Rules:** 40 detection rules
- **CRITICAL:** 5 rules (password manager, authentication, infrastructure)
- **HIGH:** 17 rules (attacks and active threats)
- **MEDIUM:** 14 rules (suspicious patterns)
- **LOW:** 4 rules (informational/baseline)

### Rule Categories

| Category | Count | Focus |
|----------|-------|-------|
| **Authentication** | 11 | Brute force, credential attacks, compromised accounts |
| **Password Manager** | 4 | Vault compromise, credential theft, device abuse |
| **Reverse Proxy** | 8 | SQL injection, command injection, DoS attacks |
| **Access Control** | 4 | Privilege escalation, unauthorized access |
| **Infrastructure** | 4 | Container escape, port scanning, cryptomining |
| **Data Exfiltration** | 3 | Bulk downloads, large transfers, DNS tunneling |
| **Applications** | 4 | App-specific attacks, unauthorized operations |
| **IoT & Smart Home** | 2 | Device failures, unusual automation triggers |

---

## Table of Contents

- [Quick Reference](#quick-reference)
- [Understanding Detection Rules](#understanding-detection-rules)
- [CRITICAL Severity Rules](#critical-severity-rules)
- [HIGH Severity Rules](#high-severity-rules)
- [MEDIUM Severity Rules](#medium-severity-rules)
- [LOW Severity Rules](#low-severity-rules)
- [Rule Management](#rule-management)
- [Response Playbooks](#response-playbooks)
- [Tuning Guidance](#tuning-guidance)
- [Contributing Rules](#contributing-rules)
- [Troubleshooting](#troubleshooting)

---

## Understanding Detection Rules

### How Rules Work

SIEMBox detection rules automatically analyze incoming logs to identify security threats:

```
Incoming Log → Parser (extracts fields) → Rule Engine (checks conditions) → Alert (if matched)
```

**Example: SSH Brute Force**

1. SSH login attempt arrives as syslog: `Failed password for admin from 203.0.113.50 port 54321`
2. SSH Parser extracts fields: `user=admin`, `source_ip=203.0.113.50`, `result=failed`
3. Rule Engine evaluates: "Is this IP making 5+ failed attempts in 5 minutes?"
4. Result: YES → Alert generated with severity HIGH
5. Security analyst receives notification and investigates

### Rule Components

Each detection rule contains:

- **Name:** Clear, actionable description
- **Conditions:** Log fields that must match (AND logic)
- **Aggregation:** How to group related events (if applicable)
- **Severity:** How critical is this threat (critical/high/medium/low)
- **Alert Template:** Message shown to analyst with field substitution
- **Tags:** Searchable keywords for rule organization

### Key Concepts

**Conditions** - Filters applied to incoming logs:
- `equals` - Exact value match
- `contains` - Substring match
- `regex` - Regular expression pattern
- `greater_than` - Numeric comparison

**Aggregation** - Groups events before alerting:
- Counts occurrences of matching events
- Groups by specific field (IP, user, service, etc.)
- Triggers when threshold is exceeded within timeframe
- Example: "5 failures from same IP in 5 minutes"

**Thresholds** - Tunable parameters:
- Balance between detecting attacks and avoiding false positives
- Each rule documents its threshold rationale
- Can be adjusted for your environment

---

## CRITICAL Severity Rules

Critical rules detect threats requiring immediate response within **5 minutes**. These represent:
- Complete system compromise (root access, container escape)
- Credential loss (password manager breach, successful brute force)
- Active data theft (bulk exfiltration in progress)

**When alerted on CRITICAL rules:**
1. Stop what you're doing
2. Investigate immediately
3. Consider incident response activation
4. Implement containment actions

### AUTH-002: Successful Login After Failed Attempts

**Rule ID:** AUTH-002
**Severity:** CRITICAL
**Category:** Authentication → Brute Force Success
**Required Parsers:** SSH Authentication, Authelia, authentik

#### What It Detects

Detects successful login immediately following multiple failed authentication attempts, indicating brute force attack success or account takeover in progress.

**Why Critical:** Successful brute force = attacker now has account access. Attacker can:
- Install backdoors for persistent access
- Access sensitive data with compromised account
- Escalate privileges to gain system access
- Move laterally to other services

#### Detection Logic

```yaml
conditions:
  - field: event
    operator: contains
    value: "Failed password"
  - field: source_ip
    operator: equals
    value: "[same IP from previous failures]"
  - field: event
    operator: contains
    value: "Accepted"

aggregation:
  field: source_ip
  timeframe: 30m
  threshold: "3 failures followed by success"
```

**Threshold Rationale:** 3 failed attempts in 30 minutes is aggressive enough to catch brute force (which uses many attempts) but low enough to avoid false positives (users do mistype passwords). Immediate success after failures is highly suspicious.

#### Alert Response

**Immediate (0-5 minutes):**
1. Contact user immediately - confirm if they made this login
2. If NO: Force password reset immediately
3. If YES: Document as legitimate, continue monitoring
4. Block source IP if external

**Investigation (5-30 minutes):**
1. Review all login attempts from source IP
2. Check what the user accessed after successful login
3. Look for privilege escalation attempts
4. Verify if other accounts were targeted

**Remediation (30+ minutes):**
1. Force password reset for affected account
2. Enable MFA on account if available
3. Review sudo logs for unauthorized escalation
4. Check SSH authorized_keys for backdoors

#### Example Alert

```
Title: CRITICAL: Successful Login After Failed Attempts from 203.0.113.50
Severity: CRITICAL
Description: 5 failed SSH login attempts followed by successful login for user admin
from 203.0.113.50 in 25 minutes. This indicates successful brute force attack.

Actions Required:
1. Contact user immediately to verify
2. Force password reset
3. Review account activity
4. Block source IP if external

Timestamp: 2025-12-03T14:32:15Z
User: admin
Source IP: 203.0.113.50
Failed Attempts: 5 in 25 minutes
Success: Yes at 14:32:15
```

---

### AUTH-005: Vaultwarden Master Password Failures

**Rule ID:** AUTH-005
**Severity:** CRITICAL
**Category:** Authentication → Password Manager
**Required Parsers:** Vaultwarden

#### What It Detects

Detects multiple failed master password attempts, indicating attacker trying to compromise password vault. Master password is the single point of failure for all stored credentials.

**Why Critical (HIGHEST PRIORITY):** Master password compromise = **ALL credentials compromised**. If attacker gains access:
- Every web service password compromised
- Email account credentials stolen
- API keys and tokens exposed
- SSH keys compromised
- Financial service credentials stolen
- **Complete digital infrastructure compromise possible**

#### Detection Logic

```yaml
conditions:
  - field: service
    operator: equals
    value: "vaultwarden"
  - field: event
    operator: contains
    value: "master_password_failed"

aggregation:
  field: user
  timeframe: 10m
  threshold: 3
```

**Threshold:** VERY LOW (3 failures in 10 minutes) because:
- Master password brute force should never occur
- Any failed attempt beyond 1-2 indicates active attack
- Better to alert on failed attempts than miss compromise

#### Alert Response

**URGENT (0-2 minutes):**
1. **TREAT AS CRITICAL IMMEDIATELY**
2. Contact vault owner NOW (phone call, not email)
3. Ask: "Did you just try to log in to your password manager?"

**If YES (Legitimate):**
- Document the action
- Resume normal monitoring
- Close alert with notation

**If NO (COMPROMISE CONFIRMED):**

Go to containment immediately:

1. Force logout all vault sessions
2. Disable user account temporarily
3. Begin emergency credential rotation (see playbook below)

**Emergency Credential Priority:**

```
Priority 1 (Next 15 minutes):
- Email account(s) - most critical, can reset everything else
- Vaultwarden admin credentials
- SSH/shell access to servers

Priority 2 (Next 60 minutes):
- Cloud storage (Google Drive, OneDrive, etc.)
- Financial accounts (banking, crypto, etc.)
- Database credentials
- API keys/tokens

Priority 3 (Next 6 hours):
- Media service accounts (Plex, Jellyfin, etc.)
- Less critical services
- Social media accounts
```

For each account:
1. Log in from known-good device
2. Change password immediately
3. Revoke active sessions
4. Enable MFA if available
5. Check recent account activity

#### Example Alert

```
Title: CRITICAL: Vaultwarden Master Password Attack on User testadmin
Severity: CRITICAL
Description: 3 failed master password attempts in 10 minutes for testadmin account.
This indicates active attempt to compromise the password vault.

IMMEDIATE ACTION REQUIRED:
1. Contact user immediately by phone
2. If user denies: Force password reset, assume account compromised
3. Begin emergency credential rotation
4. Disable user account temporarily
5. Review vault access logs

Timestamp: 2025-12-03T14:15:32Z
User: testadmin
Failed Attempts: 3 in 9 minutes
First Attempt: 14:06:05 UTC
Last Attempt: 14:15:32 UTC
```

---

### AUTH-008: Root SSH Login Attempt

**Rule ID:** AUTH-008
**Severity:** CRITICAL
**Category:** Authentication → Privilege Escalation
**Required Parsers:** SSH Authentication

#### What It Detects

Detects ANY SSH login attempt directly as root user (both successful and failed). This violates security best practices and indicates either attacker attempting direct system access or compromise of standard user account.

**Why Critical:** Root has unrestricted system access. Any root SSH login indicates:
- Attacker bypassed user account security
- **Full system compromise possible**
- Could indicate backdoor installation
- May allow lateral movement to other systems

#### Detection Logic

```yaml
conditions:
  - field: service
    operator: equals
    value: "sshd"
  - field: user
    operator: equals
    value: "root"
  - field: event
    operator: regex
    value: "(Accepted|Failed|Invalid)"
```

**Threshold:** Single event detection - even one root SSH attempt is suspicious and should alert.

#### Alert Response

**Immediate (0-5 minutes):**
1. Determine: Did the root login succeed or fail?
   - Failed (4xx response) = reconnaissance attempt
   - Successful (2xx response) = **full system compromise**
2. From what source IP?
3. What timestamp?

**If Login FAILED:**
- Still suspicious (attacker testing system)
- Verify PermitRootLogin is disabled in sshd_config
- Block source IP at firewall

**If Login SUCCESSFUL:**
- **URGENT: Full incident response**
- Check for unauthorized process execution
- Kill root SSH sessions immediately
- Verify system integrity

#### Remediation

**Prevent Future Root SSH Attempts:**
```bash
# Edit /etc/ssh/sshd_config
PermitRootLogin no

# Restart SSH
sudo systemctl restart ssh
```

**Best Practice:** Root SSH should NEVER be allowed. Even failed attempts indicate attacker reconnaissance.

#### Example Alert

```
Title: CRITICAL: SSH Root Login Attempt from 203.0.113.50
Severity: CRITICAL
Description: SSH login attempt as root user from external IP 203.0.113.50.
Even failed attempts indicate attacker reconnaissance.

Status: Failed (access denied - good!)

Verify:
- PermitRootLogin is disabled in /etc/ssh/sshd_config
- Block source IP: 203.0.113.50

Timestamp: 2025-12-03T23:45:12Z
Source IP: 203.0.113.50
User: root
Result: Failed
SSH Version: OpenSSH_7.4
```

---

### INFRA-002: Container Escape Attempt

**Rule ID:** INFRA-002
**Severity:** CRITICAL
**Category:** Infrastructure → Container Security
**Required Parsers:** Docker logs, System logs

#### What It Detects

Detects attempts to escape Docker container isolation to access host system. Container escape is an advanced attack technique allowing full system compromise from a single compromised container.

**Why Critical:** Container escape = Host system compromise. Attacker can:
- **Access all containers** on the host
- **Compromise entire homelab infrastructure**
- Install persistent backdoors on host
- Steal data from all services
- This represents full infrastructure compromise

#### Detection Logic

```yaml
conditions:
  - field: message
    operator: regex
    value: "(docker\\.sock|/proc/self/cgroup|/sys/class/net|capsh|unshare|nsenter|/host/)"
```

**Detected Techniques:**
- `docker.sock` access - communicating with Docker daemon
- `/proc/self/cgroup` manipulation - cgroup escape
- `nsenter` usage - namespace manipulation
- `capsh` execution - capability manipulation

#### Alert Response

**URGENT (0-5 minutes):**
1. **IMMEDIATELY stop the container:**
   ```bash
   docker stop [container-id]
   docker kill -s KILL [container-id]  # If stop hangs
   ```

2. **DO NOT restart container yet** - preserve evidence

3. **Isolate the system** if on shared network

**Investigation (5-30 minutes):**
1. Determine if container is compromised
2. Review what application was running
3. Check if any host files were modified
4. Look for backdoors or persistence mechanisms

**Remediation (30+ minutes):**
1. Rebuild container from clean image
2. Apply security patches to application
3. Implement container security policies
4. Enable container hardening

#### Example Alert

```
Title: CRITICAL: Container Escape Attempt on docker-host
Severity: CRITICAL
Description: Container escape technique detected: Attempting to access /var/run/docker.sock
This indicates potential container breakout and host compromise.

IMMEDIATE ACTION REQUIRED:
1. STOP container immediately: docker stop [container-id]
2. DO NOT restart the container
3. Preserve all logs for forensics
4. Investigate host system for backdoors
5. Rebuild container from clean image

Timestamp: 2025-12-03T15:22:45Z
Container: web-app-prod
Escape Technique: docker.sock access
Suspicious Command: cat /var/run/docker.sock
```

---

### PWDMGR-001: Vaultwarden Vault Export

**Rule ID:** PWDMGR-001
**Severity:** CRITICAL
**Category:** Password Manager → Data Theft
**Required Parsers:** Vaultwarden

#### What It Detects

Detects vault export operations that export ALL stored credentials in plaintext format. This is the highest-priority threat as it represents complete credential theft in progress.

**Why Critical:** Vault export = **ALL credentials exposed**. Single vault export compromises:
- Every service account stored in vault
- Every API key
- Every financial credential
- Every critical infrastructure password
- **Complete credential database exposed**

#### Detection Logic

```yaml
conditions:
  - field: service
    operator: equals
    value: "vaultwarden"
  - field: action
    operator: equals
    value: "vault_export"
```

**Threshold:** Single event detection - ANY vault export is immediately alertable. Vault exports are rare operations (only planned backups/migration).

#### Alert Response

**URGENT (0-2 minutes):**
1. Contact vault owner IMMEDIATELY (phone call)
2. Ask: "Did you just export your vault?"

**If YES (Legitimate):**
- Document reason and timestamp
- Resume monitoring
- Close alert

**If NO (COMPROMISE CONFIRMED):**

Follow emergency credential rotation process in AUTH-005 playbook above. This is the same incident.

#### Example Alert

```
Title: CRITICAL: Vault Export by testuser from 203.0.113.50
Severity: CRITICAL
Description: Complete credential vault export detected for user testuser from 203.0.113.50.
This exports ALL stored credentials in plaintext.

IMMEDIATE INVESTIGATION - Potential credential theft:
- Contact testuser immediately to verify this was intentional
- If user denies: ASSUME ACCOUNT COMPROMISED
- Begin emergency credential rotation
- Force password reset for testuser

Export Details:
- User: testuser
- Timestamp: 2025-12-03T14:32:15Z
- Source IP: 203.0.113.50
- Exported Entries: 847 credentials
- Format: Plaintext JSON
```

---

## HIGH Severity Rules

High severity rules detect serious threats requiring investigation within **2 hours**. These indicate active attacks or successful compromise where rapid response can limit damage.

**Rules in this category:** 17 total

### Summary: HIGH Severity Rules

| Rule ID | Name | Category |
|---------|------|----------|
| AUTH-001 | SSH Brute Force Detection | Authentication |
| AUTH-003 | Distributed Brute Force Attack | Authentication |
| AUTH-007 | Multiple Failed SSO Attempts | Authentication |
| AUTH-010 | Cross-Service Authentication Failures | Authentication |
| PROXY-001 | SQL Injection Attempt | Reverse Proxy |
| PROXY-002 | Command Injection Attempt | Reverse Proxy |
| PROXY-008 | High Request Rate DoS Attack | Reverse Proxy |
| PWDMGR-002 | Multiple Device Registrations | Password Manager |
| PWDMGR-003 | Unusual Vault Access Geolocation | Password Manager |
| PWDMGR-004 | API Token Abuse | Password Manager |
| ACCESS-001 | Sudo to Root by Non-Admin User | Access Control |
| ACCESS-003 | Unusual Process Execution via Sudo | Access Control |
| INFRA-004 | Cryptocurrency Mining Detection | Infrastructure |
| EXFIL-001 | Bulk File Download Detection | Data Exfiltration |
| EXFIL-002 | Large Data Transfer Detection | Data Exfiltration |
| EXFIL-003 | DNS Tunneling Detection | Data Exfiltration |
| APP-004 | Nextcloud Suspicious File Access | Applications |

### AUTH-001: SSH Brute Force Detection

Detects automated SSH brute force attacks based on failed password attempts. 5+ failed attempts in 5 minutes indicates automated attack.

**What It Detects:** 5+ failed SSH password attempts from same IP in 5 minutes

**Response:** Check for successful access (see AUTH-002), block source IP if external, implement rate limiting

**Tuning:** If too many false positives, increase threshold to 8, extend timeframe to 10 minutes, whitelist internal IPs

---

### AUTH-003: Distributed Brute Force Attack

Detects coordinated brute force attacks from multiple source IPs targeting same account.

**What It Detects:** 10+ failed attempts from 5+ different IPs in 10 minutes to same account

**Response:** Enable account lockout, investigate what this account has access to, implement aggressive rate limiting

**Why Distributed:** Defeats simple IP-based rate limiting, indicates coordinated attacker with resources

---

### AUTH-007: Multiple Failed SSO Authentication Attempts

Detects multiple failed attempts at centralized SSO authentication.

**What It Detects:** 6+ failed SSO attempts from same IP in 10 minutes

**Response:** Verify SSO service is responding, check for unauthorized account modifications, reset passwords for targeted accounts

**Why SSO Matters:** SSO compromise = all downstream applications compromised

---

### AUTH-010: Cross-Service Authentication Failures

Detects coordinated authentication attacks across multiple services from same source.

**What It Detects:** 15+ authentication failures across 3+ different services from same IP in 15 minutes

**Response:** Block source IP, alert all service owners, enable monitoring across infrastructure

---

### PROXY-001: SQL Injection Attempt

Detects SQL injection attack patterns in HTTP requests.

**What It Detects:** SQL patterns in request paths (quotes, SQL keywords, operators)

**Response:** Verify application patches are current, check database for unauthorized queries, implement WAF rules

---

### PROXY-002: Command Injection Attempt

Detects command injection patterns attempting to execute system commands.

**What It Detects:** Command execution indicators (semicolons, pipes, backticks, $(), bash commands)

**Response:** Check if commands executed, investigate application process, patch vulnerability

**Why Dangerous:** Command injection leads to Remote Code Execution (RCE) - full system compromise possible

---

### PROXY-008: High Request Rate DoS Attack

Detects denial-of-service attacks through excessive HTTP requests.

**What It Detects:** 1000+ HTTP requests from same IP in 1 minute

**Response:** Block source IP, enable rate limiting, fail over to cached content if possible

---

### PWDMGR-002: Multiple Device Registrations

Detects multiple new device registrations for same account in short timeframe.

**What It Detects:** 5+ device registrations to same vault account in 1 hour

**Response:** Verify devices with user, remove unknown devices, force password reset

**Why It Matters:** Each registered device is persistence mechanism for attacker

---

### PWDMGR-003: Unusual Vault Access Geolocation

Detects vault access from unusual geographic locations.

**What It Detects:** Vault access from location different than user's baseline

**Response:** Contact user to verify, if suspicious force password reset and enable MFA

---

### PWDMGR-004: API Token Abuse

Detects suspicious API token usage indicating token compromise.

**What It Detects:** 100+ API requests with valid token or unusual access pattern in 5 minutes

**Response:** Revoke suspicious tokens, verify what data was accessed, rotate credentials

---

### ACCESS-001: Sudo to Root by Non-Admin User

Detects non-admin users attempting sudo to root.

**What It Detects:** Non-whitelisted user executing sudo to become root

**Response:** Verify user identity, check command executed, investigate privilege escalation attempt

---

### ACCESS-003: Unusual Process Execution via Sudo

Detects suspicious process execution through sudo.

**What It Detects:** Unexpected or dangerous commands executed with sudo

**Response:** Kill suspicious process, investigate source, check for backdoors

---

### INFRA-004: Cryptocurrency Mining Detection

Detects cryptocurrency mining activity consuming system resources.

**What It Detects:** Mining process signatures or high CPU/network usage patterns

**Response:** Kill mining processes, check for persistence, patch vulnerability

---

### EXFIL-001: Bulk File Download Detection

Detects mass file downloads indicating data exfiltration.

**What It Detects:** 100+ file downloads (pdf/doc/xls/zip) from same IP in 10 minutes

**Response:** BLOCK source IP immediately, verify user identity, assess data exposed

**Time-Sensitive:** Data extraction may be happening NOW - respond immediately

---

### EXFIL-002: Large Data Transfer Detection

Detects unusually large data transfers.

**What It Detects:** 1GB+ data transfer in single session

**Response:** Identify destination, verify legitimacy, block if unauthorized

---

### EXFIL-003: DNS Tunneling Detection

Detects DNS tunneling attempts using DNS queries to exfiltrate data.

**What It Detects:** Abnormally long DNS queries or 100+ DNS queries in short timeframe

**Response:** Block suspicious DNS queries, identify source system, check for malware

---

### APP-004: Nextcloud Suspicious File Access

Detects suspicious file access patterns in Nextcloud.

**What It Detects:** 20+ document downloads from same user in 10 minutes

**Response:** Verify user identity, review what files accessed, assess data exposure

---

## MEDIUM Severity Rules

Medium severity rules detect suspicious patterns requiring investigation within **24 hours**. These warrant attention but are not immediate emergencies.

**Rules in this category:** 14 total

| Rule ID | Name | Category |
|---------|------|----------|
| AUTH-004 | Account Enumeration Attempt | Authentication |
| AUTH-009 | API Authentication Failures | Authentication |
| AUTH-011 | Admin Interface Access from Unusual IP | Authentication |
| ACCESS-002 | Unauthorized Administrative Access | Access Control |
| INFRA-001 | Port Scanning Detection | Infrastructure |
| INFRA-003 | Unusual Service Restart Pattern | Infrastructure |
| PROXY-003 | Path Traversal Attempt | Reverse Proxy |
| PROXY-004 | Directory Enumeration Detection | Reverse Proxy |
| PROXY-005 | Malicious User Agent Detection | Reverse Proxy |
| PROXY-006 | HTTP Method Abuse | Reverse Proxy |
| PROXY-007 | Large Request Body DoS | Reverse Proxy |
| APP-001 | Home Assistant Unauthorized Automation | Applications |
| APP-003 | Pi-hole DNS Anomaly | Applications |
| IOT-001 | Unusual Smart Device Automation Trigger | IoT |

### Investigation Guide for MEDIUM Rules

**Typical Response Timeline:**

1. **Within 4 hours:** Review alert and determine if legitimate
2. **Within 24 hours:** Full investigation and response
3. **Documentation:** Log findings for trend analysis

**Response Steps:**

1. **Verify legitimacy** - Is this expected activity?
2. **Assess impact** - If malicious, what could be compromised?
3. **Determine root cause** - Why did this alert trigger?
4. **Implement fix** - Change configuration, update systems, etc.
5. **Document** - Record for future reference

---

## LOW Severity Rules

Low severity rules detect patterns worth noting for trend analysis but don't require immediate action. These are informational and help establish baseline behavior.

**Rules in this category:** 4 total

| Rule ID | Name | Category |
|---------|------|----------|
| AUTH-006 | Authentication Outside Normal Hours | Authentication |
| ACCESS-004 | Service Account Interactive Login | Access Control |
| APP-002 | Unusual Media Streaming Pattern | Applications |
| IOT-002 | Smart Lock Repeated Failures | IoT |

### Low Severity Rule Purpose

These rules help identify:
- Baseline user behavior patterns
- Trend analysis over time
- Policy violations (after-hours access, service account misuse)
- Hardware/software issues (repeated lock failures)

**Action:** Archive for review as convenient, look for patterns over days/weeks

---

## Rule Management

### Tuning Rules for Your Environment

Rules are configured with baseline thresholds suitable for typical homelabs. However, your environment may be different.

#### Environment Factors

**Single User Homelab:**
- Fewer failed authentication attempts are expected
- Lower thresholds catch more attacks
- Less legitimate variation

**Multi-User Homelab:**
- More authentication failures expected (users making typos)
- Higher thresholds needed to avoid alert fatigue
- More legitimate variation

**24/7 Monitored:**
- Aggressive detection appropriate
- Lower thresholds acceptable
- After-hours alerts make sense

**Casual Monitoring:**
- Higher thresholds to reduce noise
- After-hours alerts may not be useful
- Focus on critical rules only

#### Tuning Process

**Step 1: Monitor and Identify False Positives**
- Run rules for 1-2 weeks
- Note which alerts are not real threats
- Record patterns

**Step 2: Analyze Root Causes**
```
Example: AUTH-001 (SSH Brute Force) alerting 10 times per day
- Cause: IT department testing SSH from same IP
- Solution: Whitelist that IP OR increase threshold
```

**Step 3: Implement Tuning**

Via UI:
1. Navigate to Detection Rules
2. Find the rule
3. Click "Edit"
4. Modify threshold (e.g., 5 failures → 10 failures)
5. Save

Via API:
```bash
curl -X PUT http://localhost:8421/api/rules/AUTH-001 \
  -H "Authorization: Bearer TOKEN" \
  -d '{"aggregation": {"threshold": 10}}'
```

**Step 4: Monitor for Effectiveness**
- Continue monitoring for 1-2 weeks
- Verify false positives decreased
- Verify real attacks still detected
- Fine-tune if needed

#### Common Tuning Scenarios

**Scenario: Too many SSH brute force alerts from internal network**

```yaml
# Solution 1: Whitelist internal network
exclude_conditions:
  - field: source_ip
    operator: in_list
    value: ["192.168.1.0/24"]

# Solution 2: Increase threshold
aggregation:
  threshold: 10  # was 5

# Solution 3: Only aggressive for external IPs
# Requires custom rule logic
```

**Scenario: Password manager alerts every time user exports vault**

```yaml
# Solution: Whitelist known backup time window
exclude_timeframes:
  - "02:00-04:00"  # Known backup time
```

### Creating Custom Rules

You can create rules for threats not covered by built-in rules.

#### Rule Template

```yaml
name: "[Clear Rule Name]"
description: "What this rule detects and why it matters"
severity: "critical|high|medium|low"
enabled: true
tags: ["tag1", "tag2"]

conditions:
  # What log fields must match?
  - field: field_name
    operator: equals|contains|regex
    value: "match_value"

# Optional: aggregate events before alerting
aggregation:
  field: field_to_group_by
  timeframe: "5m|10m|1h"
  threshold: 10

alert:
  title: "[Alert Title] from {source_ip}"
  description: "Detailed description with {field_variables}"
```

#### Example: Unauthorized Calendar Access Rule

```yaml
name: "Unauthorized Calendar Access"
description: "Detects access to calendar files outside normal patterns"
severity: high
enabled: true
tags: ["nextcloud", "data-theft"]

conditions:
  - field: service
    operator: equals
    value: "nextcloud"
  - field: path
    operator: contains
    value: "/calendar/"
  - field: user
    operator: not_equals
    value: "admin"

aggregation:
  field: user
  timeframe: 5m
  threshold: 10

alert:
  title: "Unauthorized Calendar Access by {user}"
  description: "{count} calendar file accesses by {user} from {source_ip}"
```

---

## Response Playbooks

### Playbook 1: Authentication Attack Response

**When to Use:** AUTH-001, AUTH-002, AUTH-003, AUTH-005, AUTH-007, AUTH-008, AUTH-010

#### Phase 1: Verify (0-5 minutes)

1. Contact affected user immediately
2. Ask: "Did you make this login attempt?"
3. Document response

**If YES (Legitimate):**
- Close alert with notation "verified legitimate"
- Continue monitoring

**If NO (Compromise Confirmed):**
- Proceed to Phase 2

#### Phase 2: Contain (5-15 minutes)

1. Force password reset for affected account
2. Kill existing sessions from suspicious IP
3. Block source IP at firewall if external
4. Enable MFA if available

#### Phase 3: Investigate (15-60 minutes)

1. Review all login attempts from suspicious IP
2. Check for successful logins
3. Determine what accounts were targeted
4. Check for privilege escalation attempts

#### Phase 4: Remediate (60+ minutes)

1. Change all sensitive credentials
2. Audit user accounts (new accounts created?)
3. Review sudo logs (unauthorized escalation?)
4. Check SSH keys (backdoors installed?)

---

### Playbook 2: Password Manager Compromise Response

**When to Use:** PWDMGR-001, PWDMGR-002, PWDMGR-003, PWDMGR-004, AUTH-005

**CRITICAL:** Treat as highest priority

#### Emergency Actions (0-10 minutes)

1. **Call vault owner immediately** (phone, not email)
2. Ask: "Did you just do this?"
3. If NO: **ASSUME ALL CREDENTIALS COMPROMISED**

#### Credential Priority Order

```
Priority 1 - Next 15 minutes:
- Email account(s)
- Vaultwarden admin
- SSH/shell access

Priority 2 - Next 60 minutes:
- Cloud storage
- Financial accounts
- Databases

Priority 3 - Within 6 hours:
- Media services
- Less critical apps
```

#### For Each Compromised Account

1. Change password immediately
2. Review account activity
3. Revoke active sessions
4. Enable MFA
5. Check for unauthorized API tokens

---

### Playbook 3: Data Exfiltration Response

**When to Use:** EXFIL-001, EXFIL-002, EXFIL-003

**Time-Sensitive:** Data theft may be happening NOW

#### Phase 1: STOP Data Transfer (0-5 minutes)

1. **Block source IP immediately:**
   ```bash
   firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="203.0.113.50" reject'
   ```

2. Kill user session (if web-based)

3. Rate limit (if DNS exfiltration)

#### Phase 2: Assess Data Loss (5-20 minutes)

1. What data was accessed?
2. How much data total?
3. How sensitive is data?
4. How long did exfiltration continue?

#### Phase 3: Investigation (20-60 minutes)

1. How did attacker get this access?
2. Is attacker still connected?
3. Are there backdoors installed?

#### Phase 4: Remediation (1-24 hours)

1. If credentials exposed: change ALL credentials
2. If personal data: notify affected individuals
3. Patch vulnerability that allowed access
4. Implement better monitoring

---

## Tuning Guidance

### Identifying False Positives

Monitor rules for patterns of non-threatening alerts:

1. Which rules generate most alerts?
2. What percentage are real threats vs. false positives?
3. What patterns lead to false positives?

### Adjusting Thresholds

**If too many false positives:**
- Increase threshold (e.g., 5 → 8)
- Extend timeframe (e.g., 5m → 10m)
- Whitelist known good sources
- Add exclusion conditions

**If missing attacks:**
- Lower threshold (e.g., 10 → 5)
- Reduce timeframe (e.g., 10m → 5m)
- Remove whitelists
- Expand conditions

### Alert Fatigue Management

Too many alerts = alerts ignored = real threats missed.

**Reduce Alert Volume:**
- Disable LOW severity rules if purely informational
- Whitelist known good activity
- Use time-based exclusions for maintenance windows
- Focus on actionable alerts only

---

## Contributing Rules

We welcome community detection rule contributions! If you've created a rule that detects interesting threats in your environment, share it with the community.

### How to Contribute a Rule

1. **Develop your rule** using the template in this document
2. **Test thoroughly** with real log data from your environment
3. **Tune thresholds** to minimize false positives
4. **Create a pull request** with:
   - Rule YAML file with complete configuration
   - Clear documentation of what it detects
   - Example logs and expected alert output
   - Tuning guidance for different environments
   - Response recommendations for analysts

### Rule Development Checklist

- [ ] Rule name is clear and action-oriented
- [ ] Description explains what threat it detects
- [ ] Severity level is appropriate (critical/high/medium/low)
- [ ] Conditions are tested and work correctly
- [ ] Aggregation timeframe and threshold are reasonable
- [ ] False positive rate is acceptable for your environment
- [ ] Alert message includes helpful context
- [ ] Documentation includes tuning guidance
- [ ] Rule tested with multiple log samples
- [ ] Response playbook or recommendations documented

### Rule Quality Guidelines

- **Keep logic simple**: Complex rules are harder to understand and maintain
- **Avoid regex overuse**: Consider structured field conditions instead
- **Document assumptions**: Note what environment/config the rule assumes
- **Provide examples**: Include real log samples that trigger the rule
- **Include context**: Alert messages should give analysts enough info to respond
- **Tune carefully**: Balance detection sensitivity with false positive rate
- **Test edge cases**: Consider incomplete logs, truncated fields, etc.

### Submission Process

1. Create rule in YAML format (see template above)
2. Test with real logs from your environment
3. Document expected behavior and tuning guidance
4. Submit pull request with:
   - Rule file(s) in `/rules/[category]/` directory
   - Updated `/docs/reference/RULES.md` with rule documentation
   - Example logs and alert output

### Performance Considerations

- Rules are evaluated on every incoming log
- Keep conditions simple to avoid CPU overhead
- Use aggregation to batch evaluations when appropriate
- Test with realistic log volume before contributing

### Community Rule Standards

Contributed rules will be evaluated for:
- **Accuracy**: Does it detect what it claims?
- **Performance**: Does it impact log processing speed?
- **Clarity**: Can operators understand what it does?
- **Usefulness**: Is this a threat worth detecting?
- **Documentation**: Is it well explained?

We may request changes to align with SIEMBox standards. This is a collaborative process!

---

## Troubleshooting

### Rules Not Generating Alerts

**Problem:** Rule is enabled but no alerts appear.

**Diagnosis:**
1. Check if rule is enabled
2. Verify parser is receiving logs
3. Test rule manually with sample log
4. Review rule conditions

**Solutions:**
- Check field names match parser output
- Verify operators are correct
- Test parser separately
- Enable debug logging

### Too Many False Positives

**Problem:** Rule generates constant alerts.

**Solutions (in order):**
1. Increase threshold
2. Extend timeframe
3. Whitelist known good sources
4. Add exclusion conditions
5. Disable rule if untunable

### Performance Issues

**Problem:** Rule engine is slow.

**Solutions:**
1. Disable complex rules
2. Disable LOW priority rules
3. Optimize aggregation
4. Use shorter timeframes

---

## Quick Rule Index

### By Category

- **Authentication (11):** AUTH-001 to AUTH-011
- **Password Manager (4):** PWDMGR-001 to PWDMGR-004
- **Reverse Proxy (8):** PROXY-001 to PROXY-008
- **Access Control (4):** ACCESS-001 to ACCESS-004
- **Infrastructure (4):** INFRA-001 to INFRA-004
- **Data Exfiltration (3):** EXFIL-001 to EXFIL-003
- **Applications (4):** APP-001 to APP-004
- **IoT & Smart Home (2):** IOT-001 to IOT-002

### By Severity

- **CRITICAL (5):** AUTH-002, AUTH-005, AUTH-008, INFRA-002, PWDMGR-001
- **HIGH (17):** AUTH-001, AUTH-003, AUTH-007, AUTH-010, PROXY-001, PROXY-002, PROXY-008, PWDMGR-002, PWDMGR-003, PWDMGR-004, ACCESS-001, ACCESS-003, INFRA-004, EXFIL-001, EXFIL-002, EXFIL-003, APP-004
- **MEDIUM (14):** AUTH-004, AUTH-009, AUTH-011, ACCESS-002, INFRA-001, INFRA-003, PROXY-003, PROXY-004, PROXY-005, PROXY-006, PROXY-007, APP-001, APP-003, IOT-001
- **LOW (4):** AUTH-006, ACCESS-004, APP-002, IOT-002

---

## Document Information

**Version:** 1.0
**Status:** Complete
**Last Updated:** December 2025
**Coverage:** All 40 detection rules documented
**Next Review:** Monthly

---

## Getting Help

- **Rule Issues:** [GitHub Issues](https://github.com/cladkins/SIEMBOX/issues)
- **Rule Development:** [GitHub Discussions](https://github.com/cladkins/SIEMBOX/discussions)
- **Submit Rules:** [GitHub Pull Requests](https://github.com/cladkins/SIEMBOX/pulls)

---

## License

MIT License - Same as SIEMBox
