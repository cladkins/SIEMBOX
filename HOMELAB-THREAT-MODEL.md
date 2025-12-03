# SIEMBox Homelab Threat Model

**Version:** 1.0
**Date:** 2025-12-03
**Purpose:** Comprehensive threat landscape analysis and detection rule specifications for self-hosted homelab environments

---

## Executive Summary

### Overview

Homelabbers face a unique threat landscape distinct from enterprise environments. With 90% using reverse proxies, limited security staff (typically 1 person), and internet-exposed services, homelabs are attractive targets for automated attacks and opportunistic attackers. This document provides a comprehensive threat model to guide the design of 30+ detection rules tailored for SIEMBox deployments in homelab environments.

### Key Findings

1. **High-Value Targets:** Password managers (Vaultwarden), authentication systems (Authelia, authentik), and personal data stores (Nextcloud, Immich) are the most critical assets requiring the strongest protection.

2. **Primary Attack Vectors:** Brute force authentication attacks, reverse proxy exploitation attempts, and credential stuffing dominate the threat landscape for internet-exposed homelabs.

3. **Alert Fatigue Risk:** Single-admin operations require carefully tuned thresholds to balance detection sensitivity with false positive rates. Critical alerts must be actionable and accurate.

4. **Detection Priority:** Authentication-based attacks (brute force, credential stuffing) and reverse proxy exploitation attempts are the highest priority threats requiring immediate detection capabilities.

### Top 8 Threat Categories

1. **Authentication Attacks** (Critical Priority)
2. **Reverse Proxy Exploitation** (Critical Priority)
3. **Password Manager Compromise** (Critical Priority)
4. **Access Control Violations** (High Priority)
5. **Data Exfiltration** (High Priority)
6. **Infrastructure Attacks** (High Priority)
7. **Application-Specific Threats** (Medium Priority)
8. **IoT/Smart Home Compromise** (Medium Priority)

### Detection Strategy Summary

- **30+ detection rules** covering all threat categories
- **Severity levels** aligned with asset criticality in homelab context
- **Threshold recommendations** optimized for small user bases (5-10 users)
- **Response playbooks** designed for single-admin scenarios
- **False positive mitigation** through careful aggregation timeframes

---

## Threat Landscape Analysis

### Homelab Characteristics

**Deployment Profile:**
- Internet-facing services via reverse proxies (NGINX Proxy Manager, Traefik, Caddy)
- Limited security expertise and resources
- Small user base (family, friends - typically 5-10 known users)
- Diverse technology stacks (20+ different applications common)
- Mix of critical (password vaults) and non-critical (media servers) assets
- Often running on consumer hardware/cloud VPS
- No 24/7 monitoring or dedicated security team

**Common Technology Stack:**
- **Reverse Proxies:** NGINX Proxy Manager (842 users), Traefik (751), Caddy (598), Cloudflare Tunnels (563)
- **Authentication:** Authelia (390), Pocket ID (310), authentik (268), Keycloak (158)
- **Password Management:** Vaultwarden (152) - CRITICAL TARGET
- **File/Photo Storage:** Nextcloud (118), Immich (429) - HIGH VALUE DATA
- **Home Automation:** Home Assistant (588) - IOT GATEWAY
- **Media Servers:** Jellyfin (522), Plex (208) - LOW PRIORITY
- **Network Security:** Pi-hole (50) - DNS SECURITY

### Attack Frequency Assessment

**Very High Frequency (Daily/Hourly):**
- SSH brute force attempts
- Web application scanning (path enumeration, vulnerability scanning)
- Generic authentication brute force
- Bot traffic and crawler abuse

**High Frequency (Weekly):**
- Credential stuffing from breached databases
- Targeted application exploitation attempts
- SQL injection probing
- Command injection attempts

**Medium Frequency (Monthly):**
- Targeted attacks following reconnaissance
- Password manager specific attacks
- API abuse and token theft attempts
- DNS tunneling and exfiltration attempts

**Low Frequency (Rare but High Impact):**
- Zero-day exploitation
- Advanced persistent threats
- Social engineering attacks
- Physical access attacks

### Attack Sophistication Levels

**Script Kiddies (95% of attacks):**
- Automated scanning tools (Nmap, Nikto, ZAP)
- Public exploit frameworks (Metasploit, SQLmap)
- Password spraying with common passwords
- Credential stuffing from public breach dumps
- **Detection Priority:** HIGH (volume creates risk)

**Opportunistic Attackers (4% of attacks):**
- Shodan/Censys reconnaissance
- Targeted vulnerability exploitation
- Credential stuffing with targeted wordlists
- Basic lateral movement attempts
- **Detection Priority:** HIGH (moderate skill, targeted)

**Advanced Attackers (1% of attacks):**
- Custom exploit development
- Multi-stage persistence
- Advanced evasion techniques
- **Detection Priority:** MEDIUM (rare but severe)

### Asset Value Matrix

| Asset Type | Examples | Value | Impact if Compromised |
|------------|----------|-------|----------------------|
| **CRITICAL** | Vaultwarden, Authentication Systems | Maximum | Total credential loss, complete breach |
| **HIGH** | Nextcloud, Immich, Private Documents | Very High | Personal data theft, privacy violation |
| **MEDIUM** | Home Assistant, Reverse Proxies | High | System access, lateral movement gateway |
| **LOW** | Media Servers, Public Services | Moderate | Service disruption, minor data exposure |
| **INFO** | Monitoring, Logging Systems | Low | Information disclosure only |

---

## Top 8 Threat Categories

### 1. Authentication Attacks (CRITICAL PRIORITY)

**Threat Overview:**
Authentication systems are the primary entry point for attackers targeting homelabs. With internet-exposed login pages and limited account lockout mechanisms, homelabs face constant brute force and credential stuffing attacks.

**Attack Patterns:**
- **Brute Force:** Automated password guessing against SSH, web logins, API endpoints
- **Credential Stuffing:** Using breached credentials from other services
- **Account Enumeration:** Identifying valid usernames before attack
- **Password Spraying:** Common passwords across many accounts
- **Timing-Based Attacks:** Slow brute force to evade detection

**Frequency:** Very High (Hourly attempts common)

**Sophistication:** Low to Medium (mostly automated tools)

**Target Applications:**
- SSH (port 22 or custom ports)
- Authelia/authentik authentication portals
- Vaultwarden login pages
- Nextcloud/Immich login endpoints
- Home Assistant login
- NGINX Proxy Manager admin interfaces

**Impact Assessment:**
- **Successful Brute Force:** Account compromise, unauthorized access
- **Credential Stuffing Success:** Multiple service compromise if passwords reused
- **Account Enumeration:** Targeted attack preparation
- **Password Manager Breach:** CATASTROPHIC - all credentials lost

**Detection Requirements:**
- Failed login attempt monitoring across all services
- Success-after-failures detection
- Unusual login patterns (time, location, frequency)
- Cross-service authentication correlation
- Account enumeration attempt detection

**Indicators of Compromise:**
- Multiple failed logins from single IP (5+ in 5 minutes)
- Failed logins from multiple IPs (distributed attack)
- Successful login after many failures
- Login attempts outside normal hours
- Logins from unexpected geographic locations
- Rapid sequential login attempts

---

### 2. Reverse Proxy Exploitation (CRITICAL PRIORITY)

**Threat Overview:**
With 90%+ of homelabbers using reverse proxies as the gateway to their services, these systems are the most exposed attack surface. Misconfigurations, outdated software, and lack of WAF capabilities make reverse proxies prime exploitation targets.

**Attack Patterns:**
- **SQL Injection:** Database exploitation via web inputs
- **Command Injection:** OS command execution via web parameters
- **Path Traversal:** Access to files outside web root
- **Server-Side Request Forgery (SSRF):** Internal service exploitation
- **HTTP Request Smuggling:** Proxy confusion attacks
- **Directory Enumeration:** Scanning for hidden endpoints
- **XXE (XML External Entity):** XML parser exploitation

**Frequency:** Very High (Constant scanning)

**Sophistication:** Low to High (automated scanners to manual exploitation)

**Target Applications:**
- NGINX Proxy Manager (most popular target)
- Traefik reverse proxy
- Caddy reverse proxy
- Standard NGINX configurations
- Apache reverse proxies

**Impact Assessment:**
- **SQL Injection Success:** Database compromise, data theft
- **Command Injection Success:** System-level access, full compromise
- **Path Traversal Success:** Sensitive file disclosure
- **SSRF Success:** Internal network access, lateral movement

**Detection Requirements:**
- Malicious payload detection in HTTP requests
- Directory enumeration detection (404 patterns)
- SQL injection pattern matching
- Command injection string detection
- Suspicious user-agent monitoring
- Excessive request rate detection
- Error rate spike monitoring

**Indicators of Compromise:**
- SQL keywords in URL parameters (`' OR '1'='1`, `UNION SELECT`)
- Command injection strings (`; rm -rf`, `| cat /etc/passwd`)
- Path traversal attempts (`../../../etc/passwd`)
- Rapid 404 errors from same IP (20+ in 5 minutes)
- Known scanner user agents (sqlmap, nikto, masscan)
- High request volumes (100+ requests in 1 minute)
- Unusual HTTP methods (TRACE, TRACK, DEBUG)

---

### 3. Password Manager Compromise (CRITICAL PRIORITY)

**Threat Overview:**
Vaultwarden (Bitwarden-compatible password manager) is the single highest-value target in any homelab. Successful compromise provides attackers with credentials to ALL other services. This threat category deserves dedicated, highly sensitive detection.

**Attack Patterns:**
- **Master Password Brute Force:** Direct attacks on vault unlock
- **API Authentication Bypass:** Exploiting API vulnerabilities
- **Session Token Theft:** Stealing authenticated sessions
- **Backup File Theft:** Targeting vault backups
- **Memory Scraping:** Runtime password extraction
- **Mass Export Operations:** Bulk credential theft

**Frequency:** Medium (Targeted attacks once discovered)

**Sophistication:** Medium to High (requires reconnaissance)

**Target Applications:**
- Vaultwarden server
- Bitwarden clients
- Vault backup locations
- Database files

**Impact Assessment:**
- **Master Password Compromise:** CATASTROPHIC - complete credential loss
- **Vault Export:** Total credential database theft
- **Session Hijacking:** Temporary access to all stored credentials
- **Backup Theft:** Offline attack opportunity

**Detection Requirements:**
- Master password failure monitoring (stricter than general auth)
- Vault export/download monitoring
- API token abuse detection
- Unusual vault access patterns
- Geographic anomaly detection
- Failed API authentication monitoring
- Database file access monitoring

**Indicators of Compromise:**
- 3+ failed master password attempts (very low threshold)
- Mass credential exports (10+ items in short timeframe)
- API authentication failures
- Vault access from new/unusual IPs
- Access during unusual hours
- Multiple device registrations in short period
- Database file reads outside normal backup schedule

---

### 4. Access Control Violations (HIGH PRIORITY)

**Threat Overview:**
After successful initial access, attackers attempt privilege escalation and lateral movement. Detecting unauthorized access attempts and privilege violations is critical for containing breaches before full compromise.

**Attack Patterns:**
- **Privilege Escalation:** Gaining admin/root access
- **Lateral Movement:** Moving between services/systems
- **Unauthorized Admin Access:** Accessing admin interfaces
- **API Abuse:** Exploiting API endpoints beyond authorization
- **File System Traversal:** Accessing restricted files
- **Container Escape:** Breaking out of Docker containers

**Frequency:** Medium (Post-compromise activity)

**Sophistication:** Medium to High

**Target Areas:**
- Sudo commands
- Administrative web interfaces
- API endpoints with elevated privileges
- Container runtime
- Database admin interfaces
- Configuration file access

**Impact Assessment:**
- **Privilege Escalation Success:** Full system control
- **Lateral Movement Success:** Multi-system compromise
- **Container Escape:** Host system access
- **Admin Interface Access:** Configuration tampering, backdoor creation

**Detection Requirements:**
- Sudo/su command monitoring
- Administrative action logging
- Unexpected process execution
- Container runtime anomaly detection
- File permission violation monitoring
- API rate limiting violation detection

**Indicators of Compromise:**
- Sudo to root by non-admin users
- Failed sudo attempts (3+ in 10 minutes)
- Admin interface access from unexpected IPs
- Unusual API endpoint access patterns
- Process execution from web directories
- Container runtime errors indicating escape attempts
- Access to sensitive files (/etc/shadow, database configs)

---

### 5. Data Exfiltration (HIGH PRIORITY)

**Threat Overview:**
Homelabs contain valuable personal data (photos, documents, backups). Detecting bulk data downloads or unusual transfer patterns is critical for preventing data theft.

**Attack Patterns:**
- **Bulk File Downloads:** Mass download of photos/documents
- **Database Dumps:** Exporting entire databases
- **DNS Tunneling:** Covert data exfiltration via DNS
- **Backup Theft:** Stealing backup archives
- **Cloud Sync Abuse:** Unauthorized cloud uploads
- **API-Based Exfiltration:** Automated data extraction via APIs

**Frequency:** Low to Medium (Post-compromise)

**Sophistication:** Medium to High

**Target Applications:**
- Nextcloud file shares
- Immich photo libraries
- Database servers
- Backup systems
- Document management (Paperless-ngx)

**Impact Assessment:**
- **Photo Library Theft:** Privacy violation, potential extortion
- **Document Theft:** Identity theft, financial fraud
- **Database Export:** Complete data loss, credential exposure
- **Backup Theft:** Historical data compromise

**Detection Requirements:**
- Large download volume monitoring
- Rapid file access patterns
- Database export detection
- DNS query anomaly detection
- Unusual backup activity
- API rate limit violations

**Indicators of Compromise:**
- 100+ files downloaded in 10 minutes
- Total download volume >5GB in 1 hour
- Database export commands executed
- Excessive DNS queries (DNS tunneling pattern)
- Backup files accessed outside backup schedule
- Mass API calls for file metadata/downloads

---

### 6. Infrastructure Attacks (HIGH PRIORITY)

**Threat Overview:**
Attacks targeting the underlying infrastructure (SSH, containers, system services) can provide persistent access and system-level control. Infrastructure compromise often precedes lateral movement to applications.

**Attack Patterns:**
- **SSH Brute Force:** Direct SSH password attacks
- **Port Scanning:** Network reconnaissance
- **Container Exploitation:** Docker/Podman vulnerabilities
- **Service Exploitation:** Vulnerable daemon exploitation
- **Denial of Service:** Resource exhaustion attacks
- **Cryptocurrency Mining:** Resource hijacking

**Frequency:** Very High for SSH, Medium for others

**Sophistication:** Low to Medium

**Target Areas:**
- SSH daemon (port 22 or custom)
- Docker API (if exposed)
- System services (systemd, cron)
- Network services (DNS, NTP)
- Resource limits (CPU, memory, disk)

**Impact Assessment:**
- **SSH Compromise:** System-level access, persistence
- **Container Escape:** Host system access
- **Service Exploitation:** Specific service compromise
- **DoS Success:** Service unavailability
- **Cryptomining:** Resource theft, increased costs

**Detection Requirements:**
- SSH authentication monitoring
- Port scan detection
- Unusual process monitoring
- Resource utilization anomalies
- Service restart/crash detection
- Network connection anomaly detection

**Indicators of Compromise:**
- 5+ failed SSH attempts in 5 minutes
- Successful SSH after multiple failures
- Rapid connection attempts to multiple ports
- Unexpected processes consuming high CPU/memory
- Service crashes or repeated restarts
- Unusual outbound connections
- Disk space exhaustion patterns

---

### 7. Application-Specific Threats (MEDIUM PRIORITY)

**Threat Overview:**
Popular homelab applications have unique security considerations. While typically lower priority than authentication/infrastructure, application-specific attacks can lead to service compromise and data exposure.

**Attack Patterns:**
- **Home Assistant Exploitation:** IoT control, automation abuse
- **Media Server Abuse:** Unauthorized streaming, sharing violations
- **Pi-hole Manipulation:** DNS poisoning, ad-blocking bypass
- **Container Registry Abuse:** Malicious image uploads
- **Git Repository Theft:** Source code exposure
- **Wiki/Documentation Access:** Information disclosure

**Frequency:** Low to Medium (Application-dependent)

**Sophistication:** Medium

**Target Applications:**
- Home Assistant automation platform
- Plex/Jellyfin media servers
- Pi-hole DNS server
- GitLab/Gitea repositories
- Container registries
- Wiki/documentation platforms

**Impact Assessment:**
- **Home Assistant Compromise:** Physical security risk, privacy invasion
- **Media Server Abuse:** Bandwidth theft, DMCA issues
- **DNS Poisoning:** Traffic redirection, phishing attacks
- **Repository Theft:** Intellectual property loss, credential exposure

**Detection Requirements:**
- Application-specific log monitoring
- Unusual automation trigger patterns
- Excessive media streaming detection
- DNS query anomaly detection
- Repository access monitoring
- Administrative action auditing

**Indicators of Compromise:**
- Unauthorized Home Assistant automation changes
- Excessive Plex/Jellyfin streaming (50+ streams)
- Unusual DNS responses or query patterns
- Git repository downloads by unauthorized users
- Container image uploads from unexpected sources
- Mass page access on wiki platforms

---

### 8. IoT and Smart Home Compromise (MEDIUM PRIORITY)

**Threat Overview:**
Home Assistant and other IoT platforms provide control over physical devices. Compromise can lead to privacy invasion, physical security risks, and broader network access via insecure IoT devices.

**Attack Patterns:**
- **Device Enumeration:** Discovering connected IoT devices
- **Command Injection:** Sending unauthorized commands to devices
- **Firmware Exploitation:** Exploiting vulnerable IoT firmware
- **Network Pivoting:** Using IoT devices for lateral movement
- **Surveillance Abuse:** Accessing cameras/microphones
- **Automation Tampering:** Changing smart home rules

**Frequency:** Low (Requires specific targeting)

**Sophistication:** Medium to High

**Target Devices:**
- Home Assistant integrations
- Smart locks and security systems
- Cameras and microphones
- Smart lights and switches
- Climate control systems
- Z-Wave/Zigbee controllers

**Impact Assessment:**
- **Camera/Microphone Access:** Privacy invasion, surveillance
- **Smart Lock Control:** Physical security breach
- **Automation Tampering:** Property damage, safety risks
- **Network Pivoting:** Broader network compromise

**Detection Requirements:**
- Unusual automation trigger patterns
- Device command anomalies
- Unauthorized device addition/removal
- Excessive device communication
- Failed device authentication
- Firmware update anomalies

**Indicators of Compromise:**
- Automation triggers at unusual times
- Mass device commands in short timeframe
- New devices added without admin action
- Failed authentication to IoT devices
- Unusual Z-Wave/Zigbee traffic patterns
- Camera/lock access from unexpected IPs

---

## Severity Matrix

### Severity Level Definitions

**CRITICAL:** Immediate threat to high-value assets requiring instant response. Potential for complete system compromise or total data loss. Examples: Password manager compromise, successful admin access, data exfiltration in progress.

**HIGH:** Serious security threat with potential for significant damage. Active attacks that could lead to compromise if not addressed quickly. Examples: SSH brute force, SQL injection attempts, privilege escalation attempts.

**MEDIUM:** Potentially malicious activity that warrants investigation. May indicate reconnaissance or low-sophistication attacks. Examples: Directory scanning, failed authentication attempts, unusual access patterns.

**LOW:** Informational alerts about minor security events or system health. May indicate normal activity or very low-risk events. Examples: Server errors, after-hours access by known users, non-critical service restarts.

**INFO:** Purely informational logging with no immediate security implications. Used for baseline monitoring and trend analysis. Examples: Successful logins, normal API usage, routine maintenance activities.

### Threat Category to Severity Mapping

| Threat Category | Base Severity | Escalation Conditions | Rationale |
|----------------|---------------|----------------------|-----------|
| **Authentication Attacks** | Medium → High | Critical if Vaultwarden or admin interfaces | Direct path to system access |
| **Reverse Proxy Exploitation** | Medium → High | Critical if exploit successful (5xx after injection attempt) | Primary attack surface for external threats |
| **Password Manager Compromise** | **CRITICAL** | Always critical | Single point of failure for all credentials |
| **Access Control Violations** | Medium → High | Critical if root/admin escalation detected | Indicates active compromise |
| **Data Exfiltration** | High | Critical if >10GB transferred | Irreversible data loss |
| **Infrastructure Attacks** | High | Medium if only reconnaissance | Foundation for lateral movement |
| **Application-Specific Threats** | Low → Medium | High if Home Assistant or critical app | Varies by application value |
| **IoT/Smart Home Compromise** | Low → Medium | High if physical security devices affected | Physical security implications |

### Asset Criticality Severity Adjustment

| Asset Type | Severity Multiplier | Examples |
|-----------|-------------------|----------|
| **Password Managers** | +2 levels | Vaultwarden brute force: Medium → CRITICAL |
| **Authentication Systems** | +1 level | Authelia/authentik attacks: Medium → HIGH |
| **Personal Data Stores** | +1 level | Nextcloud/Immich bulk access: Medium → HIGH |
| **Admin Interfaces** | +1 level | Proxy manager access: Low → MEDIUM |
| **Infrastructure Services** | +1 level | SSH compromise: Medium → HIGH |
| **Media Servers** | No change | Plex abuse stays LOW or MEDIUM |
| **Monitoring/Logging** | -1 level | Log system issues: MEDIUM → LOW |

### Time-Based Severity Escalation

Some threats escalate in severity based on persistence:

- **Sustained Attacks:** 3+ detection events in 1 hour → +1 severity level
- **Rapid Escalation:** Attack succeeds after detections → +2 severity levels
- **Multiple Targets:** Same attacker hitting 3+ services → +1 severity level
- **After-Hours Activity:** Critical asset access during off-hours → +1 severity level

---

## Detection Rule Specifications

### Rule Naming Convention

Format: `[Category]-[Number]: [Descriptive Name]`

Examples:
- `AUTH-001: SSH Brute Force Detection`
- `PROXY-001: SQL Injection Attempt`
- `PWDMGR-001: Vaultwarden Master Password Failures`

### Field Requirements

Detection rules require parsed log fields. Standard field names:

**Common Fields:**
- `timestamp` - Log event timestamp
- `source_ip` / `client_ip` - Source IP address
- `user` / `username` - Username involved
- `message` - Raw log message
- `event` / `event_type` - Event classification
- `severity` - Log severity level

**Authentication Fields:**
- `auth_result` - success/failure
- `auth_method` - password/key/token
- `target_user` - User being authenticated as

**HTTP/Proxy Fields:**
- `status_code` - HTTP status code
- `path` / `url` - Requested path
- `method` - HTTP method (GET/POST/etc)
- `user_agent` - Client user agent
- `bytes_sent` - Response size

**Application-Specific Fields:**
- `command` - Executed command (sudo logs)
- `service` - Service name
- `action` - Action performed
- `target` - Action target

---

## Detection Rules by Category

### Category 1: Authentication Attacks (10 Rules)

#### AUTH-001: SSH Brute Force Detection
**Priority:** HIGH
**Severity:** high
**Description:** Detects automated SSH brute force attacks based on failed password attempts

**Detection Logic:**
```yaml
conditions:
  - field: event
    operator: contains
    value: "Failed password"
  - field: service
    operator: equals
    value: "sshd"

aggregation:
  field: source_ip
  timeframe: 5m
  threshold: 5
```

**Threshold Rationale:** 5 failed attempts in 5 minutes balances detection with preventing false positives from legitimate user typos. Homelab environments have small user bases, so legitimate failures should be rare.

**False Positive Considerations:**
- User forgetting password (typically 2-3 attempts max)
- Misconfigured automation tools
- Mobile SSH client issues

**Tuning Guidance:**
- Increase threshold to 8-10 if false positives occur
- Decrease timeframe to 3m for more aggressive detection
- Add whitelist for known admin IPs

**Response Actions:**
1. Review source IP reputation
2. Check if any attempts succeeded
3. Verify IP is not from known admin
4. Consider IP blocking if persistent
5. Review SSH logs for successful access

---

#### AUTH-002: Successful Login After Failed Attempts
**Priority:** CRITICAL
**Severity:** critical
**Description:** Detects successful authentication immediately following multiple failures, indicating potential brute force success

**Detection Logic:**
```yaml
conditions:
  - field: event
    operator: contains
    value: "Accepted"
  - field: source_ip
    operator: exists
    value: true

aggregation:
  field: source_ip
  custom_query: true
  # Check for 3+ failures in 10 minutes before this success
```

**Threshold Rationale:** Any successful login after 3+ failures within 10 minutes is highly suspicious. Legitimate users typically don't succeed after multiple failures without a password reset.

**False Positive Considerations:**
- User with multiple devices/sessions
- Password recently changed (user forgetting new password)
- Typo corrections

**Tuning Guidance:**
- Adjust failure threshold to 5+ for less sensitive detection
- Whitelist known user IPs to reduce noise
- Correlate with user behavior patterns

**Response Actions:**
1. **IMMEDIATE:** Verify if legitimate user or compromise
2. Check if user was expected to log in
3. Review all actions taken during session
4. Consider session termination if suspicious
5. Force password reset if compromised

---

#### AUTH-003: Distributed Brute Force Attack
**Priority:** HIGH
**Severity:** high
**Description:** Detects coordinated brute force attacks from multiple IPs targeting same account

**Detection Logic:**
```yaml
conditions:
  - field: event
    operator: contains
    value: "Failed password"
  - field: user
    operator: exists
    value: true

aggregation:
  field: user
  timeframe: 15m
  threshold: 10
  distinct_count: source_ip >= 3
```

**Threshold Rationale:** 10 failed attempts from 3+ different IPs targeting same account within 15 minutes indicates distributed/botnet attack.

**False Positive Considerations:**
- Very rare for legitimate users
- Possibly misconfigured service with multiple servers

**Tuning Guidance:**
- Increase distinct IP threshold to 5+ for enterprise scenarios
- Adjust total attempts to 15+ if too sensitive
- Monitor for specific high-value accounts (admin, root)

**Response Actions:**
1. Identify targeted account
2. Implement account lockout if available
3. Review source IP geographic distribution
4. Consider temporary service restriction
5. Alert user if personal account targeted

---

#### AUTH-004: Account Enumeration Attempt
**Priority:** MEDIUM
**Severity:** medium
**Description:** Detects attempts to identify valid usernames by testing multiple accounts

**Detection Logic:**
```yaml
conditions:
  - field: event
    operator: contains
    value: "Invalid user"

aggregation:
  field: source_ip
  timeframe: 10m
  threshold: 10
  distinct_count: user >= 5
```

**Threshold Rationale:** 10 attempts to test 5+ different usernames from single IP indicates enumeration. Legitimate users know their username.

**False Positive Considerations:**
- Misconfigured automated tools
- User confusion on multi-tenant systems
- Very rare in homelab context

**Tuning Guidance:**
- Increase threshold to 15 attempts if noisy
- Reduce distinct user count to 3 for more aggressive detection
- Consider blocking after detection

**Response Actions:**
1. Log all tested usernames
2. Check if any valid users were discovered
3. Review source IP reputation
4. Consider IP blocking to prevent further reconnaissance
5. Monitor for escalation to brute force

---

#### AUTH-005: Vaultwarden Master Password Failures
**Priority:** CRITICAL
**Severity:** critical
**Description:** Detects failed master password attempts on Vaultwarden password manager

**Detection Logic:**
```yaml
conditions:
  - field: service
    operator: equals
    value: "vaultwarden"
  - field: message
    operator: contains
    value: "Invalid password"

aggregation:
  field: source_ip
  timeframe: 10m
  threshold: 3
```

**Threshold Rationale:** VERY LOW threshold (3 attempts) because Vaultwarden compromise is catastrophic. Any repeated failures require immediate investigation.

**False Positive Considerations:**
- User genuinely forgetting master password
- Browser autofill issues
- Mobile app sync problems

**Tuning Guidance:**
- DO NOT increase threshold above 5
- Consider threshold of 1 for maximum security
- Implement IP whitelisting for known users
- Enable MFA to mitigate brute force

**Response Actions:**
1. **IMMEDIATE INVESTIGATION REQUIRED**
2. Verify legitimate user or attack
3. Check if any attempts succeeded
4. Review all vault access from that IP
5. Consider temporary IP block
6. Contact vault owner immediately
7. Force session logout if suspicious

---

#### AUTH-006: Authentication Outside Normal Hours
**Priority:** LOW
**Severity:** low
**Description:** Detects successful authentication during unusual hours (00:00-06:00)

**Detection Logic:**
```yaml
conditions:
  - field: event
    operator: contains
    value: "Accepted"
  - field: timestamp
    operator: regex
    value: "T0[0-5]:"

alert:
  title: "After-Hours Authentication: {user} from {source_ip}"
  description: "Login detected between midnight and 6am"
```

**Threshold Rationale:** Single event detection. Low severity because some users have irregular schedules, but worth logging for pattern analysis.

**False Positive Considerations:**
- Night shift workers
- Different time zones
- Automated jobs/backups
- Users with irregular schedules

**Tuning Guidance:**
- Adjust time range based on your schedule
- Whitelist known automation IPs
- Disable if too noisy for your usage pattern
- Elevate to MEDIUM for critical services only

**Response Actions:**
1. Review user identity and typical schedule
2. Check what actions were performed
3. Verify geographic location matches user
4. Document as baseline if recurring pattern
5. Investigate if unusual for that specific user

---

#### AUTH-007: Multiple Failed Authelia/Authentik Attempts
**Priority:** HIGH
**Severity:** high
**Description:** Detects brute force attacks against SSO authentication portals

**Detection Logic:**
```yaml
conditions:
  - field: service
    operator: regex
    value: "authelia|authentik|keycloak"
  - field: event
    operator: contains
    value: "authentication failed"

aggregation:
  field: source_ip
  timeframe: 5m
  threshold: 5
```

**Threshold Rationale:** SSO systems protect multiple downstream services. 5 failures in 5 minutes indicates automated attack.

**False Positive Considerations:**
- Users forgetting SSO password (affects many services)
- Browser cookie/session issues
- Mobile app authentication problems

**Tuning Guidance:**
- Increase threshold to 8 if false positives occur
- Implement account lockout at SSO level
- Enable MFA for additional protection
- Whitelist known admin IPs

**Response Actions:**
1. Check if SSO compromise would affect multiple services
2. Review source IP reputation
3. Verify no successful authentications occurred
4. Consider temporary IP block
5. Alert affected user if personal account
6. Review SSO logs for any unusual activity

---

#### AUTH-008: Root SSH Login Attempt
**Priority:** CRITICAL
**Severity:** critical
**Description:** Detects direct root SSH login attempts (should always be disabled)

**Detection Logic:**
```yaml
conditions:
  - field: event
    operator: contains
    value: "Accepted"
  - field: user
    operator: equals
    value: "root"
  - field: service
    operator: equals
    value: "sshd"
```

**Threshold Rationale:** Single event detection. Direct root SSH login violates security best practices and should NEVER occur.

**False Positive Considerations:**
- None - direct root SSH should be disabled
- Emergency access scenarios (document these)
- Legacy systems not yet hardened

**Tuning Guidance:**
- No tuning needed - this should always alert
- Disable rule only if direct root SSH is policy-approved
- Document any legitimate root SSH access

**Response Actions:**
1. **IMMEDIATE INVESTIGATION REQUIRED**
2. Verify if legitimate admin or compromise
3. Review all commands executed as root
4. Check for persistence mechanisms installed
5. Disable direct root SSH immediately
6. Implement sudo-based administration
7. Consider system compromise if unexpected

---

#### AUTH-009: API Authentication Failures
**Priority:** MEDIUM
**Severity:** medium
**Description:** Detects repeated API authentication failures indicating token theft or API abuse

**Detection Logic:**
```yaml
conditions:
  - field: message
    operator: contains
    value: "API authentication failed"
  - field: status_code
    operator: equals
    value: "401"

aggregation:
  field: source_ip
  timeframe: 10m
  threshold: 10
```

**Threshold Rationale:** APIs typically have higher failure tolerance than interactive auth. 10 failures in 10 minutes indicates brute force or token guessing.

**False Positive Considerations:**
- Expired API tokens
- Misconfigured automation
- Mobile app token refresh issues
- Development/testing activity

**Tuning Guidance:**
- Increase threshold to 20 for noisy APIs
- Whitelist known automation IPs
- Adjust timeframe to 15m for less aggressive detection
- Track specific API endpoints separately

**Response Actions:**
1. Identify targeted API endpoint
2. Review API token usage patterns
3. Check for any successful authentications
4. Verify source IP legitimacy
5. Consider API rate limiting
6. Rotate API tokens if compromised

---

#### AUTH-010: Cross-Service Authentication Failures
**Priority:** HIGH
**Severity:** high
**Description:** Detects same IP failing authentication across multiple different services (credential stuffing)

**Detection Logic:**
```yaml
conditions:
  - field: message
    operator: contains
    value: "authentication failed"

aggregation:
  field: source_ip
  timeframe: 15m
  threshold: 15
  distinct_count: service >= 3
```

**Threshold Rationale:** 15 failures across 3+ different services indicates credential stuffing attack using breached password lists.

**False Positive Considerations:**
- User forgetting password after change
- Browser autofill issues across services
- Mobile device authentication problems
- Very rare in legitimate use

**Tuning Guidance:**
- Increase service count to 5+ for large homelabs
- Adjust threshold to 20+ if too sensitive
- Monitor for specific credential pairs being tested

**Response Actions:**
1. **High priority - potential credential stuffing**
2. Identify all services targeted
3. Review if any authentications succeeded
4. Check source IP reputation/geolocation
5. Consider blocking IP immediately
6. Verify users' passwords not in breach databases
7. Recommend password changes if compromised

---

### Category 2: Reverse Proxy Exploitation (8 Rules)

#### PROXY-001: SQL Injection Attempt
**Priority:** HIGH
**Severity:** high
**Description:** Detects SQL injection patterns in HTTP requests

**Detection Logic:**
```yaml
conditions:
  - field: path
    operator: regex
    value: "('|\"|;|--|\bOR\b|\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b)"
  - field: status_code
    operator: exists
    value: true
```

**Threshold Rationale:** Single event detection for any SQL injection pattern. Even failed attempts indicate reconnaissance.

**False Positive Considerations:**
- Legitimate SQL queries in documentation URLs
- Code examples in technical forums
- Very rare for legitimate traffic

**Tuning Guidance:**
- Whitelist known safe paths (docs, forums)
- Adjust regex to reduce specific false positives
- Elevate to CRITICAL if 5xx response (potential success)

**Response Actions:**
1. Review full request including parameters
2. Check response code (200/5xx indicates potential success)
3. Identify targeted application/endpoint
4. Review database logs for actual queries
5. Block source IP immediately
6. Verify database integrity
7. Check for data exfiltration

---

#### PROXY-002: Command Injection Attempt
**Priority:** HIGH
**Severity:** high
**Description:** Detects command injection patterns in HTTP requests

**Detection Logic:**
```yaml
conditions:
  - field: path
    operator: regex
    value: "(;|\\||`|\\$\\(|\\||&&|cat|curl|wget|bash|sh|cmd\\.exe)"
  - field: method
    operator: regex
    value: "GET|POST"
```

**Threshold Rationale:** Single event detection. Command injection attempts are always malicious.

**False Positive Considerations:**
- Terminal emulator web apps (gotty, wetty)
- Code hosting platforms
- Very rare otherwise

**Tuning Guidance:**
- Whitelist known terminal applications
- Adjust pattern for specific false positives
- Monitor response codes for success indicators

**Response Actions:**
1. **HIGH PRIORITY** - potential system compromise
2. Check if command executed (5xx error, unusual response time)
3. Review system process list for unexpected processes
4. Examine system logs for command execution
5. Block IP immediately
6. Search for persistence mechanisms
7. Consider system quarantine if successful

---

#### PROXY-003: Path Traversal Attempt
**Priority:** MEDIUM
**Severity:** medium
**Description:** Detects attempts to access files outside web root

**Detection Logic:**
```yaml
conditions:
  - field: path
    operator: regex
    value: "(\\.\\.[\\/\\\\]|\\.\\.%2f|\\.\\.%5c)"
```

**Threshold Rationale:** Single event detection. Path traversal attempts indicate reconnaissance or exploitation.

**False Positive Considerations:**
- Legitimate relative paths in APIs
- Static asset loading
- Very uncommon

**Tuning Guidance:**
- Whitelist known legitimate patterns
- Combine with status code for refined detection
- Escalate to HIGH if sensitive file requested

**Response Actions:**
1. Review requested file path
2. Check response code (200 = success = CRITICAL)
3. Verify file was not actually served
4. Block IP if persistent attempts
5. Review web server configuration
6. Ensure proper path sanitization

---

#### PROXY-004: Directory Enumeration Detection
**Priority:** MEDIUM
**Severity:** medium
**Description:** Detects automated directory/file scanning via 404 patterns

**Detection Logic:**
```yaml
conditions:
  - field: status_code
    operator: equals
    value: "404"

aggregation:
  field: client_ip
  timeframe: 5m
  threshold: 20
```

**Threshold Rationale:** 20 404s in 5 minutes indicates automated scanning. Legitimate users don't generate this many missing page requests.

**False Positive Considerations:**
- Broken links on site
- Aggressive web crawlers
- Development/testing activity
- Mobile app API polling

**Tuning Guidance:**
- Increase threshold to 30-50 for high-traffic sites
- Whitelist known crawler IPs (Google, Bing)
- Adjust timeframe to 10m for less sensitivity
- Track specific path patterns separately

**Response Actions:**
1. Review requested paths for patterns
2. Identify scanner type (dirbuster, nikto, etc.)
3. Check source IP reputation
4. Verify no sensitive paths were discovered
5. Consider rate limiting or IP blocking
6. Monitor for escalation to exploitation

---

#### PROXY-005: Malicious User Agent Detection
**Priority:** LOW
**Severity:** low
**Description:** Detects known security scanner user agents

**Detection Logic:**
```yaml
conditions:
  - field: user_agent
    operator: regex
    value: "(sqlmap|nikto|nmap|masscan|metasploit|burp|zap|acunetix|nessus|openvas)"
```

**Threshold Rationale:** Single event detection. Scanning tools should never access production homelab services.

**False Positive Considerations:**
- Authorized security testing
- Penetration testing by owner
- Network security tools

**Tuning Guidance:**
- Whitelist your own security scanning IPs
- Document authorized testing activity
- Combine with other indicators for higher confidence

**Response Actions:**
1. Verify if authorized security testing
2. Review source IP and timing
3. Check what endpoints were accessed
4. Block IP if unauthorized
5. Monitor for actual exploitation attempts
6. Document for security metrics

---

#### PROXY-006: HTTP Method Abuse
**Priority:** MEDIUM
**Severity:** medium
**Description:** Detects unusual HTTP methods that may indicate exploitation attempts

**Detection Logic:**
```yaml
conditions:
  - field: method
    operator: regex
    value: "(TRACE|TRACK|DEBUG|OPTIONS|CONNECT)"
```

**Threshold Rationale:** Single event detection. These methods are rarely legitimate and often used for vulnerability research.

**False Positive Considerations:**
- CORS preflight requests (OPTIONS)
- Legitimate debugging tools
- API testing frameworks

**Tuning Guidance:**
- Whitelist OPTIONS for APIs with CORS
- Disable rule if methods are policy-approved
- Monitor specific methods separately

**Response Actions:**
1. Identify specific method used
2. Review request headers and path
3. Check if method is enabled/necessary
4. Disable unnecessary HTTP methods
5. Monitor for exploitation attempts
6. Log for security audit trail

---

#### PROXY-007: Large Request Body (Potential DoS)
**Priority:** MEDIUM
**Severity:** medium
**Description:** Detects unusually large request bodies that may indicate DoS or upload abuse

**Detection Logic:**
```yaml
conditions:
  - field: request_size
    operator: greater_than
    value: 104857600  # 100MB

alert:
  title: "Large Request from {client_ip}"
  description: "Request size: {request_size} bytes to {path}"
```

**Threshold Rationale:** 100MB requests are unusual for most homelab services. Adjust based on legitimate use cases (file uploads, backups).

**False Positive Considerations:**
- Legitimate file uploads (Nextcloud, photo uploads)
- Backup operations
- Video streaming uploads
- Database restores

**Tuning Guidance:**
- Adjust size threshold based on your services
- Whitelist known upload endpoints (Nextcloud, Immich)
- Reduce to 10MB for services without upload functionality
- Monitor for repeated large requests

**Response Actions:**
1. Identify target endpoint
2. Verify if legitimate upload/operation
3. Check if request completed successfully
4. Monitor disk space and bandwidth
5. Implement request size limits if needed
6. Consider rate limiting for upload endpoints

---

#### PROXY-008: High Request Rate (Potential DoS)
**Priority:** HIGH
**Severity:** high
**Description:** Detects excessive request rates indicating DoS attack or abuse

**Detection Logic:**
```yaml
conditions:
  - field: client_ip
    operator: exists
    value: true

aggregation:
  field: client_ip
  timeframe: 1m
  threshold: 100
```

**Threshold Rationale:** 100 requests per minute from single IP is excessive for homelab services. Legitimate users rarely exceed 20-30 req/min.

**False Positive Considerations:**
- API-heavy applications
- Real-time data polling
- Mobile app sync operations
- Automated monitoring tools

**Tuning Guidance:**
- Increase threshold to 200+ for API-heavy services
- Whitelist known automation IPs
- Adjust timeframe to 5m for less aggressive detection
- Track specific endpoints separately

**Response Actions:**
1. **Potential DoS attack** - prioritize investigation
2. Review request patterns and endpoints
3. Check server resource utilization
4. Implement rate limiting immediately
5. Block IP if clearly malicious
6. Monitor for distributed attacks
7. Consider enabling DDoS protection

---

### Category 3: Password Manager Security (4 Rules)

#### PWDMGR-001: Vaultwarden Vault Export
**Priority:** CRITICAL
**Severity:** critical
**Description:** Detects vault export operations that could indicate credential theft

**Detection Logic:**
```yaml
conditions:
  - field: service
    operator: equals
    value: "vaultwarden"
  - field: action
    operator: equals
    value: "vault_export"

alert:
  title: "CRITICAL: Vault Export by {user} from {source_ip}"
  description: "Complete credential vault export detected"
```

**Threshold Rationale:** Single event detection. Vault exports are rare operations that should be closely monitored.

**False Positive Considerations:**
- Legitimate user backup operations
- Migration to new device/service
- Scheduled backup automation

**Tuning Guidance:**
- Document all legitimate export operations
- Require MFA for vault exports
- Alert on ANY export for maximum visibility
- Consider blocking exports entirely if not needed

**Response Actions:**
1. **IMMEDIATE INVESTIGATION** - potential credential theft
2. Verify legitimate user operation
3. Contact user immediately to confirm
4. Review export contents if accessible
5. Check for subsequent unusual activity
6. Force password changes if compromised
7. Review all vault access logs

---

#### PWDMGR-002: Multiple Device Registrations
**Priority:** HIGH
**Severity:** high
**Description:** Detects rapid registration of multiple devices/clients to password vault

**Detection Logic:**
```yaml
conditions:
  - field: service
    operator: equals
    value: "vaultwarden"
  - field: event
    operator: contains
    value: "device registered"

aggregation:
  field: user
  timeframe: 1h
  threshold: 3
```

**Threshold Rationale:** 3 device registrations in 1 hour is unusual. Legitimate users typically register devices infrequently.

**False Positive Considerations:**
- User setting up multiple new devices
- Family members using shared account (discouraged)
- Reinstalling apps after system restore

**Tuning Guidance:**
- Increase threshold to 5 for multi-device households
- Adjust timeframe to 24h for less sensitivity
- Document legitimate bulk device setups

**Response Actions:**
1. Identify user and devices registered
2. Verify legitimate user activity
3. Check device types and IP addresses
4. Contact user to confirm device registrations
5. Review for suspicious geographic locations
6. Force re-authentication if suspicious
7. Enable device approval workflow if available

---

#### PWDMGR-003: Unusual Vault Access Geolocation
**Priority:** HIGH
**Severity:** high
**Description:** Detects vault access from unexpected geographic locations

**Detection Logic:**
```yaml
conditions:
  - field: service
    operator: equals
    value: "vaultwarden"
  - field: event
    operator: equals
    value: "vault_unlock"
  - field: country
    operator: not_equals
    value: "{user_home_country}"  # Requires GeoIP enrichment
```

**Threshold Rationale:** Single event detection for access outside user's typical country. Requires GeoIP data enrichment.

**False Positive Considerations:**
- User traveling abroad
- VPN usage changing apparent location
- Tor or privacy proxy usage
- International family members

**Tuning Guidance:**
- Whitelist known travel destinations
- Document VPN exit nodes
- Consider regional zones instead of country-level
- Adjust based on user's typical patterns

**Response Actions:**
1. Verify user travel status
2. Contact user immediately to confirm
3. Check for concurrent logins from different locations
4. Review all vault items accessed
5. Consider session termination if suspicious
6. Enable geographic restrictions if available
7. Recommend travel mode or alerting

---

#### PWDMGR-004: API Token Abuse
**Priority:** HIGH
**Severity:** high
**Description:** Detects excessive API access to vault indicating automated credential harvesting

**Detection Logic:**
```yaml
conditions:
  - field: service
    operator: equals
    value: "vaultwarden"
  - field: path
    operator: contains
    value: "/api/"

aggregation:
  field: source_ip
  timeframe: 10m
  threshold: 50
```

**Threshold Rationale:** 50 API calls in 10 minutes exceeds normal client sync behavior. Indicates automated access or abuse.

**False Positive Considerations:**
- Initial vault sync after new installation
- Multiple devices syncing simultaneously
- Browser extension background sync
- Mobile app aggressive polling

**Tuning Guidance:**
- Increase threshold to 100 for multi-device users
- Whitelist known client sync patterns
- Adjust timeframe to 5m for more aggressive detection
- Monitor specific API endpoints separately

**Response Actions:**
1. Identify API endpoints being accessed
2. Review authentication method (token vs session)
3. Check what vault data was accessed
4. Verify source IP matches known devices
5. Consider API rate limiting
6. Revoke API tokens if compromised
7. Force re-authentication of all clients

---

### Category 4: Access Control & Privilege Escalation (4 Rules)

#### ACCESS-001: Sudo to Root by Non-Admin
**Priority:** HIGH
**Severity:** high
**Description:** Detects sudo privilege escalation by users not in admin group

**Detection Logic:**
```yaml
conditions:
  - field: command
    operator: contains
    value: "sudo"
  - field: target_user
    operator: equals
    value: "root"
  - field: user
    operator: not_equals
    value: "{admin_users}"  # Requires user whitelist
```

**Threshold Rationale:** Single event detection. Non-admin users should not sudo to root in properly configured systems.

**False Positive Considerations:**
- Legitimate admin users not in whitelist
- Emergency access scenarios
- Improperly configured user roles

**Tuning Guidance:**
- Maintain accurate admin user whitelist
- Adjust for temporary admin delegations
- Document all legitimate sudo-to-root users

**Response Actions:**
1. Verify user identity and authorization
2. Review command being executed as root
3. Check if legitimate administrative task
4. Investigate if user account compromised
5. Review sudo configuration
6. Revoke sudo access if unauthorized
7. Audit all actions taken as root

---

#### ACCESS-002: Failed Sudo Attempts
**Priority:** MEDIUM
**Severity:** medium
**Description:** Detects repeated failed sudo attempts indicating privilege escalation reconnaissance

**Detection Logic:**
```yaml
conditions:
  - field: message
    operator: contains
    value: "sudo: authentication failure"

aggregation:
  field: user
  timeframe: 10m
  threshold: 3
```

**Threshold Rationale:** 3 failed sudo attempts in 10 minutes indicates password guessing or compromised user account attempting escalation.

**False Positive Considerations:**
- User forgetting sudo password
- Typos in password entry
- Recently changed password confusion

**Tuning Guidance:**
- Increase threshold to 5 for forgiving detection
- Adjust timeframe to 15m
- Track specific commands being attempted

**Response Actions:**
1. Identify user and commands attempted
2. Check if user has legitimate sudo rights
3. Review if account may be compromised
4. Verify recent account activity
5. Consider account lock if excessive failures
6. Investigate if persistent attempts continue

---

#### ACCESS-003: Unusual Process Execution
**Priority:** HIGH
**Severity:** high
**Description:** Detects execution of unusual processes that may indicate exploitation

**Detection Logic:**
```yaml
conditions:
  - field: process_name
    operator: regex
    value: "(nc|ncat|socat|telnet|wget|curl|python|perl|ruby|php).*-e"
  - field: parent_process
    operator: contains
    value: "www-data|nginx|apache"
```

**Threshold Rationale:** Single event detection. Shell spawning from web processes indicates potential compromise.

**False Positive Considerations:**
- Legitimate web application functions (rare)
- Administrative scripts run via web interface
- CI/CD pipeline operations

**Tuning Guidance:**
- Whitelist known legitimate processes
- Adjust parent process list for your web servers
- Monitor process arguments for reverse shells

**Response Actions:**
1. **HIGH PRIORITY** - potential web shell or exploitation
2. Identify process details and arguments
3. Review web server logs for exploitation attempts
4. Check file system for web shells
5. Terminate suspicious processes
6. Investigate parent process origin
7. Consider system quarantine if active compromise

---

#### ACCESS-004: Admin Interface Access from Unusual IP
**Priority:** MEDIUM
**Severity:** medium
**Description:** Detects access to admin interfaces from IPs outside whitelist

**Detection Logic:**
```yaml
conditions:
  - field: path
    operator: regex
    value: "/admin|/administration|/manage|/dashboard"
  - field: client_ip
    operator: not_in_list
    value: "{admin_ip_whitelist}"
```

**Threshold Rationale:** Single event detection. Admin interfaces should only be accessed from known IPs (local network, VPN, specific public IPs).

**False Positive Considerations:**
- Admin accessing from new location
- Mobile admin access
- VPN IP changes
- Dynamic IP address changes

**Tuning Guidance:**
- Maintain accurate admin IP whitelist
- Consider IP ranges instead of individual IPs
- Document temporary admin access scenarios
- Use VPN requirement for admin access

**Response Actions:**
1. Review source IP and geographic location
2. Verify if legitimate admin access
3. Check what admin actions were performed
4. Contact admin to confirm if unexpected
5. Review for credential compromise
6. Consider session termination if suspicious
7. Enforce VPN requirement for admin access

---

### Category 5: Data Exfiltration (3 Rules)

#### EXFIL-001: Bulk File Download Detection
**Priority:** HIGH
**Severity:** high
**Description:** Detects mass file downloads indicating data exfiltration

**Detection Logic:**
```yaml
conditions:
  - field: service
    operator: regex
    value: "nextcloud|immich|paperless"
  - field: action
    operator: equals
    value: "file_download"

aggregation:
  field: source_ip
  timeframe: 10m
  threshold: 100
```

**Threshold Rationale:** 100 file downloads in 10 minutes exceeds normal user behavior. Indicates automated data harvesting.

**False Positive Considerations:**
- Legitimate bulk downloads by user
- Sync client initial synchronization
- Backup/archive operations
- Photo/video collection downloads

**Tuning Guidance:**
- Adjust threshold based on typical user download patterns
- Whitelist sync client IPs/user agents
- Increase threshold to 200+ for photo libraries
- Monitor file size in addition to count

**Response Actions:**
1. **HIGH PRIORITY** - potential data theft
2. Identify user and files accessed
3. Calculate total data volume transferred
4. Verify if legitimate user operation
5. Check for concurrent suspicious activity
6. Consider rate limiting or session termination
7. Review for compromised credentials

---

#### EXFIL-002: Large Data Transfer
**Priority:** HIGH
**Severity:** high
**Description:** Detects unusually large data transfers that may indicate exfiltration

**Detection Logic:**
```yaml
conditions:
  - field: bytes_sent
    operator: greater_than
    value: 5368709120  # 5GB

aggregation:
  field: source_ip
  timeframe: 1h
  threshold: 1
```

**Threshold Rationale:** 5GB transfer in 1 hour is unusual for homelab services. Adjust based on legitimate use cases.

**False Positive Considerations:**
- Legitimate large file transfers
- Video streaming/downloads
- Backup operations
- Photo/video uploads
- Media library syncing

**Tuning Guidance:**
- Adjust size threshold for your typical usage
- Whitelist known backup IPs
- Increase threshold to 10GB+ for media servers
- Monitor specific services separately

**Response Actions:**
1. Identify service and user involved
2. Review what data was transferred
3. Verify legitimate operation or exfiltration
4. Check for compromised credentials
5. Monitor for continued large transfers
6. Implement bandwidth throttling if needed
7. Review data sensitivity of transferred files

---

#### EXFIL-003: DNS Tunneling Detection
**Priority:** MEDIUM
**Severity:** medium
**Description:** Detects DNS query patterns indicating data exfiltration via DNS tunneling

**Detection Logic:**
```yaml
conditions:
  - field: service
    operator: equals
    value: "dns"
  - field: query_type
    operator: equals
    value: "TXT"

aggregation:
  field: source_ip
  timeframe: 5m
  threshold: 50
```

**Threshold Rationale:** 50 TXT queries in 5 minutes is unusual. Legitimate TXT queries are infrequent (SPF, DKIM, verification).

**False Positive Considerations:**
- Legitimate bulk TXT lookups
- Email server verification checks
- Certificate validation processes
- Security tool scanning

**Tuning Guidance:**
- Monitor subdomain length (>30 chars indicates tunneling)
- Track specific domains being queried
- Combine with unusual query patterns
- Whitelist known legitimate TXT lookups

**Response Actions:**
1. Review DNS queries and target domains
2. Identify source system generating queries
3. Check for data encoding in subdomains
4. Verify if tunneling tool detected
5. Block DNS tunneling at firewall if confirmed
6. Investigate source system for compromise
7. Implement DNS query monitoring

---

### Category 6: Infrastructure Attacks (4 Rules)

#### INFRA-001: Port Scan Detection
**Priority:** MEDIUM
**Severity:** medium
**Description:** Detects network port scanning reconnaissance

**Detection Logic:**
```yaml
conditions:
  - field: event
    operator: contains
    value: "connection refused"

aggregation:
  field: source_ip
  timeframe: 5m
  threshold: 10
  distinct_count: destination_port >= 5
```

**Threshold Rationale:** 10 connection attempts to 5+ different ports in 5 minutes indicates scanning.

**False Positive Considerations:**
- Service discovery by legitimate tools
- Network troubleshooting
- Misconfigured applications
- Load balancer health checks

**Tuning Guidance:**
- Increase port count to 10+ for stricter detection
- Adjust threshold to 20+ for noisy environments
- Whitelist network monitoring tools
- Track TCP vs UDP separately

**Response Actions:**
1. Identify scan type (TCP/UDP/SYN)
2. Review ports being scanned
3. Check source IP reputation
4. Block IP to prevent further reconnaissance
5. Verify no services were discovered
6. Monitor for escalation to exploitation

---

#### INFRA-002: Container Escape Attempt
**Priority:** CRITICAL
**Severity:** critical
**Description:** Detects attempts to escape container isolation

**Detection Logic:**
```yaml
conditions:
  - field: message
    operator: regex
    value: "(docker\.sock|/proc/self/cgroup|/sys/class/net|capsh|unshare|nsenter)"
  - field: process_name
    operator: not_equals
    value: "docker"
```

**Threshold Rationale:** Single event detection. Container escape attempts indicate advanced attacker and are critical security events.

**False Positive Considerations:**
- Legitimate container management operations
- Docker-in-docker scenarios
- Container orchestration tools
- Security scanning tools

**Tuning Guidance:**
- Whitelist known management processes
- Document legitimate docker.sock access
- Monitor specific escape techniques separately

**Response Actions:**
1. **CRITICAL** - potential full system compromise
2. Identify container and process attempting escape
3. Immediately isolate container if possible
4. Review container runtime configuration
5. Check for privilege escalation
6. Verify host system integrity
7. Consider container termination
8. Audit all recent container activities

---

#### INFRA-003: Unusual Service Restart Pattern
**Priority:** MEDIUM
**Severity:** medium
**Description:** Detects repeated service restarts that may indicate crashes or tampering

**Detection Logic:**
```yaml
conditions:
  - field: event
    operator: contains
    value: "service.*restart"

aggregation:
  field: service_name
  timeframe: 15m
  threshold: 3
```

**Threshold Rationale:** 3 restarts in 15 minutes indicates instability, exploitation attempts, or tampering.

**False Positive Considerations:**
- Legitimate service updates
- Configuration testing
- Automated deployment processes
- Known unstable services

**Tuning Guidance:**
- Whitelist services with known restart patterns
- Adjust threshold for stable vs unstable services
- Document planned restarts
- Track restart reasons separately

**Response Actions:**
1. Identify service and restart reason
2. Review service logs for errors/crashes
3. Check for exploitation indicators
4. Verify service configuration integrity
5. Monitor service behavior post-restart
6. Investigate if restarts continue
7. Consider service isolation if suspicious

---

#### INFRA-004: Cryptocurrency Mining Detection
**Priority:** HIGH
**Severity:** high
**Description:** Detects cryptocurrency mining activity based on process and network patterns

**Detection Logic:**
```yaml
conditions:
  - field: process_name
    operator: regex
    value: "(xmrig|minergate|ethminer|cpuminer|cgminer|bfgminer)"

alert:
  title: "Crypto Mining Detected: {process_name}"
  description: "Unauthorized mining process on {hostname}"
```

**Threshold Rationale:** Single event detection. Cryptocurrency mining should never occur on homelab infrastructure.

**False Positive Considerations:**
- Authorized mining operations (rare)
- Security research/honeypot activity
- Mining pool testing

**Tuning Guidance:**
- Whitelist if authorized mining
- Monitor CPU usage patterns in addition
- Track network connections to mining pools
- Combine with unusual process detection

**Response Actions:**
1. **HIGH PRIORITY** - resource theft and likely compromise
2. Terminate mining process immediately
3. Identify how miner was installed
4. Check for persistence mechanisms (cron, systemd)
5. Review recent system access logs
6. Scan for additional malware
7. Investigate initial compromise vector
8. Restore from clean backup if necessary

---

### Category 7: Application-Specific Threats (4 Rules)

#### APP-001: Home Assistant Unauthorized Automation Change
**Priority:** MEDIUM
**Severity:** medium
**Description:** Detects changes to Home Assistant automations from unexpected sources

**Detection Logic:**
```yaml
conditions:
  - field: service
    operator: equals
    value: "homeassistant"
  - field: action
    operator: equals
    value: "automation_edited"

alert:
  title: "Home Assistant Automation Modified"
  description: "Automation {automation_name} changed by {user}"
```

**Threshold Rationale:** Single event detection. Automation changes should be logged and reviewed for unauthorized modifications.

**False Positive Considerations:**
- Legitimate user configuration changes
- Automated rule tuning by ML features
- Mobile app configuration edits

**Tuning Guidance:**
- Whitelist known admin users
- Document legitimate automation changes
- Track specific critical automations separately
- Adjust severity for security-related automations

**Response Actions:**
1. Review automation changes made
2. Verify legitimate user action
3. Check if automation affects security devices
4. Test automation for malicious behavior
5. Revert unauthorized changes
6. Review Home Assistant access logs
7. Enable change approval workflow if available

---

#### APP-002: Excessive Media Streaming
**Priority:** LOW
**Severity:** low
**Description:** Detects excessive streaming that may indicate account sharing or abuse

**Detection Logic:**
```yaml
conditions:
  - field: service
    operator: regex
    value: "plex|jellyfin"
  - field: action
    operator: equals
    value: "stream_start"

aggregation:
  field: user
  timeframe: 24h
  threshold: 50
```

**Threshold Rationale:** 50 stream starts in 24 hours exceeds normal single-user behavior. Adjust based on household size.

**False Positive Considerations:**
- Large household with multiple users
- Binge watching behavior
- Music streaming (many short streams)
- Testing/troubleshooting

**Tuning Guidance:**
- Adjust threshold for household size
- Monitor concurrent streams instead
- Track bandwidth usage separately
- Whitelist known power users

**Response Actions:**
1. Review user account and stream patterns
2. Check for concurrent streams from different IPs
3. Verify user hasn't shared credentials
4. Review bandwidth usage
5. Consider stream limits if excessive
6. Educate user on sharing policy
7. Implement concurrent stream limits

---

#### APP-003: Pi-hole Unusual DNS Query Pattern
**Priority:** MEDIUM
**Severity:** medium
**Description:** Detects unusual DNS query patterns that may indicate malware C2 or DNS abuse

**Detection Logic:**
```yaml
conditions:
  - field: service
    operator: equals
    value: "pihole"
  - field: query_type
    operator: equals
    value: "A"

aggregation:
  field: source_ip
  timeframe: 5m
  threshold: 500
```

**Threshold Rationale:** 500 DNS queries in 5 minutes exceeds normal behavior. May indicate malware beaconing or DNS abuse.

**False Positive Considerations:**
- Applications with aggressive DNS caching disabled
- Mobile devices with many background apps
- IoT devices with frequent cloud polling
- DNS-based ad blocking causing retries

**Tuning Guidance:**
- Adjust threshold for your network size
- Whitelist known noisy devices
- Monitor for specific suspicious domains
- Track query failure rates separately

**Response Actions:**
1. Identify source device generating queries
2. Review domains being queried
3. Check for malware C2 patterns
4. Verify device is not compromised
5. Review device for suspicious processes
6. Block suspicious domains at Pi-hole
7. Consider device quarantine if malware suspected

---

#### APP-004: Nextcloud Mass File Access
**Priority:** MEDIUM
**Severity:** medium
**Description:** Detects bulk file access that may indicate automated scanning or data harvesting

**Detection Logic:**
```yaml
conditions:
  - field: service
    operator: equals
    value: "nextcloud"
  - field: action
    operator: equals
    value: "file_access"

aggregation:
  field: user
  timeframe: 10m
  threshold: 200
```

**Threshold Rationale:** 200 file accesses in 10 minutes exceeds normal interactive behavior. Indicates automated access or scanning.

**False Positive Considerations:**
- Sync client synchronization
- Backup operations
- Mass file operations (move, copy)
- Photo gallery browsing

**Tuning Guidance:**
- Increase threshold for users with large libraries
- Whitelist sync client user agents
- Adjust based on typical user patterns
- Monitor specific file types separately

**Response Actions:**
1. Identify user and files accessed
2. Review if legitimate sync or scanning
3. Check for compromised credentials
4. Verify no sensitive files accessed
5. Monitor for download/export operations
6. Consider rate limiting if abuse
7. Review access patterns for anomalies

---

### Category 8: IoT and Smart Home (3 Rules)

#### IOT-001: Unusual Smart Home Automation Trigger
**Priority:** MEDIUM
**Severity:** medium
**Description:** Detects automation triggers during unexpected times or conditions

**Detection Logic:**
```yaml
conditions:
  - field: service
    operator: equals
    value: "homeassistant"
  - field: event
    operator: equals
    value: "automation_triggered"
  - field: timestamp
    operator: regex
    value: "T0[1-5]:"  # 1am-5am

alert:
  title: "Late Night Automation: {automation_name}"
  description: "Automation triggered at unusual hour"
```

**Threshold Rationale:** Single event detection for automations during sleeping hours (1am-5am). Adjust based on household schedule.

**False Positive Considerations:**
- Scheduled overnight automations (cleaning, backups)
- Shift workers with unusual schedules
- Legitimate late-night device usage
- Automated maintenance tasks

**Tuning Guidance:**
- Adjust time range for your schedule
- Whitelist known overnight automations
- Track specific security-related automations
- Severity to LOW if frequently triggered

**Response Actions:**
1. Review automation details and trigger
2. Verify if scheduled or unexpected trigger
3. Check for unauthorized access to HA
4. Review what devices were controlled
5. Verify no physical security implications
6. Investigate if persistent pattern
7. Consider automation approval workflow

---

#### IOT-002: Smart Lock Repeated Failed Access
**Priority:** HIGH
**Severity:** high
**Description:** Detects repeated failed access attempts to smart locks

**Detection Logic:**
```yaml
conditions:
  - field: device_type
    operator: equals
    value: "lock"
  - field: event
    operator: contains
    value: "access_denied"

aggregation:
  field: device_id
  timeframe: 10m
  threshold: 5
```

**Threshold Rationale:** 5 failed lock access attempts in 10 minutes indicates physical breach attempt or technical issue.

**False Positive Considerations:**
- User forgetting/entering wrong code
- Mechanical lock issues
- Battery/connectivity problems
- Children playing with smart lock

**Tuning Guidance:**
- Reduce threshold to 3 for high-security locks
- Adjust timeframe based on lock usage
- Track specific access methods separately (code vs NFC)
- Implement lock-specific alerting

**Response Actions:**
1. **HIGH PRIORITY** - physical security threat
2. Verify if legitimate user or breach attempt
3. Review lock access logs and attempts
4. Check physical lock status
5. Alert household occupants immediately
6. Review security camera footage if available
7. Consider temporary lock disable if under attack
8. Contact authorities if breach confirmed

---

#### IOT-003: Unexpected IoT Device Communication
**Priority:** MEDIUM
**Severity:** medium
**Description:** Detects IoT devices communicating with unexpected external hosts

**Detection Logic:**
```yaml
conditions:
  - field: device_type
    operator: regex
    value: "camera|sensor|switch|lock"
  - field: destination_ip
    operator: not_in_list
    value: "{allowed_iot_destinations}"

alert:
  title: "Unusual IoT Communication from {device_name}"
  description: "Device contacted {destination_ip}"
```

**Threshold Rationale:** Single event detection. IoT devices should only communicate with known, approved services (manufacturer cloud, Home Assistant).

**False Positive Considerations:**
- Firmware updates from new CDN
- Manufacturer cloud service IP changes
- DNS resolution differences
- New device setup/registration

**Tuning Guidance:**
- Maintain accurate allowed destination list
- Whitelist manufacturer cloud services
- Document legitimate external communications
- Monitor for specific suspicious destinations (foreign IPs)

**Response Actions:**
1. Identify device and destination contacted
2. Research destination IP/domain
3. Check if manufacturer-related or suspicious
4. Verify device firmware integrity
5. Consider VLAN isolation for IoT devices
6. Block unauthorized destinations at firewall
7. Factory reset device if compromised

---

## Response Playbooks

### Playbook 1: Authentication Attack Response

**Trigger Events:**
- AUTH-001: SSH Brute Force
- AUTH-002: Successful Login After Failures
- AUTH-003: Distributed Brute Force
- AUTH-007: SSO Authentication Failures

**Immediate Actions (0-15 minutes):**
1. **Triage Alert:**
   - Review source IP(s) and target account(s)
   - Check if any authentication attempts succeeded
   - Verify if source IPs are known/authorized
   - Assess geographic location of attacks

2. **Contain Threat:**
   - Block attacking IP(s) at firewall if persistent
   - Implement rate limiting if not already enabled
   - Enable account lockout if available
   - Consider temporary service restriction

3. **Verify Account Security:**
   - Check for successful logins from attack IPs
   - Review recent account activity
   - Force password reset if compromise suspected
   - Terminate active sessions if suspicious

**Investigation Steps (15-60 minutes):**
1. **Gather Evidence:**
   - Export all authentication logs for timeframe
   - Document attack patterns (IPs, timing, accounts)
   - Check other services for similar attacks
   - Review firewall logs for reconnaissance

2. **Assess Impact:**
   - Determine if any accounts were compromised
   - Check for data access or exfiltration
   - Review system integrity if access gained
   - Identify privilege levels of targeted accounts

3. **Root Cause Analysis:**
   - Identify how attacker discovered service
   - Review password strength policies
   - Check for credential leaks in breach databases
   - Assess account lockout configuration

**Mitigation Steps:**
1. **Short-term:**
   - IP blocking for persistent attackers
   - Rate limiting implementation
   - Account lockout policies
   - MFA enforcement for critical accounts

2. **Long-term:**
   - Implement fail2ban or similar IPS
   - Move SSH to non-standard port
   - VPN requirement for administrative access
   - Password manager usage enforcement
   - Regular password rotation policy

**Recovery Steps:**
1. **If No Compromise:**
   - Document attack for records
   - Tune detection rules if false positive
   - Monitor for escalation
   - Update security metrics

2. **If Compromise Confirmed:**
   - Force password reset for affected accounts
   - Revoke all active sessions
   - Review and revert unauthorized changes
   - Audit all actions taken by compromised account
   - Implement additional authentication controls
   - Consider system restoration if severely compromised

**Prevention Recommendations:**
1. Implement strong password policies (16+ characters, complexity)
2. Enable MFA for all accounts, especially privileged ones
3. Use password manager (Vaultwarden) for unique passwords
4. Implement fail2ban or IP blocking after failed attempts
5. Move SSH to non-standard port (security through obscurity layer)
6. Require VPN for administrative access
7. Implement geo-blocking if users in specific regions
8. Regular security awareness training
9. Monitor breach databases for credential leaks
10. Implement CAPTCHA for web-based authentication

---

### Playbook 2: Reverse Proxy Exploitation Response

**Trigger Events:**
- PROXY-001: SQL Injection Attempt
- PROXY-002: Command Injection Attempt
- PROXY-003: Path Traversal Attempt
- PROXY-008: High Request Rate

**Immediate Actions (0-5 minutes):**
1. **Assess Severity:**
   - Check HTTP response codes (200/5xx = potential success = CRITICAL)
   - Review injection payload specifics
   - Identify targeted application/endpoint
   - Check for multiple attack types from same source

2. **Immediate Containment:**
   - Block attacking IP immediately if exploitation suspected
   - Rate limit endpoint if under heavy attack
   - Consider temporary service shutdown if actively exploited
   - Enable WAF rules if available

3. **Quick Integrity Check:**
   - Verify database/application responding normally
   - Check for unusual error rates
   - Review most recent application logs
   - Test application functionality

**Investigation Steps (5-60 minutes):**
1. **Detailed Analysis:**
   - Review full HTTP request including headers/parameters
   - Check application error logs for injection results
   - Examine database query logs if SQL injection
   - Review command execution logs if command injection
   - Identify all requests from attacking IP

2. **Exploitation Assessment:**
   - Determine if exploitation was successful
   - Check for data exfiltration indicators
   - Review for backdoor/webshell installation
   - Examine file system for unauthorized modifications
   - Check database integrity

3. **Scope Determination:**
   - Identify all affected endpoints/applications
   - Review logs for similar attacks from other IPs
   - Check if attack part of larger campaign
   - Assess if other services vulnerable

**Mitigation Steps:**
1. **Immediate Fixes:**
   - Patch vulnerable application if known CVE
   - Implement input validation/sanitization
   - Enable WAF with appropriate rule sets
   - Restrict HTTP methods to required only
   - Disable unnecessary endpoints

2. **Enhanced Protection:**
   - Deploy ModSecurity or similar WAF
   - Implement rate limiting per endpoint
   - Add request size limits
   - Enable query logging for auditing
   - Configure strict Content Security Policy

**Recovery Steps:**
1. **If Exploitation Confirmed:**
   - Isolate affected systems immediately
   - Restore from clean backup if possible
   - Rebuild system from scratch if necessary
   - Reset all credentials (database, admin, API)
   - Review and remove any backdoors/webshells
   - Audit all recent changes to codebase

2. **Post-Recovery:**
   - Conduct full security audit
   - Implement comprehensive logging
   - Enable integrity monitoring
   - Set up file change detection
   - Schedule regular vulnerability scanning

**Prevention Recommendations:**
1. Keep all applications and frameworks updated
2. Implement Web Application Firewall (ModSecurity, Cloudflare)
3. Use parameterized queries/prepared statements (SQL injection prevention)
4. Implement strict input validation and output encoding
5. Disable directory listing and unnecessary HTTP methods
6. Use security headers (CSP, X-Frame-Options, etc.)
7. Regular penetration testing and vulnerability scanning
8. Implement rate limiting per IP and endpoint
9. Deploy intrusion detection system (Snort, Suricata)
10. Regular security awareness training for developers

---

### Playbook 3: Password Manager Compromise Response

**Trigger Events:**
- PWDMGR-001: Vault Export
- PWDMGR-002: Multiple Device Registrations
- PWDMGR-003: Unusual Vault Access Geolocation
- PWDMGR-004: API Token Abuse
- AUTH-005: Vaultwarden Master Password Failures

**Immediate Actions (0-5 minutes):**
1. **CRITICAL ALERT - Act Immediately:**
   - Contact vault owner by phone/secondary channel
   - Verify if alert represents legitimate activity
   - Block suspicious IPs at firewall immediately
   - Terminate all active Vaultwarden sessions
   - Disable API access temporarily if abuse detected

2. **Prevent Further Access:**
   - Change Vaultwarden admin password
   - Revoke all API tokens
   - Force re-authentication for all clients
   - Consider temporary service shutdown if active theft

3. **Rapid Assessment:**
   - Check if vault export/mass access completed
   - Review exactly what credentials were accessed
   - Verify master password not compromised
   - Identify all sessions from suspicious IPs

**Investigation Steps (5-30 minutes):**
1. **Detailed Impact Assessment:**
   - Review all vault access logs during incident window
   - Identify every credential item accessed
   - Document export operations if any
   - Check for API token theft or creation
   - Review device registration history
   - Examine authentication patterns

2. **Compromise Scope:**
   - Determine if master password compromised
   - Check if vault database file accessed
   - Review for credential exfiltration
   - Assess if attacker created backdoor (new user, API token)
   - Verify backup file security

3. **Attack Vector Identification:**
   - Review how attacker gained access (brute force, credential stuffing, session hijacking)
   - Check for vulnerabilities in Vaultwarden version
   - Examine authentication logs for initial compromise
   - Investigate client device security

**Mitigation Steps:**
1. **If Master Password Compromised:**
   - **IMMEDIATE:** Change master password
   - Force re-authentication of all clients
   - Review and rotate ALL stored credentials (prioritize critical services)
   - Enable MFA if not already enabled
   - Consider migrating to new vault instance

2. **If Vault Data Exported:**
   - **CRITICAL:** Assume ALL credentials compromised
   - Begin emergency password rotation plan
   - Prioritize high-value accounts (banking, email, admin)
   - Enable MFA on all services that support it
   - Monitor all accounts for unauthorized access
   - Consider credit freeze if financial data stored

3. **Enhanced Security:**
   - Require MFA for vault access (mandatory)
   - Implement geo-restrictions if possible
   - Enable device approval workflow
   - Restrict API access or disable if not needed
   - Implement vault timeout policies
   - Enable clipboard clearing
   - Restrict export functionality

**Recovery Steps:**
1. **Credential Rotation Priority Order:**
   - Tier 1 (Immediate - 0-24 hours):
     - Primary email accounts
     - Banking and financial services
     - Crypto wallets/exchanges
     - Domain registrar accounts
     - Cloud infrastructure (AWS, Azure, etc.)
     - Admin accounts for all services

   - Tier 2 (High Priority - 24-48 hours):
     - Secondary email accounts
     - Social media accounts
     - Payment services (PayPal, Venmo)
     - VPN/security services
     - Backup/cloud storage
     - Work-related accounts

   - Tier 3 (Medium Priority - 48-72 hours):
     - Shopping accounts
     - Streaming services
     - Forum/community accounts
     - Less critical personal accounts

   - Tier 4 (Low Priority - 1 week):
     - Rarely used accounts
     - Non-sensitive services
     - Deprecated accounts (consider deletion)

2. **System Hardening:**
   - Rebuild Vaultwarden instance if necessary
   - Update to latest version
   - Review and harden configuration
   - Implement network segmentation
   - Enable comprehensive logging
   - Set up real-time monitoring
   - Configure backup encryption

3. **Long-term Recovery:**
   - Audit all services for unauthorized access
   - Monitor credit reports for identity theft
   - Review financial statements for fraud
   - Update security incident documentation
   - Conduct lessons-learned analysis
   - Update disaster recovery plan

**Prevention Recommendations:**
1. **MANDATORY:** Enable MFA for Vaultwarden (TOTP, U2F, or Duo)
2. Use extremely strong master password (20+ characters, random)
3. Enable vault timeout (15 minutes or less)
4. Disable or restrict vault export functionality
5. Implement IP whitelisting for admin access
6. Require VPN for vault access
7. Enable device approval workflow
8. Regular vault backup with strong encryption
9. Monitor Vaultwarden logs in real-time with SIEM
10. Keep Vaultwarden updated (security patches)
11. Consider hardware security key requirement
12. Implement geographic access restrictions
13. Regular security audits of Vaultwarden instance
14. Emergency credential rotation plan and testing
15. Secondary authentication factor backup (recovery codes)

**Special Note:** Password manager compromise is the highest-severity incident in homelab environments. This single point of failure can lead to complete account takeover across all services. Response must be immediate, comprehensive, and thorough. Consider this a CRITICAL SECURITY INCIDENT requiring full incident response procedures.

---

### Playbook 4: Data Exfiltration Response

**Trigger Events:**
- EXFIL-001: Bulk File Download
- EXFIL-002: Large Data Transfer
- EXFIL-003: DNS Tunneling Detection

**Immediate Actions (0-10 minutes):**
1. **Assess Situation:**
   - Identify what data/files being accessed
   - Review total volume transferred so far
   - Determine if exfiltration still in progress
   - Check if legitimate user or attacker
   - Verify data sensitivity level

2. **Stop Ongoing Exfiltration:**
   - Terminate suspicious sessions immediately
   - Block source IP at firewall if malicious
   - Rate limit endpoint if still accessible
   - Consider temporary service shutdown if critical data

3. **Preserve Evidence:**
   - Capture current system state
   - Export relevant logs before rotation
   - Document timestamps and file lists
   - Screenshot active sessions/connections

**Investigation Steps (10-60 minutes):**
1. **Scope Assessment:**
   - List all files/data accessed
   - Calculate total data volume transferred
   - Identify data classification (personal, financial, credentials)
   - Review access method (API, web interface, sync client)
   - Check for concurrent exfiltration methods

2. **Timeline Reconstruction:**
   - Identify when exfiltration started
   - Review initial compromise vector
   - Document attacker progression
   - Check for related security events
   - Determine if automated or manual

3. **Impact Analysis:**
   - Assess sensitivity of exfiltrated data
   - Determine potential harm from disclosure
   - Check for credential/key exposure
   - Review for personal identifying information (PII)
   - Assess legal/compliance implications

**Mitigation Steps:**
1. **Immediate Remediation:**
   - Change all credentials if potentially exposed
   - Revoke API tokens/access keys
   - Enable MFA on affected services
   - Implement rate limiting on file access
   - Add download volume monitoring

2. **Access Control Review:**
   - Review and tighten file permissions
   - Implement principle of least privilege
   - Add data loss prevention (DLP) controls
   - Enable file access auditing
   - Consider encryption at rest

**Recovery Steps:**
1. **If Credentials Exfiltrated:**
   - Follow password rotation plan (see Playbook 3)
   - Force re-authentication across services
   - Review for unauthorized access
   - Enable enhanced monitoring

2. **If Personal Data Exfiltrated:**
   - Document incident thoroughly
   - Assess notification requirements
   - Consider credit monitoring services
   - Review insurance coverage
   - Update privacy policies

3. **System Hardening:**
   - Implement file access rate limiting
   - Enable comprehensive file audit logging
   - Add data classification labels
   - Deploy DLP solution if available
   - Configure alerting on bulk access patterns

**Prevention Recommendations:**
1. Implement data classification and labeling
2. Enable comprehensive file access auditing
3. Configure rate limits on file downloads
4. Deploy data loss prevention (DLP) tools
5. Encrypt sensitive data at rest
6. Implement network segmentation for sensitive data
7. Monitor for unusual access patterns
8. Regular access rights reviews
9. Principle of least privilege for all accounts
10. Enable download throttling for bulk operations

---

### Playbook 5: Infrastructure Compromise Response

**Trigger Events:**
- INFRA-002: Container Escape Attempt
- ACCESS-001: Sudo to Root
- ACCESS-003: Unusual Process Execution
- INFRA-004: Cryptocurrency Mining

**Immediate Actions (0-10 minutes):**
1. **Critical Assessment:**
   - Determine if system-level access achieved
   - Check if compromise is active (malware running)
   - Identify compromised system/container
   - Assess potential for lateral movement
   - Verify if other systems affected

2. **Immediate Containment:**
   - Isolate compromised system from network if possible
   - Terminate suspicious processes
   - Block attacker IP at firewall
   - Disable compromised user accounts
   - Consider complete system shutdown if actively exploited

3. **Evidence Preservation:**
   - Capture memory dump if possible
   - Export all available logs
   - Document running processes and network connections
   - Take filesystem snapshot/backup
   - Preserve network traffic captures

**Investigation Steps (10-120 minutes):**
1. **Compromise Assessment:**
   - Review initial access vector
   - Identify privilege escalation method
   - Check for rootkit or persistent malware
   - Examine systemd/cron for persistence
   - Review SSH keys and authorized_keys
   - Check for new user accounts
   - Examine sudo configuration

2. **Lateral Movement Check:**
   - Review access to other systems
   - Check for SSH connections from compromised system
   - Examine Docker/container access
   - Review credentials stored on system
   - Check for network scanning activity

3. **Data Access Assessment:**
   - Review files accessed by attacker
   - Check database access logs
   - Examine sensitive file access (config files, keys)
   - Verify backup integrity
   - Assess data exfiltration indicators

**Mitigation Steps:**
1. **If Container Compromise:**
   - Terminate container immediately
   - Review container image for vulnerabilities
   - Check host system integrity
   - Verify container isolation held
   - Rebuild container from clean image

2. **If Host System Compromise:**
   - Consider complete system rebuild
   - Restore from known-good backup
   - Verify backup not compromised
   - Change all credentials
   - Review and remove backdoors

3. **Persistence Removal:**
   - Remove malicious cron jobs
   - Clean systemd services
   - Remove unauthorized SSH keys
   - Delete malicious user accounts
   - Remove suspicious startup scripts
   - Check for modified system binaries

**Recovery Steps:**
1. **System Restoration:**
   - Rebuild from clean OS installation (recommended)
   - OR restore from verified clean backup
   - Verify all patches applied
   - Harden system configuration
   - Implement security controls
   - Restore application data
   - Thoroughly test before production

2. **Credential Rotation:**
   - Change all system passwords
   - Regenerate SSH keys
   - Rotate API keys and tokens
   - Update database credentials
   - Renew TLS certificates
   - Update application secrets

3. **Enhanced Monitoring:**
   - Deploy file integrity monitoring (AIDE, Tripwire)
   - Enable process monitoring
   - Implement network segmentation
   - Add endpoint detection and response (EDR) if possible
   - Configure comprehensive logging
   - Set up real-time alerting

**Prevention Recommendations:**
1. Regular security patching and updates
2. Implement principle of least privilege
3. Disable unnecessary services
4. Use security-hardened configurations
5. Enable SELinux or AppArmor
6. Regular security audits and vulnerability scans
7. File integrity monitoring
8. Strong password policies and key management
9. Network segmentation and firewalling
10. Regular backup testing and verification
11. Container image scanning before deployment
12. Disable root login (SSH and console)
13. Implement defense-in-depth architecture
14. Regular penetration testing
15. Incident response plan testing

---

## Appendix

### A. Threshold Tuning Guidelines

**General Principles:**
1. Start with recommended thresholds and adjust based on your environment
2. Track false positive rates and tune accordingly
3. Consider user base size (5-10 users vs 20+ users)
4. Balance sensitivity with alert fatigue
5. Document all threshold changes with rationale

**Tuning Process:**
1. Deploy rule with recommended threshold
2. Monitor for 1-2 weeks
3. Calculate false positive rate (false positives / total alerts)
4. Adjust threshold to achieve target false positive rate (<10% for HIGH/CRITICAL severity)
5. Re-evaluate after environmental changes

**Service-Specific Adjustments:**

**High-Traffic Services (Media servers, file sharing):**
- Increase thresholds by 50-100%
- Extend timeframes for aggregation
- Consider whitelist-based exclusions

**Critical Services (Password managers, auth systems):**
- Decrease thresholds by 30-50%
- Reduce timeframes for faster detection
- Set lower tolerance for anomalies

**Low-Traffic Services (Admin interfaces):**
- Keep sensitive thresholds
- Consider single-event detection
- Implement strict IP whitelisting

### B. False Positive Mitigation Strategies

**1. IP Whitelisting:**
```yaml
# Add to any rule
exclude_conditions:
  - field: source_ip
    operator: in_list
    value: "{trusted_ips}"
```

**2. User Whitelisting:**
```yaml
# Add to any rule
exclude_conditions:
  - field: user
    operator: in_list
    value: ["admin", "backup_user"]
```

**3. Time-Based Exclusions:**
```yaml
# Exclude during backup windows
exclude_timeframes:
  - "02:00-04:00"  # Nightly backups
```

**4. User-Agent Whitelisting:**
```yaml
# Exclude legitimate automation
exclude_conditions:
  - field: user_agent
    operator: contains
    value: "monitoring-tool"
```

### C. Severity Escalation Matrix

| Base Alert | Escalation Condition | New Severity | Rationale |
|-----------|---------------------|--------------|-----------|
| AUTH-001 (HIGH) | Targets admin/root account | CRITICAL | Admin compromise is critical |
| PROXY-001 (HIGH) | Response code 200/5xx | CRITICAL | Exploitation successful |
| AUTH-003 (HIGH) | >50 source IPs involved | CRITICAL | Large-scale attack |
| EXFIL-001 (HIGH) | >10GB transferred | CRITICAL | Massive data loss |
| ACCESS-001 (HIGH) | Root access achieved | CRITICAL | Complete system control |

### D. Integration with External Tools

**Fail2ban Integration:**
```bash
# Auto-block IPs after SIEMBox alerts
# Create fail2ban filter for SIEMBox alerts
[Definition]
failregex = "rule_matched.*source_ip.*<HOST>"
ignoreregex =
```

**Firewall Automation:**
```bash
# Auto-block via iptables
iptables -A INPUT -s <offending_ip> -j DROP
```

**Notification Integration:**
- Email (SMTP configuration)
- Discord/Slack webhooks
- PagerDuty/Opsgenie for critical alerts
- SMS via Twilio for emergency alerts
- Mobile push notifications

### E. Compliance Mapping

**GDPR Considerations:**
- Data breach notification requirements (72 hours)
- Personal data protection monitoring
- Access logging for audit trails
- Data minimization principles

**ISO 27001 Alignment:**
- A.9: Access Control monitoring
- A.12: Operations Security logging
- A.16: Information Security Incident Management
- A.18: Compliance monitoring

**CIS Controls Mapping:**
- Control 4: Secure Configuration (infrastructure rules)
- Control 6: Access Control Management (authentication rules)
- Control 8: Audit Log Management (all rules)
- Control 13: Network Monitoring (proxy/infrastructure rules)

### F. Homelab-Specific Considerations

**Small User Base Impact:**
- Lower thresholds acceptable (fewer false positives)
- Single-event detection viable for critical assets
- User behavior patterns easier to establish

**Limited Resources:**
- Prioritize high-value detections
- Consolidate similar rules to reduce overhead
- Focus on critical asset protection
- Accept some risk on low-value assets

**Single Admin Operations:**
- Critical alerts require immediate attention
- Medium/Low alerts can be batch-reviewed
- Alert fatigue is major concern
- Consider alert throttling for non-critical events

**Technology Diversity:**
- Parse logs consistently across services
- Use generic field names where possible
- Leverage SIEM correlation capabilities
- Document parser requirements per rule

### G. Testing and Validation

**Rule Testing Process:**
1. Create test log samples that should trigger rule
2. Inject test logs into SIEMBox
3. Verify alert generated with correct severity
4. Check alert content and field substitution
5. Confirm aggregation logic if applicable

**Example Test Logs:**

**SSH Brute Force Test:**
```
Jun 1 10:30:01 server sshd[1234]: Failed password for admin from 192.168.1.100
Jun 1 10:30:05 server sshd[1234]: Failed password for admin from 192.168.1.100
Jun 1 10:30:09 server sshd[1234]: Failed password for admin from 192.168.1.100
Jun 1 10:30:13 server sshd[1234]: Failed password for admin from 192.168.1.100
Jun 1 10:30:17 server sshd[1234]: Failed password for admin from 192.168.1.100
```

**SQL Injection Test:**
```
192.168.1.100 - - [01/Jun/2025:10:30:00] "GET /login?user=admin' OR '1'='1 HTTP/1.1" 200
```

### H. Metrics and KPIs

**Detection Effectiveness:**
- True Positive Rate: (True Positives / Total Attacks) × 100%
- False Positive Rate: (False Positives / Total Alerts) × 100%
- Mean Time to Detect (MTTD): Average time from attack start to alert
- Mean Time to Respond (MTTR): Average time from alert to containment

**Target Metrics for Homelabs:**
- False Positive Rate: <15% (acceptable for single-admin operations)
- Critical Alert False Positive Rate: <5%
- MTTD: <5 minutes for critical events
- MTTR: <30 minutes for critical events, <24 hours for medium

**Rule Performance Tracking:**
```sql
SELECT
  rule_name,
  COUNT(*) as total_alerts,
  SUM(CASE WHEN status = 'false_positive' THEN 1 ELSE 0 END) as false_positives,
  AVG(EXTRACT(EPOCH FROM (updated_at - created_at))) as avg_response_time
FROM alerts
GROUP BY rule_name
ORDER BY false_positives DESC;
```

### I. Continuous Improvement

**Quarterly Review Process:**
1. Analyze false positive rates per rule
2. Review undetected security events (if any)
3. Adjust thresholds based on 90 days of data
4. Add new rules for emerging threats
5. Deprecate rules with high false positive rates
6. Update documentation with lessons learned

**Community Feedback Loop:**
1. Share anonymized detection metrics
2. Contribute refined rules to SIEMBox community
3. Adopt community rule improvements
4. Report bugs and enhancement requests
5. Participate in threat intelligence sharing

### J. Additional Resources

**Threat Intelligence Sources:**
- MITRE ATT&CK Framework (https://attack.mitre.org)
- OWASP Top 10 (https://owasp.org/Top10/)
- CVE Database (https://cve.mitre.org)
- AlienVault OTX (https://otx.alienvault.com)
- SANS Internet Storm Center (https://isc.sans.edu)

**Log Management Best Practices:**
- Centralize all logs to SIEMBox
- Implement log retention policies (90+ days)
- Enable log forwarding from all services
- Use structured logging (JSON format preferred)
- Implement log integrity protection

**Recommended Parsers:**
- SSH Authentication logs
- NGINX/Apache access and error logs
- Vaultwarden application logs
- Home Assistant logs
- Docker container logs
- System logs (auth.log, syslog)
- Application-specific logs per homelab stack

---

## Document Version History

**Version 1.0** - 2025-12-03
- Initial threat model creation
- 30+ detection rule specifications
- 5 comprehensive response playbooks
- Homelab-specific guidance and thresholds

---

## Acknowledgments

This threat model was developed based on:
- 2025 Homelab Survey Data (r/homelab, r/selfhosted communities)
- MITRE ATT&CK Framework tactics and techniques
- OWASP Web Security Testing Guide
- Real-world homelab attack telemetry
- Community-contributed threat intelligence
- SIEMBox detection rule engine capabilities

---

**Document End**

For questions, feedback, or contributions to this threat model, please visit:
- GitHub Issues: https://github.com/cladkins/SIEMBOX/issues
- Discussions: https://github.com/cladkins/SIEMBOX/discussions
