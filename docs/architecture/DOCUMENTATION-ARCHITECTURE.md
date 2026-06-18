# SIEMBox Documentation Architecture

**Version:** 1.0
**Date:** 2025-12-03
**Purpose:** Design comprehensive documentation structure for homelab parser/rule redesign

---

## 1. Executive Summary

This document defines the information architecture, content organization, and documentation standards for SIEMBox's major redesign focusing on homelab applications. The redesign will create 20+ parsers, 30+ detection rules, and 15+ integration guides tailored specifically for self-hosted enthusiasts.

### Key Changes from Current State

**Current Documentation Issues:**
- PARSERS.md lists parsers alphabetically (hard to navigate)
- RULES.md lacks clear organization by threat category
- No integration guides for popular applications
- Missing "quick start" for common homelab stacks
- Limited beginner-friendly guidance

**New Documentation Approach:**
- **Category-based organization** for both parsers and rules
- **Quick Start sections** for popular homelab combinations
- **Integration guides directory** with per-application deep dives
- **Comprehensive style guide** for consistency
- **Beginner-friendly focus** without sacrificing technical accuracy

---

## 2. Information Architecture

### 2.1 PARSERS.md Redesign

#### Current Problems
- Alphabetical listing (Authelia, Caddy, NGINX... no logical grouping)
- No indication of which parsers are "must have"
- Missing context about when to use each parser
- Minimal troubleshooting guidance
- Hard to find parsers for specific use cases

#### New Structure

```markdown
# SIEMBox Parsers

## Quick Start

### Popular Homelab Combinations
This section shows exactly which parsers you need for common setups.

**NGINX Proxy Manager + Authelia Stack** (Most Common)
- Required Parsers: NGINX Proxy Manager, Authelia
- Detection Rules: Brute Force Detection, SQL Injection Attempts
- Time to Setup: 15 minutes

**Traefik + authentik Stack** (Modern Alternative)
- Required Parsers: Traefik, authentik
- Time to Setup: 20 minutes

**Complete Media Server Monitoring**
- Required Parsers: Jellyfin, Plex, Docker Container Logs
- Time to Setup: 10 minutes

**Password Manager Security** (HIGHEST PRIORITY)
- Required Parsers: Vaultwarden
- Critical Rules: Master Password Failures, Vault Export Detection
- Setup Time: 5 minutes

**Table of Contents**
- [Quick Start](#quick-start)
- [Reverse Proxy Parsers](#reverse-proxy-parsers-critical)
- [Authentication Parsers](#authentication-parsers-high-priority)
- [Password Manager Parsers](#password-manager-parsers-highest-security)
- [Data Storage Parsers](#data-storage-parsers)
- [Media & Entertainment Parsers](#media--entertainment-parsers)
- [Smart Home & IoT Parsers](#smart-home--iot-parsers)
- [Infrastructure Parsers](#infrastructure-parsers)
- [Utility Parsers](#utility-parsers)
- [Creating Custom Parsers](#creating-custom-parsers)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing-parsers)

## Reverse Proxy Parsers (CRITICAL - 90% of Homelabbers)

### Why This Matters
Your reverse proxy is the gateway to ALL your services. It's exposed to the internet and is the #1 attack surface. Monitoring it is non-negotiable.

### Parsers in This Category
- NGINX Proxy Manager
- Traefik
- Caddy
- Standard NGINX
- HAProxy

## Authentication Service Parsers (HIGH PRIORITY)

### Why This Matters
Authentication systems protect access to all your services. A compromised auth system means everything else is compromised too.

### Parsers in This Category
- Authelia
- authentik
- Keycloak
- Pocket ID

## Password Manager Parsers (HIGHEST SECURITY - CRITICAL)

### Why This Matters
Your password manager is the single point of failure in your homelab. If compromised, the attacker has credentials to EVERYTHING. This requires the strictest monitoring.

### Parsers in This Category
- Vaultwarden (Bitwarden-compatible)

## Data Storage Parsers (HIGH VALUE)

### Why This Matters
These services store your personal files, photos, and documents. Compromise means data theft and privacy violations.

### Parsers in This Category
- Nextcloud
- Immich
- Paperless-ngx

## Media & Entertainment Parsers (CONVENIENCE)

### Why This Matters
These services provide value but are lower security priority. Compromise typically means unauthorized streaming, not data loss.

### Parsers in This Category
- Jellyfin
- Plex
- Emby

## Smart Home & IoT Parsers (CONVENIENCE + PHYSICAL SECURITY)

### Why This Matters
These services control your physical environment. Compromise could affect physical security or privacy (cameras, locks, microphones).

### Parsers in This Category
- Home Assistant
- Generic IoT device logs

## Infrastructure Parsers (FOUNDATIONAL)

### Why This Matters
These are the foundation of your entire system. Infrastructure compromise is the hardest to recover from.

### Parsers in This Category
- SSH Authentication
- Docker Container Logs
- Fail2ban
- Generic Syslog
- Linux Sudo

## Utility Parsers (SUPPORTING)

### Why This Matters
These provide additional context and health monitoring.

### Parsers in This Category
- Pi-hole DNS
- Generic JSON logs
- CSV-based logs
- Generic Apache/Nginx access logs

---

## [Individual Parser Template - See Section 3.1]

---

## Creating Custom Parsers

[Advanced section for users who need parsers for unlisted applications]

## Troubleshooting

### Parser Not Matching Logs
[Common issues and solutions]

### Incorrect Field Extraction
[Debugging field mapping issues]

## Contributing Parsers

[How to submit parsers to the community]
```

#### Rationale for New Structure

1. **Quick Start First** - New users immediately see what they need
2. **Category-Based Organization** - Groups similar applications together
3. **Priority Indicators** - Makes it clear what's most important to monitor
4. **Context and "Why"** - Explains security relevance to beginners
5. **Progressive Disclosure** - Basic info first, advanced options later

---

### 2.2 RULES.md Redesign

#### Current Problems
- Rules listed without categorization
- Severity levels not clearly visualized
- No indication of which rules are most important
- Missing response guidance for each rule
- No clear connection between rules and required parsers
- Rule dependencies not shown

#### New Structure

```markdown
# SIEMBox Detection Rules

## Quick Reference

### Severity Level Guide

| Severity | Color | Meaning | Response Time | Examples |
|----------|-------|---------|----------------|----------|
| CRITICAL | Red | Immediate action required | <5 minutes | Password manager compromise, Root access gained |
| HIGH | Orange | Serious threat, investigate today | <2 hours | SSH brute force success, SQL injection |
| MEDIUM | Yellow | Suspicious activity, review soon | <24 hours | Failed auth attempts, Directory scanning |
| LOW | Blue | Informational, archive for analysis | As convenient | After-hours access by known user, Service restart |

### Rule Categories Overview

- **Authentication Attacks** (10 rules) - 95% of attacks target this
- **Reverse Proxy Exploitation** (8 rules) - Primary attack surface
- **Password Manager Security** (4 rules) - Highest priority
- **Access Control & Privilege** (4 rules) - Post-compromise detection
- **Data Exfiltration** (3 rules) - Theft in progress
- **Infrastructure Attacks** (4 rules) - System-level threats
- **Application-Specific** (4 rules) - Service-unique threats
- **IoT & Smart Home** (3 rules) - Physical security threats

---

## Table of Contents
- [Quick Reference](#quick-reference)
- [Understanding Rules](#understanding-rules)
- [CRITICAL Severity Rules](#critical-severity-rules)
- [HIGH Severity Rules](#high-severity-rules)
- [MEDIUM Severity Rules](#medium-severity-rules)
- [LOW Severity Rules](#low-severity-rules)
- [Rule Organization](#rule-organization)
- [Tuning Rules](#tuning-rules)
- [Creating Custom Rules](#creating-custom-rules)
- [Response Playbooks](#response-playbooks)
- [Contributing Rules](#contributing-rules)

## Understanding Rules

### How Rules Work
[Simple explanation with diagram]

### Severity Levels
[Clear definition of each level]

### Threshold Tuning
[Guidance for adjusting sensitivity]

---

## CRITICAL Severity Rules

### Why Critical?
These rules detect threats that could result in:
- Complete credential loss (password manager compromise)
- Full system access (root shell, container escape)
- Immediate data theft (bulk exfiltration in progress)

### Critical Rules by Category

#### Password Manager Security (HIGHEST PRIORITY)

**PWDMGR-001: Vaultwarden Master Password Failures**
- Severity: CRITICAL (never compromise)
- Threshold: 3+ failures in 10 minutes (VERY LOW threshold)
- Required Parser: Vaultwarden
- Detection Logic: Failed master password attempts
- Why It Matters: Master password loss = all credentials lost
- Immediate Action: Contact user immediately, block IP, check vault access
- Investigation: Review what was accessed, check for successful breaches

**PWDMGR-002: Vault Export Detected**
- Severity: CRITICAL
- Threshold: Single event detection (any export = alert)
- Required Parser: Vaultwarden
- Why It Matters: Bulk credential theft in progress
- Immediate Action: Block user session, verify legitimate operation

#### Authentication Attacks Leading to Successful Access

**AUTH-002: Successful Login After Failed Attempts**
- Severity: CRITICAL (indicates brute force success)
- Threshold: Successful login after 3+ failures
- Required Parser: SSH Authentication, Authelia, authentik
- Why It Matters: Attack succeeded - attacker has access
- Immediate Action: Force password reset, review all session activity

**AUTH-008: Root SSH Login Successful**
- Severity: CRITICAL
- Threshold: Single event (should NEVER happen)
- Required Parser: SSH Authentication
- Why It Matters: Direct root access violates security best practice
- Immediate Action: Investigate immediately, verify not compromise

#### System-Level Compromise

**ACCESS-001: Sudo to Root by Unauthorized User**
- Severity: CRITICAL
- Threshold: Non-admin user sudo to root (with admin whitelist)
- Required Parser: Linux Sudo
- Why It Matters: Unauthorized privilege escalation
- Immediate Action: Investigate immediately

**INFRA-002: Container Escape Attempt**
- Severity: CRITICAL
- Threshold: Single event
- Required Parser: Docker logs or system logs
- Why It Matters: Container isolation broken = host system at risk
- Immediate Action: Isolate and rebuild container

---

## HIGH Severity Rules

### Why High?
These rules detect active attacks that could lead to compromise if not addressed quickly.

[Similar detailed breakdown for HIGH severity rules...]

---

## MEDIUM Severity Rules

### Why Medium?
These rules detect suspicious patterns that warrant investigation but are not immediate emergencies.

[Similar detailed breakdown for MEDIUM severity rules...]

---

## LOW Severity Rules

### Why Low?
These are informational alerts for trend analysis and security awareness.

[Similar detailed breakdown for LOW severity rules...]

---

## Rule Organization

### By Threat Category

#### Authentication Attacks (10 Rules)
- SSH Brute Force Detection
- Successful Login After Failures
- Distributed Brute Force Attack
- Account Enumeration Attempt
- Vaultwarden Master Password Failures
- After-Hours Authentication
- SSO Authentication Failures
- Root SSH Login Attempt
- API Authentication Failures
- Cross-Service Authentication Failures

#### Reverse Proxy Exploitation (8 Rules)
[List...]

#### Password Manager Security (4 Rules)
[List...]

[Continue for all categories...]

---

## Tuning Rules

### Understanding False Positives
[Guidance on tuning threshold]

### Adjusting for Your Environment
[Service-specific tuning recommendations]

---

## Creating Custom Rules

### Example: Detect Custom Application Attack
[Step-by-step guide with example]

---

## Response Playbooks

### Playbook 1: Authentication Attack Response
[See HOMELAB-THREAT-MODEL.md for detailed playbooks]

### Playbook 2: Password Manager Compromise
[See HOMELAB-THREAT-MODEL.md for detailed playbooks]

[Continue...]

---

## Contributing Rules

[How to submit custom rules to community]
```

#### Rationale for New Structure

1. **Severity-Based Organization** - Most important alerts first
2. **Quick Reference Table** - Understand severity at a glance
3. **Context and "Why"** - Security relevance for each rule
4. **Parser Dependencies** - Clear what parsers are needed
5. **Action-Oriented** - Specific guidance on what to do
6. **Threat Categories** - Secondary organization by attack type

---

### 2.3 INTEGRATION-GUIDES Directory Structure

#### Directory Organization

```
integration-guides/
├── README.md (Index and navigation)
├── _templates/ (Reusable templates)
│   ├── integration-guide-template.md
│   ├── quick-deploy-docker-compose.yml
│   └── verification-checklist.md
├── reverse-proxies/
│   ├── README.md (Category overview)
│   ├── nginx-proxy-manager.md
│   ├── traefik.md
│   ├── caddy.md
│   └── standard-nginx.md
├── authentication/
│   ├── README.md
│   ├── authelia.md
│   ├── authentik.md
│   └── keycloak.md
├── critical-services/
│   ├── README.md
│   └── vaultwarden.md
├── data-storage/
│   ├── README.md
│   ├── nextcloud.md
│   ├── immich.md
│   └── paperless-ngx.md
├── smart-home/
│   ├── README.md
│   └── home-assistant.md
├── media-servers/
│   ├── README.md
│   ├── jellyfin.md
│   ├── plex.md
│   └── emby.md
├── infrastructure/
│   ├── README.md
│   ├── docker-logs.md
│   ├── ssh-access.md
│   └── fail2ban.md
└── advanced/
    ├── README.md
    ├── custom-parser-development.md
    ├── advanced-rule-creation.md
    └── performance-tuning.md
```

#### Directory Navigation

**Root README** (`integration-guides/README.md`)
- Welcome and overview
- Category descriptions
- Quick links to most popular guides
- How to use this section
- Contributing guidelines

**Category READMEs** (e.g., `reverse-proxies/README.md`)
- Overview of category importance
- List of guides in category
- Why monitor this category
- Common security patterns

**Individual Integration Guides**
- Follow template (section 3.3)
- 10-15 minutes to set up
- Includes Docker Compose snippet
- Troubleshooting section
- Related documentation links

---

### 2.4 Supporting Documentation

#### New Documents to Create

**HOMELAB-QUICK-START.md**
- For first-time users
- "What do I monitor first?"
- Priority order: NGINX Proxy Manager → Vaultwarden → then rest
- 5-minute minimum setup
- Links to each integration guide

**PARSER-QUICK-START.md**
- Explains what parsers do
- How to import parsers
- Testing that parsers work
- Troubleshooting common issues

**RULES-QUICK-START.md**
- Explains what rules do
- How to import rules
- Understanding alert severity
- Initial rule tuning

**STACKS.md** (Popular Homelab Setups)
- Pre-configured parser + rule bundles
- Example 1: NGINX Proxy Manager + Authelia
- Example 2: Traefik + authentik
- Example 3: Media server stack
- One-click import where possible

---

## 3. Content Templates

### 3.1 Parser Documentation Template

Each parser entry should follow this structure for consistency:

```markdown
## [Application Name] Parser

### Overview
Brief description of what this application does and why monitoring it matters.

**Security Relevance:** Why you should care about monitoring this application
- Example: "NGINX Proxy Manager is your primary attack surface"
- Example: "Vaultwarden stores all your credentials - highest priority"

### Quick Facts
| Property | Value |
|----------|-------|
| **Severity** | Critical / High / Medium / Low |
| **Frequency** | Very High / High / Medium / Low |
| **Required for** | [List popular stacks that need this] |
| **Difficulty** | Beginner / Intermediate / Advanced |

### What Gets Monitored
- Log entry 1: What does this detect?
- Log entry 2: What does this detect?
- Log entry 3: What does this detect?

### Setup Instructions

#### Step 1: Configure Application Logging
Application-specific instructions for enabling logs.

**For Docker:**
```yaml
services:
  app:
    environment:
      - LOG_LEVEL=INFO
    volumes:
      - /path/to/logs:/app/logs
```

#### Step 2: Import Parser
Via UI:
1. Navigate to Parsers
2. Click Import
3. Search for "[Application]"
4. Click Import

OR via API:
```bash
curl -X POST http://localhost:8421/api/parsers \
  -H "Authorization: Bearer TOKEN" \
  -d @parser.json
```

#### Step 3: Test Parser
Test with sample log:
```
[Paste actual log line here]
```

Expected parsed fields:
```json
{
  "field1": "value1",
  "field2": "value2"
}
```

Test in UI:
1. Navigate to Parsers
2. Click on [Application] parser
3. Paste sample log
4. Click "Test Parse"
5. Verify fields extracted correctly

### Log Format & Examples

**Example Log 1: [Situation]**
```
[Raw log line]
```

Parsed as:
```json
{
  "field": "value"
}
```

**Example Log 2: [Situation]**
```
[Raw log line]
```

### Fields Extracted

| Field Name | Description | Example |
|-----------|-------------|---------|
| `field1` | Description | value |
| `field2` | Description | value |

### Related Detection Rules

These rules work with this parser:
- [Rule Name] - What it detects
- [Rule Name] - What it detects

### Troubleshooting

#### Logs not appearing
**Problem:** Parser is configured but no logs are appearing in SIEMBox

**Solutions:**
1. Verify application is generating logs
2. Check log shipper can access log file
3. Verify log shipper has correct file path
4. Ensure parser is enabled in SIEMBox

#### Parser not matching
**Problem:** Logs appear but parser isn't extracting fields

**Solutions:**
1. Check log format matches expected format
2. Verify application version (log format may have changed)
3. Test parser with exact log line (case-sensitive)
4. Check field mappings are correct

#### Fields missing or incorrect
**Problem:** Some fields not extracted or values are wrong

**Solutions:**
1. Verify regex pattern is correct
2. Test with multiple log samples
3. Check field mapping names
4. See "Test Parser" section above

### Advanced Configuration

#### For Multiple Instances
If monitoring multiple instances of this application:
1. Configure each with unique tag/facility
2. This allows per-instance rule tuning
3. Example: nginx-prod vs nginx-staging

#### For Non-Standard Paths
If application logs to non-standard location:
1. Configure log shipper with custom path
2. Ensure path is within mounted volumes
3. Update parser test with actual log samples

### Tips & Best Practices

- Tip 1: Best practice recommendation
- Tip 2: Common gotcha to avoid
- Tip 3: Pro tip for advanced users

### Security Notes

- Security consideration 1
- Security consideration 2
- Known issues or limitations

### Related Documentation
- [Link to relevant PARSERS.md section]
- [Link to relevant RULES.md section]
- [Link to relevant integration guide]
- [Link to official application docs]

### Example Alert Workflows

**Scenario 1: [Type of Alert]**
- Alert generated: [Example alert]
- Investigation steps: [What to check]
- Response: [What to do]

---
```

### 3.2 Rule Documentation Template

Each rule should follow this structure:

```markdown
## [Rule Name]

### Quick Facts
| Property | Value |
|----------|-------|
| **Rule ID** | [Category-###] |
| **Severity** | CRITICAL / HIGH / MEDIUM / LOW |
| **Threshold** | [Aggregation threshold] |
| **Timeframe** | [Time window] |
| **Priority** | Why is this important? |

### What It Detects

**Overview:**
Clear 1-2 sentence description of what security threat this rule detects.

**Attack Scenario:**
Example of how an attacker might trigger this rule.

**Legitimate Trigger:**
Example of how a legitimate user might trigger this (for false positive considerations).

### Technical Details

**Required Parsers:**
- Parser 1: Why needed
- Parser 2: Why needed

**Detection Logic:**
```yaml
conditions:
  - field: field_name
    operator: equals
    value: "value"

aggregation:
  field: source_ip
  timeframe: 5m
  threshold: 5
```

**Threshold Rationale:**
Explanation of why this specific threshold was chosen. Example:
"5 failed attempts in 5 minutes is high enough to catch automated brute force but low enough to avoid false positives from legitimate user typos."

### Severity Justification

**Why CRITICAL/HIGH/MEDIUM/LOW?**
- How bad is successful exploitation?
- How likely is this attack?
- How fast does it escalate?
- Can it be recovered from?

### Alert Response

#### Immediate Actions (0-5 minutes)
1. Quick assessment: What happened?
2. Containment: Stop ongoing attack
3. Preservation: Capture evidence

#### Investigation (5-60 minutes)
1. Detailed analysis: Review logs
2. Scope determination: How many systems affected?
3. Impact assessment: What was accessed?

#### Response (60+ minutes)
1. Remediation: Fix the problem
2. Recovery: Restore affected systems
3. Prevention: Stop it happening again

### False Positive Considerations

**Common False Positives:**
- Scenario 1: User activity that looks like attack
- Scenario 2: Misconfigured tool that triggers alert
- Scenario 3: Normal behavior that exceeds threshold

**Mitigation:**
- Whitelist trusted IPs
- Adjust threshold
- Add exclusion conditions
- Document exceptions

### Tuning Guidance

**If Too Many Alerts (False Positive Rate >20%):**
- Increase threshold by 30-50%
- Extend timeframe
- Add whitelist for known IPs
- Add exclusion conditions

**If Detecting Real Attacks:**
- Keep current settings
- Consider lowering threshold
- Reduce timeframe for faster detection

**Environment-Specific Adjustments:**
- Single user homelab: Lower thresholds
- Multi-user homelab: Higher thresholds
- 24/7 monitoring: Aggressive detection
- Casual monitoring: Higher thresholds

### Testing This Rule

**Test Scenario 1: Should Trigger**
1. Perform action that should trigger rule
2. Wait for aggregation timeframe
3. Verify alert appears in SIEMBox
4. Check alert has correct severity and message

**Test Scenario 2: Should Not Trigger**
1. Perform similar but benign action
2. Verify no alert (or LOW severity if unavoidable)

**Example Test:**
```
Log to generate: [Actual log line]
Expected alert after: 5 minutes
Expected alert severity: HIGH
```

### Response Playbook

[Link to detailed response playbook in HOMELAB-THREAT-MODEL.md]

### Related Rules

**Rules that often trigger together:**
- Rule A: Because X and Y are related attacks
- Rule B: Because attacker often uses both techniques

### Example Alerts

**Alert Example 1:**
```
Title: SSH Brute Force Detected from 192.168.1.100
Severity: HIGH
Description: 6 failed SSH login attempts detected in 5 minutes
```

**Alert Example 2:**
```
Title: SSH Brute Force Detected from 10.0.0.0/8
Severity: CRITICAL
Description: 50 failed attempts from 8 different IPs in 5 minutes
```

### Advanced Configuration

#### For Specific User Accounts
Only alert for admin accounts:
```yaml
conditions:
  - field: user
    operator: in_list
    value: ["admin", "root"]
```

#### For Specific Applications
Only alert for password manager:
```yaml
conditions:
  - field: service
    operator: equals
    value: "vaultwarden"
```

#### Time-Based Exclusions
Don't alert during backup windows:
```yaml
exclude_timeframes:
  - "02:00-04:00"
```

### Tips & Best Practices

- Best practice 1
- Best practice 2
- Common mistake to avoid

### Related Documentation
- [Link to related parser]
- [Link to related rule]
- [Link to response playbook]
- [Link to threat category in HOMELAB-THREAT-MODEL.md]

---
```

### 3.3 Integration Guide Template

Each application guide should follow this structure:

```markdown
# [Application Name] Integration Guide

## Overview

### What This Guide Covers
Monitoring [Application] in your SIEMBox setup.

### Security Relevance

**Why Monitor This?**
[Why this application is worth monitoring - security benefits]

Example: "Vaultwarden stores all your credentials. Monitoring it is critical because..."

**Typical Attacks:**
- Attack vector 1
- Attack vector 2
- Attack vector 3

**Data at Risk:**
What data could be compromised if this application is breached?

### Prerequisites

**Required:**
- SIEMBox running and accessible
- Log Shipper deployed on system running [Application]
- [Application] installed and running
- [Application] version: X.X or later

**Optional:**
- MFA enabled on [Application] (recommended)
- Backup of [Application] data
- Admin access to [Application]

### Architecture

```
[Application] running on: 192.168.1.100:8080
       ↓
Log file: /var/log/[app]/app.log
       ↓
Log Shipper reads file
       ↓
Sends to SIEMBox:514 (syslog)
       ↓
SIEMBox Syslog Server
       ↓
Parser extracts fields
       ↓
Rules trigger on suspicious patterns
       ↓
Alerts in SIEMBox dashboard
```

---

## Setup Instructions

### Step 1: Configure [Application] Logging

**Default Log Location:**
```
/var/log/[app]/app.log
```

**Enable Debug Logging (Optional):**
```
[Application-specific configuration]
```

**Verify Logs Are Generating:**
```bash
tail -f /var/log/[app]/app.log
```

You should see entries like:
```
[Sample log line]
```

### Step 2: Deploy Log Shipper Configuration

**Option A: Managed Mode (Recommended)**

1. In SIEMBox UI, go to **Log Shippers**
2. Click **Add Shipper**
3. Name it "App Server" or similar
4. Copy the API key
5. Create docker-compose.yml on the [Application] server:

```yaml
services:
  siembox-log-shipper:
    image: siembox-log-shipper:managed
    container_name: siembox-log-shipper
    restart: unless-stopped
    network_mode: host
    environment:
      - SHIPPER_API_KEY=paste-your-api-key-here
      - SIEMBOX_API_URL=http://192.168.1.100:8421/api
    volumes:
      - /var/log/[app]:/var/log/[app]:ro
      # Add other log paths as needed
```

6. Deploy:
```bash
docker compose up -d
```

7. In SIEMBox UI, click **View** on your shipper
8. Click **Add Source**
9. Configure:
   - Type: file
   - File Path: /var/log/[app]/app.log
   - Tag: [app-descriptive-name]
   - Facility: local0
   - Enabled: ✓

10. **The shipper will pick up the config within 30 seconds and start forwarding logs!**

**Option B: Standalone Mode**

Create .env file on [Application] server:
```bash
SIEM_HOST=192.168.1.100
SIEM_PORT=514

SOURCE_1_TYPE=file
SOURCE_1_FILE_PATH=/var/log/[app]/app.log
SOURCE_1_TAG=[app-tag]
SOURCE_1_FACILITY=local0
SOURCE_1_ENABLED=true
```

### Step 3: Verify Logs Are Being Received

**In SIEMBox UI:**
1. Navigate to **Logs**
2. Search for tag: `[app-tag]`
3. You should see logs appearing in real-time
4. Check timestamp is recent (within last 1 minute)

**Via Database:**
```bash
docker exec siembox-postgres psql -U siembox -d siembox -c \
  "SELECT COUNT(*) FROM raw_logs WHERE tags LIKE '%[app-tag]%';"
```

Expected: Count > 0 and increasing

### Step 4: Import Parser

**Via UI:**
1. Navigate to **Parsers**
2. Click **Import Community Parser**
3. Search for "[Application Name]"
4. Click **Import**

**Via API:**
```bash
curl -X POST http://localhost:8421/api/parsers \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d @parser.json
```

### Step 5: Test Parser

**Test With Sample Log:**

In the Parsers page, find "[Application] Parser" and click it:

1. Paste sample log in **Test Log** field:
```
[Sample log from your actual logs]
```

2. Click **Test Parse**

3. Verify extracted fields appear correctly

Expected output:
```json
{
  "field1": "value1",
  "field2": "value2"
}
```

### Step 6: Import Detection Rules

**Via UI:**
1. Navigate to **Detection Rules**
2. Click **Import Community Rules**
3. Search for "[Application Name]"
4. Select rules to import:
   - [Rule 1] - Recommended for beginners
   - [Rule 2] - For advanced users
   - [Rule 3] - Optional
5. Click **Import**

**Recommended Rules for [Application]:**
- Rule 1: Why this rule matters
- Rule 2: Why this rule matters

### Step 7: Trigger a Test Alert

**Purpose:** Verify that rules are working

**Option 1: Simulate Brute Force [If Applicable]**
```bash
# Try logging in with wrong password 5+ times
for i in {1..6}; do
  curl -X POST http://localhost:8080/login \
    -d "username=admin&password=wrong"
done
```

Check SIEMBox for alert within 30 seconds.

**Option 2: Check for Existing Alerts**
If you have recent login failures, they should already trigger alerts.

---

## Verification Checklist

After setup, verify everything works:

- [ ] Log Shipper shows "online" status in SIEMBox UI
- [ ] Logs appearing in SIEMBox Logs page
- [ ] Parser successfully extracting fields
- [ ] At least one detection rule is enabled
- [ ] Test alert successfully triggered
- [ ] Alert appears in Alerts dashboard
- [ ] Alert has correct severity level
- [ ] Alert message is clear and actionable

---

## Troubleshooting

### Shipper Shows "Offline"

**Problem:** Log shipper shows offline in SIEMBox UI

**Causes & Solutions:**

1. **Incorrect API key**
   ```bash
   docker logs siembox-log-shipper | grep -i "unauthorized"
   ```
   Solution: Verify API key in docker-compose.yml

2. **Network connectivity issue**
   ```bash
   docker exec siembox-log-shipper ping 192.168.1.100
   ```
   Solution: Ensure network connectivity

3. **SIEMBox not accessible**
   ```bash
   docker exec siembox-log-shipper curl -v http://192.168.1.100:8421/api/health
   ```
   Solution: Check SIEMBox is running and accessible

4. **Shipper container crashed**
   ```bash
   docker logs siembox-log-shipper
   ```
   Solution: Check logs for errors

### Logs Not Appearing

**Problem:** Shipper is online but logs aren't appearing in SIEMBox

**Checklist:**
1. Verify logs exist on disk
   ```bash
   ls -la /var/log/[app]/app.log
   ```

2. Verify log file is readable by shipper
   ```bash
   docker exec siembox-log-shipper ls -la /var/log/[app]/
   ```

3. Check for volume mount warnings
   ```bash
   docker logs siembox-log-shipper | grep "File not found"
   ```

4. Verify source is enabled in SIEMBox UI

5. Check syslog is receiving logs
   ```bash
   docker logs siembox-backend | grep "syslog received"
   ```

**Solution Steps:**
1. Verify file path in source config
2. Ensure volume mount includes log directory
3. Verify read permissions (chmod 644)
4. Restart shipper: `docker restart siembox-log-shipper`

### Parser Not Matching

**Problem:** Logs appear in SIEMBox but fields not extracted

**Debug Steps:**
1. Get actual log line:
   ```bash
   tail -1 /var/log/[app]/app.log
   ```

2. Test parser with exact line in SIEMBox UI
3. Check if log format matches expected format
4. Verify application version matches parser version

**Common Issues:**
- Application upgraded and log format changed
- Non-standard logging configuration
- Parser needs to be updated

**Solution:**
- Verify sample logs match parser test logs
- Check application version compatibility
- Report parser issue if incompatible

### False Positive Alerts

**Problem:** Getting too many alerts that aren't real threats

**Solution:**

1. **Understand the rule**
   - Read rule documentation
   - Review alert examples
   - Check threshold rationale

2. **Adjust threshold**
   - Increase threshold in rule
   - Extend timeframe
   - Add whitelist for known IPs

3. **Example: Too many "Login Attempts" alerts**
   - Increase threshold from 5 to 8 attempts
   - Extend timeframe from 5m to 10m
   - Whitelist admin IPs

**Process:**
1. Identify problematic rule
2. Click on rule to edit
3. Adjust threshold/timeframe
4. Save changes
5. Monitor for reduction in false positives

### Missing Fields in Parsed Logs

**Problem:** Some fields not being extracted by parser

**Investigation:**
1. Check actual log format
2. Compare to parser test logs
3. Verify field mappings are correct
4. Check for log variations

**Solution:**
1. Review parser documentation
2. Update parser to handle log variations
3. Test with multiple log samples

---

## Security Configuration

### Recommended Security Settings

#### 1. Enable MFA (If Available)
[Application-specific MFA setup]

#### 2. Strong Passwords
[Password policy recommendations]

#### 3. API Key Rotation
[How often to rotate keys and how]

#### 4. Access Control
[Limit who can access this application]

#### 5. Backup Strategy
[How to backup [Application] data]

---

## Advanced Configuration

### Monitoring Multiple Instances

If you run multiple instances of [Application]:

1. Configure each with unique tag
2. Deploy separate log shipper (or configure multiple sources)
3. Create instance-specific rules or alerts

Example:
```bash
SOURCE_1_TAG=app-prod
SOURCE_2_TAG=app-staging
SOURCE_3_TAG=app-test
```

### Custom Log Paths

If [Application] logs to non-standard location:

1. Update docker-compose volumes
2. Configure source with correct path
3. Verify permissions

### Performance Tuning

If experiencing performance issues:

1. Reduce log retention period
2. Disable non-critical rules
3. Adjust log shipping batch size

---

## Common Workflows

### Workflow 1: Investigate Failed Login

**Alert Received:** "[Application] Failed Login Attempt from 192.168.1.50"

**Response:**
1. Check if legitimate user
2. Review login attempt details
3. Monitor for repeated attempts
4. Block IP if malicious

### Workflow 2: Investigate Data Access Spike

**Alert Received:** "[Application] Bulk File Access Detected"

**Response:**
1. Identify user performing access
2. Verify legitimate operation
3. Check for data exfiltration indicators
4. Monitor account for compromise

---

## Related Documentation

### SIEMBox Documentation
- [PARSERS.md](/PARSERS.md) - [Application Name] parser
- [RULES.md](/RULES.md) - [Application Name] rules
- [HOMELAB-THREAT-MODEL.md](/HOMELAB-THREAT-MODEL.md) - Threat analysis

### Official Documentation
- [Official [Application] Docs](https://docs.example.com)
- [Official Security Best Practices](https://example.com/security)
- [Community Resources](https://community.example.com)

### Related Integration Guides
- [Related App 1 Guide](./related-app-1.md)
- [Related App 2 Guide](./related-app-2.md)

---

## Example Response Scenarios

### Scenario: Password Brute Force

**Alert:** "Failed login attempts from 203.0.113.50"

**Steps:**
1. Review login attempts
2. Check if any succeeded
3. Block IP in firewall
4. Monitor account for compromise

### Scenario: Unauthorized Access

**Alert:** "[Application] Access from Unexpected IP"

**Steps:**
1. Contact user to verify
2. Review what was accessed
3. Check for data exfiltration
4. Force password reset if suspicious

---

## Tips & Troubleshooting

**Pro Tip 1:** [Useful advice]
**Pro Tip 2:** [Useful advice]
**Common Gotcha:** [Common mistake to avoid]

---

## Support & Contributing

- Found an issue with this guide? [Report it](https://github.com/cladkins/SIEMBOX/issues)
- Have improvements? [Submit a PR](https://github.com/cladkins/SIEMBOX/pulls)
- Questions? [Start a discussion](https://github.com/cladkins/SIEMBOX/discussions)

---

## Document Version

**Version:** 1.0
**Last Updated:** [Date]
**Compatible with:** [Application] X.X+, SIEMBox 1.0+

---
```

---

## 4. Style Guide

### 4.1 Writing Style Guidelines

#### Tone & Voice

**Target Audience:** Homelabbers (technical enthusiasts, not necessarily security experts)

**Characteristics:**
- **Encouraging and supportive** - Assume capabilities but acknowledge learning curve
- **Clear and concise** - Short sentences, active voice
- **Jargon explained** - Define technical terms on first use
- **Practical focus** - Real-world examples, actionable steps
- **Security-conscious** - Emphasize "why" behind recommendations

#### Language Principles

1. **Avoid Unnecessary Jargon**
   - Good: "Verify logs are being received"
   - Bad: "Ensure telemetry ingestion pipeline validation"

2. **Use Active Voice**
   - Good: "The parser extracts fields from logs"
   - Bad: "Fields are extracted from logs by the parser"

3. **Be Specific**
   - Good: "Run `docker logs siembox-backend` to view backend logs"
   - Bad: "Check the logs to see what's happening"

4. **Explain the "Why"**
   - Good: "Port 514 is the standard syslog port, making it easy for log shippers to find"
   - Bad: "Use port 514"

5. **Provide Examples**
   - Always include working examples
   - Show expected output
   - Include failure cases when relevant

#### Writing Pattern for Instructions

```markdown
## [Action Title]

[1-2 sentence explanation of what this does and why]

**Steps:**
1. [Specific action with screenshot/command if complex]
   ```bash
   # Code example if needed
   ```

2. [Next action]

3. [Verify step - how do you know it worked?]

**Success Indicator:**
You'll see [specific outcome that proves success]

**If [common issue]:**
[Solution]
```

### 4.2 Formatting Standards

#### Headings Hierarchy
```markdown
# Page Title (h1 - one per document)

## Main Section (h2)

### Subsection (h3)

#### Detailed Subsection (h4)

##### Specific Item (h5) - use sparingly
```

#### Code Blocks

**Bash/Shell Commands:**
```bash
# Add comments to explain complex commands
docker exec siembox-postgres psql -U siembox -d siembox -c "SELECT * FROM logs;"
```

**Configuration Files:**
```yaml
# Clear comments for each section
services:
  app:
    environment:
      - LOG_LEVEL=INFO  # Controls verbosity
```

**JSON Examples:**
```json
{
  "field": "value",
  "nested": {
    "field": "value"
  }
}
```

#### Tables

**For Comparisons:**
```markdown
| Feature | Parser A | Parser B |
|---------|----------|----------|
| Regex Support | ✓ | ✓ |
| Grok Support | ✓ | ✗ |
```

**For Reference Data:**
```markdown
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | String | Yes | Parser name |
| type | Enum | Yes | Parser type |
```

#### Lists

**Unordered (when order doesn't matter):**
- Item 1
- Item 2
- Item 3

**Ordered (when sequence matters):**
1. First step
2. Second step
3. Third step

**Nested with explanation:**
1. **First Category**
   - Detail A
   - Detail B

2. **Second Category**
   - Detail C

#### Admonitions (Callouts)

**For Important Information:**
```markdown
### Important: [Title]
[Content that users must know]
```

**For Warnings:**
```markdown
### Warning: [Title]
[Something that could go wrong]
```

**For Tips:**
```markdown
### Tip: [Title]
[Helpful advice for advanced users]
```

**For Examples:**
```markdown
### Example: [Scenario]
[Example of the concept in action]
```

#### Links

**Internal Documentation:**
```markdown
[Link text](./FILENAME.md)  # Same directory
[Link text](/FILENAME.md)   # Root directory
[Link to section](#section-anchor)
```

**External Links:**
```markdown
[Official Documentation](https://docs.example.com)
[GitHub Issue](https://github.com/cladkins/SIEMBOX/issues/123)
```

### 4.3 Technical Standards

#### Command Examples

**Always include:**
- Expected output or success indicator
- Common errors and solutions
- Assumptions about environment

**Example:**
```bash
# Navigate to SIEMBox directory
cd /path/to/siembox

# Start the services
docker compose up -d

# Expected output:
# Creating siembox-postgres ... done
# Creating siembox-backend ... done
# Creating siembox-frontend ... done
```

#### Configuration Snippets

**Always include:**
- Full context (what file, where it goes)
- Comments explaining key settings
- Required vs optional parameters
- Complete examples

**Example:**
```yaml
# File: docker-compose.yml
services:
  app:
    image: myapp:latest
    environment:
      # Required - your SIEMBox API key from the UI
      - SHIPPER_API_KEY=your-key-here
      # Optional - defaults to localhost:8421
      - SIEMBOX_API_URL=http://192.168.1.100:8421/api
    volumes:
      # Read-only access to log directory
      - /var/log/app:/var/log/app:ro
```

#### Log Samples

**Always include:**
- Multiple examples showing variations
- Field extraction explanation
- How to identify this log type
- What triggers generate this log

**Example:**
```
Log Line:
Jun 1 10:30:45 server sshd[12345]: Failed password for user from 192.168.1.100 port 54321

Parsed Fields:
- timestamp: Jun 1 10:30:45
- hostname: server
- event: Failed password
- user: user
- source_ip: 192.168.1.100
- source_port: 54321
```

### 4.4 Consistency Standards

#### Terminology
- Use consistent terms across all docs
- Example: Don't mix "log shipper" and "log forwarder"
- Create glossary for project-specific terms
- Bold technical terms on first use

#### Capitalization
- SIEMBox (always with capital S, I, E, M, B)
- Docker, Kubernetes, PostgreSQL (proper product names)
- Lowercase for generic terms: docker container, log parser

#### Cross-References
- Every doc should reference related docs
- Use "See also:" sections consistently
- Link to troubleshooting from setup guides
- Link from quick start to detailed guides

---

## 5. Navigation Strategy

### 5.1 Cross-Referencing System

#### From Parsers
Each parser should reference:
- Related detection rules
- Integration guide (if exists)
- Troubleshooting tips
- Similar parsers

#### From Rules
Each rule should reference:
- Required parsers
- Response playbook
- Related threat category
- Similar rules

#### From Integration Guides
Each guide should reference:
- Required parsers
- Relevant detection rules
- Troubleshooting documentation
- Official application docs

#### From Quick Start
Should link to:
- Detailed setup guides
- Integration guides
- Parsers documentation
- Rules documentation

### 5.2 Table of Contents Strategy

**PARSERS.md TOC:**
```markdown
- [Quick Start](#quick-start)
  - [Popular Combinations](#popular-homelab-combinations)
- [By Security Priority](#by-security-priority)
  - [Critical Parsers](#password-manager-parsers-highest-security)
  - [High Priority Parsers](#reverse-proxy-parsers-critical)
  - [Medium Priority](#authentication-service-parsers)
- [By Category](#reverse-proxy-parsers-critical)
  - [Reverse Proxies](#reverse-proxy-parsers-critical)
  - [Authentication](#authentication-service-parsers)
  - [Storage](#data-storage-parsers)
  - [Media](#media--entertainment-parsers)
- [Reference](#creating-custom-parsers)
  - [Custom Parsers](#creating-custom-parsers)
  - [Troubleshooting](#troubleshooting)
```

**RULES.md TOC:**
```markdown
- [Quick Reference](#quick-reference)
  - [Severity Guide](#severity-level-guide)
  - [Category Overview](#rule-categories-overview)
- [By Severity](#critical-severity-rules)
  - [Critical Rules](#critical-severity-rules)
  - [High Rules](#high-severity-rules)
  - [Medium Rules](#medium-severity-rules)
  - [Low Rules](#low-severity-rules)
- [By Category](#rule-organization)
  - [Authentication](#authentication-attacks-10-rules)
  - [Reverse Proxy](#reverse-proxy-exploitation-8-rules)
  - [Password Manager](#password-manager-security-4-rules)
  - [Access Control](#access-control--privilege-4-rules)
- [Reference](#tuning-rules)
  - [Tuning](#tuning-rules)
  - [Custom Rules](#creating-custom-rules)
  - [Playbooks](#response-playbooks)
```

**Integration Guides Index:**
```markdown
# Integration Guides

## Getting Started
- [Quick Start](#)
- [Choose Your Stack](#)
- [Installation Overview](#)

## Categories
- **[Reverse Proxies](./reverse-proxies/README.md)**
  - [NGINX Proxy Manager](./reverse-proxies/nginx-proxy-manager.md)
  - [Traefik](./reverse-proxies/traefik.md)
  - [Caddy](./reverse-proxies/caddy.md)

[Continue for all categories...]

## Advanced
- [Custom Parsers](./advanced/custom-parser-development.md)
- [Advanced Rules](./advanced/advanced-rule-creation.md)
```

### 5.3 Search Optimization

#### Keywords for Each Section

**Parsers.md Keywords:**
- Parser name (exact match)
- Application name and aliases
- Log type (access log, auth log, etc.)
- Security category (brute force, SQL injection, etc.)

**Rules.md Keywords:**
- Rule name (exact match)
- Threat type (brute force, injection, etc.)
- Severity level (critical, high, medium, low)
- Detection pattern (authentication, exploitation, etc.)

**Integration Guides Keywords:**
- Application name and aliases
- Technology category (reverse proxy, auth, storage)
- Use case (media server monitoring, etc.)
- Setup keyword (Docker, deployment, configuration)

#### Heading Strategy for SEO

```markdown
# [Application Name] - [What it is]
## [Action] [Application] with SIEMBox
### [Specific scenario] for [Application]
```

---

## 6. Quick Start Guide Design

### 6.1 Popular Stack Combinations

#### Stack 1: NGINX Proxy Manager + Authelia (Most Common)

**Estimated Setup Time:** 30 minutes

**What You Get:**
- Reverse proxy monitoring (primary attack surface)
- Single sign-on authentication (centralized security)
- Detection for both components

**Quick Setup:**
1. Deploy Log Shipper on NGINX Proxy Manager server
2. Deploy Log Shipper on Authelia server
3. Import NGINX Proxy Manager parser
4. Import Authelia parser
5. Import recommended rules (5 rules total)

**Next Steps:**
- [Full NGINX Proxy Manager Guide](./integration-guides/reverse-proxies/nginx-proxy-manager.md)
- [Full Authelia Guide](./integration-guides/authentication/authelia.md)

#### Stack 2: Traefik + authentik (Modern Alternative)

**Estimated Setup Time:** 35 minutes

[Similar structure...]

#### Stack 3: Complete Media Server Monitoring

**Estimated Setup Time:** 20 minutes

[Similar structure...]

#### Stack 4: Password Manager Security (MUST HAVE)

**Estimated Setup Time:** 10 minutes

**What You Get:**
- Master password attempt detection (prevent brute force)
- Vault export alerts (detect theft in progress)
- API abuse detection (detect token theft)

**Quick Setup:**
1. Deploy Log Shipper on Vaultwarden server
2. Import Vaultwarden parser
3. Import all Vaultwarden rules (CRITICAL - 4 rules)
4. Test parser and rules

**Critical:** This should be set up FIRST, before anything else

**Next Steps:**
- [Full Vaultwarden Guide](./integration-guides/critical-services/vaultwarden.md)
- [Threat Model: Password Manager Compromise](../HOMELAB-THREAT-MODEL.md#3-password-manager-compromise-critical-priority)

### 6.2 Deployment Templates

#### Minimal Setup (Single Server)

For homelabbers running everything on one server:

```yaml
# docker-compose.yml for log shipper on main server
version: '3.8'

services:
  siembox-log-shipper:
    image: siembox-log-shipper:managed
    container_name: siembox-log-shipper
    restart: unless-stopped
    network_mode: host
    environment:
      - SHIPPER_API_KEY=your-api-key
      - SIEMBOX_API_URL=http://localhost:8421/api
    volumes:
      - /var/log:/var/log:ro
      # Docker logs from other containers
      - /var/run/docker.sock:/var/run/docker.sock:ro
```

#### Multi-Server Setup

For homelabbers with services on multiple servers:

**On each server:**
```yaml
services:
  siembox-log-shipper:
    image: siembox-log-shipper:managed
    container_name: siembox-log-shipper
    restart: unless-stopped
    network_mode: host
    environment:
      - SHIPPER_API_KEY=server-unique-key
      - SIEMBOX_API_URL=http://central-siembox:8421/api
    volumes:
      - /var/log:/var/log:ro
      # Application-specific logs
      - /path/to/app/logs:/app/logs:ro
```

---

## 7. Migration Guide Design

### 7.1 For Existing Users

#### Upgrading from Old Documentation

**What's Changing:**
- New PARSERS.md organization
- New RULES.md structure
- New integration guides
- Better cross-references

**What's NOT Changing:**
- Your existing parsers (still compatible)
- Your existing rules (still compatible)
- Your detector configuration (unchanged)

**Migration Steps:**
1. No action required - old parsers/rules work as-is
2. When setting up new applications, use new guides
3. New documentation uses better organization

#### Adopting New Parsers

**For Popular Applications:**
Your existing parsers may now have community versions available.

**Option 1: Keep existing parsers**
- Your parsers work fine
- No need to change
- Can coexist with community versions

**Option 2: Migrate to community parser**
1. Test community parser with your logs
2. Update rules to use community parser fields
3. Disable old parser
4. Verify rules still working

### 7.2 Breaking Changes

**None planned!** The redesign maintains backward compatibility:
- Existing parsers continue to work
- Existing rules continue to work
- New documentation is additive

---

## 8. Quality Assurance

### 8.1 Documentation Checklist

Every documentation page must meet these standards:

#### Content Checklist
- [ ] Clear purpose statement at beginning
- [ ] Prerequisites listed explicitly
- [ ] Step-by-step instructions (numbered)
- [ ] Working examples provided
- [ ] Expected output shown
- [ ] Common issues addressed
- [ ] Related documentation linked
- [ ] Tested by at least one person

#### Style Checklist
- [ ] Consistent terminology used
- [ ] No unexplained jargon
- [ ] Tone is encouraging and clear
- [ ] Headings follow hierarchy
- [ ] Code examples syntax-highlighted
- [ ] Tables properly formatted
- [ ] Links are tested and work

#### Technical Accuracy
- [ ] Instructions were tested
- [ ] Commands run successfully
- [ ] Examples match current version
- [ ] Security recommendations current
- [ ] No outdated information

#### Accessibility
- [ ] Screenshots have alt text (if included)
- [ ] Links are descriptive (not "click here")
- [ ] Sentences are short and clear
- [ ] Complex concepts explained simply

### 8.2 Testing Protocol for New Documentation

**Before Publishing:**

1. **Technical Review**
   - Does the setup work as documented?
   - Are all prerequisites listed?
   - Do all links work?
   - Are code examples correct?

2. **User Testing**
   - Can a beginner follow the steps?
   - Are error cases covered?
   - Is troubleshooting section helpful?
   - Is time estimate accurate?

3. **Peer Review**
   - Is language clear and concise?
   - Are there typos?
   - Does it match style guide?
   - Are there missing sections?

4. **Security Review**
   - Are security best practices included?
   - Are warnings in place for dangerous operations?
   - Are default passwords mentioned for change?
   - Are access controls discussed?

---

## 9. Appendix: Example Completed Sections

### 9.1 Example: Vaultwarden Parser Entry

[This would show a completed parser entry following the template above]

### 9.2 Example: SSH Brute Force Rule Entry

[This would show a completed rule entry following the template above]

### 9.3 Example: NGINX Proxy Manager Integration Guide Excerpt

[This would show portions of a completed integration guide following the template above]

---

## 10. Implementation Timeline

### Phase 1: Foundation (Week 1)
- [ ] Create integration-guides directory structure
- [ ] Create documentation templates
- [ ] Establish style guide
- [ ] Set up cross-reference system

### Phase 2: Reorganization (Weeks 2-3)
- [ ] Redesign PARSERS.md with new structure
- [ ] Reorganize RULES.md by severity and category
- [ ] Create HOMELAB-QUICK-START.md
- [ ] Create STACKS.md with popular combinations

### Phase 3: Integration Guides (Weeks 4-6)
- [ ] Write guides for top 5 applications (Vaultwarden, NGINX PM, Authelia, etc.)
- [ ] Write guides for next 5 applications
- [ ] Write guides for remaining applications
- [ ] Create README files for each category

### Phase 4: Polish & Review (Week 7)
- [ ] Technical review of all documentation
- [ ] User testing with actual homelabbers
- [ ] Final edits and corrections
- [ ] Publish updated documentation

### Phase 5: Community & Maintenance (Ongoing)
- [ ] Accept community contributions
- [ ] Update for new applications
- [ ] Maintain consistency across docs
- [ ] Regular review and updates

---

## 11. Success Metrics

### Documentation Effectiveness

**Quantitative:**
- Pages with >50 views per month
- Average time on page (target: 5+ minutes)
- Click-through rate to related docs (target: >20%)
- Reduced GitHub issues about setup (target: -30%)

**Qualitative:**
- User feedback and satisfaction
- Community contributions
- Reduced support questions
- Positive comments in discussions

### Audience Reach

- Beginner users complete setup in <1 hour
- Integration guides completed within timeframe
- Homelabbers successfully deploy multiple parsers
- Rules work with minimal false positives

### Community Engagement

- Parser/rule contributions increase
- Integration guide quality improves
- Community spots gaps in documentation
- Users help each other using references

---

## 12. Future Enhancements

### Potential Additions

1. **Video Tutorials**
   - Short demo videos for common setups
   - Troubleshooting walkthroughs

2. **Interactive Guides**
   - Step-by-step wizard in UI
   - Automated parser/rule import

3. **Community Translations**
   - French, Spanish, German, Chinese
   - Community-contributed translations

4. **Documentation Search**
   - Full-text search across all docs
   - Semantic search ("how do I...")

5. **Analytics & Telemetry**
   - Which guides users follow
   - What they get stuck on
   - Areas needing improvement

---

## Conclusion

This documentation architecture provides a clear, scalable structure for growing the SIEMBox homelab documentation ecosystem. By organizing content by security priority, use case, and user skill level, we enable homelabbers to quickly find what they need and deploy monitoring effectively.

The templates, style guide, and navigation strategy ensure consistency across all documentation as it grows to 20+ parsers, 30+ rules, and 15+ integration guides.

---

**Document Control**
- **Version:** 1.0
- **Last Updated:** 2025-12-03
- **Status:** Ready for Implementation
- **Next Review:** After Phase 3 Implementation (6 weeks)

---

**Approval & Sign-Off**

This documentation architecture is ready for implementation. The structure supports:
- Clear organization for homelabbers to understand what to monitor
- Scalable templates for adding 20+ parsers and 30+ rules
- Comprehensive integration guides for popular applications
- Consistency across all documentation
- Easy navigation and cross-referencing

---
