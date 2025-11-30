# SIEMBox Detection Rules

This document contains built-in and community-contributed detection rules for SIEMBox. These rules automatically generate alerts when suspicious activity is detected in your logs.

## Table of Contents
- [Built-in Rules](#built-in-rules)
  - [SSH Brute Force Detection](#ssh-brute-force-detection)
  - [Direct Root SSH Login](#direct-root-ssh-login)
  - [Sudo Privilege Escalation](#sudo-privilege-escalation)
  - [Web Path Scanning](#web-path-scanning)
  - [Web Server Errors](#web-server-errors)
  - [Multiple Failed Authentication](#multiple-failed-authentication)
- [UniFi Security Rules](#unifi-security-rules)
  - [Repeated Attack Attempts](#unifi-ips-repeated-attack-attempts)
  - [Internal System Under Attack](#unifi-ips-internal-system-under-attack)
  - [IDS/IPS Error Events](#unifi-idsips-error-events)
  - [Port Scan Detection](#unifi-ips-port-scan-detection)
- [Rule Concepts](#rule-concepts)
- [Creating Custom Rules](#creating-custom-rules)

---

## Built-in Rules

These rules are automatically included with every SIEMBox installation.

### SSH Brute Force Detection

Detects brute force attacks against SSH by monitoring failed password attempts.

**Configuration:**
- **Name:** `SSH Brute Force Detection`
- **Severity:** `high`
- **Tags:** `ssh`, `brute-force`, `authentication`

**YAML:**
```yaml
name: SSH Brute Force Detection
description: Detects multiple failed SSH login attempts from same IP
severity: high
enabled: true
tags: [ssh, brute-force, authentication]

conditions:
  - field: event
    operator: equals
    value: "Failed password"

aggregation:
  field: source_ip
  timeframe: 5m
  threshold: 5

alert:
  title: "SSH Brute Force Detected from {source_ip}"
  description: "{count} failed SSH login attempts detected in 5 minutes"
```

**What It Detects:**
- 5 or more failed SSH password attempts from the same IP in 5 minutes

**Use Cases:**
- Detect automated brute force attacks
- Identify compromised systems attempting to breach SSH
- Alert on credential stuffing attempts

**Works With Parsers:**
- SSH Authentication parser

---

### Direct Root SSH Login

Detects when someone successfully logs in directly as root user via SSH.

**Configuration:**
- **Name:** `Direct Root SSH Login`
- **Severity:** `critical`
- **Tags:** `ssh`, `root`, `privilege`

**YAML:**
```yaml
name: Direct Root SSH Login
description: Detects successful SSH login as root user
severity: critical
enabled: true
tags: [ssh, root, privilege]

conditions:
  - field: event
    operator: contains
    value: "Accepted"
  - field: user
    operator: equals
    value: "root"

alert:
  title: "Root SSH Login from {source_ip}"
  description: "Direct root login detected from {source_ip}"
```

**What It Detects:**
- Any successful SSH login using the root account

**Use Cases:**
- Enforce security best practice (no direct root login)
- Detect unauthorized root access
- Monitor for privilege abuse

**Works With Parsers:**
- SSH Authentication parser

---

### Sudo Privilege Escalation

Monitors sudo commands executed to become root user.

**Configuration:**
- **Name:** `Sudo Privilege Escalation`
- **Severity:** `medium`
- **Tags:** `sudo`, `privilege-escalation`

**YAML:**
```yaml
name: Sudo Privilege Escalation
description: Detects sudo commands executed to become root
severity: medium
enabled: true
tags: [sudo, privilege-escalation]

conditions:
  - field: target_user
    operator: equals
    value: "root"
  - field: command
    operator: not_contains
    value: "/usr/bin/whoami"

alert:
  title: "Sudo to Root by {user}"
  description: "User {user} executed sudo command as root: {command}"
```

**What It Detects:**
- Sudo commands executed as root (excluding harmless commands like whoami)

**Use Cases:**
- Monitor administrative actions
- Track privilege escalation
- Audit root command execution

**Works With Parsers:**
- Linux Sudo parser

---

### Web Path Scanning

Detects directory/path scanning attempts by monitoring 404 errors.

**Configuration:**
- **Name:** `Web Path Scanning`
- **Severity:** `medium`
- **Tags:** `web`, `scanning`, `reconnaissance`

**YAML:**
```yaml
name: Web Path Scanning
description: Detects multiple 404 errors from same IP (directory scanning)
severity: medium
enabled: true
tags: [web, scanning, reconnaissance]

conditions:
  - field: status_code
    operator: equals
    value: "404"

aggregation:
  field: client_ip
  timeframe: 5m
  threshold: 20

alert:
  title: "Web Scanning Detected from {client_ip}"
  description: "{count} 404 errors detected in 5 minutes from {client_ip}"
```

**What It Detects:**
- 20 or more 404 errors from the same IP in 5 minutes

**Use Cases:**
- Detect reconnaissance/enumeration attempts
- Identify vulnerability scanners
- Alert on directory brute forcing

**Works With Parsers:**
- Apache/Nginx Access Log parser

---

### Web Server Errors

Monitors for application/server errors that may indicate issues.

**Configuration:**
- **Name:** `Web Server Errors`
- **Severity:** `low`
- **Tags:** `web`, `availability`, `errors`

**YAML:**
```yaml
name: Web Server Errors
description: Detects multiple HTTP 5xx server errors
severity: low
enabled: true
tags: [web, availability, errors]

conditions:
  - field: status_code
    operator: regex
    value: "^5\\d{2}$"

aggregation:
  field: path
  timeframe: 10m
  threshold: 10

alert:
  title: "Multiple Server Errors on {path}"
  description: "{count} HTTP 5xx errors detected in 10 minutes"
```

**What It Detects:**
- 10 or more HTTP 5xx errors on the same path in 10 minutes

**Use Cases:**
- Monitor application health
- Detect backend service failures
- Alert on code errors

**Works With Parsers:**
- Apache/Nginx Access Log parser

---

### Multiple Failed Authentication

Generic rule for detecting failed authentication attempts across various services.

**Configuration:**
- **Name:** `Multiple Failed Authentication`
- **Severity:** `medium`
- **Tags:** `authentication`, `failed-login`

**YAML:**
```yaml
name: Multiple Failed Authentication
description: Detects multiple failed authentication attempts (generic)
severity: medium
enabled: true
tags: [authentication, failed-login]

conditions:
  - field: message
    operator: contains
    value: "failed"
  - field: message
    operator: contains
    value: "authentication"

aggregation:
  field: source_ip
  timeframe: 10m
  threshold: 8

alert:
  title: "Multiple Failed Logins from {source_ip}"
  description: "{count} failed authentication attempts in 10 minutes"
```

**What It Detects:**
- 8 or more failed authentication events from same IP in 10 minutes

**Use Cases:**
- Catch-all for various authentication failures
- Detect brute force on custom applications
- Monitor authentication across services

**Works With Parsers:**
- Generic Syslog parser
- Any parser that includes authentication messages

---

## UniFi Security Rules

Detection rules specifically for Ubiquiti UniFi IDS/IPS and firewall logs.

### UniFi IPS Repeated Attack Attempts

Detects persistent attackers who trigger multiple IPS blocks.

**Configuration:**
- **Name:** `UniFi IPS Repeated Attack Attempts`
- **Severity:** `high`
- **Tags:** `unifi`, `ips`, `intrusion`, `attack`

**YAML:**
```yaml
name: UniFi IPS Repeated Attack Attempts
description: Detects multiple IPS block events from same external IP (persistent attack)
severity: high
enabled: true
tags: [unifi, ips, intrusion, attack]

conditions:
  - field: action_type
    operator: equals
    value: "ips"
  - field: action
    operator: equals
    value: "add"

aggregation:
  field: external_ip
  timeframe: 10m
  threshold: 5

alert:
  title: "Repeated IPS Blocks from {external_ip}"
  description: "{count} IPS block events from {external_ip} in 10 minutes - possible persistent attack"
```

**What It Detects:**
- 5 or more IPS block events from the same external IP in 10 minutes

**Use Cases:**
- Identify persistent attackers
- Detect automated attack tools
- Monitor for multiple attack vectors from same source

**Works With Parsers:**
- Ubiquiti UniFi IDS/IPS parser

---

### UniFi IPS Internal System Under Attack

Critical alert when internal systems are heavily targeted.

**Configuration:**
- **Name:** `UniFi IPS Internal System Under Attack`
- **Severity:** `critical`
- **Tags:** `unifi`, `ips`, `internal-threat`, `attack`

**YAML:**
```yaml
name: UniFi IPS Internal System Under Attack
description: Detects when internal system is being repeatedly targeted by IPS blocks
severity: critical
enabled: true
tags: [unifi, ips, internal-threat, attack]

conditions:
  - field: action_type
    operator: equals
    value: "ips"
  - field: action
    operator: equals
    value: "add"

aggregation:
  field: internal_ip
  timeframe: 15m
  threshold: 10

alert:
  title: "Internal System {internal_ip} Under Attack"
  description: "{count} IPS blocks targeting {internal_ip} in 15 minutes - system may be compromised or under heavy attack"
```

**What It Detects:**
- 10 or more IPS blocks targeting the same internal IP in 15 minutes

**Use Cases:**
- Detect compromised internal systems
- Monitor for lateral movement attempts
- Alert on heavy targeting of critical infrastructure

**Works With Parsers:**
- Ubiquiti UniFi IDS/IPS parser

---

### UniFi IDS/IPS Error Events

Monitors IDS/IPS system errors that may indicate issues.

**Configuration:**
- **Name:** `UniFi IDS/IPS Error Events`
- **Severity:** `medium`
- **Tags:** `unifi`, `ips`, `ids`, `errors`

**YAML:**
```yaml
name: UniFi IDS/IPS Error Events
description: Detects error-level events in UniFi IDS/IPS system
severity: medium
enabled: true
tags: [unifi, ips, ids, errors]

conditions:
  - field: severity
    operator: equals
    value: "Error"
  - field: event_type
    operator: contains
    value: "error"

alert:
  title: "UniFi IDS/IPS Error Detected"
  description: "IDS/IPS error event: {event_type} - {external_ip}:{external_port} -> {internal_ip}:{internal_port}"
```

**What It Detects:**
- Error-level events in the IDS/IPS system

**Use Cases:**
- Monitor IDS/IPS health
- Catch system misconfigurations
- Detect IPS capacity issues

**Works With Parsers:**
- Ubiquiti UniFi IDS/IPS parser

---

### UniFi IPS Port Scan Detection

Detects port scanning activity based on rapid IPS blocks.

**Configuration:**
- **Name:** `UniFi IPS Port Scan Detection`
- **Severity:** `high`
- **Tags:** `unifi`, `ips`, `port-scan`, `reconnaissance`

**YAML:**
```yaml
name: UniFi IPS Port Scan Detection
description: Detects potential port scanning activity based on IPS blocks from same IP to multiple internal ports
severity: high
enabled: true
tags: [unifi, ips, port-scan, reconnaissance]

conditions:
  - field: action_type
    operator: equals
    value: "ips"
  - field: action
    operator: equals
    value: "add"

aggregation:
  field: external_ip
  timeframe: 5m
  threshold: 8

alert:
  title: "Port Scan Detected from {external_ip}"
  description: "{count} IPS blocks from {external_ip} in 5 minutes - likely port scanning activity"
```

**What It Detects:**
- 8 or more IPS blocks from same IP in 5 minutes (rapid reconnaissance)

**Use Cases:**
- Detect port scanning reconnaissance
- Identify vulnerability scanners
- Alert on pre-attack enumeration

**Works With Parsers:**
- Ubiquiti UniFi IDS/IPS parser

---

## Rule Concepts

### Rule Components

**Conditions:**
- Field-based matching (exact, contains, regex)
- Multiple conditions are AND'ed together
- Match specific log fields extracted by parsers

**Aggregation:**
- Count events over time windows
- Group by specific fields
- Trigger alerts when threshold is exceeded

**Operators:**
- `equals` - Exact match
- `contains` - Substring match
- `not_contains` - Does not contain substring
- `regex` - Regular expression match
- `greater_than` - Numeric comparison
- `less_than` - Numeric comparison

**Severity Levels:**
- `low` - Informational, minor issues
- `medium` - Potentially suspicious activity
- `high` - Serious security concerns
- `critical` - Immediate action required

**Timeframes:**
- `1m` - 1 minute
- `5m` - 5 minutes
- `10m` - 10 minutes
- `15m` - 15 minutes
- `30m` - 30 minutes
- `1h` - 1 hour
- `24h` - 24 hours

### Alert Templates

Rules can use field substitution in alerts:
- `{field_name}` - Replaced with field value
- `{count}` - Number of matching events
- `{source_ip}` - Source IP (if available)

---

## Creating Custom Rules

### Example: Detect Excessive Database Errors

```yaml
name: Database Connection Errors
description: Detects multiple database connection failures
severity: medium
enabled: true
tags: [database, errors, availability]

conditions:
  - field: message
    operator: contains
    value: "database"
  - field: message
    operator: contains
    value: "connection failed"

aggregation:
  field: service
  timeframe: 5m
  threshold: 10

alert:
  title: "Database Connection Issues in {service}"
  description: "{count} database connection failures in 5 minutes"
```

### Example: Detect Suspicious Login Times

```yaml
name: After-Hours Login
description: Detects successful logins outside business hours
severity: low
enabled: true
tags: [authentication, anomaly]

conditions:
  - field: event
    operator: contains
    value: "Accepted"
  - field: timestamp
    operator: regex
    value: "(00|01|02|03|04|05|20|21|22|23):"

alert:
  title: "After-Hours Login from {source_ip}"
  description: "Successful login detected outside business hours (8am-8pm)"
```

### Rule Best Practices

1. **Start with Higher Thresholds**: Begin conservatively and tune down to reduce false positives
2. **Use Aggregation**: Group events to detect patterns, not individual occurrences
3. **Tag Appropriately**: Use consistent tags for filtering and organization
4. **Clear Alert Titles**: Make alerts actionable and specific
5. **Test Rules**: Verify rules trigger correctly with sample data
6. **Document Purpose**: Include clear descriptions of what and why

### Adding Rules via UI

1. Navigate to **Detection Rules** page
2. Click **Create Rule**
3. Paste YAML or use the rule builder
4. Test with sample logs
5. Enable and save

### Adding Rules via Database

```sql
INSERT INTO detection_rules (name, description, severity, rule_yaml, rule_logic, tags, enabled)
VALUES (
    'My Custom Rule',
    'Description of what this detects',
    'medium',
    'name: My Custom Rule
description: Description
severity: medium
enabled: true
tags: [custom, security]

conditions:
  - field: some_field
    operator: equals
    value: "some_value"

alert:
  title: "Alert Title"
  description: "Alert description"',
    '{"conditions": [{"field": "some_field", "operator": "equals", "value": "some_value"}]}',
    ARRAY['custom', 'security'],
    true
);
```

---

## Contributing Rules

Have a detection rule to share? Please submit a pull request with:
1. Rule YAML with clear description
2. Example log samples that trigger it
3. Expected alert output
4. Use cases and threat scenarios

### Submission Guidelines
- Test rules with real data before submitting
- Use descriptive names and tags
- Set appropriate severity levels
- Include aggregation for pattern detection
- Document any parser dependencies

---

## Detection Strategy

### Defense in Depth

Combine multiple rule types:
- **Authentication monitoring** - Brute force, unusual logins
- **Reconnaissance detection** - Scanning, enumeration
- **Intrusion detection** - IPS/IDS alerts, exploits
- **Privilege monitoring** - Root access, sudo usage
- **Error tracking** - Application health, system issues

### Tuning Rules

Monitor false positive rates:
- Too many alerts? Increase thresholds or timeframes
- Missing attacks? Lower thresholds or add more conditions
- Wrong severity? Adjust based on actual impact

### Integration with Parsers

Rules work best with proper log parsing:
- Ensure parsers extract all relevant fields
- Use consistent field names across parsers
- Test parser + rule combinations
- See [PARSERS.md](./PARSERS.md) for parser documentation

---

## Support

- **Issues**: https://github.com/cladkins/SIEMBOX/issues
- **Discussions**: https://github.com/cladkins/SIEMBOX/discussions
- **Parser Documentation**: [PARSERS.md](./PARSERS.md)

## License

MIT License - Same as SIEMBox
