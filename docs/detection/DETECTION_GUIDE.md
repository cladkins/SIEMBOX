# SIEM BOX - Detection Rules Guide

This guide covers how to create, configure, and manage detection rules in SIEM BOX using the web interface. Detection rules analyze parsed log data to identify security events, anomalies, and potential threats.

## Table of Contents

1. [Overview](#overview)
2. [Web Interface Management](#web-interface-management)
3. [Rule Types](#rule-types)
4. [Creating Custom Rules](#creating-custom-rules)
5. [Rule Conditions](#rule-conditions)
6. [Threshold Rules](#threshold-rules)
7. [Pattern Rules](#pattern-rules)
8. [Correlation Rules](#correlation-rules)
9. [Anomaly Detection](#anomaly-detection)
10. [Testing Rules](#testing-rules)
11. [API Usage](#api-usage)
12. [Best Practices](#best-practices)
13. [Troubleshooting](#troubleshooting)

## Overview

The SIEM BOX detection system continuously analyzes parsed log data to identify security threats and anomalies. All detection rules are managed through the intuitive web interface, making it easy to create, test, and deploy custom detection logic without manual configuration files.

### Key Components

- **Detection Rules**: Configuration that defines what to look for in logs
- **Alerts**: Generated when rules match log data
- **Conditions**: Criteria that must be met for a rule to trigger
- **Thresholds**: Numeric limits for triggering rules
- **Correlation**: Rules that analyze relationships between multiple events

### Detection Flow

1. **Log Parsing**: Raw logs are parsed into structured data
2. **Rule Evaluation**: Detection rules analyze parsed logs
3. **Alert Generation**: Matching rules create alerts
4. **Notification**: Alerts trigger configured notifications
5. **Response**: Security team investigates and responds

## Web Interface Management

All detection rule management is performed through the SIEM BOX web interface, providing a user-friendly experience for creating, testing, and managing detection rules.

### Accessing Detection Rules

1. **Navigate to Rules**: Click on "Rules" in the main navigation
2. **Rule Dashboard**: View all detection rules with status and performance metrics
3. **Rule Management**: Create, edit, enable/disable, and test rules through web forms

### Rules Page Overview

The Rules page provides comprehensive rule management through several sections:

#### Rule List View
- **Rule Status**: Visual indicators for enabled/disabled rules
- **Rule Information**: Name, type, severity, category, and last modified
- **Performance Metrics**: Trigger count, false positive rate, and execution time
- **Quick Actions**: Enable/disable, edit, test, and delete rules

#### Rule Creation Interface
- **Rule Builder**: Step-by-step wizard for creating new rules
- **Template Library**: Pre-built rule templates for common threats
- **Real-Time Validation**: Immediate feedback on rule syntax and logic
- **Preview Mode**: See how rules will match against sample data

#### Rule Testing Environment
- **Test Data Upload**: Upload sample logs for rule testing
- **Live Testing**: Test rules against recent log data
- **Performance Analysis**: Monitor rule execution time and resource usage
- **Result Visualization**: See exactly which logs match rule conditions

### Rule Management Workflow

1. **Rule Creation**: Use the web interface to create new detection rules
   - Select rule type from dropdown menu
   - Configure conditions using form fields
   - Set severity and category
   - Test rule against sample data

2. **Rule Validation**: Built-in validation ensures rule quality
   - Syntax checking for patterns and conditions
   - Logic validation to prevent conflicts
   - Performance impact assessment
   - False positive prediction

3. **Rule Deployment**: Deploy rules with confidence
   - Gradual rollout options
   - Monitoring mode for new rules
   - Automatic rollback on errors
   - Real-time performance monitoring

4. **Rule Maintenance**: Keep rules effective over time
   - Performance dashboards
   - False positive tracking
   - Automatic tuning suggestions
   - Rule effectiveness metrics

### Web Interface Features

#### Visual Rule Builder
- **Drag-and-Drop Interface**: Build complex rules visually
- **Condition Chaining**: Combine multiple conditions with AND/OR logic
- **Field Autocomplete**: Automatic suggestions for log fields
- **Pattern Testing**: Test regex patterns in real-time

#### Rule Templates
- **Pre-Built Rules**: 20+ ready-to-use detection rules
- **Custom Templates**: Save your own rules as templates
- **Template Categories**: Organized by threat type and severity
- **One-Click Deployment**: Deploy templates with minimal configuration

#### Real-Time Monitoring
- **Rule Performance**: Live metrics on rule execution
- **Alert Generation**: Real-time alert creation and notification
- **Resource Usage**: Monitor CPU and memory impact
- **Error Tracking**: Automatic detection of rule issues

#### Collaboration Features
- **Rule Sharing**: Share rules between team members
- **Version Control**: Track changes to rule configurations
- **Comments and Notes**: Add context and documentation
- **Approval Workflows**: Require approval for critical rule changes

## Rule Types

SIEM BOX supports several types of detection rules:

### 1. Threshold Rules

Monitor for events that exceed specified limits within time windows.

**Use Cases**:
- Brute force attacks (multiple failed logins)
- Port scanning (many connection attempts)
- High error rates
- Unusual traffic volumes

### 2. Pattern Rules

Match specific patterns or signatures in log data.

**Use Cases**:
- SQL injection attempts
- Malware signatures
- Suspicious user agents
- Command injection

### 3. Correlation Rules

Analyze relationships between multiple events or log sources.

**Use Cases**:
- Successful login after failed attempts
- Privilege escalation sequences
- Multi-stage attacks
- Cross-system activities

### 4. Anomaly Rules

Detect deviations from normal behavior patterns.

**Use Cases**:
- Unusual login times
- Geographic anomalies
- Traffic spikes
- Behavioral changes

### 5. Temporal Rules

Monitor for events occurring at unusual times.

**Use Cases**:
- Off-hours access
- Weekend activities
- Holiday logins
- Time-based restrictions

### 6. Geolocation Rules

Analyze geographic patterns in log data.

**Use Cases**:
- Impossible travel
- Restricted countries
- VPN detection
- Location-based access control

## Creating Custom Rules

All detection rules are created and managed through the web interface, providing an intuitive experience for security analysts and administrators.

### Rule Creation Workflow

1. **Access Rule Builder**: Navigate to Rules → Create New Rule
2. **Select Rule Type**: Choose from threshold, pattern, correlation, or anomaly detection
3. **Configure Basic Information**: Set name, description, severity, and category
4. **Define Conditions**: Use the visual interface to set detection criteria
5. **Test Rule**: Validate rule logic against sample or recent log data
6. **Deploy Rule**: Enable the rule for active monitoring

### Rule Configuration Form

The web interface provides a comprehensive form for rule configuration:

#### Basic Information Section
| Field | Description | Example |
|-------|-------------|---------|
| **Rule Name** | Unique identifier for the rule | "SSH Brute Force Detection" |
| **Description** | Detailed explanation of what the rule detects | "Detects multiple failed SSH login attempts" |
| **Rule Type** | Detection methodology | Threshold, Pattern, Correlation, Anomaly |
| **Severity** | Alert severity level | Low, Medium, High, Critical |
| **Category** | Security threat category | Brute Force, Web Attack, Malware |
| **Enabled** | Rule activation status | ✓ Enabled / ☐ Disabled |

#### Conditions Configuration
The conditions section adapts based on the selected rule type:

- **Log Type Filter**: Select which types of logs to analyze
- **Field Conditions**: Specify field values and patterns to match
- **Time Windows**: Define time-based constraints
- **Thresholds**: Set numeric limits for triggering alerts
- **Grouping**: Configure how events are grouped for analysis

### Severity Levels

| Level | Description | Response Time |
|-------|-------------|---------------|
| `low` | Informational events | Review within 24 hours |
| `medium` | Potential security issues | Review within 4 hours |
| `high` | Likely security incidents | Review within 1 hour |
| `critical` | Active security breaches | Immediate response |

### Security Categories

| Category | Description | Examples |
|----------|-------------|----------|
| `brute_force` | Password/credential attacks | SSH brute force, login attempts |
| `web_attack` | Web application attacks | SQL injection, XSS, path traversal |
| `network_scan` | Network reconnaissance | Port scans, service discovery |
| `privilege_escalation` | Elevation of privileges | Sudo abuse, root access |
| `malware` | Malicious software | Virus signatures, suspicious processes |
| `data_exfiltration` | Data theft attempts | Large uploads, DNS tunneling |
| `authentication` | Authentication events | Failed logins, account lockouts |
| `network_anomaly` | Unusual network activity | Unexpected connections, protocols |
| `container_security` | Container-related threats | Escape attempts, privilege abuse |

## Creating Custom Rules

### Step 1: Identify the Threat

Define what you want to detect:
- What specific behavior indicates a threat?
- What log sources contain relevant data?
- What fields should be analyzed?
- What constitutes normal vs. suspicious activity?

### Step 2: Choose Rule Type

Select the appropriate rule type based on your detection logic:

- **Threshold**: Count-based detection
- **Pattern**: Signature-based detection
- **Correlation**: Multi-event analysis
- **Anomaly**: Baseline deviation
- **Temporal**: Time-based analysis
- **Geolocation**: Location-based analysis

### Step 3: Define Conditions

Create the rule conditions based on your chosen type.

### Example: Custom Brute Force Rule

```yaml
detection_rules:
  - name: "Custom Application Brute Force"
    description: "Detects brute force attacks against custom application"
    rule_type: "threshold"
    severity: "high"
    category: "brute_force"
    conditions:
      log_type: "web_api"
      field_conditions:
        endpoint: "/api/login"
        status_code: "401"
      threshold:
        count: 10
        time_window: 300  # 5 minutes
        group_by: ["client_ip"]
    enabled: true
```

## Rule Conditions

### Basic Conditions

All rules support these basic condition types:

```yaml
conditions:
  log_type: "authentication"  # Filter by log type
  category: "security"        # Filter by log category
  field_conditions:           # Filter by field values
    field_name: "value"
    another_field: ["value1", "value2"]  # Multiple values
```

### Field Conditions

Field conditions filter logs based on parsed field values:

```yaml
field_conditions:
  # Exact match
  username: "admin"
  
  # Multiple values (OR logic)
  status_code: ["400", "401", "403", "404"]
  
  # Pattern matching (regex)
  user_agent: "(?i)(bot|crawler|scanner)"
  
  # Numeric comparisons
  response_time: ">1.0"
  bytes_sent: ">=1048576"  # 1MB
```

### Operators for Numeric Fields

| Operator | Description | Example |
|----------|-------------|---------|
| `>` | Greater than | `response_time: ">1.0"` |
| `>=` | Greater than or equal | `bytes_sent: ">=1024"` |
| `<` | Less than | `cpu_usage: "<90"` |
| `<=` | Less than or equal | `memory_usage: "<=80"` |
| `==` | Equal to | `port: "==22"` |
| `!=` | Not equal to | `status: "!=200"` |

## Threshold Rules

Threshold rules trigger when event counts exceed specified limits within time windows.

### Basic Threshold Structure

```yaml
conditions:
  log_type: "authentication"
  field_conditions:
    action: "failed"
  threshold:
    count: 5              # Number of events
    time_window: 300      # Time window in seconds
    group_by: ["src_ip"]  # Group events by these fields
```

### Advanced Threshold Options

```yaml
threshold:
  count: 10
  time_window: 600
  group_by: ["src_ip", "username"]
  
  # Unique field counting
  unique_field: "username"  # Count unique usernames per group
  
  # Field-based thresholds
  field_threshold:
    field: "bytes_sent"
    operator: ">"
    value: 10485760  # 10MB
  
  # Minimum baseline
  min_baseline_count: 5  # Require at least 5 events for baseline
```

### Example: SSH Brute Force Detection

```yaml
- name: "SSH Brute Force Attack"
  description: "Detects multiple failed SSH login attempts from same IP"
  rule_type: "threshold"
  severity: "high"
  category: "brute_force"
  conditions:
    log_type: "authentication"
    field_conditions:
      action: "Failed"
      protocol: "ssh"
    threshold:
      count: 5
      time_window: 300
      group_by: ["src_ip"]
  enabled: true
```

### Example: High Volume Data Transfer

```yaml
- name: "Large Data Transfer"
  description: "Detects unusually large data transfers"
  rule_type: "threshold"
  severity: "medium"
  category: "data_exfiltration"
  conditions:
    log_type: "web_access"
    threshold:
      count: 1
      time_window: 60
      field_threshold:
        field: "bytes_sent"
        operator: ">"
        value: 104857600  # 100MB
  enabled: true
```

## Pattern Rules

Pattern rules match specific signatures or patterns in log data using regular expressions.

### Basic Pattern Structure

```yaml
conditions:
  log_type: "web_access"
  field: "url"  # Field to search
  patterns:
    - '(?i)(union.*select|select.*from)'  # SQL injection
    - '(?i)(<script|javascript:)'         # XSS
    - '(?i)(\.\.\/|\.\.\\)'              # Path traversal
```

### Pattern Options

```yaml
conditions:
  log_type: "web_access"
  field: "user_agent"
  patterns:
    - '(?i)(nmap|nikto|sqlmap)'  # Case-insensitive
    - '^$'                       # Empty string
    - '\b(bot|crawler)\b'        # Word boundaries
  
  # Multiple field patterns
  multi_field_patterns:
    url: ['(?i)(union.*select)']
    user_agent: ['(?i)(sqlmap)']
```

### Example: Web Attack Detection

```yaml
- name: "Web Application Attack Patterns"
  description: "Detects common web attack patterns in URLs"
  rule_type: "pattern"
  severity: "high"
  category: "web_attack"
  conditions:
    log_type: "web_access"
    field: "url"
    patterns:
      - '(?i)(union.*select|select.*from|insert.*into)'  # SQL injection
      - '(?i)(<script|javascript:|onload=|onerror=)'      # XSS
      - '(?i)(\.\.\/|\.\.\\|\/etc\/passwd)'              # Path traversal
      - '(?i)(cmd\.exe|powershell|\/bin\/sh)'            # Command injection
  enabled: true
```

### Example: Suspicious Process Execution

```yaml
- name: "Suspicious Process Execution"
  description: "Detects execution of suspicious processes"
  rule_type: "pattern"
  severity: "high"
  category: "malware"
  conditions:
    log_type: "system"
    field: "message"
    patterns:
      - '(?i)(nc\.exe|netcat|ncat)\s+-[lep]'
      - '(?i)(powershell.*-enc|powershell.*-e\s+[A-Za-z0-9+\/=]+)'
      - '(?i)(certutil.*-decode|certutil.*-urlcache)'
      - '(?i)(wmic.*process.*call.*create)'
  enabled: true
```

## Correlation Rules

Correlation rules analyze relationships between multiple events to detect complex attack patterns.

### Basic Correlation Structure

```yaml
conditions:
  sequence:
    - log_type: "authentication"
      field_conditions:
        action: "Failed"
      min_count: 3
      time_window: 300
    - log_type: "authentication"
      field_conditions:
        action: "Accepted"
      time_window: 60
  correlation_field: "src_ip"  # Field to correlate events
```

### Correlation Options

```yaml
conditions:
  sequence:
    - # First event criteria
      log_type: "authentication"
      field_conditions:
        action: "Failed"
      min_count: 5
      time_window: 300
      
    - # Second event criteria
      log_type: "authentication"
      field_conditions:
        action: "Accepted"
      max_count: 1
      time_window: 120
      
  correlation_field: "src_ip"
  max_time_span: 600  # Maximum time between first and last event
```

### Example: Successful Login After Brute Force

```yaml
- name: "Successful Login After Failed Attempts"
  description: "Detects successful login after multiple failed attempts"
  rule_type: "correlation"
  severity: "high"
  category: "successful_brute_force"
  conditions:
    sequence:
      - log_type: "authentication"
        field_conditions:
          action: "Failed"
        min_count: 3
        time_window: 300
      - log_type: "authentication"
        field_conditions:
          action: "Accepted"
        time_window: 60
    correlation_field: "src_ip"
  enabled: true
```

### Example: Privilege Escalation Sequence

```yaml
- name: "Privilege Escalation Sequence"
  description: "Detects user login followed by privilege escalation"
  rule_type: "correlation"
  severity: "high"
  category: "privilege_escalation"
  conditions:
    sequence:
      - log_type: "authentication"
        field_conditions:
          action: "Accepted"
        time_window: 300
      - log_type: "authentication"
        field_conditions:
          command: "(?i)(sudo|su)"
        time_window: 600
    correlation_field: "username"
  enabled: true
```

## Anomaly Detection

Anomaly rules detect deviations from established baselines.

### Basic Anomaly Structure

```yaml
conditions:
  log_type: "web_access"
  field_conditions:
    status_code: ["4xx", "5xx"]
  anomaly:
    baseline_window: 3600      # 1 hour baseline
    detection_window: 300      # 5 minute detection window
    threshold_multiplier: 3.0  # 3x normal rate
    min_baseline_count: 10     # Minimum events for baseline
```

### Anomaly Options

```yaml
anomaly:
  baseline_window: 7200       # Baseline period in seconds
  detection_window: 300       # Detection period in seconds
  threshold_multiplier: 2.5   # Multiplier for anomaly threshold
  min_baseline_count: 20      # Minimum baseline events
  
  # Statistical methods
  method: "standard_deviation"  # or "percentile"
  percentile: 95               # For percentile method
  
  # Grouping
  group_by: ["src_ip"]        # Group anomalies by field
```

### Example: HTTP Error Rate Spike

```yaml
- name: "HTTP Error Rate Spike"
  description: "Detects unusual spike in HTTP error responses"
  rule_type: "anomaly"
  severity: "medium"
  category: "application_error"
  conditions:
    log_type: "web_access"
    field_conditions:
      status_code: ["400", "401", "403", "404", "500", "502", "503"]
    anomaly:
      baseline_window: 3600
      detection_window: 300
      threshold_multiplier: 3.0
      min_baseline_count: 10
  enabled: true
```

## Testing Rules

### Manual Testing

1. **Create test data**: Generate or collect sample logs
2. **Ingest logs**: Send test data to SIEM BOX
3. **Run detection**: Execute rules against test data
4. **Verify alerts**: Check that expected alerts are generated

### API Testing Workflow

```bash
# 1. Create a test rule
curl -X POST "http://localhost:8000/api/v1/detection/rules" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Rule",
    "description": "Test detection rule",
    "rule_type": "threshold",
    "severity": "medium",
    "category": "test",
    "conditions": {
      "log_type": "authentication",
      "field_conditions": {
        "action": "failed"
      },
      "threshold": {
        "count": 3,
        "time_window": 300,
        "group_by": ["src_ip"]
      }
    },
    "is_enabled": true
  }'

# 2. Run detection on recent logs
curl -X POST "http://localhost:8000/api/v1/detection/auto-detect"

# 3. Check generated alerts
curl "http://localhost:8000/api/v1/alerts/?hours=1"
```

### Validation Checklist

- [ ] Rule triggers on expected log patterns
- [ ] Rule doesn't trigger on normal activity
- [ ] Alert severity is appropriate
- [ ] Alert contains relevant context
- [ ] Performance impact is acceptable
- [ ] False positive rate is low

## API Usage

### Available Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/detection/rules` | GET | List detection rules |
| `/api/v1/detection/rules` | POST | Create new rule |
| `/api/v1/detection/rules/{id}` | GET | Get specific rule |
| `/api/v1/detection/rules/{id}` | PUT | Update rule |
| `/api/v1/detection/rules/{id}` | DELETE | Delete rule |
| `/api/v1/detection/rules/{id}/enable` | POST | Enable rule |
| `/api/v1/detection/rules/{id}/disable` | POST | Disable rule |
| `/api/v1/detection/run` | POST | Run detection on logs |
| `/api/v1/detection/auto-detect` | POST | Auto-detect on recent logs |
| `/api/v1/detection/stats` | GET | Get detection statistics |

### Create Detection Rule

```bash
curl -X POST "http://localhost:8000/api/v1/detection/rules" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Custom Brute Force Rule",
    "description": "Detects brute force attacks",
    "rule_type": "threshold",
    "severity": "high",
    "category": "brute_force",
    "conditions": {
      "log_type": "authentication",
      "field_conditions": {
        "action": "failed"
      },
      "threshold": {
        "count": 5,
        "time_window": 300,
        "group_by": ["src_ip"]
      }
    },
    "is_enabled": true
  }'
```

### List Detection Rules

```bash
# Get all rules
curl "http://localhost:8000/api/v1/detection/rules"

# Get enabled rules only
curl "http://localhost:8000/api/v1/detection/rules?enabled_only=true"

# Filter by category
curl "http://localhost:8000/api/v1/detection/rules?category=brute_force"

# Filter by severity
curl "http://localhost:8000/api/v1/detection/rules?severity=high"
```

### Run Detection

```bash
# Run detection on specific parsed logs
curl -X POST "http://localhost:8000/api/v1/detection/run" \
  -H "Content-Type: application/json" \
  -d '{
    "parsed_log_ids": ["uuid1", "uuid2"],
    "rule_ids": ["rule-uuid1", "rule-uuid2"]
  }'

# Auto-detect on recent logs
curl -X POST "http://localhost:8000/api/v1/detection/auto-detect" \
  -d '{"hours": 2}'
```

### Get Detection Statistics

```bash
curl "http://localhost:8000/api/v1/detection/stats"
```

Response:
```json
{
  "total_rules": 25,
  "enabled_rules": 20,
  "disabled_rules": 5,
  "rules_by_category": {
    "brute_force": 5,
    "web_attack": 8,
    "malware": 4,
    "network_scan": 3,
    "privilege_escalation": 5
  },
  "rules_by_severity": {
    "low": 3,
    "medium": 8,
    "high": 12,
    "critical": 2
  },
  "detection_performance": {
    "avg_processing_time": 0.045,
    "rules_processed_24h": 15420,
    "alerts_generated_24h": 23
  }
}
```

## Best Practices

### Rule Design

1. **Start Conservative**: Begin with higher thresholds and adjust based on results
2. **Use Specific Conditions**: Avoid overly broad rules that generate false positives
3. **Layer Detection**: Use multiple rules to detect different aspects of threats
4. **Consider Context**: Include relevant context in alert data
5. **Regular Review**: Periodically review and update rules

### Performance Optimization

1. **Efficient Conditions**: Use specific log_type and field filters
2. **Reasonable Thresholds**: Avoid extremely low thresholds that trigger frequently
3. **Time Windows**: Use appropriate time windows for your environment
4. **Resource Monitoring**: Monitor CPU and memory usage during detection

### False Positive Reduction

1. **Whitelist Known Good**: Exclude known legitimate activities
2. **Business Context**: Consider business hours and normal operations
3. **Gradual Deployment**: Test rules in monitoring mode before enabling alerts
4. **Feedback Loop**: Use false positive feedback to improve rules

### Alert Quality

1. **Meaningful Names**: Use descriptive rule names
2. **Clear Descriptions**: Explain what the rule detects and why it matters
3. **Appropriate Severity**: Match severity to actual risk level
4. **Rich Context**: Include relevant fields in alert data

### Maintenance

1. **Version Control**: Track rule changes
2. **Documentation**: Document rule logic and purpose
3. **Regular Testing**: Test rules with new attack patterns
4. **Performance Monitoring**: Monitor rule performance and effectiveness

## Troubleshooting

### Common Issues

#### 1. Rules Not Triggering

**Symptoms**: Expected alerts not generated

**Solutions**:
- Verify log data contains expected fields
- Check rule conditions match actual log values
- Ensure rule is enabled
- Verify time windows are appropriate
- Check log parsing is working correctly

#### 2. Too Many False Positives

**Symptoms**: Excessive alerts for normal activity

**Solutions**:
- Increase thresholds
- Add more specific conditions
- Exclude known good sources
- Adjust time windows
- Add business context filters

#### 3. Performance Issues

**Symptoms**: Slow detection, high resource usage

**Solutions**:
- Optimize rule conditions
- Reduce detection frequency
- Use more specific log_type filters
- Adjust time windows
- Monitor resource usage

#### 4. Missing Context in Alerts

**Symptoms**: Alerts lack useful information

**Solutions**:
- Include relevant fields in conditions
- Ensure log parsing extracts needed data
- Add correlation with other log sources
- Include baseline information for anomalies

### Debug Mode

Enable debug logging for detection issues:

```bash
# Set environment variable
export LOG_LEVEL=DEBUG

# Check detection logs
docker logs siembox-backend | grep detection
```

### Rule Testing

Test individual rules before deployment:

```bash
# Disable rule initially
curl -X POST "http://localhost:8000/api/v1/detection/rules/{rule_id}/disable"

# Test with sample data
curl -X POST "http://localhost:8000/api/v1/detection/run" \
  -d '{"parsed_log_ids": ["test-log-id"], "rule_ids": ["rule-id"]}'

# Enable after testing
curl -X POST "http://localhost:8000/api/v1/detection/rules/{rule_id}/enable"
```

This comprehensive guide provides the foundation for creating effective detection rules in SIEM BOX. Remember to start with well-known attack patterns, test thoroughly, and continuously refine based on your environment's specific needs.