# SIEM BOX - Log Parsing Guide

This guide covers how to configure, create, and manage custom parsing rules in SIEM BOX. The parsing system transforms raw log data into structured, searchable information that can be used for detection and analysis.

## Table of Contents

1. [Overview](#overview)
2. [Parser Management Approach](#parser-management-approach)
3. [Parser Configuration](#parser-configuration)
4. [Creating Custom Parsers](#creating-custom-parsers)
5. [Pattern Matching](#pattern-matching)
6. [Field Extraction](#field-extraction)
7. [Severity Mapping](#severity-mapping)
8. [Testing Parsers](#testing-parsers)
9. [API Usage](#api-usage)
10. [Troubleshooting](#troubleshooting)
11. [Best Practices](#best-practices)

## Overview

The SIEM BOX parsing system processes raw log entries and extracts structured data using configurable parsers. Each parser is designed to handle specific log formats and sources. The system comes with 20+ pre-configured parsers for common log types and provides advanced YAML-based configuration for custom parsing needs.

### Key Components

- **Raw Logs**: Unprocessed log entries stored in the `raw_logs` table
- **Parsed Logs**: Structured data extracted from raw logs, stored in the `parsed_logs` table
- **Parsers**: Configuration files that define how to extract data from specific log formats
- **Field Mapping**: Rules for extracting and naming specific data fields
- **Severity Mapping**: Rules for determining log severity levels

### Supported Log Types

- **Syslog (RFC3164)**: Standard syslog format
- **Firewall Logs**: Unifi, OPNsense, pfSense
- **Authentication Logs**: SSH, PAM, Authentik
- **Web Server Logs**: Nginx, Apache
- **Container Logs**: Docker, Kubernetes
- **System Logs**: General system events

## Parser Management Approach

SIEM BOX provides two approaches for managing log parsers:

### 1. Pre-configured Parsers (Recommended)

The system includes 20+ production-ready parsers that handle the most common log formats:

- **Automatic Detection**: Parsers automatically match and process incoming logs
- **Zero Configuration**: Works out-of-the-box for standard log formats
- **Optimized Performance**: Pre-tuned patterns for maximum efficiency
- **Regular Updates**: Parsers are maintained and updated with new releases

**When to use**: For standard log sources like syslog, firewalls, web servers, and authentication systems.

### 2. Custom YAML Configuration (Advanced)

For specialized log formats or custom applications, you can create custom parsers using YAML configuration:

- **Full Control**: Define exact parsing patterns and field extraction
- **Complex Patterns**: Support for advanced regex patterns and conditional logic
- **Custom Fields**: Extract application-specific data fields
- **Severity Mapping**: Define custom severity level mappings

**When to use**: For proprietary applications, custom log formats, or when you need specific field extraction not covered by default parsers.

### Monitoring Parser Performance

Use the web interface to monitor parsing effectiveness:

1. Navigate to **Logs** → **Parsing Statistics**
2. Review parsing success rates by log type
3. Identify unparsed logs that may need custom parsers
4. Monitor performance metrics and processing times

## Parser Configuration

> **Note**: This section covers advanced YAML-based parser configuration. Most users will find the pre-configured parsers sufficient for their needs. Use the web interface to monitor parsing performance and identify if custom parsers are needed.

Parsers are defined in YAML configuration files located in [`backend/config/parsers/`](../../backend/config/parsers/). The main configuration file is [`default_parsers.yaml`](../../backend/config/parsers/default_parsers.yaml).

### When to Create Custom Parsers

Consider creating custom parsers when:

- **Unparsed Logs**: The web interface shows logs that aren't being parsed by existing parsers
- **Custom Applications**: You have proprietary applications with unique log formats
- **Specific Fields**: You need to extract fields not covered by default parsers
- **Performance Optimization**: You want to optimize parsing for high-volume, specific log types

### Checking Parser Effectiveness

Before creating custom parsers, use the web interface to:

1. **Review Parsing Statistics**: Check which log types have low parsing rates
2. **Examine Unparsed Logs**: Identify patterns in logs that aren't being processed
3. **Monitor Performance**: Ensure current parsers are meeting performance requirements

### Parser Structure

```yaml
parsers:
  - name: "parser_name"
    version: "1.0"
    log_type: "log_category"
    category: "security|system|network|web"
    description: "Human-readable description"
    patterns:
      - pattern: 'regex_pattern'
        fields: ["field1", "field2", "field3"]
        action: "optional_action_name"
    severity_mapping:
      "value": "severity_level"
    enabled: true
```

### Configuration Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Unique parser identifier |
| `version` | string | Yes | Parser version for tracking changes |
| `log_type` | string | Yes | Type of logs this parser handles |
| `category` | string | Yes | Log category (security, system, network, web) |
| `description` | string | Yes | Human-readable description |
| `patterns` | array | Yes | List of regex patterns and field mappings |
| `severity_mapping` | object | No | Maps extracted values to severity levels |
| `enabled` | boolean | Yes | Whether the parser is active |

## Creating Custom Parsers

### Step 1: Analyze Your Log Format

Before creating a parser, analyze your log format to identify:

1. **Consistent patterns** in the log structure
2. **Key fields** you want to extract (IP addresses, usernames, timestamps, etc.)
3. **Variable elements** that need flexible matching
4. **Severity indicators** in the logs

### Example Log Analysis

Let's analyze a custom application log:

```
2024-01-15 14:30:25 [INFO] user=john.doe ip=192.168.1.100 action=login status=success session=abc123
2024-01-15 14:31:02 [ERROR] user=jane.smith ip=10.0.0.50 action=file_access status=denied file=/etc/passwd
2024-01-15 14:31:15 [WARN] user=admin ip=172.16.0.10 action=config_change status=success module=firewall
```

### Step 2: Create the Parser Configuration

```yaml
parsers:
  - name: "custom_app_logs"
    version: "1.0"
    log_type: "application"
    category: "security"
    description: "Custom application security logs"
    patterns:
      - pattern: '^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+user=(\w+\.?\w*)\s+ip=(\d+\.\d+\.\d+\.\d+)\s+action=(\w+)\s+status=(\w+)(?:\s+session=(\w+))?(?:\s+file=([^\s]+))?(?:\s+module=(\w+))?'
        fields: ["timestamp", "level", "username", "src_ip", "action", "status", "session_id", "file_path", "module"]
    severity_mapping:
      "INFO": "info"
      "WARN": "warning"
      "ERROR": "error"
      "CRITICAL": "critical"
    enabled: true
```

### Step 3: Test the Parser

Use the parsing API to test your new parser:

```bash
# Test parsing with specific parser
curl -X POST "http://localhost:8000/api/v1/parsing/parse" \
  -H "Content-Type: application/json" \
  -d '{
    "raw_log_ids": ["your-log-id"],
    "parser_name": "custom_app_logs"
  }'
```

### Step 4: Deploy the Parser

1. Add your parser configuration to the YAML file
2. Restart the SIEM BOX backend service
3. Verify the parser is loaded using the API

```bash
# Check available parsers
curl "http://localhost:8000/api/v1/parsing/parsers"
```

## Pattern Matching

SIEM BOX uses Python regular expressions for pattern matching. Understanding regex is crucial for creating effective parsers.

### Common Regex Patterns

| Pattern | Description | Example |
|---------|-------------|---------|
| `\d+` | One or more digits | `123`, `4567` |
| `\d{1,3}` | 1 to 3 digits | `1`, `12`, `123` |
| `\w+` | One or more word characters | `username`, `file123` |
| `\S+` | One or more non-whitespace | `192.168.1.1`, `filename.txt` |
| `[^\s]+` | One or more non-space | Similar to `\S+` |
| `.*` | Any characters (greedy) | Matches everything |
| `.*?` | Any characters (non-greedy) | Matches minimally |
| `(?:...)` | Non-capturing group | Groups without creating a field |
| `(...)?` | Optional capturing group | May or may not be present |

### IP Address Pattern

```regex
(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})
```

### Timestamp Patterns

```regex
# ISO 8601: 2024-01-15T14:30:25Z
(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)

# Syslog: Jan 15 14:30:25
(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})

# Custom: 2024-01-15 14:30:25
(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})
```

### Username Patterns

```regex
# Simple username
(\w+)

# Email-style username
([\w\.-]+@[\w\.-]+)

# Domain\username
([\w\\]+\\[\w]+)
```

## Field Extraction

Fields are extracted based on the order of capturing groups in your regex pattern. Each capturing group `(...)` corresponds to a field in the `fields` array.

### Field Naming Conventions

Use consistent field names across parsers:

| Field Type | Recommended Names |
|------------|-------------------|
| IP Addresses | `src_ip`, `dst_ip`, `client_ip` |
| Ports | `src_port`, `dst_port` |
| Users | `username`, `user`, `target_user` |
| Actions | `action`, `command`, `method` |
| Status | `status`, `result`, `outcome` |
| Files | `file_path`, `filename` |
| Protocols | `protocol` |
| Timestamps | `timestamp`, `event_time` |

### Example Field Extraction

```yaml
patterns:
  - pattern: '^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\w+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\w+)\s+(.*)$'
    fields: ["timestamp", "hostname", "src_ip", "protocol", "message"]
```

This pattern extracts:
1. `timestamp`: `2024-01-15 14:30:25`
2. `hostname`: `server01`
3. `src_ip`: `192.168.1.100`
4. `protocol`: `TCP`
5. `message`: `Connection established`

## Severity Mapping

Severity mapping translates extracted values into standardized severity levels.

### Standard Severity Levels

| Level | Description | Use Cases |
|-------|-------------|-----------|
| `debug` | Detailed diagnostic information | Debug logs, trace information |
| `info` | General information | Normal operations, status updates |
| `warning` | Warning conditions | Non-critical issues, potential problems |
| `error` | Error conditions | Application errors, failed operations |
| `critical` | Critical conditions | System failures, security breaches |

### Mapping Examples

```yaml
severity_mapping:
  # HTTP status codes
  "200": "info"
  "201": "info"
  "400": "warning"
  "401": "warning"
  "403": "warning"
  "404": "warning"
  "500": "error"
  "502": "error"
  "503": "error"
  
  # Log levels
  "DEBUG": "debug"
  "INFO": "info"
  "WARN": "warning"
  "WARNING": "warning"
  "ERROR": "error"
  "FATAL": "critical"
  "CRITICAL": "critical"
  
  # Authentication results
  "success": "info"
  "failed": "warning"
  "blocked": "warning"
  "denied": "warning"
```

## Testing Parsers

### Web Interface Testing (Recommended)

The easiest way to test and validate parsers is through the web interface:

1. **Monitor Parsing Statistics**:
   - Navigate to **Logs** → **Parsing Statistics**
   - Review success rates for different log types
   - Identify logs that aren't being parsed

2. **Examine Parsed Results**:
   - Go to **Logs** → **Parsed Logs**
   - Filter by log type or time range
   - Verify that fields are extracted correctly
   - Check severity mapping accuracy

3. **Review Unparsed Logs**:
   - Navigate to **Logs** → **Raw Logs**
   - Filter for unparsed entries
   - Analyze patterns that need custom parsers

### API Testing Workflow (Advanced)

For programmatic testing and automation:

```bash
# 1. Ingest a test log
curl -X POST "http://localhost:8000/api/v1/logs/ingest" \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2024-01-15T14:30:25Z",
    "hostname": "test-server",
    "app_name": "test-app",
    "raw_message": "2024-01-15 14:30:25 [INFO] user=john.doe ip=192.168.1.100 action=login status=success"
  }'

# 2. Get the log ID from the response and test parsing
curl -X POST "http://localhost:8000/api/v1/parsing/parse" \
  -H "Content-Type: application/json" \
  -d '{
    "raw_log_ids": ["LOG_ID_HERE"],
    "parser_name": "custom_app_logs"
  }'

# 3. Check parsed results
curl "http://localhost:8000/api/v1/parsing/parsed?limit=1"
```

### Validation Checklist

**Web Interface Validation**:
- [ ] Parsing statistics show improved success rates
- [ ] Parsed logs display all expected fields
- [ ] Field values are correct and properly formatted
- [ ] Severity levels are mapped correctly
- [ ] No increase in unparsed log volume

**Technical Validation**:
- [ ] Parser handles edge cases (missing fields, malformed data)
- [ ] Performance is acceptable for expected log volume
- [ ] Regex patterns are optimized and don't cause backtracking
- [ ] Parser configuration follows naming conventions

## API Usage

### Available Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/parsing/parse` | POST | Parse specific raw logs |
| `/api/v1/parsing/auto-parse` | POST | Auto-parse recent unparsed logs |
| `/api/v1/parsing/parsed` | GET | Retrieve parsed logs |
| `/api/v1/parsing/unparsed` | GET | Get unparsed raw logs |
| `/api/v1/parsing/parsers` | GET | List available parsers |
| `/api/v1/parsing/stats` | GET | Get parsing statistics |

### Parse Specific Logs

```bash
curl -X POST "http://localhost:8000/api/v1/parsing/parse" \
  -H "Content-Type: application/json" \
  -d '{
    "raw_log_ids": ["uuid1", "uuid2"],
    "parser_name": "optional_specific_parser"
  }'
```

### Auto-Parse Recent Logs

```bash
curl -X POST "http://localhost:8000/api/v1/parsing/auto-parse" \
  -H "Content-Type: application/json" \
  -d '{
    "hours": 1
  }'
```

### Get Parsing Statistics

```bash
curl "http://localhost:8000/api/v1/parsing/stats"
```

Response:
```json
{
  "total_raw_logs": 1500,
  "total_parsed_logs": 1200,
  "parsing_rate": 80.0,
  "parser_stats": {
    "syslog_rfc3164": {
      "processed": 800,
      "success_rate": 95.5
    },
    "unifi_firewall": {
      "processed": 400,
      "success_rate": 88.2
    }
  }
}
```

## Troubleshooting

### Web Interface Diagnostics

Start troubleshooting with the web interface:

1. **Check Parsing Statistics**:
   - Low success rates indicate parser issues
   - High unparsed log counts suggest missing parsers
   - Performance metrics show bottlenecks

2. **Examine Sample Logs**:
   - Review unparsed logs for patterns
   - Compare parsed vs. unparsed log formats
   - Identify common characteristics in failed parsing

3. **Monitor Real-time Processing**:
   - Watch parsing rates during log ingestion
   - Identify specific log sources with issues
   - Track parsing performance over time

### Common Issues

#### 1. Parser Not Matching Logs

**Symptoms**: Logs remain unparsed, no fields extracted, visible in web interface unparsed logs

**Solutions**:
- Review unparsed logs in the web interface to understand the format
- Verify regex pattern with online regex testers
- Check for special characters that need escaping
- Ensure pattern matches the entire log format
- Test with actual log samples from the interface

#### 2. Incorrect Field Extraction

**Symptoms**: Fields contain wrong data or are empty

**Solutions**:
- Count capturing groups in regex
- Verify field array matches group count
- Check for optional groups that might not match
- Use non-capturing groups `(?:...)` for grouping without extraction

#### 3. Performance Issues

**Symptoms**: Slow parsing, high CPU usage

**Solutions**:
- Optimize regex patterns (avoid excessive backtracking)
- Use more specific patterns instead of greedy matching
- Consider splitting complex patterns into multiple simpler ones
- Monitor parser statistics for bottlenecks

#### 4. Severity Mapping Not Working

**Symptoms**: All logs have same severity or no severity

**Solutions**:
- Verify extracted field values match mapping keys
- Check for case sensitivity issues
- Ensure severity field is being extracted correctly
- Add debug logging to see extracted values

### Debug Mode

Enable debug logging to troubleshoot parsing issues:

```bash
# Set environment variable
export LOG_LEVEL=DEBUG

# Or modify backend configuration
# In backend/.env:
LOG_LEVEL=DEBUG
```

### Log Analysis

Check backend logs for parsing errors:

```bash
# View backend logs
docker logs siembox-backend

# Follow logs in real-time
docker logs -f siembox-backend
```

## Best Practices

### Monitoring and Maintenance

1. **Regular Web Interface Reviews**:
   - Check parsing statistics weekly
   - Monitor for declining success rates
   - Review unparsed logs for new patterns
   - Track performance trends over time

2. **Proactive Monitoring**:
   - Set up alerts for parsing rate drops
   - Monitor log volume changes
   - Watch for new log sources
   - Track parser performance metrics

### Parser Design

1. **Start Simple**: Begin with basic patterns and add complexity gradually
2. **Use Specific Patterns**: Avoid overly broad regex that might match unintended logs
3. **Handle Variations**: Account for different log formats from the same source
4. **Test Thoroughly**: Use diverse log samples for testing
5. **Document Patterns**: Add comments explaining complex regex patterns
6. **Validate with Web Interface**: Always verify parser effectiveness through the UI

### Performance Optimization

1. **Anchor Patterns**: Use `^` and `$` to anchor patterns when possible
2. **Avoid Backtracking**: Use possessive quantifiers and atomic groups
3. **Order Patterns**: Put most common patterns first
4. **Limit Scope**: Use specific log_type filters to reduce processing
5. **Monitor Impact**: Use web interface metrics to measure performance changes

### Maintenance

1. **Version Control**: Track parser changes with version numbers
2. **Monitor Performance**: Regularly check parsing statistics via web interface
3. **Update Patterns**: Adapt to changes in log formats based on unparsed log analysis
4. **Backup Configurations**: Keep backups of working parser configurations
5. **Document Changes**: Record why parsers were modified and their impact

### Security Considerations

1. **Validate Input**: Ensure patterns don't expose sensitive data
2. **Sanitize Fields**: Clean extracted data before storage
3. **Limit Complexity**: Avoid regex patterns that could cause DoS
4. **Access Control**: Restrict parser modification to authorized users
5. **Audit Changes**: Track who modifies parsers and when

### Example: Complete Parser Development

Let's create a parser for a custom web application:

#### 1. Log Sample Analysis

```
[2024-01-15 14:30:25] INFO 192.168.1.100 GET /api/users/123 200 0.045s user_id=456 session=abc123
[2024-01-15 14:30:26] WARN 10.0.0.50 POST /api/login 401 0.012s user_id=null session=null
[2024-01-15 14:30:27] ERROR 172.16.0.10 DELETE /api/admin/users 403 0.003s user_id=789 session=def456
```

#### 2. Parser Configuration

```yaml
parsers:
  - name: "webapp_api_logs"
    version: "1.0"
    log_type: "web_api"
    category: "web"
    description: "Custom web application API logs"
    patterns:
      - pattern: '^\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]\s+(\w+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\w+)\s+([^\s]+)\s+(\d+)\s+([\d\.]+)s\s+user_id=(\w+|null)\s+session=(\w+|null)$'
        fields: ["timestamp", "level", "client_ip", "method", "endpoint", "status_code", "response_time", "user_id", "session_id"]
    severity_mapping:
      "INFO": "info"
      "WARN": "warning"
      "ERROR": "error"
      "CRITICAL": "critical"
      "200": "info"
      "201": "info"
      "400": "warning"
      "401": "warning"
      "403": "warning"
      "404": "warning"
      "500": "error"
    enabled: true
```

#### 3. Testing and Validation

```bash
# Test the parser
curl -X POST "http://localhost:8000/api/v1/parsing/parse" \
  -H "Content-Type: application/json" \
  -d '{
    "raw_log_ids": ["test-log-id"],
    "parser_name": "webapp_api_logs"
  }'

# Verify results
curl "http://localhost:8000/api/v1/parsing/parsed?log_type=web_api&limit=5"
```

This comprehensive guide should help you create, test, and maintain effective log parsers for SIEM BOX. Remember to start simple, test thoroughly, and iterate based on real-world log data.