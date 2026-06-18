# Application-Specific Parser Documentation

This directory contains detailed parser documentation for specific applications commonly used in homelab environments.

## Contents

### [AUTHENTICATION-PARSERS.md](./AUTHENTICATION-PARSERS.md)
Parsers for authentication and identity services:
- **Authelia**: Access log parsing and authentication events
- **Authentik**: Audit log parsing and user activity
- **Keycloak**: Event log parsing and identity management
- Field extraction patterns for each service
- Integration with authentication detection rules

### [CRITICAL-APPLICATION-PARSERS.md](./CRITICAL-APPLICATION-PARSERS.md)
Parsers for critical infrastructure applications:
- **Nextcloud**: Access and error log parsing
- **Pi-hole**: DNS query log parsing and blocking events
- **Additional critical services**
- Security event detection
- Performance monitoring patterns

### [REVERSE-PROXY-PARSERS.md](./REVERSE-PROXY-PARSERS.md)
Parsers for reverse proxy and web gateway services:
- **Nginx Proxy Manager**: Access and error log parsing
- **Traefik**: JSON access log parsing
- **Caddy**: JSON access log parsing
- **Standard Nginx**: Access and error log formats
- HTTP request analysis
- Security event detection (attacks, scans, etc.)

## Parser Architecture

### Parser Types

SIEMBox supports three parser types:

1. **Regex Parsers**: Pattern matching using regular expressions
2. **Grok Parsers**: Logstash-style grok patterns
3. **JSON Parsers**: Direct JSON parsing for structured logs

### Parser Priority

Parsers are evaluated in priority order (highest to lowest):
- **50-60**: Specialized application parsers
- **40-49**: Reverse proxy parsers
- **20-39**: Authentication and infrastructure parsers
- **10-19**: Generic system parsers
- **1-9**: Fallback parsers

### Field Extraction

Common extracted fields:
- `timestamp`: Event timestamp
- `source_ip`: Client/source IP address
- `dest_ip`: Destination IP address
- `http_method`: HTTP request method (GET, POST, etc.)
- `http_uri`: Requested URI/path
- `http_status`: HTTP response status code
- `user_agent`: Client user agent string
- `username`: Authenticated username
- `event_type`: Categorized event type
- `severity`: Log severity level

## Using These Parsers

### View in Web Interface
1. Navigate to http://your-siembox:8420
2. Go to **Parsers** page
3. Search for the application name
4. View parser details, test patterns, and manage priority

### Test Parser Matching
```bash
# Send a test log via syslog
echo "your test log message" | nc -u your-siembox 514

# Check if it was parsed
curl http://your-siembox:8421/api/logs?limit=1
```

### Deploy Custom Parsers
See [../reference/PARSERS.md](../reference/PARSERS.md) for:
- Parser syntax reference
- Creating custom parsers
- Testing and validation
- Community-contributed parsers

## Integration with Detection Rules

These parsers extract fields used by detection rules in [../reference/RULES.md](../reference/RULES.md):

### Authentication Parsers → AUTH Rules
- AUTH-001: SSH Brute Force Detection
- AUTH-002: Brute Force Success After Failures
- AUTH-007: Authentication from Suspicious Countries
- AUTH-009: Impossible Travel Detection

### Reverse Proxy Parsers → PROXY Rules
- PROXY-001: SQL Injection Attempt
- PROXY-002: XSS Attack Pattern
- PROXY-003: Path Traversal Attack
- PROXY-004: Command Injection Attempt
- PROXY-005: Proxy Error Rate Spike

### Application Parsers → APP Rules
- APP-001: File Upload Attack
- APP-002: Sensitive File Access
- APP-003: API Rate Limit Exceeded
- APP-004: Application Error Spike

## Parser Development Workflow

1. **Identify Log Format**: Collect sample logs from the application
2. **Design Field Extraction**: Determine which fields to extract
3. **Write Parser**: Create regex/grok/JSON parser
4. **Test Locally**: Use test logs to validate extraction
5. **Deploy**: Add parser via UI or API
6. **Monitor**: Check parsing success rate and adjust
7. **Contribute**: Share parser with community (see CONTRIBUTING.md)

## Related Documentation

- **Main Parser Reference**: [../reference/PARSERS.md](../reference/PARSERS.md)
- **Detection Rules**: [../reference/RULES.md](../reference/RULES.md)
- **API Documentation**: [../../API.md](../../API.md)
- **Troubleshooting**: [../operations/TROUBLESHOOTING.md](../operations/TROUBLESHOOTING.md)

## Contributing

Have a parser for an application not listed here? Please contribute!
See [CONTRIBUTING.md](../../CONTRIBUTING.md) for submission guidelines.
