# Reverse Proxy Parsers for SIEMBox

**Version:** 1.0
**Date:** 2025-12-03
**Purpose:** Critical reverse proxy parsers for homelab SIEM deployments

---

## Overview

### Why Reverse Proxy Parsers Are Critical

Based on homelab survey data, **90%+ of homelabbers use reverse proxies** as their primary gateway to self-hosted services. This makes reverse proxies:

1. **The #1 Attack Surface** - Every external request passes through your reverse proxy
2. **The First Line of Defense** - Detecting attacks here prevents compromise of backend services
3. **High-Value Target** - Attackers scan for vulnerable proxies constantly
4. **Single Point of Failure** - Proxy compromise can expose ALL backend services

**Bottom Line:** If you monitor nothing else, monitor your reverse proxy. These 4 parsers are non-negotiable for homelab security.

### Threat Context

Reverse proxies face constant attacks:
- **SQL Injection** - Database exploitation via web parameters
- **Command Injection** - OS command execution via input fields
- **Path Traversal** - Accessing files outside web root
- **Directory Scanning** - Automated enumeration of endpoints
- **Brute Force Authentication** - Credential guessing attacks
- **Application Exploitation** - CVE-based attacks on backend apps

### What These Parsers Enable

With these parsers deployed, you can detect:
- SQL injection attempts in real-time
- Command injection strings
- Path traversal attacks
- Directory scanning (404 patterns)
- Suspicious user agents (sqlmap, nikto, etc.)
- Brute force authentication attempts
- Excessive request rates (DoS patterns)
- Server errors indicating exploitation

---

## Table of Contents

1. [Parser 1: NGINX Proxy Manager](#parser-1-nginx-proxy-manager)
2. [Parser 2: Traefik](#parser-2-traefik)
3. [Parser 3: Caddy](#parser-3-caddy)
4. [Parser 4: Standard NGINX](#parser-4-standard-nginx)
5. [Appendix A: Common Patterns](#appendix-a-common-patterns)
6. [Appendix B: Installation Guide](#appendix-b-installation-guide)
7. [Appendix C: Troubleshooting](#appendix-c-troubleshooting)

---

## Parser 1: NGINX Proxy Manager

### Overview

**Priority:** HIGHEST (842 users - most popular reverse proxy in homelabs)

**About NGINX Proxy Manager:**
NGINX Proxy Manager provides a web UI for managing NGINX reverse proxy configurations. It's the most popular choice for homelabbers due to its ease of use, automatic SSL certificate management, and simple interface. However, this popularity makes it a high-value target for attackers.

**Security Relevance:**
- Exposes multiple backend services through single entry point
- Common target for automated vulnerability scanners
- Access logs contain rich attack indicators (SQL injection, path traversal, etc.)
- Error logs reveal backend connection issues and potential exploits
- Misconfigurations can expose backend services directly

**Default Log Locations:**
- Access logs: `/data/logs/proxy-host-*.log`
- Error logs: `/data/logs/error.log`
- Format: Combined NGINX format with additional fields

### Log Format Examples

**Access Log (Successful Request):**
```
192.168.1.100 - user@example.com [03/Dec/2025:12:34:56 +0000] "GET /api/users HTTP/1.1" 200 1234 "https://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

**Access Log (Failed Authentication):**
```
203.0.113.50 - - [03/Dec/2025:12:35:10 +0000] "POST /login HTTP/1.1" 401 187 "https://example.com/login" "curl/7.68.0"
```

**Access Log (SQL Injection Attempt):**
```
198.51.100.25 - - [03/Dec/2025:12:36:22 +0000] "GET /api/search?q=test' OR '1'='1 HTTP/1.1" 400 0 "-" "sqlmap/1.5.2"
```

**Access Log (Path Traversal Attempt):**
```
198.51.100.30 - - [03/Dec/2025:12:37:45 +0000] "GET /../../../etc/passwd HTTP/1.1" 404 162 "-" "Mozilla/5.0"
```

**Error Log (Backend Connection Failed):**
```
2025/12/03 12:34:56 [error] 123#123: *456 connect() failed (111: Connection refused) while connecting to upstream, client: 192.168.1.100, server: example.com, request: "GET /api/health HTTP/1.1", upstream: "http://10.0.0.50:3000/api/health"
```

### Parser Configuration

**Parser 1A: NGINX Proxy Manager Access Logs**

```json
{
  "name": "nginx-proxy-manager-access",
  "description": "Parses NGINX Proxy Manager access logs for security monitoring",
  "enabled": true,
  "priority": 60,
  "parser_type": "regex",
  "pattern": "^(?P<client_ip>[\\d.]+)\\s+-\\s+(?P<username>\\S+)\\s+\\[(?P<timestamp>[^\\]]+)\\]\\s+\"(?P<http_method>\\S+)\\s+(?P<request_uri>\\S+)\\s+(?P<http_version>[^\"]+)\"\\s+(?P<http_status>\\d+)\\s+(?P<bytes_sent>\\d+)\\s+\"(?P<referrer>[^\"]*)\"\\s+\"(?P<user_agent>[^\"]+)\"",
  "field_mappings": {
    "client_ip": "client_ip",
    "username": "username",
    "timestamp": "timestamp",
    "http_method": "http_method",
    "request_uri": "request_uri",
    "http_version": "http_version",
    "http_status": "http_status",
    "bytes_sent": "bytes_sent",
    "referrer": "referrer",
    "user_agent": "user_agent"
  },
  "test_samples": [
    {
      "raw_message": "192.168.1.100 - admin@example.com [03/Dec/2025:12:34:56 +0000] \"GET /api/users HTTP/1.1\" 200 1234 \"https://example.com/\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\"",
      "expected_fields": {
        "client_ip": "192.168.1.100",
        "username": "admin@example.com",
        "timestamp": "03/Dec/2025:12:34:56 +0000",
        "http_method": "GET",
        "request_uri": "/api/users",
        "http_version": "HTTP/1.1",
        "http_status": "200",
        "bytes_sent": "1234",
        "referrer": "https://example.com/",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
      }
    },
    {
      "raw_message": "203.0.113.50 - - [03/Dec/2025:12:35:10 +0000] \"POST /login HTTP/1.1\" 401 187 \"https://example.com/login\" \"curl/7.68.0\"",
      "expected_fields": {
        "client_ip": "203.0.113.50",
        "username": "-",
        "timestamp": "03/Dec/2025:12:35:10 +0000",
        "http_method": "POST",
        "request_uri": "/login",
        "http_version": "HTTP/1.1",
        "http_status": "401",
        "bytes_sent": "187",
        "referrer": "https://example.com/login",
        "user_agent": "curl/7.68.0"
      }
    },
    {
      "raw_message": "198.51.100.25 - - [03/Dec/2025:12:36:22 +0000] \"GET /api/search?q=test' OR '1'='1 HTTP/1.1\" 400 0 \"-\" \"sqlmap/1.5.2\"",
      "expected_fields": {
        "client_ip": "198.51.100.25",
        "username": "-",
        "timestamp": "03/Dec/2025:12:36:22 +0000",
        "http_method": "GET",
        "request_uri": "/api/search?q=test' OR '1'='1",
        "http_version": "HTTP/1.1",
        "http_status": "400",
        "bytes_sent": "0",
        "referrer": "-",
        "user_agent": "sqlmap/1.5.2"
      }
    },
    {
      "raw_message": "198.51.100.30 - - [03/Dec/2025:12:37:45 +0000] \"GET /../../../etc/passwd HTTP/1.1\" 404 162 \"-\" \"Mozilla/5.0\"",
      "expected_fields": {
        "client_ip": "198.51.100.30",
        "username": "-",
        "timestamp": "03/Dec/2025:12:37:45 +0000",
        "http_method": "GET",
        "request_uri": "/../../../etc/passwd",
        "http_version": "HTTP/1.1",
        "http_status": "404",
        "bytes_sent": "162",
        "referrer": "-",
        "user_agent": "Mozilla/5.0"
      }
    },
    {
      "raw_message": "192.168.1.150 - user@domain.com [03/Dec/2025:14:22:33 +0000] \"POST /api/upload HTTP/2.0\" 500 2048 \"https://app.example.com/upload\" \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)\"",
      "expected_fields": {
        "client_ip": "192.168.1.150",
        "username": "user@domain.com",
        "timestamp": "03/Dec/2025:14:22:33 +0000",
        "http_method": "POST",
        "request_uri": "/api/upload",
        "http_version": "HTTP/2.0",
        "http_status": "500",
        "bytes_sent": "2048",
        "referrer": "https://app.example.com/upload",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
      }
    }
  ]
}
```

**Parser 1B: NGINX Proxy Manager Error Logs**

```json
{
  "name": "nginx-proxy-manager-error",
  "description": "Parses NGINX Proxy Manager error logs for backend issues and exploitation attempts",
  "enabled": true,
  "priority": 61,
  "parser_type": "regex",
  "pattern": "^(?P<timestamp>\\d{4}/\\d{2}/\\d{2}\\s+\\d{2}:\\d{2}:\\d{2})\\s+\\[(?P<severity>\\w+)\\]\\s+(?P<pid>\\d+)#(?P<tid>\\d+):\\s+\\*(?P<connection_id>\\d+)\\s+(?P<error_message>.+?),\\s+client:\\s+(?P<client_ip>[\\d.]+),\\s+server:\\s+(?P<server_name>\\S+),\\s+request:\\s+\"(?P<request>[^\"]+)\"(?:,\\s+upstream:\\s+\"(?P<upstream>[^\"]+)\")?",
  "field_mappings": {
    "timestamp": "timestamp",
    "severity": "severity",
    "pid": "pid",
    "tid": "tid",
    "connection_id": "connection_id",
    "error_message": "error_message",
    "client_ip": "client_ip",
    "server_name": "server_name",
    "request": "request",
    "upstream": "upstream_host"
  },
  "test_samples": [
    {
      "raw_message": "2025/12/03 12:34:56 [error] 123#123: *456 connect() failed (111: Connection refused) while connecting to upstream, client: 192.168.1.100, server: example.com, request: \"GET /api/health HTTP/1.1\", upstream: \"http://10.0.0.50:3000/api/health\"",
      "expected_fields": {
        "timestamp": "2025/12/03 12:34:56",
        "severity": "error",
        "pid": "123",
        "tid": "123",
        "connection_id": "456",
        "error_message": "connect() failed (111: Connection refused) while connecting to upstream",
        "client_ip": "192.168.1.100",
        "server_name": "example.com",
        "request": "GET /api/health HTTP/1.1",
        "upstream_host": "http://10.0.0.50:3000/api/health"
      }
    },
    {
      "raw_message": "2025/12/03 13:15:22 [warn] 124#124: *789 upstream timed out (110: Connection timed out) while reading response header from upstream, client: 192.168.1.105, server: api.example.com, request: \"POST /api/process HTTP/1.1\", upstream: \"http://10.0.0.55:8080/api/process\"",
      "expected_fields": {
        "timestamp": "2025/12/03 13:15:22",
        "severity": "warn",
        "pid": "124",
        "tid": "124",
        "connection_id": "789",
        "error_message": "upstream timed out (110: Connection timed out) while reading response header from upstream",
        "client_ip": "192.168.1.105",
        "server_name": "api.example.com",
        "request": "POST /api/process HTTP/1.1",
        "upstream_host": "http://10.0.0.55:8080/api/process"
      }
    },
    {
      "raw_message": "2025/12/03 14:45:10 [error] 125#125: *1234 recv() failed (104: Connection reset by peer) while reading response header from upstream, client: 203.0.113.75, server: app.example.com, request: \"GET /admin HTTP/1.1\"",
      "expected_fields": {
        "timestamp": "2025/12/03 14:45:10",
        "severity": "error",
        "pid": "125",
        "tid": "125",
        "connection_id": "1234",
        "error_message": "recv() failed (104: Connection reset by peer) while reading response header from upstream",
        "client_ip": "203.0.113.75",
        "server_name": "app.example.com",
        "request": "GET /admin HTTP/1.1",
        "upstream_host": null
      }
    }
  ]
}
```

### Fields Extracted

| Field Name | Type | Description | Security Value |
|-----------|------|-------------|----------------|
| `client_ip` | string | Client IP address | Track attacker IPs, geo-blocking |
| `username` | string | Authenticated username (or `-`) | Identify compromised accounts |
| `timestamp` | string | Request timestamp | Correlate attack timelines |
| `http_method` | string | HTTP method (GET/POST/etc) | Detect method abuse |
| `request_uri` | string | Full request URI with parameters | SQL injection, path traversal detection |
| `http_version` | string | HTTP protocol version | Identify legacy client attacks |
| `http_status` | integer | HTTP response status code | 5xx = potential exploit success |
| `bytes_sent` | integer | Response size in bytes | Data exfiltration detection |
| `referrer` | string | HTTP referrer header | CSRF detection, bot identification |
| `user_agent` | string | Client user agent string | Scanner detection (sqlmap, nikto) |
| `severity` | string | Log severity (error/warn) | Error log only - issue priority |
| `error_message` | string | Full error description | Backend connectivity, exploits |
| `upstream_host` | string | Backend server address | Backend compromise tracking |

### Installation

**SQL INSERT Statement (Access Logs):**

```sql
INSERT INTO parsers (name, description, enabled, priority, parser_type, pattern, field_mappings, test_samples, created_at, updated_at)
VALUES (
  'nginx-proxy-manager-access',
  'Parses NGINX Proxy Manager access logs for security monitoring',
  true,
  60,
  'regex',
  '^(?P<client_ip>[\d.]+)\s+-\s+(?P<username>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<http_method>\S+)\s+(?P<request_uri>\S+)\s+(?P<http_version>[^"]+)"\s+(?P<http_status>\d+)\s+(?P<bytes_sent>\d+)\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]+)"',
  '{"client_ip":"client_ip","username":"username","timestamp":"timestamp","http_method":"http_method","request_uri":"request_uri","http_version":"http_version","http_status":"http_status","bytes_sent":"bytes_sent","referrer":"referrer","user_agent":"user_agent"}',
  '[{"raw_message":"192.168.1.100 - admin@example.com [03/Dec/2025:12:34:56 +0000] \"GET /api/users HTTP/1.1\" 200 1234 \"https://example.com/\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\"","expected_fields":{"client_ip":"192.168.1.100","username":"admin@example.com","timestamp":"03/Dec/2025:12:34:56 +0000","http_method":"GET","request_uri":"/api/users","http_version":"HTTP/1.1","http_status":"200","bytes_sent":"1234","referrer":"https://example.com/","user_agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}}]',
  NOW(),
  NOW()
);
```

**SQL INSERT Statement (Error Logs):**

```sql
INSERT INTO parsers (name, description, enabled, priority, parser_type, pattern, field_mappings, test_samples, created_at, updated_at)
VALUES (
  'nginx-proxy-manager-error',
  'Parses NGINX Proxy Manager error logs for backend issues and exploitation attempts',
  true,
  61,
  'regex',
  '^(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?P<severity>\w+)\]\s+(?P<pid>\d+)#(?P<tid>\d+):\s+\*(?P<connection_id>\d+)\s+(?P<error_message>.+?),\s+client:\s+(?P<client_ip>[\d.]+),\s+server:\s+(?P<server_name>\S+),\s+request:\s+"(?P<request>[^"]+)"(?:,\s+upstream:\s+"(?P<upstream>[^"]+)")?',
  '{"timestamp":"timestamp","severity":"severity","pid":"pid","tid":"tid","connection_id":"connection_id","error_message":"error_message","client_ip":"client_ip","server_name":"server_name","request":"request","upstream":"upstream_host"}',
  '[{"raw_message":"2025/12/03 12:34:56 [error] 123#123: *456 connect() failed (111: Connection refused) while connecting to upstream, client: 192.168.1.100, server: example.com, request: \"GET /api/health HTTP/1.1\", upstream: \"http://10.0.0.50:3000/api/health\"","expected_fields":{"timestamp":"2025/12/03 12:34:56","severity":"error","client_ip":"192.168.1.100","server_name":"example.com","request":"GET /api/health HTTP/1.1","upstream_host":"http://10.0.0.50:3000/api/health"}}]',
  NOW(),
  NOW()
);
```

### Testing

**Step 1: Generate Test Traffic**

```bash
# Normal request
curl -H "User-Agent: Mozilla/5.0" https://your-proxy.com/api/test

# Failed authentication
curl -X POST https://your-proxy.com/login -d "user=test&pass=wrong"

# SQL injection test (SAFE - will be blocked)
curl "https://your-proxy.com/search?q=test%27+OR+%271%27%3D%271"
```

**Step 2: Verify Logs in SIEMBox**

Navigate to Logs page and search for:
- Tag: `nginx-proxy-manager`
- Verify fields are extracted: `client_ip`, `http_status`, `request_uri`, etc.

**Step 3: Verify Parser Test**

In Parsers page:
1. Click on `nginx-proxy-manager-access`
2. Click "Test Parse"
3. Use a real log line from `/data/logs/proxy-host-*.log`
4. Verify all fields extract correctly

### Troubleshooting

**Problem: Logs not appearing in SIEMBox**

1. Verify log file permissions:
   ```bash
   ls -la /data/logs/proxy-host-*.log
   ```

2. Check log shipper can read logs:
   ```bash
   docker exec siembox-log-shipper ls -la /data/logs/
   ```

3. Verify log path in shipper configuration

**Problem: Parser not matching**

1. Get actual log line:
   ```bash
   tail -1 /data/logs/proxy-host-1.log
   ```

2. Check log format matches expected format
3. Test regex on regex101.com
4. Verify NGINX Proxy Manager version (log format may vary)

**Problem: Missing fields**

1. Verify log uses combined format
2. Check for custom NGINX Proxy Manager log formats
3. Some fields optional (username may be `-`)
4. Error logs may not have all fields (upstream is optional)

---

## Parser 2: Traefik

### Overview

**Priority:** HIGH (751 users - second most popular)

**About Traefik:**
Traefik is a modern, cloud-native reverse proxy and load balancer. It automatically discovers services, handles SSL certificates, and provides excellent observability through structured JSON logs. Popular in Docker and Kubernetes environments.

**Security Relevance:**
- JSON logs provide rich, structured data
- Automatic service discovery can be exploited
- Middleware can be bypassed if misconfigured
- Multiple protocol support (HTTP, TCP, UDP) increases attack surface
- Excellent for detecting application-layer attacks

**Default Log Locations:**
- Access logs: `/var/log/traefik/access.log` (or Docker stdout)
- Format: JSON (structured logging)

### Log Format Examples

**Successful Request:**
```json
{"ClientAddr":"192.168.1.100:54321","ClientHost":"192.168.1.100","ClientPort":"54321","ClientUsername":"admin","DownstreamContentSize":1234,"DownstreamStatus":200,"Duration":15000000,"OriginContentSize":1234,"OriginDuration":12000000,"OriginStatus":200,"Overhead":3000000,"RequestAddr":"example.com","RequestContentSize":0,"RequestCount":42,"RequestHost":"example.com","RequestMethod":"GET","RequestPath":"/api/users","RequestPort":"443","RequestProtocol":"HTTP/1.1","RequestScheme":"https","RetryAttempts":0,"RouterName":"api@docker","ServiceAddr":"10.0.0.50:3000","ServiceName":"api@docker","ServiceURL":{"Scheme":"http","Opaque":"","User":null,"Host":"10.0.0.50:3000","Path":"","RawPath":"","ForceQuery":false,"RawQuery":"","Fragment":"","RawFragment":""},"StartUTC":"2025-12-03T12:34:56.789Z","StartLocal":"2025-12-03T12:34:56.789-05:00","downstream_Content-Type":"application/json","level":"info","msg":"","request_Accept-Encoding":"gzip","request_User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36","time":"2025-12-03T12:34:56Z"}
```

**Failed Request (404):**
```json
{"ClientAddr":"203.0.113.50:12345","ClientHost":"203.0.113.50","ClientPort":"12345","ClientUsername":"-","DownstreamContentSize":19,"DownstreamStatus":404,"Duration":2000000,"RequestAddr":"example.com","RequestHost":"example.com","RequestMethod":"GET","RequestPath":"/admin/config.php","RequestPort":"443","RequestProtocol":"HTTP/1.1","RequestScheme":"https","RouterName":"web@docker","ServiceAddr":"","ServiceName":"","ServiceURL":null,"StartUTC":"2025-12-03T13:15:22.456Z","level":"info","msg":"","request_User-Agent":"nikto/2.1.6","time":"2025-12-03T13:15:22Z"}
```

**SQL Injection Attempt:**
```json
{"ClientAddr":"198.51.100.25:9876","ClientHost":"198.51.100.25","ClientPort":"9876","ClientUsername":"-","DownstreamContentSize":0,"DownstreamStatus":400,"Duration":5000000,"RequestAddr":"example.com","RequestHost":"example.com","RequestMethod":"GET","RequestPath":"/api/search?q=test' OR '1'='1","RequestPort":"443","RequestProtocol":"HTTP/1.1","RequestScheme":"https","RouterName":"api@docker","ServiceAddr":"10.0.0.50:3000","ServiceName":"api@docker","StartUTC":"2025-12-03T14:22:33.789Z","level":"info","msg":"","request_User-Agent":"sqlmap/1.5.2","time":"2025-12-03T14:22:33Z"}
```

### Parser Configuration

```json
{
  "name": "traefik-access",
  "description": "Parses Traefik JSON access logs for security monitoring",
  "enabled": true,
  "priority": 65,
  "parser_type": "json",
  "pattern": "",
  "field_mappings": {
    "ClientHost": "client_ip",
    "ClientUsername": "username",
    "time": "timestamp",
    "RequestMethod": "http_method",
    "RequestPath": "request_uri",
    "RequestProtocol": "http_version",
    "DownstreamStatus": "http_status",
    "DownstreamContentSize": "bytes_sent",
    "request_User-Agent": "user_agent",
    "Duration": "response_time",
    "ServiceAddr": "upstream_host",
    "RequestHost": "request_host",
    "ServiceName": "service_name",
    "RouterName": "router_name"
  },
  "test_samples": [
    {
      "raw_message": "{\"ClientAddr\":\"192.168.1.100:54321\",\"ClientHost\":\"192.168.1.100\",\"ClientPort\":\"54321\",\"ClientUsername\":\"admin\",\"DownstreamContentSize\":1234,\"DownstreamStatus\":200,\"Duration\":15000000,\"RequestHost\":\"example.com\",\"RequestMethod\":\"GET\",\"RequestPath\":\"/api/users\",\"RequestPort\":\"443\",\"RequestProtocol\":\"HTTP/1.1\",\"RequestScheme\":\"https\",\"ServiceAddr\":\"10.0.0.50:3000\",\"ServiceName\":\"api@docker\",\"RouterName\":\"api@docker\",\"StartUTC\":\"2025-12-03T12:34:56.789Z\",\"level\":\"info\",\"msg\":\"\",\"request_User-Agent\":\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\",\"time\":\"2025-12-03T12:34:56Z\"}",
      "expected_fields": {
        "client_ip": "192.168.1.100",
        "username": "admin",
        "timestamp": "2025-12-03T12:34:56Z",
        "http_method": "GET",
        "request_uri": "/api/users",
        "http_version": "HTTP/1.1",
        "http_status": 200,
        "bytes_sent": 1234,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "response_time": 15000000,
        "upstream_host": "10.0.0.50:3000",
        "request_host": "example.com",
        "service_name": "api@docker",
        "router_name": "api@docker"
      }
    },
    {
      "raw_message": "{\"ClientAddr\":\"203.0.113.50:12345\",\"ClientHost\":\"203.0.113.50\",\"ClientPort\":\"12345\",\"ClientUsername\":\"-\",\"DownstreamContentSize\":19,\"DownstreamStatus\":404,\"Duration\":2000000,\"RequestHost\":\"example.com\",\"RequestMethod\":\"GET\",\"RequestPath\":\"/admin/config.php\",\"RequestPort\":\"443\",\"RequestProtocol\":\"HTTP/1.1\",\"RequestScheme\":\"https\",\"RouterName\":\"web@docker\",\"ServiceAddr\":\"\",\"ServiceName\":\"\",\"StartUTC\":\"2025-12-03T13:15:22.456Z\",\"level\":\"info\",\"msg\":\"\",\"request_User-Agent\":\"nikto/2.1.6\",\"time\":\"2025-12-03T13:15:22Z\"}",
      "expected_fields": {
        "client_ip": "203.0.113.50",
        "username": "-",
        "timestamp": "2025-12-03T13:15:22Z",
        "http_method": "GET",
        "request_uri": "/admin/config.php",
        "http_version": "HTTP/1.1",
        "http_status": 404,
        "bytes_sent": 19,
        "user_agent": "nikto/2.1.6",
        "response_time": 2000000,
        "upstream_host": "",
        "request_host": "example.com",
        "service_name": "",
        "router_name": "web@docker"
      }
    },
    {
      "raw_message": "{\"ClientAddr\":\"198.51.100.25:9876\",\"ClientHost\":\"198.51.100.25\",\"ClientPort\":\"9876\",\"ClientUsername\":\"-\",\"DownstreamContentSize\":0,\"DownstreamStatus\":400,\"Duration\":5000000,\"RequestHost\":\"example.com\",\"RequestMethod\":\"GET\",\"RequestPath\":\"/api/search?q=test' OR '1'='1\",\"RequestPort\":\"443\",\"RequestProtocol\":\"HTTP/1.1\",\"RequestScheme\":\"https\",\"RouterName\":\"api@docker\",\"ServiceAddr\":\"10.0.0.50:3000\",\"ServiceName\":\"api@docker\",\"StartUTC\":\"2025-12-03T14:22:33.789Z\",\"level\":\"info\",\"msg\":\"\",\"request_User-Agent\":\"sqlmap/1.5.2\",\"time\":\"2025-12-03T14:22:33Z\"}",
      "expected_fields": {
        "client_ip": "198.51.100.25",
        "username": "-",
        "timestamp": "2025-12-03T14:22:33Z",
        "http_method": "GET",
        "request_uri": "/api/search?q=test' OR '1'='1",
        "http_version": "HTTP/1.1",
        "http_status": 400,
        "bytes_sent": 0,
        "user_agent": "sqlmap/1.5.2",
        "response_time": 5000000,
        "upstream_host": "10.0.0.50:3000",
        "request_host": "example.com",
        "service_name": "api@docker",
        "router_name": "api@docker"
      }
    }
  ]
}
```

### Fields Extracted

| Field Name | Type | Description | Security Value |
|-----------|------|-------------|----------------|
| `client_ip` | string | Client IP address | Track attacker IPs, geo-blocking |
| `username` | string | Authenticated username | Identify compromised accounts |
| `timestamp` | string | Request timestamp (ISO 8601) | Precise correlation |
| `http_method` | string | HTTP method | Detect method abuse |
| `request_uri` | string | Request path with query params | SQL injection, XSS detection |
| `http_version` | string | HTTP protocol version | Legacy client identification |
| `http_status` | integer | HTTP response status | Exploitation indicators |
| `bytes_sent` | integer | Response size | Data exfiltration patterns |
| `user_agent` | string | Client user agent | Scanner detection |
| `response_time` | integer | Request duration (nanoseconds) | Slow attacks, DoS patterns |
| `upstream_host` | string | Backend service address | Backend targeting |
| `request_host` | string | Requested hostname | Virtual host attacks |
| `service_name` | string | Traefik service name | Service-specific attacks |
| `router_name` | string | Traefik router name | Routing abuse detection |

### Installation

**SQL INSERT Statement:**

```sql
INSERT INTO parsers (name, description, enabled, priority, parser_type, pattern, field_mappings, test_samples, created_at, updated_at)
VALUES (
  'traefik-access',
  'Parses Traefik JSON access logs for security monitoring',
  true,
  65,
  'json',
  '',
  '{"ClientHost":"client_ip","ClientUsername":"username","time":"timestamp","RequestMethod":"http_method","RequestPath":"request_uri","RequestProtocol":"http_version","DownstreamStatus":"http_status","DownstreamContentSize":"bytes_sent","request_User-Agent":"user_agent","Duration":"response_time","ServiceAddr":"upstream_host","RequestHost":"request_host","ServiceName":"service_name","RouterName":"router_name"}',
  '[{"raw_message":"{\"ClientAddr\":\"192.168.1.100:54321\",\"ClientHost\":\"192.168.1.100\",\"ClientPort\":\"54321\",\"ClientUsername\":\"admin\",\"DownstreamContentSize\":1234,\"DownstreamStatus\":200,\"Duration\":15000000,\"RequestHost\":\"example.com\",\"RequestMethod\":\"GET\",\"RequestPath\":\"/api/users\",\"RequestPort\":\"443\",\"RequestProtocol\":\"HTTP/1.1\",\"RequestScheme\":\"https\",\"ServiceAddr\":\"10.0.0.50:3000\",\"ServiceName\":\"api@docker\",\"RouterName\":\"api@docker\",\"StartUTC\":\"2025-12-03T12:34:56.789Z\",\"level\":\"info\",\"msg\":\"\",\"request_User-Agent\":\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\",\"time\":\"2025-12-03T12:34:56Z\"}","expected_fields":{"client_ip":"192.168.1.100","username":"admin","timestamp":"2025-12-03T12:34:56Z","http_method":"GET","request_uri":"/api/users","http_status":200}}]',
  NOW(),
  NOW()
);
```

### Testing

**Step 1: Verify JSON Log Format**

```bash
docker logs traefik | tail -1 | jq .
```

Ensure Traefik is configured for JSON access logs:

```yaml
# traefik.yml or docker-compose.yml
accessLog:
  format: json
  filePath: /var/log/traefik/access.log
```

**Step 2: Verify Parser**

In SIEMBox Parsers page:
1. Click "traefik-access"
2. Test with actual JSON log
3. Verify all fields extracted

**Step 3: Check Log Shipper**

Ensure shipper is reading Traefik logs:
```bash
docker logs siembox-log-shipper | grep traefik
```

### Troubleshooting

**Problem: JSON not parsing**

1. Verify Traefik log format is JSON:
   ```yaml
   accessLog:
     format: json
   ```

2. Check for malformed JSON:
   ```bash
   docker logs traefik | tail -1 | jq .
   ```
   If error, JSON is malformed

**Problem: Missing fields**

- Traefik version differences may omit fields
- Check Traefik documentation for your version
- Update field mappings as needed

**Problem: Logs not appearing**

1. Verify accessLog enabled in Traefik config
2. Check log file path matches shipper configuration
3. For Docker logging, use journald driver

---

## Parser 3: Caddy

### Overview

**Priority:** HIGH (598 users - third most popular)

**About Caddy:**
Caddy is a modern web server with automatic HTTPS, simple configuration, and excellent security defaults. It logs in JSON format by default, making it ideal for SIEM integration. Popular for its simplicity and automatic certificate management.

**Security Relevance:**
- JSON logs provide structured data
- Automatic HTTPS reduces misconfigurations
- Built-in security features (TLS, headers)
- Simpler configuration reduces errors
- Excellent for detecting application attacks

**Default Log Locations:**
- Access logs: `/var/log/caddy/access.log` or stdout
- Format: JSON (default)

### Log Format Examples

**Successful Request:**
```json
{"level":"info","ts":1701612896.789,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"192.168.1.100","remote_port":"54321","client_ip":"192.168.1.100","proto":"HTTP/2.0","method":"GET","host":"example.com","uri":"/api/users","headers":{"User-Agent":["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"],"Accept-Encoding":["gzip"]}},"bytes_read":0,"user_id":"admin","duration":0.015,"size":1234,"status":200,"resp_headers":{"Content-Type":["application/json"]}}
```

**Failed Request (401):**
```json
{"level":"info","ts":1701613200.456,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"203.0.113.50","remote_port":"12345","client_ip":"203.0.113.50","proto":"HTTP/1.1","method":"POST","host":"example.com","uri":"/login","headers":{"User-Agent":["curl/7.68.0"]}},"bytes_read":45,"duration":0.008,"size":187,"status":401}
```

**SQL Injection Attempt:**
```json
{"level":"info","ts":1701613500.789,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.25","remote_port":"9876","client_ip":"198.51.100.25","proto":"HTTP/1.1","method":"GET","host":"example.com","uri":"/api/search?q=test' OR '1'='1","headers":{"User-Agent":["sqlmap/1.5.2"]}},"bytes_read":0,"duration":0.003,"size":0,"status":400}
```

### Parser Configuration

```json
{
  "name": "caddy-access",
  "description": "Parses Caddy JSON access logs for security monitoring",
  "enabled": true,
  "priority": 70,
  "parser_type": "json",
  "pattern": "",
  "field_mappings": {
    "ts": "timestamp",
    "request.client_ip": "client_ip",
    "user_id": "username",
    "request.method": "http_method",
    "request.uri": "request_uri",
    "request.proto": "http_version",
    "status": "http_status",
    "size": "bytes_sent",
    "request.headers.User-Agent": "user_agent",
    "duration": "response_time",
    "request.host": "request_host",
    "bytes_read": "bytes_read"
  },
  "test_samples": [
    {
      "raw_message": "{\"level\":\"info\",\"ts\":1701612896.789,\"logger\":\"http.log.access\",\"msg\":\"handled request\",\"request\":{\"remote_ip\":\"192.168.1.100\",\"remote_port\":\"54321\",\"client_ip\":\"192.168.1.100\",\"proto\":\"HTTP/2.0\",\"method\":\"GET\",\"host\":\"example.com\",\"uri\":\"/api/users\",\"headers\":{\"User-Agent\":[\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\"],\"Accept-Encoding\":[\"gzip\"]}},\"bytes_read\":0,\"user_id\":\"admin\",\"duration\":0.015,\"size\":1234,\"status\":200,\"resp_headers\":{\"Content-Type\":[\"application/json\"]}}",
      "expected_fields": {
        "timestamp": 1701612896.789,
        "client_ip": "192.168.1.100",
        "username": "admin",
        "http_method": "GET",
        "request_uri": "/api/users",
        "http_version": "HTTP/2.0",
        "http_status": 200,
        "bytes_sent": 1234,
        "user_agent": ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"],
        "response_time": 0.015,
        "request_host": "example.com",
        "bytes_read": 0
      }
    },
    {
      "raw_message": "{\"level\":\"info\",\"ts\":1701613200.456,\"logger\":\"http.log.access\",\"msg\":\"handled request\",\"request\":{\"remote_ip\":\"203.0.113.50\",\"remote_port\":\"12345\",\"client_ip\":\"203.0.113.50\",\"proto\":\"HTTP/1.1\",\"method\":\"POST\",\"host\":\"example.com\",\"uri\":\"/login\",\"headers\":{\"User-Agent\":[\"curl/7.68.0\"]}},\"bytes_read\":45,\"duration\":0.008,\"size\":187,\"status\":401}",
      "expected_fields": {
        "timestamp": 1701613200.456,
        "client_ip": "203.0.113.50",
        "username": null,
        "http_method": "POST",
        "request_uri": "/login",
        "http_version": "HTTP/1.1",
        "http_status": 401,
        "bytes_sent": 187,
        "user_agent": ["curl/7.68.0"],
        "response_time": 0.008,
        "request_host": "example.com",
        "bytes_read": 45
      }
    },
    {
      "raw_message": "{\"level\":\"info\",\"ts\":1701613500.789,\"logger\":\"http.log.access\",\"msg\":\"handled request\",\"request\":{\"remote_ip\":\"198.51.100.25\",\"remote_port\":\"9876\",\"client_ip\":\"198.51.100.25\",\"proto\":\"HTTP/1.1\",\"method\":\"GET\",\"host\":\"example.com\",\"uri\":\"/api/search?q=test' OR '1'='1\",\"headers\":{\"User-Agent\":[\"sqlmap/1.5.2\"]}},\"bytes_read\":0,\"duration\":0.003,\"size\":0,\"status\":400}",
      "expected_fields": {
        "timestamp": 1701613500.789,
        "client_ip": "198.51.100.25",
        "username": null,
        "http_method": "GET",
        "request_uri": "/api/search?q=test' OR '1'='1",
        "http_version": "HTTP/1.1",
        "http_status": 400,
        "bytes_sent": 0,
        "user_agent": ["sqlmap/1.5.2"],
        "response_time": 0.003,
        "request_host": "example.com",
        "bytes_read": 0
      }
    }
  ]
}
```

### Fields Extracted

| Field Name | Type | Description | Security Value |
|-----------|------|-------------|----------------|
| `timestamp` | float | Unix timestamp with decimals | Precise timing correlation |
| `client_ip` | string | Client IP address | Attacker identification |
| `username` | string | User ID (if authenticated) | Account compromise tracking |
| `http_method` | string | HTTP method | Method abuse detection |
| `request_uri` | string | Request URI with params | SQL injection, XSS, path traversal |
| `http_version` | string | HTTP protocol version | Legacy client attacks |
| `http_status` | integer | HTTP response status | Success/failure indicators |
| `bytes_sent` | integer | Response size | Data exfiltration |
| `user_agent` | array | Client user agent (array) | Scanner detection |
| `response_time` | float | Request duration (seconds) | Slow attack patterns |
| `request_host` | string | Requested hostname | Virtual host attacks |
| `bytes_read` | integer | Request body size | Upload abuse detection |

### Installation

**SQL INSERT Statement:**

```sql
INSERT INTO parsers (name, description, enabled, priority, parser_type, pattern, field_mappings, test_samples, created_at, updated_at)
VALUES (
  'caddy-access',
  'Parses Caddy JSON access logs for security monitoring',
  true,
  70,
  'json',
  '',
  '{"ts":"timestamp","request.client_ip":"client_ip","user_id":"username","request.method":"http_method","request.uri":"request_uri","request.proto":"http_version","status":"http_status","size":"bytes_sent","request.headers.User-Agent":"user_agent","duration":"response_time","request.host":"request_host","bytes_read":"bytes_read"}',
  '[{"raw_message":"{\"level\":\"info\",\"ts\":1701612896.789,\"logger\":\"http.log.access\",\"msg\":\"handled request\",\"request\":{\"remote_ip\":\"192.168.1.100\",\"remote_port\":\"54321\",\"client_ip\":\"192.168.1.100\",\"proto\":\"HTTP/2.0\",\"method\":\"GET\",\"host\":\"example.com\",\"uri\":\"/api/users\",\"headers\":{\"User-Agent\":[\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\"],\"Accept-Encoding\":[\"gzip\"]}},\"bytes_read\":0,\"user_id\":\"admin\",\"duration\":0.015,\"size\":1234,\"status\":200}","expected_fields":{"timestamp":1701612896.789,"client_ip":"192.168.1.100","username":"admin","http_method":"GET","request_uri":"/api/users","http_status":200}}]',
  NOW(),
  NOW()
);
```

### Testing

**Step 1: Verify Caddy JSON Logging**

Caddy logs JSON by default. Check configuration:

```json
{
  "logging": {
    "logs": {
      "default": {
        "encoder": "json"
      }
    }
  }
}
```

**Step 2: Test Parser**

```bash
# Generate test request
curl https://your-caddy-server.com/api/test

# Check logs
tail -1 /var/log/caddy/access.log | jq .
```

**Step 3: Verify in SIEMBox**

Navigate to Parsers → caddy-access → Test Parse with real log

### Troubleshooting

**Problem: nested field not extracting**

Caddy uses nested JSON. Field mappings must use dot notation:
- `request.client_ip` not `client_ip`
- `request.headers.User-Agent` not `User-Agent`

**Problem: User-Agent is array**

Caddy returns headers as arrays. Detection rules should handle:
```yaml
conditions:
  - field: user_agent
    operator: contains
    value: "sqlmap"
```

**Problem: No user_id field**

`user_id` only appears if Caddy authentication configured. Field will be null otherwise.

---

## Parser 4: Standard NGINX

### Overview

**Priority:** HIGH (528 users - foundational web server)

**About Standard NGINX:**
Standard NGINX is the industry-standard web server and reverse proxy. While less common than NGINX Proxy Manager in homelabs, it's the foundation for many custom setups and commercial deployments. Understanding standard NGINX logs is essential.

**Security Relevance:**
- Most common format in documentation/tutorials
- Used in custom homelab setups
- Combined log format is industry standard
- Error logs reveal backend issues
- Compatible with many tools and parsers

**Default Log Locations:**
- Access logs: `/var/log/nginx/access.log`
- Error logs: `/var/log/nginx/error.log`
- Format: Combined (default) or custom

### Log Format Examples

**Combined Access Log (Default):**
```
192.168.1.100 - admin [03/Dec/2025:12:34:56 +0000] "GET /api/users HTTP/1.1" 200 1234 "https://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

**Custom Format with Upstream:**
```
192.168.1.100 - admin [03/Dec/2025:12:34:56 +0000] "GET /api/users HTTP/1.1" 200 1234 "https://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" "10.0.0.50:3000"
```

**Error Log:**
```
2025/12/03 12:34:56 [error] 123#123: *456 connect() failed (111: Connection refused) while connecting to upstream, client: 192.168.1.100, server: example.com, request: "GET /api/health HTTP/1.1", upstream: "http://10.0.0.50:3000/api/health", host: "example.com"
```

**Failed Authentication:**
```
203.0.113.50 - - [03/Dec/2025:12:35:10 +0000] "POST /login HTTP/1.1" 401 187 "https://example.com/login" "curl/7.68.0"
```

**SQL Injection Attempt:**
```
198.51.100.25 - - [03/Dec/2025:12:36:22 +0000] "GET /api/search?q=test' OR '1'='1 HTTP/1.1" 400 0 "-" "sqlmap/1.5.2"
```

### Parser Configuration

**Parser 4A: Standard NGINX Access Logs**

```json
{
  "name": "nginx-access",
  "description": "Parses standard NGINX combined access logs",
  "enabled": true,
  "priority": 75,
  "parser_type": "regex",
  "pattern": "^(?P<client_ip>[\\d.]+)\\s+-\\s+(?P<username>\\S+)\\s+\\[(?P<timestamp>[^\\]]+)\\]\\s+\"(?P<http_method>\\S+)\\s+(?P<request_uri>\\S+)\\s+(?P<http_version>[^\"]+)\"\\s+(?P<http_status>\\d+)\\s+(?P<bytes_sent>\\d+)\\s+\"(?P<referrer>[^\"]*)\"\\s+\"(?P<user_agent>[^\"]+)\"(?:\\s+\"(?P<upstream>[^\"]+)\")?",
  "field_mappings": {
    "client_ip": "client_ip",
    "username": "username",
    "timestamp": "timestamp",
    "http_method": "http_method",
    "request_uri": "request_uri",
    "http_version": "http_version",
    "http_status": "http_status",
    "bytes_sent": "bytes_sent",
    "referrer": "referrer",
    "user_agent": "user_agent",
    "upstream": "upstream_host"
  },
  "test_samples": [
    {
      "raw_message": "192.168.1.100 - admin [03/Dec/2025:12:34:56 +0000] \"GET /api/users HTTP/1.1\" 200 1234 \"https://example.com/\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\"",
      "expected_fields": {
        "client_ip": "192.168.1.100",
        "username": "admin",
        "timestamp": "03/Dec/2025:12:34:56 +0000",
        "http_method": "GET",
        "request_uri": "/api/users",
        "http_version": "HTTP/1.1",
        "http_status": "200",
        "bytes_sent": "1234",
        "referrer": "https://example.com/",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "upstream_host": null
      }
    },
    {
      "raw_message": "192.168.1.100 - admin [03/Dec/2025:12:34:56 +0000] \"GET /api/users HTTP/1.1\" 200 1234 \"https://example.com/\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\" \"10.0.0.50:3000\"",
      "expected_fields": {
        "client_ip": "192.168.1.100",
        "username": "admin",
        "timestamp": "03/Dec/2025:12:34:56 +0000",
        "http_method": "GET",
        "request_uri": "/api/users",
        "http_version": "HTTP/1.1",
        "http_status": "200",
        "bytes_sent": "1234",
        "referrer": "https://example.com/",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "upstream_host": "10.0.0.50:3000"
      }
    },
    {
      "raw_message": "203.0.113.50 - - [03/Dec/2025:12:35:10 +0000] \"POST /login HTTP/1.1\" 401 187 \"https://example.com/login\" \"curl/7.68.0\"",
      "expected_fields": {
        "client_ip": "203.0.113.50",
        "username": "-",
        "timestamp": "03/Dec/2025:12:35:10 +0000",
        "http_method": "POST",
        "request_uri": "/login",
        "http_version": "HTTP/1.1",
        "http_status": "401",
        "bytes_sent": "187",
        "referrer": "https://example.com/login",
        "user_agent": "curl/7.68.0",
        "upstream_host": null
      }
    },
    {
      "raw_message": "198.51.100.25 - - [03/Dec/2025:12:36:22 +0000] \"GET /api/search?q=test' OR '1'='1 HTTP/1.1\" 400 0 \"-\" \"sqlmap/1.5.2\"",
      "expected_fields": {
        "client_ip": "198.51.100.25",
        "username": "-",
        "timestamp": "03/Dec/2025:12:36:22 +0000",
        "http_method": "GET",
        "request_uri": "/api/search?q=test' OR '1'='1",
        "http_version": "HTTP/1.1",
        "http_status": "400",
        "bytes_sent": "0",
        "referrer": "-",
        "user_agent": "sqlmap/1.5.2",
        "upstream_host": null
      }
    },
    {
      "raw_message": "198.51.100.30 - - [03/Dec/2025:12:37:45 +0000] \"GET /../../../etc/passwd HTTP/1.1\" 404 162 \"-\" \"Mozilla/5.0\"",
      "expected_fields": {
        "client_ip": "198.51.100.30",
        "username": "-",
        "timestamp": "03/Dec/2025:12:37:45 +0000",
        "http_method": "GET",
        "request_uri": "/../../../etc/passwd",
        "http_version": "HTTP/1.1",
        "http_status": "404",
        "bytes_sent": "162",
        "referrer": "-",
        "user_agent": "Mozilla/5.0",
        "upstream_host": null
      }
    }
  ]
}
```

**Parser 4B: Standard NGINX Error Logs**

```json
{
  "name": "nginx-error",
  "description": "Parses standard NGINX error logs for backend monitoring",
  "enabled": true,
  "priority": 76,
  "parser_type": "regex",
  "pattern": "^(?P<timestamp>\\d{4}/\\d{2}/\\d{2}\\s+\\d{2}:\\d{2}:\\d{2})\\s+\\[(?P<severity>\\w+)\\]\\s+(?P<pid>\\d+)#(?P<tid>\\d+):\\s+\\*(?P<connection_id>\\d+)\\s+(?P<error_message>.+?),\\s+client:\\s+(?P<client_ip>[\\d.]+),\\s+server:\\s+(?P<server_name>\\S+),\\s+request:\\s+\"(?P<request>[^\"]+)\"(?:,\\s+upstream:\\s+\"(?P<upstream>[^\"]+)\")?(?:,\\s+host:\\s+\"(?P<host>[^\"]+)\")?",
  "field_mappings": {
    "timestamp": "timestamp",
    "severity": "severity",
    "pid": "pid",
    "tid": "tid",
    "connection_id": "connection_id",
    "error_message": "error_message",
    "client_ip": "client_ip",
    "server_name": "server_name",
    "request": "request",
    "upstream": "upstream_host",
    "host": "request_host"
  },
  "test_samples": [
    {
      "raw_message": "2025/12/03 12:34:56 [error] 123#123: *456 connect() failed (111: Connection refused) while connecting to upstream, client: 192.168.1.100, server: example.com, request: \"GET /api/health HTTP/1.1\", upstream: \"http://10.0.0.50:3000/api/health\", host: \"example.com\"",
      "expected_fields": {
        "timestamp": "2025/12/03 12:34:56",
        "severity": "error",
        "pid": "123",
        "tid": "123",
        "connection_id": "456",
        "error_message": "connect() failed (111: Connection refused) while connecting to upstream",
        "client_ip": "192.168.1.100",
        "server_name": "example.com",
        "request": "GET /api/health HTTP/1.1",
        "upstream_host": "http://10.0.0.50:3000/api/health",
        "request_host": "example.com"
      }
    },
    {
      "raw_message": "2025/12/03 13:15:22 [warn] 124#124: *789 upstream timed out (110: Connection timed out) while reading response header from upstream, client: 192.168.1.105, server: api.example.com, request: \"POST /api/process HTTP/1.1\", upstream: \"http://10.0.0.55:8080/api/process\"",
      "expected_fields": {
        "timestamp": "2025/12/03 13:15:22",
        "severity": "warn",
        "pid": "124",
        "tid": "124",
        "connection_id": "789",
        "error_message": "upstream timed out (110: Connection timed out) while reading response header from upstream",
        "client_ip": "192.168.1.105",
        "server_name": "api.example.com",
        "request": "POST /api/process HTTP/1.1",
        "upstream_host": "http://10.0.0.55:8080/api/process",
        "request_host": null
      }
    },
    {
      "raw_message": "2025/12/03 14:45:10 [error] 125#125: *1234 recv() failed (104: Connection reset by peer) while reading response header from upstream, client: 203.0.113.75, server: app.example.com, request: \"GET /admin HTTP/1.1\"",
      "expected_fields": {
        "timestamp": "2025/12/03 14:45:10",
        "severity": "error",
        "pid": "125",
        "tid": "125",
        "connection_id": "1234",
        "error_message": "recv() failed (104: Connection reset by peer) while reading response header from upstream",
        "client_ip": "203.0.113.75",
        "server_name": "app.example.com",
        "request": "GET /admin HTTP/1.1",
        "upstream_host": null,
        "request_host": null
      }
    }
  ]
}
```

### Fields Extracted

| Field Name | Type | Description | Security Value |
|-----------|------|-------------|----------------|
| `client_ip` | string | Client IP address | Attacker tracking |
| `username` | string | Authenticated username | Account monitoring |
| `timestamp` | string | Request timestamp | Attack timeline |
| `http_method` | string | HTTP method | Method abuse |
| `request_uri` | string | Request URI with params | Injection detection |
| `http_version` | string | HTTP protocol | Legacy attacks |
| `http_status` | integer | HTTP status code | Exploitation indicators |
| `bytes_sent` | integer | Response size | Data exfiltration |
| `referrer` | string | HTTP referrer | CSRF detection |
| `user_agent` | string | Client user agent | Scanner detection |
| `upstream_host` | string | Backend server (optional) | Backend targeting |
| `severity` | string | Error severity (error/warn) | Issue priority |
| `error_message` | string | Full error description | Backend issues |
| `request_host` | string | Requested hostname | Virtual host attacks |

### Installation

**SQL INSERT Statement (Access Logs):**

```sql
INSERT INTO parsers (name, description, enabled, priority, parser_type, pattern, field_mappings, test_samples, created_at, updated_at)
VALUES (
  'nginx-access',
  'Parses standard NGINX combined access logs',
  true,
  75,
  'regex',
  '^(?P<client_ip>[\d.]+)\s+-\s+(?P<username>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<http_method>\S+)\s+(?P<request_uri>\S+)\s+(?P<http_version>[^"]+)"\s+(?P<http_status>\d+)\s+(?P<bytes_sent>\d+)\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]+)"(?:\s+"(?P<upstream>[^"]+)")?',
  '{"client_ip":"client_ip","username":"username","timestamp":"timestamp","http_method":"http_method","request_uri":"request_uri","http_version":"http_version","http_status":"http_status","bytes_sent":"bytes_sent","referrer":"referrer","user_agent":"user_agent","upstream":"upstream_host"}',
  '[{"raw_message":"192.168.1.100 - admin [03/Dec/2025:12:34:56 +0000] \"GET /api/users HTTP/1.1\" 200 1234 \"https://example.com/\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\"","expected_fields":{"client_ip":"192.168.1.100","username":"admin","timestamp":"03/Dec/2025:12:34:56 +0000","http_method":"GET","request_uri":"/api/users","http_version":"HTTP/1.1","http_status":"200","bytes_sent":"1234"}}]',
  NOW(),
  NOW()
);
```

**SQL INSERT Statement (Error Logs):**

```sql
INSERT INTO parsers (name, description, enabled, priority, parser_type, pattern, field_mappings, test_samples, created_at, updated_at)
VALUES (
  'nginx-error',
  'Parses standard NGINX error logs for backend monitoring',
  true,
  76,
  'regex',
  '^(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?P<severity>\w+)\]\s+(?P<pid>\d+)#(?P<tid>\d+):\s+\*(?P<connection_id>\d+)\s+(?P<error_message>.+?),\s+client:\s+(?P<client_ip>[\d.]+),\s+server:\s+(?P<server_name>\S+),\s+request:\s+"(?P<request>[^"]+)"(?:,\s+upstream:\s+"(?P<upstream>[^"]+)")?(?:,\s+host:\s+"(?P<host>[^"]+)")?',
  '{"timestamp":"timestamp","severity":"severity","pid":"pid","tid":"tid","connection_id":"connection_id","error_message":"error_message","client_ip":"client_ip","server_name":"server_name","request":"request","upstream":"upstream_host","host":"request_host"}',
  '[{"raw_message":"2025/12/03 12:34:56 [error] 123#123: *456 connect() failed (111: Connection refused) while connecting to upstream, client: 192.168.1.100, server: example.com, request: \"GET /api/health HTTP/1.1\", upstream: \"http://10.0.0.50:3000/api/health\", host: \"example.com\"","expected_fields":{"timestamp":"2025/12/03 12:34:56","severity":"error","client_ip":"192.168.1.100","server_name":"example.com"}}]',
  NOW(),
  NOW()
);
```

### Testing

**Step 1: Verify NGINX Log Format**

Check `/etc/nginx/nginx.conf` for log format:

```nginx
log_format combined '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent"';

access_log /var/log/nginx/access.log combined;
error_log /var/log/nginx/error.log;
```

**Step 2: Generate Test Traffic**

```bash
curl https://your-nginx-server.com/api/test
tail -1 /var/log/nginx/access.log
```

**Step 3: Verify Parser**

In SIEMBox → Parsers → nginx-access → Test Parse

### Troubleshooting

**Problem: Custom log format not matching**

NGINX allows custom log formats. Check your `log_format` directive:

```nginx
log_format custom '$remote_addr - $remote_user [$time_local] '
                  '"$request" $status $body_bytes_sent '
                  '"$http_referer" "$http_user_agent" '
                  '"$upstream_addr"';  # Custom addition
```

Update parser pattern to match your custom format.

**Problem: Upstream field not extracting**

Upstream logging requires configuration:

```nginx
log_format with_upstream '$remote_addr - $remote_user [$time_local] '
                         '"$request" $status $body_bytes_sent '
                         '"$http_referer" "$http_user_agent" '
                         '"$upstream_addr"';

access_log /var/log/nginx/access.log with_upstream;
```

**Problem: Error logs not matching**

Error log format is mostly standardized but can vary slightly by NGINX version. Test with actual error logs.

---

## Appendix A: Common Patterns

### Reusable Regex Patterns

These patterns can be used when creating custom parsers:

**IP Address:**
```regex
(?:[0-9]{1,3}\.){3}[0-9]{1,3}
```

**Timestamp (NGINX Combined):**
```regex
\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}
```

**Timestamp (NGINX Error):**
```regex
\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}
```

**Timestamp (ISO 8601):**
```regex
\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?
```

**HTTP Method:**
```regex
(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)
```

**HTTP Status Code:**
```regex
[1-5]\d{2}
```

**URL Path:**
```regex
/[^\s]*
```

**User Agent:**
```regex
[^"]+
```

**SQL Injection Patterns:**
```regex
(?:'|\"|;|--|\bOR\b|\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b)
```

**Command Injection Patterns:**
```regex
(?:;|\\||`|\\$\\(|&&|cat|curl|wget|bash|sh|cmd\.exe)
```

**Path Traversal Patterns:**
```regex
(?:\.\.[\\/\\\\]|\.\.%2f|\.\.%5c)
```

---

## Appendix B: Installation Guide

### Quick Installation (All 4 Parsers)

**Step 1: Download Parser Definitions**

Save each parser JSON to a file:
- `nginx-proxy-manager-access.json`
- `nginx-proxy-manager-error.json`
- `traefik-access.json`
- `caddy-access.json`
- `nginx-access.json`
- `nginx-error.json`

**Step 2: Import via API**

```bash
# Set your SIEMBox URL and token
SIEMBOX_URL="http://localhost:3001"
TOKEN="your-api-token"

# Import each parser
for parser in *.json; do
  curl -X POST "${SIEMBOX_URL}/api/parsers" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN}" \
    -d @"${parser}"
  echo "Imported ${parser}"
done
```

**Step 3: Import via SQL**

```bash
# Connect to PostgreSQL
docker exec -it siembox-postgres psql -U siembox -d siembox

# Run SQL INSERT statements from each parser section above
```

**Step 4: Import via UI**

1. Navigate to SIEMBox → Parsers
2. Click "Import Parser"
3. Paste JSON configuration
4. Click "Import"
5. Repeat for each parser

### Log Shipper Configuration

**For NGINX Proxy Manager:**

```bash
# In SIEMBox UI, add source:
Type: file
Path: /data/logs/proxy-host-1.log
Tag: nginx-proxy-manager
Facility: local0
Enabled: Yes

# Repeat for each proxy host file (proxy-host-*.log)
```

**For Traefik:**

```bash
# In SIEMBox UI, add source:
Type: file
Path: /var/log/traefik/access.log
Tag: traefik
Facility: local1
Enabled: Yes
```

**For Caddy:**

```bash
# In SIEMBox UI, add source:
Type: file
Path: /var/log/caddy/access.log
Tag: caddy
Facility: local2
Enabled: Yes
```

**For Standard NGINX:**

```bash
# In SIEMBox UI, add sources:
Type: file
Path: /var/log/nginx/access.log
Tag: nginx
Facility: local3
Enabled: Yes

Type: file
Path: /var/log/nginx/error.log
Tag: nginx-error
Facility: local3
Enabled: Yes
```

### Verification Checklist

After installation:

- [ ] Parser shows "Enabled" in UI
- [ ] Test parse succeeds with sample log
- [ ] Logs appearing in SIEMBox logs page
- [ ] Fields extracting correctly (check parsed_data)
- [ ] Priority order correct (lower number = higher priority)
- [ ] Log shipper online and forwarding logs
- [ ] At least one detection rule enabled

---

## Appendix C: Troubleshooting

### Common Issues Across All Parsers

**Issue: Parser not matching any logs**

**Symptoms:**
- Logs appear in raw_logs table
- parsed_data is empty or null
- No fields extracted

**Solutions:**
1. Verify parser is enabled
2. Check parser priority (lower number = higher priority)
3. Test parser with exact log line via UI
4. Verify log format hasn't changed (application update)
5. Check for special characters in log (escaping issues)

**Issue: Some fields not extracting**

**Symptoms:**
- Parser matches
- Only some fields populate
- Expected fields are null

**Solutions:**
1. Check field mappings are correct
2. Verify field exists in log format
3. Optional fields may be null (this is normal)
4. Test with multiple log samples
5. Check for regex group matching issues

**Issue: Logs not appearing at all**

**Symptoms:**
- No logs in SIEMBox
- raw_logs table empty
- Log shipper shows online

**Solutions:**
1. Verify log file path in shipper config
2. Check file permissions (log shipper must read)
3. Verify log file exists and has content
4. Check syslog server is receiving logs
5. Review shipper logs for errors

**Issue: Parser priority conflicts**

**Symptoms:**
- Wrong parser matching logs
- Unexpected field extraction
- Generic parser matching instead of specific

**Solutions:**
1. Check parser priorities (lower = higher)
2. Specific parsers should have priority 60-80
3. Generic parsers should have priority 100+
4. Test parser matching order
5. Adjust priorities to correct order

### Parser-Specific Issues

**NGINX Proxy Manager:**

**Issue: Proxy host files not found**

NGINX Proxy Manager creates separate log files per proxy host:
```
/data/logs/proxy-host-1.log
/data/logs/proxy-host-2.log
/data/logs/proxy-host-3.log
```

Configure log shipper to watch entire directory or add each file separately.

**Issue: Username field always dash**

If NGINX Proxy Manager not using HTTP Basic Auth, username will be `-`. This is normal.

**Traefik:**

**Issue: Not logging in JSON**

Traefik must be configured for JSON access logs:

```yaml
# traefik.yml
accessLog:
  format: json
  filePath: /var/log/traefik/access.log
```

Or via command line:
```bash
--accesslog.format=json
```

**Issue: Headers are arrays**

Traefik returns headers as arrays (e.g., `["value1", "value2"]`). Detection rules must handle this:

```yaml
conditions:
  - field: user_agent
    operator: contains
    value: "sqlmap"
```

The `contains` operator works with arrays.

**Caddy:**

**Issue: Nested fields not extracting**

Caddy uses deeply nested JSON. Use dot notation in field mappings:

```json
{
  "request.client_ip": "client_ip",
  "request.headers.User-Agent": "user_agent"
}
```

**Issue: Timestamp is Unix float**

Caddy uses Unix timestamps with decimals (e.g., `1701612896.789`). Convert to human-readable in detection rules or keep as-is for precise correlation.

**Standard NGINX:**

**Issue: Custom log format not matching**

Check your NGINX config for `log_format` directive. Parser is designed for standard "combined" format:

```nginx
log_format combined '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent"';
```

If using custom format, update parser pattern accordingly.

**Issue: Upstream field missing**

Upstream logging requires explicit configuration:

```nginx
log_format with_upstream '$remote_addr - $remote_user [$time_local] '
                         '"$request" $status $body_bytes_sent '
                         '"$http_referer" "$http_user_agent" '
                         '"$upstream_addr"';

access_log /var/log/nginx/access.log with_upstream;
```

### Getting Help

**Before asking for help:**

1. Test parser with actual log line
2. Check parser is enabled
3. Verify log shipper is forwarding logs
4. Review SIEMBox backend logs for errors
5. Check parser priority order

**When reporting issues:**

Include:
- Exact parser configuration (JSON)
- Sample log line (sanitized if needed)
- Expected vs actual field extraction
- Parser test results from UI
- SIEMBox version
- Reverse proxy application and version

**Resources:**

- GitHub Issues: https://github.com/cladkins/SIEMBOX/issues
- Discussions: https://github.com/cladkins/SIEMBOX/discussions
- Documentation: https://github.com/cladkins/SIEMBOX/tree/main/docs

---

## Conclusion

These 4 reverse proxy parsers provide comprehensive coverage for 90%+ of homelabs:

1. **NGINX Proxy Manager** - Most popular (842 users)
2. **Traefik** - Modern cloud-native (751 users)
3. **Caddy** - Simple and secure (598 users)
4. **Standard NGINX** - Industry standard (528 users)

Together, these parsers enable detection of:
- SQL injection attempts
- Command injection strings
- Path traversal attacks
- Directory scanning patterns
- Brute force authentication
- Malicious user agents
- Excessive request rates
- Server errors and backend failures

**Next Steps:**

1. Install parsers for your reverse proxy
2. Configure log shipper to forward logs
3. Test parser with sample logs
4. Import detection rules from RULES.md
5. Monitor alerts and tune thresholds

**Remember:** Your reverse proxy is your #1 attack surface. These parsers are NON-NEGOTIABLE for homelab security.

---

**Document Version:** 1.0
**Last Updated:** 2025-12-03
**Compatible with:** SIEMBox 1.0+
**Parsers Included:** 6 (4 applications, access + error variants)

---
