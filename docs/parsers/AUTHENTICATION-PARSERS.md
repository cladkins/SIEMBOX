# Authentication Service Parsers for SIEMBox

**Version:** 1.0
**Date:** 2025-12-03
**Purpose:** Critical authentication service parsers for homelab SIEM deployments

---

## Overview

### Why Authentication Service Parsers Are Critical

Based on homelab survey data, **1,169 homelabbers use dedicated authentication services** to protect access to their applications. These services are the second most critical monitoring priority after reverse proxies because:

1. **Single Point of Failure** - SSO compromise grants access to ALL protected services
2. **High-Value Target** - Attackers specifically target authentication systems
3. **Credential Gateway** - All user credentials flow through these systems
4. **Brute Force Magnet** - Authentication portals face constant credential attacks
5. **Account Enumeration Risk** - Failed logins can reveal valid usernames

**Bottom Line:** If you use SSO or centralized authentication, monitoring it is mandatory. These parsers detect credential attacks before they succeed.

### Threat Context

Authentication services face these attacks daily:
- **Brute Force** - Automated password guessing (hourly attempts)
- **Credential Stuffing** - Breached credential testing from other sites
- **Account Enumeration** - Username discovery via timing attacks
- **Session Hijacking** - Token theft and replay attacks
- **MFA Bypass Attempts** - Second factor evasion techniques
- **API Token Abuse** - Automated credential harvesting

### What These Parsers Enable

With these parsers deployed, you can detect:
- Failed authentication attempts (brute force indicators)
- Successful auth after multiple failures (attack success)
- Account enumeration patterns
- Unusual login locations or times
- Session management anomalies
- API authentication abuse
- Multi-factor authentication failures
- Cross-service credential stuffing

---

## Table of Contents

1. [Parser 1: Authelia](#parser-1-authelia)
2. [Parser 2: authentik](#parser-2-authentik)
3. [Parser 3: Keycloak](#parser-3-keycloak)
4. [Appendix A: Common Patterns](#appendix-a-common-patterns)
5. [Appendix B: Installation Guide](#appendix-b-installation-guide)
6. [Appendix C: Troubleshooting](#appendix-c-troubleshooting)

---

## Parser 1: Authelia

### Overview

**Priority:** CRITICAL (390 users - most popular SSO solution)

**About Authelia:**
Authelia is an open-source authentication and authorization server providing single sign-on (SSO) and two-factor authentication (2FA) for applications. It's the most popular authentication solution in homelabs due to its simplicity, comprehensive documentation, and excellent integration with reverse proxies. Authelia uses JSON structured logs making it ideal for SIEM integration.

**Security Relevance:**
- Protects access to multiple backend applications via SSO
- Handles first-factor (password) and second-factor (TOTP/WebAuthn) authentication
- Common target for credential stuffing attacks
- Failed authentication logs reveal brute force attempts
- Session logs track user access patterns
- API verification logs show application access attempts
- Critical for detecting account takeover attempts

**Default Log Locations:**
- Container logs: Docker stdout (JSON format)
- File logs: `/config/authelia.log` (if configured)
- Format: JSON structured logging (default)

### Log Format Examples

**Successful First Factor Authentication:**
```json
{"level":"info","method":"POST","path":"/api/firstfactor","remote_ip":"192.168.1.100","time":"2025-12-03T12:34:56-05:00","msg":"Successful 1FA","username":"admin"}
```

**Failed First Factor Authentication:**
```json
{"level":"warn","method":"POST","path":"/api/firstfactor","remote_ip":"192.168.1.100","time":"2025-12-03T12:35:22-05:00","msg":"Unsuccessful 1FA","username":"admin","error":"Credentials are wrong"}
```

**API Verification Success:**
```json
{"level":"info","method":"GET","path":"/api/verify","remote_ip":"192.168.1.50","time":"2025-12-03T12:36:45-05:00","msg":"Access to https://app.example.com/ is allowed","username":"user@example.com","status_code":200}
```

**API Verification Denied:**
```json
{"level":"warn","method":"GET","path":"/api/verify","remote_ip":"203.0.113.50","time":"2025-12-03T12:37:10-05:00","msg":"Access to https://app.example.com/ is not authorized","status_code":401}
```

**Session Created:**
```json
{"level":"info","msg":"Session created","remote_ip":"192.168.1.100","session_id":"abc123def456","time":"2025-12-03T12:34:58-05:00","username":"admin"}
```

**Second Factor Authentication Success:**
```json
{"level":"info","method":"POST","path":"/api/secondfactor/totp","remote_ip":"192.168.1.100","time":"2025-12-03T12:35:05-05:00","msg":"Successful 2FA","username":"admin"}
```

**Second Factor Authentication Failed:**
```json
{"level":"warn","method":"POST","path":"/api/secondfactor/totp","remote_ip":"192.168.1.100","time":"2025-12-03T12:35:08-05:00","msg":"Unsuccessful 2FA","username":"admin","error":"Wrong TOTP code"}
```

### Parser Configuration

**Parser 1A: Authelia Access Logs**

```json
{
  "name": "authelia-access",
  "description": "Parses Authelia authentication and access logs for security monitoring",
  "enabled": true,
  "priority": 65,
  "parser_type": "json",
  "pattern": "",
  "field_mappings": {
    "time": "timestamp",
    "remote_ip": "client_ip",
    "username": "username",
    "method": "http_method",
    "path": "request_path",
    "status_code": "http_status",
    "msg": "message",
    "error": "error_message",
    "session_id": "session_id",
    "level": "log_level"
  },
  "test_samples": [
    {
      "raw_message": "{\"level\":\"info\",\"method\":\"POST\",\"path\":\"/api/firstfactor\",\"remote_ip\":\"192.168.1.100\",\"time\":\"2025-12-03T12:34:56-05:00\",\"msg\":\"Successful 1FA\",\"username\":\"admin\"}",
      "expected_fields": {
        "timestamp": "2025-12-03T12:34:56-05:00",
        "client_ip": "192.168.1.100",
        "username": "admin",
        "http_method": "POST",
        "request_path": "/api/firstfactor",
        "http_status": null,
        "message": "Successful 1FA",
        "error_message": null,
        "session_id": null,
        "log_level": "info"
      }
    },
    {
      "raw_message": "{\"level\":\"warn\",\"method\":\"POST\",\"path\":\"/api/firstfactor\",\"remote_ip\":\"192.168.1.100\",\"time\":\"2025-12-03T12:35:22-05:00\",\"msg\":\"Unsuccessful 1FA\",\"username\":\"admin\",\"error\":\"Credentials are wrong\"}",
      "expected_fields": {
        "timestamp": "2025-12-03T12:35:22-05:00",
        "client_ip": "192.168.1.100",
        "username": "admin",
        "http_method": "POST",
        "request_path": "/api/firstfactor",
        "http_status": null,
        "message": "Unsuccessful 1FA",
        "error_message": "Credentials are wrong",
        "session_id": null,
        "log_level": "warn"
      }
    },
    {
      "raw_message": "{\"level\":\"info\",\"method\":\"GET\",\"path\":\"/api/verify\",\"remote_ip\":\"192.168.1.50\",\"time\":\"2025-12-03T12:36:45-05:00\",\"msg\":\"Access to https://app.example.com/ is allowed\",\"username\":\"user@example.com\",\"status_code\":200}",
      "expected_fields": {
        "timestamp": "2025-12-03T12:36:45-05:00",
        "client_ip": "192.168.1.50",
        "username": "user@example.com",
        "http_method": "GET",
        "request_path": "/api/verify",
        "http_status": 200,
        "message": "Access to https://app.example.com/ is allowed",
        "error_message": null,
        "session_id": null,
        "log_level": "info"
      }
    },
    {
      "raw_message": "{\"level\":\"warn\",\"method\":\"GET\",\"path\":\"/api/verify\",\"remote_ip\":\"203.0.113.50\",\"time\":\"2025-12-03T12:37:10-05:00\",\"msg\":\"Access to https://app.example.com/ is not authorized\",\"status_code\":401}",
      "expected_fields": {
        "timestamp": "2025-12-03T12:37:10-05:00",
        "client_ip": "203.0.113.50",
        "username": null,
        "http_method": "GET",
        "request_path": "/api/verify",
        "http_status": 401,
        "message": "Access to https://app.example.com/ is not authorized",
        "error_message": null,
        "session_id": null,
        "log_level": "warn"
      }
    },
    {
      "raw_message": "{\"level\":\"info\",\"msg\":\"Session created\",\"remote_ip\":\"192.168.1.100\",\"session_id\":\"abc123def456\",\"time\":\"2025-12-03T12:34:58-05:00\",\"username\":\"admin\"}",
      "expected_fields": {
        "timestamp": "2025-12-03T12:34:58-05:00",
        "client_ip": "192.168.1.100",
        "username": "admin",
        "http_method": null,
        "request_path": null,
        "http_status": null,
        "message": "Session created",
        "error_message": null,
        "session_id": "abc123def456",
        "log_level": "info"
      }
    }
  ]
}
```

### Fields Extracted

| Field Name | Type | Description | Security Value |
|-----------|------|-------------|----------------|
| `timestamp` | string | Event timestamp (ISO 8601) | Precise attack correlation |
| `client_ip` | string | Client IP address | Track attacker IPs, geo-blocking |
| `username` | string | Username attempted/authenticated | Account targeting detection |
| `http_method` | string | HTTP method (POST/GET) | API abuse detection |
| `request_path` | string | API endpoint path | Endpoint targeting patterns |
| `http_status` | integer | HTTP response status | Success/failure indicators |
| `message` | string | Log message describing event | Human-readable context |
| `error_message` | string | Detailed error (if failed) | Failure reason analysis |
| `session_id` | string | Session identifier | Session tracking, hijacking detection |
| `log_level` | string | Log severity (info/warn/error) | Alert prioritization |

### Installation

**SQL INSERT Statement:**

```sql
INSERT INTO parsers (name, description, enabled, priority, parser_type, pattern, field_mappings, test_samples, created_at, updated_at)
VALUES (
  'authelia-access',
  'Parses Authelia authentication and access logs for security monitoring',
  true,
  65,
  'json',
  '',
  '{"time":"timestamp","remote_ip":"client_ip","username":"username","method":"http_method","path":"request_path","status_code":"http_status","msg":"message","error":"error_message","session_id":"session_id","level":"log_level"}',
  '[{"raw_message":"{\"level\":\"info\",\"method\":\"POST\",\"path\":\"/api/firstfactor\",\"remote_ip\":\"192.168.1.100\",\"time\":\"2025-12-03T12:34:56-05:00\",\"msg\":\"Successful 1FA\",\"username\":\"admin\"}","expected_fields":{"timestamp":"2025-12-03T12:34:56-05:00","client_ip":"192.168.1.100","username":"admin","http_method":"POST","request_path":"/api/firstfactor","message":"Successful 1FA","log_level":"info"}}]',
  NOW(),
  NOW()
);
```

### Testing

**Step 1: Verify Authelia JSON Logging**

Authelia logs JSON by default. Check Docker logs:

```bash
docker logs authelia | tail -5 | jq .
```

**Step 2: Generate Test Authentication**

```bash
# Trigger failed login (use wrong password)
curl -X POST https://auth.example.com/api/firstfactor \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"wrongpassword"}'

# Check Authelia logs
docker logs authelia | grep "Unsuccessful 1FA"
```

**Step 3: Verify Parser in SIEMBox**

Navigate to Parsers → authelia-access → Test Parse with real log

**Step 4: Check Log Shipper**

```bash
# Verify shipper is reading Authelia logs
docker logs siembox-log-shipper | grep authelia
```

### Troubleshooting

**Problem: Logs not appearing**

1. Verify Authelia container is running:
   ```bash
   docker ps | grep authelia
   ```

2. Check Authelia is logging to stdout:
   ```bash
   docker logs authelia --tail 10
   ```

3. Verify log shipper is configured for Docker logs:
   ```yaml
   SOURCE_1_TYPE=journald
   SOURCE_1_TAG=authelia
   SOURCE_1_ENABLED=true
   ```

**Problem: Username field missing**

- API verification requests may not include username (unauthenticated)
- This is normal for denied access attempts
- Username appears after successful authentication

**Problem: JSON not parsing**

1. Verify Authelia version (JSON logging is default in v4.30+)
2. Check for text format logs (older versions)
3. Ensure log level is configured (default is `info`)

**Problem: Session ID not extracting**

- Session ID only appears in session-related logs
- Not all log entries include session_id field
- This is normal and expected

---

## Parser 2: authentik

### Overview

**Priority:** HIGH (268 users - modern identity provider)

**About authentik:**
authentik is a modern, flexible open-source identity provider focused on ease of use and security. It provides comprehensive authentication, authorization, and user management with excellent API support. authentik's event-driven architecture generates rich, detailed JSON logs ideal for security monitoring.

**Security Relevance:**
- Central identity provider for multiple applications
- Event-based logging captures every authentication action
- Supports multiple authentication methods (password, OAuth, SAML, LDAP)
- Detailed event context for forensic analysis
- Flow execution logs reveal enumeration attempts
- User and admin action tracking
- API event logging for automation monitoring

**Default Log Locations:**
- Container logs: Docker stdout (JSON format)
- File logs: `/media/logs/` (if configured)
- Format: JSON event logs (structured)

### Log Format Examples

**Successful Login Event:**
```json
{"timestamp":"2025-12-03T12:34:56.789Z","event":"login","user":{"username":"admin","email":"admin@example.com","pk":1},"client_ip":"192.168.1.100","context":{"auth_method":"password","binding":{"app":"my-app"}},"action":"login","result":"success"}
```

**Failed Login Event:**
```json
{"timestamp":"2025-12-03T12:35:15.123Z","event":"login_failed","user":{"username":"admin","email":"admin@example.com"},"client_ip":"192.168.1.100","context":{"reason":"invalid_password","auth_method":"password"},"action":"login","result":"failure"}
```

**Flow Execution (Identification Stage):**
```json
{"timestamp":"2025-12-03T12:36:22.456Z","event":"flow_execution","flow_slug":"default-authentication-flow","client_ip":"192.168.1.100","stage":"identification","result":"success"}
```

**Flow Execution Failure:**
```json
{"timestamp":"2025-12-03T12:36:30.789Z","event":"flow_execution","flow_slug":"default-authentication-flow","client_ip":"203.0.113.50","stage":"authentication","result":"failure","context":{"error":"Invalid credentials"}}
```

**User Creation Event:**
```json
{"timestamp":"2025-12-03T12:37:45.012Z","event":"model_created","user":{"username":"admin","email":"admin@example.com","pk":1},"client_ip":"192.168.1.10","context":{"model":"authentik_core.user","created":{"username":"newuser","email":"newuser@example.com","is_active":true}},"action":"model_created","result":"success"}
```

**API Token Used:**
```json
{"timestamp":"2025-12-03T12:38:10.345Z","event":"token_view","user":{"username":"api-user","pk":5},"client_ip":"192.168.1.200","context":{"token_identifier":"token123","app":"api-client"},"action":"token_view","result":"success"}
```

### Parser Configuration

```json
{
  "name": "authentik-events",
  "description": "Parses authentik event logs for authentication and authorization monitoring",
  "enabled": true,
  "priority": 66,
  "parser_type": "json",
  "pattern": "",
  "field_mappings": {
    "timestamp": "timestamp",
    "event": "event_type",
    "user.username": "username",
    "user.email": "user_email",
    "user.pk": "user_id",
    "client_ip": "client_ip",
    "action": "action",
    "result": "result",
    "context": "event_context",
    "flow_slug": "flow_name",
    "stage": "flow_stage",
    "context.reason": "failure_reason",
    "context.auth_method": "auth_method",
    "context.model": "model_type",
    "context.error": "error_message"
  },
  "test_samples": [
    {
      "raw_message": "{\"timestamp\":\"2025-12-03T12:34:56.789Z\",\"event\":\"login\",\"user\":{\"username\":\"admin\",\"email\":\"admin@example.com\",\"pk\":1},\"client_ip\":\"192.168.1.100\",\"context\":{\"auth_method\":\"password\",\"binding\":{\"app\":\"my-app\"}},\"action\":\"login\",\"result\":\"success\"}",
      "expected_fields": {
        "timestamp": "2025-12-03T12:34:56.789Z",
        "event_type": "login",
        "username": "admin",
        "user_email": "admin@example.com",
        "user_id": 1,
        "client_ip": "192.168.1.100",
        "action": "login",
        "result": "success",
        "auth_method": "password"
      }
    },
    {
      "raw_message": "{\"timestamp\":\"2025-12-03T12:35:15.123Z\",\"event\":\"login_failed\",\"user\":{\"username\":\"admin\",\"email\":\"admin@example.com\"},\"client_ip\":\"192.168.1.100\",\"context\":{\"reason\":\"invalid_password\",\"auth_method\":\"password\"},\"action\":\"login\",\"result\":\"failure\"}",
      "expected_fields": {
        "timestamp": "2025-12-03T12:35:15.123Z",
        "event_type": "login_failed",
        "username": "admin",
        "user_email": "admin@example.com",
        "client_ip": "192.168.1.100",
        "action": "login",
        "result": "failure",
        "failure_reason": "invalid_password",
        "auth_method": "password"
      }
    },
    {
      "raw_message": "{\"timestamp\":\"2025-12-03T12:36:22.456Z\",\"event\":\"flow_execution\",\"flow_slug\":\"default-authentication-flow\",\"client_ip\":\"192.168.1.100\",\"stage\":\"identification\",\"result\":\"success\"}",
      "expected_fields": {
        "timestamp": "2025-12-03T12:36:22.456Z",
        "event_type": "flow_execution",
        "client_ip": "192.168.1.100",
        "flow_name": "default-authentication-flow",
        "flow_stage": "identification",
        "result": "success"
      }
    },
    {
      "raw_message": "{\"timestamp\":\"2025-12-03T12:36:30.789Z\",\"event\":\"flow_execution\",\"flow_slug\":\"default-authentication-flow\",\"client_ip\":\"203.0.113.50\",\"stage\":\"authentication\",\"result\":\"failure\",\"context\":{\"error\":\"Invalid credentials\"}}",
      "expected_fields": {
        "timestamp": "2025-12-03T12:36:30.789Z",
        "event_type": "flow_execution",
        "client_ip": "203.0.113.50",
        "flow_name": "default-authentication-flow",
        "flow_stage": "authentication",
        "result": "failure",
        "error_message": "Invalid credentials"
      }
    },
    {
      "raw_message": "{\"timestamp\":\"2025-12-03T12:37:45.012Z\",\"event\":\"model_created\",\"user\":{\"username\":\"admin\",\"email\":\"admin@example.com\",\"pk\":1},\"client_ip\":\"192.168.1.10\",\"context\":{\"model\":\"authentik_core.user\",\"created\":{\"username\":\"newuser\",\"email\":\"newuser@example.com\",\"is_active\":true}},\"action\":\"model_created\",\"result\":\"success\"}",
      "expected_fields": {
        "timestamp": "2025-12-03T12:37:45.012Z",
        "event_type": "model_created",
        "username": "admin",
        "user_email": "admin@example.com",
        "user_id": 1,
        "client_ip": "192.168.1.10",
        "action": "model_created",
        "result": "success",
        "model_type": "authentik_core.user"
      }
    }
  ]
}
```

### Fields Extracted

| Field Name | Type | Description | Security Value |
|-----------|------|-------------|----------------|
| `timestamp` | string | Event timestamp (ISO 8601 with ms) | Precise attack correlation |
| `event_type` | string | Event type (login, login_failed, etc) | Attack pattern identification |
| `username` | string | Username involved in event | Account targeting detection |
| `user_email` | string | User email address | Account correlation |
| `user_id` | integer | User primary key | User tracking across events |
| `client_ip` | string | Client IP address | Attacker IP tracking |
| `action` | string | Action performed | Audit trail |
| `result` | string | Event result (success/failure) | Success/failure analysis |
| `event_context` | object | Full context object (nested) | Detailed forensic data |
| `flow_name` | string | Authentication flow slug | Flow-based attack detection |
| `flow_stage` | string | Current flow stage | Enumeration detection |
| `failure_reason` | string | Reason for failure | Attack analysis |
| `auth_method` | string | Authentication method used | Method-specific attacks |
| `model_type` | string | Model being modified (admin actions) | Privilege change detection |
| `error_message` | string | Error details | Detailed failure analysis |

### Installation

**SQL INSERT Statement:**

```sql
INSERT INTO parsers (name, description, enabled, priority, parser_type, pattern, field_mappings, test_samples, created_at, updated_at)
VALUES (
  'authentik-events',
  'Parses authentik event logs for authentication and authorization monitoring',
  true,
  66,
  'json',
  '',
  '{"timestamp":"timestamp","event":"event_type","user.username":"username","user.email":"user_email","user.pk":"user_id","client_ip":"client_ip","action":"action","result":"result","context":"event_context","flow_slug":"flow_name","stage":"flow_stage","context.reason":"failure_reason","context.auth_method":"auth_method","context.model":"model_type","context.error":"error_message"}',
  '[{"raw_message":"{\"timestamp\":\"2025-12-03T12:34:56.789Z\",\"event\":\"login\",\"user\":{\"username\":\"admin\",\"email\":\"admin@example.com\",\"pk\":1},\"client_ip\":\"192.168.1.100\",\"context\":{\"auth_method\":\"password\",\"binding\":{\"app\":\"my-app\"}},\"action\":\"login\",\"result\":\"success\"}","expected_fields":{"timestamp":"2025-12-03T12:34:56.789Z","event_type":"login","username":"admin","user_email":"admin@example.com","user_id":1,"client_ip":"192.168.1.100","action":"login","result":"success"}}]',
  NOW(),
  NOW()
);
```

### Testing

**Step 1: Verify authentik Event Logging**

Check authentik container logs:

```bash
docker logs authentik-server | tail -5 | jq .
```

**Step 2: Generate Test Events**

```bash
# Trigger failed login
curl -X POST https://auth.example.com/flows/executor/default-authentication-flow/ \
  -H "Content-Type: application/json" \
  -d '{"uid_field":"wronguser","password":"wrongpass"}'

# Check event logs
docker logs authentik-server | grep login_failed
```

**Step 3: Verify Parser in SIEMBox**

Navigate to Parsers → authentik-events → Test Parse with real event log

**Step 4: Check Event Generation**

In authentik admin interface:
1. Navigate to Events → Logs
2. Trigger test authentication
3. Verify events are logged

### Troubleshooting

**Problem: No event logs appearing**

1. Verify event logging is enabled in authentik:
   ```bash
   # Check authentik configuration
   docker exec authentik-server env | grep LOG
   ```

2. Enable DEBUG logging if needed:
   ```yaml
   environment:
     AUTHENTIK_LOG_LEVEL: debug
   ```

**Problem: Nested fields not extracting**

authentik uses deeply nested JSON. Use dot notation:
- `user.username` not `username`
- `context.reason` not `reason`
- `context.auth_method` not `auth_method`

**Problem: Some events missing user field**

- Flow execution events may not have user context
- Unauthenticated events won't have user data
- This is normal for early flow stages

**Problem: Context field too large**

- The `context` object can be very large
- Store full context for forensics
- Use specific nested fields for detection rules

---

## Parser 3: Keycloak

### Overview

**Priority:** HIGH (158 users - enterprise-grade IAM)

**About Keycloak:**
Keycloak is a comprehensive open-source identity and access management solution providing SSO, OAuth 2.0, OpenID Connect, and SAML 2.0 support. It's popular in homelabs for its enterprise features, extensive protocol support, and comprehensive audit logging. Keycloak generates detailed JSON event logs for every authentication and administrative action.

**Security Relevance:**
- Enterprise-grade audit logging captures all events
- Comprehensive authentication event tracking
- Admin event logs track privilege changes
- Client authentication monitoring for API abuse
- User management event tracking
- Failed authentication reason analysis
- Token lifecycle event monitoring

**Default Log Locations:**
- Container logs: Docker stdout (JSON format)
- File logs: `/opt/keycloak/logs/` (if configured)
- Format: JSON event logs

### Log Format Examples

**Login Event (Success):**
```json
{"type":"LOGIN","realmId":"master","clientId":"account-console","userId":"abc-123-def-456","ipAddress":"192.168.1.100","error":null,"details":{"username":"admin","auth_method":"openid-connect","auth_type":"code","redirect_uri":"https://example.com/auth/callback"},"time":1701612896789}
```

**Login Error:**
```json
{"type":"LOGIN_ERROR","realmId":"master","clientId":"account-console","userId":null,"ipAddress":"192.168.1.100","error":"invalid_user_credentials","details":{"username":"admin","auth_method":"openid-connect","reason":"Invalid username or password"},"time":1701612900123}
```

**Code to Token Exchange:**
```json
{"type":"CODE_TO_TOKEN","realmId":"master","clientId":"my-app","userId":"abc-123-def-456","ipAddress":"192.168.1.100","error":null,"details":{"code_id":"xyz789","token_id":"token456","grant_type":"authorization_code"},"time":1701612905456}
```

**Code to Token Error:**
```json
{"type":"CODE_TO_TOKEN_ERROR","realmId":"master","clientId":"my-app","userId":null,"ipAddress":"203.0.113.50","error":"invalid_code","details":{"code_id":"invalid123","reason":"Code is expired"},"time":1701612910789}
```

**Admin Event - User Update:**
```json
{"type":"UPDATE","realmId":"master","authDetails":{"realmId":"master","clientId":"security-admin-console","userId":"admin-user-id","ipAddress":"192.168.1.10"},"resourceType":"USER","resourcePath":"users/abc-123-def-456","representation":"{\"username\":\"testuser\",\"enabled\":true,\"emailVerified\":true}","time":1701612920012}
```

**Admin Event - User Creation:**
```json
{"type":"CREATE","realmId":"master","authDetails":{"realmId":"master","clientId":"security-admin-console","userId":"admin-user-id","ipAddress":"192.168.1.10"},"resourceType":"USER","resourcePath":"users/new-user-id","representation":"{\"username\":\"newuser\",\"email\":\"newuser@example.com\",\"enabled\":true}","time":1701612925345}
```

**Logout Event:**
```json
{"type":"LOGOUT","realmId":"master","clientId":"account-console","userId":"abc-123-def-456","ipAddress":"192.168.1.100","error":null,"details":{"username":"admin"},"time":1701613000678}
```

### Parser Configuration

```json
{
  "name": "keycloak-events",
  "description": "Parses Keycloak audit events for authentication and admin action monitoring",
  "enabled": true,
  "priority": 67,
  "parser_type": "json",
  "pattern": "",
  "field_mappings": {
    "time": "timestamp",
    "type": "event_type",
    "realmId": "realm",
    "clientId": "client_id",
    "userId": "user_id",
    "ipAddress": "client_ip",
    "error": "error_code",
    "details": "event_details",
    "details.username": "username",
    "details.auth_method": "auth_method",
    "details.reason": "failure_reason",
    "details.redirect_uri": "redirect_uri",
    "authDetails": "auth_details",
    "authDetails.userId": "admin_user_id",
    "authDetails.ipAddress": "admin_ip",
    "resourceType": "resource_type",
    "resourcePath": "resource_path",
    "representation": "resource_data"
  },
  "test_samples": [
    {
      "raw_message": "{\"type\":\"LOGIN\",\"realmId\":\"master\",\"clientId\":\"account-console\",\"userId\":\"abc-123-def-456\",\"ipAddress\":\"192.168.1.100\",\"error\":null,\"details\":{\"username\":\"admin\",\"auth_method\":\"openid-connect\",\"auth_type\":\"code\",\"redirect_uri\":\"https://example.com/auth/callback\"},\"time\":1701612896789}",
      "expected_fields": {
        "timestamp": 1701612896789,
        "event_type": "LOGIN",
        "realm": "master",
        "client_id": "account-console",
        "user_id": "abc-123-def-456",
        "client_ip": "192.168.1.100",
        "error_code": null,
        "username": "admin",
        "auth_method": "openid-connect",
        "redirect_uri": "https://example.com/auth/callback"
      }
    },
    {
      "raw_message": "{\"type\":\"LOGIN_ERROR\",\"realmId\":\"master\",\"clientId\":\"account-console\",\"userId\":null,\"ipAddress\":\"192.168.1.100\",\"error\":\"invalid_user_credentials\",\"details\":{\"username\":\"admin\",\"auth_method\":\"openid-connect\",\"reason\":\"Invalid username or password\"},\"time\":1701612900123}",
      "expected_fields": {
        "timestamp": 1701612900123,
        "event_type": "LOGIN_ERROR",
        "realm": "master",
        "client_id": "account-console",
        "user_id": null,
        "client_ip": "192.168.1.100",
        "error_code": "invalid_user_credentials",
        "username": "admin",
        "auth_method": "openid-connect",
        "failure_reason": "Invalid username or password"
      }
    },
    {
      "raw_message": "{\"type\":\"CODE_TO_TOKEN\",\"realmId\":\"master\",\"clientId\":\"my-app\",\"userId\":\"abc-123-def-456\",\"ipAddress\":\"192.168.1.100\",\"error\":null,\"details\":{\"code_id\":\"xyz789\",\"token_id\":\"token456\",\"grant_type\":\"authorization_code\"},\"time\":1701612905456}",
      "expected_fields": {
        "timestamp": 1701612905456,
        "event_type": "CODE_TO_TOKEN",
        "realm": "master",
        "client_id": "my-app",
        "user_id": "abc-123-def-456",
        "client_ip": "192.168.1.100",
        "error_code": null
      }
    },
    {
      "raw_message": "{\"type\":\"CODE_TO_TOKEN_ERROR\",\"realmId\":\"master\",\"clientId\":\"my-app\",\"userId\":null,\"ipAddress\":\"203.0.113.50\",\"error\":\"invalid_code\",\"details\":{\"code_id\":\"invalid123\",\"reason\":\"Code is expired\"},\"time\":1701612910789}",
      "expected_fields": {
        "timestamp": 1701612910789,
        "event_type": "CODE_TO_TOKEN_ERROR",
        "realm": "master",
        "client_id": "my-app",
        "user_id": null,
        "client_ip": "203.0.113.50",
        "error_code": "invalid_code",
        "failure_reason": "Code is expired"
      }
    },
    {
      "raw_message": "{\"type\":\"UPDATE\",\"realmId\":\"master\",\"authDetails\":{\"realmId\":\"master\",\"clientId\":\"security-admin-console\",\"userId\":\"admin-user-id\",\"ipAddress\":\"192.168.1.10\"},\"resourceType\":\"USER\",\"resourcePath\":\"users/abc-123-def-456\",\"representation\":\"{\\\"username\\\":\\\"testuser\\\",\\\"enabled\\\":true,\\\"emailVerified\\\":true}\",\"time\":1701612920012}",
      "expected_fields": {
        "timestamp": 1701612920012,
        "event_type": "UPDATE",
        "realm": "master",
        "resource_type": "USER",
        "resource_path": "users/abc-123-def-456",
        "admin_user_id": "admin-user-id",
        "admin_ip": "192.168.1.10"
      }
    }
  ]
}
```

### Fields Extracted

| Field Name | Type | Description | Security Value |
|-----------|------|-------------|----------------|
| `timestamp` | integer | Unix timestamp (milliseconds) | Precise event timing |
| `event_type` | string | Event type (LOGIN, LOGIN_ERROR, etc) | Attack pattern classification |
| `realm` | string | Keycloak realm | Multi-tenant tracking |
| `client_id` | string | Client/application ID | Application targeting |
| `user_id` | string | User UUID | User tracking |
| `client_ip` | string | Client IP address | Attacker IP tracking |
| `error_code` | string | Error code (if failed) | Failure classification |
| `event_details` | object | Full details object (nested) | Complete forensic data |
| `username` | string | Username from details | Account targeting |
| `auth_method` | string | Authentication method | Method-specific attacks |
| `failure_reason` | string | Detailed failure reason | Attack analysis |
| `redirect_uri` | string | OAuth redirect URI | OAuth attack detection |
| `auth_details` | object | Admin authentication context | Admin action audit |
| `admin_user_id` | string | Admin performing action | Privilege tracking |
| `admin_ip` | string | Admin IP address | Admin access monitoring |
| `resource_type` | string | Resource being modified | Privilege escalation |
| `resource_path` | string | Specific resource path | Targeted resource tracking |
| `resource_data` | string | JSON representation of changes | Change auditing |

### Installation

**SQL INSERT Statement:**

```sql
INSERT INTO parsers (name, description, enabled, priority, parser_type, pattern, field_mappings, test_samples, created_at, updated_at)
VALUES (
  'keycloak-events',
  'Parses Keycloak audit events for authentication and admin action monitoring',
  true,
  67,
  'json',
  '',
  '{"time":"timestamp","type":"event_type","realmId":"realm","clientId":"client_id","userId":"user_id","ipAddress":"client_ip","error":"error_code","details":"event_details","details.username":"username","details.auth_method":"auth_method","details.reason":"failure_reason","details.redirect_uri":"redirect_uri","authDetails":"auth_details","authDetails.userId":"admin_user_id","authDetails.ipAddress":"admin_ip","resourceType":"resource_type","resourcePath":"resource_path","representation":"resource_data"}',
  '[{"raw_message":"{\"type\":\"LOGIN\",\"realmId\":\"master\",\"clientId\":\"account-console\",\"userId\":\"abc-123-def-456\",\"ipAddress\":\"192.168.1.100\",\"error\":null,\"details\":{\"username\":\"admin\",\"auth_method\":\"openid-connect\",\"auth_type\":\"code\",\"redirect_uri\":\"https://example.com/auth/callback\"},\"time\":1701612896789}","expected_fields":{"timestamp":1701612896789,"event_type":"LOGIN","realm":"master","client_id":"account-console","user_id":"abc-123-def-456","client_ip":"192.168.1.100","username":"admin"}}]',
  NOW(),
  NOW()
);
```

### Testing

**Step 1: Enable Keycloak Event Logging**

In Keycloak admin console:
1. Navigate to Realm Settings → Events
2. Enable "Login Events" and "Admin Events"
3. Set "Event Listeners" to include "jboss-logging"

**Step 2: Verify Event Logs**

```bash
# Check Keycloak container logs
docker logs keycloak | grep -E "LOGIN|LOGIN_ERROR" | tail -5
```

**Step 3: Generate Test Events**

```bash
# Trigger failed login
curl -X POST https://auth.example.com/realms/master/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=account-console&username=wronguser&password=wrongpass&grant_type=password"

# Check event logs
docker logs keycloak | grep LOGIN_ERROR
```

**Step 4: Verify Parser in SIEMBox**

Navigate to Parsers → keycloak-events → Test Parse with real event

### Troubleshooting

**Problem: No event logs in container output**

1. Verify event listeners are configured:
   - Realm Settings → Events → Event Listeners
   - Ensure "jboss-logging" is enabled

2. Check Keycloak logging level:
   ```bash
   # In Keycloak container
   /opt/keycloak/bin/kc.sh show-config | grep log
   ```

3. Enable event logging:
   ```bash
   # Via environment variable
   KC_LOG_LEVEL=INFO
   ```

**Problem: Admin events not appearing**

- Admin events are separate from login events
- Both must be enabled in Realm Settings → Events
- Admin events require "Admin Events Settings" enabled

**Problem: Timestamp conversion**

Keycloak uses milliseconds since epoch:
- Convert to ISO 8601 for rules: `new Date(timestamp).toISOString()`
- Detection rules can use numeric comparison directly

**Problem: Missing username in LOGIN_ERROR**

- Failed login attempts may not have username in top level
- Username is in `details.username` field
- Parser extracts from nested location

**Problem: resourcePath format varies**

- Admin event paths follow pattern: `{resourceType}/{resourceId}`
- Examples: `users/abc-123`, `roles/role-name`, `clients/client-id`
- Parse resourcePath for specific resource monitoring

---

## Appendix A: Common Patterns

### Reusable Detection Patterns

**Failed Authentication Detection:**
```yaml
conditions:
  - field: message
    operator: contains
    value: "Unsuccessful"
  # OR
  - field: result
    operator: equals
    value: "failure"
  # OR
  - field: error_code
    operator: exists
    value: true
```

**Successful Authentication After Failures:**
```yaml
# Requires custom query correlating failed + successful events
# Track same client_ip with failures followed by success
```

**Account Enumeration Detection:**
```yaml
# Multiple failed attempts with different usernames from same IP
aggregation:
  field: client_ip
  timeframe: 10m
  threshold: 10
  distinct_count: username >= 5
```

**Session Anomaly Detection:**
```yaml
# Track session_id patterns
# Multiple IPs using same session = hijacking
# Rapid session creation = automation
```

### Timestamp Conversion

**Authelia (ISO 8601):**
```javascript
// Already in standard format
// 2025-12-03T12:34:56-05:00
```

**authentik (ISO 8601 with ms):**
```javascript
// Already in standard format
// 2025-12-03T12:34:56.789Z
```

**Keycloak (Unix ms):**
```javascript
// Convert milliseconds to ISO 8601
const date = new Date(1701612896789);
const isoString = date.toISOString();
// Result: 2025-12-03T17:34:56.789Z
```

### Common Field Mappings

**Standard Field Names Across All Parsers:**
- `client_ip` - Source IP address
- `username` - Username attempted/authenticated
- `timestamp` - Event timestamp (normalize format)
- `event_type` or `message` - What happened
- `result` - success/failure indicator
- `error_message` or `error_code` - Why it failed

---

## Appendix B: Installation Guide

### Quick Installation (All 3 Parsers)

**Step 1: Download Parser Definitions**

Save each parser JSON to a file:
- `authelia-access.json`
- `authentik-events.json`
- `keycloak-events.json`

**Step 2: Import via API**

```bash
# Set your SIEMBox URL and token
SIEMBOX_URL="http://localhost:8421"
TOKEN="your-api-token"

# Import each parser
for parser in authelia-access.json authentik-events.json keycloak-events.json; do
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

**For Authelia (Docker Logs):**

```yaml
# In SIEMBox UI, add source:
Type: journald
Container: authelia
Tag: authelia
Facility: local0
Enabled: Yes
```

**For authentik (Docker Logs):**

```yaml
# In SIEMBox UI, add source:
Type: journald
Container: authentik-server
Tag: authentik
Facility: local1
Enabled: Yes
```

**For Keycloak (Docker Logs):**

```yaml
# In SIEMBox UI, add source:
Type: journald
Container: keycloak
Tag: keycloak
Facility: local2
Enabled: Yes
```

**Alternative: File-Based Logging**

If applications log to files instead of stdout:

```yaml
# Authelia file logs
Type: file
Path: /config/authelia.log
Tag: authelia
Facility: local0
Enabled: Yes

# authentik file logs
Type: file
Path: /media/logs/authentik.log
Tag: authentik
Facility: local1
Enabled: Yes

# Keycloak file logs
Type: file
Path: /opt/keycloak/logs/keycloak.log
Tag: keycloak
Facility: local2
Enabled: Yes
```

### Verification Checklist

After installation:

- [ ] Parser shows "Enabled" in UI
- [ ] Test parse succeeds with sample log
- [ ] Logs appearing in SIEMBox logs page
- [ ] Fields extracting correctly (check parsed_data)
- [ ] Priority order correct (65-67 range)
- [ ] Log shipper online and forwarding logs
- [ ] Username field populating for auth events
- [ ] Timestamp format correct
- [ ] At least one detection rule enabled

### Recommended Detection Rules

Import these rules after parsers are working:

**For All Authentication Services:**
1. **AUTH-001: Brute Force Detection** - 5+ failures in 5 minutes
2. **AUTH-002: Successful Auth After Failures** - Success after 3+ failures
3. **AUTH-003: Distributed Brute Force** - Same user from 3+ IPs
4. **AUTH-004: Account Enumeration** - 10+ different usernames from same IP
5. **AUTH-006: After-Hours Authentication** - Logins during unusual hours
6. **AUTH-010: Cross-Service Credential Stuffing** - Same IP failing on multiple services

**Service-Specific:**
- **Authelia:** Monitor MFA failures, session anomalies
- **authentik:** Track flow execution failures, admin events
- **Keycloak:** Monitor admin events, client authentication, token abuse

---

## Appendix C: Troubleshooting

### Common Issues Across All Parsers

**Issue: JSON not parsing**

**Symptoms:**
- Logs appear in raw_logs
- parsed_data is null
- No fields extracted

**Solutions:**
1. Verify application outputs JSON logs (check container logs)
2. Test log line with `jq` to verify valid JSON:
   ```bash
   echo 'log line' | jq .
   ```
3. Check for text-based logging (older versions)
4. Verify parser_type is "json"
5. Check field_mappings use correct JSON paths

**Issue: Nested fields not extracting**

**Symptoms:**
- Top-level fields work
- Nested fields are null
- Details/context missing

**Solutions:**
1. Use dot notation in field_mappings:
   - `user.username` not `username`
   - `details.reason` not `reason`
   - `context.auth_method` not `auth_method`
2. Verify nested path is correct (check actual JSON)
3. Test parser with full JSON log
4. Some nested fields may be optional (null is normal)

**Issue: Username missing in some logs**

**Symptoms:**
- Username field is null
- Only some logs have username
- Unauthenticated events missing user

**Solutions:**
- This is NORMAL for unauthenticated events
- Failed logins may not have username
- API verification before auth won't have username
- Check nested location (details.username, user.username)

**Issue: Timestamps not correlating**

**Symptoms:**
- Event times don't match
- Timezone issues
- Correlation problems

**Solutions:**
1. **Authelia:** Uses ISO 8601 with timezone offset
2. **authentik:** Uses UTC ISO 8601
3. **Keycloak:** Uses Unix milliseconds
4. Convert all to UTC for correlation
5. Detection rules should use timestamp field consistently

### Service-Specific Issues

**Authelia:**

**Issue: No logs appearing**

Check Authelia configuration for log output:
```yaml
# configuration.yml
log:
  level: info
  format: json  # Required for parser
  file_path: /config/authelia.log  # Or omit for stdout
```

**Issue: MFA events not logging**

- Authelia logs 1FA and 2FA separately
- Check for `/api/secondfactor/*` paths
- Both success and failure logged
- Verify MFA is actually configured

**authentik:**

**Issue: Flow events missing**

- Flow logging may be disabled
- Check authentik settings: System → Settings → Event retention
- Enable flow execution logging
- Flow events generate many logs (can be noisy)

**Issue: Context field too large**

- authentik's context can be very detailed
- Store full context for forensics
- Use nested field extraction for detection
- Consider log retention for large context objects

**Keycloak:**

**Issue: Admin events not logging**

Enable admin events:
1. Realm Settings → Events tab
2. Enable "Save Events"
3. Enable "Admin Events"
4. Set "Event Listeners" to include "jboss-logging"

**Issue: Event types not recognized**

Keycloak has many event types:
- LOGIN, LOGIN_ERROR
- LOGOUT
- CODE_TO_TOKEN, CODE_TO_TOKEN_ERROR
- REFRESH_TOKEN, REFRESH_TOKEN_ERROR
- CLIENT_LOGIN, CLIENT_LOGIN_ERROR
- And many more

Detection rules should handle multiple event types.

**Issue: Multiple realms**

- Keycloak supports multiple realms
- Events include `realmId` field
- Create realm-specific rules if needed
- Track cross-realm attacks

### Performance Considerations

**High Log Volume:**

Authentication services can generate many logs:
- Authelia: Moderate (every auth attempt + API verify)
- authentik: High (every flow step + events)
- Keycloak: Very High (comprehensive events)

**Optimization:**
1. Adjust log retention policies
2. Filter non-security events at shipper
3. Use aggregation in detection rules
4. Consider separate storage for audit logs

**Parser Priority:**

All auth parsers use priority 65-67:
- Should be higher priority than generic parsers
- Lower than critical parsers (60-64 reserved)
- Adjust if conflicts occur

### Getting Help

**Before asking for help:**

1. Verify JSON logs are being generated
2. Test parser with actual log line
3. Check field mappings match your log format
4. Verify log shipper is forwarding logs
5. Review SIEMBox backend logs for errors

**When reporting issues:**

Include:
- Exact parser configuration (JSON)
- Sample log line (sanitized)
- Expected vs actual field extraction
- Parser test results from UI
- SIEMBox version
- Authentication service and version
- Configuration files (sanitized)

**Resources:**

- GitHub Issues: https://github.com/cladkins/SIEMBOX/issues
- Discussions: https://github.com/cladkins/SIEMBOX/discussions
- Documentation: https://github.com/cladkins/SIEMBOX

---

## Conclusion

These 3 authentication service parsers provide comprehensive coverage for the most popular SSO solutions in homelabs:

1. **Authelia** - Most popular SSO (390 users)
2. **authentik** - Modern identity provider (268 users)
3. **Keycloak** - Enterprise-grade IAM (158 users)

Together with the 6 reverse proxy parsers, these form the foundation of homelab security monitoring.

### What These Parsers Enable

**Detection Capabilities:**
- Brute force authentication attacks
- Credential stuffing from breached databases
- Account enumeration attempts
- Successful auth after failures (attack success)
- Distributed attacks from multiple IPs
- Session hijacking patterns
- API token abuse
- Admin privilege changes
- Cross-service correlation

**Security Benefits:**
- Early detection of credential attacks
- Prevent account takeover
- Track authentication patterns
- Audit administrative changes
- Forensic investigation support
- Compliance audit trails

**Next Steps:**

1. Install parsers for your authentication service(s)
2. Configure log shipper to forward auth logs
3. Test parser with sample logs
4. Import authentication detection rules
5. Tune thresholds for your environment
6. Monitor alerts and refine

**Remember:** Authentication systems are the second most critical monitoring priority. These parsers directly support 10+ detection rules from the homelab threat model (AUTH-001 through AUTH-010).

**Integration with Reverse Proxy Parsers:**

These authentication parsers work together with reverse proxy parsers to provide defense-in-depth:
- Reverse proxies detect injection attacks
- Authentication services detect credential attacks
- Together they cover primary attack surfaces
- Correlation enables advanced threat detection

---

**Document Version:** 1.0
**Last Updated:** 2025-12-03
**Compatible with:** SIEMBox 1.0+
**Parsers Included:** 3 (Authelia, authentik, Keycloak)
**Total Coverage:** 817 homelab users (1,169 total auth users)

---
