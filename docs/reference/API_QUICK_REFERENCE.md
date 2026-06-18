# SIEMBox API Quick Reference

Quick reference guide for common SIEMBox API operations. For complete documentation, see [API.md](../../API.md).

## Base URL

```
http://localhost:8421/api
```

## Authentication

All endpoints (except `/auth/login`) require a JWT bearer token:

```bash
Authorization: Bearer <your-jwt-token>
```

### Get Token

```bash
POST /api/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "changeme"
}

# Response
{
  "message": "Login successful",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "username": "admin",
    "role": "admin"
  }
}
```

---

## Quick Command Reference

### Authentication

```bash
# Login
curl -X POST http://localhost:8421/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"changeme"}'

# Logout
curl -X POST http://localhost:8421/api/auth/logout \
  -H "Authorization: Bearer $TOKEN"
```

### Logs

```bash
# Get raw logs (latest 100)
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8421/api/logs/raw?limit=100"

# Get parsed logs with filters
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8421/api/logs/parsed?source_ip=192.168.1.100&limit=50"

# Search logs
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8421/api/logs/parsed?search=error&limit=100"
```

### Parsers

```bash
# List all parsers
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8421/api/parsers"

# Get specific parser
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8421/api/parsers/1"

# Create parser
curl -X POST http://localhost:8421/api/parsers \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-parser",
    "description": "My custom parser",
    "pattern": "^(?<field>.*)",
    "pattern_type": "regex",
    "priority": 50,
    "enabled": true
  }'

# Test parser
curl -X POST http://localhost:8421/api/parsers/test \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "pattern": "^(?<ip>\\d+\\.\\d+\\.\\d+\\.\\d+)",
    "pattern_type": "regex",
    "test_message": "192.168.1.100 - test message"
  }'
```

### Detection Rules

```bash
# List all rules
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8421/api/rules"

# Get specific rule
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8421/api/rules/1"

# Create rule
curl -X POST http://localhost:8421/api/rules \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Failed Login Detection",
    "description": "Detects failed login attempts",
    "severity": "medium",
    "enabled": true,
    "conditions": [
      {
        "field": "message",
        "operator": "contains",
        "value": "Failed password"
      }
    ]
  }'

# Reload rules engine
curl -X POST http://localhost:8421/api/rules/reload \
  -H "Authorization: Bearer $TOKEN"
```

### Alerts

```bash
# Get all alerts
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8421/api/alerts"

# Filter by severity
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8421/api/alerts?severity=high"

# Get unacknowledged alerts
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8421/api/alerts?acknowledged=false"

# Acknowledge alert
curl -X PUT http://localhost:8421/api/alerts/1/acknowledge \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"notes": "Investigated - false positive"}'
```

### Users

```bash
# List users (admin only)
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8421/api/users"

# Create user (admin only)
curl -X POST http://localhost:8421/api/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "analyst1",
    "password": "SecurePassword123",
    "role": "analyst"
  }'

# Update user (admin only)
curl -X PUT http://localhost:8421/api/users/2 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role": "viewer"}'
```

### Log Shippers

```bash
# List shippers
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8421/api/shippers"

# Get shipper config (shipper uses this)
curl "http://localhost:8421/api/shippers/config/YOUR_API_KEY"

# Register shipper (shipper uses this)
curl -X POST http://localhost:8421/api/shippers/register \
  -H "Content-Type: application/json" \
  -d '{"api_key": "YOUR_64_CHAR_API_KEY"}'

# Regenerate shipper API key (admin only)
curl -X POST http://localhost:8421/api/shippers/1/regenerate-key \
  -H "Authorization: Bearer $TOKEN"
```

### Assets

```bash
# List assets
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8421/api/assets"

# Get asset details
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8421/api/assets/1"

# Create scan
curl -X POST http://localhost:8421/api/assets/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Network Scan",
    "scan_type": "port",
    "targets": ["192.168.1.0/24"],
    "ports": "22,80,443"
  }'

# Get scan status
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8421/api/assets/scans/1"
```

### Settings

```bash
# Get settings
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8421/api/settings"

# Update retention settings (admin only)
curl -X PUT http://localhost:8421/api/settings \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "raw_logs_retention_days": 30,
    "parsed_logs_retention_days": 90,
    "alerts_retention_days": 365
  }'
```

---

## Common Query Parameters

### Pagination

```bash
?limit=100&offset=0
```

- `limit`: Number of results (default: 100, max: 1000)
- `offset`: Skip this many results (default: 0)

### Date Filtering

```bash
?start_date=2025-01-01&end_date=2025-01-31
```

- `start_date`: ISO 8601 format (YYYY-MM-DD)
- `end_date`: ISO 8601 format (YYYY-MM-DD)

### Sorting

```bash
?sort_by=created_at&sort_order=desc
```

- `sort_by`: Field name
- `sort_order`: `asc` or `desc`

### Search

```bash
?search=keyword
```

Performs case-insensitive search across relevant fields.

---

## Response Formats

### Success Response

```json
{
  "data": [...],      // Response data
  "total": 150,       // Total count (for paginated)
  "limit": 100,       // Results per page
  "offset": 0         // Current offset
}
```

### Error Response

```json
{
  "status": "error",
  "statusCode": 400,
  "message": "Invalid input parameters"
}
```

---

## HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 201 | Created |
| 400 | Bad Request (invalid input) |
| 401 | Unauthorized (missing/invalid token) |
| 403 | Forbidden (insufficient permissions) |
| 404 | Not Found |
| 429 | Too Many Requests (rate limited) |
| 500 | Internal Server Error |

---

## Rate Limits

| Endpoint | Limit |
|----------|-------|
| General API | 100 requests / 15 minutes |
| Asset scans | 10 scans / 15 minutes |
| Vulnerability scans | 5 scans / 30 minutes |
| Credential operations | 20 requests / hour |
| Audit logs | 30 requests / 5 minutes |

Rate limit headers:
```
RateLimit-Limit: 100
RateLimit-Remaining: 95
RateLimit-Reset: 1704812400
```

---

## Common Filter Examples

### Logs by IP Address

```bash
GET /api/logs/parsed?source_ip=192.168.1.100
```

### Logs by Time Range

```bash
GET /api/logs/parsed?start_date=2025-01-01&end_date=2025-01-31
```

### High Severity Alerts

```bash
GET /api/alerts?severity=high
GET /api/alerts?severity=critical
```

### Unacknowledged Alerts

```bash
GET /api/alerts?acknowledged=false
```

### Recent Logs (Last 1000)

```bash
GET /api/logs/parsed?limit=1000&sort_by=created_at&sort_order=desc
```

### Search Logs for Keywords

```bash
GET /api/logs/parsed?search=error
GET /api/logs/parsed?search=failed%20login
```

---

## JavaScript/TypeScript Examples

### Using Axios

```typescript
import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:8421/api',
  headers: {
    'Content-Type': 'application/json'
  }
});

// Set token after login
api.defaults.headers.common['Authorization'] = `Bearer ${token}`;

// Get logs
const logs = await api.get('/logs/parsed', {
  params: {
    limit: 100,
    source_ip: '192.168.1.100'
  }
});

// Create parser
const parser = await api.post('/parsers', {
  name: 'my-parser',
  pattern: '^(?<field>.*)',
  pattern_type: 'regex',
  priority: 50,
  enabled: true
});

// Acknowledge alert
await api.put(`/alerts/${alertId}/acknowledge`, {
  notes: 'Investigated - false positive'
});
```

### Using Fetch

```javascript
// Login
const loginResponse = await fetch('http://localhost:8421/api/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    username: 'admin',
    password: 'changeme'
  })
});
const { token } = await loginResponse.json();

// Get logs
const logsResponse = await fetch('http://localhost:8421/api/logs/parsed?limit=100', {
  headers: { 'Authorization': `Bearer ${token}` }
});
const { data: logs } = await logsResponse.json();
```

---

## Python Examples

### Using Requests

```python
import requests

base_url = 'http://localhost:8421/api'

# Login
response = requests.post(f'{base_url}/auth/login', json={
    'username': 'admin',
    'password': 'changeme'
})
token = response.json()['token']

# Set headers
headers = {'Authorization': f'Bearer {token}'}

# Get logs
response = requests.get(f'{base_url}/logs/parsed',
    headers=headers,
    params={'limit': 100, 'source_ip': '192.168.1.100'}
)
logs = response.json()['data']

# Create parser
response = requests.post(f'{base_url}/parsers',
    headers=headers,
    json={
        'name': 'my-parser',
        'pattern': '^(?<field>.*)',
        'pattern_type': 'regex',
        'priority': 50,
        'enabled': True
    }
)
```

---

## Bash Script Example

```bash
#!/bin/bash

BASE_URL="http://localhost:8421/api"

# Login and get token
TOKEN=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"changeme"}' \
  | jq -r '.token')

# Get logs
curl -s -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/logs/parsed?limit=100" \
  | jq '.data[] | {timestamp: .created_at, message: .raw_message}'

# Get high severity alerts
curl -s -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/alerts?severity=high" \
  | jq '.data[] | {rule: .rule_name, time: .created_at}'
```

---

## Testing with Postman

1. **Import Collection**: Create requests for common endpoints
2. **Set Environment Variables**:
   - `base_url`: `http://localhost:8421/api`
   - `token`: `<your-jwt-token>`
3. **Use Collection Variables**: `{{base_url}}/logs/parsed`
4. **Set Authorization**: Bearer Token → `{{token}}`

---

## WebSocket Support (Future)

WebSocket support for real-time updates is planned for future releases. This will enable:
- Real-time alert notifications
- Live log streaming
- Dashboard auto-refresh

---

## Need More Details?

**API Documentation:**
- **Complete API Docs**: [API.md](../../API.md) - Full REST API reference
- **Backend Development**: [backend/README.md](../../backend/README.md) - API development guide

**Application Guides:**
- **Parser Guide**: [PARSERS.md](../../PARSERS.md) - Creating and managing parsers
- **Rules Guide**: [RULES.md](../../RULES.md) - Detection rule configuration
- **Getting Started**: [Getting Started (Development)](../guides/GETTING_STARTED_DEVELOPMENT.md) - Development setup

**Support:**
- **FAQ**: [FAQ.md](../../FAQ.md) - Frequently asked questions
- **Glossary**: [GLOSSARY.md](../../GLOSSARY.md) - Technical terminology
- **Troubleshooting**: [docs/operations/TROUBLESHOOTING.md](../operations/TROUBLESHOOTING.md) - Common issues
