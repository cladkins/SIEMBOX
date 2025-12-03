# Vaultwarden Parser Implementation Guide

## Overview

The Vaultwarden parser is CRITICAL priority (55 - highest in the system) because Vaultwarden compromise means ALL stored credentials are compromised. This parser must extract fields needed by 5 detection rules:

- **AUTH-005** (CRITICAL): Vaultwarden master password failures
- **PWDMGR-001** (CRITICAL): Vault export detection
- **PWDMGR-002** (HIGH): Multiple device registrations
- **PWDMGR-003** (HIGH): Unusual vault geolocation access
- **PWDMGR-004** (HIGH): API token abuse

## Vaultwarden Log Format

Vaultwarden logs follow this structure:
```
[TIMESTAMP][MODULE][LEVEL] MESSAGE [additional fields]
```

Example logs:
```
[2025-12-03 12:34:56.789][vaultwarden::api::identity][WARN] Failed login attempt from IP: 192.168.1.100, Email: admin@example.com
[2025-12-03 12:37:45.789][vaultwarden::api::core][WARN] Vault export initiated by admin@example.com from 192.168.1.100
[2025-12-03 12:40:00.678][vaultwarden::api::identity][INFO] New device registered for admin@example.com from 192.168.1.100, Device: Chrome/Desktop
```

## Required Fields for Detection Rules

### AUTH-005: Master Password Failures
Needs:
- `service`: "vaultwarden"
- `message`: Contains "Invalid password" OR "Failed login attempt"
- `source_ip`: Client IP for aggregation

### PWDMGR-001: Vault Export
Needs:
- `service`: "vaultwarden"
- `action`: "vault_export" (derived from message)
- `user`: Email of user performing export
- `source_ip`: Client IP

### PWDMGR-002: Multiple Device Registrations
Needs:
- `service`: "vaultwarden"
- `event`: "device_registered" (derived from message)
- `user`: Email of user
- `source_ip`: Client IP (optional)

### PWDMGR-003: Unusual Vault Geolocation
Needs:
- `service`: "vaultwarden"
- `event`: "vault_accessed" OR "login_success"
- `country`: Will be added by GeoIP enrichment
- `source_ip`: Client IP for GeoIP lookup
- `user`: Email of user

### PWDMGR-004: API Token Abuse
Needs:
- `service`: "vaultwarden"
- `path`: API endpoint path (e.g., "/api/sync")
- `source_ip`: Client IP for aggregation
- `status_code`: HTTP status (if available)

## Implementation Challenge

The Vaultwarden log format doesn't explicitly provide `action`, `event`, or `path` fields. These must be derived from the `message` and `module` fields using pattern matching.

## Solution: Post-Processing Enhancement

### Option 1: Multiple Specialized Parsers (RECOMMENDED)

Create separate parsers for different Vaultwarden log types:

1. **vaultwarden-auth** (Priority 55)
   - Matches: Authentication logs (login success/failure)
   - Module: `vaultwarden::api::identity`
   - Extracts: email, source_ip, event (success/failure)

2. **vaultwarden-vault-operations** (Priority 54)
   - Matches: Vault operations (export, sync, access)
   - Module: `vaultwarden::api::core`
   - Extracts: action field from message

3. **vaultwarden-device** (Priority 53)
   - Matches: Device registration logs
   - Module: `vaultwarden::api::identity` + "device registered"
   - Extracts: device, event="device_registered"

4. **vaultwarden-api** (Priority 52)
   - Matches: API calls
   - Module: `vaultwarden::api::`
   - Extracts: path, status_code (if available)

### Option 2: Single Parser with Field Transformation (CURRENT APPROACH)

Use one parser that extracts all possible fields, then add post-processing logic to derive `action` and `event` from the `message` field.

**Field Mappings:**
```json
{
  "timestamp": "timestamp",
  "module": "module",
  "log_level": "log_level",
  "message": "message",
  "client_ip": "client_ip",
  "source_ip": "client_ip",
  "email": "email",
  "user": "email",
  "admin_email": "admin_email",
  "admin_ip": "admin_ip",
  "device": "device",
  "service": "vaultwarden"  // Static value
}
```

**Post-Processing Rules:**

```typescript
// Add this logic in parserEngine.ts after field extraction
if (fields.service === 'vaultwarden') {
  // Derive action from message
  if (fields.message.includes('Vault export')) {
    fields.action = 'vault_export';
  } else if (fields.message.includes('Vault import')) {
    fields.action = 'vault_import';
  } else if (fields.message.includes('Vault sync')) {
    fields.action = 'vault_sync';
  } else if (fields.message.includes('Vault accessed')) {
    fields.action = 'vault_access';
  }

  // Derive event from message
  if (fields.message.includes('Failed login') || fields.message.includes('Invalid password')) {
    fields.event = 'login_failure';
  } else if (fields.message.includes('Successful login')) {
    fields.event = 'login_success';
  } else if (fields.message.includes('device registered')) {
    fields.event = 'device_registered';
  } else if (fields.message.includes('API authentication failed')) {
    fields.event = 'api_auth_failure';
  }

  // Derive path from module (rough approximation)
  if (fields.module.includes('::api::core')) {
    fields.path = '/api/core';
  } else if (fields.module.includes('::api::identity')) {
    fields.path = '/api/identity';
  } else if (fields.module.includes('::api::admin')) {
    fields.path = '/admin';
  }
}
```

## Recommendation

Start with **Option 2** (single parser with post-processing) because:
1. Faster to implement
2. Works with current backend architecture
3. Can be enhanced later if needed
4. Provides all fields needed by detection rules

If we encounter performance issues or need more precision, we can migrate to **Option 1** (multiple specialized parsers).

## Implementation Steps

### Step 1: Database Migration
Run `004-add-vaultwarden-parser.sql` to create the base parser

### Step 2: Enhance Parser Engine
Add post-processing logic to `backend/src/services/parser/parserEngine.ts`:

```typescript
// After line 125 (after field extraction in applyRegexParser)
// Add post-processing for specific parsers
fields = this.postProcessFields(parser.name, fields);

// New method:
private postProcessFields(parserName: string, fields: Record<string, any>): Record<string, any> {
  // Vaultwarden-specific field derivation
  if (parserName === 'vaultwarden-access' && fields.message) {
    const message = fields.message.toLowerCase();

    // Derive action field
    if (message.includes('vault export')) {
      fields.action = 'vault_export';
    } else if (message.includes('vault import')) {
      fields.action = 'vault_import';
    } else if (message.includes('vault sync')) {
      fields.action = 'vault_sync';
    } else if (message.includes('vault accessed')) {
      fields.action = 'vault_access';
    }

    // Derive event field
    if (message.includes('failed login') || message.includes('invalid password')) {
      fields.event = 'login_failure';
    } else if (message.includes('successful login')) {
      fields.event = 'login_success';
    } else if (message.includes('device registered')) {
      fields.event = 'device_registered';
    } else if (message.includes('api authentication failed')) {
      fields.event = 'api_auth_failure';
    }

    // Derive path from module
    if (fields.module) {
      if (fields.module.includes('::api::core')) {
        fields.path = '/api/core';
      } else if (fields.module.includes('::api::identity')) {
        fields.path = '/api/identity';
      } else if (fields.module.includes('::api::admin')) {
        fields.path = '/admin';
      }
    }

    // Ensure service field is always set
    fields.service = 'vaultwarden';
  }

  return fields;
}
```

### Step 3: Test with Sample Logs

Create test script `backend/test-vaultwarden-parser.ts`:

```typescript
import { ParserEngine } from './src/services/parser/parserEngine';

const sampleLogs = [
  "[2025-12-03 12:34:56.789][vaultwarden::api::identity][WARN] Failed login attempt from IP: 192.168.1.100, Email: admin@example.com",
  "[2025-12-03 12:37:45.789][vaultwarden::api::core][WARN] Vault export initiated by admin@example.com from 192.168.1.100",
  "[2025-12-03 12:40:00.678][vaultwarden::api::identity][INFO] New device registered for admin@example.com from 192.168.1.100, Device: Chrome/Desktop",
];

async function test() {
  const engine = new ParserEngine();
  await engine.initialize();

  for (const log of sampleLogs) {
    console.log('Testing:', log);
    // Test parsing logic
  }
}

test();
```

### Step 4: Validate Detection Rules

After parser is deployed, verify each rule works:
- AUTH-005: Generate 3 failed logins, verify alert triggers
- PWDMGR-001: Simulate vault export, verify critical alert
- PWDMGR-002: Register 3 devices in 1 hour, verify alert
- PWDMGR-003: (Requires GeoIP enrichment first)
- PWDMGR-004: Make 50+ API calls in 10 minutes, verify alert

## Alternative: Wait for Real Vaultwarden Logs

Since we don't have real Vaultwarden logs to analyze, we could:
1. Deploy a test Vaultwarden instance
2. Capture real logs from various operations
3. Refine parser based on actual log format
4. Update detection rules if needed

This is more accurate but takes longer.

## Decision

**Recommendation:** Proceed with Option 2 (post-processing enhancement) using the migration file already created. Add the post-processing logic to parserEngine.ts in Step 2. This unblocks 5 detection rules immediately.

Once we have real Vaultwarden logs from production, we can refine the parser as needed.

## Testing Checklist

- [ ] Migration runs successfully
- [ ] Parser appears in database with priority 55
- [ ] Parser matches failed login logs
- [ ] Parser matches vault export logs
- [ ] Parser matches device registration logs
- [ ] Post-processing correctly sets `action` field
- [ ] Post-processing correctly sets `event` field
- [ ] Post-processing correctly sets `path` field
- [ ] Post-processing correctly sets `service` field
- [ ] AUTH-005 rule triggers on 3 failed logins
- [ ] PWDMGR-001 rule triggers on vault export
- [ ] PWDMGR-002 rule triggers on 3 device registrations
- [ ] PWDMGR-004 rule triggers on 50+ API calls

## Known Limitations

1. **API path extraction is approximated** - We use module name instead of actual HTTP path
   - Impact: PWDMGR-004 might have false positives/negatives
   - Fix: Requires Vaultwarden to log actual HTTP paths

2. **Status codes not available** - Vaultwarden logs don't include HTTP status codes
   - Impact: Can't filter API calls by success/failure status
   - Fix: Configure Vaultwarden reverse proxy to log API calls with status codes

3. **No session tracking** - Can't correlate multiple actions in same session
   - Impact: Can't detect session hijacking patterns
   - Fix: Future enhancement - add session correlation engine

4. **Message patterns may change** - Future Vaultwarden versions might change log messages
   - Impact: Parser might break on Vaultwarden updates
   - Fix: Add parser versioning and update tests when Vaultwarden updates

## Future Enhancements

1. **JSON logging** - Configure Vaultwarden to output JSON logs instead of text
   - Makes parsing more reliable
   - Easier to add new fields
   - Less regex brittleness

2. **Reverse proxy integration** - Use reverse proxy logs for API monitoring
   - NGINX/Traefik can log all HTTP details
   - More accurate path and status code data
   - Already have reverse proxy parsers from Phase 2A

3. **Session correlation** - Track user sessions across logs
   - Detect session hijacking
   - Identify suspicious session patterns
   - Requires backend enhancement

4. **Behavioral baselines** - Learn normal user behavior
   - Alert on deviations from normal patterns
   - Reduce false positives
   - Requires machine learning integration
