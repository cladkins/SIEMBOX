# Asset Discovery - Deployment and Testing Guide

## Overview

This guide walks through deploying and testing the Asset Discovery Phase 0 & 1 implementation. The features enable automated network asset discovery, NMAP scanning, and vulnerability baseline management within SIEMBox.

**Status**: Phase 0 & 1 complete and committed to `develop` branch
**Target**: Testing on remote Docker environment
**Database Impact**: Pre-v1.0 schema changes (database reset recommended)

## What Was Implemented

### Phase 0: Security Foundation

The security groundwork for all asset discovery and scanning operations:

**Role-Based Access Control (RBAC)**
- 4-tier role hierarchy: Viewer < Analyst < Operator < Admin
- Viewer: Read-only access to asset inventory
- Analyst: Can trigger asset discovery scans and auto-discovery
- Operator: Can manage vulnerability scans and remediation
- Admin: Full access including credential management
- Enforced via `/backend/src/middleware/scanPermissions.ts`

**Audit Logging**
- Logs all security-sensitive operations (scans, credential changes, etc.)
- Automatic redaction of sensitive fields (passwords, API keys)
- Tracks user context: IP, user agent, timestamp, request/response
- 1-year retention policy (configurable)
- Service: `/backend/src/services/audit/auditService.ts`
- Database table: `audit_logs`

**Credential Encryption**
- AES-256-GCM encryption for stored credentials
- Credentials never logged in plaintext
- Supports username/password and SSH key pairs
- Environment-based key management
- Database table: `scan_credentials`

**Database Schema Expansion**
- 7 new tables for asset management and scanning
- Comprehensive indexes for performance
- JSONB columns for flexible metadata storage

**Input Validation & Rate Limiting**
- Scan request validation (targets, scan types)
- Rate limiting: 10 scans per 15 minutes per user
- SQL injection prevention via parameterized queries
- CIDR notation validation for IP ranges

### Phase 1: Asset Discovery

Complete asset discovery infrastructure with NMAP integration and log correlation:

**Backend API (10 Endpoints)**

Asset Management:
- `GET /api/assets` - List all assets with filtering and pagination
- `GET /api/assets/:id` - Get asset details with services
- `POST /api/assets` - Create/add asset manually
- `PUT /api/assets/:id` - Update asset properties
- `DELETE /api/assets/:id` - Delete asset
- `GET /api/assets/:id/services` - Get services running on asset

Asset Discovery:
- `POST /api/assets/scan` - Trigger NMAP scan (Analyst+)
- `GET /api/assets/scans/:scanId` - Get scan status and results
- `GET /api/assets/scans` - Get recent scans
- `POST /api/assets/discover` - Trigger log-based auto-discovery (Analyst+)

Statistics & Metadata:
- `GET /api/assets/statistics` - Asset discovery statistics

**NMAP Scanner Service**
- Scan types: ping, port, service, OS detection
- Async execution with background job processing
- Result parsing and asset creation
- Service enumeration and versioning
- Automatic stale asset detection (30-day threshold)

**Auto-Discovery Service**
- Correlates IPs and hostnames from raw logs
- Extracts source IPs from parsed logs
- Enriches assets with additional metadata
- Runs every 6 hours automatically
- Manual trigger available via API

**Frontend Asset Management UI**
- Asset Inventory page with table view
- Advanced search by IP, hostname, or metadata
- Filter by asset type, criticality, and status
- Asset details modal with tabs:
  - Services tab: Shows ports, protocols, banners
  - Metadata tab: Raw JSON asset data
- Trigger NMAP scan dialog
- Asset deletion with confirmation
- Role-based UI element visibility

**Background Job System**
- Auto-discovery job: Every 6 hours
- Scan result processing: Real-time
- Stale asset marking: Every 24 hours
- Graceful error handling and logging

## Prerequisites

### System Requirements
- Remote Docker server running SIEMBox
- Docker Compose v2.0+
- PostgreSQL 13+ (already running in container)
- NMAP 7.x (will be installed in container)
- 2GB available disk space for database
- Network access to scan targets (local network recommended for testing)

### Access Requirements
- SSH access to remote Docker server
- Admin user credentials for SIEMBox
- Git access to pull latest `develop` branch

### Database Backup (Highly Recommended)
Before schema changes, create a backup:
```bash
docker compose exec postgres pg_dump -U siembox siembox > /tmp/siembox_backup_$(date +%s).sql
```

## Deployment Steps

### 1. Pull Latest Changes

On your remote Docker server:

```bash
cd /path/to/SIEMBox
git fetch origin
git checkout develop
git pull origin develop
```

Verify you're on the correct branch and commits:
```bash
git log --oneline -5
# Should show:
# fe36cb0 feat: implement Phase 1 Assets & Vulnerabilities frontend UI
# a93d0e5 feat: implement Phase 1 Asset Discovery backend
# d6a5ea8 feat: implement comprehensive security foundation for scanning features
```

### 2. Update Dependencies

**Backend** - Install NMAP and additional dependencies:
```bash
cd backend
npm install
```

Verify node-nmap is installed:
```bash
npm ls node-nmap
# Should show: node-nmap@2.x.x
```

**Frontend** - Refresh dependencies:
```bash
cd frontend
npm install
```

### 3. Database Migration - Pre-v1.0 Schema Changes

SIEMBox is pre-v1.0, and database schema changes require careful handling. Choose one approach:

**Option A: Reset Database (Recommended for Testing)**

This approach is safe for testing environments and clears all existing data.

```bash
# Stop all containers
docker compose down

# Remove database volume to start fresh
docker volume rm siembox_postgres_data

# Start fresh with new schema
docker compose up -d

# Wait for PostgreSQL to initialize (important!)
sleep 15

# Verify tables were created
docker compose exec postgres psql -U siembox -d siembox -c "\dt"
# Should list: assets, asset_services, audit_logs, scan_credentials, etc.
```

**Option B: Preserve Existing Data (Advanced)**

If you have important logs to preserve:

```bash
# Backup current database
docker compose exec postgres pg_dump -U siembox siembox > /tmp/siembox_backup.sql

# Stop containers but keep volumes
docker compose down

# Start PostgreSQL only
docker compose up -d postgres

# Wait for startup
sleep 10

# Run the schema migration
docker compose exec postgres psql -U siembox -d siembox < backend/migrations/001_initial_schema.sql

# Start remaining services
docker compose up -d
```

**Verify Schema Creation:**

```bash
# Check that all asset tables exist
docker compose exec postgres psql -U siembox -d siembox -c "\dt audit_logs assets asset_services vulnerabilities vulnerability_scans scan_credentials"

# Expected output shows 6 new tables:
# audit_logs | table | siembox
# assets     | table | siembox
# etc.
```

### 4. Generate Encryption Key

The credential encryption system requires a 32-byte encryption key. Add to your `.env`:

```bash
# Generate key
ENCRYPTION_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")

# Add to .env file
echo "CREDENTIAL_ENCRYPTION_KEY=$ENCRYPTION_KEY" >> .env

# Verify it was added
grep CREDENTIAL_ENCRYPTION_KEY .env
# Should show: CREDENTIAL_ENCRYPTION_KEY=<64 hex characters>
```

### 5. Update Environment Configuration

Ensure `.env` includes required variables:

```bash
# Database
DATABASE_URL=postgresql://siembox:siembox@postgres:5432/siembox

# Encryption (added in step 4)
CREDENTIAL_ENCRYPTION_KEY=<your-generated-key>

# NMAP settings (optional, defaults work)
NMAP_TIMEOUT=300
NMAP_MAX_PARALLEL_SCANS=3

# Auto-discovery settings (optional)
AUTO_DISCOVERY_INTERVAL=360  # 6 hours in minutes
STALE_ASSET_THRESHOLD=30     # days
```

### 6. Rebuild and Restart Containers

```bash
# Build images with latest code
docker compose build

# Restart all services
docker compose up -d

# Wait for services to be ready
sleep 10

# Check logs for errors
docker compose logs --tail=50 backend
docker compose logs --tail=50 frontend
```

### 7. Verify Deployment Success

**Backend health check:**
```bash
# Should return: {"message":"OK"}
curl -s http://localhost:5000/api/health | jq .
```

**Frontend health check:**
```bash
# Should return HTML (frontend is running)
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000
# Should show: 200
```

**Check application logs:**
```bash
docker compose logs backend | grep -E "Server listening|Asset discovery|Error"
docker compose logs frontend | tail -20
```

**Expected successful startup messages:**
```
Backend:
- Server listening on port 5000
- [Auto-Discovery] Starting periodic discovery job (6h interval)
- Database connected
- Audit logging initialized

Frontend:
- Vite v4.x.x  ready in XXX ms
- Local: http://localhost:3000
```

## Testing Phase 0: Security Foundation

### Test 1: RBAC System Enforcement

**Objective**: Verify that role-based access control prevents unauthorized scan operations.

**Verify Roles Exist:**
```bash
docker compose exec postgres psql -U siembox -d siembox -c "SELECT id, username, role FROM users ORDER BY id;"
```

**Expected Output:**
```
 id | username | role
----+----------+-------
  1 | admin    | admin
  2 | analyst  | analyst      # (if created)
  3 | viewer   | viewer       # (if created)
```

**Test Role Enforcement:**

1. Login to SIEMBox UI with admin user (http://localhost:3000)
2. Navigate to Assets page (should be visible)
3. Look for "Trigger Scan" button (should be present for admin)
4. Verify scan options are available

**Create Test Users:**
```bash
# Create analyst user (has scan permissions)
curl -X POST http://localhost:5000/api/users \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "analyst_test",
    "email": "analyst@test.local",
    "password": "TestPassword123!",
    "role": "analyst"
  }'

# Create viewer user (no scan permissions)
curl -X POST http://localhost:5000/api/users \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "viewer_test",
    "email": "viewer@test.local",
    "password": "TestPassword123!",
    "role": "viewer"
  }'
```

**Test Viewer Access (Should Fail):**
```bash
# Login as viewer
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "viewer_test", "password": "TestPassword123!"}' \
  | jq '.token' | tr -d '"' > /tmp/viewer_token.txt

# Try to trigger scan (should return 403 Forbidden)
curl -X POST http://localhost:5000/api/assets/scan \
  -H "Authorization: Bearer $(cat /tmp/viewer_token.txt)" \
  -H "Content-Type: application/json" \
  -d '{"targets": ["192.168.1.1"], "scanType": "ping"}' \
  -w "\nHTTP Status: %{http_code}\n"

# Expected: HTTP 403
# Response: { "error": "Insufficient permissions for asset scanning" }
```

**Test Analyst Access (Should Succeed):**
```bash
# Login as analyst
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "analyst_test", "password": "TestPassword123!"}' \
  | jq '.token' | tr -d '"' > /tmp/analyst_token.txt

# Trigger scan (should return 202 Accepted)
curl -X POST http://localhost:5000/api/assets/scan \
  -H "Authorization: Bearer $(cat /tmp/analyst_token.txt)" \
  -H "Content-Type: application/json" \
  -d '{"targets": ["192.168.1.1"], "scanType": "ping"}' \
  -w "\nHTTP Status: %{http_code}\n"

# Expected: HTTP 202
# Response: { "message": "Scan initiated successfully", "scanId": 1, "status": "queued" }
```

**Test Result:**
- [ ] Viewer gets 403 error when attempting scan
- [ ] Analyst gets 202 success when triggering scan
- [ ] Admin can perform all operations
- [ ] Menu items show/hide based on role in UI

### Test 2: Audit Logging

**Objective**: Verify that all security-sensitive actions are logged with proper context and no sensitive data is exposed.

**Trigger an Audit Event:**
1. Login as analyst user
2. Navigate to Assets page
3. Click "Trigger Scan" button
4. Submit a scan request

**Check Audit Logs:**
```bash
# View recent audit logs
docker compose exec postgres psql -U siembox -d siembox -c "
SELECT
  id,
  timestamp,
  action,
  user_id,
  resource_type,
  ip_address,
  response_status
FROM audit_logs
ORDER BY timestamp DESC
LIMIT 10;"
```

**Expected Output:**
```
 id |           timestamp           |      action      | user_id | resource_type | ip_address | response_status
----+-------------------------------+------------------+---------+---------------+------------+-----------------
  5 | 2025-12-17 14:30:45.123456+00 | assets.scan      |       2 | scan          | 172.x.x.x  |             202
  4 | 2025-12-17 14:30:12.654321+00 | assets.discover  |       1 | asset         | 172.x.x.x  |             200
  3 | 2025-12-17 14:15:22.456789+00 | user.role_change |       1 | user          | 172.x.x.x  |             200
```

**Verify Sensitive Data Not Logged:**
```bash
# Check that passwords/keys not in audit logs
docker compose exec postgres psql -U siembox -d siembox -c "
SELECT request_body, details
FROM audit_logs
WHERE action LIKE 'credential%'
LIMIT 5;" | grep -E "password|key|secret"

# Expected: No output (meaning no sensitive data found)
```

**Check Audit Context:**
```bash
# Verify user agent and other request context captured
docker compose exec postgres psql -U siembox -d siembox -c "
SELECT
  action,
  user_agent,
  ip_address,
  response_status
FROM audit_logs
WHERE user_id IS NOT NULL
ORDER BY timestamp DESC
LIMIT 3;"
```

**Test Result:**
- [ ] Audit log created for scan operation
- [ ] User ID and timestamp recorded
- [ ] No passwords or API keys in request_body
- [ ] HTTP response status captured
- [ ] IP address and user agent recorded

### Test 3: Encryption Key Validation

**Objective**: Verify that credential encryption is properly initialized and configured.

**Check Environment Variable:**
```bash
docker compose exec backend env | grep CREDENTIAL_ENCRYPTION_KEY
```

**Expected Output:**
```
CREDENTIAL_ENCRYPTION_KEY=<64-character hex string>
```

**Verify Encryption is Active:**
```bash
# Check backend logs for encryption initialization
docker compose logs backend | grep -i "encryption\|credential"
```

**Expected Messages:**
```
Credential encryption initialized with AES-256-GCM
Encryption key validated successfully
```

**Test Credential Storage (if using credentials in scanning):**
```bash
# Create a test credential (if credentials endpoint exists)
curl -X POST http://localhost:5000/api/credentials \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test_cred",
    "credential_type": "password",
    "username": "testuser",
    "password": "TestPassword123!"
  }'

# Verify in database - password should be encrypted
docker compose exec postgres psql -U siembox -d siembox -c "
SELECT
  id,
  name,
  credential_type,
  username,
  encrypted_password,
  is_active
FROM scan_credentials
WHERE name = 'test_cred';"
```

**Expected Output:**
```
 id |   name    | credential_type | username | encrypted_password | is_active
----+-----------+-----------------+----------+--------------------+-----------
  1 | test_cred | password        | testuser | <32+ char hex str> | t
```

**Verify Password is Not Plaintext:**
```bash
# The encrypted_password field should be 32+ hex characters, not readable
docker compose exec postgres psql -U siembox -d siembox -c "
SELECT
  encrypted_password,
  encryption_iv,
  encryption_auth_tag
FROM scan_credentials
WHERE name = 'test_cred';"
```

**Expected**: All fields contain hex strings, not plaintext

**Test Result:**
- [ ] CREDENTIAL_ENCRYPTION_KEY environment variable set
- [ ] Encryption logs show successful initialization
- [ ] Credentials stored encrypted in database
- [ ] Encryption IV and auth tag present
- [ ] Credentials not readable as plaintext

### Test 4: Database Schema Validation

**Objective**: Verify all new Phase 0 tables exist with correct structure and indexes.

**List New Tables:**
```bash
docker compose exec postgres psql -U siembox -d siembox -c "
SELECT tablename FROM pg_tables
WHERE tablename IN ('audit_logs', 'scan_credentials', 'assets', 'asset_services', 'vulnerabilities', 'asset_vulnerabilities', 'vulnerability_scans')
ORDER BY tablename;"
```

**Expected Output:**
```
       tablename
------------------------
 asset_services
 asset_vulnerabilities
 assets
 audit_logs
 scan_credentials
 vulnerabilities
 vulnerability_scans
```

**Verify Table Structures:**
```bash
# Check audit_logs columns
docker compose exec postgres psql -U siembox -d siembox -c "
\d audit_logs"
```

**Expected Columns:**
```
                      Table "public.audit_logs"
      Column      |       Type       | Collation | Nullable |      Default
------------------+------------------+-----------+----------+-------------------
 id               | integer          |           | not null | nextval('audit_...
 timestamp        | timestamptz      |           | not null | now()
 user_id          | integer          |           |          |
 action           | character varying |           | not null |
 resource_type    | character varying |           |          |
 resource_id      | integer          |           |          |
 ip_address       | inet             |           |          |
 user_agent       | text             |           |          |
 request_body     | jsonb            |           |          |
 response_status  | integer          |           |          |
 details          | jsonb            |           |          |
 created_at       | timestamptz      |           | not null | now()
```

**Check Assets Table:**
```bash
docker compose exec postgres psql -U siembox -d siembox -c "
\d assets"
```

**Expected Key Columns:**
- `ip_address` (INET, UNIQUE)
- `hostname` (VARCHAR)
- `asset_type` (VARCHAR)
- `criticality` (VARCHAR)
- `status` (VARCHAR)
- `discovery_method` (VARCHAR)
- `metadata` (JSONB)

**Verify Indexes Exist:**
```bash
# Count indexes for asset-related tables
docker compose exec postgres psql -U siembox -d siembox -c "
SELECT
  tablename,
  indexname
FROM pg_indexes
WHERE tablename IN ('assets', 'asset_services', 'audit_logs', 'scan_credentials')
ORDER BY tablename, indexname;"
```

**Expected**: 10+ indexes across the tables

**Test Result:**
- [ ] All 7 new tables exist
- [ ] Correct column types and constraints
- [ ] Indexes created for performance-critical columns
- [ ] JSONB columns for flexible metadata
- [ ] Foreign key relationships defined

## Testing Phase 1: Asset Discovery

### Test 1: Frontend - Assets Page Access

**Objective**: Verify the Assets page is accessible and renders correctly.

**Access Assets Page:**
1. Open browser: http://localhost:3000
2. Login with admin credentials (admin / changeme)
3. Look for menu item: "Assets & Vulnerabilities" (should be visible in sidebar)
4. Click "Assets" submenu
5. **Expected**: Assets page loads with empty table

**Verify Page Elements:**

The Assets page should display:
- [ ] Page title: "Assets"
- [ ] Search bar (search by IP or hostname)
- [ ] Filter controls:
  - Asset Type dropdown (Server, Workstation, Network Device, etc.)
  - Status dropdown (Active, Offline)
  - Criticality dropdown (Low, Medium, High, Critical)
- [ ] "Trigger Scan" button (if Analyst+ role)
- [ ] Asset table with columns:
  - IP Address
  - Hostname
  - Asset Type (with color indicators)
  - Criticality (with color badges)
  - Status (with status indicators)
  - Last Seen
  - Actions (Edit, Delete)
- [ ] Pagination controls (if multiple assets)

**Test Search Functionality:**

Create test asset:
```bash
curl -X POST http://localhost:5000/api/assets \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "192.168.1.100",
    "hostname": "webserver-prod",
    "asset_type": "server",
    "criticality": "critical",
    "status": "active"
  }'
```

Then in UI:
1. Type "192.168.1.100" in search box
2. **Expected**: Only matching asset shown
3. Clear search, verify all assets shown again

**Test Filters:**
1. Filter by Status: "Active"
2. **Expected**: Only active assets shown
3. Apply Criticality filter: "Critical"
4. **Expected**: Only critical assets shown
5. Clear filters, all assets return

**Test Result:**
- [ ] Assets page accessible and loads without errors
- [ ] All UI elements present
- [ ] Search functionality works
- [ ] Filters work correctly
- [ ] Asset table displays data

**Troubleshooting:**
- If menu not visible: Check user role (must be Analyst+)
- If page 404: Check frontend build, verify routes.ts changes
- If API error: Check backend logs: `docker compose logs backend | tail -50`

### Test 2: Auto-Discovery from Logs

**Objective**: Verify the auto-discovery service can identify assets from existing logs.

**Check for Existing Assets (from log discovery):**

If you have existing logs in the system:
```bash
docker compose exec postgres psql -U siembox -d siembox -c "
SELECT
  COUNT(DISTINCT source_ip) as unique_ips
FROM raw_logs;"
```

**If count > 0, trigger auto-discovery:**
```bash
# Using API (requires auth token)
curl -X POST http://localhost:5000/api/assets/discover \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -w "\nHTTP Status: %{http_code}\n"
```

**Expected Response:**
```json
{
  "message": "Auto-discovery completed",
  "discovered": 3,
  "staleMarked": 0,
  "enriched": 2
}
```

**Verify Discovery Method:**
```bash
# Check discovered assets and their method
docker compose exec postgres psql -U siembox -d siembox -c "
SELECT
  ip_address,
  hostname,
  discovery_method,
  first_seen,
  last_seen,
  status
FROM assets
WHERE discovery_method = 'log_correlation'
ORDER BY ip_address;"
```

**Expected Output:**
```
  ip_address  | hostname | discovery_method | first_seen | last_seen | status
--------------+----------+------------------+------------+-----------+--------
 192.168.1.10 | router   | log_correlation  | 2025-...   | 2025-...  | active
 192.168.1.50 | workpc   | log_correlation  | 2025-...   | 2025-...  | active
```

**Check Auto-Discovery Job Status:**
```bash
# Check backend logs for auto-discovery activity
docker compose logs backend | grep -i "auto-discovery\|discovery" | tail -20
```

**Expected Messages:**
```
[Auto-Discovery] Starting periodic discovery job (6h interval)
[Auto-Discovery] Job scheduled successfully
[Auto-Discovery] Discovery cycle completed: found X new assets
```

**Test Manual Discovery Trigger:**

In UI:
1. Go to Assets page
2. Click "Trigger Scan" button
3. Select "Auto-Discovery" option
4. Click "Discover"
5. **Expected**: Success message with number of discovered assets
6. Check database to verify assets were added

**Test Result:**
- [ ] Auto-discovery identifies IPs from raw logs
- [ ] Assets created with `discovery_method = 'log_correlation'`
- [ ] Hostname extracted when available
- [ ] Auto-discovery job runs on schedule (check logs)
- [ ] Manual trigger via UI works
- [ ] Discovered asset count accurate

### Test 3: NMAP Scanning

**Objective**: Verify NMAP scanner can be triggered and produces valid results.

**Verify NMAP Installation:**
```bash
# Check if nmap is installed in backend container
docker compose exec backend which nmap
# Expected: /usr/bin/nmap or similar

docker compose exec backend nmap --version
# Expected: Nmap version 7.x or higher
```

**If NMAP Not Found:**

Update Dockerfile to include NMAP:
```dockerfile
RUN apt-get update && apt-get install -y nmap
```

Then rebuild:
```bash
docker compose build backend
docker compose restart backend
```

**Trigger Scan via UI:**

1. Navigate to Assets page
2. Click "Trigger Scan" button
3. Select scan type:
   - "Ping Scan (Fast)" - Checks if host is online
   - "Port Scan" - Scans common ports
   - "Service Scan" - Identifies running services
   - "OS Detection" - Attempts OS fingerprinting
4. Enter target:
   - Single IP: `192.168.1.1`
   - CIDR range: `192.168.1.0/24`
   - Multiple IPs: `192.168.1.1,192.168.1.2`
5. Click "Trigger Scan"
6. **Expected**: Success message with scan ID

**Monitor Scan Progress:**
```bash
# Watch backend logs in real-time
docker compose logs -f backend | grep -i "nmap\|scan"
```

**Check Scan Status:**
```bash
# Query vulnerability_scans table
docker compose exec postgres psql -U siembox -d siembox -c "
SELECT
  id,
  scan_type,
  target,
  status,
  started_at,
  completed_at,
  assets_discovered,
  vulnerabilities_found
FROM vulnerability_scans
ORDER BY created_at DESC
LIMIT 5;"
```

**Expected Status Lifecycle:**
```
id | scan_type | target    | status    | started_at | completed_at | assets_discovered
---+-----------+-----------+-----------+------------+--------------+------------------
 1 | port      | 192.168.1 | queued    | NULL       | NULL         | NULL
    # Wait 10-30 seconds...
 1 | port      | 192.168.1 | running   | 2025-...   | NULL         | NULL
    # Wait for completion (depending on scan type)...
 1 | port      | 192.168.1 | completed| 2025-...   | 2025-...     | 3
```

**Verify Scan Results in Database:**
```bash
# Check discovered assets from NMAP scan
docker compose exec postgres psql -U siembox -d siembox -c "
SELECT
  ip_address,
  hostname,
  os_type,
  discovery_method,
  last_scanned
FROM assets
WHERE discovery_method = 'nmap'
ORDER BY last_scanned DESC;"
```

**Expected Output:**
```
  ip_address  | hostname  | os_type      | discovery_method | last_scanned
--------------+-----------+--------------+------------------+------------------
 192.168.1.1  | router    | Linux 2.6-3  | nmap             | 2025-12-17 14:30
 192.168.1.50 | workpc    | Windows 10   | nmap             | 2025-12-17 14:30
```

**Check Discovered Services:**
```bash
# List all services discovered by NMAP
docker compose exec postgres psql -U siembox -d siembox -c "
SELECT
  a.ip_address,
  s.port,
  s.protocol,
  s.service_name,
  s.service_version,
  s.state
FROM assets a
JOIN asset_services s ON a.id = s.asset_id
WHERE a.discovery_method = 'nmap'
ORDER BY a.ip_address, s.port;"
```

**Expected Output:**
```
  ip_address  | port | protocol | service_name | service_version | state
--------------+------+----------+--------------+-----------------+--------
 192.168.1.1  |   22 | tcp      | ssh          | OpenSSH 7.4     | open
 192.168.1.1  |   80 | tcp      | http         | nginx           | open
 192.168.1.1  | 443  | tcp      | https        | nginx           | open
 192.168.1.50 |   80 | tcp      | http         | IIS 10          | open
```

**Test Result:**
- [ ] NMAP installed in backend container
- [ ] Scan initiated from UI successfully
- [ ] Scan status tracked in database (queued → running → completed)
- [ ] Assets created from NMAP results
- [ ] Services enumerated with ports and versions
- [ ] Scan completion recorded with timestamp
- [ ] Results accessible via API

### Test 4: Asset Details Dialog

**Objective**: Verify asset details modal displays all asset information.

**Open Asset Details:**

1. In Assets page table, find an asset row
2. Click anywhere on the row OR click a details button
3. **Expected**: Modal dialog opens with asset details

**Verify Asset Details Content:**

The modal should display:
- [ ] Asset IP address
- [ ] Hostname
- [ ] Asset type (with icon)
- [ ] Criticality level (with color badge)
- [ ] Status (Active/Offline)
- [ ] Discovery method (NMAP, Log Correlation, Manual)
- [ ] First seen and last seen timestamps
- [ ] Metadata JSON view

**Check Services Tab:**

1. Click "Services" tab in modal
2. **Expected**: Table showing:
   - Port number
   - Protocol (TCP/UDP)
   - Service name
   - Service version (if detected)
   - State (open, closed, filtered)

Example:
```
Port | Protocol | Service  | Version | State
-----+----------+----------+---------+-------
  22 | tcp      | ssh      | v7.4    | open
  80 | tcp      | http     | nginx   | open
 443 | tcp      | https    | nginx   | open
```

**Check Metadata Tab:**

1. Click "Metadata" tab
2. **Expected**: Raw JSON data about the asset
3. Should be formatted and readable

**Test Edit Asset:**
1. In modal, edit asset properties:
   - Change hostname
   - Change criticality level
   - Add tags
2. Click "Save" or "Update"
3. **Expected**: Modal closes, asset updated in table

**Test Delete Asset:**
1. In modal, click "Delete" button
2. **Expected**: Confirmation dialog
3. Click "Confirm Delete"
4. **Expected**: Modal closes, asset removed from table

**Test Result:**
- [ ] Modal opens on asset row click
- [ ] All asset properties displayed
- [ ] Services tab shows discovered ports/services
- [ ] Metadata tab shows JSON data
- [ ] Edit functionality works
- [ ] Delete functionality works with confirmation

### Test 5: Rate Limiting

**Objective**: Verify rate limiting prevents abuse of scan operations.

**Rate Limit Configuration:**
- Limit: 10 scans per 15 minutes per user
- Returns HTTP 429 (Too Many Requests) when exceeded

**Test Rate Limiting:**
```bash
# Save admin token
TOKEN=$(curl -s -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "changeme"}' | jq -r '.token')

# Trigger 11 scans rapidly (targeting non-existent IP to avoid heavy processing)
for i in {1..11}; do
  echo "Scan $i:"
  curl -s -X POST http://localhost:5000/api/assets/scan \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"targets": ["192.0.2.1"], "scanType": "ping"}' \
    -w "HTTP %{http_code}\n" \
    -o /tmp/scan_response_$i.txt

  cat /tmp/scan_response_$i.txt | jq . 2>/dev/null || cat /tmp/scan_response_$i.txt
  echo ""
  sleep 1
done
```

**Expected Results:**

```
Scan 1: HTTP 202 (Accepted)
  {"message": "Scan initiated successfully", "scanId": 1}

Scan 2-10: HTTP 202 (Accepted)
  Similar success responses

Scan 11: HTTP 429 (Too Many Requests)
  {"error": "Rate limit exceeded. Maximum 10 scans per 15 minutes"}
```

**Test Rate Limit Reset:**
```bash
# Wait 15 minutes (900 seconds) or modify rate limiter timeout for testing
# Then trigger another scan - should succeed
curl -X POST http://localhost:5000/api/assets/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"targets": ["192.0.2.1"], "scanType": "ping"}' \
  -w "\nHTTP Status: %{http_code}\n"

# Should return: HTTP 202
```

**Test Result:**
- [ ] First 10 scans return 202 Accepted
- [ ] 11th scan returns 429 Too Many Requests
- [ ] Rate limit resets after 15 minutes
- [ ] Rate limit tracks per user (different users have separate limits)

### Test 6: Search and Filtering

**Objective**: Verify search and filter capabilities work correctly in Assets page.

**Prepare Test Data:**
```bash
# Create multiple test assets with different properties
curl -X POST http://localhost:5000/api/assets \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "10.0.1.100",
    "hostname": "webserver-prod",
    "asset_type": "server",
    "criticality": "critical",
    "status": "active"
  }'

curl -X POST http://localhost:5000/api/assets \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "10.0.1.101",
    "hostname": "database-prod",
    "asset_type": "server",
    "criticality": "high",
    "status": "active"
  }'

curl -X POST http://localhost:5000/api/assets \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "10.0.2.50",
    "hostname": "workstation-dev",
    "asset_type": "workstation",
    "criticality": "low",
    "status": "offline"
  }'
```

**Test Search by IP Address:**
1. In Assets page, type "10.0.1.100" in search box
2. **Expected**: Only the webserver asset shown
3. Clear search, all assets return

**Test Search by Hostname:**
1. Type "webserver" in search box
2. **Expected**: Only assets matching hostname pattern shown
3. Clear search

**Test Filter by Asset Type:**
1. Open Asset Type dropdown
2. Select "Server"
3. **Expected**: Only server-type assets shown
4. Clear filter

**Test Filter by Criticality:**
1. Open Criticality dropdown
2. Select "Critical"
3. **Expected**: Only critical assets shown
4. Add additional filters:
   - Asset Type = Server
   - Status = Active
5. **Expected**: Assets matching ALL filters shown

**Test Filter by Status:**
1. Open Status dropdown
2. Select "Active"
3. **Expected**: Offline asset hidden
4. Select "Offline"
5. **Expected**: Only offline asset shown

**Test Pagination:**
If you have 50+ assets:
1. Verify pagination controls appear
2. Click next page
3. **Expected**: New asset set shown
4. Verify page indicator shows correct page number

**Test Result:**
- [ ] Search by IP address works
- [ ] Search by hostname works
- [ ] Filters work individually
- [ ] Filters can be combined
- [ ] Filter results accurate
- [ ] Pagination works (if applicable)

## Common Issues and Solutions

### Issue: "Assets page is blank"

**Symptoms**: Assets page loads but shows empty table.

**Possible Causes & Solutions:**

1. **No assets discovered yet**
   - Expected if you just deployed
   - Solution: Trigger auto-discovery or NMAP scan

2. **Auto-discovery job not running**
   - Solution: Check backend logs
   ```bash
   docker compose logs backend | grep -i "auto-discovery"
   ```
   - If no messages, restart backend: `docker compose restart backend`

3. **Database connection issue**
   - Solution: Check if assets table has data
   ```bash
   docker compose exec postgres psql -U siembox -d siembox -c "SELECT COUNT(*) FROM assets;"
   ```
   - If count is 0, manually trigger discovery or create test assets

### Issue: "Scan fails immediately"

**Symptoms**: Triggering a scan returns error immediately instead of 202 status.

**Possible Causes & Solutions:**

1. **NMAP not installed in backend container**
   ```bash
   docker compose exec backend which nmap
   ```
   - If not found, rebuild container:
   ```bash
   docker compose build backend
   docker compose up -d
   ```

2. **Rate limit already exceeded**
   ```bash
   # Check recent scans
   docker compose exec postgres psql -U siembox -d siembox -c "
   SELECT COUNT(*) FROM vulnerability_scans
   WHERE initiated_by = <your_user_id>
   AND created_at > NOW() - INTERVAL '15 minutes';"
   ```
   - If count >= 10, wait for rate limit window to reset

3. **Invalid scan target**
   - Solution: Use valid CIDR or IP format
   - Valid examples: `192.168.1.1`, `192.168.1.0/24`, `192.168.1.1,192.168.1.2`

4. **Backend service not healthy**
   ```bash
   docker compose logs backend | tail -50
   ```
   - Look for error messages and restart if needed

### Issue: "Rate limiting triggers too quickly"

**Symptoms**: Getting 429 errors after only a few scans.

**Possible Causes & Solutions:**

1. **Rate limit configured too strict**
   - Check `/backend/src/middleware/rateLimiter.ts`
   - Default is 10 scans per 15 minutes
   - For testing, you can increase temporarily:
   ```bash
   # Edit the rate limiter configuration and rebuild
   # Change limit: 10 to limit: 100 for testing
   docker compose build backend
   docker compose restart backend
   ```

2. **Previous scans still in 15-minute window**
   - Solution: Wait 15 minutes for window to reset
   - Or reset database to clear scan history

### Issue: "Credential encryption error"

**Symptoms**: Error about missing encryption key when attempting credential operations.

**Possible Causes & Solutions:**

1. **CREDENTIAL_ENCRYPTION_KEY not set**
   ```bash
   docker compose exec backend env | grep CREDENTIAL_ENCRYPTION_KEY
   ```
   - Should show 64-character hex string
   - If empty, add to `.env` file (see Deployment Step 4)

2. **Invalid encryption key format**
   - Must be 64 hex characters (32 bytes)
   - Verify: `echo $CREDENTIAL_ENCRYPTION_KEY | wc -c`
   - Should show 65 (64 chars + newline)

3. **Key changed but credentials still encrypted with old key**
   - Solution: Reset database or decrypt/re-encrypt with new key

### Issue: "Database schema mismatch"

**Symptoms**: Errors about missing tables when accessing assets page.

**Possible Causes & Solutions:**

1. **Schema migration didn't run**
   ```bash
   docker compose exec postgres psql -U siembox -d siembox -c "\dt assets"
   ```
   - If table not found, manually run migration:
   ```bash
   docker compose exec postgres psql -U siembox -d siembox < backend/migrations/001_initial_schema.sql
   ```

2. **Old database volume still in use**
   - Solution: Reset database completely
   ```bash
   docker compose down
   docker volume rm siembox_postgres_data
   docker compose up -d
   sleep 15
   ```

3. **Partial migration failure**
   - Solution: Drop and recreate database
   ```bash
   docker compose exec postgres psql -U siembox -c "DROP DATABASE siembox;"
   docker compose exec postgres psql -U siembox -c "CREATE DATABASE siembox OWNER siembox;"
   docker compose restart postgres
   docker compose exec postgres psql -U siembox -d siembox < backend/migrations/001_initial_schema.sql
   ```

### Issue: "Permission denied for scan operations"

**Symptoms**: Getting 403 Forbidden when attempting scans with analyst user.

**Possible Causes & Solutions:**

1. **User role not properly saved**
   ```bash
   docker compose exec postgres psql -U siembox -d siembox -c "
   SELECT username, role FROM users WHERE username = 'analyst_test';"
   ```
   - Verify role shows 'analyst'
   - If not, update: `UPDATE users SET role = 'analyst' WHERE username = 'analyst_test';`

2. **Middleware configuration issue**
   - Check `/backend/src/middleware/scanPermissions.ts`
   - Verify it checks for 'analyst' and higher roles

3. **Request headers missing auth token**
   - Verify Authorization header format: `Authorization: Bearer TOKEN`
   - Token should be JWT from login response

### Issue: "NMAP scan hangs or times out"

**Symptoms**: Scan status stuck in 'running' state for extended period.

**Possible Causes & Solutions:**

1. **Target is unreachable or blocking NMAP**
   - Solution: Use local network targets for testing
   - Test with: `docker compose exec backend nmap -p 22 192.168.1.1`

2. **NMAP timeout too short**
   - Increase NMAP_TIMEOUT in `.env` (default 300 seconds)
   - Rebuild: `docker compose build backend && docker compose up -d`

3. **Scan queue backed up**
   - Check pending scans:
   ```bash
   docker compose exec postgres psql -U siembox -d siembox -c "
   SELECT id, status, created_at FROM vulnerability_scans
   WHERE status IN ('queued', 'running')
   ORDER BY created_at;"
   ```
   - Kill stuck scan if needed (update status to 'failed')

## Performance Verification

### Database Query Performance

Test dashboard statistics query speed:
```bash
# Measure query time for asset statistics
time docker compose exec postgres psql -U siembox -d siembox -c "
SELECT
  COUNT(*) as total_assets,
  COUNT(CASE WHEN status = 'active' THEN 1 END) as active,
  COUNT(CASE WHEN status = 'offline' THEN 1 END) as offline,
  COUNT(DISTINCT criticality) as criticality_types
FROM assets;"
```

**Expected**: < 50ms for queries

### Backend Response Times

Test assets endpoint performance:
```bash
# Get admin token
TOKEN=$(curl -s -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "changeme"}' | jq -r '.token')

# Test with 50 assets
time curl -s \
  -H "Authorization: Bearer $TOKEN" \
  "http://localhost:5000/api/assets?limit=50" | jq '.assets | length'
```

**Expected**: < 200ms response time for 50 assets

### Scan Performance

Monitor scan execution time:
```bash
docker compose exec postgres psql -U siembox -d siembox -c "
SELECT
  scan_type,
  target,
  duration_seconds,
  assets_discovered,
  status
FROM vulnerability_scans
WHERE status = 'completed'
ORDER BY completed_at DESC
LIMIT 5;"
```

**Expected**:
- Ping scan: 5-30 seconds
- Port scan: 30-120 seconds
- Service/OS detection: 2-5 minutes

## Success Criteria Checklist

### Phase 0: Security Foundation
- [ ] All 7 new database tables exist and have correct schema
- [ ] Audit logs capture scan operations with user context
- [ ] RBAC prevents viewers from triggering scans
- [ ] RBAC allows analysts to trigger scans
- [ ] Credential encryption key validated on startup
- [ ] Credentials stored encrypted in database
- [ ] No sensitive data in audit log request bodies
- [ ] Rate limiting prevents >10 scans per 15 minutes

### Phase 1: Asset Discovery
- [ ] Assets page accessible and loads without errors
- [ ] Auto-discovery identifies IPs from raw logs
- [ ] Auto-discovery runs on schedule (every 6 hours)
- [ ] NMAP scans execute successfully
- [ ] Scan results stored in assets and asset_services tables
- [ ] Asset details dialog displays all information
- [ ] Services tab shows discovered ports and versions
- [ ] Search functionality works for IPs and hostnames
- [ ] Filters work (asset type, criticality, status)
- [ ] Rate limiting prevents scan abuse
- [ ] Delete asset functionality works with confirmation
- [ ] Asset statistics available via API

## Next Steps

Once Phase 0/1 testing is complete and all success criteria met:

### Option A: Continue to Phase 2
- Implement Vulnerability Management
- Integrate CVE database (NVD, EPSS)
- Build vulnerability correlation engine
- Create remediation workflows

### Option B: Continue to Phase 3
- Implement Vulnerability Scanning
- Deploy HashiCorp Vault for credential management
- Add authenticated scanning (SSH, SNMP)
- Build discovery templates

### Option C: Deploy to Production
- Configure production `.env` with security hardening
- Set up monitoring and alerting
- Configure log retention policies
- Document operational procedures
- Create runbooks for common tasks

### Option D: Community Contributions
- Share parsers for common log sources
- Document your NMAP configurations
- Contribute detection rules
- Publish use cases and case studies

## Getting Help

If you encounter issues not covered in this guide:

### 1. Collect Diagnostic Information

**Logs**:
```bash
# Save backend logs
docker compose logs backend > /tmp/backend.log

# Save frontend logs
docker compose logs frontend > /tmp/frontend.log

# Save postgres logs
docker compose logs postgres > /tmp/postgres.log
```

**Database State**:
```bash
# Export schema
docker compose exec postgres pg_dump -U siembox siembox --schema-only > /tmp/schema.sql

# Export asset data (redacted)
docker compose exec postgres psql -U siembox -d siembox -c "
SELECT ip_address, hostname, asset_type, status FROM assets;" > /tmp/assets.txt
```

### 2. Create GitHub Issue

Include:
- Error message (from logs)
- Steps to reproduce
- Expected vs actual behavior
- Database info (`SELECT version();`)
- SIEMBox version (`git log --oneline -1`)
- System info (Docker version, OS)
- Diagnostic logs (see above)

### 3. Engage Community

- GitHub Discussions: https://github.com/cladkins/SIEMBOX/discussions
- Check existing issues for similar problems
- Include minimal reproducible example

### 4. Continue in Claude Code

If needing deeper investigation:
- Provide logs and error messages
- Describe what you've already tried
- Share database query results
- Continue troubleshooting with Claude Code

## Additional Resources

- **Backend API Documentation**: `/docs/reference/API.md`
- **NMAP Configuration**: `backend/test-nmap-patterns.js`
- **Database Schema**: `backend/migrations/001_initial_schema.sql`
- **Project README**: `/README.md`
- **Deployment Guide**: `/DEPLOYMENT.md`
- **Architecture Context**: `.claude/CLAUDE.md`
