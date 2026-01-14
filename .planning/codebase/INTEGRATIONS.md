# External Integrations

## Network Protocols

### Syslog Protocol (RFC 3164 / RFC 5424)

**UDP Port 514** - Syslog message reception
- **Protocol**: dgram (Node.js UDP)
- **Bind address**: 0.0.0.0:514
- **Message format**: RFC 3164 (primary)
- **Use case**: Fast, fire-and-forget log transmission
- **Reliability**: No delivery guarantee (UDP nature)

**TCP Port 514** - Syslog message reception
- **Protocol**: net.createServer (Node.js TCP)
- **Bind address**: 0.0.0.0:514
- **Multi-message support**: Newline-delimited streams
- **Use case**: Reliable log delivery with connection state
- **Reliability**: TCP guarantees delivery

**Implementation**: `/backend/src/services/syslog/syslogServer.ts`

### HTTP/HTTPS

**Backend API** - Port 3001
- **Protocol**: HTTP (Express framework)
- **Format**: JSON request/response bodies
- **Authentication**: JWT bearer tokens
- **Endpoints**: RESTful API (see API.md)

**Frontend** - Port 3000
- **Server**: Nginx reverse proxy
- **Protocol**: HTTP
- **Function**: Serves Vue.js SPA, proxies /api to backend
- **Production**: Should be behind HTTPS termination

## Database Integration

### PostgreSQL Connection

**Technology**: PostgreSQL 15 Alpine
- **Client library**: node-postgres (`pg` 8.11.3)
- **Protocol**: PostgreSQL wire protocol
- **Connection details**:
  - Host: `postgres` (Docker service) or configurable
  - Port: 5432
  - Database: `siembox` (default)
  - User: `siembox` (default)

**Connection Pooling**:
```typescript
{
  max: 20,                      // Max connections in pool
  idleTimeoutMillis: 30000,     // 30 seconds
  connectionTimeoutMillis: 2000 // 2 seconds
}
```

**Health checks**: Pool connects on startup, validates connectivity

### Database Features

**JSONB Storage**:
- `parsed_data` in parsed_logs table
- `field_mappings` in parsers table
- `rule_logic` in detection_rules table
- `metadata` in various tables
- Query operators: `->`, `->>`, `@>`, `?`, `?|`, `?&`

**PostgreSQL Extensions**:
- **pgcrypto**: Cryptographic functions
  - `gen_random_bytes()` - Generate API keys
  - `encode()/decode()` - Hex encoding for shipper IDs
  - SHA256 hashing for API key derivation

**Advanced Features**:
- Array types for tags
- Foreign keys for referential integrity
- Triggers for automated timestamp updates
- Indexes for query performance
- Full-text search capability (future)

## Authentication Mechanisms

### JWT (JSON Web Tokens)

**Library**: jsonwebtoken 9.0.2

**Flow**:
1. User POST username/password to `/api/auth/login`
2. Backend validates with bcrypt
3. Backend generates JWT with `JWT_SECRET` env var
4. Frontend stores token in localStorage
5. Axios interceptor adds `Authorization: Bearer <token>` header
6. Backend middleware validates token on protected routes

**Token Payload**:
```json
{
  "userId": 1,
  "username": "admin",
  "role": "admin",
  "iat": 1702123456,
  "exp": 1702209856
}
```

**Token Storage**:
- Client: localStorage (frontend)
- Server: Sessions table (database)

### Password Hashing

**Library**: bcrypt 5.1.1
- **Rounds**: 10 salt rounds
- **Usage**:
  - Password storage on user creation
  - Password verification on login
  - Password updates

**Implementation**: `/backend/src/models/User.ts`

### API Key Authentication (Log Shippers)

**Format**: 64-character hex strings
- **Generation**: `encode(gen_random_bytes(32), 'hex')`
- **Storage**: `log_shippers.api_key` column (database)
- **Derivation**: Shipper ID = `SHA256(api_key)[0:8]`

**Authentication Flow**:
1. Shipper sends `SHIPPER_API_KEY` to `/api/shippers/register`
2. Backend validates key against database
3. Backend returns configuration JSON
4. Shipper polls `/api/shippers/config/:api_key` every 30s
5. Heartbeat: Re-register every 60s to update `last_seen`

**Fallback**: Cached configuration for resilience (ghost shipper mode)

## External Services & APIs

### NMAP Integration

**Purpose**: Network asset discovery and vulnerability scanning

**Library**: node-nmap 4.0.0
- **Binary**: `/usr/sbin/nmap` (installed in Docker image via apk)
- **Platform**: Alpine Linux package

**Scan Types**:
- **Ping scan**: Host discovery (`-sn`)
- **Port scan**: Service discovery (`-p`)
- **Service scan**: Version detection (`-sV`)
- **OS detection**: Operating system fingerprinting (`-O`)

**Data Flow**:
```
User → POST /api/assets/scans (targets, scan_type)
  ↓
Backend creates scan record in database
  ↓
NmapScanner spawns nmap process with target IPs/CIDRs
  ↓
Parse XML results from nmap
  ↓
Store in assets and asset_services tables
  ↓
Create audit log entry for compliance
```

**Security**:
- Rate limiting: 10 scans per 15 minutes
- Authorization: Admin/Operator roles only
- Input validation: IP/CIDR format validation
- Audit logging: All scan activity recorded

**Implementation**: `/backend/src/services/scanner/nmapScanner.ts`

### Log Shipper API

**Purpose**: Managed log forwarding with centralized configuration

**Endpoints**:

1. **POST /api/shippers/register**
   - Authenticate with API key
   - Create shipper record
   - Return configuration

2. **GET /api/shippers/config/:api_key**
   - Fetch current configuration
   - Update configuration if changed
   - Used for polling (every 30s)

3. **GET /api/shippers/unknown-sources**
   - Detect ghost shippers
   - Find logs with unknown shipper_id
   - Admin visibility into misconfigured shippers

4. **POST /api/shippers/:id/regenerate-key**
   - Rotate API key
   - Invalidate old key
   - Return new key (one-time display)

**Configuration Response**:
```json
{
  "siem_host": "192.168.1.76",
  "siem_port": "514",
  "sources": [
    {
      "source_type": "file",
      "file_path": "/var/log/nginx/access.log",
      "tag": "nginx",
      "facility": "local0",
      "enabled": true
    },
    {
      "source_type": "docker",
      "container_name": "myapp",
      "tag": "myapp",
      "facility": "local1",
      "enabled": true
    }
  ]
}
```

**Resilience**: Cached configuration fallback
- Location: `/tmp/siembox-cached-config.json`
- Saved on every successful config fetch
- Loaded when fetch fails (404/network error)

## Third-Party Integrations

### Parser Support (Community Parsers)

**Supported Applications** (via regex/grok patterns):
- **Web Servers**: Nginx, Apache, Caddy, Traefik
- **Authentication**: Authelia, Keycloak
- **File Sharing**: Nextcloud
- **DNS**: Pi-hole
- **Password Managers**: Vaultwarden
- **Network**: UniFi devices
- **Generic**: Syslog formats, JSON logs

**Parser Types**:
- **Regex**: Native JavaScript RegExp with named groups
- **Grok**: Simplified grok-to-regex conversion
- **JSON**: Native JSON.parse for structured logs

**Community Contributions**: See `PARSERS.md`

### Detection Rule Targets

**Threat Categories**:
- Authentication failures (SSH, web apps)
- Web attacks (SQL injection, XSS, LFI)
- DNS anomalies
- Brute force attempts
- Privilege escalation
- System events

**Rule Engine**: Evaluates parsed logs against conditions
- Field operators: equals, contains, regex, greater_than, etc.
- Aggregations: threshold, timeframe, distinct_count
- Severity levels: low, medium, high, critical

## Rate Limiting & Security

### Express Rate Limit

**Library**: express-rate-limit 7.1.5
- **Storage**: In-memory (per-process)
- **Key generation**: User ID or IP address
- **Headers**: Standard `RateLimit-*` headers

**Endpoint Limits**:
- **Scans**: 10 per 15 minutes
- **Asset scans**: 15 per 10 minutes
- **Vulnerability scans**: 5 per 30 minutes
- **Credential operations**: 20 per hour
- **Audit logs**: 30 per 5 minutes
- **General API**: 100 per 15 minutes

**Bypass**: Admin users bypass most limits (except credentials)

### CORS (Cross-Origin Resource Sharing)

**Library**: cors 2.8.5
- **Configuration**: `CORS_ORIGIN` environment variable
- **Default**: `*` (allow all origins)
- **Credentials**: Enabled for cookie support
- **Production**: Should restrict to specific origins

### Security Headers

**Nginx Configuration**:
- `X-Frame-Options: SAMEORIGIN` - Clickjacking protection
- `X-Content-Type-Options: nosniff` - MIME sniffing protection
- `X-XSS-Protection: 1; mode=block` - Legacy XSS protection
- `Strict-Transport-Security` - HTTPS enforcement (if configured)

## Log Parsing Architecture

### Two-Stage Parsing Pipeline

**Stage 1: Syslog Protocol Parsing**
- **Input**: Raw syslog message via UDP/TCP port 514
- **Format**: `<PRI>TIMESTAMP HOSTNAME TAG: MESSAGE`
- **Process**: Extract metadata (priority, timestamp, hostname, tag)
- **Output**: Store **MESSAGE only** in `raw_logs.raw_message`
- **Implementation**: `/backend/src/services/syslog/syslogParser.ts`

**Stage 2: Application Log Parsing**
- **Input**: Extracted message from Stage 1
- **Process**: Apply user-defined parsers (regex/grok/JSON)
- **Priority**: Parsers tried in priority order, first match wins
- **Output**: Structured fields in `parsed_logs.parsed_data` (JSONB)
- **Implementation**: `/backend/src/services/parser/parserEngine.ts`

**Critical Understanding**:
- `raw_message` contains ONLY the message portion (not full syslog line)
- Parser patterns should match against clean message content
- Commit `0f58032` changed this behavior for consistency

### Rules Engine Integration

**Trigger**: After parsing log, rules engine evaluates
- **Input**: Parsed log fields (JSONB data)
- **Process**: Check conditions against all enabled rules
- **Output**: Create alerts if rule matches
- **Implementation**: `/backend/src/services/rules/rulesEngine.ts`

## Data Retention & Cleanup

### Cleanup Service

**Schedule**: Every 24 hours (configurable via `CLEANUP_INTERVAL_HOURS`)

**Process**:
1. Fetch retention policies from settings
2. Delete logs older than retention period
3. Delete associated parsed logs (cascade)
4. Delete old alerts (cascade)

**Tables Affected**:
- `raw_logs` - Raw syslog messages
- `parsed_logs` - Parsed log data
- `alerts` - Generated alerts

**Foreign Keys**: Ensure referential integrity during deletion

**Implementation**: `/backend/src/services/cleanup/cleanupService.ts`

### Auto-Discovery Job

**Schedule**: Every 6 hours (default)

**Process**:
1. Fetch enabled discovery policies from database
2. Extract target IPs/CIDRs
3. Spawn NmapScanner for each target
4. Parse results, update assets table
5. Create audit log entries

**Concurrency**: Sequential execution (one scan at a time)

**Implementation**: `/backend/src/jobs/autoDiscovery.ts`

## Container Networking

### Docker Network

**Type**: Bridge network (`siembox-network`)

**Services**:
- `postgres:5432` - PostgreSQL (internal only)
- `backend:3001` - API server (exposed to host)
- `backend:514/udp` - Syslog UDP (exposed to host)
- `backend:514/tcp` - Syslog TCP (exposed to host)
- `frontend:80` - Nginx (exposed as 3000 to host)

**Service Discovery**:
- Docker DNS resolves service names
- Frontend proxies `/api` to `http://backend:3001`
- Backend connects to `postgres:5432`

### Container Communication

**Internal** (Docker network):
- Frontend → Backend: HTTP (port 3001)
- Backend → Database: PostgreSQL (port 5432)

**External** (host network):
- User → Frontend: HTTP (port 3000)
- Log Shipper → Backend: Syslog UDP/TCP (port 514)
- User → Backend API: HTTP (port 3001)

## Environment Configuration

### Backend Environment Variables

**Required**:
- `JWT_SECRET` - JWT signing key (must change from default)
- `DB_PASSWORD` - PostgreSQL password
- `CREDENTIAL_ENCRYPTION_KEY` - Encryption key for stored credentials

**Optional**:
- `NODE_ENV` - Environment (production/development)
- `PORT` - API server port (default: 3001)
- `HOST` - Bind address (default: 0.0.0.0)
- `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER` - PostgreSQL connection
- `DEFAULT_ADMIN_PASSWORD` - Initial admin password
- `LOG_LEVEL` - Winston log level (info, debug, error)
- `CORS_ORIGIN` - CORS allowed origins
- `SYSLOG_PORT` - Syslog listener port (default: 514)
- `CLEANUP_INTERVAL_HOURS` - Retention cleanup frequency

### Frontend Environment Variables

**Optional**:
- `VITE_API_URL` - Backend API base URL (default: `/api`)

### Log Shipper Environment Variables

**Required**:
- `SIEMBOX_API_URL` - SIEMBox API endpoint
- `SHIPPER_API_KEY` - 64-char hex API key for authentication

**Optional**:
- `CONFIG_POLL_INTERVAL` - Config fetch interval (default: 30s)
- `HEARTBEAT_INTERVAL` - Heartbeat interval (default: 60s)

## Integration Patterns

### Request/Response Flow

**User Authentication**:
```
Browser → POST /api/auth/login
  ↓
Express (backend:3001)
  ↓
UserModel.findByUsername()
  ↓
PostgreSQL query
  ↓
bcrypt.compare(password, hash)
  ↓
Generate JWT token
  ↓
Return to browser
```

**Log Ingestion**:
```
Application → Syslog UDP/TCP 514
  ↓
SyslogServer (Node.js)
  ↓
SyslogParser (RFC 3164)
  ↓
RawLog.create() → PostgreSQL
  ↓
ParserEngine.process()
  ↓
ParsedLog.create() → PostgreSQL
  ↓
RulesEngine.evaluate()
  ↓
Alert.create() → PostgreSQL (if match)
```

**Asset Discovery**:
```
User → POST /api/assets/scans
  ↓
Validate input (IP/CIDR)
  ↓
Create scan record
  ↓
NmapScanner.scan()
  ↓
Spawn nmap process
  ↓
Parse XML output
  ↓
AssetRepository.upsert()
  ↓
AuditService.log()
```

## Future Integration Opportunities

1. **Webhook notifications** - Alert delivery to external systems
2. **Elasticsearch** - Alternative log storage backend
3. **Grafana** - Dashboards and visualization
4. **Prometheus** - Metrics collection
5. **Slack/Discord** - Alert notifications
6. **Email** - SMTP integration for alerts
7. **LDAP/SAML** - Enterprise authentication
8. **S3/Object storage** - Long-term log archival
9. **Kafka** - Event streaming for high-volume logs
10. **Redis** - Caching layer for performance

## Integration Security

### Best Practices Implemented

1. **API authentication** - JWT tokens for all protected endpoints
2. **API key validation** - Shippers authenticate with database-stored keys
3. **Rate limiting** - Prevent abuse of scan/API endpoints
4. **Input validation** - express-validator on all inputs
5. **SQL injection prevention** - Parameterized queries only
6. **CORS configuration** - Restrict allowed origins
7. **Security headers** - Nginx adds protection headers
8. **Audit logging** - Track all scan and sensitive operations

### Areas for Improvement

1. **API versioning** - Currently no version prefix
2. **OAuth 2.0** - Support for third-party integrations
3. **API rate limiting per key** - More granular control
4. **Webhook signatures** - HMAC verification for webhooks
5. **TLS/SSL** - Currently HTTP, should use HTTPS in production
6. **Certificate pinning** - For log shipper connections
