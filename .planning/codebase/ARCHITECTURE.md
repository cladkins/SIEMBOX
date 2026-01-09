# System Architecture

## Overview

SIEMBox is a **containerized microservices SIEM system** with a three-tier architecture. The system follows a client-server model with clear separation between data ingestion, processing, storage, and presentation layers.

## Architecture Pattern

**Microservices with Shared Database**
- 3 main services: Frontend, Backend, Database
- 1 optional service: Log Shipper
- Deployment: Docker Compose orchestration
- Communication: HTTP REST API + Syslog protocols

## Component Architecture

### 1. Frontend Service (Vue.js SPA)
- **Technology**: Vue 3 + Composition API + TypeScript + Vite
- **Port**: 3000 (Nginx production server)
- **Pattern**: Single Page Application
- **State Management**: Pinia stores
- **Routing**: Vue Router with auth guards
- **Communication**: Axios with JWT bearer tokens

### 2. Backend Service (Node.js API + Syslog Server)
- **Technology**: Express + TypeScript + Node.js
- **API Port**: 3001 (REST endpoints)
- **Syslog Ports**: 514 UDP/TCP (log ingestion)
- **Pattern**: Layered architecture (Routes → Services → Models → Database)

**Key Components:**
- Express REST API server
- Dual-protocol Syslog server (UDP + TCP)
- Parser Engine (log transformation)
- Rules Engine (threat detection)
- Cleanup Service (retention management)
- Auto-Discovery Job (asset scanning)

### 3. Database Service (PostgreSQL)
- **Technology**: PostgreSQL 15 Alpine
- **Port**: 5432 (internal Docker network only)
- **Pattern**: Relational database with JSONB flexibility
- **Storage**: Structured tables + JSONB columns for logs
- **Volume**: Persistent Docker volume

### 4. Log Shipper (Optional Component)
- **Technology**: Alpine Linux + Bash script
- **Pattern**: Managed agent with config polling
- **Authentication**: API key-based registration
- **Resilience**: Cached configuration fallback
- **Transport**: Syslog RFC 3164 format via netcat

## Data Flow Architecture

### Log Ingestion Pipeline (4-Stage Process)

```
Stage 1: Collection
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│ Log Source  │ --> │ Log Shipper  │ --> │ Syslog      │
│ (files/etc) │     │ (optional)   │     │ UDP/TCP 514 │
└─────────────┘     └──────────────┘     └─────────────┘

Stage 2: Syslog Parsing
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│ SyslogServer│ --> │ SyslogParser │ --> │ raw_logs    │
│ (receives)  │     │ (RFC 3164)   │     │ (MESSAGE)   │
└─────────────┘     └──────────────┘     └─────────────┘

Stage 3: Application Parsing
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│ ParserEngine│ --> │ Regex/Grok   │ --> │ parsed_logs │
│ (priority)  │     │ /JSON        │     │ (JSONB)     │
└─────────────┘     └──────────────┘     └─────────────┘

Stage 4: Detection & Alerting
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│ RulesEngine │ --> │ Condition    │ --> │ alerts      │
│ (evaluate)  │     │ Evaluation   │     │ (table)     │
└─────────────┘     └──────────────┘     └─────────────┘
```

**Key Details:**
- **Stage 2**: Only MESSAGE portion stored in raw_message (not full syslog line)
- **Stage 3**: Parsers tried in priority order, first match wins
- **Stage 4**: Rules evaluated against parsed fields

### Authentication Flow

```
1. Client → POST /api/auth/login (username + password)
2. Backend → Validates with bcrypt, creates session
3. Backend → Returns JWT token
4. Client → Stores token in localStorage
5. Client → Sends Authorization: Bearer <token> header
6. Backend → Validates token via authenticate middleware
7. Backend → Attaches user to req.user
```

### Log Shipper Configuration Management

```
Startup:
1. Generate shipper_id: SHA256(api_key)[0:8]
2. POST /api/shippers/register (authenticate)
3. Receive config (sources, syslog host/port)
4. Cache config to /tmp/siembox-cached-config.json
5. Start tailing configured sources

Polling Loop (every 30s):
1. GET /api/shippers/config/:api_key
2. Success: Update cache, apply if changed
3. Failure: Continue with cached config (ghost shipper mode)
4. Heartbeat: Re-register every 60s
```

## Design Patterns

### 1. Repository Pattern
**Location**: `/backend/src/models/*`
- Each entity has a Model class with static methods
- Models encapsulate database queries
- Examples: `UserModel.findById()`, `AlertModel.create()`

### 2. Service Layer Pattern
**Location**: `/backend/src/services/*`
- Business logic separated from routes
- Services coordinate between models
- Examples: `ParserEngine`, `RulesEngine`, `NmapScanner`

### 3. Middleware Pattern
**Location**: `/backend/src/middleware/*`
- Express middleware for cross-cutting concerns
- Examples: `authenticate`, `authorize()`, `errorHandler`

### 4. Singleton Pattern
**Location**: `RulesEngine.getInstance()`
- Rules engine maintains loaded rules in memory
- Avoids repeated database queries

### 5. Observer Pattern (Event-Driven)
**Location**: Parser Engine → Rules Engine
- After parsing log, triggers rules evaluation
- Decoupled: Parser doesn't know about alerts

### 6. Strategy Pattern
**Location**: Parser types (regex, grok, JSON)
- Different parsing strategies selected at runtime
- `applyParser()` dispatches to appropriate method

### 7. Composition API Pattern (Frontend)
**Location**: Vue 3 components
- Component logic in composable functions
- Stores use Pinia's `defineStore` with composition API

## Key Architectural Decisions

### 1. Two-Stage Log Parsing
**Decision**: Separate syslog protocol from application parsing

**Rationale:**
- Syslog parser handles RFC 3164 extraction
- Application parsers work with clean message content
- Allows flexible parser development

### 2. JSONB Storage for Logs
**Decision**: PostgreSQL JSONB columns for parsed fields

**Rationale:**
- Flexible schema supports any log format
- JSON query operators for field filtering
- Balance of structure and flexibility

### 3. Priority-Based Parser Ordering
**Decision**: First match wins, priority determines order

**Rationale:**
- Efficient - stops after first success
- Predictable - lower number = higher precedence
- Custom parsers can override generic ones

### 4. Cached Configuration Fallback
**Decision**: Shippers cache config, continue if API fails

**Rationale:**
- Operational resilience during API issues
- Security - requires initial authentication
- Visibility - admins can detect ghost shippers

### 5. Session-Based Authentication
**Decision**: Session tokens in database, not stateless JWT

**Rationale:**
- Session revocation capability
- Track active sessions per user
- Store expiration in database

### 6. Rules Engine Singleton
**Decision**: Single instance with in-memory rules

**Rationale:**
- Performance - avoid loading rules per log
- Consistency - all logs use same ruleset
- Reload capability via /reload endpoint

## Security Architecture

### Authentication & Authorization
- **Method**: Session token-based authentication
- **Storage**: Tokens in database, client in localStorage
- **Transport**: Bearer token in Authorization header
- **RBAC**: 4 roles (admin, analyst, viewer, operator)
- **Middleware**: `authenticate()`, `authorize()`, `requireAdmin()`

### API Security
- **Rate Limiting**: 100 req/15min per IP (configurable per endpoint)
- **CORS**: Configurable origin (CORS_ORIGIN env var)
- **Input Validation**: express-validator on endpoints
- **SQL Injection Prevention**: Parameterized queries

### Password Security
- **Hashing**: bcrypt with 10 salt rounds
- **Storage**: Only password_hash in database
- **Default Admin**: Created on startup, change forced

### Network Security
- **Docker Network**: Bridge network isolates services
- **Port Exposure**: Only frontend (3000), API (3001), syslog (514)
- **Database**: Internal Docker network only

## Scalability Considerations

### Current Limitations (Single Node)
- Single PostgreSQL instance (no replication)
- Single Node.js process (no clustering)
- Single syslog listener (no load balancing)

### Future Scaling Strategies
- **Horizontal Scaling**: Backend replicas behind load balancer
- **Database Replication**: PostgreSQL read replicas
- **Syslog Load Balancing**: Multiple servers, shared database
- **Caching**: Redis for sessions and hot data

## Monitoring & Observability

### Health Checks
- **API**: `GET /health` - Basic uptime check
- **Database**: `GET /health/database-status` - Parser/rule counts
- **Docker**: Container health checks in docker-compose.yml

### Logging
- **Backend**: Winston with configurable log levels
- **Frontend**: Console logging (dev mode)
- **Log Shipper**: Colored stdout with timestamps

### Metrics (Future)
- No built-in metrics currently
- Future: Prometheus metrics for Grafana dashboards

## Container Networking

**Docker Network**: Bridge network (siembox-network)

**Services:**
- `postgres:5432` - Database (internal)
- `backend:3001` - API server (exposed)
- `backend:514/udp` - Syslog UDP (exposed)
- `backend:514/tcp` - Syslog TCP (exposed)
- `frontend:80` - Nginx (exposed as 3000)

**Service Discovery:**
- Docker DNS for inter-service communication
- Frontend proxies API to `http://backend:3001`
- Backend connects to `postgres:5432`

## Critical System Flows

### Log Processing Flow
```
Syslog Message → SyslogServer (port 514)
  ↓
SyslogParser (extract metadata)
  ↓
raw_logs table (store MESSAGE only)
  ↓
ParserEngine (apply parsers by priority)
  ↓
parsed_logs table (JSONB fields)
  ↓
RulesEngine (evaluate conditions)
  ↓
alerts table (if rule matches)
```

### User Authentication Flow
```
Login Form → POST /api/auth/login
  ↓
Backend validates credentials (bcrypt)
  ↓
Generate session token
  ↓
Store in sessions table
  ↓
Return token to client
  ↓
Client stores in localStorage
  ↓
Axios interceptor adds to all requests
  ↓
Backend middleware validates token
```

### Asset Discovery Flow
```
Auto-Discovery Job (every 6 hours)
  ↓
Fetch enabled discovery policies
  ↓
NmapScanner spawns nmap process
  ↓
Parse XML results
  ↓
Store in assets table
  ↓
Store services in asset_services table
  ↓
Create audit log entry
```

## Architecture Strengths

1. **Clear separation of concerns** - Each layer has defined responsibilities
2. **Flexible log schema** - JSONB supports any log format
3. **Resilient log shippers** - Cached config prevents data loss
4. **Modular parser system** - Easy to add new parsers
5. **Type safety** - TypeScript throughout stack
6. **Security-first** - Authentication, RBAC, parameterized queries
7. **Containerized** - Easy deployment and scaling

## Architecture Weaknesses / Future Improvements

1. **Single point of failure** - No HA/failover
2. **No caching layer** - Redis would improve performance
3. **Limited metrics** - Need Prometheus integration
4. **No message queue** - Could use for async processing
5. **Monolithic backend** - Could split into microservices
