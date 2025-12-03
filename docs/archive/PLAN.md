# SIEMBox Implementation Plan

## Project Overview
SIEMBox is a basic SIEM (Security Information and Event Management) system designed for homelabbers. It provides syslog collection, custom parsing, detection rules, and a dashboard for security monitoring.

## Technology Stack
- **Backend**: Node.js with Express.js
- **Database**: PostgreSQL
- **Frontend**: Vue.js 3 with Composition API
- **Deployment**: Docker Compose
- **Additional**: TypeScript for type safety

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                         SIEMBox                              │
├─────────────────────────────────────────────────────────────┤
│  Frontend (Vue.js)                                          │
│  ├─ Dashboard (Alert Visualization)                         │
│  ├─ Parser Builder GUI                                      │
│  ├─ Detection Rule Editor                                   │
│  └─ User Management                                         │
├─────────────────────────────────────────────────────────────┤
│  Backend API (Node.js/Express)                              │
│  ├─ REST API                                                │
│  ├─ Authentication & Authorization                          │
│  ├─ Parser Management                                       │
│  └─ Detection Rule Management                               │
├─────────────────────────────────────────────────────────────┤
│  Syslog Ingestion Service (Node.js)                         │
│  ├─ UDP/TCP Listener (Port 514)                             │
│  ├─ Parser Engine                                           │
│  └─ Detection Rules Engine                                  │
├─────────────────────────────────────────────────────────────┤
│  Database (PostgreSQL)                                       │
│  ├─ Raw Logs                                                │
│  ├─ Parsed Logs                                             │
│  ├─ Alerts                                                  │
│  ├─ Parsers                                                 │
│  ├─ Detection Rules                                         │
│  └─ Users & Permissions                                     │
└─────────────────────────────────────────────────────────────┘
```

## Development Workflow

### GitHub Repository
- **Repository**: https://github.com/cladkins/SIEMBOX (Private)
- **Branches**:
  - `main`: Production-ready code
  - `develop`: Active development branch (default for all work)
- **Workflow**: All development commits go to `develop` branch

### Testing Environment
- Code is pulled from GitHub to Docker server for homelab testing
- Test in realistic homelab environment before merging to `main`

### Security & Secrets Management
**CRITICAL**: Never commit secrets or sensitive data to the repository

Protected files (never commit):
- `.env` files (use `.env.example` as template)
- `config.local.js` or similar local config files
- Database credentials
- API keys, tokens, or passwords
- SSL certificates and private keys
- Any files containing real homelab IPs, hostnames, or network details

Best practices:
- Use `.env.example` with placeholder values
- Document required environment variables
- Use environment variables for all secrets
- Add comprehensive `.gitignore` from the start
- Review commits before pushing to catch accidental secrets

## Implementation Phases

### Phase 1: Project Foundation
**Goal**: Set up the basic project structure and development environment

#### Tasks:
1. Initialize Node.js backend project
   - Set up TypeScript
   - Configure ESLint and Prettier
   - Install core dependencies (Express, pg, etc.)
   - Create folder structure

2. Initialize Vue.js frontend project
   - Use Vite for build tooling
   - Configure TypeScript
   - Set up Vue Router and Pinia (state management)
   - Install UI library (e.g., Element Plus or Vuetify)

3. Set up PostgreSQL schema
   - Design database tables
   - Create migration scripts
   - Set up connection pooling

4. Create Docker Compose configuration
   - PostgreSQL service
   - Backend service
   - Frontend service
   - Nginx reverse proxy

**Deliverables**:
- Working dev environment
- Database schema
- Docker setup with hot-reload for development

---

### Phase 2: Syslog Ingestion Service
**Goal**: Collect and store syslog messages from network devices

#### Database Tables:
```sql
-- Raw syslog messages
CREATE TABLE raw_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    raw_message TEXT NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    facility INTEGER,
    severity INTEGER,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Parsed logs
CREATE TABLE parsed_logs (
    id SERIAL PRIMARY KEY,
    raw_log_id INTEGER REFERENCES raw_logs(id),
    parser_id INTEGER REFERENCES parsers(id),
    parsed_data JSONB NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_parsed_logs_timestamp ON parsed_logs(timestamp DESC);
CREATE INDEX idx_parsed_logs_source_ip ON parsed_logs(source_ip);
CREATE INDEX idx_parsed_data_gin ON parsed_logs USING GIN(parsed_data);
```

#### Implementation:
1. Create syslog listener service
   - UDP listener on port 514 (standard syslog)
   - TCP listener on port 514 (for reliable delivery)
   - Parse RFC 3164 and RFC 5424 syslog formats
   - Extract: facility, severity, timestamp, hostname, message

2. Store raw logs in database
   - Batch inserts for performance
   - Add metadata (source IP, receive time)

3. Create basic log viewer API endpoint
   - GET /api/logs/raw
   - Pagination and filtering

**Deliverables**:
- Syslog service receiving logs on port 514
- Raw logs stored in PostgreSQL
- Basic API to view logs

---

### Phase 3: Parser Engine
**Goal**: Allow users to create custom parsers for different log types

#### Database Tables:
```sql
CREATE TABLE parsers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    enabled BOOLEAN DEFAULT true,
    parser_type VARCHAR(50) NOT NULL, -- 'regex', 'grok', 'json'
    pattern TEXT NOT NULL,
    field_mappings JSONB NOT NULL, -- Maps regex groups to field names
    test_samples JSONB, -- Sample logs for testing
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

#### Implementation:
1. Parser engine core
   - Support for regex-based parsing
   - Support for grok patterns (common log formats)
   - Support for JSON log parsing
   - Field extraction and normalization

2. Parser matching system
   - Try parsers in priority order
   - Cache parser results
   - Handle parsing failures gracefully

3. Parser API endpoints
   - POST /api/parsers - Create new parser
   - GET /api/parsers - List all parsers
   - PUT /api/parsers/:id - Update parser
   - DELETE /api/parsers/:id - Delete parser
   - POST /api/parsers/:id/test - Test parser against sample log

4. Built-in parsers
   - SSH authentication logs
   - Apache/Nginx access logs
   - Firewall logs (basic)
   - Windows Event Log (if JSON formatted)
   - Generic syslog parser

**Deliverables**:
- Parser engine processing raw logs
- API for parser management
- 5+ built-in parsers
- Parsed logs stored with structured data

---

### Phase 4: Detection Rules Engine
**Goal**: Create YAML-based detection rules to identify security events

#### Database Tables:
```sql
CREATE TABLE detection_rules (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    enabled BOOLEAN DEFAULT true,
    severity VARCHAR(20) NOT NULL, -- 'low', 'medium', 'high', 'critical'
    rule_yaml TEXT NOT NULL,
    rule_logic JSONB NOT NULL, -- Parsed YAML for quick access
    tags TEXT[], -- For categorization
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE alerts (
    id SERIAL PRIMARY KEY,
    rule_id INTEGER REFERENCES detection_rules(id),
    parsed_log_id INTEGER REFERENCES parsed_logs(id),
    severity VARCHAR(20) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    matched_data JSONB NOT NULL,
    status VARCHAR(20) DEFAULT 'new', -- 'new', 'investigating', 'closed'
    assigned_to INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_alerts_created_at ON alerts(created_at DESC);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_status ON alerts(status);
```

#### YAML Rule Format:
```yaml
name: SSH Brute Force Attempt
description: Detects multiple failed SSH login attempts from same IP
severity: high
enabled: true
tags: [ssh, brute-force, authentication]

# Conditions to match
conditions:
  - field: program
    operator: equals
    value: sshd

  - field: message
    operator: contains
    value: "Failed password"

# Aggregation (optional)
aggregation:
  field: source_ip
  timeframe: 5m  # 5 minutes
  threshold: 5   # 5 or more events

# Alert template
alert:
  title: "SSH Brute Force Detected from {source_ip}"
  description: "{count} failed SSH login attempts detected"
```

#### Implementation:
1. YAML rule parser
   - Validate YAML structure
   - Parse conditions, aggregations, thresholds
   - Support operators: equals, contains, regex, greater_than, less_than

2. Rule evaluation engine
   - Evaluate rules against parsed logs in real-time
   - Support for stateful rules (counting, time windows)
   - Generate alerts when rules match

3. Rule API endpoints
   - POST /api/rules - Create new rule
   - GET /api/rules - List all rules
   - PUT /api/rules/:id - Update rule
   - DELETE /api/rules/:id - Delete rule
   - POST /api/rules/:id/test - Test rule against logs

4. Alert API endpoints
   - GET /api/alerts - List alerts (with filtering)
   - GET /api/alerts/:id - Get alert details
   - PUT /api/alerts/:id - Update alert (change status, assign)
   - DELETE /api/alerts/:id - Delete alert

5. Built-in detection rules
   - SSH brute force
   - Multiple failed login attempts
   - Privilege escalation (sudo)
   - Port scanning detection
   - Unusual login times
   - Root login attempts

**Deliverables**:
- Rules engine processing logs
- YAML-based rule format
- 6+ built-in detection rules
- Alerts generated and stored

---

### Phase 5: Frontend Dashboard
**Goal**: Create a Vue.js dashboard for viewing alerts and logs

#### Pages/Components:
1. **Dashboard (Home)**
   - Alert summary cards (count by severity)
   - Recent alerts table
   - Alert timeline chart
   - Top alert sources
   - Alert status distribution

2. **Alerts Page**
   - Searchable/filterable alert table
   - Filter by: severity, status, time range, rule
   - Alert detail modal
   - Bulk actions (mark as investigating, close)
   - Export alerts

3. **Logs Viewer**
   - Raw logs table
   - Parsed logs table (with JSON viewer)
   - Search and filter
   - Time range selector
   - Real-time log streaming (optional)

#### Implementation:
1. Set up Vue Router
   - Dashboard route
   - Alerts route
   - Logs route
   - Parsers route
   - Rules route
   - Settings route

2. Create API service layer
   - Axios-based HTTP client
   - Error handling
   - Authentication interceptor

3. Build dashboard components
   - Chart library (Chart.js or ECharts)
   - Data tables with sorting/filtering
   - Real-time updates (polling or WebSocket)

4. Responsive design
   - Mobile-friendly layout
   - Dark mode support

**Deliverables**:
- Functional dashboard
- Alert and log visualization
- Responsive UI

---

### Phase 6: Parser Builder GUI
**Goal**: User-friendly interface for creating custom parsers

#### Features:
1. Parser editor
   - Name and description fields
   - Parser type selector (regex, grok, JSON)
   - Pattern editor with syntax highlighting
   - Field mapping builder (drag-and-drop or form)

2. Parser testing
   - Sample log input area
   - Live preview of parsed results
   - Show matched fields
   - Error display for invalid patterns

3. Parser library
   - List of all parsers
   - Enable/disable toggle
   - Edit and delete actions
   - Import/export parsers (JSON)

#### Implementation:
1. Create parser editor component
   - Code editor (Monaco or CodeMirror)
   - Field mapping UI
   - Validation

2. Create parser test component
   - Live testing against sample logs
   - Display parsed output
   - Show parsing errors

3. Create parser list component
   - Table with parsers
   - Enable/disable switches
   - Actions (edit, delete, test, export)

**Deliverables**:
- Parser builder GUI
- Test functionality
- Parser management

---

### Phase 7: Detection Rule Editor GUI
**Goal**: User-friendly YAML editor for creating detection rules

#### Features:
1. Rule editor
   - YAML editor with syntax highlighting
   - Rule template selector (common rule patterns)
   - Live YAML validation
   - Field auto-completion (based on parser outputs)

2. Rule testing
   - Test against historical logs
   - Show which logs would match
   - Display potential alerts

3. Rule library
   - List of all rules
   - Enable/disable toggle
   - Filter by severity, tags
   - Import/export rules (YAML)

#### Implementation:
1. Create rule editor component
   - YAML editor (Monaco with YAML support)
   - Template selector
   - Validation display

2. Create rule test component
   - Historical log query
   - Match preview
   - Alert preview

3. Create rule list component
   - Table with rules
   - Severity badges
   - Tag filters
   - Actions (edit, delete, test, export)

**Deliverables**:
- Rule editor GUI
- Rule testing functionality
- Rule management

---

### Phase 8: Authentication & Access Control
**Goal**: Secure the application with user authentication

#### Database Tables:
```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'viewer', -- 'admin', 'analyst', 'viewer'
    enabled BOOLEAN DEFAULT true,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);
```

#### Roles:
- **Admin**: Full access (manage users, rules, parsers, settings)
- **Analyst**: Can manage rules and parsers, view alerts, update alerts
- **Viewer**: Read-only access to dashboard and alerts

#### Implementation:
1. Authentication system
   - Password hashing (bcrypt)
   - Session-based auth or JWT
   - Login/logout endpoints
   - Password reset functionality

2. Authorization middleware
   - Protect API routes by role
   - Check permissions before actions

3. User management API
   - POST /api/auth/login
   - POST /api/auth/logout
   - POST /api/users - Create user (admin only)
   - GET /api/users - List users (admin only)
   - PUT /api/users/:id - Update user (admin only)
   - DELETE /api/users/:id - Delete user (admin only)

4. Frontend authentication
   - Login page
   - Auth state management (Pinia)
   - Route guards
   - User profile display

5. Initial admin user
   - Create default admin on first run
   - Display credentials in Docker logs

**Deliverables**:
- User authentication
- Role-based access control
- User management UI (admin)

---

### Phase 9: Docker Compose & Deployment
**Goal**: Package everything for easy deployment

#### Docker Compose Services:
1. **PostgreSQL**
   - Official postgres:15 image
   - Volume for data persistence
   - Environment variables for credentials

2. **Backend**
   - Custom Node.js image
   - Depends on PostgreSQL
   - Port 514 exposed for syslog (UDP/TCP)
   - API port (3000)

3. **Frontend**
   - Custom nginx image with Vue.js build
   - Depends on backend
   - Port 80/443 exposed

4. **Nginx (reverse proxy)**
   - Route / to frontend
   - Route /api to backend
   - SSL/TLS support (optional)

#### Implementation:
1. Create Dockerfiles
   - Backend Dockerfile (multi-stage build)
   - Frontend Dockerfile (build Vue.js, serve with nginx)

2. Create docker-compose.yml
   - Define all services
   - Configure networks
   - Set up volumes
   - Environment variables

3. Create .env.example
   - Database credentials
   - JWT secret
   - Default admin credentials

4. Create startup script
   - Run database migrations
   - Seed initial data (parsers, rules)
   - Create default admin user

5. Health checks
   - Backend health endpoint
   - PostgreSQL connection check

**Deliverables**:
- Complete Docker Compose setup
- One-command deployment: `docker-compose up -d`
- Persistent data storage

---

### Phase 10: Documentation & Polish
**Goal**: Make the project easy to use and maintain

#### Documentation:
1. **README.md**
   - Project description
   - Features list
   - Quick start guide
   - Architecture overview

2. **INSTALL.md**
   - Prerequisites
   - Docker installation
   - Manual installation
   - Configuration options

3. **USER_GUIDE.md**
   - Dashboard walkthrough
   - Creating parsers guide
   - Writing detection rules guide
   - Managing alerts
   - User management

4. **API_DOCUMENTATION.md**
   - All API endpoints
   - Request/response examples
   - Authentication

5. **PARSER_GUIDE.md**
   - Parser types explained
   - Regex examples
   - Grok patterns
   - Best practices

6. **RULE_GUIDE.md**
   - YAML format specification
   - Condition operators
   - Aggregation options
   - Example rules

7. **CONTRIBUTING.md**
   - Development setup
   - Code style guide
   - How to add parsers/rules
   - Pull request process

#### Polish:
1. Error handling
   - User-friendly error messages
   - Proper HTTP status codes
   - Logging

2. Performance optimization
   - Database indexing
   - Query optimization
   - Caching where appropriate

3. Testing (optional but recommended)
   - Unit tests for parser engine
   - Unit tests for rules engine
   - API integration tests

**Deliverables**:
- Complete documentation
- Polished user experience
- Production-ready code

---

## File Structure

```
SIEMBox/
├── backend/
│   ├── src/
│   │   ├── config/
│   │   │   └── database.ts
│   │   ├── middleware/
│   │   │   ├── auth.ts
│   │   │   └── errorHandler.ts
│   │   ├── models/
│   │   │   ├── User.ts
│   │   │   ├── Parser.ts
│   │   │   ├── Rule.ts
│   │   │   ├── Log.ts
│   │   │   └── Alert.ts
│   │   ├── routes/
│   │   │   ├── auth.ts
│   │   │   ├── logs.ts
│   │   │   ├── parsers.ts
│   │   │   ├── rules.ts
│   │   │   ├── alerts.ts
│   │   │   └── users.ts
│   │   ├── services/
│   │   │   ├── syslog/
│   │   │   │   ├── syslogServer.ts
│   │   │   │   └── syslogParser.ts
│   │   │   ├── parser/
│   │   │   │   ├── parserEngine.ts
│   │   │   │   └── builtinParsers.ts
│   │   │   ├── rules/
│   │   │   │   ├── rulesEngine.ts
│   │   │   │   └── builtinRules.ts
│   │   │   └── alerting/
│   │   │       └── alertManager.ts
│   │   ├── utils/
│   │   │   ├── logger.ts
│   │   │   └── validation.ts
│   │   ├── app.ts
│   │   └── server.ts
│   ├── migrations/
│   │   ├── 001_initial_schema.sql
│   │   └── 002_seed_data.sql
│   ├── Dockerfile
│   ├── package.json
│   └── tsconfig.json
│
├── frontend/
│   ├── src/
│   │   ├── assets/
│   │   ├── components/
│   │   │   ├── AlertCard.vue
│   │   │   ├── AlertTable.vue
│   │   │   ├── LogViewer.vue
│   │   │   ├── ParserEditor.vue
│   │   │   ├── RuleEditor.vue
│   │   │   └── ...
│   │   ├── views/
│   │   │   ├── Dashboard.vue
│   │   │   ├── Alerts.vue
│   │   │   ├── Logs.vue
│   │   │   ├── Parsers.vue
│   │   │   ├── Rules.vue
│   │   │   ├── Settings.vue
│   │   │   └── Login.vue
│   │   ├── services/
│   │   │   └── api.ts
│   │   ├── stores/
│   │   │   ├── auth.ts
│   │   │   ├── alerts.ts
│   │   │   └── ...
│   │   ├── router/
│   │   │   └── index.ts
│   │   ├── App.vue
│   │   └── main.ts
│   ├── Dockerfile
│   ├── nginx.conf
│   ├── package.json
│   └── vite.config.ts
│
├── docker-compose.yml
├── .env.example
├── README.md
├── INSTALL.md
├── USER_GUIDE.md
├── API_DOCUMENTATION.md
├── PARSER_GUIDE.md
├── RULE_GUIDE.md
└── CONTRIBUTING.md
```

## Next Steps

1. Review this plan and confirm approach
2. Begin Phase 1: Project Foundation
3. Iterate through each phase
4. Test thoroughly at each stage
5. Deploy and gather feedback

## Timeline Estimate

- **Phase 1-2**: Core infrastructure and syslog ingestion
- **Phase 3-4**: Parser and detection engines
- **Phase 5-7**: Frontend development
- **Phase 8-9**: Security and deployment
- **Phase 10**: Documentation and polish

## Success Criteria

- [ ] Syslog successfully ingested from multiple sources
- [ ] Custom parsers can be created via GUI
- [ ] Custom detection rules can be written in YAML
- [ ] Alerts displayed on dashboard in real-time
- [ ] 5+ built-in parsers included
- [ ] 5+ built-in detection rules included
- [ ] Basic access control working (admin/analyst/viewer)
- [ ] Docker Compose deployment works out-of-the-box
- [ ] Documentation complete and clear

---

*This plan is a living document and may be adjusted as development progresses.*
