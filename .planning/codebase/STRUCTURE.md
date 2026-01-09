# Codebase Structure

## Top-Level Organization

```
/SIEMBox
├── backend/              # Node.js Express API + Syslog server
├── frontend/             # Vue.js 3 web interface
├── log-shipper/          # Alpine log forwarder (Bash)
├── docs/                 # Documentation (guides, reference, operations)
├── rules/                # Detection rule YAML files (by category)
├── scripts/              # Utility scripts (deployment, diagnostics)
├── tests/                # Integration and validation tests
├── analysis/             # Claude Code analysis reports (git-ignored)
├── .claude/              # Claude Code project context
├── docker-compose.yml    # Container orchestration
├── README.md             # Project overview
├── DEPLOYMENT.md         # Installation guide
├── API.md → docs/reference/API.md         # Symlink
├── PARSERS.md → docs/reference/PARSERS.md # Symlink
├── RULES.md → docs/reference/RULES.md     # Symlink
└── SECURITY.md → docs/reference/SECURITY.md # Symlink
```

## Backend Structure (`/backend`)

**Organization Pattern**: Layered architecture (Routes → Services → Models → Database)

```
/backend
├── src/
│   ├── server.ts              # Entry point (starts Express, Syslog, jobs)
│   ├── app.ts                 # Express app config & route registration
│   ├── config/
│   │   └── database.ts        # PostgreSQL connection pool
│   │
│   ├── middleware/            # Express middleware
│   │   ├── auth.ts            # authenticate, authorize, requireAdmin
│   │   ├── errorHandler.ts    # Global error handler & 404
│   │   ├── rateLimiter.ts     # Rate limiting configs
│   │   ├── scanPermissions.ts # Asset scan authorization
│   │   └── scanValidation.ts  # Asset scan validation
│   │
│   ├── routes/                # API endpoints (controller layer)
│   │   ├── auth.ts            # POST /api/auth/login, /logout
│   │   ├── users.ts           # CRUD /api/users
│   │   ├── logs.ts            # GET /api/logs (raw & parsed)
│   │   ├── parsers.ts         # CRUD + test endpoint
│   │   ├── rules.ts           # CRUD + reload endpoint
│   │   ├── alerts.ts          # GET/PUT /api/alerts
│   │   ├── settings.ts        # System settings CRUD
│   │   ├── shippers.ts        # Shipper registration & config
│   │   └── assets.ts          # Asset inventory & scanning
│   │
│   ├── services/              # Business logic layer
│   │   ├── syslog/
│   │   │   ├── syslogServer.ts   # UDP/TCP listener
│   │   │   └── syslogParser.ts   # RFC 3164 parsing
│   │   ├── parser/
│   │   │   └── parserEngine.ts   # Regex/grok/JSON parsing
│   │   ├── rules/
│   │   │   └── rulesEngine.ts    # Detection rule evaluation
│   │   ├── cleanup/
│   │   │   └── cleanupService.ts # Retention enforcement
│   │   ├── assets/
│   │   │   ├── assetRepository.ts    # Asset CRUD
│   │   │   ├── scanRepository.ts     # Scan CRUD
│   │   │   └── autoDiscoveryService.ts # Network scanning
│   │   ├── scanner/
│   │   │   └── nmapScanner.ts    # Nmap wrapper (490 lines)
│   │   ├── credentials/
│   │   │   └── credentialEncryption.ts # Encrypt/decrypt
│   │   └── audit/
│   │       └── auditService.ts   # Audit log generation
│   │
│   ├── models/                # Data access layer (repository pattern)
│   │   ├── User.ts
│   │   ├── Session.ts
│   │   ├── RawLog.ts
│   │   ├── ParsedLog.ts
│   │   ├── Parser.ts
│   │   ├── DetectionRule.ts
│   │   ├── Alert.ts
│   │   ├── LogShipper.ts
│   │   ├── Asset.ts
│   │   └── Scan.ts
│   │
│   ├── types/                 # TypeScript definitions
│   │   ├── index.ts           # Common types
│   │   ├── apiTypes.ts        # Request/response types
│   │   ├── serviceTypes.ts    # Service-specific types
│   │   └── nmapTypes.ts       # Nmap result types
│   │
│   ├── utils/
│   │   ├── logger.ts          # Winston logger config
│   │   └── typeGuards.ts      # TypeScript type guards
│   │
│   ├── jobs/
│   │   └── autoDiscovery.ts   # Scheduled asset discovery
│   │
│   └── scripts/
│       ├── migrate.ts         # Database migration runner
│       └── import-rules.ts    # Auto-import rules from /rules
│
├── migrations/
│   └── 001_initial_schema.sql # Complete DB schema (459 lines)
│
├── tests/                     # Backend tests
│   ├── TESTING_GHOST_SHIPPERS.md
│   └── README_SHIPPER_TESTS.md
│
├── scripts/                   # Test/diagnostic scripts
│   └── README.md
│
├── package.json               # Dependencies (47 TS files)
├── tsconfig.json              # TypeScript config
├── Dockerfile                 # Multi-stage build
└── README.md                  # Backend dev guide
```

**Stats:**
- ~10,353 lines of TypeScript
- 47 TypeScript source files
- Entry point: `server.ts`

## Frontend Structure (`/frontend`)

**Organization Pattern**: Feature-based views + shared services/stores

```
/frontend
├── src/
│   ├── main.ts                # Entry point (Vue app setup)
│   ├── App.vue                # Root component
│   │
│   ├── router/
│   │   └── index.ts           # Vue Router + auth guards
│   │
│   ├── stores/                # Pinia state management
│   │   ├── auth.ts            # Auth state (token, user, login/logout)
│   │   └── alerts.ts          # Alert state management
│   │
│   ├── views/                 # Page-level components (21 files)
│   │   ├── Layout.vue         # App shell (sidebar, header, content)
│   │   ├── Login.vue          # Login page (public)
│   │   ├── Dashboard.vue      # Main dashboard (charts, stats)
│   │   ├── Logs.vue           # Log viewer (raw + parsed)
│   │   ├── Parsers.vue        # Parser CRUD
│   │   ├── Rules.vue          # Detection rule CRUD
│   │   ├── Alerts.vue         # Alert management
│   │   ├── Shippers.vue       # Log shipper management
│   │   ├── Settings.vue       # System settings
│   │   ├── Users.vue          # User management (admin)
│   │   ├── Assets.vue         # Asset inventory
│   │   ├── VulnerabilityScanning.vue
│   │   ├── VulnerabilityManagement.vue
│   │   └── __tests__/         # View unit tests
│   │
│   ├── services/
│   │   ├── api.ts             # Axios HTTP client + API methods
│   │   └── assetService.ts    # Asset-specific API calls
│   │
│   ├── components/            # Reusable components
│   │
│   └── assets/                # Static assets (images, styles)
│
├── public/                    # Static files (served by Vite)
├── dist/                      # Build output (generated)
├── package.json               # Dependencies
├── vite.config.ts             # Vite build config
├── tsconfig.json              # TypeScript config
├── Dockerfile                 # Multi-stage build (Vite + Nginx)
└── README.md                  # Frontend dev guide
```

**Stats:**
- ~5,798 lines of TypeScript and Vue
- 21 view components
- Entry point: `main.ts`

## Log Shipper Structure (`/log-shipper`)

**Organization Pattern**: Single Bash script + documentation

```
/log-shipper
├── shipper-managed.sh         # Main log forwarder (529 lines)
├── Dockerfile                 # Alpine + dependencies
├── compose.yml                # Standalone deployment example
├── config.yml.example         # Legacy config (not used)
├── .env.example               # Environment variables
├── README.md                  # Shipper setup guide
├── VERIFICATION-GUIDE.md      # Log flow verification
├── QUICK-REFERENCE.md         # Commands & troubleshooting
├── DEPLOYMENT-VERIFICATION.md # Deployment checklist
├── INCIDENT-REPORT-PROCESS-MANAGEMENT.md # Architecture details
└── test-process-management.sh # Test script
```

**Key Functions** (in `shipper-managed.sh`):
- `generate_shipper_id()` - Creates 8-char ID from API key
- `register_shipper()` - POST to register endpoint
- `fetch_config()` - GET config from API
- `save_cached_config()` / `load_cached_config()` - Fallback caching
- `tail_file_source()` - Tails log files, sends via syslog
- `tail_docker_source()` - Tails Docker container logs
- `send_log()` - Formats RFC 3164 message, sends via netcat
- `apply_config()` - Starts/stops tailing processes

## Documentation Structure (`/docs`)

**Organization Pattern**: Hierarchical by topic

```
/docs
├── README.md                  # Documentation index
│
├── reference/                 # API & feature docs
│   ├── API.md                 # Complete REST API reference
│   ├── PARSERS.md             # Community parser library
│   ├── RULES.md               # Detection rule examples
│   ├── SECURITY.md            # Security hardening guide
│   └── [additional docs]
│
├── guides/                    # How-to guides
│   ├── PRE-V1-DATABASE.md     # Pre-v1.0 schema management
│   └── [setup guides]
│
├── operations/                # Operational procedures
│   ├── TROUBLESHOOTING.md     # Common issues & solutions
│   ├── SHIPPER-DIAGNOSTICS.md # Shipper debugging
│   └── [operational checklists]
│
├── architecture/              # Design documents
├── parsers/                   # App-specific parser guides
├── security/                  # Security documentation
├── features/                  # Feature specs
└── archive/                   # Historical docs
```

## Rules Structure (`/rules`)

**Organization Pattern**: Categorized by threat type

```
/rules
├── authentication/            # Login failures, brute force
├── access-control/            # Authorization violations
├── application/               # App-specific rules
├── data-exfiltration/         # Data export detection
├── infrastructure/            # System and network events
├── iot/                       # IoT device rules
├── password-manager/          # Vaultwarden-specific
└── reverse-proxy/             # Nginx/Traefik/Caddy
```

**Format**: YAML detection rules
- Imported automatically on backend startup
- Each file contains rule definition with conditions

## Scripts Structure (`/scripts`)

**Organization Pattern**: Grouped by purpose

```
/scripts
├── deployment/                # Deployment automation
├── diagnostics/               # System diagnostic tools
└── testing/                   # Test utilities
```

## Tests Structure (`/tests`)

**Organization Pattern**: Backend tests + validation guides

```
/tests
└── backend/                   # Backend validation tests
    ├── TEST_GUIDE.md          # Testing workflow
    ├── TEST_SUITE_MANIFEST.md # Test inventory
    ├── PARSER_VALIDATION_WORKFLOW.md # Parser testing
    ├── QUICK_REFERENCE.md     # Quick commands
    ├── README.md              # Test suite overview
    └── [test scripts]
```

## File Naming Conventions

### Backend
- **Models**: PascalCase + `.ts` (e.g., `DetectionRule.ts`, `ParsedLog.ts`)
- **Routes**: lowercase + `.ts` (e.g., `auth.ts`, `logs.ts`)
- **Services**: camelCase + Service suffix (e.g., `parserEngine.ts`)
- **Middleware**: camelCase + `.ts` (e.g., `auth.ts`, `errorHandler.ts`)

### Frontend
- **Views**: PascalCase + `.vue` (e.g., `Dashboard.vue`, `Alerts.vue`)
- **Stores**: camelCase + `.ts` (e.g., `auth.ts`, `alerts.ts`)
- **Services**: camelCase + `.ts` (e.g., `api.ts`, `assetService.ts`)

### Tests
- **Unit tests**: `[name].test.ts`
- **Integration tests**: `[name].integration.test.ts`
- **Spec tests** (frontend): `[name].spec.ts`

## Module Organization

### Backend Layered Flow
```
HTTP Request
  ↓
Route Handler (routes/*.ts)
  ↓
Service (services/*/*.ts)    [Business Logic]
  ↓
Model (models/*.ts)           [Data Access]
  ↓
Database (PostgreSQL)
```

### Frontend Feature-Based Flow
```
User Interaction
  ↓
View (views/*.vue)            [UI Component]
  ↓
Service (services/*.ts)       [API Calls]
  ↓
Store (stores/*.ts)           [State Management]
  ↓
Backend API
```

## Import Patterns

### Backend
- **Relative imports** from project root
- **Order**: External packages first, then internal
- **Grouping**: Separated by blank lines

Example:
```typescript
import { Router, Request, Response } from 'express';
import { UserModel } from '../models/User';
import { logger } from '../utils/logger';
```

### Frontend
- **Path alias**: `@/` for imports from `src/`
- **Vue imports**: Destructure from 'vue'
- **Element Plus**: Import components as needed

Example:
```typescript
import { ref } from 'vue';
import { ElMessage } from 'element-plus';
import { useAuthStore } from '@/stores/auth';
import { api } from '@/services/api';
```

## Entry Points

### Backend
- **Main**: `src/server.ts` - Starts all services
- **App Config**: `src/app.ts` - Express middleware and routes
- **Migration**: `migrations/001_initial_schema.sql` - Database schema

### Frontend
- **Main**: `src/main.ts` - Vue app initialization
- **Router**: `src/router/index.ts` - Route definitions
- **API Client**: `src/services/api.ts` - HTTP client

### Log Shipper
- **Main**: `shipper-managed.sh` - Forwarder logic

## Code Statistics

- **Total TypeScript/Vue files**: ~7,316 (including node_modules)
- **Backend source files**: 47 TypeScript files (~10,353 lines)
- **Frontend source files**: 21 TypeScript/Vue files (~5,798 lines)
- **Database schema**: 459 lines (single migration)
- **Log shipper**: 529-line Bash script

## Directory Size

- **Frontend node_modules**: 231MB
- **Backend node_modules**: 123MB
- **Git repository**: Varies (depends on history)

## Configuration Files

### Root Level
- `docker-compose.yml` - Container orchestration
- `.env.example` - Environment variable template
- `.gitignore` - Git exclusions
- `README.md` - Project overview

### Backend
- `tsconfig.json` - TypeScript config (ES2022, CommonJS)
- `.eslintrc.json` - Linting rules
- `.prettierrc` - Code formatting
- `jest.config.js` - Test configuration
- `package.json` - Dependencies and scripts

### Frontend
- `tsconfig.json` - TypeScript config (ES2020, ESNext)
- `vite.config.ts` - Build configuration
- `package.json` - Dependencies and scripts

## Notable Structure Patterns

1. **Separation of Concerns**: Clear layers (routes, services, models)
2. **Feature-Based Frontend**: Views organized by page/feature
3. **Shared Services**: Common utilities in services directories
4. **Co-located Tests**: Some tests near source, some in /tests
5. **Documentation Hub**: Centralized in /docs with symlinks at root
6. **Configuration as Code**: Rules and parsers in version control
