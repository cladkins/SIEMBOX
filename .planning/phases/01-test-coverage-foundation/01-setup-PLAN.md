# Phase 1.1: Test Coverage Foundation - Setup & Critical Tests

**Phase:** 1 - Test Coverage Foundation
**Plan:** 1.1 - Setup & Critical Tests (Weeks 1-3)
**Goal:** Establish test infrastructure and cover critical paths
**Estimated Duration:** 3 weeks
**Prerequisites:** None (starting fresh)

---

## Objective

Set up modern testing infrastructure for SIEMBox (Jest + Testcontainers for backend, Vitest + MSW for frontend) and implement tests for security-critical and core functionality workflows. Achieve 60%+ backend coverage and 50%+ frontend coverage with all critical paths tested.

---

## Execution Context

**Load before starting:**
- @.planning/phases/01-test-coverage-foundation/01-RESEARCH.md (comprehensive testing research)
- @backend/jest.config.js (current Jest configuration)
- @frontend/vitest.config.ts (if exists, current Vitest configuration)
- @backend/package.json (current dependencies)
- @frontend/package.json (current dependencies)
- @.planning/codebase/TESTING.md (current test state analysis)
- @.planning/codebase/ARCHITECTURE.md (system architecture for test planning)
- @docs/guides/TESTING_GUIDE.md (existing testing documentation)

---

## Context

### Current State
- **Backend**: Jest 29.7.0 + ts-jest installed, minimal configuration exists
- **Frontend**: Vitest mentioned in docs but may not be fully configured
- **Test Coverage**: Only 8 test files exist (parser tests, syslog tests, shipper tests)
- **Coverage**: Unknown (no coverage reports generated)
- **CI/CD**: No automated test runs configured

### Research Findings
- **Backend Stack**: Jest + Testcontainers + SuperTest + Fishery + mock-spawn
- **Frontend Stack**: Vitest + MSW + @vue/test-utils + @pinia/testing
- **Coverage Targets**: 80% backend, 70% frontend (phased approach)
- **Key Pattern**: Testcontainers snapshot/restore for 500x speedup

### Critical Paths (Priority for Testing)
1. **Authentication Flow**: Login → JWT issuance → Authorization checks
2. **Log Ingestion Pipeline**: Syslog → Parser → Rules → Alerts
3. **Parser Engine**: Regex/grok pattern matching, field extraction
4. **Rules Engine**: Condition evaluation, aggregation, alert generation
5. **API Security**: Authentication, authorization, input validation

### Known Risks
- Docker required for Testcontainers (verify availability)
- Port 514 requires root for syslog testing (use dynamic ports in tests)
- NMAP binary required for asset scanning tests (mock in unit tests)
- Test execution time could be slow without optimization

---

## Tasks

### Week 1: Infrastructure Setup

#### Task 1.1: Backend Test Infrastructure
**Description:** Install and configure complete backend testing stack

**Steps:**
1. Install testing dependencies:
   ```bash
   cd backend
   npm install --save-dev \
     @testcontainers/postgresql@^10.7.2 \
     supertest@^6.3.4 \
     fishery@^2.2.2 \
     mock-spawn@^0.2.6 \
     @types/supertest@^6.0.2
   ```

2. Update `jest.config.js` with enhanced configuration:
   - Add coverage thresholds (global: 60%, services: 70%)
   - Configure path mapping for `@/*` imports
   - Add `setupFilesAfterEnv` for test helpers
   - Configure parallel execution (`maxWorkers: 4`)
   - Add coverage exclusions (migrations, types, index files)

3. Create test directory structure:
   ```
   backend/tests/
   ├── setup.ts                 # Global test setup
   ├── helpers/
   │   ├── database.ts          # Testcontainers helpers
   │   ├── factories.ts         # Fishery factories
   │   └── supertest.ts         # API test helpers
   ├── unit/
   │   ├── services/
   │   ├── models/
   │   └── utils/
   └── integration/
       ├── api/
       └── workflows/
   ```

4. Create `tests/setup.ts`:
   - Set test environment variables
   - Configure longer timeouts for container tests (60s)
   - Set up global test hooks if needed

5. Create `tests/helpers/database.ts`:
   - Testcontainers setup/teardown functions
   - Snapshot create/restore utilities
   - Connection pool helpers
   - Migration runner for tests

**Verification:**
- [ ] All dependencies install successfully
- [ ] `npm test` command runs without errors
- [ ] Jest configuration loads correctly
- [ ] Test directory structure created

**Output:**
- Updated `backend/package.json`
- Enhanced `backend/jest.config.js`
- Test directory structure in `backend/tests/`
- Helper utilities created

---

#### Task 1.2: Frontend Test Infrastructure
**Description:** Install and configure complete frontend testing stack

**Steps:**
1. Install testing dependencies:
   ```bash
   cd frontend
   npm install --save-dev \
     vitest@^1.2.0 \
     @vitest/coverage-v8@^1.2.0 \
     @vue/test-utils@^2.4.4 \
     @pinia/testing@^0.1.3 \
     msw@^2.0.0 \
     happy-dom@^13.0.0
   ```

2. Create `vitest.config.ts`:
   - Configure Vue plugin
   - Set test environment to happy-dom
   - Configure coverage with v8 provider
   - Add path aliases matching vite.config.ts
   - Set coverage thresholds (global: 50%)
   - Configure setupFiles for MSW

3. Create test directory structure:
   ```
   frontend/test/
   ├── setup.ts                 # Global test setup
   ├── mocks/
   │   ├── handlers.ts          # MSW request handlers
   │   └── server.ts            # MSW server setup
   ├── unit/
   │   ├── components/
   │   ├── stores/
   │   └── composables/
   └── fixtures/
       └── mockData.ts          # Shared test data
   ```

4. Create MSW setup:
   - `test/mocks/handlers.ts`: Define API mock responses
   - `test/mocks/server.ts`: Configure MSW server
   - `test/setup.ts`: Start/stop MSW server in hooks

5. Update `package.json` scripts:
   ```json
   {
     "scripts": {
       "test": "vitest",
       "test:ui": "vitest --ui",
       "test:coverage": "vitest --coverage"
     }
   }
   ```

**Verification:**
- [ ] All dependencies install successfully
- [ ] `npm test` command runs without errors
- [ ] Vitest configuration loads correctly
- [ ] MSW server starts/stops correctly
- [ ] Test directory structure created

**Output:**
- Updated `frontend/package.json`
- New `frontend/vitest.config.ts`
- Test directory structure in `frontend/test/`
- MSW handlers and server setup

---

#### Task 1.3: Test Data Factories
**Description:** Create Fishery factories for backend test data

**Steps:**
1. Create `tests/helpers/factories.ts` with factories for:
   - User (with roles: admin, analyst, viewer, operator)
   - Session (with JWT tokens)
   - Parser (with regex/grok/JSON patterns)
   - DetectionRule (with conditions and aggregation)
   - Alert (with severities)
   - RawLog (with syslog metadata)
   - ParsedLog (with JSONB fields)
   - LogShipper (with API keys)
   - Asset (with scan results)

2. Example factory pattern:
   ```typescript
   import { Factory } from 'fishery';
   import { User } from '@/types';

   export const userFactory = Factory.define<User>(({ sequence }) => ({
     id: sequence,
     username: `user${sequence}`,
     email: `user${sequence}@example.com`,
     password_hash: '$2b$10$fake.hash.for.testing',
     role: 'analyst',
     created_at: new Date(),
     updated_at: new Date(),
   }));

   // Build single user
   const admin = userFactory.build({ role: 'admin' });

   // Build multiple users
   const users = userFactory.buildList(10);
   ```

3. Create frontend `test/fixtures/mockData.ts` with mock data for:
   - Logs (raw and parsed)
   - Alerts (different severities)
   - Parsers and Rules
   - User sessions
   - API responses

**Verification:**
- [ ] All factories create valid data
- [ ] Factories support overrides
- [ ] Sequence numbers work correctly
- [ ] Mock data is realistic and useful

**Output:**
- `backend/tests/helpers/factories.ts`
- `frontend/test/fixtures/mockData.ts`

---

#### Task 1.4: CI/CD Pipeline Setup
**Description:** Configure GitHub Actions for automated testing

**Steps:**
1. Create `.github/workflows/test.yml`:
   ```yaml
   name: Tests

   on:
     push:
       branches: [develop, main]
     pull_request:
       branches: [develop]

   jobs:
     backend-tests:
       runs-on: ubuntu-latest
       services:
         postgres:
           image: postgres:15
           env:
             POSTGRES_USER: test
             POSTGRES_PASSWORD: test
             POSTGRES_DB: testdb
           ports:
             - 5432:5432
           options: >-
             --health-cmd pg_isready
             --health-interval 10s
             --health-timeout 5s
             --health-retries 5

       steps:
         - uses: actions/checkout@v4
         - uses: actions/setup-node@v4
           with:
             node-version: '20'
             cache: 'npm'
             cache-dependency-path: backend/package-lock.json

         - name: Install dependencies
           run: cd backend && npm ci

         - name: Run tests
           run: cd backend && npm test -- --coverage --maxWorkers=4
           env:
             DB_HOST: localhost
             DB_PORT: 5432
             DB_NAME: testdb
             DB_USER: test
             DB_PASSWORD: test

         - name: Upload coverage
           uses: codecov/codecov-action@v3
           with:
             files: ./backend/coverage/lcov.info
             flags: backend

     frontend-tests:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - uses: actions/setup-node@v4
           with:
             node-version: '20'
             cache: 'npm'
             cache-dependency-path: frontend/package-lock.json

         - name: Install dependencies
           run: cd frontend && npm ci

         - name: Run tests
           run: cd frontend && npm test -- --coverage

         - name: Upload coverage
           uses: codecov/codecov-action@v3
           with:
             files: ./frontend/coverage/lcov.info
             flags: frontend
   ```

2. Sign up for Codecov:
   - Visit https://about.codecov.io/
   - Connect GitHub repository
   - Add `CODECOV_TOKEN` to repository secrets

3. Add coverage badges to README.md:
   ```markdown
   [![Backend Coverage](https://codecov.io/gh/cladkins/SIEMBOX/branch/develop/graph/badge.svg?flag=backend)](https://codecov.io/gh/cladkins/SIEMBOX)
   [![Frontend Coverage](https://codecov.io/gh/cladkins/SIEMBOX/branch/develop/graph/badge.svg?flag=frontend)](https://codecov.io/gh/cladkins/SIEMBOX)
   ```

**Verification:**
- [ ] GitHub Actions workflow file created
- [ ] Workflow runs on push to develop
- [ ] PostgreSQL service starts correctly
- [ ] Tests execute in CI environment
- [ ] Coverage reports upload to Codecov
- [ ] Badges display in README

**Output:**
- `.github/workflows/test.yml`
- Updated `README.md` with badges
- Codecov integration configured

---

### Week 2: Backend Critical Path Tests

#### Task 2.1: Authentication & Authorization Tests
**Description:** Test security-critical authentication and authorization logic

**Priority:** 🔴 Critical (Security)

**Steps:**
1. Create `tests/unit/services/auth/authentication.test.ts`:
   - Test password hashing with bcrypt
   - Test JWT token generation and validation
   - Test login success and failure cases
   - Test session creation and cleanup
   - Test token expiration handling

2. Create `tests/unit/middleware/auth.test.ts`:
   - Test `authenticate` middleware with valid/invalid tokens
   - Test `authorize` middleware with different roles
   - Test unauthorized access attempts
   - Test missing/malformed Authorization headers

3. Create `tests/integration/api/auth.integration.test.ts`:
   - Test POST `/api/auth/login` (success, failure, validation)
   - Test POST `/api/auth/logout` (session cleanup)
   - Test protected routes require authentication
   - Test role-based access control (admin, analyst, viewer)
   - Use SuperTest for HTTP testing
   - Use Testcontainers for real database

4. Example integration test:
   ```typescript
   import request from 'supertest';
   import { app } from '@/app';
   import { setupTestDatabase, teardownTestDatabase } from '@tests/helpers/database';
   import { userFactory } from '@tests/helpers/factories';

   describe('Authentication API', () => {
     let pool;

     beforeAll(async () => {
       pool = await setupTestDatabase();
     }, 60000);

     afterAll(async () => {
       await teardownTestDatabase(pool);
     });

     describe('POST /api/auth/login', () => {
       it('should login with valid credentials', async () => {
         // Create user in database
         const user = await userFactory.create({ username: 'admin', role: 'admin' });

         const response = await request(app)
           .post('/api/auth/login')
           .send({ username: 'admin', password: 'changeme' })
           .expect(200);

         expect(response.body.token).toBeDefined();
         expect(response.body.user.username).toBe('admin');
         expect(response.body.user.role).toBe('admin');
       });

       it('should reject invalid credentials', async () => {
         await request(app)
           .post('/api/auth/login')
           .send({ username: 'admin', password: 'wrongpassword' })
           .expect(401);
       });

       it('should validate required fields', async () => {
         await request(app)
           .post('/api/auth/login')
           .send({ username: 'admin' })
           .expect(400);
       });
     });
   });
   ```

**Verification:**
- [ ] All authentication logic unit tested
- [ ] Middleware tests cover auth edge cases
- [ ] Integration tests cover full auth workflow
- [ ] Coverage >95% for auth-related code

**Output:**
- `tests/unit/services/auth/*.test.ts`
- `tests/unit/middleware/auth.test.ts`
- `tests/integration/api/auth.integration.test.ts`

---

#### Task 2.2: Parser Engine Tests
**Description:** Test log parsing with regex, grok, and JSON patterns

**Priority:** 🟡 High (Core Functionality)

**Steps:**
1. Create `tests/unit/services/parser/parserEngine.test.ts`:
   - Test regex pattern matching and field extraction
   - Test grok pattern parsing
   - Test JSON log parsing
   - Test parser priority ordering (lower number = higher priority)
   - Test parser selection for different log formats
   - Test error handling for invalid patterns

2. Reuse existing parser tests and expand:
   - Review `/tests/backend/parser-tests/` directory
   - Add tests for all 19 pre-built parsers
   - Add edge case tests (empty logs, malformed logs, Unicode)
   - Add performance tests (1000+ logs)

3. Create `tests/integration/workflows/log-parsing.integration.test.ts`:
   - Test end-to-end: raw log → parser selection → field extraction → database storage
   - Test parser reloading after configuration change
   - Test parser priority conflicts
   - Test multiple parsers matching same log

4. Use real log samples from fixtures:
   ```typescript
   const nginxLog = '[09/Jan/2026:10:00:00 +0000] 192.168.1.100 - GET /api/logs 200';
   const result = parserEngine.parse(nginxLog);

   expect(result.parsed).toBe(true);
   expect(result.fields.client_ip).toBe('192.168.1.100');
   expect(result.fields.method).toBe('GET');
   expect(result.fields.status_code).toBe('200');
   ```

**Verification:**
- [ ] Parser engine logic fully unit tested
- [ ] All 19 parsers have test coverage
- [ ] Edge cases handled correctly
- [ ] Integration tests cover end-to-end parsing
- [ ] Coverage >90% for parser engine

**Output:**
- `tests/unit/services/parser/parserEngine.test.ts`
- Updated `tests/backend/parser-tests/*.test.ts`
- `tests/integration/workflows/log-parsing.integration.test.ts`

---

#### Task 2.3: Rules Engine Tests
**Description:** Test detection rule evaluation and alert generation

**Priority:** 🟡 High (Core Functionality)

**Steps:**
1. Create `tests/unit/services/rules/rulesEngine.test.ts`:
   - Test condition evaluation (equals, contains, regex, greater than, less than)
   - Test boolean logic (AND, OR, NOT)
   - Test aggregation (count, distinct count, threshold)
   - Test time-based aggregation (events in time window)
   - Test rule priority
   - Test rule enabling/disabling

2. Create test cases for all condition types:
   ```typescript
   describe('Condition Evaluation', () => {
     it('should evaluate equals condition', () => {
       const condition = { field: 'status_code', operator: 'equals', value: '404' };
       const log = { status_code: '404' };
       expect(rulesEngine.evaluateCondition(condition, log)).toBe(true);
     });

     it('should evaluate contains condition', () => {
       const condition = { field: 'message', operator: 'contains', value: 'error' };
       const log = { message: 'An error occurred' };
       expect(rulesEngine.evaluateCondition(condition, log)).toBe(true);
     });

     it('should evaluate regex condition', () => {
       const condition = { field: 'ip', operator: 'regex', value: '^192\\.168\\.' };
       const log = { ip: '192.168.1.100' };
       expect(rulesEngine.evaluateCondition(condition, log)).toBe(true);
     });
   });
   ```

3. Create `tests/integration/workflows/detection-alerting.integration.test.ts`:
   - Test full workflow: parsed log → rule evaluation → alert creation
   - Test multiple rules matching same log
   - Test aggregation rules (5 failed logins → alert)
   - Test alert deduplication
   - Use Testcontainers for database

**Verification:**
- [ ] All condition operators tested
- [ ] Aggregation logic tested
- [ ] Integration tests cover full detection workflow
- [ ] Coverage >90% for rules engine

**Output:**
- `tests/unit/services/rules/rulesEngine.test.ts`
- `tests/integration/workflows/detection-alerting.integration.test.ts`

---

#### Task 2.4: Syslog Server Tests
**Description:** Test UDP/TCP syslog ingestion and parsing

**Priority:** 🟡 High (Core Functionality)

**Steps:**
1. Create `tests/unit/services/syslog/syslogParser.test.ts`:
   - Test RFC 3164 syslog format parsing
   - Test priority (PRI) extraction (facility + severity)
   - Test timestamp parsing
   - Test hostname extraction
   - Test app name and process ID extraction
   - Test message extraction (what gets stored in raw_logs)

2. Create `tests/integration/services/syslog/syslogServer.integration.test.ts`:
   - Start syslog server on dynamic port (port: 0)
   - Send UDP syslog messages
   - Verify messages stored in database
   - Test TCP syslog connection
   - Test malformed syslog messages
   - Test high-volume ingestion (1000+ messages)

3. Use real UDP sockets in integration tests:
   ```typescript
   import dgram from 'dgram';
   import { SyslogServer } from '@/services/syslog/syslogServer';

   describe('Syslog Server Integration', () => {
     let server: SyslogServer;
     let client: dgram.Socket;
     let port: number;

     beforeAll(async () => {
       server = new SyslogServer({ port: 0 });
       await server.start();
       port = server.getPort();
       client = dgram.createSocket('udp4');
     });

     it('should receive and store syslog message', async () => {
       const message = '<134>Jan 9 10:00:00 webserver nginx: GET /api 200';

       await new Promise((resolve) => {
         client.send(message, port, 'localhost', resolve);
       });

       // Wait for processing
       await new Promise((resolve) => setTimeout(resolve, 100));

       const logs = await pool.query('SELECT * FROM raw_logs ORDER BY created_at DESC LIMIT 1');
       expect(logs.rows[0].raw_message).toContain('GET /api 200');
       expect(logs.rows[0].app_name).toBe('nginx');
     });
   });
   ```

**Verification:**
- [ ] Syslog parser handles all RFC 3164 formats
- [ ] Integration tests use real UDP/TCP sockets
- [ ] High-volume ingestion tested
- [ ] Coverage >85% for syslog components

**Output:**
- `tests/unit/services/syslog/syslogParser.test.ts`
- `tests/integration/services/syslog/syslogServer.integration.test.ts`

---

#### Task 2.5: API Endpoint Tests
**Description:** Test all REST API endpoints with SuperTest

**Priority:** 🟡 High (User-Facing)

**Steps:**
1. Create integration tests for critical API routes:
   - `tests/integration/api/logs.integration.test.ts` - GET /api/logs (filtering, pagination)
   - `tests/integration/api/alerts.integration.test.ts` - GET/PUT /api/alerts
   - `tests/integration/api/parsers.integration.test.ts` - CRUD operations
   - `tests/integration/api/rules.integration.test.ts` - CRUD operations
   - `tests/integration/api/users.integration.test.ts` - Admin-only operations

2. Test patterns for each endpoint:
   - Authentication required (401 without token)
   - Authorization checks (403 if wrong role)
   - Input validation (400 for invalid data)
   - Success cases (200/201 with valid data)
   - Error handling (500 for server errors)
   - Pagination and filtering
   - Sorting

3. Example API test:
   ```typescript
   describe('Logs API', () => {
     let token: string;

     beforeAll(async () => {
       // Login to get token
       const response = await request(app)
         .post('/api/auth/login')
         .send({ username: 'admin', password: 'changeme' });
       token = response.body.token;
     });

     describe('GET /api/logs/parsed', () => {
       it('should require authentication', async () => {
         await request(app)
           .get('/api/logs/parsed')
           .expect(401);
       });

       it('should return paginated logs', async () => {
         const response = await request(app)
           .get('/api/logs/parsed?limit=10&offset=0')
           .set('Authorization', `Bearer ${token}`)
           .expect(200);

         expect(response.body.data).toBeInstanceOf(Array);
         expect(response.body.total).toBeDefined();
         expect(response.body.limit).toBe(10);
       });

       it('should filter by source IP', async () => {
         const response = await request(app)
           .get('/api/logs/parsed?source_ip=192.168.1.100')
           .set('Authorization', `Bearer ${token}`)
           .expect(200);

         response.body.data.forEach(log => {
           expect(log.parsed_data.client_ip).toBe('192.168.1.100');
         });
       });
     });
   });
   ```

**Verification:**
- [ ] All API endpoints have integration tests
- [ ] Authentication/authorization tested
- [ ] Input validation tested
- [ ] Error handling tested
- [ ] Coverage >80% for route handlers

**Output:**
- `tests/integration/api/*.integration.test.ts` (5+ files)

---

### Week 3: Frontend Critical Path Tests

#### Task 3.1: Frontend Authentication Store Tests
**Description:** Test Pinia authentication store logic

**Priority:** 🔴 Critical (Security)

**Steps:**
1. Create `test/unit/stores/auth.test.ts`:
   - Test login action (success, failure)
   - Test logout action (clear state, session cleanup)
   - Test token storage and retrieval
   - Test authenticated state getter
   - Test role-based permissions getter
   - Test token refresh logic

2. Use @pinia/testing helpers:
   ```typescript
   import { setActivePinia, createPinia } from 'pinia';
   import { useAuthStore } from '@/stores/auth';
   import { describe, it, expect, beforeEach, vi } from 'vitest';

   describe('Auth Store', () => {
     beforeEach(() => {
       setActivePinia(createPinia());
     });

     it('should login successfully', async () => {
       const store = useAuthStore();

       // Mock API call (will be intercepted by MSW)
       await store.login('admin', 'password');

       expect(store.isAuthenticated).toBe(true);
       expect(store.user?.username).toBe('admin');
       expect(store.token).toBeDefined();
     });

     it('should handle login error', async () => {
       const store = useAuthStore();

       await expect(
         store.login('admin', 'wrongpassword')
       ).rejects.toThrow();

       expect(store.isAuthenticated).toBe(false);
     });

     it('should logout and clear state', async () => {
       const store = useAuthStore();

       await store.login('admin', 'password');
       await store.logout();

       expect(store.isAuthenticated).toBe(false);
       expect(store.user).toBeNull();
       expect(store.token).toBeNull();
     });
   });
   ```

3. Configure MSW handlers for auth endpoints in `test/mocks/handlers.ts`

**Verification:**
- [ ] All store actions tested
- [ ] State getters tested
- [ ] MSW intercepts API calls correctly
- [ ] Coverage >80% for auth store

**Output:**
- `test/unit/stores/auth.test.ts`
- Updated `test/mocks/handlers.ts` with auth handlers

---

#### Task 3.2: Frontend Component Tests (Critical Views)
**Description:** Test core UI components and views

**Priority:** 🟡 High (User-Facing)

**Steps:**
1. Create component tests for critical views:
   - `test/unit/views/Login.test.ts` - Login form and validation
   - `test/unit/views/Dashboard.test.ts` - Statistics display
   - `test/unit/views/Logs.test.ts` - Log table, filtering, pagination
   - `test/unit/views/Alerts.test.ts` - Alert list, acknowledge button

2. Test patterns for each component:
   - Component renders correctly
   - Props are handled correctly
   - User interactions (clicks, inputs)
   - Events are emitted
   - Conditional rendering based on state
   - Loading/error states

3. Example component test:
   ```typescript
   import { mount } from '@vue/test-utils';
   import { describe, it, expect } from 'vitest';
   import LogsView from '@/views/Logs.vue';
   import { createTestingPinia } from '@pinia/testing';

   describe('Logs View', () => {
     it('should render log table', () => {
       const wrapper = mount(LogsView, {
         global: {
           plugins: [
             createTestingPinia({
               initialState: {
                 logs: {
                   items: [
                     { id: 1, message: 'Test log', timestamp: '2026-01-09' }
                   ]
                 }
               }
             })
           ]
         }
       });

       expect(wrapper.find('table').exists()).toBe(true);
       expect(wrapper.text()).toContain('Test log');
     });

     it('should handle refresh button click', async () => {
       const wrapper = mount(LogsView, {
         global: {
           plugins: [createTestingPinia({ stubActions: false })]
         }
       });

       await wrapper.find('button.refresh').trigger('click');

       // Verify store action was called (MSW will intercept API)
       const logsStore = useLogsStore();
       expect(logsStore.fetchLogs).toHaveBeenCalled();
     });
   });
   ```

4. Test Element Plus component integration:
   - ElTable, ElButton, ElForm usage
   - ElMessage notifications
   - ElDialog modals

**Verification:**
- [ ] Critical views have component tests
- [ ] User interactions tested
- [ ] Loading/error states tested
- [ ] Coverage >70% for critical views

**Output:**
- `test/unit/views/*.test.ts` (4+ files)

---

#### Task 3.3: Frontend API Service Tests
**Description:** Test API client and error handling

**Priority:** 🟡 High (Integration)

**Steps:**
1. Create `test/unit/services/api.test.ts`:
   - Test HTTP methods (GET, POST, PUT, DELETE)
   - Test authentication header injection
   - Test error handling (401, 403, 404, 500)
   - Test request/response interceptors
   - Test timeout handling

2. Use MSW for all network mocking:
   ```typescript
   import { api } from '@/services/api';
   import { describe, it, expect } from 'vitest';
   import { http, HttpResponse } from 'msw';
   import { server } from '@test/mocks/server';

   describe('API Service', () => {
     it('should fetch logs successfully', async () => {
       const logs = await api.getLogs({ limit: 10 });

       expect(logs.data).toHaveLength(10);
       expect(logs.total).toBeDefined();
     });

     it('should handle 401 unauthorized', async () => {
       server.use(
         http.get('/api/logs', () => {
           return new HttpResponse(null, { status: 401 });
         })
       );

       await expect(api.getLogs()).rejects.toThrow('Unauthorized');
     });

     it('should retry on network error', async () => {
       let attempts = 0;

       server.use(
         http.get('/api/logs', () => {
           attempts++;
           if (attempts < 3) {
             return HttpResponse.error();
           }
           return HttpResponse.json({ data: [], total: 0 });
         })
       );

       const logs = await api.getLogs();
       expect(attempts).toBe(3);
       expect(logs.data).toEqual([]);
     });
   });
   ```

**Verification:**
- [ ] All API methods tested
- [ ] Error handling tested
- [ ] MSW intercepts requests correctly
- [ ] Coverage >80% for API service

**Output:**
- `test/unit/services/api.test.ts`

---

## Checkpoints

### Checkpoint 1: Week 1 Complete (Setup)
**Validation:**
- [ ] Backend dependencies installed, Jest runs
- [ ] Frontend dependencies installed, Vitest runs
- [ ] Test directory structures created
- [ ] Database helpers with Testcontainers work
- [ ] Factories generate valid test data
- [ ] MSW server starts/stops correctly
- [ ] GitHub Actions workflow runs successfully
- [ ] Codecov integration working

**Deliverables:**
- Working Jest + Testcontainers setup
- Working Vitest + MSW setup
- Test helpers and factories
- CI/CD pipeline running

**Decision Point:**
If tests are too slow (>5 minutes total), investigate:
- Container startup optimization (reuse, caching)
- Parallel execution issues
- Database cleanup strategies

---

### Checkpoint 2: Week 2 Complete (Backend Critical Tests)
**Validation:**
- [ ] Authentication/authorization tests passing (>95% coverage)
- [ ] Parser engine tests passing (>90% coverage)
- [ ] Rules engine tests passing (>90% coverage)
- [ ] Syslog server tests passing (>85% coverage)
- [ ] API endpoint tests passing (>80% coverage)
- [ ] Backend coverage >60% overall
- [ ] No flaky tests (all tests pass consistently)

**Deliverables:**
- Comprehensive auth tests
- Parser and rules engine tests
- Syslog integration tests
- API integration tests

**Decision Point:**
If coverage <60%, identify gaps:
- Missing edge case tests?
- Untested error paths?
- Need more integration tests?

---

### Checkpoint 3: Week 3 Complete (Frontend Critical Tests)
**Validation:**
- [ ] Auth store tests passing (>80% coverage)
- [ ] Critical view tests passing (>70% coverage)
- [ ] API service tests passing (>80% coverage)
- [ ] Frontend coverage >50% overall
- [ ] All MSW handlers working correctly
- [ ] No console errors/warnings in tests

**Deliverables:**
- Auth store comprehensive tests
- Critical view component tests
- API service tests

**Decision Point:**
If coverage <50%, prioritize:
- More store tests (other stores)
- More component tests (forms, dialogs)
- More integration tests (user workflows)

---

## Verification

### Unit Tests
**Criteria:**
- [ ] All service methods have unit tests
- [ ] All models have CRUD tests
- [ ] All utilities have tests
- [ ] Edge cases covered
- [ ] Error paths tested

**Commands:**
```bash
# Backend
cd backend && npm test -- --coverage

# Frontend
cd frontend && npm test -- --coverage
```

### Integration Tests
**Criteria:**
- [ ] Authentication flow tested end-to-end
- [ ] Log ingestion pipeline tested
- [ ] Detection/alerting workflow tested
- [ ] API endpoints tested with SuperTest
- [ ] Database operations use Testcontainers

**Commands:**
```bash
# Run only integration tests
cd backend && npm test -- --testMatch='**/*.integration.test.ts'
```

### CI/CD
**Criteria:**
- [ ] Tests run on every push to develop
- [ ] Tests run on every pull request
- [ ] Coverage reports upload automatically
- [ ] Workflow completes in <10 minutes
- [ ] PostgreSQL service starts reliably

**Validation:**
- Check GitHub Actions tab for green checkmarks
- Review Codecov dashboard for coverage trends
- Verify badges display correctly in README

---

## Success Criteria

### Coverage Targets (Week 1-3)
- ✅ Backend: 60%+ overall coverage
- ✅ Backend critical services: 70%+ coverage
- ✅ Backend security code: 95%+ coverage
- ✅ Frontend: 50%+ overall coverage
- ✅ Frontend stores: 70%+ coverage

### Test Quality
- ✅ Zero flaky tests (100% pass rate)
- ✅ All critical paths have integration tests
- ✅ Tests run in <5 minutes (backend + frontend)
- ✅ CI/CD pipeline completes in <10 minutes

### Documentation
- ✅ Test helpers documented
- ✅ Factory usage examples provided
- ✅ Common test patterns documented
- ✅ Troubleshooting guide created

---

## Output

### Files Created/Modified
**Backend:**
- `backend/package.json` - Updated dependencies
- `backend/jest.config.js` - Enhanced configuration
- `backend/tests/setup.ts` - Global test setup
- `backend/tests/helpers/database.ts` - Testcontainers utilities
- `backend/tests/helpers/factories.ts` - Fishery factories
- `backend/tests/helpers/supertest.ts` - API test helpers
- `backend/tests/unit/**/*.test.ts` - Unit tests (20+ files)
- `backend/tests/integration/**/*.integration.test.ts` - Integration tests (10+ files)

**Frontend:**
- `frontend/package.json` - Updated dependencies
- `frontend/vitest.config.ts` - New configuration
- `frontend/test/setup.ts` - Global test setup
- `frontend/test/mocks/handlers.ts` - MSW handlers
- `frontend/test/mocks/server.ts` - MSW server
- `frontend/test/fixtures/mockData.ts` - Test data
- `frontend/test/unit/**/*.test.ts` - Unit tests (15+ files)

**CI/CD:**
- `.github/workflows/test.yml` - GitHub Actions workflow
- `README.md` - Coverage badges

**Documentation:**
- Update existing `docs/guides/TESTING_GUIDE.md` with new patterns

### Metrics
- Backend coverage: 60%+ → 80%+ (goal)
- Frontend coverage: 0% → 50%+ (goal)
- Test count: 8 → 100+ tests
- CI/CD: None → Automated with every push

---

## Next Steps

After completing Plan 1.1 (Weeks 1-3):

1. **Run coverage report:**
   ```bash
   cd backend && npm test -- --coverage
   cd frontend && npm test -- --coverage
   ```

2. **Review coverage gaps:**
   - Check HTML coverage reports
   - Identify untested files/functions
   - Prioritize remaining coverage

3. **Proceed to Plan 1.2:**
   - Comprehensive coverage (Weeks 4-6)
   - All remaining services, models, utilities
   - All remaining views, stores, composables
   - Target: 80% backend, 70% frontend

4. **Update project state:**
   - Update `.planning/STATE.md` with progress
   - Document any issues encountered
   - Record decisions made

---

**Plan Created:** 2026-01-09
**Estimated Duration:** 3 weeks
**Prerequisites:** None (ready to start)
**Next Plan:** 1.2 - Comprehensive Coverage (Weeks 4-6)
