# SIEMBox Testing Guide

Comprehensive guide to testing SIEMBox components, from unit tests to integration tests and validation workflows.

## Table of Contents

- [Overview](#overview)
- [Testing Philosophy](#testing-philosophy)
- [Quick Start](#quick-start)
- [Backend Testing](#backend-testing)
- [Frontend Testing](#frontend-testing)
- [Parser Testing](#parser-testing)
- [Integration Testing](#integration-testing)
- [Testing Best Practices](#testing-best-practices)
- [CI/CD Integration](#cicd-integration)
- [Troubleshooting Tests](#troubleshooting-tests)

---

## Overview

SIEMBox uses multiple testing strategies to ensure code quality and reliability:

| Test Type | Framework | Location | Purpose |
|-----------|-----------|----------|---------|
| **Backend Unit** | Jest | `/backend/tests` | Test individual functions/modules |
| **Backend Integration** | Jest | `/backend/tests` | Test API endpoints and workflows |
| **Frontend Unit** | Vitest | `/frontend/src/**/__tests__` | Test Vue components |
| **Parser Validation** | Custom | `/tests/backend/parser-tests` | Validate parser patterns |
| **Regression Tests** | Jest | `/backend/tests` | Prevent bug reintroduction |

## Testing Philosophy

1. **Test Behavior, Not Implementation**: Focus on what code does, not how it does it
2. **Write Tests First (when possible)**: TDD helps design better APIs
3. **Keep Tests Fast**: Unit tests should run in milliseconds
4. **Maintain Independence**: Each test should run in isolation
5. **Test the Happy Path AND Edge Cases**: Cover both success and failure scenarios

---

## Quick Start

### Run All Tests

```bash
# Backend tests
cd backend
npm test

# Frontend tests
cd frontend
npm test

# Parser validation tests
cd tests/backend/parser-tests
npm test
```

### Watch Mode (Auto-run on changes)

```bash
# Backend
cd backend
npm run test:watch

# Frontend
cd frontend
npm run test:watch
```

### Coverage Reports

```bash
# Backend coverage
cd backend
npm run test:coverage

# View HTML report
open coverage/index.html
```

---

## Backend Testing

### Test Structure

```
backend/
├── tests/                     # Integration and unit tests
│   ├── routes/               # API endpoint tests
│   │   ├── shippers.test.ts
│   │   └── shippers.integration.test.ts
│   ├── services/             # Service layer tests
│   │   └── syslog/
│   │       └── syslogParser.test.ts
│   ├── models/               # Database model tests
│   └── utils/                # Utility function tests
└── src/**/__tests__/         # Co-located tests (if any)
```

### Writing Backend Tests

**Example unit test:**

```typescript
// tests/services/parser/parserEngine.test.ts
import { describe, it, expect, jest } from '@jest/globals';
import { ParserEngine } from '../../../src/services/parser/parserEngine';

describe('ParserEngine', () => {
  it('should parse log with regex parser', () => {
    const parser = {
      pattern: '^(?<ip>\\d+\\.\\d+\\.\\d+\\.\\d+)',
      pattern_type: 'regex'
    };
    const message = '192.168.1.100 - test message';

    const result = ParserEngine.applyParser(parser, message);

    expect(result).toHaveProperty('ip', '192.168.1.100');
  });
});
```

**Example integration test:**

```typescript
// tests/routes/logs.integration.test.ts
import request from 'supertest';
import app from '../src/app';

describe('GET /api/logs/parsed', () => {
  let authToken: string;

  beforeAll(async () => {
    // Login and get token
    const response = await request(app)
      .post('/api/auth/login')
      .send({ username: 'admin', password: 'changeme' });
    authToken = response.body.token;
  });

  it('should return parsed logs', async () => {
    const response = await request(app)
      .get('/api/logs/parsed?limit=10')
      .set('Authorization', `Bearer ${authToken}`);

    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty('data');
    expect(Array.isArray(response.body.data)).toBe(true);
  });
});
```

### Mocking Dependencies

```typescript
// Mock database
jest.mock('../../src/config/database');
import { query } from '../../src/config/database';
const mockQuery = query as jest.MockedFunction<typeof query>;

// Setup mock behavior
mockQuery.mockResolvedValueOnce({
  rows: [{ id: 1, name: 'test' }],
  rowCount: 1,
  command: 'SELECT',
  oid: 0,
  fields: []
});
```

### Running Backend Tests

```bash
# All tests
npm test

# Specific test file
npm test -- shippers.test.ts

# Tests matching pattern
npm test -- --testNamePattern="should parse"

# With coverage
npm run test:coverage

# Watch mode
npm run test:watch
```

### Backend Test Documentation

For detailed backend testing information, see:
- **[Backend README](../../backend/README.md)** - Testing section
- **[Shipper Tests](../../backend/tests/README_SHIPPER_TESTS.md)** - Ghost shipper testing
- **[Syslog Parser Tests](../../backend/tests/)** - Syslog parsing validation

---

## Frontend Testing

### Test Structure

```
frontend/
└── src/
    ├── views/
    │   └── __tests__/
    │       └── Login.spec.ts
    ├── stores/
    │   └── __tests__/
    │       └── auth.spec.ts
    └── components/
        └── __tests__/
            └── MyComponent.spec.ts
```

### Writing Frontend Tests

**Example component test:**

```typescript
// src/views/__tests__/Login.spec.ts
import { describe, it, expect, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import Login from '../Login.vue';

describe('Login.vue', () => {
  it('renders login form', () => {
    const wrapper = mount(Login);

    expect(wrapper.find('form').exists()).toBe(true);
    expect(wrapper.find('input[type="text"]').exists()).toBe(true);
    expect(wrapper.find('input[type="password"]').exists()).toBe(true);
  });

  it('calls login on form submit', async () => {
    const wrapper = mount(Login);
    const loginSpy = vi.spyOn(wrapper.vm, 'handleLogin');

    await wrapper.find('form').trigger('submit');

    expect(loginSpy).toHaveBeenCalled();
  });
});
```

**Example store test:**

```typescript
// src/stores/__tests__/auth.spec.ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { setActivePinia, createPinia } from 'pinia';
import { useAuthStore } from '../auth';

// Mock API
vi.mock('@/services/api', () => ({
  api: {
    login: vi.fn()
  }
}));

describe('Auth Store', () => {
  beforeEach(() => {
    setActivePinia(createPinia());
  });

  it('should login successfully', async () => {
    const store = useAuthStore();
    const { api } = await import('@/services/api');

    (api.login as any).mockResolvedValue({
      data: { token: 'test-token', user: { id: 1 } }
    });

    await store.login('admin', 'password');

    expect(store.isAuthenticated).toBe(true);
    expect(store.token).toBe('test-token');
  });
});
```

### Running Frontend Tests

```bash
# All tests
npm test

# Watch mode
npm run test:watch

# UI mode (visual test runner)
npm run test:ui

# With coverage
npm run test:coverage
```

### Frontend Test Documentation

For detailed frontend testing information, see:
- **[Frontend README](../../frontend/README.md)** - Testing section

---

## Parser Testing

Parser testing is critical for ensuring logs are correctly parsed. SIEMBox has a dedicated parser test suite.

### Parser Test Structure

```
tests/backend/parser-tests/
├── README.md                      # Parser test overview
├── fixtures.ts                    # Test log samples
├── testUtils.ts                   # Test utilities
├── nginxParser.test.ts            # NGINX parser tests
├── parserIntegration.test.ts      # Integration tests
└── parserRegression.test.ts       # Regression tests
```

### Writing Parser Tests

```typescript
// tests/backend/parser-tests/myParser.test.ts
import { describe, it, expect } from '@jest/globals';
import { testRegexPattern, shouldMatch } from './testUtils';

describe('MyApp Parser', () => {
  const pattern = /^\[(?<timestamp>[^\]]+)\].*(?<status>\d{3})/;

  it('should match standard log format', () => {
    const message = '[2025-01-09 10:00:00] GET /api 200';

    expect(shouldMatch(pattern, message)).toBe(true);
  });

  it('should extract timestamp and status', () => {
    const message = '[2025-01-09 10:00:00] GET /api 200';
    const fields = testRegexPattern(pattern, message);

    expect(fields.timestamp).toBe('2025-01-09 10:00:00');
    expect(fields.status).toBe('200');
  });

  it('should NOT match invalid format', () => {
    const message = 'This is not a valid log';

    expect(shouldMatch(pattern, message)).toBe(false);
  });
});
```

### Parser Validation Workflow

1. **Create test fixtures** with sample log messages
2. **Write tests** for positive and negative cases
3. **Test edge cases** (empty fields, special characters, truncated logs)
4. **Run validation suite**
5. **Deploy parser** after all tests pass

### Running Parser Tests

```bash
cd tests/backend/parser-tests

# All parser tests
npm test

# Specific parser
npm test -- nginxParser.test.ts

# Watch mode
npm run test:watch
```

### Parser Test Documentation

For detailed parser testing information, see:
- **[Parser Test README](../../tests/backend/parser-tests/README.md)** - Parser testing overview
- **[Parser Validation Workflow](../../tests/backend/PARSER_VALIDATION_WORKFLOW.md)** - Step-by-step workflow
- **[Parser Test Guide](../../tests/backend/TEST_GUIDE.md)** - Detailed test guide
- **[Test Suite Manifest](../../tests/backend/TEST_SUITE_MANIFEST.md)** - Complete test inventory
- **[Quick Reference](../../tests/backend/QUICK_REFERENCE.md)** - Common commands

---

## Integration Testing

Integration tests verify that multiple components work together correctly.

### Integration Test Scenarios

1. **Log Ingestion Flow**: Syslog → Parser → Database → Rules → Alerts
2. **API Workflows**: Login → Fetch Data → Update → Logout
3. **User Management**: Create User → Assign Role → Authenticate → Delete
4. **Shipper Registration**: Register → Fetch Config → Send Logs → Detect

### Example Integration Test

```typescript
// tests/integration/logIngestion.integration.test.ts
import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';

describe('Log Ingestion Integration', () => {
  beforeAll(async () => {
    // Setup: Start services, create parser
  });

  afterAll(async () => {
    // Cleanup: Stop services, remove test data
  });

  it('should ingest, parse, and detect', async () => {
    // 1. Send syslog message
    await sendSyslogMessage('192.168.1.100 - Failed login');

    // 2. Verify raw log created
    const rawLog = await getRawLog();
    expect(rawLog).toBeDefined();

    // 3. Verify log was parsed
    const parsedLog = await getParsedLog(rawLog.id);
    expect(parsedLog).toHaveProperty('parsed_data');
    expect(parsedLog.parsed_data.client_ip).toBe('192.168.1.100');

    // 4. Verify alert was created
    const alerts = await getAlerts();
    expect(alerts).toHaveLength(1);
    expect(alerts[0].message).toContain('Failed login');
  });
});
```

### Running Integration Tests

```bash
# Run integration tests
npm test -- --testNamePattern="integration"

# Or run specific integration test file
npm test -- logs.integration.test.ts
```

---

## Testing Best Practices

### 1. Test Naming

**Good:**
```typescript
it('should return 404 when user not found')
it('should parse NGINX access log with standard format')
it('should NOT match invalid syslog format')
```

**Bad:**
```typescript
it('test1')
it('works')
it('parser test')
```

### 2. Arrange-Act-Assert Pattern

```typescript
it('should create user', async () => {
  // Arrange
  const userData = { username: 'test', password: 'pass' };

  // Act
  const user = await UserModel.create(userData);

  // Assert
  expect(user).toHaveProperty('id');
  expect(user.username).toBe('test');
});
```

### 3. Don't Test Implementation Details

**Bad (testing implementation):**
```typescript
it('should call parseMessage internally', () => {
  const spy = jest.spyOn(parser, '_parseMessage');
  parser.process(message);
  expect(spy).toHaveBeenCalled();
});
```

**Good (testing behavior):**
```typescript
it('should extract IP from message', () => {
  const result = parser.process('192.168.1.100 - test');
  expect(result.ip).toBe('192.168.1.100');
});
```

### 4. Use Descriptive Matchers

```typescript
// Specific matchers are better
expect(array).toHaveLength(3);  // ✅
expect(array.length).toBe(3);   // ❌

expect(obj).toHaveProperty('key', 'value');  // ✅
expect(obj.key).toBe('value');                // ❌

expect(str).toMatch(/pattern/);  // ✅
expect(/pattern/.test(str)).toBe(true);  // ❌
```

### 5. Avoid Test Interdependence

```typescript
// Bad - tests depend on each other
let userId;
it('creates user', async () => {
  userId = await createUser();
});
it('updates user', async () => {
  await updateUser(userId);  // Depends on previous test
});

// Good - each test is independent
it('creates user', async () => {
  const userId = await createUser();
  expect(userId).toBeDefined();
});
it('updates user', async () => {
  const userId = await createUser();  // Create own test data
  await updateUser(userId);
});
```

### 6. Test Edge Cases

```typescript
describe('Parser Edge Cases', () => {
  it('should handle empty input', () => {
    expect(parse('')).toBeNull();
  });

  it('should handle very long input', () => {
    const longString = 'x'.repeat(10000);
    expect(() => parse(longString)).not.toThrow();
  });

  it('should handle special characters', () => {
    const special = '!@#$%^&*()';
    expect(() => parse(special)).not.toThrow();
  });

  it('should handle null/undefined', () => {
    expect(parse(null)).toBeNull();
    expect(parse(undefined)).toBeNull();
  });
});
```

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Tests

on: [push, pull_request]

jobs:
  backend-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '20'
      - run: cd backend && npm install
      - run: cd backend && npm test
      - run: cd backend && npm run test:coverage
      - uses: codecov/codecov-action@v3
        with:
          files: ./backend/coverage/lcov.info

  frontend-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '20'
      - run: cd frontend && npm install
      - run: cd frontend && npm test
```

### Pre-commit Hooks

```bash
# Install husky
npm install --save-dev husky

# Add pre-commit hook
npx husky install
npx husky add .husky/pre-commit "npm test"
```

---

## Troubleshooting Tests

### Tests Fail Intermittently

**Cause**: Race conditions, timing issues, or test interdependence

**Solution**:
- Add proper async/await
- Use `beforeEach` to reset state
- Increase timeouts for slow operations
- Mock time-dependent functions

### Tests Pass Locally But Fail in CI

**Cause**: Environment differences

**Solution**:
- Check Node.js version matches
- Verify environment variables
- Ensure database is seeded consistently
- Check for hardcoded paths or ports

### Slow Test Suite

**Cause**: Too many integration tests, network calls, or database operations

**Solution**:
- Mock external dependencies
- Use in-memory databases for tests
- Parallelize test execution
- Split slow tests into separate suite

### Coverage Not Increasing

**Cause**: Untested code paths, especially error handling

**Solution**:
- Check coverage report for uncovered lines
- Add tests for error paths
- Test edge cases
- Remove dead code

---

## Test Coverage Goals

| Component | Current | Goal |
|-----------|---------|------|
| Backend Services | ~30% | 70%+ |
| Backend Routes | ~20% | 80%+ |
| Backend Models | ~40% | 90%+ |
| Frontend Components | ~10% | 70%+ |
| Frontend Stores | ~15% | 80%+ |
| Parsers | ~60% | 95%+ |

---

## Additional Resources

### Backend Testing
- **[Backend README](../../backend/README.md)** - Testing section
- **[Jest Documentation](https://jestjs.io/)**
- **[Supertest Documentation](https://github.com/visionmedia/supertest)**

### Frontend Testing
- **[Frontend README](../../frontend/README.md)** - Testing section
- **[Vitest Documentation](https://vitest.dev/)**
- **[Vue Test Utils](https://test-utils.vuejs.org/)**

### Parser Testing
- **[Parser Test README](../../tests/backend/parser-tests/README.md)**
- **[Parser Validation Workflow](../../tests/backend/PARSER_VALIDATION_WORKFLOW.md)**
- **[Test Guide](../../tests/backend/TEST_GUIDE.md)**

### General Testing
- **[Testing Library Best Practices](https://kentcdodds.com/blog/common-mistakes-with-react-testing-library)**
- **[Test-Driven Development](https://martinfowler.com/bliki/TestDrivenDevelopment.html)**

---

## Contributing Tests

When contributing to SIEMBox:

1. ✅ Add tests for new features
2. ✅ Update existing tests when changing behavior
3. ✅ Ensure all tests pass before submitting PR
4. ✅ Aim for 70%+ code coverage on new code
5. ✅ Document test setup if complex

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for full guidelines.
