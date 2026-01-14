# Testing Practices

## Testing Framework

### Backend Testing Stack
- **Framework**: Jest 29.7.0
- **TypeScript support**: ts-jest 29.1.1
- **Preset**: `ts-jest`
- **Test environment**: `node`
- **Mocking**: Jest built-in mocking

### Frontend Testing Stack
- **Framework**: Vitest (Vite-native)
- **Component testing**: @vue/test-utils
- **Mocking**: vi (Vitest mocking API)

## Jest Configuration

**File**: `/backend/jest.config.js`

```javascript
{
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/server.ts',
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html']
}
```

## Test Organization

### Directory Structure
```
/tests/
  └── backend/
      ├── parser-tests/
      │   ├── fixtures.ts              # Test data
      │   ├── testUtils.ts             # Test helpers
      │   ├── nginxParser.test.ts      # Parser tests
      │   ├── parserIntegration.test.ts # Integration
      │   └── parserRegression.test.ts  # Regression
      └── syslog-tests/
          └── syslogParser.test.ts

/backend/tests/                        # Alternative location
  ├── routes/
  │   ├── shippers.test.ts            # Unit tests
  │   └── shippers.integration.test.ts # Integration
  └── services/
      └── syslog/
          └── syslogParser.test.ts

/frontend/src/views/__tests__/         # Co-located
  └── Shippers-ActivityLog.spec.ts
```

### File Naming
- **Unit tests**: `[name].test.ts`
- **Integration tests**: `[name].integration.test.ts`
- **Spec tests** (frontend): `[name].spec.ts`
- **Test utilities**: `testUtils.ts`
- **Test fixtures**: `fixtures.ts`

## Test Structure

### Describe Blocks
```typescript
describe('NGINX Parser Patterns', () => {
  describe('NGINX Access Log Patterns', () => {
    describe('Basic access log parsing', () => {
      it('should match standard NGINX access log format', () => {
        // Test implementation
      });
    });
  });
});
```

**Standards:**
- Organize hierarchically
- Use descriptive names
- Group related test cases

### Test Case Organization (AAA Pattern)
```typescript
it('should detect single ghost shipper with logs', async () => {
  // Arrange: Set up test data and mocks
  const ghostShipperId = 'deadbeef';
  mockQuery.mockResolvedValueOnce({ rows: [] });

  // Act: Execute the code under test
  const result = await getUnknownShippers();

  // Assert: Verify expected outcomes
  expect(result.rows).toHaveLength(1);
  expect(result.rows[0].shipper_id).toBe(ghostShipperId);
});
```

## Mocking Patterns

### Backend (Jest)
```typescript
// Mock entire module
jest.mock('../../src/config/database');

// Mock specific function
const mockQuery = query as jest.MockedFunction<typeof query>;

// Setup mock behavior
mockQuery.mockResolvedValueOnce({
  rows: [],
  rowCount: 0,
  command: 'SELECT',
  oid: 0,
  fields: [],
});

// Mock implementation
mockQuery.mockImplementation(async (sql, params) => {
  return { rows: mockData };
});
```

### Frontend (Vitest)
```typescript
// Mock module
vi.mock('@/services/api', () => ({
  api: {
    getShippers: vi.fn(),
    getShipper: vi.fn(),
    getShipperActivity: vi.fn(),
  },
}));

// Use mock
const { api } = await import('@/services/api');
(api.getShipper as any).mockResolvedValue({
  data: mockShipper
});

// Clear mocks
beforeEach(() => {
  vi.clearAllMocks();
});
```

## Test Utilities

**Location**: `tests/backend/parser-tests/testUtils.ts`

**Custom helpers:**
- `createMockParser()` - Create mock parser objects
- `testRegexPattern()` - Test regex pattern matching
- `extractNamedGroups()` - Extract named capture groups
- `extractNumberedGroups()` - Extract numbered groups
- `mapGroupsToFields()` - Map groups to field names
- `shouldMatch()` / `shouldNotMatch()` - Boolean matching
- `testPatternBatch()` - Test against multiple inputs
- `validateFields()` - Compare extracted vs expected fields

**Example usage:**
```typescript
import { testRegexPattern, shouldMatch } from './testUtils';

it('should match pattern', () => {
  const result = shouldMatch(pattern, message);
  expect(result).toBe(true);
});

it('should extract correct fields', () => {
  const fields = testRegexPattern(pattern, message);
  expect(fields.status_code).toBe('200');
  expect(fields.method).toBe('GET');
});
```

## Test Data Management

### Fixtures
**File**: `fixtures.ts`

```typescript
export const NGINX_PARSER_FIXTURES = {
  access_log_full: {
    message: '[09/Dec/2025:20:35:53 +0000] 192.168.1.100 - 200...',
    expected: {
      timestamp: '09/Dec/2025:20:35:53 +0000',
      client_ip: '192.168.1.100',
      status_code: '200',
    }
  },
  error_log_standard: {
    message: '2025/12/09 20:35:53 [error] 1234#0: *1 ...',
    expected: { /* ... */ }
  }
};

export const NEGATIVE_TEST_CASES = {
  apache_variations: ['...'],
  ssh_variations: ['...'],
};
```

**Standards:**
- Separate file for test data
- Named exports for data sets
- Include positive and negative cases
- Realistic data mirroring production

## Test Descriptions

**Good examples:**
```typescript
it('should NOT return registered shipper as unknown')
it('should handle activity log fetch failure gracefully')
it('should match standard NGINX access log format')
it('should extract client IP from log message')
```

**Standards:**
- Use `it('should ...')` format
- Be specific and descriptive
- Include context in description

## Assertions

### Common Matchers
```typescript
// Equality
expect(value).toBe(expected)
expect(object).toEqual(expectedObject)

// Arrays
expect(array).toHaveLength(3)
expect(array).toContain(item)

// Objects
expect(object).toHaveProperty('key', 'value')
expect(object).toMatchObject({ key: 'value' })

// Functions
expect(fn).toHaveBeenCalled()
expect(fn).toHaveBeenCalledWith(arg1, arg2)
expect(fn).toHaveBeenCalledTimes(2)

// Strings/Regex
expect(value).toMatch(/regex/)
expect(string).toContain('substring')

// Types
expect(error).toBeInstanceOf(ApiError)
expect(value).toBeDefined()
expect(value).toBeNull()
expect(value).toBeTruthy()
```

### Multiple Assertions
```typescript
it('should extract all log fields correctly', () => {
  const result = parseLog(logMessage);

  // Multiple assertions per test OK for complex objects
  expect(result.timestamp).toBe('2025-12-09T20:35:53Z');
  expect(result.client_ip).toBe('192.168.1.100');
  expect(result.method).toBe('GET');
  expect(result.status_code).toBe('200');
});
```

## Test Categories

### Unit Tests
- Test individual functions/methods in isolation
- Mock all external dependencies
- Fast execution
- High coverage of edge cases

**Example:**
```typescript
describe('Parser Engine', () => {
  it('should apply regex parser correctly', () => {
    const parser = { type: 'regex', pattern: '/.../' };
    const result = applyParser(parser, message);
    expect(result).toMatchObject(expected);
  });
});
```

### Integration Tests
- Test multiple components together
- May use real database/services
- File suffix: `.integration.test.ts`
- Test realistic workflows

**Example:**
```typescript
describe('Shipper Registration (Integration)', () => {
  it('should register shipper and return config', async () => {
    const response = await request(app)
      .post('/api/shippers/register')
      .send({ api_key: validKey });

    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty('siem_host');
  });
});
```

### Regression Tests
- Prevent previously fixed bugs
- Document bug context in comments
- File suffix: `.regression.test.ts` or grouped

**Example:**
```typescript
describe('Regression Prevention', () => {
  /**
   * CRITICAL: Prevents bytea casting bug re-introduction
   * Context: Bug caused all shippers to appear as unknown
   */
  it('must use decode(api_key, hex) not api_key::bytea', () => {
    // Test that prevents specific bug
  });
});
```

## Coverage Practices

### Configuration
- **Coverage directory**: `coverage/`
- **Reporters**: text, lcov, html
- **Exclusions**:
  - Type definitions (`*.d.ts`)
  - Entry points (`server.ts`)

### Commands
```bash
npm run test              # Run all tests
npm run test:watch        # Watch mode
npm run test:coverage     # Generate coverage report
npm run test:parser       # Run specific test suite
npm run test:syslog       # Run specific test suite
```

### Coverage Targets
- **Unit tests**: Aim for 70%+ coverage
- **Critical paths**: 90%+ coverage
- **Services**: High priority for coverage
- **Routes**: Test success and error paths

## Lifecycle Hooks

```typescript
describe('Test Suite', () => {
  beforeAll(() => {
    // Run once before all tests
    setupDatabase();
  });

  beforeEach(() => {
    // Run before each test
    vi.clearAllMocks();
    resetTestData();
  });

  afterEach(() => {
    // Run after each test
    cleanupTestData();
  });

  afterAll(() => {
    // Run once after all tests
    closeDatabase();
  });

  it('test case', () => {
    // Test implementation
  });
});
```

## Async Testing

```typescript
// Async/await
it('should fetch data asynchronously', async () => {
  const result = await fetchData();
  expect(result).toBeDefined();
});

// Promise rejection
it('should handle errors', async () => {
  await expect(failingFunction()).rejects.toThrow();
});

// With timeout
it('should complete quickly', async () => {
  const result = await fastOperation();
  expect(result).toBe(expected);
}, 1000); // 1 second timeout
```

## Testing Edge Cases

**Documented patterns:**
- Empty arrays/objects
- Null/undefined values
- Very large numbers or strings
- Special characters
- Concurrent operations
- Error conditions
- Boundary values

**Examples:**
```typescript
describe('Edge Cases', () => {
  it('should return empty array when no logs exist', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [] });
    const result = await getLogs();
    expect(result).toEqual([]);
  });

  it('should handle very long strings', () => {
    const longString = 'A'.repeat(10000);
    expect(shouldMatch(pattern, longString)).toBe(true);
  });

  it('should handle special characters', () => {
    const specialChars = '!@#$%^&*()_+-=[]{}|;:",.<>?/\\';
    expect(() => parseLog(specialChars)).not.toThrow();
  });

  it('should handle concurrent requests', async () => {
    const promises = Array(10).fill(null).map(() => fetchData());
    const results = await Promise.all(promises);
    expect(results).toHaveLength(10);
  });
});
```

## Test Documentation

### Comments in Tests
```typescript
/**
 * CRITICAL TEST: Validates ghost shipper detection
 *
 * Background: A bytea casting bug caused all registered
 * shippers to be returned as "unknown"
 *
 * This test ensures the fix remains in place
 */
it('should NOT return registered shippers as unknown', async () => {
  // Arrange: Create registered shipper
  const apiKey = 'validkey123';
  const shipperId = generateShipperId(apiKey);

  // Act: Query for unknown shippers
  const result = await getUnknownShippers();

  // Assert: Registered shipper should NOT appear
  expect(result.find(s => s.id === shipperId)).toBeUndefined();
});
```

**Standards:**
- Explain complex setup
- Document bug context for regression tests
- Mark critical tests with `CRITICAL:` prefix
- Note dependencies or prerequisites

## Running Tests

### Backend Commands
```bash
# All tests
npm run test

# Watch mode (auto-run on file changes)
npm run test:watch

# Coverage report
npm run test:coverage

# Specific test file
npm run test -- shippers.test.ts

# Specific test suite
npm run test:parser
npm run test:syslog
```

### Frontend Commands
```bash
# All tests
npm run test

# Watch mode
npm run test:watch

# UI mode (Vitest UI)
npm run test:ui
```

### Test Output
```
PASS  tests/routes/shippers.test.ts
  ✓ should return all shippers (15ms)
  ✓ should detect ghost shippers (8ms)
  ✓ should NOT return registered shippers as unknown (5ms)

Test Suites: 1 passed, 1 total
Tests:       3 passed, 3 total
Time:        2.345s
```

## Best Practices

### 1. Isolation
- Tests don't depend on each other
- Each test can run independently
- Use beforeEach to reset state

### 2. Clarity
- Test names clearly describe behavior
- Arrange-Act-Assert pattern
- One logical assertion per test

### 3. Completeness
- Test success paths
- Test error paths
- Test edge cases

### 4. Speed
- Unit tests run quickly (<50ms each)
- Mock external dependencies
- Use in-memory databases for integration tests

### 5. Maintainability
- Use test utilities to reduce duplication
- Keep tests simple and readable
- Update tests when code changes

### 6. Documentation
- Complex tests include comments
- Regression tests document bug context
- Critical tests marked clearly

### 7. Determinism
- Tests produce consistent results
- No flaky tests
- No dependencies on external state

### 8. Focused
- Each test validates one behavior
- Don't test implementation details
- Test public API, not internals

## Current Test Coverage

**Backend:**
- 8 test files identified
- Core services need more coverage
- Critical paths: syslog parser, parser engine
- Models and routes: limited coverage

**Frontend:**
- Minimal test coverage
- Component tests needed
- Store tests needed
- Integration tests with API mocking

**Recommendations:**
1. Add unit tests for core services (70%+ coverage goal)
2. Add integration tests for critical paths
3. Implement frontend component tests
4. Add E2E tests for key user workflows
5. Set up CI/CD to run tests automatically

## Test Utilities Worth Creating

1. **Database test helpers**: Setup/teardown test database
2. **Auth helpers**: Generate test tokens, mock auth
3. **API test client**: Wrapper for supertest requests
4. **Factory functions**: Create test data (users, logs, parsers)
5. **Assertion helpers**: Custom matchers for domain objects
6. **Mock builders**: Fluent API for creating mocks

## Testing Anti-Patterns to Avoid

❌ **Testing implementation details**
```typescript
// BAD: Testing internal method
expect(service._privateMethod()).toBe(value);
```

✅ **Test public behavior**
```typescript
// GOOD: Testing public API
expect(service.process(input)).toBe(output);
```

❌ **Multiple unrelated assertions**
```typescript
// BAD: Testing unrelated things
it('should work', () => {
  expect(parseLog()).toBe(result);
  expect(formatDate()).toBe(date);
  expect(validateUser()).toBe(true);
});
```

✅ **Focused tests**
```typescript
// GOOD: One concept per test
it('should parse log correctly', () => {
  expect(parseLog()).toBe(result);
});

it('should format date correctly', () => {
  expect(formatDate()).toBe(date);
});
```

❌ **Brittle tests**
```typescript
// BAD: Depends on exact array order
expect(results).toEqual([item1, item2, item3]);
```

✅ **Flexible assertions**
```typescript
// GOOD: Check content, not order
expect(results).toContain(item1);
expect(results).toHaveLength(3);
```
