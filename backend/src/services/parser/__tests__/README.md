# Parser Test Suite Documentation

## Overview

This directory contains comprehensive tests for the SIEMBox parser system, with a focus on NGINX parser validation and regression testing for existing parsers.

## Test Structure

### Test Files

1. **syslogParser.test.ts** - Unit tests for syslog parsing (RFC 3164/5424)
   - Priority/facility/severity calculation
   - Timestamp parsing (BSD format)
   - Hostname and TAG extraction
   - Process ID extraction
   - Message extraction
   - Error handling

2. **nginxParser.test.ts** - Unit tests for NGINX-specific patterns
   - NGINX access log pattern matching
   - NGINX error log pattern matching
   - Field extraction from logs
   - Edge cases (IPv6, long user agents, special characters)
   - Negative test cases (Apache, SSH, system logs)
   - Parser collision detection

3. **parserIntegration.test.ts** - Integration tests for full pipeline
   - Syslog extraction to parser pipeline
   - Message preparation for parsing
   - Full end-to-end pipeline tests
   - Field extraction validation
   - Handling of malformed logs
   - Performance characteristics

4. **parserRegression.test.ts** - Regression tests for existing parsers
   - SSH parser functionality
   - Sudo parser functionality
   - Apache parser functionality
   - No cross-contamination between parsers
   - Backward compatibility
   - Load testing

### Test Utilities

**fixtures.ts** - Test data and fixtures
- Syslog format examples
- NGINX log variants (access and error)
- Negative test cases
- Parser configuration templates

**testUtils.ts** - Helper functions for testing
- Pattern matching utilities
- Group extraction functions
- Field mapping and validation
- Batch testing functions

## Running Tests

### Install Dependencies

First, install Jest and TypeScript testing dependencies:

```bash
cd /Users/chrisadkins/Projects/SIEMBox/backend
npm install
```

### Run All Tests

```bash
npm test
```

### Run Specific Test Suites

```bash
# Test only syslog parser
npm run test:syslog

# Test only parser patterns
npm run test:parser

# Run tests in watch mode (for development)
npm run test:watch

# Generate coverage report
npm run test:coverage
```

### Run Individual Test Files

```bash
# Test syslog parser specifically
npm test -- src/services/syslog/__tests__/syslogParser.test.ts

# Test NGINX parser patterns
npm test -- src/services/parser/__tests__/nginxParser.test.ts

# Test integration
npm test -- src/services/parser/__tests__/parserIntegration.test.ts

# Test regression
npm test -- src/services/parser/__tests__/parserRegression.test.ts
```

## Test Coverage Goals

Target coverage metrics:

| Category | Target |
|----------|--------|
| Line Coverage | >80% |
| Branch Coverage | >75% |
| Function Coverage | >80% |
| Statement Coverage | >80% |

View coverage report:

```bash
npm run test:coverage
# Open coverage/index.html in browser
```

## NGINX Parser Test Status

### Pending Patterns

The NGINX parser tests are designed to activate once the backend-architect provides corrected parser patterns. Tests will use `pending()` if patterns are not yet set.

The tests expect patterns for:

1. **NGINX Access Log Pattern**
   - Should match: Standard NGINX access logs with various field combinations
   - Should NOT match: Apache, SSH, or system logs
   - Required fields: client_ip, method, path, status_code (minimum)

2. **NGINX Error Log Pattern**
   - Should match: NGINX error logs with [error], [warn], [crit] levels
   - Should NOT match: Access logs or other application logs
   - Required fields: timestamp, severity, pid (minimum)

### Sample Logs for Testing

Once patterns are provided, the following real database samples should parse correctly:

```
1. <134>Dec 09 20:36:20 komodo NGINX: [09/Dec/2025:20:35:53 +0000] - 200 200 - GET
2. <134>Dec 09 20:36:19 komodo NGINX: [09/Dec/2025:20:12:14 +0000] 301 - GET http w
3. <134>Dec 09 20:36:19 komodo NGINX: 2025/12/08 19:37:36 [error] 1484#1484: *17597
4. <134>Dec 09 19:52:03 komodo NGINX: 68.218.17.107 -
```

## How to Enable NGINX Parser Tests

When the backend-architect provides corrected patterns:

1. Update the pattern constants in `nginxParser.test.ts`:
   ```typescript
   const NGINX_ACCESS_PATTERN = '<your-actual-pattern-here>';
   const NGINX_ERROR_PATTERN = '<your-actual-pattern-here>';
   ```

2. Run tests to see which tests now pass:
   ```bash
   npm run test:parser
   ```

3. All tests should pass with the corrected patterns. If any fail, the patterns may need refinement.

## Test Design Principles

### Arrange-Act-Assert Pattern

All tests follow the AAA pattern:

```typescript
describe('Feature under test', () => {
  it('should do something specific', () => {
    // Arrange: Set up test data and conditions
    const input = 'test data';

    // Act: Perform the action being tested
    const result = parseFunction(input);

    // Assert: Verify the expected outcome
    expect(result).toEqual(expectedValue);
  });
});
```

### Isolation and Independence

- Each test is independent and can run in any order
- Tests use fixtures instead of shared state
- Mock objects are used for external dependencies
- No database calls in unit tests

### Clear Test Names

Test names describe what is being tested and the expected behavior:

```typescript
it('should extract client IP from standard access log format', () => {
  // Clear what is tested (extraction), what input (standard format), what expected
});
```

### Negative Testing

Tests include both positive (should match) and negative (should NOT match) cases to ensure:
- Parsers are specific enough to not false-match
- Different log types are distinguishable
- Edge cases are handled

## Common Issues and Solutions

### Jest Not Found

If Jest is not found, reinstall dependencies:

```bash
rm -rf node_modules
npm install
```

### Tests Timeout

If tests timeout, increase the timeout in `jest.config.js`:

```javascript
testTimeout: 10000, // milliseconds
```

### Pattern Not Set Warning

Tests use `pending()` when patterns aren't provided. This is intentional and shows as pending in test output. Once patterns are provided, remove the `pending()` call.

### Coverage Not Generated

Ensure `jest.config.js` has coverage settings and run:

```bash
npm run test:coverage
```

## Adding New Parser Tests

To add tests for a new parser:

1. Create a new test file: `src/services/parser/__tests__/parserName.test.ts`
2. Add test fixtures to `fixtures.ts`
3. Add test utilities to `testUtils.ts` if needed
4. Follow the same pattern as existing tests
5. Ensure both positive and negative cases are tested

Example structure:

```typescript
import { PARSER_FIXTURES, NEGATIVE_TEST_CASES } from './fixtures';
import { testRegexPattern, shouldMatch, shouldNotMatch } from './testUtils';

describe('MyParser Tests', () => {
  const MY_PARSER_PATTERN = ''; // Pattern from backend-architect

  describe('Positive cases', () => {
    it('should match valid logs', () => {
      const fixture = PARSER_FIXTURES.my_log;
      expect(shouldMatch(MY_PARSER_PATTERN, fixture.message)).toBe(true);
    });
  });

  describe('Negative cases', () => {
    it('should NOT match other log types', () => {
      const otherLog = 'some other log format';
      expect(shouldNotMatch(MY_PARSER_PATTERN, otherLog)).toBe(true);
    });
  });
});
```

## Integration with CI/CD

These tests are designed to run in CI/CD pipelines:

```yaml
# Example GitHub Actions
- name: Run tests
  run: npm test -- --coverage --verbose

- name: Upload coverage
  uses: codecov/codecov-action@v3
  with:
    files: ./coverage/lcov.info
```

## Debugging Tests

### Run Single Test

```bash
npm test -- --testNamePattern="should parse NGINX access log"
```

### Enable Debug Output

```bash
DEBUG=* npm test
```

### Run with Verbose Output

```bash
npm test -- --verbose
```

## Future Enhancements

- [ ] E2E tests with actual database
- [ ] Performance benchmarking
- [ ] Snapshot testing for parser output
- [ ] Mutation testing to validate test quality
- [ ] Integration with code coverage reporting tools

## Contact and Issues

If you encounter issues with tests:

1. Check test output for detailed error messages
2. Review the fixture data and expected values
3. Ensure patterns are correctly formatted regex
4. Verify syslog format compliance with RFC 3164/5424

For parser pattern issues, coordinate with the backend-architect team.
