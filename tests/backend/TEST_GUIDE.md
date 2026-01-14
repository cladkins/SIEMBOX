# SIEMBox Parser Test Suite - Execution Guide

## Quick Start

### 1. Install Dependencies

```bash
cd /Users/chrisadkins/Projects/SIEMBox/backend
npm install
```

This installs Jest, TypeScript testing support, and all required dependencies.

### 2. Run Tests

```bash
# Run all tests
npm test

# Run parser tests specifically
npm run test:parser

# Run syslog tests specifically
npm run test:syslog

# Watch mode (reruns on file changes)
npm run test:watch

# Generate coverage report
npm run test:coverage
```

## Test Suite Overview

### What's Tested

This test suite provides comprehensive validation of:

1. **Syslog Parsing** - RFC 3164 format handling
   - Priority/facility/severity extraction
   - Timestamp parsing
   - Hostname and application name extraction
   - Process ID extraction
   - Message content extraction

2. **NGINX Parser Patterns** - Access and error log validation
   - Positive matches (various log formats)
   - Negative matches (Apache, SSH, system logs)
   - Field extraction accuracy
   - Edge cases (IPv6, long user agents, special characters)

3. **Full Pipeline Integration**
   - Syslog → Message extraction → Parser matching
   - Field mapping and validation
   - Error handling and malformed logs

4. **Regression Tests**
   - Existing parsers still work (SSH, Sudo, Apache)
   - No cross-contamination between parsers
   - Load testing under concurrent parsing

## Understanding Test Results

### Passing Tests

When a test passes, you'll see:

```
PASS  src/services/syslog/__tests__/syslogParser.test.ts
  Syslog Parser
    parseSyslogMessage
      RFC 3164 format (BSD syslog)
        ✓ should parse NGINX access log with priority and TAG (5 ms)
```

### Pending Tests

Some tests are pending (waiting for pattern data):

```
PENDING  src/services/parser/__tests__/nginxParser.test.ts
  ○ skipped 12 tests
```

These tests use `pending()` because the NGINX parser patterns haven't been provided yet by the backend-architect. Once patterns are provided, these tests will become active.

### Failed Tests

If a test fails, you'll see detailed error information:

```
FAIL  src/services/parser/__tests__/nginxParser.test.ts
  NGINX Parser Patterns
    NGINX Access Log Patterns
      ✕ should match standard NGINX access log format (15 ms)

    Expected: true
    Received: false
```

## Common Scenarios

### Scenario 1: Validating Syslog Extraction

The syslog parser tests verify that messages are correctly extracted from RFC 3164 format:

**Test File:** `src/services/syslog/__tests__/syslogParser.test.ts`

**What It Tests:**
```
Raw syslog: <134>Dec 09 20:36:20 komodo NGINX: [09/Dec/2025:20:35:53 +0000] - 200 200 - GET

Expected extraction:
- Facility: 16 (local0)
- Severity: 6 (info)
- Hostname: komodo
- AppName: NGINX
- Message: [09/Dec/2025:20:35:53 +0000] - 200 200 - GET
```

**Run just these tests:**
```bash
npm run test:syslog
```

### Scenario 2: Testing NGINX Access Log Patterns

Once the backend-architect provides the access log pattern, these tests validate it:

**Test File:** `src/services/parser/__tests__/nginxParser.test.ts`

**What It Tests:**
- Pattern matches various access log formats
- Extracts client IP, method, status code, etc.
- Doesn't match Apache or SSH logs

**Activate:**
1. Get pattern from backend-architect
2. Update `NGINX_ACCESS_PATTERN` in nginxParser.test.ts
3. Run tests:
```bash
npm run test:parser
```

### Scenario 3: Testing NGINX Error Log Patterns

Similar to access logs but for error log format:

**What It Tests:**
- Pattern matches `2025/12/08 19:37:36 [error] ...` format
- Extracts timestamp, severity, pid, etc.
- Doesn't match other log types

### Scenario 4: Integration Testing

Full pipeline tests verify the complete flow:

**Test File:** `src/services/parser/__tests__/parserIntegration.test.ts`

**What It Tests:**
1. Syslog extraction produces correct message format
2. Message can be parsed by pattern matcher
3. Fields are correctly extracted and mapped
4. Real database samples parse successfully

**Run:**
```bash
npm test -- src/services/parser/__tests__/parserIntegration.test.ts
```

### Scenario 5: Regression Testing

Ensure existing parsers aren't broken by new NGINX parsers:

**Test File:** `src/services/parser/__tests__/parserRegression.test.ts`

**What It Tests:**
- SSH logs still parse correctly
- Sudo logs still parse correctly
- Apache logs still parse correctly
- Parsers don't cross-contaminate
- Load performance is acceptable

**Run:**
```bash
npm test -- src/services/parser/__tests__/parserRegression.test.ts
```

## Workflow: Adding NGINX Parser Patterns

### Step 1: Get Patterns from backend-architect

Patterns should look like:

```
NGINX Access: (?P<client_ip>\S+)\s+-\s+(?P<remote_user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<http_version>\S+)"\s+(?P<status_code>\d+)
NGINX Error: (?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?P<severity>\w+)\]\s+(?P<pid>\d+)#(?P<worker_id>\d+)
```

### Step 2: Update Test Fixtures

Edit `src/services/parser/__tests__/nginxParser.test.ts`:

```typescript
const NGINX_ACCESS_PATTERN = 'your-pattern-here';
const NGINX_ERROR_PATTERN = 'your-pattern-here';
```

### Step 3: Remove pending() Calls

Change:
```typescript
if (!NGINX_ACCESS_PATTERN) {
  pending('NGINX_ACCESS_PATTERN not yet provided by backend-architect');
}
```

To: Just remove the entire if block (the tests will run).

### Step 4: Run Tests

```bash
npm run test:parser
```

### Step 5: Fix Pattern if Tests Fail

If tests fail, review error messages and adjust the pattern. Common issues:

- **"should match" failed**: Pattern too restrictive
- **"should NOT match" failed**: Pattern too broad
- **Field not extracted**: Check named group names match field_mappings

### Step 6: Verify Integration

```bash
npm test -- src/services/parser/__tests__/parserIntegration.test.ts
```

### Step 7: Check Regression

```bash
npm test -- src/services/parser/__tests__/parserRegression.test.ts
```

## Understanding Sample Test Logs

These real logs from the database are used for testing:

### Access Log Examples

```
Log 1: <134>Dec 09 20:36:20 komodo NGINX: [09/Dec/2025:20:35:53 +0000] - 200 200 - GET
       Extracted message: [09/Dec/2025:20:35:53 +0000] - 200 200 - GET
       Type: Access log with minimal fields

Log 2: <134>Dec 09 20:36:19 komodo NGINX: [09/Dec/2025:20:12:14 +0000] 301 - GET http w
       Extracted message: [09/Dec/2025:20:12:14 +0000] 301 - GET http w
       Type: Access log with redirect status
```

### Error Log Examples

```
Log 3: <134>Dec 09 20:36:19 komodo NGINX: 2025/12/08 19:37:36 [error] 1484#1484: *17597
       Extracted message: 2025/12/08 19:37:36 [error] 1484#1484: *17597
       Type: Error log with PID and connection ID

Log 4: <134>Dec 09 19:52:03 komodo NGINX: 68.218.17.107 -
       Extracted message: 68.218.17.107 -
       Type: Minimal/malformed log
```

## Performance Baseline

The test suite includes performance tests:

```
Test: should parse logs in reasonable time
Expected: 1000 logs parsed in < 100ms

Test: should handle rapid sequential parsing
Expected: 1000 mixed logs parsed in < 200ms
```

If performance degrades, investigate:
1. Regex pattern complexity
2. Database connection pooling
3. System load

## Debugging Failed Tests

### Check Test Output

```bash
npm test -- --verbose
```

This shows detailed output for each test.

### Run Specific Test

```bash
npm test -- --testNamePattern="should parse NGINX access log"
```

### See Stack Traces

```bash
npm test -- --verbose --detectOpenHandles
```

### Debug Pattern Issues

Create a quick test script:

```typescript
// test-pattern.ts
const pattern = 'your-pattern-here';
const testLog = '[09/Dec/2025:20:35:53 +0000] - 200 200 - GET';
const regex = new RegExp(pattern);
const match = testLog.match(regex);
console.log('Matched:', match ? 'YES' : 'NO');
console.log('Groups:', match?.groups || match?.slice(1));
```

Run with:
```bash
npx ts-node test-pattern.ts
```

## Coverage Reports

Generate coverage to see what's tested:

```bash
npm run test:coverage
```

Opens in `coverage/index.html`.

Look for:
- Red areas = not covered
- Green areas = covered
- Yellow areas = partially covered (some branches untested)

Target >80% coverage for parser-related code.

## Continuous Integration

In CI/CD pipelines, use:

```bash
npm test -- --coverage --verbose --detectOpenHandles
```

This ensures:
- All tests pass
- Coverage meets threshold
- No resource leaks
- Detailed failure information

## Troubleshooting

### "Cannot find module 'jest'"

**Solution:** Reinstall dependencies
```bash
npm install
```

### "Pattern not yet provided by backend-architect"

**Expected behavior:** Tests show as pending until patterns are provided. This is intentional.

**To fix:** Add patterns to nginxParser.test.ts

### "Tests timeout"

**Solution:** Increase timeout in jest.config.js
```javascript
testTimeout: 20000
```

### "Coverage below threshold"

**Solution:** Review coverage report and add tests for uncovered lines

## Next Steps

1. **Install dependencies:** `npm install`
2. **Run initial tests:** `npm test`
3. **Review test results:** Check which tests pass/pending
4. **Coordinate with backend-architect:** Get NGINX parser patterns
5. **Update patterns in tests:** Add to nginxParser.test.ts
6. **Run full suite:** `npm test`
7. **Generate coverage:** `npm run test:coverage`
8. **Commit tests:** Git commit when all tests pass

## Resources

- **Jest Documentation:** https://jestjs.io/docs/getting-started
- **TypeScript Jest:** https://jestjs.io/docs/getting-started#using-typescript
- **Regex Testing Tools:** https://regex101.com
- **Test File Locations:** `/Users/chrisadkins/Projects/SIEMBox/backend/src/services/**/__tests__/`

## Contact

For questions about tests:
1. Review the test file comments
2. Check test README: `src/services/parser/__tests__/README.md`
3. Coordinate with team on pattern validation
