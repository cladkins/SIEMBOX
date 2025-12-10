# NGINX Parser Test Suite - Quick Reference

## Installation

```bash
cd /Users/chrisadkins/Projects/SIEMBox/backend
npm install
```

## Run Tests

```bash
npm test                    # All tests
npm run test:parser         # NGINX & parser tests only
npm run test:syslog         # Syslog tests only
npm run test:watch          # Watch mode (auto-rerun on changes)
npm run test:coverage       # Coverage report
```

## Test Status

| Test Suite | Status | Count |
|-----------|--------|-------|
| Syslog Parser | Active | 50+ tests |
| NGINX Parser | Pending* | 40+ tests |
| Integration | Pending* | 20+ tests |
| Regression | Active | 30+ tests |

*Pending: Waiting for NGINX patterns from backend-architect

## Enable NGINX Tests

Once patterns are received from backend-architect:

1. Open: `/Users/chrisadkins/Projects/SIEMBox/backend/src/services/parser/__tests__/nginxParser.test.ts`

2. Add patterns:
```typescript
const NGINX_ACCESS_PATTERN = 'pattern-from-backend-architect';
const NGINX_ERROR_PATTERN = 'pattern-from-backend-architect';
```

3. Remove `pending()` calls from the test file

4. Run tests:
```bash
npm run test:parser
```

## Key Locations

| Item | Location |
|------|----------|
| Test Files | `src/services/**/__tests__/*.test.ts` |
| Test Fixtures | `src/services/parser/__tests__/fixtures.ts` |
| Test Utilities | `src/services/parser/__tests__/testUtils.ts` |
| Jest Config | `jest.config.js` |
| Test Guide | `TEST_GUIDE.md` |
| Workflow Guide | `PARSER_VALIDATION_WORKFLOW.md` |
| This Summary | `NGINX_TEST_SUITE_SUMMARY.md` |

## Sample Logs Being Tested

### Access Logs
```
<134>Dec 09 20:36:20 komodo NGINX: [09/Dec/2025:20:35:53 +0000] - 200 200 - GET
<134>Dec 09 20:36:19 komodo NGINX: [09/Dec/2025:20:12:14 +0000] 301 - GET http w
```

### Error Logs
```
<134>Dec 09 20:36:19 komodo NGINX: 2025/12/08 19:37:36 [error] 1484#1484: *17597
<134>Dec 09 19:52:03 komodo NGINX: 68.218.17.107 -
```

## Expected Test Results

### With Patterns
```
PASS  src/services/parser/__tests__/nginxParser.test.ts
PASS  src/services/parser/__tests__/parserIntegration.test.ts
PASS  src/services/parser/__tests__/parserRegression.test.ts
PASS  src/services/syslog/__tests__/syslogParser.test.ts

Tests:  140 passed in 5.2s
Coverage: 80%+
```

### Without Patterns
```
PENDING  src/services/parser/__tests__/nginxParser.test.ts
Tests:  90 passed, 50 pending in 3.1s
```

## Common Commands

```bash
# Run specific test file
npm test -- src/services/syslog/__tests__/syslogParser.test.ts

# Run test matching name pattern
npm test -- --testNamePattern="should parse NGINX"

# Run in watch mode (development)
npm run test:watch

# Generate coverage report
npm run test:coverage
# Open coverage/index.html in browser

# Run with verbose output
npm test -- --verbose

# Debug a specific test
npm test -- --testNamePattern="exact test name" --verbose
```

## What Gets Tested

### Syslog Parsing (50+ tests) - ACTIVE
- RFC 3164 format compliance
- Priority/facility/severity calculation
- Timestamp parsing (all months)
- Hostname extraction
- App name and process ID extraction
- Message content extraction

### NGINX Patterns (40+ tests) - PENDING
- Access log matching
- Error log matching
- Field extraction
- Edge cases (IPv6, special chars, long values)
- Non-matching (Apache, SSH, system logs)

### Integration (20+ tests) - PENDING
- Full pipeline validation
- Message preparation
- Field mapping
- Error handling

### Regression (30+ tests) - ACTIVE
- SSH log parsing still works
- Sudo log parsing still works
- Apache log parsing still works
- No parser cross-contamination
- Performance unchanged

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Cannot find module 'jest'" | `npm install` |
| Tests timeout | Increase `testTimeout` in `jest.config.js` |
| Pattern not matching | Check regex syntax at https://regex101.com |
| Coverage missing | Run `npm run test:coverage` |
| Need specific test | Use `--testNamePattern="name"` |

## Documentation Links

- **Test README:** `src/services/parser/__tests__/README.md` - Detailed test structure
- **Test Guide:** `TEST_GUIDE.md` - How to run and understand tests
- **Workflow:** `PARSER_VALIDATION_WORKFLOW.md` - How to integrate patterns
- **Summary:** `NGINX_TEST_SUITE_SUMMARY.md` - Complete overview

## Test Writing Pattern

All tests follow Arrange-Act-Assert:

```typescript
it('should do something specific', () => {
  // Arrange: Set up test data
  const input = testFixture;

  // Act: Perform action
  const result = testFunction(input);

  // Assert: Verify outcome
  expect(result).toEqual(expected);
});
```

## Pattern Validation Checklist

When adding NGINX patterns, ensure:

- [ ] All 4 sample database logs parse correctly
- [ ] Access logs don't match error pattern
- [ ] Error logs don't match access pattern
- [ ] Apache logs don't match NGINX pattern
- [ ] SSH logs don't match NGINX pattern
- [ ] All required fields are extracted
- [ ] Performance is acceptable (<100ms for 1000 logs)
- [ ] Coverage >80%

## Integration Workflow

1. Backend-architect develops patterns
2. Backend-architect sends patterns to Test Automator
3. Test Automator updates test constants
4. Test Automator runs full test suite
5. Review results and fix any issues
6. Document pattern validation
7. Commit patterns to database
8. Monitor in production

## Performance Targets

- Parse 1 syslog message: <1ms
- Parse 1000 messages: <100ms
- Extract fields: <0.1ms per log
- Full pipeline: <200ms for 1000 logs

Current: ✓ All targets met (active tests)

## Coverage Targets

| Metric | Target | Current* |
|--------|--------|----------|
| Line | >80% | TBD |
| Branch | >75% | TBD |
| Function | >80% | TBD |
| Statement | >80% | TBD |

*Once patterns are provided

## Key Files to Know

### Test Files
- `src/services/syslog/__tests__/syslogParser.test.ts` - Syslog unit tests
- `src/services/parser/__tests__/nginxParser.test.ts` - NGINX pattern tests
- `src/services/parser/__tests__/parserIntegration.test.ts` - Integration tests
- `src/services/parser/__tests__/parserRegression.test.ts` - Regression tests

### Utilities
- `src/services/parser/__tests__/fixtures.ts` - Test data
- `src/services/parser/__tests__/testUtils.ts` - Helper functions

### Configuration
- `jest.config.js` - Jest configuration
- `package.json` - Test scripts and dependencies

### Documentation
- `TEST_GUIDE.md` - Quick start
- `PARSER_VALIDATION_WORKFLOW.md` - Full workflow
- `NGINX_TEST_SUITE_SUMMARY.md` - Complete summary

## Success Definition

Tests are ready when:
1. All 140+ tests pass
2. Coverage >80%
3. NGINX patterns validated
4. No false matches
5. Existing parsers unaffected
6. Performance acceptable

## Next Actions

- [ ] Review test files
- [ ] Run `npm install` if needed
- [ ] Run `npm test` to see current status
- [ ] Wait for patterns from backend-architect
- [ ] Add patterns to nginxParser.test.ts
- [ ] Run full test suite
- [ ] Generate coverage report
- [ ] Commit to git

## Contact

See individual documentation files for detailed information:
- Questions about tests? → `TEST_GUIDE.md`
- Questions about patterns? → `PARSER_VALIDATION_WORKFLOW.md`
- Questions about structure? → `NGINX_TEST_SUITE_SUMMARY.md`
