# NGINX Parser Validation Workflow

## Overview

This document describes the complete workflow for validating and integrating NGINX parser patterns into SIEMBox, with comprehensive test coverage to ensure correctness and prevent regressions.

## Workflow Phases

### Phase 1: Pattern Development (backend-architect)

**Responsibility:** backend-architect team

**Deliverables:**
1. NGINX access log regex pattern
2. NGINX error log regex pattern
3. Field mapping documentation
4. Sample log validation

**Definition of Done:**
- [ ] Patterns created and tested locally
- [ ] Pattern matches all 4 sample database logs
- [ ] Pattern doesn't false-match Apache/SSH/system logs
- [ ] Documentation provided to test team

### Phase 2: Test Integration (Test Automator)

**Responsibility:** Test Automator

**Activities:**

1. **Receive Patterns**
   - Get patterns from backend-architect
   - Document pattern intent and coverage
   - Record in pattern validation log

2. **Integrate into Test Suite**
   - Update pattern constants in `nginxParser.test.ts`
   - Remove `pending()` calls
   - Run tests to verify patterns work

3. **Validate Test Results**
   - All NGINX parser tests should pass
   - Regression tests should pass (existing parsers unaffected)
   - Integration tests should pass (full pipeline works)
   - Performance benchmarks should pass

4. **Generate Coverage Report**
   ```bash
   npm run test:coverage
   ```
   - NGINX parser code should have >80% coverage
   - Syslog parser should have >85% coverage (existing code)

5. **Document Results**
   - Create test execution report
   - Note any issues or edge cases
   - Update test documentation

**Definition of Done:**
- [ ] All unit tests passing
- [ ] All integration tests passing
- [ ] All regression tests passing
- [ ] Coverage >80%
- [ ] Documentation updated
- [ ] Test report created

### Phase 3: Deployment Validation (backend-architect + Test Automator)

**Responsibility:** Shared

**Activities:**

1. **Pattern Database Insertion**
   - Verify patterns stored correctly in parser table
   - Confirm priority order (NGINX before fallback parsers)
   - Check enable/disable flags

2. **Live Data Testing**
   - Process 4 sample database logs
   - Verify fields extracted correctly
   - Check parsed_data JSONB format

3. **Performance Validation**
   - Measure parser throughput
   - Check memory usage
   - Verify no slowdown vs baseline

4. **Integration Testing**
   - Test detection rules work with parsed fields
   - Verify alerts fire correctly
   - Check UI displays parsed logs

**Definition of Done:**
- [ ] Patterns inserted into database
- [ ] Sample logs parse correctly
- [ ] Performance meets baseline
- [ ] No alerts in logs
- [ ] UI shows parsed data correctly

### Phase 4: Production Monitoring (DevOps/Operations)

**Responsibility:** Operations team

**Activities:**

1. **Monitor Parser Performance**
   - Watch error logs for parser failures
   - Track parsing success rate
   - Alert on anomalies

2. **Validate Field Extraction**
   - Spot-check parsed logs for accuracy
   - Verify field values are correct types
   - Monitor for null/empty fields

3. **User Feedback**
   - Gather feedback on NGINX log visibility
   - Monitor alert accuracy
   - Track false positives/negatives

## Test Validation Checklist

Use this checklist to ensure parser patterns are correct:

### Syslog Extraction Tests
- [ ] RFC 3164 format recognized
- [ ] Priority extracted correctly
- [ ] Facility and severity calculated correctly
- [ ] Hostname extracted
- [ ] App name (NGINX) extracted
- [ ] Process ID extracted (if present)
- [ ] Message portion extracted (without syslog headers)

### NGINX Access Log Tests
- [ ] Matches standard format logs
- [ ] Doesn't match Apache logs
- [ ] Doesn't match SSH logs
- [ ] Doesn't match system logs
- [ ] Handles missing optional fields (dashes)
- [ ] Handles IPv6 addresses
- [ ] Handles long user agent strings
- [ ] Handles paths with special characters
- [ ] Extracts client IP correctly
- [ ] Extracts HTTP method correctly
- [ ] Extracts status code correctly

### NGINX Error Log Tests
- [ ] Matches error log format
- [ ] Doesn't match access logs
- [ ] Handles different severity levels ([error], [warn], [crit], etc)
- [ ] Extracts timestamp correctly
- [ ] Extracts severity correctly
- [ ] Extracts PID correctly
- [ ] Handles special characters in message

### Integration Tests
- [ ] Full pipeline works (syslog → extraction → parsing)
- [ ] Sample database logs parse successfully
- [ ] Distinguishes between access and error logs
- [ ] No cross-contamination with other parsers
- [ ] Handles malformed logs gracefully
- [ ] Performance acceptable (1000 logs < 200ms)

### Regression Tests
- [ ] SSH logs still parse correctly
- [ ] Sudo logs still parse correctly
- [ ] Apache logs still parse correctly
- [ ] No parser cross-contamination
- [ ] Existing parser performance unchanged
- [ ] Load test passes (100 mixed logs in reasonable time)

## Sample Logs for Validation

These are the actual logs from the SIEMBox database that must parse correctly:

### Access Logs

**Log 1:** Minimal access log with status codes
```
Raw:     <134>Dec 09 20:36:20 komodo NGINX: [09/Dec/2025:20:35:53 +0000] - 200 200 - GET
Message: [09/Dec/2025:20:35:53 +0000] - 200 200 - GET
```

**Expected Fields:**
- timestamp: [09/Dec/2025:20:35:53 +0000]
- status_code: 200

**Log 2:** Redirect response
```
Raw:     <134>Dec 09 20:36:19 komodo NGINX: [09/Dec/2025:20:12:14 +0000] 301 - GET http w
Message: [09/Dec/2025:20:12:14 +0000] 301 - GET http w
```

**Expected Fields:**
- timestamp: [09/Dec/2025:20:12:14 +0000]
- status_code: 301

### Error Logs

**Log 3:** Standard error with connection details
```
Raw:     <134>Dec 09 20:36:19 komodo NGINX: 2025/12/08 19:37:36 [error] 1484#1484: *17597
Message: 2025/12/08 19:37:36 [error] 1484#1484: *17597
```

**Expected Fields:**
- timestamp: 2025/12/08 19:37:36
- severity: error
- pid: 1484
- worker_id: 1484
- connection_id: 17597

**Log 4:** Minimal/malformed log
```
Raw:     <134>Dec 09 19:52:03 komodo NGINX: 68.218.17.107 -
Message: 68.218.17.107 -
```

**Notes:**
- This is likely malformed or a partial log
- May not match either pattern (acceptable)
- Should not cause parser to crash

## Pattern Validation Questions

When reviewing patterns, answer:

1. **Accuracy:** Do all sample logs parse correctly?
   - Access logs match access pattern?
   - Error logs match error pattern?
   - No false matches between patterns?

2. **Specificity:** Are patterns specific enough?
   - Don't match Apache logs?
   - Don't match SSH logs?
   - Don't match system logs?

3. **Completeness:** Are all needed fields extracted?
   - Can identify log type?
   - Can extract key fields?
   - Can map to meaningful columns?

4. **Performance:** Are patterns efficient?
   - No catastrophic backtracking?
   - Parse quickly?
   - Scale to thousands of logs/second?

5. **Robustness:** Do patterns handle edge cases?
   - Missing optional fields?
   - Very long values?
   - Special characters?
   - Malformed logs?

## Test Execution Report Template

### Header
```
NGINX Parser Test Execution Report
Date: [DATE]
Backend Architect: [NAME]
Test Automator: [NAME]
Patterns Validated: access, error
```

### Test Results Summary
```
Total Tests: ___
Passed: ___
Failed: ___
Pending: ___
Coverage: ___%
```

### Access Log Pattern Results
```
Pattern: [PATTERN_STRING]

Test Results:
- ✓/✗ Matches sample log 1
- ✓/✗ Matches sample log 2
- ✓/✗ Doesn't match Apache logs
- ✓/✗ Doesn't match SSH logs
- ✓/✗ Field extraction works

Notes: [ANY ISSUES OR OBSERVATIONS]
```

### Error Log Pattern Results
```
Pattern: [PATTERN_STRING]

Test Results:
- ✓/✗ Matches sample log 3
- ✓/✗ Doesn't match access logs
- ✓/✗ Handles different severity levels
- ✓/✗ Field extraction works

Notes: [ANY ISSUES OR OBSERVATIONS]
```

### Integration Results
```
Full Pipeline Tests:
- ✓/✗ Syslog extraction works
- ✓/✗ Message preparation works
- ✓/✗ Parser matching works
- ✓/✗ Field mapping works
```

### Regression Results
```
Existing Parsers:
- ✓/✗ SSH logs still work
- ✓/✗ Sudo logs still work
- ✓/✗ Apache logs still work
- ✓/✗ No cross-contamination
- ✓/✗ Performance acceptable
```

### Issues Found
```
[List any issues with pattern, tests, or integration]

Issue 1: [DESCRIPTION]
Severity: [Critical/High/Medium/Low]
Resolution: [HOW TO FIX]

Issue 2: ...
```

### Recommendations
```
[Any suggestions for improvements or next steps]
```

## Git Workflow for Pattern Integration

### 1. Feature Branch
```bash
git checkout -b feature/nginx-parser-validation
```

### 2. Update Tests
```bash
# Add patterns to test files
# Update fixtures if needed
# Run tests to verify
npm test
```

### 3. Create Test Commit
```bash
git add src/services/parser/__tests__/
git commit -m "test: add NGINX parser pattern validation"
```

### 4. Test Report
```bash
# Generate and commit coverage report
npm run test:coverage
git add coverage/
git commit -m "docs: add test coverage report for NGINX parsers"
```

### 5. Create Pull Request
```
Title: "feat: Add comprehensive NGINX parser validation test suite"

Description:
- Unit tests for NGINX access and error log patterns
- Integration tests for full parsing pipeline
- Regression tests for existing parsers
- Coverage report and documentation

Related: [Issue/PR numbers from backend-architect]
```

## Success Criteria

The NGINX parser validation is complete when:

1. **All Tests Pass**
   - [ ] Unit tests: 100%
   - [ ] Integration tests: 100%
   - [ ] Regression tests: 100%

2. **Coverage Goals Met**
   - [ ] Line coverage: >80%
   - [ ] Branch coverage: >75%
   - [ ] Function coverage: >80%

3. **Patterns Validated**
   - [ ] All 4 sample logs parse correctly
   - [ ] No false matches with other log types
   - [ ] Fields extracted accurately
   - [ ] Performance acceptable

4. **Documentation Complete**
   - [ ] Test README updated
   - [ ] Test Guide created
   - [ ] Coverage report available
   - [ ] Pattern documentation in place

5. **Code Quality**
   - [ ] No console errors or warnings
   - [ ] No unhandled exceptions
   - [ ] Clean test output
   - [ ] Ready for production

## Quick Reference

### Run All Tests
```bash
npm test
```

### Run Only Parser Tests
```bash
npm run test:parser
```

### Generate Coverage
```bash
npm run test:coverage
```

### Watch Mode for Development
```bash
npm run test:watch
```

### Check Specific Pattern
```bash
npm test -- --testNamePattern="should match NGINX access"
```

## Related Documentation

- **Test README:** `src/services/parser/__tests__/README.md`
- **Test Execution Guide:** `TEST_GUIDE.md`
- **Parser Documentation:** `PARSERS.md`
- **API Documentation:** `API.md`

## Timeline Estimate

- **Pattern Development:** 1-2 days (backend-architect)
- **Test Integration:** 2-4 hours (Test Automator)
- **Validation & Debugging:** 4-8 hours (both teams)
- **Documentation & Deployment:** 2-4 hours (Test Automator)

**Total:** 2-4 days for complete validation and integration
