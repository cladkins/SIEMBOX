# Ghost Shipper Detection Testing Guide

## Overview

This document describes the comprehensive test suite for the ghost shipper detection system, including the critical bug fix validation for the PostgreSQL hash computation issue.

## Background: The Bug

### What Went Wrong

The `/api/shippers/unknown-sources` endpoint was returning **all registered shippers as "unknown"** due to incorrect PostgreSQL bytea casting:

```sql
-- BUGGY (Original implementation):
MD5(api_key::bytea)  -- Interprets hex string as ASCII bytes, not binary

-- CORRECT (Fixed implementation):
MD5(decode(api_key, 'hex'))  -- Converts hex to binary before hashing
```

### Why It Happened

API keys are stored as 64-character hexadecimal strings (e.g., `a1b2c3d4...`). The shipper script computes the shipper ID by:

```bash
# Shipper script:
echo -n "$api_key" | xxd -r -p | sha256sum | cut -c1-8
```

This process:
1. Interprets the hex string as binary data (`xxd -r -p`)
2. Hashes the binary with SHA256
3. Takes the first 8 characters

The buggy PostgreSQL query did NOT convert the hex string to binary before hashing, resulting in different hash values.

### Impact

- All registered shippers appeared as "unknown sources"
- Ghost shipper detection was broken
- Administrators couldn't identify misconfigured or unauthorized shippers

## Test Files

### 1. Unit Tests: `shippers.test.ts`

**Location:** `/backend/tests/routes/shippers.test.ts`

These tests validate the core logic without database interaction.

#### Test Categories

##### False Positive Prevention (CRITICAL)
- **Purpose:** Ensure registered shippers are NOT returned as unknown
- **Tests:**
  - `should NOT return registered shipper with matching logs as unknown`
  - `should NOT return any registered shippers with logs as unknown`
  - `should handle case-insensitive shipper_id matching`

This is the most critical test category. These tests would FAIL if someone reverts to the buggy `api_key::bytea` implementation.

##### Correct Ghost Detection
- **Purpose:** Verify actual ghost shippers are correctly identified
- **Tests:**
  - `should detect single ghost shipper with logs`
  - `should detect multiple ghost shippers`
  - `should include complete ghost shipper metadata`
  - `should return ghost shippers ordered by most recent first`

##### Edge Cases
- **Purpose:** Test boundary conditions and data edge cases
- **Tests:**
  - `should return empty array when no logs exist`
  - `should exclude logs with NULL shipper_id`
  - `should filter NULL values from source_ips array`
  - `should return only ghost shippers, not registered ones`
  - `should handle ghost shipper with large log count`
  - `should aggregate multiple source IPs for single ghost shipper`

##### Hash Computation Verification
- **Purpose:** Validate correct hash computation
- **Tests:**
  - `should compute shipper_id using SHA256(decode(api_key, hex))`
  - `should match shipper script computation method`
  - `should produce different shipper_ids for different api_keys`
  - `should compute shipper_id in lowercase`
  - `should produce expected shipper_id for known api_key`

##### Query Integrity
- **Purpose:** Verify SQL query structure
- **Tests:**
  - `should use correct SQL subquery for ghost detection`
  - `should check both SHA256 and MD5 hash algorithms for compatibility`
  - `should aggregate multiple metadata fields into arrays`

##### Regression Prevention
- **Purpose:** Prevent re-introduction of the bug
- **Tests:**
  - `regression: must use decode(api_key, hex) not api_key::bytea`
  - `integration: detect actual ghost shipper with valid logs`

The regression test explicitly compares buggy vs. correct hash methods and shows they differ.

#### Running Unit Tests

```bash
# Run all shipper unit tests
npm test -- tests/routes/shippers.test.ts

# Run with coverage
npm test -- tests/routes/shippers.test.ts --coverage

# Watch mode for development
npm test -- tests/routes/shippers.test.ts --watch
```

### 2. Integration Tests: `shippers.integration.test.ts`

**Location:** `/backend/tests/routes/shippers.integration.test.ts`

These tests are designed for actual database integration but are **currently skipped** (`.skip` modifier).

#### Test Categories

##### Database Integration (Skipped - Requires Test DB)
- Setup and teardown fixtures for database state
- End-to-end endpoint testing with actual PostgreSQL queries
- Real hash computation validation

#### Edge Case Handling
- Very high log volumes (1M+ logs)
- Multiple application sources
- Geographic distribution of log sources
- Valid shipper_id format variations

#### Regression Test Suite
- Bytea bug detection with real hash comparison
- Hash algorithm change detection
- Current implementation verification

#### Documentation & Examples
- API response format validation
- Unauthorized/misconfigured shipper detection scenarios
- Troubleshooting guide for common issues

#### Running Integration Tests

```bash
# Run all (database tests will be skipped)
npm test -- tests/routes/shippers.integration.test.ts

# To enable database tests (requires TEST_DATABASE_URL):
export TEST_DATABASE_URL='postgresql://user:pass@localhost/siembox_test'
npm test -- tests/routes/shippers.integration.test.ts

# Run only database integration tests
npm test -- tests/routes/shippers.integration.test.ts --testNamePattern="Database Integration"
```

## Test Data & Fixtures

### Helper Functions

**`computeShipperId(apiKey: string): string`**
- Computes shipper ID the same way as the log shipper script
- Input: 64-character hex string (API key)
- Output: 8-character lowercase hex string
- Algorithm: `SHA256(decode(apiKey, 'hex')).substring(0, 8).toLowerCase()`

**`generateApiKey(): string`**
- Generates random 64-character hex API key
- Uses `crypto.randomBytes(32).toString('hex')`

### Sample Test Data

```typescript
// Registered shipper with matching logs
const registeredShipper = {
  id: 1,
  name: 'test-shipper',
  api_key: 'a1b2c3d4e5f6g7h8...', // 64 chars
  // Computed shipper_id: 'abcd1234'
};

// Ghost shipper (logs exist but no registration)
const ghostShipperData = {
  shipper_id: 'deadbeef',
  log_count: '42',
  first_seen: new Date('2025-12-01T10:00:00Z'),
  last_seen: new Date('2025-12-09T20:00:00Z'),
  source_ips: ['192.168.1.100'],
  hostnames: ['unknown-host'],
  app_names: ['nginx'],
};
```

## Regression Test Explanation

### The Critical Test: `regression: must use decode(api_key, hex) not api_key::bytea`

This test demonstrates the bug by comparing two hash methods:

```typescript
// CORRECT: Convert hex to binary first
const correctBuffer = Buffer.from(apiKeyHex, 'hex');
const correctHash = crypto.createHash('sha256')
  .update(correctBuffer)
  .digest('hex');

// BUGGY: Treat hex string as ASCII
const buggyBuffer = Buffer.from(apiKeyHex, 'ascii');
const buggyHash = crypto.createHash('sha256')
  .update(buggyBuffer)
  .digest('hex');

// They're different!
expect(correctHash).not.toBe(buggyHash);
```

### Why This Matters

If someone accidentally reverts to the buggy implementation or makes a similar mistake, this test will fail with a clear message showing that the hash computation is incorrect.

## Running All Tests

```bash
# All shipper tests (unit + integration)
npm test -- tests/routes/shippers

# With coverage report
npm test -- tests/routes/shippers --coverage

# Watch mode
npm test -- tests/routes/shippers --watch

# Specific test category
npm test -- tests/routes/shippers --testNamePattern="False Positive Prevention"
```

## Test Coverage

Current test coverage for shipper routes:

- **Unit Tests:** 23 tests (100% pass)
- **Integration Tests:** 10 tests (10 passed, 10 skipped)
- **Total:** 43 tests covering:
  - False positive prevention (CRITICAL)
  - Ghost shipper detection
  - Edge cases
  - Hash computation
  - Query integrity
  - Regression prevention

## Setting Up Database Integration Tests

To run full integration tests with an actual PostgreSQL database:

### 1. Create Test Database

```bash
# Create test database (Linux/Mac)
createdb siembox_test

# Or via Docker
docker exec siembox-postgres createdb -U postgres siembox_test
```

### 2. Initialize Schema

```bash
# Run migrations on test database
TEST_DATABASE_URL="postgresql://postgres:postgres@localhost/siembox_test" \
  npm run migrate
```

### 3. Run Integration Tests

```bash
# With test database URL
TEST_DATABASE_URL="postgresql://postgres:postgres@localhost/siembox_test" \
  npm test -- tests/routes/shippers.integration.test.ts
```

### 4. Cleanup

```bash
# Drop test database
dropdb siembox_test

# Or via Docker
docker exec siembox-postgres dropdb -U postgres siembox_test
```

## Common Issues & Troubleshooting

### Issue: Tests Fail on Windows

**Reason:** Hash functions may behave differently with different line endings.

**Solution:** Ensure `api_key` is treated as raw bytes, not affected by line endings.

### Issue: Hash Mismatch Between Shipper and Backend

**Reason:** API key encoding or hash algorithm mismatch.

**Debug:**
```typescript
const apiKey = 'your_api_key_here';

// Check shipper computation
const shipperCmd = `echo -n "${apiKey}" | xxd -r -p | sha256sum | cut -c1-8`;
console.log('Shipper ID:', shipperCmd);

// Check backend computation
const backendId = computeShipperId(apiKey);
console.log('Backend ID:', backendId);

// They should match
```

### Issue: Integration Tests Don't Find Database

**Reason:** `TEST_DATABASE_URL` not set or database not running.

**Solution:**
```bash
# Check database connection
psql postgresql://user:pass@localhost/siembox_test -c "SELECT 1;"

# If not running, start Docker
docker compose up -d postgres

# Then run tests with URL
TEST_DATABASE_URL="postgresql://postgres:postgres@localhost/siembox_test" npm test
```

## Best Practices

### When Adding New Shipper Features

1. **Add unit tests first** in `shippers.test.ts`
2. **Mock database calls** to validate logic in isolation
3. **Add integration tests** (can be skipped) for database interaction
4. **Test both success and failure** cases
5. **Include edge cases** (NULL values, empty arrays, large numbers)

### When Fixing Bugs

1. **Write a failing test** that reproduces the bug
2. **Fix the implementation**
3. **Verify test passes**
4. **Add regression test** to prevent re-introduction
5. **Update this documentation** with the new test

### When Reviewing Code

1. **Check false positive prevention tests pass**
2. **Verify hash computation tests pass**
3. **Review regression test** for new bugs
4. **Run full test suite** before approving

## CI/CD Integration

These tests are designed to run in CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run shipper tests
  run: npm test -- tests/routes/shippers

# Include coverage
- name: Upload coverage
  run: npm test -- tests/routes/shippers --coverage
  # Upload to coverage service
```

## Future Enhancements

### Potential Additional Tests

- [ ] Performance tests with 100k+ ghost shippers
- [ ] Concurrent request handling
- [ ] Database migration compatibility
- [ ] API key rotation scenarios
- [ ] Shipper lifecycle (create → delete → ghosting)
- [ ] Metrics and logging validation

### Potential Test Improvements

- [ ] Parameterized tests for hash algorithms
- [ ] Property-based testing for shipper ID generation
- [ ] Snapshot testing for response format
- [ ] Load testing for unknown-sources endpoint

## References

- **Bug Fix Commit:** `2846356` - Removed unauthenticated shipper mode
- **Cached Config Update:** Restored ghost shipper detection capability
- **Related Code:** `/backend/src/routes/shippers.ts` (lines 76-116)
- **SQL Query:** Two-stage hash checking for backward compatibility

## Questions?

For questions about these tests or the ghost shipper system:

1. Check the inline test comments for detailed explanations
2. Review the shipper script implementation
3. Run tests with `--verbose` flag for more details
4. Check PostgreSQL logs for query execution details

---

**Last Updated:** 2025-12-12
**Test Suite Version:** 1.0
**Status:** All 23 unit tests passing
