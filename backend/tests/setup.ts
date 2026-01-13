/**
 * Global Test Setup
 * Runs before all tests to configure the testing environment
 */

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-jwt-secret-key-for-testing-only';
process.env.LOG_LEVEL = 'error'; // Reduce noise in test output

// Increase timeout for container operations
jest.setTimeout(60000);

// Mock console methods to reduce test output noise
global.console = {
  ...console,
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  // Keep error for debugging
  error: console.error,
};

// Global teardown - ensure all connections are closed
afterAll(async () => {
  // Give time for any pending async operations to complete
  await new Promise((resolve) => setTimeout(resolve, 500));
});
