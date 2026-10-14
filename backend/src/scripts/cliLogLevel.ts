/**
 * Imported first by scripts/auth-admin.ts: when that script is the program
 * being run, the shared logger only prints warnings and errors, so its own
 * output isn't buried under the backend's startup lines (LOG_LEVEL=info is
 * set in the container). AUTH_ADMIN_LOG_LEVEL overrides it. Has no effect when
 * the script is imported (the tests).
 */
if (/auth-admin\.[jt]s$/.test(require.main?.filename ?? '')) {
  process.env.LOG_LEVEL = process.env.AUTH_ADMIN_LOG_LEVEL || 'warn';
}

export {};
