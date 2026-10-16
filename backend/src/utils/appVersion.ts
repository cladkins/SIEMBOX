/**
 * The backend's version, from its package.json.
 *
 * The container runs `node dist/server.js` directly (not `npm start`), so
 * process.env.npm_package_version is never populated. require() resolves to
 * /app/package.json at runtime (dist/utils/appVersion.js -> ../../package.json)
 * and is typed `any`, so it sidesteps tsc's rootDir check.
 */
export const APP_VERSION: string = (() => {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports -- runtime path outside rootDir, see above
    return require('../../package.json').version || '0.1.0';
  } catch {
    return process.env.npm_package_version || '0.1.0';
  }
})();
