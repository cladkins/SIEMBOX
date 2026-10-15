/**
 * The migrate runner (`npm run migrate`; the image runs it before every server
 * start). It executes every file in migrations/ in sorted order, with no
 * tracking table, so each must be idempotent. Then, after every migration:
 *
 * - the admin account is created only when the users table is empty, already
 *   required to choose a new password at its first sign-in;
 * - admin accounts still on the default password "changeme" are flagged so
 *   they must change it before anything else (an upgrade's catch);
 * - the "ADMIN SIGN-IN" banner is printed only while an admin account waits
 *   for that change.
 *
 * See services/auth/defaultCredentials.ts. None of these overwrites a password
 * or clears a flag, so re-running is harmless.
 */
import fs from 'fs';
import path from 'path';
import pool, { closePools } from '../config/database';
import { diagnoseDbConnectionError } from '../config/dbDiagnostics';
import { logger } from '../utils/logger';
import { defaultPasswordBanner, flagAdminsOnDefaultPassword, seedDefaultAdmin } from '../services/auth/defaultCredentials';

/** Run every migration, then the admin seed, the default-password scan and the banner. Throws on failure. */
export async function runMigrations(): Promise<void> {
  logger.info('Starting database migrations...');

  const migrationsDir = path.join(__dirname, '../../migrations');
  const migrationFiles = fs
    .readdirSync(migrationsDir)
    .filter((file) => file.endsWith('.sql'))
    .sort();

  for (const file of migrationFiles) {
    logger.info(`Running migration: ${file}`);
    const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
    await pool.query(sql);
    logger.info(`Migration completed: ${file}`);
  }

  logger.info('All migrations completed successfully!');

  // Last, so the account is never created without migration 039's columns.
  await seedDefaultAdmin();
  await flagAdminsOnDefaultPassword();

  // Point the operator at the admin sign-in without logging the secret itself.
  for (const line of await defaultPasswordBanner()) logger.warn(line);
}

if (require.main === module) {
  void (async () => {
    let code = 0;
    try {
      await runMigrations();
    } catch (error) {
      code = 1;
      logger.error('Migration failed:', error);
      // A connection-level failure here is almost always a DB_HOST / networking
      // mistake, not a database fault -- say so, since the container otherwise
      // just crash-loops on a bare "connect ECONNREFUSED".
      const hint = diagnoseDbConnectionError(error);
      if (hint) logger.error(`Database unreachable -- ${hint}`);
    }
    await closePools().catch(() => undefined);
    process.exit(code);
  })();
}
