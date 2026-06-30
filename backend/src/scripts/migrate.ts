import fs from 'fs';
import path from 'path';
import pool from '../config/database';
import { logger } from '../utils/logger';
import bcrypt from 'bcrypt';

const runMigrations = async () => {
  try {
    logger.info('Starting database migrations...');

    const migrationsDir = path.join(__dirname, '../../migrations');
    const migrationFiles = fs
      .readdirSync(migrationsDir)
      .filter((file) => file.endsWith('.sql'))
      .sort();

    for (const file of migrationFiles) {
      logger.info(`Running migration: ${file}`);
      const filePath = path.join(migrationsDir, file);
      let sql = fs.readFileSync(filePath, 'utf8');

      // Replace placeholder password hash with actual hashed password
      if (file === '002_seed_data.sql') {
        const defaultPassword = process.env.DEFAULT_ADMIN_PASSWORD || 'changeme';
        const passwordHash = await bcrypt.hash(defaultPassword, 10);
        sql = sql.replace('$2b$10$placeholder', passwordHash);
      }

      await pool.query(sql);
      logger.info(`Migration completed: ${file}`);
    }

    logger.info('All migrations completed successfully!');

    // Point the operator at the admin login without logging the secret itself.
    // A configured DEFAULT_ADMIN_PASSWORD is never echoed; only the well-known
    // 'changeme' default is named, as a prod to change it.
    logger.warn('===============================================');
    logger.warn('ADMIN LOGIN: username "admin"');
    if (process.env.DEFAULT_ADMIN_PASSWORD) {
      logger.warn('Password: the DEFAULT_ADMIN_PASSWORD you configured.');
    } else {
      logger.warn('Password: "changeme" (DEFAULT_ADMIN_PASSWORD is unset).');
    }
    logger.warn('PLEASE CHANGE THE PASSWORD AFTER FIRST LOGIN!');
    logger.warn('===============================================');

    process.exit(0);
  } catch (error) {
    logger.error('Migration failed:', error);
    process.exit(1);
  }
};

runMigrations();
