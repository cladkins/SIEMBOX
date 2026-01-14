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

    // Display default admin credentials
    logger.warn('===============================================');
    logger.warn('DEFAULT ADMIN CREDENTIALS:');
    logger.warn('Username: admin');
    logger.warn(`Password: ${process.env.DEFAULT_ADMIN_PASSWORD || 'changeme'}`);
    logger.warn('PLEASE CHANGE THE PASSWORD AFTER FIRST LOGIN!');
    logger.warn('===============================================');

    process.exit(0);
  } catch (error) {
    logger.error('Migration failed:', error);
    process.exit(1);
  }
};

runMigrations();
