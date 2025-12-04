#!/usr/bin/env node
/**
 * Seed Data Script
 *
 * This script automatically seeds detection rules on first startup.
 * It checks if rules already exist and only imports if the database is empty.
 *
 * Usage:
 *   Automatic: Called from server.ts on startup
 *   Manual: npm run seed-data
 */

import { query } from '../config/database';
import { logger } from '../utils/logger';
import { importRules } from './import-rules';

/**
 * Seed detection rules if database is empty
 */
export async function seedData(): Promise<boolean> {
  try {
    logger.info('Checking if seed data is needed...');

    // Check if rules already exist
    const result = await query('SELECT COUNT(*) as count FROM detection_rules');
    const count = parseInt(result.rows[0].count, 10);

    if (count > 0) {
      logger.info(`Detection rules already present (${count} rules), skipping seed`);
      return true;
    }

    // Import rules from YAML files
    logger.info('Seeding detection rules from YAML files...');
    await importRules();

    // Verify import
    const verifyResult = await query('SELECT COUNT(*) as count FROM detection_rules');
    const newCount = parseInt(verifyResult.rows[0].count, 10);

    logger.info(`Successfully seeded ${newCount} detection rules`);
    logger.info('Seed data initialization complete');
    return true;
  } catch (error) {
    logger.error('Failed to seed data:', error);
    return false;
  }
}

/**
 * Get seed status information
 */
export async function getSeedStatus(): Promise<{
  parsers: number;
  rules: number;
  seeded: boolean;
}> {
  try {
    const parsersResult = await query('SELECT COUNT(*) as count FROM parsers');
    const rulesResult = await query('SELECT COUNT(*) as count FROM detection_rules');

    const parsersCount = parseInt(parsersResult.rows[0].count, 10);
    const rulesCount = parseInt(rulesResult.rows[0].count, 10);

    // Consider seeded if we have minimum expected parsers and rules
    // Phase 1 (7) + Phase 2 (11) = 18 parsers
    // Minimum 40 detection rules
    const seeded = parsersCount >= 18 && rulesCount >= 40;

    return {
      parsers: parsersCount,
      rules: rulesCount,
      seeded,
    };
  } catch (error) {
    logger.error('Failed to get seed status:', error);
    throw error;
  }
}

// Allow command line execution
if (require.main === module) {
  seedData()
    .then((success) => {
      process.exit(success ? 0 : 1);
    })
    .catch((error) => {
      logger.error('Fatal error during seed:', error);
      process.exit(1);
    });
}
