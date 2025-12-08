#!/usr/bin/env node
/**
 * Import Detection Rules from YAML Files
 *
 * This script reads all YAML rule files from the rules/ directory
 * and imports them into the detection_rules database table.
 *
 * Usage:
 *   npm run import-rules
 *   node dist/scripts/import-rules.js
 */

import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import { DetectionRuleModel } from '../models/DetectionRule';
import { logger } from '../utils/logger';

interface YAMLRule {
  name: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  enabled: boolean;
  tags: string[];
  conditions: Array<{
    field: string;
    operator: string;
    value: string | number | boolean;
  }>;
  aggregation?: {
    field: string;
    timeframe: string;
    threshold: number;
    distinct_count?: string;
  };
  alert: {
    title: string;
    description: string;
  };
}

/**
 * Recursively find all .yaml files in a directory
 */
function findYAMLFiles(dir: string): string[] {
  const files: string[] = [];

  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        files.push(...findYAMLFiles(fullPath));
      } else if (entry.isFile() && (entry.name.endsWith('.yaml') || entry.name.endsWith('.yml'))) {
        files.push(fullPath);
      }
    }
  } catch (error) {
    logger.error('Error reading directory:', { dir, error });
  }

  return files;
}

/**
 * Convert YAML rule to database format
 */
function convertYAMLToRuleLogic(yamlRule: YAMLRule): any {
  return {
    conditions: yamlRule.conditions,
    aggregation: yamlRule.aggregation,
    alert: yamlRule.alert,
  };
}

/**
 * Import a single YAML rule file
 */
async function importRule(filePath: string): Promise<boolean> {
  try {
    const fileContent = fs.readFileSync(filePath, 'utf8');
    const yamlRule = yaml.load(fileContent) as YAMLRule;

    // Validate required fields
    if (!yamlRule.name || !yamlRule.severity) {
      logger.error('Invalid rule: missing required fields', { filePath });
      return false;
    }

    // Check if rule already exists
    const existing = await DetectionRuleModel.findByName(yamlRule.name);
    if (existing) {
      logger.info('Rule already exists, skipping', { name: yamlRule.name, id: existing.id });
      return false;
    }

    // Convert YAML to rule_logic format
    const ruleLogic = convertYAMLToRuleLogic(yamlRule);

    // Create rule in database
    const rule = await DetectionRuleModel.create({
      name: yamlRule.name,
      description: yamlRule.description || undefined,
      enabled: yamlRule.enabled !== false, // Default to true
      severity: yamlRule.severity,
      rule_yaml: fileContent, // Store original YAML
      rule_logic: ruleLogic,
      tags: yamlRule.tags || [],
    });

    logger.info('Rule imported successfully', {
      id: rule.id,
      name: rule.name,
      severity: rule.severity,
      filePath,
    });

    return true;
  } catch (error) {
    logger.error('Error importing rule:', { filePath, error });
    return false;
  }
}

/**
 * Main import function
 */
async function main() {
  logger.info('Starting rule import from YAML files...');

  // Find rules directory (project root / rules)
  const rulesDir = path.join(__dirname, '../../../rules');

  if (!fs.existsSync(rulesDir)) {
    logger.warn('Rules directory not found - skipping rule import', { rulesDir });
    logger.warn('Detection rules will need to be created manually or rules directory must be mounted');
    logger.info('Rule import completed: 0 imported (directory not found)');
    return; // Exit gracefully instead of crashing
  }

  logger.info('Scanning for YAML rule files', { rulesDir });

  // Find all YAML files
  const yamlFiles = findYAMLFiles(rulesDir);
  logger.info(`Found ${yamlFiles.length} YAML rule files`);

  // Import each file
  let imported = 0;
  let skipped = 0;
  let failed = 0;

  for (const filePath of yamlFiles) {
    const relativePath = path.relative(rulesDir, filePath);
    logger.info(`Importing: ${relativePath}`);

    const success = await importRule(filePath);

    if (success === true) {
      imported++;
    } else if (success === false) {
      // Already exists or validation failed
      skipped++;
    } else {
      failed++;
    }
  }

  // Summary
  logger.info('Rule import complete', {
    total: yamlFiles.length,
    imported,
    skipped,
    failed,
  });

  if (imported > 0) {
    logger.info(`✓ Successfully imported ${imported} new rules`);
  }
  if (skipped > 0) {
    logger.info(`- Skipped ${skipped} existing rules`);
  }
  if (failed > 0) {
    logger.warn(`✗ Failed to import ${failed} rules`);
  }

  // Exit
  process.exit(failed > 0 ? 1 : 0);
}

// Run if called directly
if (require.main === module) {
  main().catch((error) => {
    logger.error('Fatal error during import:', error);
    process.exit(1);
  });
}

export { main as importRules };
