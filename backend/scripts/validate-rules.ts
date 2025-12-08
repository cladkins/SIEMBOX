/**
 * Detection Rules Validation Script
 *
 * This script validates all detection rules in the database for correct syntax,
 * JSON structure, and regex patterns in conditions.
 *
 * Usage: npx ts-node backend/scripts/validate-rules.ts
 */

import { Pool } from 'pg';

interface DetectionRule {
  id: number;
  name: string;
  description: string;
  severity: string;
  enabled: boolean;
  conditions: any;
  rule_logic: any;
  rule_yaml: string;
  tags: string[];
}

interface ValidationResult {
  rule: string;
  status: 'PASS' | 'FAIL' | 'WARN';
  issues: string[];
}

// Database connection
const pool = new Pool({
  host: process.env.POSTGRES_HOST || 'localhost',
  port: parseInt(process.env.POSTGRES_PORT || '5432'),
  database: process.env.POSTGRES_DB || 'siembox',
  user: process.env.POSTGRES_USER || 'siembox',
  password: process.env.POSTGRES_PASSWORD || 'siembox',
});

/**
 * Validate a rule's conditions structure
 */
function validateConditions(conditions: any): string[] {
  const issues: string[] = [];

  if (!conditions) {
    issues.push('Conditions is null or undefined');
    return issues;
  }

  if (typeof conditions !== 'object') {
    issues.push('Conditions must be an object');
    return issues;
  }

  // Check if it has a conditions array
  if (conditions.conditions && Array.isArray(conditions.conditions)) {
    for (let i = 0; i < conditions.conditions.length; i++) {
      const condition = conditions.conditions[i];

      if (!condition.field) {
        issues.push(`Condition ${i + 1}: Missing 'field' property`);
      }

      if (!condition.operator) {
        issues.push(`Condition ${i + 1}: Missing 'operator' property`);
      }

      // Validate regex operator
      if (condition.operator === 'regex') {
        if (!condition.value) {
          issues.push(`Condition ${i + 1}: Missing regex 'value'`);
        } else {
          try {
            // Check for Python-style regex
            if (String(condition.value).includes('(?P<')) {
              issues.push(`Condition ${i + 1}: Python-style named groups found in regex: ${condition.value}`);
            }
            // Try to compile the regex
            new RegExp(condition.value);
          } catch (error) {
            issues.push(`Condition ${i + 1}: Invalid regex pattern: ${error instanceof Error ? error.message : String(error)}`);
          }
        }
      }
    }
  }

  // Check aggregation if present
  if (conditions.aggregation) {
    if (!conditions.aggregation.field) {
      issues.push('Aggregation missing required field');
    }
    if (!conditions.aggregation.timeframe) {
      issues.push('Aggregation missing timeframe');
    }
    if (!conditions.aggregation.threshold) {
      issues.push('Aggregation missing threshold');
    }
  }

  return issues;
}

/**
 * Validate severity level
 */
function validateSeverity(severity: string): string[] {
  const issues: string[] = [];
  const validSeverities = ['critical', 'high', 'medium', 'low', 'info'];

  if (!validSeverities.includes(severity.toLowerCase())) {
    issues.push(`Invalid severity level: ${severity} (must be one of: ${validSeverities.join(', ')})`);
  }

  return issues;
}

/**
 * Validate all detection rules
 */
async function validateAllRules(): Promise<void> {
  console.log('===============================================');
  console.log('  SIEMBox Detection Rules Validation Report');
  console.log('===============================================\n');

  try {
    // Fetch all detection rules
    const result = await pool.query<DetectionRule>(`
      SELECT
        id,
        name,
        description,
        severity,
        enabled,
        conditions,
        rule_logic,
        rule_yaml,
        tags
      FROM detection_rules
      ORDER BY
        CASE severity
          WHEN 'critical' THEN 1
          WHEN 'high' THEN 2
          WHEN 'medium' THEN 3
          WHEN 'low' THEN 4
          WHEN 'info' THEN 5
          ELSE 6
        END,
        name
    `);

    const rules = result.rows;
    const results: ValidationResult[] = [];

    console.log(`Found ${rules.length} detection rules to validate\n`);

    for (const rule of rules) {
      console.log(`\n[${rule.severity.toUpperCase()}] ${rule.name}`);
      console.log('─'.repeat(60));

      const issues: string[] = [];

      // Validate severity
      const severityIssues = validateSeverity(rule.severity);
      if (severityIssues.length > 0) {
        issues.push(...severityIssues);
        console.log('❌ Severity Issues:');
        severityIssues.forEach(issue => console.log(`   - ${issue}`));
      } else {
        console.log(`✓ Severity: ${rule.severity}`);
      }

      // Validate conditions structure
      const conditionIssues = validateConditions(rule.conditions);
      if (conditionIssues.length > 0) {
        issues.push(...conditionIssues);
        console.log('❌ Condition Issues:');
        conditionIssues.forEach(issue => console.log(`   - ${issue}`));
      } else {
        console.log('✓ Conditions valid');

        // Show condition summary
        if (rule.conditions?.conditions) {
          console.log(`  - ${rule.conditions.conditions.length} condition(s)`);
          rule.conditions.conditions.forEach((cond: any, idx: number) => {
            const regex = cond.operator === 'regex' ? ' [REGEX]' : '';
            console.log(`    ${idx + 1}. ${cond.field} ${cond.operator} "${cond.value}"${regex}`);
          });
        }

        if (rule.conditions?.aggregation) {
          console.log(`  - Aggregation: ${rule.conditions.aggregation.threshold} events in ${rule.conditions.aggregation.timeframe}`);
        }
      }

      // Validate rule_logic matches conditions
      if (rule.rule_logic) {
        const ruleLogicIssues = validateConditions(rule.rule_logic);
        if (ruleLogicIssues.length > 0) {
          issues.push('rule_logic has different issues than conditions');
        }
      }

      // Check if enabled
      console.log(`✓ Status: ${rule.enabled ? 'ENABLED' : 'DISABLED'}`);

      // Check tags
      if (rule.tags && rule.tags.length > 0) {
        console.log(`✓ Tags: ${rule.tags.join(', ')}`);
      }

      results.push({
        rule: rule.name,
        status: issues.length === 0 ? 'PASS' : 'FAIL',
        issues,
      });
    }

    // Summary
    console.log('\n\n===============================================');
    console.log('  VALIDATION SUMMARY');
    console.log('===============================================\n');

    const passed = results.filter(r => r.status === 'PASS').length;
    const failed = results.filter(r => r.status === 'FAIL').length;
    const warnings = results.filter(r => r.status === 'WARN').length;

    // Group by severity
    const bySeverity = rules.reduce((acc, rule) => {
      acc[rule.severity] = (acc[rule.severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    console.log(`Total Rules:    ${rules.length}`);
    console.log(`✓ Passed:       ${passed}`);
    console.log(`❌ Failed:       ${failed}`);
    console.log(`⚠ Warnings:     ${warnings}\n`);

    console.log('Rules by Severity:');
    Object.entries(bySeverity)
      .sort(([a], [b]) => {
        const order = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };
        return (order[a as keyof typeof order] || 99) - (order[b as keyof typeof order] || 99);
      })
      .forEach(([severity, count]) => {
        console.log(`  ${severity.toUpperCase()}: ${count}`);
      });

    console.log(`\nEnabled Rules:  ${rules.filter(r => r.enabled).length}`);
    console.log(`Disabled Rules: ${rules.filter(r => !r.enabled).length}`);

    if (failed > 0) {
      console.log('\n\nFAILED RULES:');
      console.log('─'.repeat(60));
      results
        .filter(r => r.status === 'FAIL')
        .forEach(r => {
          console.log(`\n${r.rule}:`);
          r.issues.forEach(issue => console.log(`  - ${issue}`));
        });
      process.exit(1);
    } else {
      console.log('\n✓ All detection rules validated successfully!');
      process.exit(0);
    }
  } catch (error) {
    console.error('ERROR:', error);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

// Run validation
validateAllRules();
