/**
 * Parser Validation Script
 *
 * This script validates all parsers in the database for JavaScript regex compatibility
 * and tests them against their test samples.
 *
 * Usage: npx ts-node backend/scripts/validate-parsers.ts
 */

import { Pool } from 'pg';

interface Parser {
  id: number;
  name: string;
  parser_type: string;
  pattern: string;
  field_mappings: any;
  test_samples: any[];
  enabled: boolean;
  priority: number;
}

interface ValidationResult {
  parser: string;
  status: 'PASS' | 'FAIL' | 'WARN';
  issues: string[];
  testsRun?: number;
  testsPassed?: number;
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
 * Validate a regex pattern for JavaScript compatibility
 */
function validateRegexPattern(pattern: string): string[] {
  const issues: string[] = [];

  // Check for Python-style named groups
  if (pattern.includes('(?P<')) {
    issues.push('Python-style named groups found: (?P<name>...) - should be (?<name>...)');
  }

  // Check if regex can be compiled
  try {
    new RegExp(pattern);
  } catch (error) {
    issues.push(`Regex compilation error: ${error instanceof Error ? error.message : String(error)}`);
  }

  return issues;
}

/**
 * Test a parser against its test samples
 */
function testParserSamples(parser: Parser): { passed: number; failed: number; errors: string[] } {
  const errors: string[] = [];
  let passed = 0;
  let failed = 0;

  if (!parser.test_samples || parser.test_samples.length === 0) {
    return { passed, failed, errors: ['No test samples provided'] };
  }

  if (parser.parser_type === 'json') {
    // JSON parsers don't need regex testing
    return { passed: parser.test_samples.length, failed: 0, errors: [] };
  }

  try {
    const regex = new RegExp(parser.pattern);

    for (let i = 0; i < parser.test_samples.length; i++) {
      const sample = parser.test_samples[i];
      const rawMessage = sample.raw_message;
      const expectedFields = sample.expected_fields;

      try {
        const match = rawMessage.match(regex);

        if (!match || !match.groups) {
          failed++;
          errors.push(`Test ${i + 1} FAILED: No match or no groups captured`);
          continue;
        }

        // Check if expected fields are present
        const missingFields: string[] = [];
        for (const [field, expectedValue] of Object.entries(expectedFields)) {
          // Check if field is mapped
          const mappedField = parser.field_mappings[field];
          if (!mappedField) continue;

          // Check if the mapped field exists in captured groups
          if (!(mappedField in match.groups)) {
            missingFields.push(field);
          }
        }

        if (missingFields.length > 0) {
          failed++;
          errors.push(`Test ${i + 1} FAILED: Missing expected fields: ${missingFields.join(', ')}`);
        } else {
          passed++;
        }
      } catch (testError) {
        failed++;
        errors.push(`Test ${i + 1} ERROR: ${testError instanceof Error ? testError.message : String(testError)}`);
      }
    }
  } catch (regexError) {
    errors.push(`Regex compilation failed: ${regexError instanceof Error ? regexError.message : String(regexError)}`);
    failed = parser.test_samples.length;
  }

  return { passed, failed, errors };
}

/**
 * Validate all parsers in the database
 */
async function validateAllParsers(): Promise<void> {
  console.log('===============================================');
  console.log('  SIEMBox Parser Validation Report');
  console.log('===============================================\n');

  try {
    // Fetch all parsers
    const result = await pool.query<Parser>(`
      SELECT
        id,
        name,
        parser_type,
        pattern,
        field_mappings,
        test_samples,
        enabled,
        priority
      FROM parsers
      ORDER BY priority, name
    `);

    const parsers = result.rows;
    const results: ValidationResult[] = [];

    console.log(`Found ${parsers.length} parsers to validate\n`);

    for (const parser of parsers) {
      console.log(`\n[${parser.priority}] ${parser.name} (${parser.parser_type})`);
      console.log('─'.repeat(60));

      const issues: string[] = [];

      // Validate regex patterns
      if (parser.parser_type === 'regex' || parser.parser_type === 'grok') {
        const regexIssues = validateRegexPattern(parser.pattern);
        if (regexIssues.length > 0) {
          issues.push(...regexIssues);
          console.log('❌ Regex Issues:');
          regexIssues.forEach(issue => console.log(`   - ${issue}`));
        } else {
          console.log('✓ Regex syntax valid');
        }

        // Test against samples
        const testResults = testParserSamples(parser);
        console.log(`✓ Tests: ${testResults.passed} passed, ${testResults.failed} failed`);

        if (testResults.errors.length > 0) {
          issues.push(...testResults.errors);
          console.log('❌ Test Errors:');
          testResults.errors.forEach(error => console.log(`   - ${error}`));
        }

        results.push({
          parser: parser.name,
          status: issues.length === 0 ? 'PASS' : 'FAIL',
          issues,
          testsRun: testResults.passed + testResults.failed,
          testsPassed: testResults.passed,
        });
      } else if (parser.parser_type === 'json') {
        console.log('✓ JSON parser (no regex validation needed)');
        results.push({
          parser: parser.name,
          status: 'PASS',
          issues: [],
        });
      } else {
        console.log(`⚠ Unknown parser type: ${parser.parser_type}`);
        results.push({
          parser: parser.name,
          status: 'WARN',
          issues: [`Unknown parser type: ${parser.parser_type}`],
        });
      }
    }

    // Summary
    console.log('\n\n===============================================');
    console.log('  VALIDATION SUMMARY');
    console.log('===============================================\n');

    const passed = results.filter(r => r.status === 'PASS').length;
    const failed = results.filter(r => r.status === 'FAIL').length;
    const warnings = results.filter(r => r.status === 'WARN').length;

    console.log(`Total Parsers:  ${parsers.length}`);
    console.log(`✓ Passed:       ${passed}`);
    console.log(`❌ Failed:       ${failed}`);
    console.log(`⚠ Warnings:     ${warnings}`);

    if (failed > 0) {
      console.log('\n\nFAILED PARSERS:');
      console.log('─'.repeat(60));
      results
        .filter(r => r.status === 'FAIL')
        .forEach(r => {
          console.log(`\n${r.parser}:`);
          r.issues.forEach(issue => console.log(`  - ${issue}`));
        });
      process.exit(1);
    } else {
      console.log('\n✓ All parsers validated successfully!');
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
validateAllParsers();
