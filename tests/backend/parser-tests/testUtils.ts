/**
 * Test utilities for parser testing
 * Provides helper functions for testing parser configurations and results
 */

import { Parser } from '../../../models/Parser';

/**
 * Create a mock parser object for testing
 */
export function createMockParser(overrides: Partial<Parser> = {}): Parser {
  const now = new Date();
  return {
    id: 1,
    name: 'test-parser',
    description: 'Test parser',
    enabled: true,
    priority: 100,
    parser_type: 'regex',
    pattern: '.*',
    field_mappings: {},
    test_samples: null,
    created_at: now,
    updated_at: now,
    ...overrides,
  };
}

/**
 * Test if a parser pattern matches a message
 */
export function testRegexPattern(pattern: string, message: string): RegExpMatchArray | null {
  try {
    const regex = new RegExp(pattern);
    return message.match(regex);
  } catch (error) {
    throw new Error(`Invalid regex pattern: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Extract named groups from regex match
 */
export function extractNamedGroups(
  pattern: string,
  message: string
): Record<string, string | undefined> | null {
  try {
    const regex = new RegExp(pattern);
    const match = message.match(regex);

    if (!match) {
      return null;
    }

    if (!match.groups) {
      return null;
    }

    return match.groups;
  } catch (error) {
    throw new Error(`Error extracting named groups: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Extract numbered groups from regex match
 */
export function extractNumberedGroups(
  pattern: string,
  message: string
): (string | undefined)[] {
  try {
    const regex = new RegExp(pattern);
    const match = message.match(regex);

    if (!match) {
      return [];
    }

    // Return groups starting from index 1 (skip full match at index 0)
    return match.slice(1);
  } catch (error) {
    throw new Error(`Error extracting numbered groups: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Map regex groups to field names
 */
export function mapGroupsToFields(
  groups: Record<string, string | undefined>,
  fieldMappings: Record<string, string>
): Record<string, string | undefined> {
  const fields: Record<string, string | undefined> = {};

  for (const [groupName, fieldName] of Object.entries(fieldMappings)) {
    if (groupName in groups) {
      fields[fieldName] = groups[groupName];
    }
  }

  return fields;
}

/**
 * Map numbered groups to field names
 */
export function mapNumberedGroupsToFields(
  groups: (string | undefined)[],
  fieldMappings: Record<string, string>
): Record<string, string | undefined> {
  const fields: Record<string, string | undefined> = {};

  for (const [groupNum, fieldName] of Object.entries(fieldMappings)) {
    const index = parseInt(groupNum, 10) - 1; // Convert to 0-based index
    if (index >= 0 && index < groups.length) {
      fields[fieldName] = groups[index];
    }
  }

  return fields;
}

/**
 * Validate that extracted fields match expected values
 */
export function validateFields(
  extracted: Record<string, string | undefined>,
  expected: Record<string, string | undefined>
): { valid: boolean; mismatches: Array<{ field: string; expected: string; actual: string | undefined }> } {
  const mismatches: Array<{ field: string; expected: string; actual: string | undefined }> = [];

  for (const [field, expectedValue] of Object.entries(expected)) {
    const actualValue = extracted[field];

    if (actualValue !== expectedValue) {
      mismatches.push({
        field,
        expected: expectedValue,
        actual: actualValue,
      });
    }
  }

  return {
    valid: mismatches.length === 0,
    mismatches,
  };
}

/**
 * Validate that a pattern should NOT match a message
 */
export function shouldNotMatch(pattern: string, message: string): boolean {
  try {
    const regex = new RegExp(pattern);
    return !regex.test(message);
  } catch (error) {
    throw new Error(`Invalid regex pattern: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Validate that a pattern DOES match a message
 */
export function shouldMatch(pattern: string, message: string): boolean {
  try {
    const regex = new RegExp(pattern);
    return regex.test(message);
  } catch (error) {
    throw new Error(`Invalid regex pattern: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Compare two sets of fields for equality
 */
export function compareFields(
  actual: Record<string, any>,
  expected: Record<string, any>
): {
  equal: boolean;
  differences: Array<{ field: string; expected: any; actual: any }>;
} {
  const differences: Array<{ field: string; expected: any; actual: any }> = [];
  const allFields = new Set([...Object.keys(expected), ...Object.keys(actual)]);

  for (const field of allFields) {
    if (JSON.stringify(expected[field]) !== JSON.stringify(actual[field])) {
      differences.push({
        field,
        expected: expected[field],
        actual: actual[field],
      });
    }
  }

  return {
    equal: differences.length === 0,
    differences,
  };
}

/**
 * Test a parser pattern against multiple messages
 */
export function testPatternBatch(
  pattern: string,
  messages: Array<{ message: string; shouldMatch: boolean }>
): Array<{
  message: string;
  shouldMatch: boolean;
  matched: boolean;
  passed: boolean;
  error?: string;
}> {
  return messages.map((testCase) => {
    try {
      const matched = shouldMatch(pattern, testCase.message);
      const passed = matched === testCase.shouldMatch;

      return {
        message: testCase.message,
        shouldMatch: testCase.shouldMatch,
        matched,
        passed,
      };
    } catch (error) {
      return {
        message: testCase.message,
        shouldMatch: testCase.shouldMatch,
        matched: false,
        passed: false,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  });
}
