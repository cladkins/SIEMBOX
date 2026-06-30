/**
 * Pure, synchronous evaluation of the non-I/O detection operators.
 *
 * This is the DB-free core of detection matching: given an operator, the value
 * pulled from a parsed log, and the rule's comparison value, decide whether the
 * condition holds. It deliberately imports nothing so it can be unit-tested
 * without a database — the same philosophy as runParser.ts on the parser side.
 *
 * The DB-backed operators (`not_in_whitelist`, `on_threat_feed`,
 * `not_on_threat_feed`) and the `regex` operator (which compiles a caller-
 * supplied pattern via `new RegExp` — kept in one reviewed place in RulesEngine)
 * are NOT handled here. `PURE_CONDITION_OPERATORS` is the exact set this module
 * owns, so the engine routes only those here.
 */

/** Operators evaluated purely (no DB / no async / no dynamic RegExp). */
export const PURE_CONDITION_OPERATORS: ReadonlySet<string> = new Set([
  'equals',
  'not_equals',
  'contains',
  'not_contains',
  'greater_than',
  'less_than',
  'in',
  'not_in',
  'exists',
]);

/**
 * Evaluate a pure operator. Mirrors the original switch in RulesEngine exactly so
 * detection behavior is unchanged. Throws if handed a non-pure operator — callers
 * must gate on PURE_CONDITION_OPERATORS first.
 */
export function evaluatePureCondition(operator: string, fieldValue: any, value: any): boolean {
  const fieldStr = String(fieldValue);
  const valueStr = String(value);

  switch (operator) {
    case 'equals':
      return fieldStr === valueStr;

    case 'contains':
      return fieldStr.toLowerCase().includes(valueStr.toLowerCase());

    case 'not_contains':
      return !fieldStr.toLowerCase().includes(valueStr.toLowerCase());

    case 'greater_than':
      return Number(fieldValue) > Number(value);

    case 'less_than':
      return Number(fieldValue) < Number(value);

    case 'exists':
      // Check if field exists and is not null/undefined
      return value === true
        ? fieldValue !== undefined && fieldValue !== null
        : fieldValue === undefined || fieldValue === null;

    case 'not_equals':
      return fieldStr !== valueStr;

    case 'in': {
      const list = Array.isArray(value)
        ? value.map((v) => String(v))
        : valueStr.split(',').map((s) => s.trim());
      return list.includes(fieldStr);
    }

    case 'not_in': {
      const list = Array.isArray(value)
        ? value.map((v) => String(v))
        : valueStr.split(',').map((s) => s.trim());
      return !list.includes(fieldStr);
    }

    default:
      throw new Error(`evaluatePureCondition called with non-pure operator: ${operator}`);
  }
}
