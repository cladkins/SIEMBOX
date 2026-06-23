/**
 * Portable detection-rule validation — shared by the rules importer, the catalog
 * install path, and the catalog CI. A rule is a YAML file (the existing format
 * under rules/); this validates its structure against what the rules engine
 * actually supports, so a rule that passes CI imports and evaluates cleanly.
 */

/** Condition operators the rules engine implements (see rulesEngine.ts). */
export const RULE_OPERATORS = [
  'equals',
  'not_equals',
  'contains',
  'not_contains',
  'regex',
  'greater_than',
  'less_than',
  'in',
  'not_in',
  'not_in_whitelist',
  'exists',
] as const;

export const RULE_SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;

export interface RuleCondition {
  field: string;
  operator: (typeof RULE_OPERATORS)[number];
  value?: string | number | boolean | Array<string | number>;
}

export interface PortableRule {
  name: string;
  description?: string;
  severity: (typeof RULE_SEVERITIES)[number];
  enabled?: boolean;
  tags?: string[];
  conditions: RuleCondition[];
  aggregation?: {
    field: string;
    timeframe: string;
    threshold: number;
    distinct_count?: string;
  };
  alert: { title: string; description: string };
}

export interface RuleValidationResult {
  ok: boolean;
  errors: string[];
  warnings: string[];
}

function isPlainObject(v: unknown): v is Record<string, any> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Validate a parsed YAML rule object. `strict` turns hygiene notes into errors. */
export function validateRule(obj: unknown, opts: { strict?: boolean } = {}): RuleValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  const note = (m: string) => (opts.strict ? errors : warnings).push(m);

  if (!isPlainObject(obj)) return { ok: false, errors: ['rule must be a YAML mapping'], warnings };
  const r = obj as Record<string, any>;

  if (typeof r.name !== 'string' || r.name.trim() === '') errors.push('name is required (non-empty string)');
  if (!RULE_SEVERITIES.includes(r.severity)) {
    errors.push(`severity must be one of ${RULE_SEVERITIES.join(', ')}`);
  }
  if (r.description !== undefined && typeof r.description !== 'string') errors.push('description must be a string');
  if (r.enabled !== undefined && typeof r.enabled !== 'boolean') errors.push('enabled must be a boolean');
  if (r.tags !== undefined && (!Array.isArray(r.tags) || r.tags.some((t: any) => typeof t !== 'string'))) {
    errors.push('tags must be an array of strings');
  }

  // conditions
  if (!Array.isArray(r.conditions) || r.conditions.length === 0) {
    errors.push('conditions must be a non-empty array');
  } else {
    r.conditions.forEach((c: any, i: number) => {
      const at = `conditions[${i}]`;
      if (!isPlainObject(c)) { errors.push(`${at} must be an object`); return; }
      if (typeof c.field !== 'string' || c.field.trim() === '') errors.push(`${at}.field is required`);
      if (!RULE_OPERATORS.includes(c.operator)) {
        errors.push(`${at}.operator "${c.operator}" is not supported (one of ${RULE_OPERATORS.join(', ')})`);
      }
      // value requirements per operator
      if (c.operator === 'exists') {
        if (c.value !== undefined && typeof c.value !== 'boolean') {
          note(`${at}.value for "exists" should be true/false`);
        }
      } else if (c.value === undefined || c.value === null || c.value === '') {
        errors.push(`${at}.value is required for operator "${c.operator}"`);
      }
      if ((c.operator === 'in' || c.operator === 'not_in') && typeof c.value === 'string' && !c.value.includes(',')) {
        note(`${at}.value for "${c.operator}" is usually a comma-separated list or array`);
      }
      if ((c.operator === 'greater_than' || c.operator === 'less_than') && c.value !== undefined && isNaN(Number(c.value))) {
        errors.push(`${at}.value for "${c.operator}" must be numeric`);
      }
      if (c.operator === 'regex' && typeof c.value === 'string') {
        try { new RegExp(c.value); } catch (e) { errors.push(`${at}.value is not a valid regex: ${(e as Error).message}`); }
      }
    });
  }

  // aggregation (optional)
  if (r.aggregation !== undefined) {
    const a = r.aggregation;
    if (!isPlainObject(a)) {
      errors.push('aggregation must be an object');
    } else {
      if (typeof a.field !== 'string' || a.field.trim() === '') errors.push('aggregation.field is required');
      if (typeof a.timeframe !== 'string' || !/^\d+[smhd]$/.test(a.timeframe)) {
        errors.push('aggregation.timeframe must look like 30s / 5m / 1h / 1d');
      }
      if (typeof a.threshold !== 'number' || a.threshold < 1) errors.push('aggregation.threshold must be a positive number');
      if (a.distinct_count !== undefined && typeof a.distinct_count !== 'string') {
        errors.push('aggregation.distinct_count must be a field name (string)');
      }
    }
  }

  // alert
  if (!isPlainObject(r.alert)) {
    errors.push('alert is required ({ title, description })');
  } else {
    if (typeof r.alert.title !== 'string' || r.alert.title.trim() === '') errors.push('alert.title is required');
    if (r.alert.description !== undefined && typeof r.alert.description !== 'string') {
      errors.push('alert.description must be a string');
    }
  }

  return { ok: errors.length === 0, errors, warnings };
}
