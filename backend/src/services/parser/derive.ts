import { logger } from '../../utils/logger';

/**
 * Declarative field derivations — the data-driven replacement for the hardcoded
 * per-parser logic in parserEngine.postProcessFields. A parser can carry a list
 * of derivation rules (as data, in its `derivations`), so new log sources can be
 * onboarded — and shared/AI-generated — without touching engine code.
 *
 * Semantics:
 *   - rules are evaluated in order;
 *   - a rule applies its `set` only if ALL its `when` field-matchers match (AND);
 *   - a `set` key is written only when currently empty, unless `overwrite: true`,
 *     so an ordered list behaves like an if/else-if chain (first match wins).
 */

export interface DeriveMatcher {
  equals?: string | number | boolean;
  contains?: string; // case-insensitive substring
  in?: Array<string | number>;
  matches?: string; // regex, tested case-INsensitively (the hardcoded blocks this replaces all lower-cased first)
  exists?: boolean;
}

/** Extract a value from another field via a regex capture group. */
export interface ExtractSpec {
  from: string; // source field to run the regex against
  pattern: string; // regex with at least one capture group
  group?: number; // capture group to use (default 1)
}

export interface DeriveRule {
  /** field -> matcher; all must match. Omit to always apply. */
  when?: Record<string, DeriveMatcher>;
  /** fields to set to a literal value when matched. */
  set?: Record<string, string | number | boolean>;
  /** fields to set from a regex capture of another field. */
  extract?: Record<string, ExtractSpec>;
  /** overwrite existing values (default false = only fill empty fields). */
  overwrite?: boolean;
}

/**
 * Structurally validate a parser's `derivations` (used by import + CI). Returns a
 * list of human-readable errors; empty array means valid. Verifies rule shape,
 * matcher keys, and that every regex (`matches` / `extract.pattern`) compiles.
 */
export function validateDerivations(rules: unknown): string[] {
  const errors: string[] = [];
  if (rules === undefined || rules === null) return errors; // optional
  if (!Array.isArray(rules)) return ['derivations must be an array'];

  const matcherKeys = new Set(['equals', 'contains', 'in', 'matches', 'exists']);
  rules.forEach((rule: any, i) => {
    const at = `derivations[${i}]`;
    if (!rule || typeof rule !== 'object' || Array.isArray(rule)) {
      errors.push(`${at} must be an object`);
      return;
    }
    if (rule.set === undefined && rule.extract === undefined) {
      errors.push(`${at} must have a "set" or "extract"`);
    }
    if (rule.when !== undefined) {
      if (typeof rule.when !== 'object' || Array.isArray(rule.when)) {
        errors.push(`${at}.when must be an object`);
      } else {
        for (const [field, matcher] of Object.entries(rule.when as Record<string, any>)) {
          if (!matcher || typeof matcher !== 'object') {
            errors.push(`${at}.when.${field} must be a matcher object`);
            continue;
          }
          for (const k of Object.keys(matcher)) {
            if (!matcherKeys.has(k)) errors.push(`${at}.when.${field} has unknown matcher "${k}"`);
          }
          if (matcher.matches !== undefined) {
            try { new RegExp(String(matcher.matches)); } catch (e) {
              errors.push(`${at}.when.${field}.matches is not a valid regex: ${(e as Error).message}`);
            }
          }
          if (matcher.in !== undefined && !Array.isArray(matcher.in)) {
            errors.push(`${at}.when.${field}.in must be an array`);
          }
        }
      }
    }
    if (rule.set !== undefined && (typeof rule.set !== 'object' || Array.isArray(rule.set))) {
      errors.push(`${at}.set must be an object`);
    }
    if (rule.extract !== undefined) {
      if (typeof rule.extract !== 'object' || Array.isArray(rule.extract)) {
        errors.push(`${at}.extract must be an object`);
      } else {
        for (const [field, spec] of Object.entries(rule.extract as Record<string, any>)) {
          if (!spec || typeof spec !== 'object') {
            errors.push(`${at}.extract.${field} must be a {from, pattern} object`);
            continue;
          }
          if (typeof spec.from !== 'string' || !spec.from) errors.push(`${at}.extract.${field}.from must be a non-empty string`);
          if (typeof spec.pattern !== 'string' || !spec.pattern) {
            errors.push(`${at}.extract.${field}.pattern must be a non-empty string`);
          } else {
            try { new RegExp(spec.pattern); } catch (e) {
              errors.push(`${at}.extract.${field}.pattern is not a valid regex: ${(e as Error).message}`);
            }
          }
          if (spec.group !== undefined && (typeof spec.group !== 'number' || spec.group < 0)) {
            errors.push(`${at}.extract.${field}.group must be a non-negative number`);
          }
        }
      }
    }
  });
  return errors;
}

function isEmpty(v: any): boolean {
  return v === undefined || v === null || v === '';
}

function matchOne(value: any, m: DeriveMatcher): boolean {
  if (m.exists !== undefined) {
    if (m.exists !== !isEmpty(value)) return false;
  }
  const needsValue =
    m.equals !== undefined || m.contains !== undefined || m.in !== undefined || m.matches !== undefined;
  if (needsValue && isEmpty(value)) return false;

  const s = String(value ?? '');
  if (m.equals !== undefined && s !== String(m.equals)) return false;
  if (m.contains !== undefined && !s.toLowerCase().includes(String(m.contains).toLowerCase())) return false;
  if (m.in !== undefined && !m.in.map(String).includes(s)) return false;
  if (m.matches !== undefined) {
    try {
      if (!new RegExp(m.matches, 'i').test(s)) return false;
    } catch {
      return false;
    }
  }
  return true;
}

function whenMatches(fields: Record<string, any>, when?: Record<string, DeriveMatcher>): boolean {
  if (!when) return true;
  for (const [field, matcher] of Object.entries(when)) {
    if (!matchOne(fields[field], matcher)) return false;
  }
  return true;
}

/**
 * Apply a parser's declarative derivations to `fields` in place.
 * Safe to call with null/undefined/non-array (no-op).
 */
export function applyDerivations(fields: Record<string, any>, rules: unknown): void {
  if (!Array.isArray(rules)) return;
  for (const rule of rules as DeriveRule[]) {
    if (!rule || typeof rule !== 'object' || (typeof rule.set !== 'object' && typeof rule.extract !== 'object')) {
      continue;
    }
    try {
      if (!whenMatches(fields, rule.when)) continue;
      for (const [key, value] of Object.entries(rule.set || {})) {
        if (rule.overwrite || isEmpty(fields[key])) {
          fields[key] = value;
        }
      }
      for (const [key, spec] of Object.entries(rule.extract || {})) {
        if (!rule.overwrite && !isEmpty(fields[key])) continue;
        const source = fields[spec?.from as string];
        if (isEmpty(source) || !spec?.pattern) continue;
        const match = String(source).match(new RegExp(spec.pattern));
        const captured = match ? match[spec.group ?? 1] : undefined;
        if (!isEmpty(captured)) fields[key] = captured;
      }
    } catch (error) {
      logger.warn('Derivation rule failed; skipping', { error: error instanceof Error ? error.message : String(error) });
    }
  }
}
