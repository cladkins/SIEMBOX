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
