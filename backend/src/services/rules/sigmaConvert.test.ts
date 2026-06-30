/**
 * Unit tests for Sigma -> portable conversion. Run with `npm test` (tsx --test).
 * Each successful conversion is also re-validated through validateRule so an
 * imported rule can never be one the engine would reject.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sigmaToPortable, convertSigmaYaml } from './sigmaConvert';
import { validateRule } from './rulePortable';

/** Assert a converted rule is non-null and passes strict portable validation. */
function assertValid(result: ReturnType<typeof sigmaToPortable>) {
  assert.ok(result.rule, `expected a rule, got errors: ${result.errors.join('; ')}`);
  const v = validateRule(result.rule, { strict: true });
  assert.ok(v.ok, `converted rule failed validation: ${v.errors.join('; ')}`);
}

test('converts a basic single-selection web rule', () => {
  const r = sigmaToPortable({
    title: 'Suspicious Admin Path',
    description: 'Access to /admin',
    level: 'high',
    tags: ['attack.t1190'],
    detection: {
      selection: { 'c-uri': '/admin', 'sc-status': 200 },
      condition: 'selection',
    },
  });
  assertValid(r);
  assert.equal(r.rule!.severity, 'high');
  assert.equal(r.rule!.enabled, false); // imported disabled for review
  assert.ok(r.rule!.tags!.includes('sigma'));
  assert.ok(r.rule!.tags!.includes('attack.t1190'));
  // c-uri -> path, sc-status -> status_code
  const fields = r.rule!.conditions.map((c) => c.field).sort();
  assert.deepEqual(fields, ['path', 'status_code']);
  const pathCond = r.rule!.conditions.find((c) => c.field === 'path');
  assert.equal(pathCond!.operator, 'equals');
  assert.equal(pathCond!.value, '/admin');
});

test('list value becomes an `in` (OR membership) condition', () => {
  const r = sigmaToPortable({
    title: 'Bad methods',
    level: 'medium',
    detection: {
      selection: { 'cs-method': ['PUT', 'DELETE', 'TRACE'] },
      condition: 'selection',
    },
  });
  assertValid(r);
  const c = r.rule!.conditions[0];
  assert.equal(c.field, 'method');
  assert.equal(c.operator, 'in');
  assert.deepEqual(c.value, ['PUT', 'DELETE', 'TRACE']);
});

test('contains / startswith / endswith / re modifiers map correctly', () => {
  const r = sigmaToPortable({
    title: 'Modifiers',
    level: 'low',
    detection: {
      selection: {
        'c-uri|contains': '../',
        'c-useragent|startswith': 'sqlmap',
        'cs-uri-stem|endswith': '.php',
        'c-uri|re': '/api/v[0-9]+/admin',
      },
      condition: 'selection',
    },
  });
  assertValid(r);
  const byVal = Object.fromEntries(r.rule!.conditions.map((c) => [String(c.value), c]));
  assert.equal(byVal['../'].operator, 'contains');
  assert.equal(byVal['^sqlmap'].operator, 'regex'); // startswith -> anchored regex
  assert.equal(byVal['\\.php$'].operator, 'regex'); // endswith -> escaped + anchored
  assert.equal(byVal['/api/v[0-9]+/admin'].operator, 'regex'); // re -> regex passthrough
});

test('wildcard values convert to anchored regex', () => {
  const r = sigmaToPortable({
    title: 'Wildcards',
    level: 'medium',
    detection: { selection: { 'c-uri': '*/wp-admin/*' }, condition: 'selection' },
  });
  assertValid(r);
  const c = r.rule!.conditions[0];
  assert.equal(c.operator, 'regex');
  assert.equal(c.value, '^.*/wp-admin/.*$');
});

test('`|all` modifier produces an AND list of conditions', () => {
  const r = sigmaToPortable({
    title: 'All of these',
    level: 'high',
    detection: {
      selection: { 'c-uri|contains|all': ['etc', 'passwd'] },
      condition: 'selection',
    },
  });
  assertValid(r);
  assert.equal(r.rule!.conditions.length, 2);
  assert.ok(r.rule!.conditions.every((c) => c.operator === 'contains'));
  assert.deepEqual(r.rule!.conditions.map((c) => c.value).sort(), ['etc', 'passwd']);
});

test('multiple selections AND-ed via `a and b` and `all of them`', () => {
  const and = sigmaToPortable({
    title: 'Two sels',
    level: 'medium',
    detection: {
      selection1: { 'cs-method': 'POST' },
      selection2: { 'sc-status': 403 },
      condition: 'selection1 and selection2',
    },
  });
  assertValid(and);
  assert.equal(and.rule!.conditions.length, 2);

  const allOf = sigmaToPortable({
    title: 'All of them',
    level: 'medium',
    detection: {
      sel_a: { 'cs-method': 'POST' },
      sel_b: { 'sc-status': 403 },
      condition: 'all of them',
    },
  });
  assertValid(allOf);
  assert.equal(allOf.rule!.conditions.length, 2);
});

test('null value means "field exists"', () => {
  const r = sigmaToPortable({
    title: 'Has user agent',
    level: 'low',
    detection: { selection: { 'c-useragent': null }, condition: 'selection' },
  });
  assertValid(r);
  assert.equal(r.rule!.conditions[0].operator, 'exists');
  assert.equal(r.rule!.conditions[0].value, true);
});

test('OR / NOT / 1-of conditions are rejected, not mistranslated', () => {
  for (const condition of ['selection or filter', 'selection and not filter', '1 of selection*']) {
    const r = sigmaToPortable({
      title: 'Complex',
      level: 'high',
      detection: { selection: { a: 'x' }, filter: { b: 'y' }, condition },
    });
    assert.equal(r.rule, null, `condition "${condition}" should be unsupported`);
    assert.ok(r.errors.length > 0);
  }
});

test('a selection that is a list of maps (OR) is rejected', () => {
  const r = sigmaToPortable({
    title: 'List selection',
    level: 'high',
    detection: { selection: [{ a: 'x' }, { b: 'y' }], condition: 'selection' },
  });
  assert.equal(r.rule, null);
});

test('gte/lte and unsupported modifiers are skipped with a warning', () => {
  // Only the gte field is present -> nothing representable -> rule fails with reason.
  const r = sigmaToPortable({
    title: 'Gte only',
    level: 'low',
    detection: { selection: { 'bytes|gte': 1000 }, condition: 'selection' },
  });
  assert.equal(r.rule, null);
  assert.ok(r.warnings.join(' ').includes('gte') || r.errors.join(' ').includes('representable'));
});

test('convertSigmaYaml handles multiple --- separated documents', () => {
  const text = `
title: Rule A
level: high
detection:
  selection:
    c-uri: /a
  condition: selection
---
title: Rule B
level: low
detection:
  selection:
    c-uri: /b
  condition: selection
`;
  const results = convertSigmaYaml(text);
  assert.equal(results.length, 2);
  assert.equal(results[0].rule!.name, 'Rule A');
  assert.equal(results[1].rule!.name, 'Rule B');
});

test('invalid YAML returns a single error result', () => {
  const results = convertSigmaYaml(':\n  - [unclosed');
  assert.equal(results.length, 1);
  assert.equal(results[0].rule, null);
  assert.ok(results[0].errors[0].toLowerCase().includes('yaml'));
});
