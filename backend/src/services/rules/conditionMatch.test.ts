/**
 * Unit tests for the pure detection operators. Run with `npm test` (tsx --test).
 * No database required — this is the DB-free matching core.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PURE_CONDITION_OPERATORS, evaluatePureCondition } from './conditionMatch';

test('equals / not_equals compare stringified values', () => {
  assert.equal(evaluatePureCondition('equals', 'root', 'root'), true);
  assert.equal(evaluatePureCondition('equals', 'root', 'admin'), false);
  // Numbers are stringified before comparison, so 22 === "22".
  assert.equal(evaluatePureCondition('equals', 22, '22'), true);
  assert.equal(evaluatePureCondition('not_equals', 'root', 'admin'), true);
  assert.equal(evaluatePureCondition('not_equals', 'root', 'root'), false);
});

test('contains / not_contains are case-insensitive substring checks', () => {
  assert.equal(evaluatePureCondition('contains', 'Failed password', 'failed'), true);
  assert.equal(evaluatePureCondition('contains', 'Accepted', 'failed'), false);
  assert.equal(evaluatePureCondition('not_contains', 'Accepted', 'failed'), true);
  assert.equal(evaluatePureCondition('not_contains', 'Failed password', 'FAILED'), false);
});

test('regex matches against the field, invalid pattern fails closed', () => {
  assert.equal(evaluatePureCondition('regex', '192.168.1.5', '^192\\.168\\.'), true);
  assert.equal(evaluatePureCondition('regex', '10.0.0.1', '^192\\.168\\.'), false);
  // An unparseable pattern must not throw — it returns false.
  assert.equal(evaluatePureCondition('regex', 'anything', '('), false);
});

test('greater_than / less_than coerce to numbers', () => {
  assert.equal(evaluatePureCondition('greater_than', '10', 5), true);
  assert.equal(evaluatePureCondition('greater_than', 3, 5), false);
  assert.equal(evaluatePureCondition('less_than', '3', 5), true);
  assert.equal(evaluatePureCondition('less_than', 10, 5), false);
});

test('exists handles both value:true and value:false', () => {
  assert.equal(evaluatePureCondition('exists', 'something', true), true);
  assert.equal(evaluatePureCondition('exists', undefined, true), false);
  assert.equal(evaluatePureCondition('exists', null, true), false);
  // value:false means "field should be absent".
  assert.equal(evaluatePureCondition('exists', undefined, false), true);
  assert.equal(evaluatePureCondition('exists', 'present', false), false);
});

test('in / not_in accept arrays and comma-separated strings', () => {
  assert.equal(evaluatePureCondition('in', 'root', ['root', 'admin']), true);
  assert.equal(evaluatePureCondition('in', 'guest', ['root', 'admin']), false);
  // String form is split on commas and trimmed.
  assert.equal(evaluatePureCondition('in', 'admin', 'root, admin, svc'), true);
  assert.equal(evaluatePureCondition('not_in', 'guest', 'root, admin'), true);
  assert.equal(evaluatePureCondition('not_in', 'root', ['root', 'admin']), false);
  // Numeric array members are stringified before comparison.
  assert.equal(evaluatePureCondition('in', 404, [200, 404, 500]), true);
});

test('PURE_CONDITION_OPERATORS lists exactly the DB-free operators', () => {
  const expected = [
    'equals',
    'not_equals',
    'contains',
    'not_contains',
    'regex',
    'greater_than',
    'less_than',
    'in',
    'not_in',
    'exists',
  ].sort();
  assert.deepEqual([...PURE_CONDITION_OPERATORS].sort(), expected);
  // The I/O-backed operators must NOT be claimed by the pure set.
  for (const op of ['not_in_whitelist', 'on_threat_feed', 'not_on_threat_feed']) {
    assert.equal(PURE_CONDITION_OPERATORS.has(op), false);
  }
});

test('non-pure operator throws (callers must gate on the set first)', () => {
  assert.throws(() => evaluatePureCondition('on_threat_feed', '1.2.3.4', true));
});
