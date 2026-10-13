/**
 * Tests for the YAML loader. js-yaml 5's own defaults (plain YAML 1.2 core)
 * would load rule, Sigma and template YAML differently from js-yaml 4; these pin
 * the js-yaml 4 behaviour that utils/yaml.ts restores, and the differences it
 * documents as kept.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { load, loadAll, dump } from './yaml';

test('merge keys (<<) are resolved, not kept as a literal "<<" key', () => {
  const doc = load('base: &b {field: path, operator: regex}\ncond:\n  <<: *b\n  value: x\n') as { cond: unknown };
  assert.deepEqual(doc.cond, { field: 'path', operator: 'regex', value: 'x' });
});

test('unquoted timestamps load as Date, quoted ones stay strings', () => {
  const doc = load('date: 2024-01-15\nat: 2024-01-15T10:20:30Z\nquoted: "2024-01-15"\nslashes: 2024/01/15\n') as {
    date: Date;
    at: Date;
    quoted: string;
    slashes: string;
  };
  assert.ok(doc.date instanceof Date);
  assert.equal(doc.date.toISOString(), '2024-01-15T00:00:00.000Z');
  assert.equal(doc.at.toISOString(), '2024-01-15T10:20:30.000Z');
  assert.equal(doc.quoted, '2024-01-15');
  assert.equal(doc.slashes, '2024/01/15');
});

test('!!binary, !!omap and !!pairs still load', () => {
  const doc = load('b: !!binary aGVsbG8=\no: !!omap [{a: 1}, {b: 2}]\np: !!pairs [{a: 1}, {a: 2}]\n') as {
    b: Uint8Array;
    o: unknown;
    p: unknown;
  };
  assert.equal(Buffer.from(doc.b).toString(), 'hello');
  assert.deepEqual(doc.o, [{ a: 1 }, { b: 2 }]);
  assert.deepEqual(doc.p, [['a', 1], ['a', 2]]);
});

test('collection mapping keys are stringified, as js-yaml 4 did', () => {
  assert.deepEqual(load('? [a, b]\n: 1\n'), { 'a,b': 1 });
});

test('YAML 1.2 scalars: yes/no/on/off stay strings, true/null/numbers resolve', () => {
  const doc = load('v: [yes, no, on, off, true, False, ~, null, 42, 0x1F, 0o17, 1e3, .inf]\n') as { v: unknown[] };
  assert.deepEqual(doc.v, ['yes', 'no', 'on', 'off', true, false, null, null, 42, 31, 15, 1000, Infinity]);
});

test('invalid YAML, duplicate keys and several documents throw', () => {
  assert.throws(() => load('not: [valid'));
  assert.throws(() => load('a: 1\na: 2\n'));
  assert.throws(() => load('a: 1\n---\nb: 2\n'), /expected a single document/);
});

test('a stream with no content loads as js-yaml 4 did', () => {
  // No document at all: blank up to one line break.
  for (const empty of ['', '   ', '\n', ' \r', '\uFEFF']) {
    assert.equal(load(empty), undefined, JSON.stringify(empty));
    assert.deepEqual(loadAll(empty), [], JSON.stringify(empty));
  }
  // One empty (null) document: comments, several blank lines, a bare marker.
  for (const blank of ['# only a comment\n', '\n\n', ' \r\n', '\t', '---\n', '...\n']) {
    assert.equal(load(blank), null, JSON.stringify(blank));
    assert.deepEqual(loadAll(blank), [null], JSON.stringify(blank));
  }
});

test('loadAll returns every document', () => {
  assert.deepEqual(loadAll('a: 1\n---\nb: 2020-01-01\n'), [{ a: 1 }, { b: new Date('2020-01-01T00:00:00.000Z') }]);
  assert.deepEqual(loadAll('---\n---\nb: 2\n'), [null, { b: 2 }]);
});

test('documented differences from js-yaml 4 (update the utils/yaml.ts comment if these change)', () => {
  const nums = load('v: [0b101, -0x1F, +0o17, -.5, -0]\n') as { v: unknown[] };
  assert.deepEqual(nums.v.slice(0, 4), ['0b101', '-0x1F', '+0o17', -0.5]);
  assert.ok(Object.is(nums.v[4], -0));
  assert.deepEqual(load('v: [2024-02-30, 2024-01-15T25:00:00Z]\n'), { v: ['2024-02-30', '2024-01-15T25:00:00Z'] });
  assert.throws(() => load('s: !!set {a, b}\n'));
  assert.throws(() => load('a: [1,\t2]\n'));
});

test('dump output loads back to the same data', () => {
  const rule = {
    name: 'r',
    conditions: [{ field: 'path', operator: 'regex', value: `(${'a|'.repeat(80)}b)` }],
    alert: { title: "it's {x}", description: '  padded  ' },
    tags: ['yes', 'on', '0x10', '2024-01-15', 'null', '8421:8421', '1:30', '-.5'],
  };
  assert.deepEqual(load(dump(rule, { lineWidth: 100, noRefs: true })), rule);
});
