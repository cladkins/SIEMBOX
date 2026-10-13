/**
 * Tests for the YAML loader. These pin the js-yaml 4 behaviour that rules/, the
 * detection catalog, rules and Sigma pasted into the UI, Nuclei templates and
 * discovery fingerprints were written against (the frontend's YAML check also
 * runs js-yaml 4), so a js-yaml upgrade that would change how any of it loads
 * fails here first. See utils/yaml.ts for why the backend stays on js-yaml 4.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { load, loadAll, dump } from './yaml';

test('merge keys (<<) are resolved, not kept as a literal "<<" key', () => {
  const doc = load('base: &b {field: path, operator: regex}\ncond:\n  <<: *b\n  value: x\n') as {
    cond: unknown;
  };
  assert.deepEqual(doc.cond, { field: 'path', operator: 'regex', value: 'x' });
});

test('unquoted timestamps load as Date, quoted ones stay strings', () => {
  const doc = load(
    'date: 2024-01-15\nat: 2024-01-15T10:20:30Z\nquoted: "2024-01-15"\nslashes: 2024/01/15\n'
  ) as {
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

test('!!binary, !!omap, !!pairs and !!set still load', () => {
  const doc = load(
    'b: !!binary aGVsbG8=\no: !!omap [{a: 1}, {b: 2}]\np: !!pairs [{a: 1}, {a: 2}]\ns: !!set {a, b}\n'
  ) as {
    b: Uint8Array;
    o: unknown;
    p: unknown;
    s: unknown;
  };
  assert.equal(Buffer.from(doc.b).toString(), 'hello');
  assert.deepEqual(doc.o, [{ a: 1 }, { b: 2 }]);
  assert.deepEqual(doc.p, [
    ['a', 1],
    ['a', 2],
  ]);
  assert.deepEqual(doc.s, { a: null, b: null });
});

test('collection mapping keys are stringified', () => {
  assert.deepEqual(load('? [a, b]\n: 1\n'), { 'a,b': 1 });
});

test('scalars: yes/no/on/off stay strings; true, null and number spellings resolve as before', () => {
  const doc = load('v: [yes, no, on, off, true, False, ~, null, 42, 0x1F, 0o17, 1e3, .inf]\n') as {
    v: unknown[];
  };
  assert.deepEqual(doc.v, [
    'yes',
    'no',
    'on',
    'off',
    true,
    false,
    null,
    null,
    42,
    31,
    15,
    1000,
    Infinity,
  ]);
  const signed = load('v: [0b101, -0x1F, +0o17, -.5, +.5, -0]\n') as { v: unknown[] };
  assert.deepEqual(signed.v, [5, -31, 15, '-.5', '+.5', 0]);
  assert.ok(Object.is(signed.v[5], 0));
});

test('out-of-range dates roll over and two-digit years read as 19xx', () => {
  const doc = load('v: [2024-02-30, 2024-01-15T25:00:00Z, 0099-01-01]\n') as { v: Date[] };
  assert.deepEqual(
    doc.v.map((d) => d.toISOString()),
    ['2024-03-01T00:00:00.000Z', '2024-01-16T01:00:00.000Z', '1999-01-01T00:00:00.000Z']
  );
});

test('continuation lines indented no deeper than their key still load', () => {
  // A rule's alert text wrapped inside a quoted string: what Rules.vue sends
  // back on Edit then Save for a rule stored this way.
  assert.deepEqual(
    load(
      'alert:\n  title: Admin access\n  description: "Request to the admin area\n  from {client_ip}"\n'
    ),
    {
      alert: { title: 'Admin access', description: 'Request to the admin area from {client_ip}' },
    }
  );
  // A pasted Sigma description and a wrapped flow tag list.
  assert.deepEqual(load('description: "Detects requests to the admin area\nof the proxy"\n'), {
    description: 'Detects requests to the admin area of the proxy',
  });
  assert.deepEqual(load('tags: [attack.t1059,\nattack.execution]\n'), {
    tags: ['attack.t1059', 'attack.execution'],
  });
  assert.deepEqual(load('a: {x: 1,\ny: 2}\n'), { a: { x: 1, y: 2 } });
  assert.deepEqual(load('- "a\nb"\n'), ['a b']);
  assert.deepEqual(load('k:\n  - "a\n  b"\n'), { k: ['a b'] });
});

test('a tab after a key, after a dash or inside a flow collection still loads', () => {
  assert.deepEqual(load('key:\t[x]\n'), { key: ['x'] });
  assert.deepEqual(load('key:\t{x: 1}\n'), { key: { x: 1 } });
  assert.deepEqual(load('-\t[x]\n'), [['x']]);
  assert.deepEqual(load('a: [1,\t2]\n'), { a: [1, 2] });
  assert.deepEqual(load('k: [a,\n\tb]\n'), { k: ['a', 'b'] });
});

test('an empty sequence entry keeps the structure js-yaml 4 gave it', () => {
  // js-yaml 4 attaches the less-indented `- g: b` to the inner list (YAML 1.2
  // would close the inner list first). Pinned so a parser change can't silently
  // regroup a Sigma selection, here one with a value commented out.
  assert.deepEqual(load('sel:\n  - f|contains:\n      - a\n      -  #b\n  - g: b\n'), {
    sel: [{ 'f|contains': ['a', null, { g: 'b' }] }],
  });
  assert.deepEqual(load('- f|contains:\n    - a\n    -\n- g: b\n'), [
    { 'f|contains': ['a', null, { g: 'b' }] },
  ]);
});

test('a key after a merge overrides a merged one, whatever its type', () => {
  assert.deepEqual(load('c:\n  <<: {1: x}\n  1: y\n'), { c: { '1': 'y' } });
  assert.deepEqual(load('base: &b {443: http}\nsvc: {<<: *b, 443: tls}\n'), {
    base: { '443': 'http' },
    svc: { '443': 'tls' },
  });
});

test('content on the --- line loads', () => {
  assert.deepEqual(load('--- a: 1\n'), { a: 1 });
  assert.deepEqual(load('--- - x\n'), ['x']);
});

test('invalid YAML, duplicate keys and several documents throw', () => {
  assert.throws(() => load('not: [valid'));
  assert.throws(() => load('a: 1\na: 2\n'));
  assert.throws(() => load('a: 1\n---\nb: 2\n'), /expected a single document/);
});

test('one load merges at most 10,000 keys through <<', () => {
  // js-yaml 4.3's security backport (maxTotalMergeKeys): aliases can't expand
  // a small document into an unbounded amount of merge work.
  const base = `a: &a {${Array.from({ length: 5001 }, (_, i) => `k${i}: ${i}`).join(', ')}}\nb: {<<: *a}\n`;
  assert.equal(Object.keys((load(base) as { b: object }).b).length, 5001);
  assert.throws(() => load(`${base}c: {<<: *a}\n`), /maxTotalMergeKeys/);
});

test('a stream with no content loads as no document or one null document', () => {
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
  assert.deepEqual(loadAll('a: 1\n---\nb: 2020-01-01\n'), [
    { a: 1 },
    { b: new Date('2020-01-01T00:00:00.000Z') },
  ]);
  assert.deepEqual(loadAll('---\n---\nb: 2\n'), [null, { b: 2 }]);
});

test('dump output loads back to the same data', () => {
  const rule = {
    name: 'r',
    conditions: [{ field: 'path', operator: 'regex', value: `(${'a|'.repeat(80)}b)` }],
    alert: { title: "it's {x}", description: '  padded  ' },
    tags: ['yes', 'on', '0x10', '2024-01-15', 'null', '8421:8421', '1:30', '-.5'],
  };
  assert.deepEqual(load(dump(rule, { lineWidth: 100, noRefs: true, sortKeys: false })), rule);
});
