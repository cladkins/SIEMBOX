/**
 * Tests for CEF extension parsing — correctness plus a guard that the parser is
 * linear (the old lazy-quantifier + look-ahead regex was a polynomial-ReDoS
 * vector). Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCefExtension } from './cef';

test('parses standard CEF extension key=value pairs', () => {
  const out = parseCefExtension('src=5.61.209.43 dst=192.168.1.194 act=blocked msg=intrusion blocked');
  assert.deepEqual(out, {
    src: '5.61.209.43',
    dst: '192.168.1.194',
    act: 'blocked',
    msg: 'intrusion blocked', // value runs (with spaces) until the next key=
  });
});

test('handles "=" inside a value and vendor keys', () => {
  const out = parseCefExtension('UNIFIipsSignature=ET SCAN foo=a=b=c spt=22');
  assert.equal(out.UNIFIipsSignature, 'ET SCAN');
  assert.equal(out.foo, 'a=b=c'); // only a whitespace-led key= starts a new field
  assert.equal(out.spt, '22');
});

test('tolerates extra whitespace and empty input', () => {
  assert.deepEqual(parseCefExtension(''), {});
  assert.deepEqual(parseCefExtension('a=1   b=2'), { a: '1', b: '2' });
});

test('is linear on adversarial input (no catastrophic backtracking)', () => {
  // Many whitespace-separated word-like tokens with no "=" used to make the lazy
  // quantifier + look-ahead backtrack polynomially. Assert it returns quickly.
  const evil = 'src=1.2.3.4 ' + 'token '.repeat(20000);
  const start = process.hrtime.bigint();
  const out = parseCefExtension(evil);
  const ms = Number(process.hrtime.bigint() - start) / 1e6;
  assert.equal(out.src?.slice(0, 7), '1.2.3.4'); // first key parsed
  assert.ok(ms < 250, `parse took ${ms.toFixed(1)}ms — should be ~linear`);
});
