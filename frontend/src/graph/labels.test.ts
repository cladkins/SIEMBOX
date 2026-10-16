import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { canvasLabel, formatCount, fullLabel, hasUnsafeChars, plural, sanitizeText } from './labels.ts';

describe('label sanitizer', () => {
  it('removes C0 and C1 control characters', () => {
    assert.equal(sanitizeText('ro\u0000ot\u0007'), 'root');
    assert.equal(sanitizeText('a\u0085b\u009fc\u007f'), 'abc');
  });

  it('removes bidi marks and overrides', () => {
    // "evil‮exe.txt" would read as "eviltxt.exe" with the override.
    assert.equal(sanitizeText('evil‮exe.txt'), 'evilexe.txt');
    assert.equal(sanitizeText('⁦a⁩‎‏؜b'), 'ab');
  });

  it('collapses whitespace and trims the ends', () => {
    assert.equal(sanitizeText('  ssh \t brute\n\nforce  '), 'ssh brute force');
  });

  it('cuts to the limit with an ellipsis, counting code points', () => {
    assert.equal(canvasLabel('a'.repeat(30)), `${'a'.repeat(23)}…`);
    assert.equal(canvasLabel('a'.repeat(24)), 'a'.repeat(24));
    assert.equal(fullLabel('😀'.repeat(70)).length, 63 * 2 + 1);
  });

  it('turns null and undefined into nothing, and anything else into text', () => {
    assert.equal(sanitizeText(null), '');
    assert.equal(sanitizeText(undefined), '');
    assert.equal(sanitizeText(42), '42');
  });

  it('tells unsafe text apart', () => {
    assert.equal(hasUnsafeChars('fine text'), false);
    assert.equal(hasUnsafeChars('tab\there'), true);
    assert.equal(hasUnsafeChars('rtl‮'), true);
  });
});

describe('counts', () => {
  it('shows "1,000+" when capped', () => {
    assert.equal(formatCount(1000, true), '1,000+');
    assert.equal(formatCount(1204), '1,204');
  });

  it('pluralizes', () => {
    assert.equal(plural(1, 'alert'), '1 alert');
    assert.equal(plural(2, 'alert'), '2 alerts');
    assert.equal(plural(3, 'identity', 'identities'), '3 identities');
  });
});
