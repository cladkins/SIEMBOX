/**
 * The label sanitizer: attacker-controlled text (usernames, host names, alert
 * titles) loses control and bidi characters and is cut to length.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hasUnsafeChars, MAX_FACT, MAX_LABEL, sanitizeFact, sanitizeLabel, sanitizeText } from './labels';

test('C0 and C1 control characters and DEL are removed', () => {
  assert.equal(sanitizeLabel('ro\u0000ot\u0007'), 'root');
  assert.equal(sanitizeLabel('a\u007fb\u0085c\u009bd'), 'abcd');
  assert.equal(sanitizeLabel('\u001b[31mred\u001b[0m'), '[31mred[0m', 'an ANSI escape loses its ESC');
});

test('bidi marks and overrides are removed', () => {
  for (const ch of ['؜', '‎', '‏', '‪', '‫', '‬', '‭', '‮', '⁦', '⁧', '⁨', '⁩']) {
    assert.equal(sanitizeLabel(`invoice${ch}fdp.exe`), 'invoicefdp.exe', `U+${ch.codePointAt(0)!.toString(16)}`);
    assert.equal(hasUnsafeChars(`x${ch}`), true);
  }
  assert.equal(hasUnsafeChars('plain text, ünïcode ✓'), false);
});

test('whitespace runs (tabs and newlines included) become one space; ends are trimmed', () => {
  assert.equal(sanitizeLabel('  Failed\n\tpassword   for\r\nroot  '), 'Failed password for root');
  assert.equal(sanitizeLabel('\n\n'), '');
});

test('cut to the maximum in code points, ending in an ellipsis', () => {
  assert.equal(sanitizeLabel('x'.repeat(MAX_LABEL)), 'x'.repeat(MAX_LABEL));
  const cut = sanitizeLabel('y'.repeat(MAX_LABEL + 10));
  assert.equal(Array.from(cut).length, MAX_LABEL);
  assert.ok(cut.endsWith('…'));
  // Astral characters count once and are never split.
  const emoji = sanitizeText('😀'.repeat(10), 5);
  assert.equal(emoji, '😀😀😀😀…');
  assert.equal(Array.from(sanitizeFact('z'.repeat(1000))).length, MAX_FACT);
  // A huge input stops early (no full copy).
  assert.equal(sanitizeText('q'.repeat(5_000_000), 8), 'qqqqqqq…');
});

test('non-strings: null and undefined are empty, others are stringified', () => {
  assert.equal(sanitizeLabel(null), '');
  assert.equal(sanitizeLabel(undefined), '');
  assert.equal(sanitizeLabel(42), '42');
});
