/**
 * Tests for the shared detection-regex compiler.
 *
 * Rule patterns used to be compiled with a bare `new RegExp(value)`: always
 * case-sensitive, with no way to ask otherwise. An author writing `(?i)` — the
 * syntax every other regex flavour uses — got a SyntaxError that was swallowed
 * into `return false`, i.e. a rule that silently never fires. Run with
 * `npm test` (tsx --test).
 */
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  compileUserRegex,
  testUserRegex,
  validateUserRegex,
  extractInlineFlags,
  clearUserRegexCache,
} from './userRegex';

beforeEach(() => clearUserRegexCache());

test('a plain pattern still compiles case-sensitively (no behaviour change)', () => {
  assert.equal(testUserRegex('UNION', 'a UNION b').matched, true);
  assert.equal(testUserRegex('UNION', 'a union b').matched, false);
});

test('an explicit flags argument makes matching case-insensitive', () => {
  assert.equal(testUserRegex('union select', 'UNION SELECT 1,2', 'i').matched, true);
});

test('a leading (?i) is translated rather than rejected', () => {
  // Bare `new RegExp('(?i)union')` throws "Invalid group" — the trap this fixes.
  // The invalid pattern is the point of the assertion, hence the disable.
  // eslint-disable-next-line no-invalid-regexp
  assert.throws(() => new RegExp('(?i)union'));

  const { regex, flags } = compileUserRegex('(?i)union');
  assert.equal(flags, 'i');
  assert.equal(regex.source, 'union');
  assert.equal(regex.test('UNION'), true);
});

test('multiple inline flags are supported', () => {
  const { flags } = compileUserRegex('(?im)^foo');
  assert.equal(flags, 'im');
});

test('inline and explicit flags merge, and duplicates collapse', () => {
  const { flags } = compileUserRegex('(?i)foo', 'im');
  assert.equal(flags, 'im');
});

test('an inline group that is not at the start is left alone', () => {
  // (?:...) mid-pattern is a real construct; only a LEADING group is flags.
  const { source, flags } = extractInlineFlags('foo(?:bar)');
  assert.equal(source, 'foo(?:bar)');
  assert.equal(flags, '');
});

test('the stateful flags g and y are rejected', () => {
  // A cached or reused /g/ RegExp carries lastIndex between calls, so identical
  // input alternates between matching and not — intermittent and undebuggable.
  for (const flag of ['g', 'y']) {
    const err = validateUserRegex('foo', flag);
    assert.ok(err, `flag ${flag} should be rejected`);
    assert.match(err!, /stateful/);
  }
});

test('an unknown flag is rejected with a helpful message', () => {
  const err = validateUserRegex('(?z)foo');
  assert.ok(err);
  assert.match(err!, /unsupported regex flag "z"/);
});

test('a malformed pattern reports an error instead of matching', () => {
  const result = testUserRegex('(unclosed', 'anything');
  assert.equal(result.matched, false);
  assert.ok(result.error, 'a broken pattern must surface an error, not just fail to match');
});

test('validateUserRegex returns null for a good pattern', () => {
  assert.equal(validateUserRegex('^[a-z]+$'), null);
  assert.equal(validateUserRegex('(?i)^[a-z]+$'), null);
  assert.equal(validateUserRegex('^[a-z]+$', 'i'), null);
});

test('repeated compilation returns the cached instance', () => {
  const a = compileUserRegex('(?i)union').regex;
  const b = compileUserRegex('(?i)union').regex;
  assert.equal(a, b, 'expected the same RegExp object from the cache');
});

test('cached instances are not stateful across calls', () => {
  // The reason g/y are banned: prove a cached regex gives the same answer twice.
  for (let i = 0; i < 3; i++) {
    assert.equal(testUserRegex('(?i)union', 'a UNION b').matched, true, `call ${i}`);
  }
});

test('patterns differing only in flags do not collide in the cache', () => {
  assert.equal(testUserRegex('union', 'UNION').matched, false);
  assert.equal(testUserRegex('union', 'UNION', 'i').matched, true);
  assert.equal(testUserRegex('union', 'UNION').matched, false);
});

test('the real PROXY-001 style pattern still works through this path', () => {
  const pattern = "('|%27|\"|%22|;|%3[Bb]|--)";
  assert.equal(testUserRegex(pattern, '/product?id=1%27').matched, true);
  assert.equal(testUserRegex(pattern, '/index.html').matched, false);
});

test('an author can now express case-insensitivity without character classes', () => {
  // What the workaround looked like vs. what it can be now.
  const classes = '(?<![A-Za-z])(?:[Uu][Nn][Ii][Oo][Nn])(?![A-Za-z])';
  const readable = '(?i)(?<![A-Za-z])union(?![A-Za-z])';
  for (const url of ['/p?id=1%20union%20select', '/p?id=1+UNION+SELECT']) {
    assert.equal(testUserRegex(classes, url).matched, testUserRegex(readable, url).matched);
  }
});
