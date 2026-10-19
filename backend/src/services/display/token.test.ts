/**
 * Display link secrets: format, hint, hash. Pure. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  DISPLAY_TOKEN_LENGTH,
  DISPLAY_TOKEN_RE,
  displayPath,
  hashDisplayToken,
  isDisplayToken,
  newDisplayToken,
  tokenHint,
} from './token';

test('a new token is sbd1_ plus 43 base64url characters (256 bits), and each is different', () => {
  const seen = new Set<string>();
  for (let i = 0; i < 200; i++) {
    const token = newDisplayToken();
    assert.equal(token.length, 48);
    assert.equal(token.length, DISPLAY_TOKEN_LENGTH);
    assert.ok(token.startsWith('sbd1_'));
    assert.match(token, /^sbd1_[A-Za-z0-9_-]{43}$/);
    assert.ok(DISPLAY_TOKEN_RE.test(token));
    assert.ok(isDisplayToken(token));
    assert.equal(Buffer.from(token.slice(5), 'base64url').length, 32, '32 random bytes');
    seen.add(token);
  }
  assert.equal(seen.size, 200);
});

test('a session token (64 hex) or anything else is not a display token', () => {
  for (const value of [
    crypto.randomBytes(32).toString('hex'), // a session token
    '',
    'sbd1_',
    'sbd1_' + 'A'.repeat(42),
    'sbd1_' + 'A'.repeat(44),
    'sbd2_' + 'A'.repeat(43),
    'SBD1_' + 'A'.repeat(43),
    'sbd1_' + 'A'.repeat(42) + '=',
    'sbd1_' + 'A'.repeat(42) + '+',
    'sbd1_' + 'A'.repeat(42) + '/',
    ' sbd1_' + 'A'.repeat(43),
    'sbd1_' + 'A'.repeat(43) + '\n',
    'Bearer sbd1_' + 'A'.repeat(43),
    'sbd1_' + 'A'.repeat(43) + ', sbd1_' + 'B'.repeat(43), // a repeated header, joined
  ]) {
    assert.equal(isDisplayToken(value), false, JSON.stringify(value));
  }
  assert.equal(isDisplayToken(undefined), false);
  assert.equal(isDisplayToken(42), false);
});

test('the hint is the last 4 characters', () => {
  const token = 'sbd1_' + 'A'.repeat(39) + 'wxYz';
  assert.equal(tokenHint(token), 'wxYz');
});

test('the hash is the sha256 hex of the token, and malformed tokens are refused before hashing', () => {
  const token = newDisplayToken();
  assert.equal(hashDisplayToken(token), crypto.createHash('sha256').update(token).digest('hex'));
  assert.match(hashDisplayToken(token), /^[0-9a-f]{64}$/);
  for (const bad of ['', 'not-a-token', crypto.randomBytes(32).toString('hex'), 'sbd1_' + '!'.repeat(43)]) {
    assert.throws(() => hashDisplayToken(bad), TypeError, bad);
  }
});

test('the path puts the secret in the fragment, which browsers never send', () => {
  const token = newDisplayToken();
  const path = displayPath(token);
  assert.equal(path, `/display#k=${token}`);
  const url = new URL(path, 'https://siembox.example');
  assert.equal(url.pathname, '/display');
  assert.equal(url.search, '');
  assert.equal(url.hash, `#k=${token}`);
});
