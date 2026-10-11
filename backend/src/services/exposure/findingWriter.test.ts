/**
 * The exposure privacy invariant: whatever a caller puts in a finding's
 * `detail`, a key that could hold a secret (password, hash, token, API key,
 * credential...) is dropped at every depth before it is stored on the finding
 * or copied into the alert. Also pins the stable alert event id that makes
 * "one finding, one alert" hold across re-checks. DB behaviour lives in
 * findingWriter.db.test.ts. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { findingEventId, sanitizeDetail, SECRET_KEY_PATTERN } from './findingWriter';

test('sanitizeDetail strips secret-like keys at any depth, including inside arrays', () => {
  const detail = {
    account: 'alice@example.com',
    password: 'hunter2',
    Password: 'hunter2',
    pass: 'x',
    pwd: 'x',
    passwordHash: 'x',
    sha1_hash: 'x',
    data_classes: ['Email addresses', 'Passwords'], // values are kept: the scrub is key-based
    breach: {
      name: 'Adobe',
      api_key: 'k',
      apiKey: 'k',
      'api-key': 'k',
      APIKEY: 'k',
      token: 't',
      refresh_token: 't',
      client_secret: 's',
      credentials: { user: 'alice', secret: 's' },
      nested: [{ hash: 'h', keep: true }, { keep: 'also' }, 'plain-string', 7],
    },
  };

  assert.deepEqual(sanitizeDetail(detail), {
    account: 'alice@example.com',
    data_classes: ['Email addresses', 'Passwords'],
    breach: {
      name: 'Adobe',
      nested: [{ keep: true }, { keep: 'also' }, 'plain-string', 7],
    },
  });
});

test('nothing secret-shaped survives anywhere in the output', () => {
  const deep: Record<string, unknown> = { level: 0 };
  let cursor = deep;
  for (let i = 1; i < 8; i++) {
    const next: Record<string, unknown> = {
      level: i,
      [`token_${i}`]: 'secret',
      list: [{ password: 'p' }],
    };
    cursor.child = next;
    cursor = next;
  }
  const keys: string[] = [];
  const walk = (v: unknown) => {
    if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === 'object') {
      for (const [k, child] of Object.entries(v)) {
        keys.push(k);
        walk(child);
      }
    }
  };
  walk(sanitizeDetail(deep));
  assert.ok(keys.includes('level') && keys.includes('child'));
  assert.deepEqual(
    keys.filter((k) => SECRET_KEY_PATTERN.test(k)),
    []
  );
});

test('sanitizeDetail copies instead of mutating, and copes with odd input', () => {
  const input = { password: 'x', ok: 1, when: new Date('2026-01-02T03:04:05Z') };
  const out = sanitizeDetail(input);
  assert.deepEqual(input.password, 'x', 'the caller’s object is untouched');
  assert.deepEqual(out, { ok: 1, when: '2026-01-02T03:04:05.000Z' });

  const cyclic: Record<string, unknown> = { a: 1 };
  cyclic.self = cyclic;
  assert.doesNotThrow(
    () => JSON.stringify(sanitizeDetail(cyclic)),
    'cycles are cut, not followed forever'
  );

  assert.deepEqual(sanitizeDetail(null), {});
  assert.deepEqual(sanitizeDetail(['not', 'an', 'object']), {});
  assert.deepEqual(sanitizeDetail({ fn: () => 1, n: null }), { n: null });
});

test('the alert event id is stable per (source, fingerprint) and distinct across sources', () => {
  const a = findingEventId('leaked-creds', 'abc');
  assert.match(a, /^[0-9a-f]{64}$/);
  assert.equal(findingEventId('leaked-creds', 'abc'), a);
  assert.notEqual(findingEventId('domain-monitor', 'abc'), a);
  assert.notEqual(findingEventId('leaked-creds', 'abd'), a);
});
