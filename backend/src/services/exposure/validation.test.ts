/**
 * What an operator may put under exposure monitoring. Domains end up as UNIQUE
 * keys and in HIBP request paths, so anything that isn't a bare hostname with a
 * real TLD — URLs, ports, wildcards, IPs, unicode look-alikes — is refused, and
 * everything accepted is stored in one canonical (lowercase) spelling.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeDomain, normalizeEmail, normalizeIdentityValue } from './validation';

// Exactly 253 characters: 63 + 63 + 63 + 57 + "com" and four dots.
const MAX_LENGTH_DOMAIN = `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(57)}.com`;

test('domains: accepted inputs are normalized to one lowercase spelling', () => {
  assert.equal(MAX_LENGTH_DOMAIN.length, 253);
  const accepted: Array<[string, string]> = [
    ['example.com', 'example.com'],
    ['  Example.COM  ', 'example.com'],
    ['sub.example.co.uk', 'sub.example.co.uk'],
    ['example.com.', 'example.com'], // fully-qualified (root dot) form
    ['xn--bcher-kva.de', 'xn--bcher-kva.de'], // punycode label
    ['example.xn--p1ai', 'example.xn--p1ai'], // punycode TLD
    ['my-brand.io', 'my-brand.io'],
    ['1password.com', '1password.com'],
    [`${'a'.repeat(63)}.com`, `${'a'.repeat(63)}.com`],
    [MAX_LENGTH_DOMAIN, MAX_LENGTH_DOMAIN],
  ];
  for (const [input, expected] of accepted) {
    assert.deepEqual(
      normalizeDomain(input),
      { ok: true, value: expected },
      `should accept ${input}`
    );
  }
});

test('domains: URLs, ports, paths, wildcards, IPs and malformed labels are rejected', () => {
  const rejected: unknown[] = [
    '',
    '   ',
    'localhost', // no TLD
    'example',
    'https://example.com',
    'http://example.com/login',
    'example.com/path',
    'example.com:8443',
    'example.com?q=1',
    'example.com#frag',
    'user@example.com',
    'ftp:example.com',
    '*.example.com',
    'exa mple.com',
    '-example.com',
    'example-.com',
    'exa_mple.com',
    'a..example.com',
    '.example.com',
    'example.com..',
    '192.168.1.1',
    '10.0.0.1.',
    '::1',
    '2001:db8::1',
    '[2001:db8::1]',
    'example.123', // numeric TLD
    'example.c', // one-letter TLD
    'bücher.de', // unicode: must be entered as punycode
    'еxample.com', // Cyrillic "е" homograph
    `${'a'.repeat(64)}.com`, // label > 63
    `${MAX_LENGTH_DOMAIN}x`, // 254 characters
    `a.${MAX_LENGTH_DOMAIN}`,
    null,
    undefined,
    42,
    { domain: 'example.com' },
  ];
  for (const input of rejected) {
    const result = normalizeDomain(input);
    assert.equal(result.ok, false, `should reject ${JSON.stringify(input)}`);
    if (!result.ok) assert.ok(result.error.length > 0);
  }
});

test('domains: the rejection says what is wrong', () => {
  const error = (input: string) => {
    const result = normalizeDomain(input);
    return result.ok ? '' : result.error;
  };
  assert.match(error('https://example.com'), /bare domain/);
  assert.match(error('*.example.com'), /wildcard/);
  assert.match(error('192.168.1.1'), /IP address/);
  assert.match(error('10.0.0.1.'), /IP address/);
  assert.match(error('::1'), /IP address/);
  assert.match(error('localhost'), /top-level domain/);
  assert.match(error('bücher.de'), /punycode/);
});

test('emails: accepted inputs are normalized', () => {
  const accepted: Array<[string, string]> = [
    ['alice@example.com', 'alice@example.com'],
    ['  Alice.Smith+Tag@Example.COM ', 'alice.smith+tag@example.com'],
    ["o'brien@example.ie", "o'brien@example.ie"],
    ['a@b.co', 'a@b.co'],
    ['first_last-1@mail.example.org.', 'first_last-1@mail.example.org'],
  ];
  for (const [input, expected] of accepted) {
    assert.deepEqual(
      normalizeEmail(input),
      { ok: true, value: expected },
      `should accept ${input}`
    );
  }
});

test('emails: malformed addresses are rejected', () => {
  const rejected: unknown[] = [
    '',
    'alice',
    'alice@',
    '@example.com',
    'alice@@example.com',
    'alice@exa@mple.com',
    '.alice@example.com',
    'alice.@example.com',
    'al..ice@example.com',
    '"alice"@example.com', // quoted local parts are not supported
    'ali ce@example.com',
    'mailto:alice@example.com',
    'alice@localhost',
    'alice@192.168.1.1',
    'alice@[127.0.0.1]',
    'alice@example.com/x',
    'alice@*.example.com',
    `${'a'.repeat(65)}@example.com`, // local part > 64
    `alice@${'a'.repeat(250)}.com`, // > 254 overall
    null,
    123,
  ];
  for (const input of rejected) {
    assert.equal(normalizeEmail(input).ok, false, `should reject ${JSON.stringify(input)}`);
  }
});

test('identity values are validated for their kind', () => {
  assert.deepEqual(normalizeIdentityValue('email', 'Bob@Example.com'), {
    ok: true,
    value: 'bob@example.com',
  });
  assert.deepEqual(normalizeIdentityValue('email_domain', 'Example.com'), {
    ok: true,
    value: 'example.com',
  });
  assert.equal(normalizeIdentityValue('email', 'example.com').ok, false);
  assert.equal(normalizeIdentityValue('email_domain', 'bob@example.com').ok, false);
});
