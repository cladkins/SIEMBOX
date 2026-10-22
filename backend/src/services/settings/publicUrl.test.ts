/**
 * The public URL validator and the setting-over-env precedence
 * (services/settings/publicUrl.ts). Pure: no database. Run with `npm test`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MAX_PUBLIC_URL_LENGTH, resolvePublicUrl, validatePublicUrl } from './publicUrl';

function ok(input: unknown): string {
  const r = validatePublicUrl(input);
  assert.ok(r.ok, `${String(input)} is accepted${r.ok ? '' : `, got: ${r.error}`}`);
  return r.value;
}

function refused(input: unknown, pattern: RegExp): void {
  const r = validatePublicUrl(input);
  assert.equal(r.ok, false, `${String(input).slice(0, 60)} is refused`);
  if (!r.ok) assert.match(r.error, pattern);
}

test('a plain https URL is accepted as is', () => {
  assert.equal(ok('https://siem.example.com'), 'https://siem.example.com');
  assert.equal(ok('http://192.168.1.10:8420'), 'http://192.168.1.10:8420');
  assert.equal(ok('http://[::1]:8420'), 'http://[::1]:8420');
});

test('a sub-path is kept, without its trailing slash', () => {
  assert.equal(ok('https://example.com/siembox'), 'https://example.com/siembox');
  assert.equal(ok('https://example.com/tools/siembox/'), 'https://example.com/tools/siembox');
});

test('trailing slashes, surrounding whitespace and default ports are normalised away', () => {
  assert.equal(ok('https://siem.example.com/'), 'https://siem.example.com');
  assert.equal(ok('https://siem.example.com///'), 'https://siem.example.com');
  assert.equal(ok('  https://siem.example.com  '), 'https://siem.example.com');
  assert.equal(ok('https://siem.example.com:443/'), 'https://siem.example.com');
  assert.equal(ok('http://siem.example.com:80'), 'http://siem.example.com');
});

test('scheme and host are lowercased, the path is not', () => {
  assert.equal(ok('HTTPS://SIEM.Example.COM/SIEMBox/'), 'https://siem.example.com/SIEMBox');
});

test('empty, whitespace-only and null mean "not set"', () => {
  assert.equal(ok(''), '');
  assert.equal(ok('   '), '');
  assert.equal(ok(null), '');
  assert.equal(ok(undefined), '');
});

test('credentials are refused', () => {
  refused('https://admin:hunter2@siem.example.com', /username or password/);
  refused('https://admin@siem.example.com', /username or password/);
  refused('https://@siem.example.com', /username or password/);
});

test('an @ in the path is not mistaken for credentials', () => {
  assert.equal(ok('https://siem.example.com/@team'), 'https://siem.example.com/@team');
});

test('a query string is refused, even an empty one', () => {
  refused('https://siem.example.com/?next=/alerts', /query string/);
  refused('https://siem.example.com?', /query string/);
});

test('a fragment is refused, even an empty one', () => {
  refused('https://siem.example.com/#/alerts', /fragment/);
  refused('https://siem.example.com#', /fragment/);
});

test('javascript:, data:, file: and other schemes are refused', () => {
  refused('javascript:alert(1)', /http:\/\/ or https:\/\//);
  refused('JavaScript://siem.example.com/%0aalert(1)', /http:\/\/ or https:\/\//);
  refused('data:text/html,<script>alert(1)</script>', /http:\/\/ or https:\/\//);
  refused('file:///etc/passwd', /http:\/\/ or https:\/\//);
  refused('ftp://siem.example.com', /http:\/\/ or https:\/\//);
});

test('relative and scheme-less values are refused', () => {
  refused('/siembox', /absolute URL/);
  refused('siem.example.com', /absolute URL/);
  refused('//siem.example.com', /absolute URL/);
  refused('https:siem.example.com', /absolute URL/);
  refused('https:/siem.example.com', /absolute URL/);
});

test('a URL with no host, or that does not parse, is refused', () => {
  refused('https://', /not a valid URL|host/);
  refused('https://exa mple.com', /spaces or control characters/);
  refused('https://siem.example.com\n.evil.com', /spaces or control characters/);
  refused('http://[::1', /not a valid URL/);
});

test('non-strings are refused', () => {
  refused(42, /must be a string/);
  refused({ url: 'https://siem.example.com' }, /must be a string/);
});

test('a value longer than 2048 characters is refused', () => {
  const prefix = 'https://siem.example.com/';
  assert.equal(MAX_PUBLIC_URL_LENGTH, 2048);
  assert.equal(ok(prefix + 'a'.repeat(MAX_PUBLIC_URL_LENGTH - prefix.length)).length, MAX_PUBLIC_URL_LENGTH);
  refused(prefix + 'a'.repeat(MAX_PUBLIC_URL_LENGTH), /at most 2048 characters/);
  // Normalisation can lengthen a value (percent-encoding); the result is held to the cap too.
  refused(prefix + '%'.repeat(MAX_PUBLIC_URL_LENGTH - prefix.length - 10) + 'é'.repeat(10), /at most 2048/);
});

test('pathological input is handled in linear time', () => {
  const started = Date.now();
  validatePublicUrl('https://' + '/'.repeat(2000) + 'x');
  validatePublicUrl('https://a' + '/'.repeat(2030));
  validatePublicUrl('h'.repeat(2048));
  assert.ok(Date.now() - started < 500);
});

test('the setting wins over SIEMBOX_PUBLIC_URL', () => {
  const r = resolvePublicUrl('https://setting.example.com', 'https://env.example.com/');
  assert.equal(r.effective_public_url, 'https://setting.example.com');
  assert.equal(r.source, 'setting');
  assert.equal(r.env_public_url, 'https://env.example.com');
});

test('SIEMBOX_PUBLIC_URL applies when the setting is unset', () => {
  for (const stored of ['', null, undefined]) {
    const r = resolvePublicUrl(stored, 'HTTPS://ENV.example.com/siembox/');
    assert.equal(r.effective_public_url, 'https://env.example.com/siembox');
    assert.equal(r.source, 'env');
  }
});

test('neither set: no public URL', () => {
  const r = resolvePublicUrl('', undefined);
  assert.equal(r.effective_public_url, '');
  assert.equal(r.source, 'none');
});

test('an invalid SIEMBOX_PUBLIC_URL is ignored and the reason reported', () => {
  const r = resolvePublicUrl('', 'javascript:alert(1)');
  assert.equal(r.effective_public_url, '');
  assert.equal(r.source, 'none');
  assert.match(r.env_error ?? '', /^SIEMBOX_PUBLIC_URL is ignored: it must be an absolute URL/);
});

test('a stored value that no longer validates is treated as unset', () => {
  const r = resolvePublicUrl('https://user:pw@siem.example.com', 'https://env.example.com');
  assert.equal(r.public_url, '');
  assert.equal(r.effective_public_url, 'https://env.example.com');
});
