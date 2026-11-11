import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extractIocs, normalizeIoc, occursIn, refang, isHuntableDomain } from './iocExtract';

const REPORT = `
The actor staged payloads at hxxps://evil-cdn[.]com/a/b.php?id=1 and 45.142.212[.]100.
C2 traffic went to update.badsite(.)net and to 2a01:4f8:c010:1::42 over port 443.
Phishing came from billing[@]invoice-portal[.]biz. The dropper SHA-256 was
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856, MD5 9e107d9d372bb6826bd81d3542a419d6.
It exploits CVE-2024-3400 and uses T1059.001 and T1566. Version 1.2.3.4.5 is not an IP.
The loader is named payload.exe and reads config.yaml. Internal host 10.0.0.5 and 192.168.1.10.
See https://twitter.com/someone and github.com for more. Our blog: research.vendor.com.
`;

test('refang undoes the common defangs', () => {
  assert.equal(refang('hxxp://a[.]b(.)c{.}d[dot]e'), 'http://a.b.c.d.e');
  assert.equal(refang('user[@]x[.]com'), 'user@x.com');
  assert.equal(refang('hxxps[:]//x.com'), 'https://x.com');
});

test('extractIocs finds each kind and refangs them', () => {
  const { indicators, techniques } = extractIocs(REPORT, {
    referenceDomains: ['vendor.com'],
    isTechnique: (t) => ['T1059.001', 'T1566'].includes(t),
  });
  const has = (type: string, value: string) => indicators.some((i) => i.type === type && i.value === value);
  assert.ok(has('url', 'https://evil-cdn.com/a/b.php?id=1'));
  assert.ok(has('domain', 'evil-cdn.com'));
  assert.ok(has('ipv4', '45.142.212.100'));
  assert.ok(has('domain', 'update.badsite.net'));
  assert.ok(has('ipv6', '2a01:4f8:c010:1::42'));
  assert.ok(has('email', 'billing@invoice-portal.biz'));
  assert.ok(has('domain', 'invoice-portal.biz'));
  assert.ok(has('sha256', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856'));
  assert.ok(has('md5', '9e107d9d372bb6826bd81d3542a419d6'));
  assert.ok(has('cve', 'CVE-2024-3400'));
  assert.deepEqual(techniques.sort(), ['T1059.001', 'T1566']);

  // Not indicators: private IPs, version strings, file names, reference sites, the vendor's own blog.
  assert.ok(!has('ipv4', '10.0.0.5'));
  assert.ok(!has('ipv4', '192.168.1.10'));
  assert.ok(!indicators.some((i) => i.value.startsWith('1.2.3.4') || i.value.startsWith('2.3.4.5')));
  assert.ok(!has('domain', 'payload.exe'));
  assert.ok(!has('domain', 'config.yaml'));
  assert.ok(!has('domain', 'github.com'));
  assert.ok(!has('domain', 'twitter.com'));
  assert.ok(!has('domain', 'research.vendor.com'));
  assert.ok(indicators.every((i) => i.context.length > 0));
});

test('the local part of an email address is not a domain', () => {
  const { indicators } = extractIocs('Contact first.name@evil-mail.org now');
  assert.ok(!indicators.some((i) => i.type === 'domain' && i.value === 'first.name'));
  assert.ok(indicators.some((i) => i.type === 'domain' && i.value === 'evil-mail.org'));
});

test('normalizeIoc validates per type', () => {
  assert.equal(normalizeIoc('ipv4', '8.8.8.8'), '8.8.8.8');
  assert.equal(normalizeIoc('ipv4', '127.0.0.1'), null);
  assert.equal(normalizeIoc('ipv4', '203.0.113.5'), null); // documentation range
  assert.equal(normalizeIoc('domain', 'Evil.COM.'), 'evil.com');
  assert.equal(normalizeIoc('domain', 'file.dll'), null);
  assert.equal(normalizeIoc('md5', '0'.repeat(32)), null);
  assert.equal(normalizeIoc('sha1', 'A'.repeat(39) + 'B'), 'a'.repeat(39) + 'b');
  assert.equal(normalizeIoc('url', 'javascript:alert(1)'), null);
  assert.equal(normalizeIoc('cve', 'cve-2021-44228'), 'CVE-2021-44228');
  assert.equal(isHuntableDomain('localhost'), false);
});

test('occursIn matches whole indicators only', () => {
  assert.equal(occursIn('conn from 1.2.3.4 port 22', '1.2.3.4', 'ipv4'), true);
  assert.equal(occursIn('conn from 11.2.3.45 port 22', '1.2.3.4', 'ipv4'), false);
  assert.equal(occursIn('conn from 1.2.3.45', '1.2.3.4', 'ipv4'), false);
  assert.equal(occursIn('ver 1.2.3.4.5', '1.2.3.4', 'ipv4'), false);
  assert.equal(occursIn('11.2.3.45 then 1.2.3.4', '1.2.3.4', 'ipv4'), true);
  assert.equal(occursIn('query sub.evil.com a', 'evil.com', 'domain'), true);
  assert.equal(occursIn('query notevil.com a', 'evil.com', 'domain'), false);
  assert.equal(occursIn('query evil.com.au a', 'evil.com', 'domain'), false);
  assert.equal(occursIn('query evil.com.', 'evil.com', 'domain'), true);
  assert.equal(occursIn('hash=aabbccdd', 'bbcc', 'md5'), false);
  assert.equal(occursIn('cve-2024-34001', 'cve-2024-3400', 'cve'), false);
  assert.equal(occursIn('rundll32.exe c:\\temp\\x.dll', 'rundll32.exe', 'keyword'), true);
});
