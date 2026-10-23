/**
 * The in-memory zip reader's guards (zip bombs, odd entries), on archives
 * built in the test (testZip.test.ts). Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readZip, zipNameProblem, ZipError, type ZipLimits } from './zipReader';
import { makeZip } from './testZip.test';

const LIMITS: ZipLimits = { maxArchiveBytes: 1 << 20, maxEntries: 10, maxEntryBytes: 4096, maxTotalBytes: 8192 };
const all = () => true;

function refuses(zip: Buffer, pattern: RegExp, limits: ZipLimits = LIMITS) {
  assert.throws(() => readZip(zip, limits, all), (e: unknown) => e instanceof ZipError && pattern.test(e.message));
}

test('reads only the entries the caller selects, and skips directories', () => {
  const zip = makeZip([
    { name: 'rules/', data: '', stored: true },
    { name: 'rules/a.yml', data: 'a' },
    { name: 'README.md', data: 'not wanted' },
  ]);
  const out = readZip(zip, LIMITS, (n) => n.endsWith('.yml'));
  assert.deepEqual(out.map((e) => e.name), ['rules/a.yml']);
});

test('refuses an archive over the size cap, and anything that is not a zip', () => {
  refuses(makeZip([{ name: 'a.yml', data: 'x'.repeat(2000) }]), /limit is 100/, { ...LIMITS, maxArchiveBytes: 100 });
  refuses(Buffer.from('this is not a zip archive at all.........'), /not a zip/);
});

test('refuses more entries than the cap (counted from the central directory)', () => {
  const entries = Array.from({ length: 11 }, (_v, i) => ({ name: `r/${i}.yml`, data: 'x' }));
  refuses(makeZip(entries), /11 entries; the limit is 10/);
});

test('zip bomb: an entry over the per-file cap is refused before inflating', () => {
  refuses(makeZip([{ name: 'big.yml', data: 'a'.repeat(5000) }]), /5000 bytes; the limit is 4096/);
});

test('zip bomb: a header that understates the size stops inflating at the declared size', () => {
  // 1 MB of zeros deflates to ~1 KB; the header claims 10 bytes.
  refuses(makeZip([{ name: 'bomb.yml', data: Buffer.alloc(1 << 20), declaredSize: 10 }]), /does not inflate to its declared size/);
});

test('zip bomb: the total across entries is capped (each under the per-file cap)', () => {
  const entries = Array.from({ length: 3 }, (_v, i) => ({ name: `r/${i}.yml`, data: 'b'.repeat(4000) }));
  refuses(makeZip(entries), /more than 8192 bytes uncompressed/);
});

test('odd entries refuse the whole archive', () => {
  for (const [name, why] of [
    ['../etc/passwd', /"\." or "\.\." path segment/],
    ['rules/../../x.yml', /path segment/],
    ['/abs.yml', /absolute path/],
    ['C:/x.yml', /drive letter/],
    ['rules\\x.yml', /backslash/],
    ['rules/a\u0000.yml', /control character/],
    ['rules//a.yml', /empty path segment/],
  ] as const) {
    refuses(makeZip([{ name, data: 'x' }]), why);
  }
  refuses(makeZip([{ name: 'a.yml', data: 'x' }, { name: 'a.yml', data: 'y' }]), /duplicate entry/);
  refuses(makeZip([{ name: 'a.yml', data: 'x', flags: 0x1 }]), /encrypted/);
  refuses(makeZip([{ name: 'a.yml', data: 'x', method: 12 }]), /compression method 12/);
  refuses(makeZip([{ name: 'a.yml', data: 'x', crc: 1234 }]), /CRC-32/);
  refuses(makeZip([{ name: 'a.yml', data: 'x' }], { entryCount: 0xffff }), /ZIP64|65535 entries/, { ...LIMITS, maxEntries: 100_000 });
});

test('zipNameProblem accepts ordinary rule paths', () => {
  assert.equal(zipNameProblem('rules/web/proxy_generic/proxy_ua_hacktool.yml'), null);
  assert.equal(zipNameProblem('rules-emerging-threats/2021/TA/x.yml'), null);
  assert.equal(zipNameProblem('version.txt'), null);
});
