/**
 * TOTP/HOTP tests against the published RFC 4226 / RFC 6238 vectors. Run with
 * `npm test` (tsx --test). Proves the MFA crypto core is correct.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { base32Encode, base32Decode, hotp, totp, verifyTotp, otpauthUrl } from './totp';

// RFC 4226 / 6238 reference secret is the ASCII string "12345678901234567890".
const RFC_SECRET_ASCII = Buffer.from('12345678901234567890');
const RFC_SECRET_B32 = base32Encode(RFC_SECRET_ASCII);

test('base32 round-trips arbitrary bytes', () => {
  for (const s of ['', 'f', 'fo', 'foo', 'foob', 'fooba', 'foobar']) {
    const buf = Buffer.from(s);
    assert.deepEqual(base32Decode(base32Encode(buf)), buf);
  }
});

test('HOTP matches RFC 4226 Appendix D vectors', () => {
  const expected = [
    '755224', '287082', '359152', '969429', '338314',
    '254676', '287922', '162583', '399871', '520489',
  ];
  for (let c = 0; c < expected.length; c++) {
    assert.equal(hotp(RFC_SECRET_ASCII, c), expected[c], `counter ${c}`);
  }
});

test('TOTP matches RFC 6238 vectors (SHA-1, 6 digits)', () => {
  // [unix seconds, expected 6-digit code] — the low 6 digits of the RFC's
  // 8-digit SHA-1 vectors.
  const cases: Array<[number, string]> = [
    [59, '287082'],
    [1111111109, '081804'],
    [1111111111, '050471'],
    [1234567890, '005924'],
    [2000000000, '279037'],
  ];
  for (const [secs, code] of cases) {
    assert.equal(totp(RFC_SECRET_B32, { now: secs * 1000 }), code, `t=${secs}`);
  }
});

test('verifyTotp accepts the current code and rejects a wrong one', () => {
  const now = 1234567890 * 1000;
  assert.equal(verifyTotp(RFC_SECRET_B32, '005924', { now }), true);
  assert.equal(verifyTotp(RFC_SECRET_B32, '000000', { now }), false);
  assert.equal(verifyTotp(RFC_SECRET_B32, 'abc', { now }), false);
  // Spaces are tolerated (users paste "005 924").
  assert.equal(verifyTotp(RFC_SECRET_B32, '005 924', { now }), true);
});

test('verifyTotp honors the drift window', () => {
  const base = 1234567890 * 1000;
  // The code for the previous 30s step should validate with window=1...
  const prevCode = totp(RFC_SECRET_B32, { now: base - 30000 });
  assert.equal(verifyTotp(RFC_SECRET_B32, prevCode, { now: base, window: 1 }), true);
  // ...but not with window=0.
  assert.equal(verifyTotp(RFC_SECRET_B32, prevCode, { now: base, window: 0 }), false);
});

test('otpauthUrl builds a scannable URI', () => {
  const url = otpauthUrl({ issuer: 'SIEMBox', account: 'admin', secret: RFC_SECRET_B32 });
  assert.ok(url.startsWith('otpauth://totp/SIEMBox:admin?'));
  assert.ok(url.includes(`secret=${RFC_SECRET_B32}`));
  assert.ok(url.includes('issuer=SIEMBox'));
});
