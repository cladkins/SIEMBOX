/**
 * RFC 6238 TOTP (and RFC 4226 HOTP) implemented on node:crypto — no third-party
 * dependency. Pure and unit-tested against the RFC test vectors, so the MFA core
 * is provably correct. SHA-1 / 6 digits / 30s step is the authenticator-app
 * default (Google Authenticator, Authy, 1Password, …).
 */
import crypto from 'crypto';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Encode bytes as RFC 4648 base32 (no padding). */
export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return out;
}

/** Decode an RFC 4648 base32 string (padding/spaces/lowercase tolerated). */
export function base32Decode(input: string): Buffer {
  const clean = input.replace(/=+$/.test(input) ? /=+$/ : / /g, '').replace(/\s/g, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) continue; // skip any stray separators
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/** Generate a new random base32 TOTP secret (default 20 bytes = 160 bits). */
export function generateSecret(bytes = 20): string {
  return base32Encode(crypto.randomBytes(bytes));
}

/** RFC 4226 HOTP for a given counter. */
export function hotp(secret: Buffer, counter: number, digits = 6, algorithm = 'sha1'): string {
  const buf = Buffer.alloc(8);
  // 64-bit big-endian counter (high 32 bits handled for completeness).
  buf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  buf.writeUInt32BE(counter >>> 0, 4);

  const hmac = crypto.createHmac(algorithm, secret).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return (binary % 10 ** digits).toString().padStart(digits, '0');
}

export interface TotpOptions {
  /** Unix time in ms (defaults to now). */
  now?: number;
  step?: number;
  digits?: number;
  algorithm?: string;
}

/** Current RFC 6238 TOTP for a base32 secret. */
export function totp(secretBase32: string, opts: TotpOptions = {}): string {
  const { now = Date.now(), step = 30, digits = 6, algorithm = 'sha1' } = opts;
  const counter = Math.floor(now / 1000 / step);
  return hotp(base32Decode(secretBase32), counter, digits, algorithm);
}

/**
 * Verify a token against a base32 secret, allowing +/- `window` steps of clock
 * drift (default 1 = +/-30s). Uses a constant-time compare per candidate.
 */
export function verifyTotp(
  secretBase32: string,
  token: string,
  opts: TotpOptions & { window?: number } = {}
): boolean {
  const { now = Date.now(), step = 30, digits = 6, algorithm = 'sha1', window = 1 } = opts;
  const cleaned = String(token).replace(/\s/g, '');
  if (!/^\d+$/.test(cleaned) || cleaned.length !== digits) return false;
  const secret = base32Decode(secretBase32);
  const counter = Math.floor(now / 1000 / step);
  for (let errorWindow = -window; errorWindow <= window; errorWindow++) {
    const candidate = hotp(secret, counter + errorWindow, digits, algorithm);
    if (candidate.length === cleaned.length && crypto.timingSafeEqual(Buffer.from(candidate), Buffer.from(cleaned))) {
      return true;
    }
  }
  return false;
}

/** Build the otpauth:// URI an authenticator app scans / imports. */
export function otpauthUrl(params: { issuer: string; account: string; secret: string }): string {
  // Conventional otpauth label keeps the issuer:account colon literal and
  // percent-encodes the two parts individually.
  const label = `${encodeURIComponent(params.issuer)}:${encodeURIComponent(params.account)}`;
  const q = new URLSearchParams({
    secret: params.secret,
    issuer: params.issuer,
    algorithm: 'SHA1',
    digits: '6',
    period: '30',
  });
  return `otpauth://totp/${label}?${q.toString()}`;
}
