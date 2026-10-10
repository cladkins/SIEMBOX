/**
 * Pwned Passwords k-anonymity check (https://haveibeenpwned.com/API/v3#PwnedPasswords).
 *
 * The password never leaves this process: it is SHA-1 hashed locally and only
 * the first 5 hex characters of the hash are sent. The API answers with every
 * known hash suffix in that range (~800-1,000 lines with `Add-Padding: true`,
 * so the response size doesn't reveal anything either), and the match happens
 * here. Padding rows always have a count of 0 and are discarded.
 *
 * SHA-1 is mandated by the API's range format; the digest is a lookup key used
 * in memory for one comparison, never a stored password hash.
 *
 * Privacy: nothing in this module logs or persists the password, its hash, the
 * prefix, or the response — including in error messages. No API key is needed
 * and the endpoint has no rate limit; the route that exposes this applies its
 * own per-IP limit so it can't be used as a high-volume oracle.
 */
import crypto from 'crypto';

// Constant host; the only variable part of the URL is the 5-hex-char prefix of
// a digest computed here, never user text.
const RANGE_API_BASE = 'https://api.pwnedpasswords.com/range/';
export const PWNED_PASSWORDS_USER_AGENT =
  'SIEMBox-ExposureMonitor (+https://github.com/cladkins/siembox)';
const DEFAULT_TIMEOUT_MS = 10_000;
const PREFIX_RE = /^[0-9A-F]{5}$/;

export interface PwnedPasswordResult {
  pwned: boolean;
  /** How many times the password appears in the corpus; 0 when not pwned. */
  count: number;
}

export type FetchFn = (url: URL, init: RequestInit) => Promise<Response>;

export interface CheckPasswordOptions {
  fetchImpl?: FetchFn;
  timeoutMs?: number;
}

/** A lookup that could not be completed. The message never contains request data. */
export class PwnedPasswordsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PwnedPasswordsError';
  }
}

/**
 * Find `suffix` (35 uppercase hex chars) in a range response. Lines are
 * `SUFFIX:COUNT`; rows with a count of 0 are padding and never a match.
 */
export function findSuffixCount(body: string, suffix: string): number {
  for (const line of body.split('\n')) {
    const sep = line.indexOf(':');
    if (sep <= 0) continue;
    if (line.slice(0, sep).trim().toUpperCase() !== suffix) continue;
    const count = Number.parseInt(line.slice(sep + 1).trim(), 10);
    if (Number.isFinite(count) && count > 0) return count;
  }
  return 0;
}

export async function checkPassword(
  pw: string,
  options: CheckPasswordOptions = {}
): Promise<PwnedPasswordResult> {
  if (typeof pw !== 'string' || pw.length === 0)
    throw new PwnedPasswordsError('A password is required');

  const digest = crypto.createHash('sha1').update(pw, 'utf8').digest('hex').toUpperCase();
  const prefix = digest.slice(0, 5);
  const suffix = digest.slice(5);
  if (!PREFIX_RE.test(prefix)) throw new PwnedPasswordsError('Could not hash the password');

  const url = new URL(RANGE_API_BASE);
  url.pathname += prefix;

  const fetchImpl: FetchFn = options.fetchImpl ?? ((u, init) => fetch(u, init));
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  let body: string;
  try {
    let res: Response;
    try {
      res = await fetchImpl(url, {
        headers: { 'Add-Padding': 'true', 'User-Agent': PWNED_PASSWORDS_USER_AGENT },
        signal: ctrl.signal,
        redirect: 'manual',
      });
    } catch {
      throw new PwnedPasswordsError(
        ctrl.signal.aborted
          ? 'Pwned Passwords lookup timed out'
          : 'Pwned Passwords could not be reached'
      );
    }
    if (res.status !== 200) {
      void res.body?.cancel().catch(() => undefined);
      throw new PwnedPasswordsError(`Pwned Passwords returned HTTP ${res.status}`);
    }
    try {
      body = await res.text();
    } catch {
      throw new PwnedPasswordsError(
        ctrl.signal.aborted
          ? 'Pwned Passwords lookup timed out'
          : 'Pwned Passwords response could not be read'
      );
    }
  } finally {
    clearTimeout(timer);
  }

  const count = findSuffixCount(body, suffix);
  return { pwned: count > 0, count };
}
