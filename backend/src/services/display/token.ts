/**
 * Display link secrets (docs/architecture/BIG-DISPLAY.md §4.1).
 *
 * A token is 'sbd1_' plus 32 random bytes in base64url: 48 characters, 256
 * bits. The versioned prefix lets secret scanners and log redaction recognise
 * a leaked one, and it can never be mistaken for a session token (64 hex).
 * Only its sha256 is stored (display_links.token_hash), like EDR and shipper
 * push keys: a fast hash is right for a high-entropy random secret, and the
 * lookup goes through a UNIQUE index, so no constant-time compare is needed.
 * token_hint, its last 4 characters, lets an admin match a screen to its row.
 */
import crypto from 'node:crypto';
import { sha256hex } from '../../models/EdrAgent';

export const DISPLAY_TOKEN_PREFIX = 'sbd1_';
/** Length of a display token: the prefix plus 43 base64url characters. */
export const DISPLAY_TOKEN_LENGTH = DISPLAY_TOKEN_PREFIX.length + 43;
/** A well-formed token. Linear (one fixed-length class), so it is safe on any input. */
export const DISPLAY_TOKEN_RE = /^sbd1_[A-Za-z0-9_-]{43}$/;

/** A new token, shown once (the create and rotate responses) and never stored. */
export function newDisplayToken(): string {
  return DISPLAY_TOKEN_PREFIX + crypto.randomBytes(32).toString('base64url');
}

/** Whether `value` has the token format. Checked before anything is hashed or queried. */
export function isDisplayToken(value: unknown): value is string {
  return typeof value === 'string' && value.length === DISPLAY_TOKEN_LENGTH && DISPLAY_TOKEN_RE.test(value);
}

/** The last 4 characters, for the admin list. */
export function tokenHint(token: string): string {
  return token.slice(-4);
}

/**
 * sha256 hex of a well-formed token (models/EdrAgent.ts sha256hex). Anything
 * else throws, so a malformed value is never hashed or looked up.
 */
export function hashDisplayToken(token: string): string {
  if (!isDisplayToken(token)) throw new TypeError('not a display link token');
  return sha256hex(token);
}

/** The path a screen opens; the admin UI prefixes its own origin. The secret is in the fragment. */
export function displayPath(token: string): string {
  return `/display#k=${token}`;
}
