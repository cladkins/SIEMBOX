/**
 * Sign-in protection policy: which throttle keys an attempt counts against,
 * when a key pauses and for how long, and what the client is told. Pure: no
 * database, no clock of its own (callers pass the database's NOW()-derived
 * values in). The counters themselves live in Postgres (models/LoginThrottle.ts).
 *
 * One schedule for every key: its T-th consecutive failure pauses it for 30
 * seconds, and each further failure doubles the pause (30 s, 1, 2, 4, 8, 16,
 * 32 minutes) up to the scope's cap. A streak ends 24 hours after its last
 * failure. Nothing is ever locked for good, so an attacker can at most slow an
 * account down, and recognized browsers (recognizedBrowsers.ts) skip every
 * account and network key, so the people who own an account keep signing in
 * from the browsers they used before.
 *
 * | Scope | Key                    | Counts                                             | T  | Cap    | On a full success |
 * |-------|------------------------|----------------------------------------------------|----|--------|-------------------|
 * | aip   | aip:<h(user)>:<net>    | wrong passwords, new browsers, one network         | 5  | 15 min | reset             |
 * | ip    | ip:<net>               | wrong passwords, new browsers, any username        | 20 | 30 min | refund only       |
 * | acct  | acct:<h(user)>         | wrong passwords, new browsers, every network       | 20 | 60 min | refund only       |
 * | br    | br:<id>                | wrong passwords and codes from one known browser   | 10 | 15 min | reset             |
 * | mfa   | mfa:<user id>          | wrong codes (sign-in from new browsers, disabling) | 5  | 60 min | reset             |
 * | pwc   | pwc:<user id>          | wrong current passwords on a password change       | 5  | 60 min | reset             |
 *
 * h(user) hashes the username exactly as typed, so a username that doesn't
 * exist gets the same keys, thresholds and messages as one that does, and no
 * string anyone typed is stored. <net> is an IPv4 address or an IPv6 /64
 * (net/clientAddress.ts signInNetworkKey). LOGIN_MAX_FAILURES,
 * LOGIN_MAX_FAILURES_PER_ADDRESS and LOGIN_MAX_FAILURES_PER_ACCOUNT (0 turns
 * that scope off) set the first three thresholds; LOGIN_PROTECTION=off turns
 * every counter off.
 */
import crypto from 'node:crypto';
import { envInt } from '../../utils/envInt';
import { formatWait } from '../../net/requestLimits';

export type SignInScope = 'aip' | 'ip' | 'acct' | 'br' | 'mfa' | 'pwc';

/** The `reason` of a SIGNIN_PAUSED 429. */
export type PauseReason = 'account_network' | 'network' | 'account' | 'browser' | 'mfa' | 'current_password';

export interface ScopePolicy {
  scope: SignInScope;
  /** Consecutive failures that start the first pause; 0 means the scope is off. */
  threshold: number;
  /** Longest pause, in seconds. */
  capSeconds: number;
  /** A full success zeroes the key; otherwise a correct password only refunds this attempt. */
  resetOnSuccess: boolean;
  reason: PauseReason;
  /** What the key counts, in plain words (the admin page). */
  label: string;
}

/** The first pause, in seconds. */
export const FIRST_PAUSE_SECONDS = 30;
/** A key's streak of failures ends this long after its last failure. */
export const STREAK_DECAY_SECONDS = 24 * 60 * 60;
/** A recognized browser is forgotten after this many consecutive failures. */
export const BROWSER_REVOKE_FAILURES = 20;
/** Usernames and passwords longer than this are not checked. */
export const MAX_USERNAME_LENGTH = 255;
export const MAX_PASSWORD_LENGTH = 1024;
export const MIN_PASSWORD_LENGTH = 8;
export const MAX_CODE_LENGTH = 64;
/** A browser token as the API issues them (32 random bytes, base64url); anything else is ignored. */
export const BROWSER_TOKEN_SHAPE = /^[A-Za-z0-9_-]{20,128}$/;

/** The order a tie between paused keys is broken in: the most specific first. */
const SCOPE_ORDER: SignInScope[] = ['aip', 'ip', 'acct', 'br', 'mfa', 'pwc'];

export interface SignInSettings {
  /** LOGIN_PROTECTION: false only when it is off. */
  protection: boolean;
  scopes: Record<SignInScope, ScopePolicy>;
  /** AUTH_ALERTS: raise alerts for sign-in attacks (authAlerts.ts). */
  alerts: boolean;
  /** AUTH_FAILURE_AUDIT_RETENTION_DAYS: how long auth.login.failure audit rows are kept; 0 keeps them. */
  failureAuditRetentionDays: number;
}

function envSwitch(name: string): boolean {
  const raw = (process.env[name] ?? '').trim().toLowerCase();
  return !['off', 'false', '0', 'no', 'disabled'].includes(raw);
}

/** The settings in effect, read from the environment. */
export function readSignInSettings(): SignInSettings {
  return {
    protection: envSwitch('LOGIN_PROTECTION'),
    alerts: envSwitch('AUTH_ALERTS'),
    failureAuditRetentionDays: envInt('AUTH_FAILURE_AUDIT_RETENTION_DAYS', 90, 0),
    scopes: {
      aip: {
        scope: 'aip',
        threshold: envInt('LOGIN_MAX_FAILURES', 5, 1),
        capSeconds: 15 * 60,
        resetOnSuccess: true,
        reason: 'account_network',
        label: 'Account from one network',
      },
      ip: {
        scope: 'ip',
        threshold: envInt('LOGIN_MAX_FAILURES_PER_ADDRESS', 20, 1),
        capSeconds: 30 * 60,
        resetOnSuccess: false,
        reason: 'network',
        label: 'Network (any username)',
      },
      acct: {
        scope: 'acct',
        threshold: envInt('LOGIN_MAX_FAILURES_PER_ACCOUNT', 20, 0),
        capSeconds: 60 * 60,
        resetOnSuccess: false,
        reason: 'account',
        label: 'Account from new browsers (all networks)',
      },
      br: {
        scope: 'br',
        threshold: 10,
        capSeconds: 15 * 60,
        resetOnSuccess: true,
        reason: 'browser',
        label: 'Recognized browser',
      },
      mfa: {
        scope: 'mfa',
        threshold: 5,
        capSeconds: 60 * 60,
        resetOnSuccess: true,
        reason: 'mfa',
        label: 'MFA codes',
      },
      pwc: {
        scope: 'pwc',
        threshold: 5,
        capSeconds: 60 * 60,
        resetOnSuccess: true,
        reason: 'current_password',
        label: 'Current password (password change)',
      },
    },
  };
}

let current: SignInSettings | null = null;

/** The settings in effect (read once). */
export function signInSettings(): SignInSettings {
  current ??= readSignInSettings();
  return current;
}

/** Re-read the environment (tests). */
export function reloadSignInSettings(): SignInSettings {
  current = readSignInSettings();
  return current;
}

export function isScope(value: unknown): value is SignInScope {
  return typeof value === 'string' && (SCOPE_ORDER as string[]).includes(value);
}

/** The scope a key belongs to, from its prefix. */
export function scopeOfKey(key: string): SignInScope | null {
  const prefix = key.split(':', 1)[0];
  return isScope(prefix) ? prefix : null;
}

/**
 * How long a key pauses after its `failures`-th consecutive failure: nothing
 * below the threshold, 30 s at it, doubling with every further failure up to
 * the cap.
 */
export function pauseSeconds(policy: Pick<ScopePolicy, 'threshold' | 'capSeconds'>, failures: number): number {
  if (policy.threshold <= 0 || failures < policy.threshold) return 0;
  const doublings = failures - policy.threshold;
  if (doublings >= 20) return policy.capSeconds;
  return Math.min(policy.capSeconds, FIRST_PAUSE_SECONDS * 2 ** doublings);
}

/** True when a streak whose last failure was `secondsSinceLastFailure` ago has ended. */
export function streakEnded(secondsSinceLastFailure: number | null): boolean {
  return secondsSinceLastFailure !== null && secondsSinceLastFailure >= STREAK_DECAY_SECONDS;
}

/** Whole seconds to wait, rounded up, never less than 1 (the Retry-After header and `retryAfter`). */
export function retryAfterSeconds(remainingMs: number): number {
  if (!Number.isFinite(remainingMs) || remainingMs <= 0) return 1;
  return Math.max(1, Math.ceil(remainingMs / 1000));
}

/** Of several paused keys, the one to report: the longest wait, ties to the most specific scope. */
export function longestPause<T extends { scope: SignInScope; remainingMs: number }>(paused: T[]): T | null {
  let best: T | null = null;
  for (const entry of paused) {
    if (
      !best ||
      entry.remainingMs > best.remainingMs ||
      (entry.remainingMs === best.remainingMs && SCOPE_ORDER.indexOf(entry.scope) < SCOPE_ORDER.indexOf(best.scope))
    ) {
      best = entry;
    }
  }
  return best;
}

/** What an attempt that failed and started a pause got wrong. */
export type PauseCause = 'password' | 'code' | 'current_password';

const CAUSE_PREFIX: Record<PauseCause, string> = {
  password: 'Incorrect username or password.',
  code: 'Incorrect code.',
  current_password: 'Current password is incorrect.',
};

/** The message for a pause of `reason` with `seconds` left, prefixed with what was wrong when this attempt started it. */
export function pauseMessage(reason: PauseReason, seconds: number, cause?: PauseCause): string {
  const wait = formatWait(seconds);
  let message: string;
  switch (reason) {
    case 'account_network':
      message = `Too many failed sign-in attempts for this account from your network. Try again in ${wait}.`;
      break;
    case 'network':
      message = `Too many failed sign-in attempts from your network. Try again in ${wait}.`;
      break;
    case 'account':
      message =
        'Sign-in to this account from new browsers is paused after many failed attempts. ' +
        `Try again in ${wait}, or use a browser you have signed in with before.`;
      break;
    case 'browser':
      message = `Too many failed sign-in attempts from this browser. Try again in ${wait}.`;
      break;
    case 'mfa':
      message = `Too many incorrect codes. Try again in ${wait}.`;
      break;
    case 'current_password':
      message = `Too many incorrect current passwords. Try again in ${wait}.`;
      break;
  }
  return cause ? `${CAUSE_PREFIX[cause]} ${message}` : message;
}

/** The body of a SIGNIN_PAUSED 429 (the Retry-After header carries the same `retryAfter`). */
export function pausedBody(reason: PauseReason, retryAfter: number, opts: { cause?: PauseCause; mfaRequired?: boolean } = {}) {
  return {
    status: 'error' as const,
    statusCode: 429,
    code: 'SIGNIN_PAUSED' as const,
    reason,
    message: pauseMessage(reason, retryAfter, opts.cause),
    retryAfter,
    ...(opts.mfaRequired ? { mfaRequired: true } : {}),
  };
}

// --- Keys ------------------------------------------------------------------

/** sha256('siembox-signin\0' + username), hex: the username part of a key. */
export function usernameHash(username: string): string {
  return crypto.createHash('sha256').update(`siembox-signin\0${username}`).digest('hex');
}

/** The 16 hex characters audit rows and log lines carry for a username that doesn't exist. */
export function auditUsernameHash(username: string): string {
  return usernameHash(username).slice(0, 16);
}

/** The network part of a key; 'unknown' when the request has no address. */
export function networkColumn(network: string): string | null {
  return network === 'unknown' ? null : network;
}

export interface ThrottleKeySpec {
  key: string;
  scope: SignInScope;
  userId: number | null;
  /** For the INET column: an address or an IPv6 /64, or null. */
  network: string | null;
}

/**
 * The keys a password attempt from a browser that isn't recognized counts
 * against: the account from this network, the network, and the account from
 * every network (unless LOGIN_MAX_FAILURES_PER_ACCOUNT=0).
 */
export function passwordKeys(
  usernameKeyHash: string,
  network: string,
  userId: number | null,
  settings: SignInSettings = signInSettings()
): ThrottleKeySpec[] {
  const net = networkColumn(network);
  const keys: ThrottleKeySpec[] = [
    { key: `aip:${usernameKeyHash}:${network}`, scope: 'aip', userId, network: net },
    { key: `ip:${network}`, scope: 'ip', userId: null, network: net },
  ];
  if (settings.scopes.acct.threshold > 0) {
    keys.push({ key: `acct:${usernameKeyHash}`, scope: 'acct', userId, network: null });
  }
  return keys;
}

export function browserKey(browserId: string, userId: number): ThrottleKeySpec {
  return { key: `br:${browserId}`, scope: 'br', userId, network: null };
}

export function mfaKey(userId: number): ThrottleKeySpec {
  return { key: `mfa:${userId}`, scope: 'mfa', userId, network: null };
}

export function passwordChangeKey(userId: number): ThrottleKeySpec {
  return { key: `pwc:${userId}`, scope: 'pwc', userId, network: null };
}

// --- Input -----------------------------------------------------------------

export interface LoginInput {
  username: string;
  password: string;
  /** The MFA code, as sent (trimmed); undefined when none was. */
  code?: string;
  /** A browser token in the issued shape; a malformed one is dropped. */
  browserToken?: string;
}

/**
 * The fields of a sign-in request, or null when they aren't what the SPA
 * sends: username a string of 1 to 255 characters, password 1 to 1024, code
 * (optional) a string or number of at most 64 characters, browserToken
 * (optional, dropped unless it has the issued shape). No database involved.
 */
export function parseLoginBody(body: unknown): LoginInput | null {
  if (!body || typeof body !== 'object') return null;
  const { username, password, code, browserToken } = body as Record<string, unknown>;
  if (typeof username !== 'string' || username.length < 1 || username.length > MAX_USERNAME_LENGTH) return null;
  if (typeof password !== 'string' || password.length < 1 || password.length > MAX_PASSWORD_LENGTH) return null;
  const parsedCode = parseCode(code);
  if (parsedCode === null) return null;
  const input: LoginInput = { username, password };
  if (parsedCode) input.code = parsedCode;
  if (typeof browserToken === 'string' && BROWSER_TOKEN_SHAPE.test(browserToken)) input.browserToken = browserToken;
  return input;
}

/**
 * An MFA code field: '' when absent or blank, the trimmed text otherwise, or
 * null when it is not a string or finite number, or is longer than 64
 * characters.
 */
export function parseCode(code: unknown): string | null {
  if (code === undefined || code === null) return '';
  if (typeof code === 'number') {
    if (!Number.isFinite(code)) return null;
    code = String(code);
  }
  if (typeof code !== 'string' || code.length > MAX_CODE_LENGTH) return null;
  return code.trim();
}
