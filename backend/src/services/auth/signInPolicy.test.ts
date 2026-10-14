/**
 * The sign-in protection policy (signInPolicy.ts): the pause schedule of every
 * scope, the 24-hour streak decay, which keys an attempt counts against,
 * messages and Retry-After rounding, the settings read from the environment
 * (LOGIN_MAX_FAILURES_PER_ACCOUNT=0 turns the account scope off,
 * LOGIN_PROTECTION=off turns counting off), and request validation.
 * Pure: no database. Run with `npm test` (tsx --test).
 */
import { test, afterEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import {
  BROWSER_TOKEN_SHAPE,
  STREAK_DECAY_SECONDS,
  auditUsernameHash,
  longestPause,
  parseCode,
  parseLoginBody,
  passwordKeys,
  pauseMessage,
  pauseSeconds,
  pausedBody,
  readSignInSettings,
  reloadSignInSettings,
  retryAfterSeconds,
  scopeOfKey,
  streakEnded,
  usernameHash,
} from './signInPolicy';

const ENV = [
  'LOGIN_PROTECTION',
  'LOGIN_MAX_FAILURES',
  'LOGIN_MAX_FAILURES_PER_ADDRESS',
  'LOGIN_MAX_FAILURES_PER_ACCOUNT',
  'AUTH_ALERTS',
  'AUTH_FAILURE_AUDIT_RETENTION_DAYS',
];
const saved = Object.fromEntries(ENV.map((name) => [name, process.env[name]]));

afterEach(() => {
  for (const name of ENV) {
    if (saved[name] === undefined) delete process.env[name];
    else process.env[name] = saved[name];
  }
  reloadSignInSettings();
});

function clearEnv() {
  for (const name of ENV) delete process.env[name];
}

/** The pause after each failure 1..n. */
function schedule(scope: keyof ReturnType<typeof readSignInSettings>['scopes'], n: number): number[] {
  const policy = readSignInSettings().scopes[scope];
  return Array.from({ length: n }, (_, i) => pauseSeconds(policy, i + 1));
}

test('defaults: thresholds, caps and what a success does, per scope', () => {
  clearEnv();
  const { scopes, protection, alerts, failureAuditRetentionDays } = readSignInSettings();
  assert.equal(protection, true);
  assert.equal(alerts, true);
  assert.equal(failureAuditRetentionDays, 90);
  const summary = Object.fromEntries(
    Object.values(scopes).map((s) => [s.scope, [s.threshold, s.capSeconds / 60, s.resetOnSuccess, s.reason]])
  );
  assert.deepEqual(summary, {
    aip: [5, 15, true, 'account_network'],
    ip: [20, 30, false, 'network'],
    acct: [20, 60, false, 'account'],
    br: [10, 15, true, 'browser'],
    mfa: [5, 60, true, 'mfa'],
    pwc: [5, 60, true, 'current_password'],
  });
});

test('the T-th failure pauses for 30 s, each further one doubles it, up to the cap', () => {
  clearEnv();
  const min = 60;
  assert.deepEqual(schedule('aip', 11), [0, 0, 0, 0, 30, 60, 120, 4 * min, 8 * min, 15 * min, 15 * min]);
  assert.deepEqual(schedule('ip', 27).slice(18), [0, 30, 60, 120, 4 * min, 8 * min, 16 * min, 30 * min, 30 * min]);
  assert.deepEqual(schedule('acct', 28).slice(18), [0, 30, 60, 120, 4 * min, 8 * min, 16 * min, 32 * min, 60 * min, 60 * min]);
  assert.deepEqual(schedule('br', 15).slice(8), [0, 30, 60, 120, 4 * min, 8 * min, 15 * min]);
  assert.deepEqual(schedule('mfa', 12).slice(3), [0, 30, 60, 120, 4 * min, 8 * min, 16 * min, 32 * min, 60 * min]);
  assert.deepEqual(schedule('pwc', 6).slice(3), [0, 30, 60]);
  // No overflow however long a streak gets.
  assert.equal(pauseSeconds(readSignInSettings().scopes.aip, 10_000), 15 * min);
});

test('LOGIN_MAX_FAILURES* set the thresholds; LOGIN_MAX_FAILURES_PER_ACCOUNT=0 turns the account scope off', () => {
  clearEnv();
  process.env.LOGIN_MAX_FAILURES = '3';
  process.env.LOGIN_MAX_FAILURES_PER_ADDRESS = '50';
  process.env.LOGIN_MAX_FAILURES_PER_ACCOUNT = '0';
  const settings = readSignInSettings();
  assert.equal(settings.scopes.aip.threshold, 3);
  assert.equal(settings.scopes.ip.threshold, 50);
  assert.equal(settings.scopes.acct.threshold, 0);
  assert.equal(pauseSeconds(settings.scopes.acct, 1_000), 0, 'an account scope that is off never pauses');
  const hash = usernameHash('alice');
  assert.deepEqual(
    passwordKeys(hash, '192.0.2.7', 4, settings).map((k) => k.scope),
    ['aip', 'ip'],
    'and is not even counted'
  );
  // Junk and values below the minimum fall back to the defaults.
  process.env.LOGIN_MAX_FAILURES = '0';
  process.env.LOGIN_MAX_FAILURES_PER_ACCOUNT = 'lots';
  const fallback = readSignInSettings();
  assert.equal(fallback.scopes.aip.threshold, 5);
  assert.equal(fallback.scopes.acct.threshold, 20);
});

test('LOGIN_PROTECTION=off, AUTH_ALERTS=off and the audit retention are read from the environment', () => {
  clearEnv();
  for (const off of ['off', 'OFF', 'false', '0', 'no']) {
    process.env.LOGIN_PROTECTION = off;
    assert.equal(readSignInSettings().protection, false, off);
  }
  process.env.LOGIN_PROTECTION = 'on';
  assert.equal(readSignInSettings().protection, true);
  process.env.AUTH_ALERTS = 'off';
  assert.equal(readSignInSettings().alerts, false);
  process.env.AUTH_FAILURE_AUDIT_RETENTION_DAYS = '0';
  assert.equal(readSignInSettings().failureAuditRetentionDays, 0, '0 keeps them');
});

test('with LOGIN_PROTECTION=off, reserve() counts nothing and needs no database', async () => {
  clearEnv();
  process.env.LOGIN_PROTECTION = 'off';
  reloadSignInSettings();
  // The pool is not touched when protection is off.
  const db = await import('../../config/database');
  const noSql = async () => {
    throw new Error('no SQL with LOGIN_PROTECTION=off');
  };
  const poolQuery = mock.method(db.default, 'query', noSql);
  const poolConnect = mock.method(db.default, 'connect', noSql);
  try {
    const { LoginThrottleModel } = await import('../../models/LoginThrottle');
    const reservation = await LoginThrottleModel.reserve(passwordKeys(usernameHash('x'), '192.0.2.1', null));
    assert.deepEqual(reservation, { outcome: 'skipped', reason: 'protection-off' });
    assert.deepEqual(await LoginThrottleModel.reset(['aip:x']), []);
    assert.equal(await LoginThrottleModel.remainingPauseMs('aip:x'), 0);
    assert.equal(poolQuery.mock.callCount() + poolConnect.mock.callCount(), 0);
  } finally {
    poolQuery.mock.restore();
    poolConnect.mock.restore();
    await db.closePools();
  }
});

test('a streak ends 24 hours after its last failure', () => {
  assert.equal(streakEnded(null), false, 'a key that never failed');
  assert.equal(streakEnded(STREAK_DECAY_SECONDS - 1), false);
  assert.equal(streakEnded(STREAK_DECAY_SECONDS), true);
});

test('keys: the username is only ever hashed, and unknown usernames look the same', () => {
  clearEnv();
  const hash = usernameHash('admin');
  assert.match(hash, /^[0-9a-f]{64}$/);
  assert.notEqual(hash, usernameHash('Admin'), 'exact, case-sensitive, like the users lookup');
  assert.equal(auditUsernameHash('admin'), hash.slice(0, 16));
  const keys = passwordKeys(hash, '2001:db8:1:2::/64', null);
  assert.deepEqual(keys, [
    { key: `aip:${hash}:2001:db8:1:2::/64`, scope: 'aip', userId: null, network: '2001:db8:1:2::/64' },
    { key: 'ip:2001:db8:1:2::/64', scope: 'ip', userId: null, network: '2001:db8:1:2::/64' },
    { key: `acct:${hash}`, scope: 'acct', userId: null, network: null },
  ]);
  for (const { key } of keys) assert.ok(!key.includes('admin'));
  // A request without an address.
  assert.deepEqual(
    passwordKeys(hash, 'unknown', 7).map((k) => [k.key.replace(hash, 'H'), k.network, k.userId]),
    [
      ['aip:H:unknown', null, 7],
      ['ip:unknown', null, null],
      ['acct:H', null, 7],
    ]
  );
  assert.equal(scopeOfKey(`aip:${hash}:192.0.2.1`), 'aip');
  assert.equal(scopeOfKey('br:12'), 'br');
  assert.equal(scopeOfKey('nope:1'), null);
});

test('messages per reason, the prefix of the failure that starts a pause, and retryAfter rounding', () => {
  assert.equal(
    pauseMessage('account_network', 120),
    'Too many failed sign-in attempts for this account from your network. Try again in 2 minutes.'
  );
  assert.equal(pauseMessage('network', 30), 'Too many failed sign-in attempts from your network. Try again in 30 seconds.');
  assert.equal(
    pauseMessage('account', 3600),
    'Sign-in to this account from new browsers is paused after many failed attempts. Try again in 60 minutes, or use a browser you have signed in with before.'
  );
  assert.equal(pauseMessage('browser', 61), 'Too many failed sign-in attempts from this browser. Try again in 2 minutes.');
  assert.equal(pauseMessage('mfa', 1), 'Too many incorrect codes. Try again in 1 second.');
  assert.equal(
    pauseMessage('account_network', 30, 'password'),
    'Incorrect username or password. Too many failed sign-in attempts for this account from your network. Try again in 30 seconds.'
  );
  assert.equal(pauseMessage('mfa', 30, 'code'), 'Incorrect code. Too many incorrect codes. Try again in 30 seconds.');
  assert.equal(retryAfterSeconds(29_001), 30, 'rounded up');
  assert.equal(retryAfterSeconds(30_000), 30);
  assert.equal(retryAfterSeconds(1), 1);
  assert.equal(retryAfterSeconds(0), 1, 'never 0');
  assert.deepEqual(pausedBody('mfa', 30, { mfaRequired: true }), {
    status: 'error',
    statusCode: 429,
    code: 'SIGNIN_PAUSED',
    reason: 'mfa',
    message: 'Too many incorrect codes. Try again in 30 seconds.',
    retryAfter: 30,
    mfaRequired: true,
  });
  assert.equal('mfaRequired' in pausedBody('network', 30), false);
});

test('of several paused keys, the longest wait is reported (ties: the most specific scope)', () => {
  assert.equal(longestPause([]), null);
  assert.equal(
    longestPause([
      { scope: 'ip' as const, remainingMs: 1000 },
      { scope: 'acct' as const, remainingMs: 5000 },
      { scope: 'aip' as const, remainingMs: 2000 },
    ])?.scope,
    'acct'
  );
  assert.equal(
    longestPause([
      { scope: 'acct' as const, remainingMs: 30_000 },
      { scope: 'aip' as const, remainingMs: 30_000 },
    ])?.scope,
    'aip'
  );
});

test('parseLoginBody: strings of the right length only; code and browserToken optional', () => {
  assert.deepEqual(parseLoginBody({ username: 'a', password: 'b' }), { username: 'a', password: 'b' });
  assert.deepEqual(parseLoginBody({ username: 'a', password: 'b', code: ' 123 456 ' }), {
    username: 'a',
    password: 'b',
    code: '123 456',
  });
  assert.deepEqual(parseLoginBody({ username: 'a', password: 'b', code: 123456 }), {
    username: 'a',
    password: 'b',
    code: '123456',
  });
  const token = 'A'.repeat(43);
  assert.equal(parseLoginBody({ username: 'a', password: 'b', browserToken: token })?.browserToken, token);
  assert.equal(parseLoginBody({ username: 'a', password: 'b', browserToken: 'short' })?.browserToken, undefined, 'malformed: ignored');
  assert.equal(parseLoginBody({ username: 'a', password: 'b', browserToken: 'x'.repeat(30) + '!' })?.browserToken, undefined);
  for (const bad of [
    undefined,
    null,
    'text',
    {},
    { username: 'a' },
    { username: '', password: 'b' },
    { username: 'a', password: '' },
    { username: 'a', password: 123 },
    { username: 'a', password: true },
    { username: ['a'], password: 'b' },
    { username: 'a'.repeat(256), password: 'b' },
    { username: 'a', password: 'b'.repeat(1025) },
    { username: 'a', password: 'b', code: true },
    { username: 'a', password: 'b', code: 'c'.repeat(65) },
    { username: 'a', password: 'b', code: { x: 1 } },
  ]) {
    assert.equal(parseLoginBody(bad), null, JSON.stringify(bad));
  }
  assert.equal(parseCode(undefined), '');
  assert.equal(parseCode('  '), '');
  assert.equal(parseCode(Number.NaN), null);
  assert.ok(BROWSER_TOKEN_SHAPE.test('abcDEF012_-'.repeat(4)));
});

test('sign-in fails open only for a broken throttle statement, never for an unreachable or exhausted database', async () => {
  const { throttleIsBroken } = await import('../../models/LoginThrottle');
  // Missing table or column, privileges, bad data, constraints, failed transactions, internal errors.
  for (const code of ['42P01', '42703', '42501', '22P02', '23505', '25P02', '40001', 'XX000', '0A000']) {
    assert.equal(throttleIsBroken({ code }), true, code);
  }
  // A pool timeout or a refused connection has no SQLSTATE; too many connections, shutdown and lost connections do.
  for (const error of [
    new Error('timeout exceeded when trying to connect'),
    { code: 'ECONNREFUSED' },
    { code: '53300' },
    { code: '57P01' },
    { code: '08006' },
    null,
  ]) {
    assert.equal(throttleIsBroken(error), false, JSON.stringify(error));
  }
});
