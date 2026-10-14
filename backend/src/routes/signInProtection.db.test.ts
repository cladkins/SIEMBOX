/**
 * Sign-in protection against a real Postgres, through the real app on TCP and
 * on the proxy socket (as the bundled nginx reaches it, with X-Forwarded-For):
 *
 * - no enumeration oracle: an unknown user, a wrong password and a disabled
 *   account with a wrong password get the identical 401 after exactly one
 *   bcrypt compare each;
 * - the account+network pause (401 x4, then 429 with Retry-After 30), checked
 *   before bcrypt, and reset by a success; 50 parallel attempts make exactly 5
 *   bcrypt calls (the reservation is atomic);
 * - spoofed X-Forwarded-For on TCP is ignored: 20 usernames pause the network
 *   127.0.0.1, and no row for the spoofed addresses appears;
 * - a paused network still checks usernames that haven't failed from it (one
 *   guess each per streak; a password change clears the user's own), and a
 *   right password that would have been its 20th failure leaves it unpaused;
 * - the counters themselves: a refund racing a wrong attempt keeps that
 *   streak's start, a right password after a streak ended refunds to an empty
 *   one, a streak 24 h old starts over even with a pause recorded; tokens
 *   unused for 90 days aren't recognized, and a user keeps at most 20;
 * - the account pause from 20 networks, which a recognized browser walks past
 *   (a token for another user doesn't), and a browser forgotten after 20
 *   failures; tokens are stored only as sha256;
 * - MFA: 5 wrong codes pause it (mfaRequired kept), a recognized browser isn't
 *   affected, a replayed TOTP is refused, one recovery code used twice at once
 *   signs in once, a code check that throws isn't counted, the right code isn't
 *   counted in "signed in after N failed attempts", /me/mfa/disable answers 400
 *   then 429, never 401, and /me/mfa/enable is refused (409) once MFA is on;
 * - the password change (400, never 401; paused after 5; a right current
 *   password is never counted, even when saving fails; success revokes
 *   sessions, browsers and counters; the Users page lists its pause apart from
 *   sign-in pauses) and an admin's password reset;
 * - the admin API (viewers get 403; clear by user, network and all; unlock),
 *   audit rows (addresses, unknown usernames as a hash, one row per pause, none
 *   per refusal), alerts (one per streak, one notification), housekeeping, the
 *   recovery CLI (an IPv6 /64 as status prints it, and 'unknown'), failing open
 *   when the throttle can't be reached,
 *   LOGIN_PROTECTION=off, and 5xx answers that are never counted.
 *
 * Skips itself when Postgres (with migration 038) isn't reachable. The users
 * it creates (sip-<tag>-...), their rows, and the counters, audit rows and
 * alerts for its test networks are removed again.
 * Run with `npm test` (tsx --test).
 */
import { test, before, after, beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';
import bcrypt from 'bcrypt';

process.env.CREDENTIAL_ENCRYPTION_KEY ||= crypto.randomBytes(32).toString('hex');

const SKIP = 'Postgres with migration 038 (login_throttle) is not reachable';
const tag = crypto.randomBytes(5).toString('hex');
const PASSWORD = `pw-${crypto.randomBytes(9).toString('hex')}`;
const TEST_NETS = ['192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '2001:db8::/32'];
const startedAt = new Date();

type Mod<T> = T extends Promise<infer U> ? U : never;
let pool: Mod<ReturnType<typeof importDb>>['default'];
let closePools: () => Promise<void>;
let UserModel: Mod<ReturnType<typeof importModels>>['UserModel'];
let SessionModel: Mod<ReturnType<typeof importModels>>['SessionModel'];
let NotificationService: typeof import('../services/notifications/notificationService').NotificationService;
let totp: typeof import('../services/auth/totp');
let policy: typeof import('../services/auth/signInPolicy');
let authAlerts: typeof import('../services/auth/authAlerts');
let authEvents: typeof import('../services/auth/authEvents');
let CredentialEncryption: typeof import('../services/credentials/credentialEncryption').CredentialEncryption;

const importDb = () => import('../config/database');
const importModels = async () => ({
  UserModel: (await import('../models/User')).UserModel,
  SessionModel: (await import('../models/Session')).SessionModel,
});

let dbReady = false;
let tcp: http.Server | undefined;
let socketServer: http.Server | null = null;
let tcpPort = 0;
let socketPath = '';
let socketDir = '';
const userIds: number[] = [];
const usernames: string[] = [];
/** Titles of the alerts notifyAlert was called for. */
const notified: string[] = [];
const restoreAfter: Array<() => void> = [];

/** Hashes of the probe usernames that don't exist, for cleanup. */
const probeHashes: string[] = [];
function probe(name: string): string {
  const username = `sip-${tag}-nobody-${name}`;
  probeHashes.push(crypto.createHash('sha256').update(`siembox-signin\0${username}`).digest('hex').slice(0, 16));
  usernames.push(username);
  return username;
}

/** A parsed JSON answer, read field by field in the assertions. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- assertions read whatever the API sent
type Json = Record<string, any>;

interface Answer {
  status: number;
  body: Json;
  headers: http.IncomingHttpHeaders;
}

/** One request to the app: over TCP (a direct caller) or the proxy socket (nginx, which sets X-Forwarded-For). */
function call(
  method: string,
  urlPath: string,
  opts: { body?: unknown; via?: 'tcp' | 'socket'; xff?: string; token?: string; headers?: Record<string, string> } = {}
): Promise<Answer> {
  const payload = opts.body === undefined ? undefined : JSON.stringify(opts.body);
  const headers: Record<string, string> = { ...(opts.headers ?? {}) };
  if (payload !== undefined) headers['Content-Type'] = 'application/json';
  if (opts.xff) headers['X-Forwarded-For'] = opts.xff;
  if (opts.token) headers.Authorization = `Bearer ${opts.token}`;
  const target = opts.via === 'socket' ? { socketPath } : { host: '127.0.0.1', port: tcpPort };
  return new Promise((resolve, reject) => {
    const req = http.request({ ...target, method, path: urlPath, headers, agent: false }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let body: Json;
        try {
          body = JSON.parse(text);
        } catch {
          body = { text };
        }
        resolve({ status: res.statusCode ?? 0, body, headers: res.headers });
      });
    });
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

const login = (body: Record<string, unknown>, opts: { via?: 'tcp' | 'socket'; xff?: string } = {}) =>
  call('POST', '/api/auth/login', { body, via: opts.via ?? 'socket', xff: opts.xff });

async function createUser(suffix: string, role: 'admin' | 'viewer' = 'viewer', extra: { enabled?: boolean } = {}) {
  const username = `sip-${tag}-${suffix}`;
  const user = await UserModel.create({ username, email: `${username}@siembox.invalid`, password: PASSWORD, role, enabled: extra.enabled ?? true });
  userIds.push(user.id);
  usernames.push(username);
  return user;
}

async function enrollMfa(userId: number): Promise<{ secret: string; recovery: string[] }> {
  const secret = totp.generateSecret();
  const recovery = ['aaaaa-bbbbb', 'ccccc-ddddd', 'eeeee-fffff'];
  const hashes = await Promise.all(recovery.map((code) => bcrypt.hash(code.replace(/-/g, ''), 4)));
  await pool.query(
    `UPDATE users SET mfa_enabled = TRUE, mfa_secret = $2, mfa_recovery_codes = $3, mfa_last_totp_step = NULL WHERE id = $1`,
    [userId, JSON.stringify(CredentialEncryption.encrypt(secret)), JSON.stringify(hashes)]
  );
  return { secret, recovery };
}

/** A 6-digit code valid for no step in the window. */
function wrongCode(secret: string): string {
  const now = Date.now();
  const valid = new Set([-1, 0, 1].map((offset) => totp.totp(secret, { now: now + offset * 30_000 })));
  for (let n = 0; ; n++) {
    const code = String(n).padStart(6, '0');
    if (!valid.has(code)) return code;
  }
}

/** Counts bcrypt.compare calls until the returned stop() is called. */
function countCompares(): { count: () => number; stop: () => void } {
  const original = bcrypt.compare;
  const spy = mock.method(bcrypt, 'compare', (...args: unknown[]) => (original as (...a: unknown[]) => unknown).apply(bcrypt, args));
  return { count: () => spy.mock.callCount(), stop: () => spy.mock.restore() };
}

async function row(key: string) {
  const res = await pool.query(
    `SELECT key, scope, user_id, abbrev(network) AS network, failures, pauses, COALESCE(paused_until > NOW(), FALSE) AS paused
       FROM login_throttle WHERE key = $1`,
    [key]
  );
  return res.rows[0] ?? null;
}

async function unpause(key: string) {
  await pool.query(`UPDATE login_throttle SET paused_until = NOW() - INTERVAL '1 second' WHERE key = $1`, [key]);
}

const aipKey = (username: string, network: string) => `aip:${policy.usernameHash(username)}:${network}`;
const acctKey = (username: string) => `acct:${policy.usernameHash(username)}`;

async function auditRows(where: string, params: unknown[]) {
  const res = await pool.query(
    `SELECT action, user_id, host(ip_address) AS ip, response_status, details FROM audit_logs
      WHERE timestamp >= $1 AND (${where}) ORDER BY id`,
    [startedAt, ...params]
  );
  return res.rows;
}

/** Wait for a fire-and-forget write to land. */
async function eventually<T>(read: () => Promise<T>, done: (value: T) => boolean, ms = 3000): Promise<T> {
  const deadline = Date.now() + ms;
  for (;;) {
    const value = await read();
    if (done(value) || Date.now() > deadline) return value;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

async function clearOurCounters() {
  await pool.query(
    `DELETE FROM login_throttle
      WHERE user_id = ANY($1) OR key = 'ip:127.0.0.1'
         OR network <<= ANY($2::inet[]) OR key = ANY($3) OR key LIKE ANY($4)`,
    [
      userIds,
      TEST_NETS,
      usernames.map((name) => acctKey(name)),
      usernames.map((name) => `aip:${policy.usernameHash(name)}:%`),
    ]
  );
}

before(async () => {
  const db = await importDb();
  pool = db.default;
  closePools = db.closePools;
  try {
    await pool.query('SELECT 1 FROM login_throttle LIMIT 1');
    await pool.query('SELECT 1 FROM recognized_browsers LIMIT 1');
    await pool.query('SELECT mfa_last_totp_step FROM users LIMIT 1');
    dbReady = true;
  } catch {
    return;
  }
  ({ UserModel, SessionModel } = await importModels());
  NotificationService = (await import('../services/notifications/notificationService')).NotificationService;
  totp = await import('../services/auth/totp');
  policy = await import('../services/auth/signInPolicy');
  authAlerts = await import('../services/auth/authAlerts');
  authEvents = await import('../services/auth/authEvents');
  CredentialEncryption = (await import('../services/credentials/credentialEncryption')).CredentialEncryption;
  policy.reloadSignInSettings();

  // Quiet: every failed sign-in logs a warning.
  const { logger } = await import('../utils/logger');
  for (const transport of logger.transports) {
    const was = transport.silent;
    transport.silent = true;
    restoreAfter.push(() => (transport.silent = was));
  }
  const notify = mock.method(NotificationService, 'notifyAlert', async (alert: { title: string }) => {
    notified.push(alert.title);
  });
  restoreAfter.push(() => notify.mock.restore());

  const app = (await import('../app')).default;
  const { createApiServer, listenProxySocket } = await import('../net/apiListeners');
  tcp = createApiServer(app);
  tcp.listen(0, '127.0.0.1');
  await once(tcp, 'listening');
  tcpPort = (tcp.address() as AddressInfo).port;
  socketDir = fs.mkdtempSync(path.join(os.tmpdir(), 'siembox-signin-'));
  socketPath = path.join(socketDir, 'api.sock');
  const quiet = { info: () => undefined, warn: () => undefined, error: () => undefined } as never;
  socketServer = (await listenProxySocket(app, socketPath, quiet)).server;
  assert.ok(socketServer, 'the proxy socket listens');
});

beforeEach(async () => {
  if (!dbReady) return;
  await clearOurCounters();
  authAlerts.resetAuthAlertState();
});

after(async () => {
  for (const restore of restoreAfter) restore();
  for (const server of [tcp, socketServer]) {
    if (!server) continue;
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
  if (socketDir) fs.rmSync(socketDir, { recursive: true, force: true });
  if (dbReady) {
    await clearOurCounters();
    await pool.query(
      `DELETE FROM audit_logs WHERE timestamp >= $1 AND (
         user_id = ANY($2) OR resource_id = ANY($2) OR ip_address <<= ANY($3::inet[])
         OR details->>'usernameHash' = ANY($4) OR (ip_address = '127.0.0.1' AND action LIKE 'auth.%')
         OR (details->>'by' = 'cli' AND action IN ('auth.unlock', 'user.password_reset', 'auth.mfa.disabled')))`,
      [startedAt, userIds, TEST_NETS, usernames.map((name) => policy.auditUsernameHash(name)).concat(probeHashes)]
    );
    await pool.query(`DELETE FROM alerts WHERE source = 'siembox-auth' AND created_at >= $1`, [startedAt]);
    // Sessions and recognized browsers go with the users (ON DELETE CASCADE).
    await pool.query(
      `DELETE FROM users WHERE id = ANY($1)
          OR (username ~ '^sip-[0-9a-f]{10}-' AND email LIKE '%@siembox.invalid' AND created_at < NOW() - INTERVAL '10 minutes')`,
      [userIds]
    );
  }
  authEvents?.stopRefusalSummary();
  await closePools?.();
});

// --- Enumeration --------------------------------------------------------------

test('an unknown user, a wrong password and a disabled account get the same 401 after one bcrypt each', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const active = await createUser('enum');
  const disabled = await createUser('enum-off', 'viewer', { enabled: false });
  const unknown = probe('enum');
  const answers: Answer[] = [];
  for (const [i, body] of [
    { username: unknown, password: PASSWORD },
    { username: active.username, password: 'wrong password' },
    { username: disabled.username, password: 'wrong password' },
  ].entries()) {
    const compares = countCompares();
    answers.push(await login(body, { xff: `192.0.2.${10 + i}` }));
    assert.equal(compares.count(), 1, `${body.username}: one bcrypt compare`);
    compares.stop();
  }
  for (const answer of answers) {
    assert.equal(answer.status, 401);
    assert.deepEqual(answer.body, { status: 'error', statusCode: 401, message: 'Invalid username or password' });
    assert.equal(answer.headers['cache-control'], 'no-store');
  }
  // Only the right password reveals that the account is disabled.
  const right = await login({ username: disabled.username, password: PASSWORD }, { xff: '192.0.2.13' });
  assert.equal(right.status, 403);
  assert.equal(right.body.message, 'Account is disabled');

  // The unknown username is audited as a hash, with no user.
  const rows = await auditRows(`action = 'auth.login.failure' AND details->>'usernameHash' = $2`, [policy.auditUsernameHash(unknown)]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].user_id, null);
  assert.equal(rows[0].details.reason, 'unknown_user');
  assert.equal(rows[0].ip, '192.0.2.10', 'the rightmost X-Forwarded-For entry over the socket');
  assert.ok(!JSON.stringify(rows[0]).includes(unknown), 'the typed username is never stored');
});

// --- Account + network --------------------------------------------------------

test('account+network: 401 four times, then 429 (Retry-After 30); paused attempts skip bcrypt; a success resets it', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const user = await createUser('aip');
  const xff = '192.0.2.20';
  for (let i = 1; i <= 4; i++) {
    assert.equal((await login({ username: user.username, password: 'nope' }, { xff })).status, 401, `failure ${i}`);
  }
  const fifth = await login({ username: user.username, password: 'nope' }, { xff });
  assert.equal(fifth.status, 429);
  assert.equal(fifth.headers['retry-after'], '30');
  assert.equal(fifth.body.code, 'SIGNIN_PAUSED');
  assert.equal(fifth.body.reason, 'account_network');
  assert.equal(fifth.body.retryAfter, 30);
  assert.match(fifth.body.message, /^Incorrect username or password\. Too many failed sign-in attempts for this account from your network\. Try again in 30 seconds\.$/);

  // While paused, even the right password is refused, without a bcrypt call or an audit row.
  const auditBefore = (await auditRows('user_id = $2', [user.id])).length;
  const compares = countCompares();
  const refused = await login({ username: user.username, password: PASSWORD }, { xff });
  assert.equal(compares.count(), 0, 'no bcrypt while paused');
  compares.stop();
  assert.equal(refused.status, 429);
  assert.equal(refused.body.message, 'Too many failed sign-in attempts for this account from your network. Try again in 30 seconds.');
  assert.ok(Number(refused.headers['retry-after']) >= 1 && Number(refused.headers['retry-after']) <= 30);
  assert.equal((await auditRows('user_id = $2', [user.id])).length, auditBefore, 'no audit row per refusal');
  assert.ok(authEvents.refusalsForKey(aipKey(user.username, '192.0.2.20')) >= 1, 'counted in memory instead');

  // Another network is not paused for this account.
  assert.equal((await login({ username: user.username, password: PASSWORD }, { xff: '192.0.2.21' })).status, 200);

  // Once the pause is over, the right password signs in and resets the key.
  await unpause(aipKey(user.username, '192.0.2.20'));
  const ok = await login({ username: user.username, password: PASSWORD }, { xff });
  assert.equal(ok.status, 200);
  assert.match(ok.body.token, /^[0-9a-f]{64}$/);
  assert.match(ok.body.browserToken, /^[A-Za-z0-9_-]{43}$/);
  const reset = await row(aipKey(user.username, '192.0.2.20'));
  assert.equal(reset.failures, 0);
  assert.equal(reset.paused, false);
  // The network and account keys keep their failures (refund only).
  assert.equal((await row('ip:192.0.2.20')).failures, 5);
  assert.equal((await row(acctKey(user.username))).failures, 5);

  // One auth.login.paused row for the one pause.
  const paused = await auditRows(`action = 'auth.login.paused' AND user_id = $2`, [user.id]);
  assert.equal(paused.length, 1);
  assert.equal(paused[0].details.scope, 'aip');
  assert.equal(paused[0].details.seconds, 30);
});

test('50 parallel wrong passwords for one account make exactly 5 bcrypt calls', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const user = await createUser('burst');
  const compares = countCompares();
  const answers = await Promise.all(
    Array.from({ length: 50 }, () => login({ username: user.username, password: 'nope' }, { xff: '192.0.2.30' }))
  );
  compares.stop();
  assert.equal(compares.count(), 5);
  const statuses = answers.map((a) => a.status).sort();
  assert.equal(statuses.filter((s) => s === 401).length, 4);
  assert.equal(statuses.filter((s) => s === 429).length, 46);
  const key = await row(aipKey(user.username, '192.0.2.30'));
  assert.equal(key.failures, 5);
  assert.equal(key.pauses, 1);
});

test('a 5xx is never counted: a check that throws is refunded', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const user = await createUser('5xx');
  assert.equal((await login({ username: user.username, password: 'nope' }, { xff: '192.0.2.40' })).status, 401);
  const { ErrorLogService } = await import('../services/errors/errorLogService');
  const logError = mock.method(ErrorLogService, 'logError', async () => null);
  const failing = mock.method(bcrypt, 'compare', async () => {
    throw new Error('thread pool on fire');
  });
  try {
    for (let i = 0; i < 6; i++) {
      assert.equal((await login({ username: user.username, password: 'nope' }, { xff: '192.0.2.40' })).status, 500);
    }
  } finally {
    failing.mock.restore();
    logError.mock.restore();
  }
  assert.equal((await row(aipKey(user.username, '192.0.2.40'))).failures, 1, 'only the checked failure counts');
  assert.equal((await login({ username: user.username, password: PASSWORD }, { xff: '192.0.2.40' })).status, 200);
});

// --- Spoofing -----------------------------------------------------------------

test('spoofed X-Forwarded-For on TCP is ignored: 20 usernames pause 127.0.0.1, from the 20th', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const statuses: number[] = [];
  let twentieth: Answer | undefined;
  for (let i = 1; i <= 25; i++) {
    const answer = await login({ username: probe(`spoof-${i}`), password: 'guess' }, { via: 'tcp', xff: `198.51.100.${i}` });
    statuses.push(answer.status);
    if (i === 20) twentieth = answer;
  }
  assert.deepEqual(statuses, [...Array(19).fill(401), ...Array(6).fill(429)]);
  assert.equal(twentieth!.body.reason, 'network');
  assert.match(twentieth!.body.message, /^Incorrect username or password\. Too many failed sign-in attempts from your network\./);
  const network = await row('ip:127.0.0.1');
  // The 21st to 25th were new usernames from this network: one checked guess each (refusingPauses).
  assert.equal(network.failures, 25);
  assert.equal(network.paused, true);
  const compares = countCompares();
  const repeat = await login({ username: `sip-${tag}-nobody-spoof-1`, password: 'guess' }, { via: 'tcp', xff: '198.51.100.200' });
  assert.equal(compares.count(), 0, 'a username that already failed from it is refused before bcrypt');
  compares.stop();
  assert.equal(repeat.status, 429);
  assert.equal(repeat.body.reason, 'network');
  const spoofed = await pool.query(`SELECT COUNT(*)::int AS n FROM login_throttle WHERE network <<= '198.51.100.0/24'`);
  assert.equal(spoofed.rows[0].n, 0, 'no row for a spoofed address');
  const audited = await auditRows(`action = 'auth.login.failure' AND details->>'usernameHash' = ANY($2)`, [probeHashes]);
  assert.ok(audited.length >= 20);
  for (const entry of audited.filter((r) => r.details.via === 'direct')) assert.equal(entry.ip, '127.0.0.1');

  // The network pause raises one medium alert for the streak.
  const alerts = await eventually(
    () => pool.query(`SELECT severity, event_id FROM alerts WHERE source = 'siembox-auth' AND created_at >= $1 AND event_id LIKE 'siembox-auth:network-pause:%'`, [startedAt]),
    (res) => res.rows.length > 0
  );
  assert.equal(alerts.rows.length, 1);
  assert.equal(alerts.rows[0].severity, 'medium');
  await clearOurCounters();
});

test('a trusted hop is believed, but never a value further left', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const unknown = probe('xff-chain');
  await login({ username: unknown, password: 'guess' }, { xff: '9.9.9.9, 203.0.113.50' });
  const rows = await auditRows(`details->>'usernameHash' = $2`, [policy.auditUsernameHash(unknown)]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].ip, '203.0.113.50');
  assert.equal(rows[0].details.via, 'proxy-socket');
  assert.ok(await row('ip:203.0.113.50'));
  assert.equal(await row('ip:9.9.9.9'), null);
});

// --- Account scope and recognized browsers -----------------------------------

test('account scope: 20 networks pause new browsers; a recognized browser still signs in, another user\'s token does not', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const victim = await createUser('acct', 'admin');
  const other = await createUser('acct-other');
  // The owner signed in from this browser before the attack.
  const first = await login({ username: victim.username, password: PASSWORD }, { xff: '203.0.113.1' });
  assert.equal(first.status, 200);
  const victimToken: string = first.body.browserToken;
  const stored = await pool.query(`SELECT token_hash FROM recognized_browsers WHERE user_id = $1`, [victim.id]);
  assert.deepEqual(stored.rows.map((r) => r.token_hash), [crypto.createHash('sha256').update(victimToken).digest('hex')], 'only the sha256 is stored');
  const otherToken: string = (await login({ username: other.username, password: PASSWORD }, { xff: '203.0.113.2' })).body.browserToken;

  const statuses: number[] = [];
  let last: Answer | undefined;
  for (let i = 1; i <= 20; i++) {
    last = await login({ username: victim.username, password: 'guess' }, { xff: `198.51.100.${i}` });
    statuses.push(last.status);
  }
  assert.deepEqual(statuses, [...Array(19).fill(401), 429], 'the 20th attempt starts the pause');
  assert.equal(last!.body.reason, 'account');
  const fresh = await login({ username: victim.username, password: PASSWORD }, { xff: '198.51.100.99' });
  assert.equal(fresh.status, 429, 'new browsers are paused, even with the right password');
  assert.equal(fresh.body.reason, 'account');
  assert.match(fresh.body.message, /use a browser you have signed in with before/);

  // A token issued to someone else is not this account's: still paused.
  const borrowed = await login({ username: victim.username, password: PASSWORD, browserToken: otherToken }, { xff: '198.51.100.98' });
  assert.equal(borrowed.status, 429);
  // The owner's own browser walks past the pause, and keeps its token.
  const owner = await login({ username: victim.username, password: PASSWORD, browserToken: victimToken }, { xff: '198.51.100.97' });
  assert.equal(owner.status, 200);
  assert.equal(owner.body.browserToken, victimToken, 'touched, not rotated');

  // One alert for the streak (critical: an admin), notified once; the owner's
  // success from a recognized browser raises nothing.
  const alerts = await eventually(
    () => pool.query(`SELECT severity, event_id FROM alerts WHERE source = 'siembox-auth' AND created_at >= $1 AND matched_data->>'user_id' = $2`, [startedAt, String(victim.id)]),
    (res) => res.rows.length > 0
  );
  assert.deepEqual(alerts.rows.map((r) => [r.severity, r.event_id.split(':')[1]]), [['critical', 'account-pause']]);
  const notifiedForVictim = () => notified.filter((title) => title.includes(victim.username)).length;
  assert.equal(notifiedForVictim(), 1);

  // Another failure later in the same streak (next pause) raises no second alert.
  await unpause(acctKey(victim.username));
  assert.equal((await login({ username: victim.username, password: 'guess' }, { xff: '198.51.100.50' })).status, 429);
  await new Promise((resolve) => setTimeout(resolve, 200));
  const again = await pool.query(`SELECT COUNT(*)::int AS n FROM alerts WHERE source = 'siembox-auth' AND created_at >= $1 AND matched_data->>'user_id' = $2`, [startedAt, String(victim.id)]);
  assert.equal(again.rows[0].n, 1, 'deduplicated per streak');
  assert.equal(notifiedForVictim(), 1);
});

test('a recognized browser is forgotten after 20 consecutive failures', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const user = await createUser('br');
  const token: string = (await login({ username: user.username, password: PASSWORD }, { xff: '203.0.113.10' })).body.browserToken;
  const browser = (await pool.query(`SELECT id::text AS id FROM recognized_browsers WHERE user_id = $1`, [user.id])).rows[0];
  const key = `br:${browser.id}`;
  const statuses: number[] = [];
  for (let i = 1; i <= 20; i++) {
    const answer = await login({ username: user.username, password: 'guess', browserToken: token }, { xff: '203.0.113.10' });
    statuses.push(answer.status);
    if (answer.status === 429) await unpause(key);
  }
  assert.deepEqual(statuses.slice(0, 9), Array(9).fill(401));
  assert.equal(statuses[9], 429, 'the browser key pauses at 10');
  assert.equal((await pool.query(`SELECT COUNT(*)::int AS n FROM recognized_browsers WHERE user_id = $1`, [user.id])).rows[0].n, 0);
  const revoked = await auditRows(`action = 'auth.browser.revoked' AND user_id = $2`, [user.id]);
  assert.equal(revoked.length, 1);
  // The recognized browser's failures never reached the account or network keys.
  assert.equal((await row(acctKey(user.username))).failures, 0);
  assert.equal((await row(aipKey(user.username, '203.0.113.10'))).failures, 0);
  assert.equal((await row('ip:203.0.113.10')).failures, 0);
  const alert = await eventually(
    () => pool.query(`SELECT severity FROM alerts WHERE source = 'siembox-auth' AND created_at >= $1 AND event_id LIKE 'siembox-auth:browser-revoked:%'`, [startedAt]),
    (res) => res.rows.length > 0
  );
  assert.deepEqual(alert.rows.map((r) => r.severity), ['high']);
  // The token is now just a new browser's.
  const after = await login({ username: user.username, password: PASSWORD, browserToken: token }, { xff: '203.0.113.11' });
  assert.equal(after.status, 200);
  assert.notEqual(after.body.browserToken, token);
});

// --- MFA ----------------------------------------------------------------------

test('MFA: 5 wrong codes pause it with mfaRequired kept; a recognized browser is not affected; replays are refused', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const user = await createUser('mfa');
  const { secret } = await enrollMfa(user.id);
  const xff = '203.0.113.20';

  // The code step: not a failure.
  const step = await login({ username: user.username, password: PASSWORD }, { xff });
  assert.equal(step.status, 401);
  assert.deepEqual(step.body, { status: 'error', statusCode: 401, message: 'MFA code required', mfaRequired: true });
  // Sign in once with a code to get this browser recognized.
  const code = totp.totp(secret);
  const ok = await login({ username: user.username, password: PASSWORD, code }, { xff });
  assert.equal(ok.status, 200);
  const token: string = ok.body.browserToken;
  // The same code again is a replay.
  const replay = await login({ username: user.username, password: PASSWORD, code }, { xff: '203.0.113.21' });
  assert.equal(replay.status, 401);
  assert.equal(replay.body.message, 'Invalid MFA code');
  assert.equal(replay.body.mfaRequired, true);
  const replayRows = await auditRows(`action = 'auth.login.failure' AND user_id = $2 AND details->>'reason' = 'mfa_replay'`, [user.id]);
  assert.equal(replayRows.length, 1);

  // Wrong codes from a new browser: 401 x4 (the one above counted), then 429 with mfaRequired.
  const bad = wrongCode(secret);
  const statuses: number[] = [];
  let last: Answer | undefined;
  for (let i = 0; i < 4; i++) {
    last = await login({ username: user.username, password: PASSWORD, code: bad }, { xff: '203.0.113.22' });
    statuses.push(last.status);
  }
  assert.deepEqual(statuses, [401, 401, 401, 429]);
  assert.equal(last!.body.reason, 'mfa');
  assert.equal(last!.body.mfaRequired, true);
  assert.match(last!.body.message, /^Incorrect code\. Too many incorrect codes\./);
  // Paused: no code and the right code both get the paused answer, with mfaRequired.
  const noCode = await login({ username: user.username, password: PASSWORD }, { xff: '203.0.113.22' });
  assert.equal(noCode.status, 429);
  assert.equal(noCode.body.mfaRequired, true);
  await pool.query('UPDATE users SET mfa_last_totp_step = NULL WHERE id = $1', [user.id]);
  assert.equal((await login({ username: user.username, password: PASSWORD, code: totp.totp(secret) }, { xff: '203.0.113.22' })).status, 429);
  // A wrong password while MFA is paused is still just a wrong password: no oracle.
  assert.equal((await login({ username: user.username, password: 'nope' }, { xff: '203.0.113.23' })).status, 401);

  // The recognized browser has a bucket of its own.
  const fromBrowser = await login({ username: user.username, password: PASSWORD, code: totp.totp(secret), browserToken: token }, { xff: '203.0.113.24' });
  assert.equal(fromBrowser.status, 200);

  const alert = await eventually(
    () => pool.query(`SELECT severity FROM alerts WHERE source = 'siembox-auth' AND created_at >= $1 AND event_id LIKE 'siembox-auth:mfa-pause:%' AND matched_data->>'user_id' = $2`, [startedAt, String(user.id)]),
    (res) => res.rows.length > 0
  );
  assert.deepEqual(alert.rows.map((r) => r.severity), ['critical']);
});

test('MFA: one recovery code used twice at once signs in once', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const user = await createUser('mfa-rec');
  const { recovery } = await enrollMfa(user.id);
  const answers = await Promise.all(
    [1, 2].map((i) => login({ username: user.username, password: PASSWORD, code: recovery[0].toUpperCase() }, { xff: `203.0.113.${30 + i}` }))
  );
  assert.deepEqual(answers.map((a) => a.status).sort(), [200, 401]);
  const left = await pool.query('SELECT jsonb_array_length(mfa_recovery_codes) AS n FROM users WHERE id = $1', [user.id]);
  assert.equal(left.rows[0].n, 2);
  assert.equal((await auditRows(`action = 'auth.mfa.recovery_used' AND user_id = $2`, [user.id])).length, 1);
});

test('/me/mfa/disable: 400 for a wrong code, 429 once paused, never 401', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const user = await createUser('mfa-off');
  const { secret } = await enrollMfa(user.id);
  const session = await SessionModel.create(user.id, 1);
  const statuses: number[] = [];
  for (let i = 0; i < 6; i++) {
    statuses.push((await call('POST', '/api/auth/me/mfa/disable', { body: { code: wrongCode(secret) }, token: session.token })).status);
  }
  assert.deepEqual(statuses, [400, 400, 400, 400, 429, 429]);
  assert.equal((await call('GET', '/api/auth/me', { token: session.token })).status, 200, 'still signed in');
  await unpause(`mfa:${user.id}`);
  const off = await call('POST', '/api/auth/me/mfa/disable', { body: { code: totp.totp(secret) }, token: session.token });
  assert.equal(off.status, 200);
  assert.deepEqual(off.body, { enabled: false });
  assert.equal((await row(`mfa:${user.id}`)).failures, 0, 'reset');
  assert.equal((await auditRows(`action = 'auth.mfa.disabled' AND user_id = $2`, [user.id])).length, 1);
});

// --- Password changes ---------------------------------------------------------

test('password change: a wrong current password is a 400 (still signed in), 429 once paused; success revokes everything', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const user = await createUser('pwc');
  const token: string = (await login({ username: user.username, password: PASSWORD }, { xff: '203.0.113.40' })).body.browserToken;
  assert.ok(token);
  await login({ username: user.username, password: 'nope' }, { xff: '203.0.113.41' }); // leaves counters behind
  const session = await SessionModel.create(user.id, 1);
  const change = (currentPassword: string, newPassword = `${PASSWORD}-new`) =>
    call('PUT', '/api/auth/me/password', { body: { currentPassword, newPassword }, token: session.token });

  const wrong = await change('wrong current');
  assert.equal(wrong.status, 400);
  assert.equal(wrong.body.message, 'Current password is incorrect');
  assert.equal((await call('GET', '/api/auth/me', { token: session.token })).status, 200, 'the session stays valid');
  assert.equal((await change(PASSWORD, PASSWORD)).status, 400, 'the new password must differ');
  assert.equal((await change(PASSWORD, 'short')).status, 400);
  const statuses: number[] = [];
  for (let i = 0; i < 4; i++) statuses.push((await change('wrong current')).status);
  assert.deepEqual(statuses, [400, 400, 400, 429]);
  assert.equal((await change(PASSWORD)).status, 429, 'paused, even with the right one');

  await unpause(`pwc:${user.id}`);
  const ok = await change(PASSWORD);
  assert.equal(ok.status, 200);
  assert.equal((await call('GET', '/api/auth/me', { token: session.token })).status, 401, 'every session is revoked');
  assert.equal((await pool.query('SELECT COUNT(*)::int AS n FROM recognized_browsers WHERE user_id = $1', [user.id])).rows[0].n, 0);
  assert.equal((await pool.query('SELECT COUNT(*)::int AS n FROM login_throttle WHERE user_id = $1', [user.id])).rows[0].n, 0);
  assert.equal((await auditRows(`action = 'auth.password.changed' AND user_id = $2`, [user.id])).length, 1);
  assert.equal((await auditRows(`action = 'auth.password.change_failed' AND user_id = $2`, [user.id])).length, 5);
  assert.equal((await login({ username: user.username, password: `${PASSWORD}-new` }, { xff: '203.0.113.42' })).status, 200);
});

// --- Admin --------------------------------------------------------------------

test('admin: viewers get 403; clear by user, network and everything; unlock; password reset revokes; all audited', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const admin = await createUser('admin', 'admin');
  const viewer = await createUser('viewer');
  const target = await createUser('target');
  const adminSession = (await SessionModel.create(admin.id, 1)).token;
  const viewerSession = (await SessionModel.create(viewer.id, 1)).token;

  for (const [method, url] of [
    ['GET', '/api/admin/sign-in-protection'],
    ['POST', '/api/admin/sign-in-protection/clear'],
    ['POST', `/api/users/${target.id}/unlock`],
  ] as const) {
    assert.equal((await call(method, url, { body: method === 'POST' ? { all: true } : undefined, token: viewerSession })).status, 403, url);
  }

  const pause = async () => {
    for (let i = 0; i < 5; i++) await login({ username: target.username, password: 'nope' }, { xff: '203.0.113.60' });
  };
  await pause();
  const page = await call('GET', '/api/admin/sign-in-protection', { token: adminSession });
  assert.equal(page.status, 200);
  const mine = page.body.counters.find((c: { key: string }) => c.key === aipKey(target.username, '203.0.113.60'));
  assert.ok(mine, 'the paused key is listed');
  assert.equal(mine.username, target.username);
  assert.equal(mine.network, '203.0.113.60');
  assert.ok(mine.paused_seconds > 0 && mine.paused_seconds <= 30);
  assert.equal(page.body.settings.protection, true);
  assert.equal(page.body.clientAddress.you.address, '127.0.0.1');

  // The Users page shows the pause.
  const list = await call('GET', '/api/users', { token: adminSession });
  const listed = list.body.find((u: { id: number }) => u.id === target.id);
  assert.ok(listed.signin_paused_until);
  assert.deepEqual(listed.signin_pause_scopes, ['aip']);

  const unlocked = await call('POST', `/api/users/${target.id}/unlock`, { token: adminSession });
  assert.equal(unlocked.status, 200);
  assert.equal(unlocked.body.cleared, 2, 'aip and acct (the network key is not the account\'s)');
  assert.equal((await login({ username: target.username, password: PASSWORD }, { xff: '203.0.113.60' })).status, 200);

  await pause();
  assert.equal((await call('POST', '/api/admin/sign-in-protection/clear', { body: { userId: target.id }, token: adminSession })).body.cleared, 2);
  await pause();
  const byNetwork = await call('POST', '/api/admin/sign-in-protection/clear', { body: { network: '203.0.113.60' }, token: adminSession });
  assert.equal(byNetwork.body.cleared, 2, 'aip and ip for that network');
  assert.equal((await call('POST', '/api/admin/sign-in-protection/clear', { body: { network: 'nonsense' }, token: adminSession })).status, 400);
  assert.equal((await call('POST', '/api/admin/sign-in-protection/clear', { body: { key: 'x', all: true }, token: adminSession })).status, 400);
  await pause();
  const all = await call('POST', '/api/admin/sign-in-protection/clear', { body: { all: true }, token: adminSession });
  assert.ok(all.body.cleared >= 3);
  const unlocks = await auditRows(`action = 'auth.unlock' AND user_id = $2`, [admin.id]);
  assert.deepEqual(unlocks.map((r) => r.details.target), ['user', 'user', 'network', 'all']);

  // An admin's password reset signs the target out everywhere and forgets their browsers.
  const targetSession = (await SessionModel.create(target.id, 1)).token;
  assert.ok((await pool.query('SELECT COUNT(*)::int AS n FROM recognized_browsers WHERE user_id = $1', [target.id])).rows[0].n > 0);
  const reset = await call('PUT', `/api/users/${target.id}`, { body: { password: `${PASSWORD}-reset` }, token: adminSession });
  assert.equal(reset.status, 200);
  assert.equal((await call('GET', '/api/auth/me', { token: targetSession })).status, 401);
  assert.equal((await pool.query('SELECT COUNT(*)::int AS n FROM recognized_browsers WHERE user_id = $1', [target.id])).rows[0].n, 0);
  assert.equal((await auditRows(`action = 'user.password_reset' AND resource_id = $2`, [target.id])).length, 1);
  assert.equal((await call('PUT', `/api/users/${target.id}`, { body: { password: 12345678 }, token: adminSession })).status, 400);
});

// --- Fail open, protection off -------------------------------------------------

test('when the throttle table is unavailable, sign-in fails open and says so', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const user = await createUser('open');
  const { ErrorLogService } = await import('../services/errors/errorLogService');
  const background = mock.method(ErrorLogService, 'logBackgroundError', () => undefined);
  // Really unavailable: only this file uses the table, and it comes back below.
  await pool.query('ALTER TABLE login_throttle RENAME TO login_throttle_unavailable');
  try {
    const statuses: number[] = [];
    for (let i = 0; i < 7; i++) statuses.push((await login({ username: user.username, password: 'nope' }, { xff: '203.0.113.70' })).status);
    assert.deepEqual(statuses, Array(7).fill(401), 'no pause without the throttle');
    assert.equal((await login({ username: user.username, password: PASSWORD }, { xff: '203.0.113.70' })).status, 200);
    assert.ok(background.mock.calls.some((c) => c.arguments[0] === 'sign-in-protection'), 'reported on the dashboard');
  } finally {
    await pool.query('ALTER TABLE login_throttle_unavailable RENAME TO login_throttle');
    background.mock.restore();
  }
  assert.equal(await row(aipKey(user.username, '203.0.113.70')), null);
  assert.equal((await auditRows(`action = 'auth.login.failure' AND user_id = $2`, [user.id])).length, 7, 'still audited');
});

test('LOGIN_PROTECTION=off counts nothing', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const user = await createUser('off');
  process.env.LOGIN_PROTECTION = 'off';
  policy.reloadSignInSettings();
  try {
    const statuses: number[] = [];
    for (let i = 0; i < 7; i++) statuses.push((await login({ username: user.username, password: 'nope' }, { xff: '203.0.113.80' })).status);
    assert.deepEqual(statuses, Array(7).fill(401));
    assert.equal(await row(aipKey(user.username, '203.0.113.80')), null);
    assert.equal((await login({ username: user.username, password: PASSWORD }, { xff: '203.0.113.80' })).status, 200);
    assert.equal((await auditRows(`action = 'auth.login.failure' AND user_id = $2`, [user.id])).length, 7, 'still audited');
  } finally {
    delete process.env.LOGIN_PROTECTION;
    policy.reloadSignInSettings();
  }
});

// --- Shared networks, refunds and streaks ---------------------------------------

test('a paused network still checks a username that has not failed from it: one guess per username per streak', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const bob = await createUser('shared-bob');
  const alice = await createUser('shared-alice');
  // 203.0.113.177 stands for a NAT, or an outer proxy SIEMBox doesn't trust: everyone behind it shares one key.
  const xff = '203.0.113.177';
  const sprayed: string[] = [];
  for (let i = 1; i <= 20; i++) {
    sprayed.push(probe(`spray-${i}`));
    await login({ username: sprayed[i - 1], password: 'guess' }, { xff });
  }
  assert.equal((await row(`ip:${xff}`)).paused, true, 'the sprayer paused the network');

  // A username that already failed from this network in this streak: refused, before bcrypt.
  let compares = countCompares();
  const again = await login({ username: sprayed[0], password: 'guess' }, { xff });
  assert.equal(compares.count(), 0, 'no bcrypt for a username that already failed here');
  compares.stop();
  assert.equal(again.status, 429);
  assert.equal(again.body.reason, 'network');

  // Bob never failed from it: his right password is checked and signs him in, and the pause stays.
  const ok = await login({ username: bob.username, password: PASSWORD }, { xff });
  assert.equal(ok.status, 200);
  const network = await row(`ip:${xff}`);
  assert.equal(network.paused, true, 'his success does not lift the network pause');
  assert.equal(network.failures, 20, 'and his attempt was refunded');

  // A fresh username gets one checked guess, the same way whether it exists or not.
  for (const username of [alice.username, probe('spray-fresh')]) {
    compares = countCompares();
    const guess = await login({ username, password: 'guess' }, { xff });
    assert.equal(compares.count(), 1, `${username}: one bcrypt compare`);
    compares.stop();
    assert.equal(guess.status, 429);
    assert.equal(guess.body.reason, 'network');
    assert.match(guess.body.message, /^Incorrect username or password\. Too many failed sign-in attempts from your network\./);
    // ... and only one: after it, that username is refused here too.
    compares = countCompares();
    assert.equal((await login({ username, password: PASSWORD }, { xff })).status, 429);
    assert.equal(compares.count(), 0);
    compares.stop();
  }

  // A password change clears Alice's own counters, so she is checked again from the paused network.
  const session = await SessionModel.create(alice.id, 1);
  const changed = await call('PUT', '/api/auth/me/password', {
    body: { currentPassword: PASSWORD, newPassword: `${PASSWORD}-new` },
    token: session.token,
  });
  assert.equal(changed.status, 200);
  assert.equal((await login({ username: alice.username, password: `${PASSWORD}-new` }, { xff })).status, 200);
});

test('a right password that is the 20th attempt on a network leaves it unpaused: the refund undoes the pause it started', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const user = await createUser('ip-refund');
  const xff = '203.0.113.178';
  for (let i = 1; i <= 19; i++) await login({ username: probe(`ip-refund-${i}`), password: 'guess' }, { xff });
  assert.equal((await row(`ip:${xff}`)).failures, 19);
  assert.equal((await login({ username: user.username, password: PASSWORD }, { xff })).status, 200);
  const network = await row(`ip:${xff}`);
  assert.equal(network.failures, 19);
  assert.equal(network.pauses, 0);
  assert.equal(network.paused, false, 'not paused by the right password');
  // The next wrong one is the 20th failure.
  const twentieth = await login({ username: probe('ip-refund-20'), password: 'guess' }, { xff });
  assert.equal(twentieth.status, 429);
  assert.equal(twentieth.body.reason, 'network');
});

test('a right and a wrong attempt at once: the refund leaves the wrong one\'s streak with a start', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const { LoginThrottleModel } = await import('../models/LoginThrottle');
  const key = 'ip:192.0.2.150';
  const keys = [{ key, scope: 'ip' as const, userId: null, network: '192.0.2.150' }];
  const right = await LoginThrottleModel.reserve(keys, null); // starts the streak
  const wrong = await LoginThrottleModel.reserve(keys, null); // lands before the right one's refund
  assert.equal(right.outcome, 'charged');
  assert.equal(wrong.outcome, 'charged');
  await LoginThrottleModel.refund(right);
  const state = (
    await pool.query(
      `SELECT failures, first_failure_at::text AS first, last_failure_at::text AS last FROM login_throttle WHERE key = $1`,
      [key]
    )
  ).rows[0];
  assert.equal(state.failures, 1, 'the wrong one stands');
  assert.ok(state.first, 'its streak keeps a start');
  assert.equal(state.last, wrong.outcome === 'charged' ? wrong.charges[0].after.lastFailureAt : null);
  // So the streak's alerts carry a real start, not 0.
  const next = await LoginThrottleModel.reserve(keys, null);
  assert.ok(next.outcome === 'charged' && next.charges[0].streakStartedAt > 1_600_000_000, 'a real epoch');
});

test('a right password after a streak ended refunds to an empty streak', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const user = await createUser('fresh-refund');
  const key = acctKey(user.username);
  await pool.query(
    `INSERT INTO login_throttle (key, scope, user_id, failures, pauses, paused_until, first_failure_at, last_failure_at)
     VALUES ($1, 'acct', $2, 27, 8, NOW() - INTERVAL '24 hours', NOW() - INTERVAL '30 hours', NOW() - INTERVAL '25 hours')`,
    [key, user.id]
  );
  assert.equal((await login({ username: user.username, password: PASSWORD }, { xff: '192.0.2.151' })).status, 200);
  const state = (
    await pool.query(
      `SELECT failures, pauses, paused_until, first_failure_at, last_failure_at < NOW() - INTERVAL '24 hours' AS old_last
         FROM login_throttle WHERE key = $1`,
      [key]
    )
  ).rows[0];
  assert.deepEqual(
    { ...state },
    { failures: 0, pauses: 0, paused_until: null, first_failure_at: null, old_last: true },
    'nothing of the old streak or of this attempt is left'
  );
});

test('a streak 24 hours old starts over, even with a pause still recorded', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const user = await createUser('decay');
  const key = aipKey(user.username, '192.0.2.152');
  await pool.query(
    `INSERT INTO login_throttle (key, scope, user_id, network, failures, pauses, paused_until, first_failure_at, last_failure_at)
     VALUES ($1, 'aip', $2, '192.0.2.152', 9, 4, NOW() + INTERVAL '10 minutes', NOW() - INTERVAL '30 hours', NOW() - INTERVAL '25 hours')`,
    [key, user.id]
  );
  const answer = await login({ username: user.username, password: 'nope' }, { xff: '192.0.2.152' });
  assert.equal(answer.status, 401, 'not refused, and the failure starts no pause');
  const state = (
    await pool.query(
      `SELECT failures, pauses, paused_until, first_failure_at > NOW() - INTERVAL '1 minute' AS new_start
         FROM login_throttle WHERE key = $1`,
      [key]
    )
  ).rows[0];
  assert.deepEqual({ ...state }, { failures: 1, pauses: 0, paused_until: null, new_start: true });
});

test('a browser token unused for 91 days is not recognized; a 21st browser drops the least recently used', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const user = await createUser('br-age');
  const xff = '192.0.2.153';
  const token: string = (await login({ username: user.username, password: PASSWORD }, { xff })).body.browserToken;
  await pool.query(`UPDATE recognized_browsers SET last_used_at = NOW() - INTERVAL '91 days' WHERE user_id = $1`, [user.id]);
  assert.equal((await login({ username: user.username, password: 'nope', browserToken: token }, { xff })).status, 401);
  assert.equal((await row(aipKey(user.username, xff))).failures, 1, 'counted as a new browser');
  const fresh = await login({ username: user.username, password: PASSWORD, browserToken: token }, { xff });
  assert.equal(fresh.status, 200);
  assert.notEqual(fresh.body.browserToken, token, 'a new token');

  await pool.query(`DELETE FROM recognized_browsers WHERE user_id = $1`, [user.id]);
  await pool.query(
    `INSERT INTO recognized_browsers (user_id, token_hash, last_used_at)
     SELECT $1, encode(sha256(($2 || g::text)::bytea), 'hex'), NOW() - g * INTERVAL '1 day' FROM generate_series(1, 20) g`,
    [user.id, `${tag}-br-age-`]
  );
  const oldest = (await pool.query(`SELECT id FROM recognized_browsers WHERE user_id = $1 ORDER BY last_used_at LIMIT 1`, [user.id])).rows[0].id;
  assert.equal((await login({ username: user.username, password: PASSWORD }, { xff })).status, 200);
  const left = await pool.query(`SELECT id FROM recognized_browsers WHERE user_id = $1`, [user.id]);
  assert.equal(left.rows.length, 20);
  assert.ok(!left.rows.some((r) => r.id === oldest), 'the least recently used one went');
});

// --- MFA counts -------------------------------------------------------------------

test('MFA: a code check that throws is refunded; the right code is not counted as a failure', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const user = await createUser('mfa-count');
  const { secret } = await enrollMfa(user.id);
  const xff = '192.0.2.155';
  const { ErrorLogService } = await import('../services/errors/errorLogService');
  const logError = mock.method(ErrorLogService, 'logError', async () => null);
  const failing = mock.method(UserModel, 'claimTotpStep', async () => {
    throw new Error('database on fire');
  });
  try {
    for (let i = 0; i < 6; i++) {
      assert.equal((await login({ username: user.username, password: PASSWORD, code: totp.totp(secret) }, { xff })).status, 500);
    }
  } finally {
    failing.mock.restore();
    logError.mock.restore();
  }
  assert.equal((await row(`mfa:${user.id}`))?.failures ?? 0, 0, 'no 5xx counted at the code');

  // 4 wrong codes and the right one: 4 failures, no "signed in after failures" alert (that needs 5).
  for (let i = 0; i < 4; i++) {
    assert.equal((await login({ username: user.username, password: PASSWORD, code: wrongCode(secret) }, { xff })).status, 401);
  }
  assert.equal((await login({ username: user.username, password: PASSWORD, code: totp.totp(secret) }, { xff })).status, 200);
  const afterFailures = () =>
    pool.query(
      `SELECT title, matched_data FROM alerts WHERE source = 'siembox-auth' AND created_at >= $1
          AND event_id LIKE 'siembox-auth:success-after-failures:%' AND matched_data->>'user_id' = $2`,
      [startedAt, String(user.id)]
    );
  await new Promise((resolve) => setTimeout(resolve, 200));
  assert.equal((await afterFailures()).rows.length, 0, '4 failures are not 5');

  // 5 wrong codes (the 5th pauses), then the right one: "after 5 failed attempts".
  for (let i = 0; i < 5; i++) await login({ username: user.username, password: PASSWORD, code: wrongCode(secret) }, { xff });
  await unpause(`mfa:${user.id}`);
  await pool.query('UPDATE users SET mfa_last_totp_step = NULL WHERE id = $1', [user.id]);
  assert.equal((await login({ username: user.username, password: PASSWORD, code: totp.totp(secret) }, { xff })).status, 200);
  const alerts = await eventually(afterFailures, (res) => res.rows.length > 0);
  assert.equal(alerts.rows.length, 1);
  assert.equal(alerts.rows[0].matched_data.failures, 5);
  assert.match(alerts.rows[0].title, /signed in after 5 failed attempts$/);
});

test('/me/mfa/enable is refused once MFA is on (409), whatever the code, and changes nothing', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const user = await createUser('mfa-enable');
  const { secret } = await enrollMfa(user.id);
  const session = (await SessionModel.create(user.id, 1)).token;
  const stored = () =>
    pool.query(`SELECT mfa_enabled, mfa_secret, mfa_recovery_codes, mfa_last_totp_step FROM users WHERE id = $1`, [user.id]);
  const before = (await stored()).rows[0];
  for (const code of [wrongCode(secret), totp.totp(secret)]) {
    const answer = await call('POST', '/api/auth/me/mfa/enable', { body: { code }, token: session });
    assert.equal(answer.status, 409, `code ${code}`);
    assert.equal(answer.body.message, 'MFA is already enabled; disable it first to re-enroll');
  }
  assert.deepEqual((await stored()).rows[0], before, 'recovery codes and the TOTP step are untouched');

  // Enrolling from scratch still works: setup, then enable with a code for the pending secret.
  const other = await createUser('mfa-enroll');
  const otherSession = (await SessionModel.create(other.id, 1)).token;
  const setup = await call('POST', '/api/auth/me/mfa/setup', { token: otherSession });
  assert.equal(setup.status, 200);
  const code = totp.totp(setup.body.secret);
  const enabled = await call('POST', '/api/auth/me/mfa/enable', { body: { code }, token: otherSession });
  assert.equal(enabled.status, 200);
  assert.equal(enabled.body.recoveryCodes.length, 10);
  assert.equal((await call('POST', '/api/auth/me/mfa/enable', { body: { code }, token: otherSession })).status, 409);
  // The code that proved the enrollment can't sign in too.
  const replay = await login({ username: other.username, password: PASSWORD, code }, { xff: '192.0.2.156' });
  assert.equal(replay.status, 401);
  assert.equal(replay.body.message, 'Invalid MFA code');
});

test('password change: a right current password whose save fails (5xx) is not counted', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const user = await createUser('pwc-5xx');
  const session = (await SessionModel.create(user.id, 1)).token;
  const change = () =>
    call('PUT', '/api/auth/me/password', { body: { currentPassword: PASSWORD, newPassword: `${PASSWORD}-new` }, token: session });
  const { ErrorLogService } = await import('../services/errors/errorLogService');
  const logError = mock.method(ErrorLogService, 'logError', async () => null);
  const failing = mock.method(UserModel, 'changeOwnPassword', async () => {
    throw new Error('database on fire');
  });
  try {
    const statuses: number[] = [];
    for (let i = 0; i < 6; i++) statuses.push((await change()).status);
    assert.deepEqual(statuses, Array(6).fill(500));
  } finally {
    failing.mock.restore();
    logError.mock.restore();
  }
  assert.equal((await row(`pwc:${user.id}`))?.failures ?? 0, 0, 'the right current password is never a failure');
  assert.equal((await change()).status, 200);
});

test('Users page: a password-change pause is not a sign-in pause', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const admin = await createUser('users-admin', 'admin');
  const user = await createUser('users-pwc');
  const adminSession = (await SessionModel.create(admin.id, 1)).token;
  const session = (await SessionModel.create(user.id, 1)).token;
  for (let i = 0; i < 5; i++) {
    await call('PUT', '/api/auth/me/password', { body: { currentPassword: 'wrong', newPassword: `${PASSWORD}-new` }, token: session });
  }
  assert.equal((await row(`pwc:${user.id}`)).paused, true);
  const listed = (await call('GET', '/api/users', { token: adminSession })).body.find((u: { id: number }) => u.id === user.id);
  assert.equal(listed.signin_paused_until, null, 'signing in is not paused');
  assert.deepEqual(listed.signin_pause_scopes, []);
  assert.ok(listed.password_change_paused_until, 'the password change is');
  assert.equal((await login({ username: user.username, password: PASSWORD }, { xff: '192.0.2.157' })).status, 200);
});

// --- Housekeeping and the CLI ---------------------------------------------------

test('housekeeping removes idle counters, unused browsers, expired sessions and old failure rows only', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const user = await createUser('hk');
  const { runSignInHousekeeping } = await import('../jobs/signInHousekeeping');
  await pool.query(
    `INSERT INTO login_throttle (key, scope, user_id, network, failures, paused_until, last_failure_at, updated_at) VALUES
       ('ip:192.0.2.201', 'ip', NULL, '192.0.2.201', 3, NULL, NOW() - INTERVAL '25 hours', NOW() - INTERVAL '25 hours'),
       ('ip:192.0.2.202', 'ip', NULL, '192.0.2.202', 3, NOW() + INTERVAL '10 minutes', NOW() - INTERVAL '25 hours', NOW()),
       ('ip:192.0.2.203', 'ip', NULL, '192.0.2.203', 3, NULL, NOW() - INTERVAL '1 hour', NOW())`
  );
  await pool.query(
    `INSERT INTO recognized_browsers (user_id, token_hash, last_used_at) VALUES
       ($1, $2, NOW() - INTERVAL '91 days'), ($1, $3, NOW() - INTERVAL '1 day')`,
    [user.id, crypto.randomBytes(32).toString('hex'), crypto.randomBytes(32).toString('hex')]
  );
  await pool.query(`INSERT INTO sessions (user_id, token, expires_at) VALUES ($1, $2, NOW() - INTERVAL '1 minute')`, [
    user.id,
    crypto.randomBytes(32).toString('hex'),
  ]);
  await pool.query(
    `INSERT INTO audit_logs (user_id, action, ip_address, timestamp, response_status) VALUES
       ($1, 'auth.login.failure', '192.0.2.204', NOW() - INTERVAL '91 days', 401),
       ($1, 'auth.login.failure', '192.0.2.204', NOW() - INTERVAL '1 day', 401),
       ($1, 'auth.login.success', '192.0.2.204', NOW() - INTERVAL '91 days', 200)`,
    [user.id]
  );
  const result = await runSignInHousekeeping();
  assert.ok(result.counters >= 1 && result.browsers >= 1 && result.sessions >= 1 && result.failureAuditRows >= 1);
  const keys = (await pool.query(`SELECT key FROM login_throttle WHERE network <<= '192.0.2.200/29' ORDER BY key`)).rows.map((r) => r.key);
  assert.deepEqual(keys, ['ip:192.0.2.202', 'ip:192.0.2.203'], 'paused and recent rows stay');
  assert.equal((await pool.query('SELECT COUNT(*)::int AS n FROM recognized_browsers WHERE user_id = $1', [user.id])).rows[0].n, 1);
  assert.equal((await pool.query('SELECT COUNT(*)::int AS n FROM sessions WHERE user_id = $1', [user.id])).rows[0].n, 0);
  const audit = await pool.query(`SELECT action FROM audit_logs WHERE user_id = $1 ORDER BY action`, [user.id]);
  assert.deepEqual(audit.rows.map((r) => r.action), ['auth.login.failure', 'auth.login.success'], 'only old failure rows go');
  await pool.query(`DELETE FROM audit_logs WHERE user_id = $1`, [user.id]);
});

test('the recovery CLI: status, unlock (user, network, all), reset-password and disable-mfa, each audited as the CLI', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const user = await createUser('cli');
  await enrollMfa(user.id);
  const { main } = await import('../scripts/auth-admin');
  const run = async (...argv: string[]) => {
    const out: string[] = [];
    const err: string[] = [];
    const code = await main(argv, { out: (l) => out.push(l), err: (l) => err.push(l) });
    return { code, out: out.join('\n'), err: err.join('\n') };
  };
  const pause = async () => {
    for (let i = 0; i < 5; i++) await login({ username: user.username, password: 'nope' }, { xff: '203.0.113.90' });
  };
  await pause();
  const status = await run('status', user.username);
  assert.equal(status.code, 0);
  assert.match(status.out, /Account from one network\s+sip-[0-9a-f]+-cli\s+203\.0\.113\.90\s+failures\s+5\s+paused \d+s/);
  assert.match(status.out, /MFA on/);

  assert.equal((await run('unlock', user.username)).out, 'Cleared 2 sign-in counter(s).');
  await pause();
  assert.equal((await run('unlock', '--network', '203.0.113.90')).out, 'Cleared 2 sign-in counter(s).');
  // An IPv6 network, exactly as status prints it (its /64), and the bare address.
  for (const typed of ['2001:db8:1:2::/64', '2001:db8:1:2::77']) {
    for (let i = 0; i < 3; i++) await login({ username: user.username, password: 'nope' }, { xff: '2001:db8:1:2::5' });
    const v6 = await run('status', user.username);
    assert.match(v6.out, /2001:db8:1:2::\/64\s+failures\s+3/);
    const unlocked = await run('unlock', '--network', typed);
    assert.equal(unlocked.code, 0, unlocked.err);
    assert.equal(unlocked.out, 'Cleared 2 sign-in counter(s).', typed);
  }
  assert.equal((await run('unlock', '--network', 'unknown')).code, 0, 'requests that had no address');
  assert.equal((await run('unlock', '--network', '192.0.2.1/64')).code, 1, 'a /64 is IPv6 only');
  await pause();
  assert.equal((await run('unlock', '--all')).code, 0);
  assert.equal((await row(aipKey(user.username, '203.0.113.90'))), null);

  const session = (await SessionModel.create(user.id, 1)).token;
  const reset = await run('reset-password', user.username);
  assert.equal(reset.code, 0);
  const newPassword = /\(shown only now\): (\S{20})$/m.exec(reset.out)?.[1];
  assert.ok(newPassword, reset.out);
  assert.equal((await call('GET', '/api/auth/me', { token: session })).status, 401, 'signed out everywhere');

  const disable = await run('disable-mfa', user.username);
  assert.equal(disable.code, 0);
  assert.equal((await pool.query('SELECT mfa_enabled FROM users WHERE id = $1', [user.id])).rows[0].mfa_enabled, false);
  assert.equal((await login({ username: user.username, password: newPassword! }, { xff: '203.0.113.91' })).status, 200);

  const rows = await auditRows(`details->>'by' = 'cli' AND resource_id = $2`, [user.id]);
  assert.deepEqual(rows.map((r) => r.action), ['auth.unlock', 'user.password_reset', 'auth.mfa.disabled']);
  for (const entry of rows) assert.equal(entry.user_id, null);
  const cliUnlocks = await auditRows(`details->>'by' = 'cli' AND action = 'auth.unlock'`, []);
  assert.ok(cliUnlocks.some((r) => r.details.target === 'network') && cliUnlocks.some((r) => r.details.target === 'all'));

  assert.equal((await run('unlock', 'no-such-user')).code, 1);
  assert.equal((await run('bogus')).code, 1);
});
