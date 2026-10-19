/**
 * Accounts that must change their password before anything else, against a
 * real Postgres through the real app (the proxy socket, as the bundled nginx
 * reaches it):
 *
 * - enforcement: a restricted account signs in (passwordChangeRequired) and
 *   its session may read /me, change the password and sign out, and nothing
 *   else (403 PASSWORD_CHANGE_REQUIRED, with no application_errors or
 *   access.denied rows); an existing session is restricted the moment the
 *   account is flagged;
 * - sign-in detection: the right password "changeme" flags the account
 *   ('default', any role, before MFA), once, with one audit row and one alert;
 *   an account already flagged keeps its reason;
 * - the change: wrong current password (400, still restricted, session kept),
 *   the default refused in any case, unchanged refused, paused after 5;
 *   success clears the flag in the same UPDATE, revokes every session and
 *   browser, audits forced: true, and the next sign-in is unrestricted;
 * - races: a sign-in with the old password that is still running when the
 *   password changes gets no session or browser (and flags nothing); a
 *   session is only created while the hash checked is current, waiting for a
 *   change in progress; a restricted session gets 401, never through, while
 *   the change or an admin's reset that lifts the restriction finishes;
 * - the boot alert: enabled accounts only, with a command that runs; a
 *   disabled account's is raised when an admin enables it, and a sign-in with
 *   "changeme" raises one nothing raised yet (still one per flag);
 * - MFA first, no MFA changes while restricted; a disabled account is still
 *   403 'Account is disabled';
 * - the admin API (mustChangePassword, default true, only with a password),
 *   the recovery CLI (reset-password always requires a change; status says
 *   so), shipper keys unaffected, and the model guard.
 *
 * Skips itself when Postgres (with migration 039) isn't reachable. The users
 * it creates (pcr-<tag>-...), their rows, and the counters, audit rows and
 * alerts they caused are removed again.
 * Run with `npm test` (tsx --test).
 */
import { test, before, after, mock } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import bcrypt from 'bcrypt';

process.env.CREDENTIAL_ENCRYPTION_KEY ||= crypto.randomBytes(32).toString('hex');

const SKIP = 'Postgres with migration 039 (users.must_change_password) is not reachable';
const tag = crypto.randomBytes(5).toString('hex');
const PASSWORD = `pw-${crypto.randomBytes(9).toString('hex')}`;
/** This file's client addresses (benchmarking range: no other test file uses it). */
const TEST_NET = '198.18.0.0/15';
const startedAt = new Date();

let dbReady = false;
let pool: typeof import('../config/database').default;
let closePools: () => Promise<void>;
let UserModel: typeof import('../models/User').UserModel;
let SessionModel: typeof import('../models/Session').SessionModel;
let LogShipperModel: typeof import('../models/LogShipper').LogShipperModel;
let totp: typeof import('../services/auth/totp');
let policy: typeof import('../services/auth/signInPolicy');
let authEvents: typeof import('../services/auth/authEvents');
let CredentialEncryption: typeof import('../services/credentials/credentialEncryption').CredentialEncryption;

let socketServer: http.Server | null = null;
let socketPath = '';
let socketDir = '';
const userIds: number[] = [];
const usernames: string[] = [];
const shipperIds: number[] = [];
const shipperShortIds: string[] = [];
/** Titles of the alerts notifyAlert was called for. */
const notified: string[] = [];
const restoreAfter: Array<() => void> = [];
let nextAddress = 1;

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- assertions read whatever the API sent
type Json = Record<string, any>;
interface Answer {
  status: number;
  body: Json;
}

/** A client address of its own for each call, so no sign-in counter is shared. */
function address(): string {
  const n = nextAddress++;
  return `198.18.${Math.floor(n / 250)}.${(n % 250) + 1}`;
}

function call(
  method: string,
  urlPath: string,
  opts: { body?: unknown; token?: string; headers?: Record<string, string>; xff?: string } = {}
): Promise<Answer> {
  const payload = opts.body === undefined ? undefined : JSON.stringify(opts.body);
  const headers: Record<string, string> = { 'X-Forwarded-For': opts.xff ?? address(), ...(opts.headers ?? {}) };
  if (payload !== undefined) headers['Content-Type'] = 'application/json';
  if (opts.token) headers.Authorization = `Bearer ${opts.token}`;
  return new Promise((resolve, reject) => {
    const req = http.request({ socketPath, method, path: urlPath, headers, agent: false }, (res) => {
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
        resolve({ status: res.statusCode ?? 0, body });
      });
    });
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

const login = (username: string, password: string, extra: Record<string, unknown> = {}) =>
  call('POST', '/api/auth/login', { body: { username, password, ...extra } });

type Reason = 'initial' | 'default' | 'admin' | 'cli';

async function createUser(
  suffix: string,
  role: 'admin' | 'viewer' = 'viewer',
  opts: { requirePasswordChange?: Reason | null; enabled?: boolean } = {}
) {
  const username = `pcr-${tag}-${suffix}`;
  const user = await UserModel.create({
    username,
    email: `${username}@siembox.invalid`,
    password: PASSWORD,
    role,
    enabled: opts.enabled ?? true,
    requirePasswordChange: opts.requirePasswordChange ?? null,
  });
  userIds.push(user.id);
  usernames.push(username);
  return user;
}

/** Give a user the password "changeme" the way only SQL (or an old version) can. */
async function setDefaultPassword(userId: number): Promise<void> {
  await pool.query('UPDATE users SET password_hash = $2 WHERE id = $1', [userId, await bcrypt.hash('changeme', 4)]);
}

async function flags(userId: number) {
  const res = await pool.query(
    `SELECT must_change_password AS must, must_change_password_reason AS reason, must_change_password_since AS since,
            password_changed_at FROM users WHERE id = $1`,
    [userId]
  );
  return res.rows[0];
}

async function auditRows(where: string, params: unknown[]) {
  const res = await pool.query(
    `SELECT action, user_id, resource_id, response_status, details FROM audit_logs
      WHERE timestamp >= $1 AND (${where}) ORDER BY id`,
    [startedAt, ...params]
  );
  return res.rows;
}

async function defaultPasswordAlerts(userId: number) {
  const res = await pool.query(
    `SELECT severity, title, description, event_id, matched_data FROM alerts
      WHERE source = 'siembox-auth' AND matched_data->>'trigger' = 'default-password' AND matched_data->>'user_id' = $1`,
    [String(userId)]
  );
  return res.rows;
}

async function countRows(sql: string, params: unknown[]): Promise<number> {
  return (await pool.query(sql, params)).rows[0].n;
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

/** A point a call waits at: `reached` once it got there, `release()` lets it go on. */
function gate() {
  let markReached!: () => void;
  let release!: () => void;
  const reached = new Promise<void>((resolve) => (markReached = resolve));
  const released = new Promise<void>((resolve) => (release = resolve));
  return { reached, markReached, released, release };
}

/**
 * Hold the next bcrypt compare of `password` once it has answered, until
 * released: a sign-in with it that read the account and checked the password
 * before a change, and goes on to create its session after it.
 */
function holdNextPasswordCheck(password: string) {
  const point = gate();
  const original = bcrypt.compare;
  let armed = true;
  const compare = mock.method(bcrypt, 'compare', async (data: string, hash: string) => {
    const ok = await original.call(bcrypt, data, hash);
    if (armed && data === password) {
      armed = false;
      point.markReached();
      await point.released;
    }
    return ok;
  });
  return { ...point, restore: () => compare.mock.restore() };
}

/**
 * Hold the next SessionModel.deleteAllForUser of `userId` (revokeAccountAccess,
 * which follows a password change or reset) until released.
 */
function holdNextSessionRevoke(userId: number) {
  const point = gate();
  const original = SessionModel.deleteAllForUser;
  let armed = true;
  const revoke = mock.method(SessionModel, 'deleteAllForUser', async (id: number) => {
    if (armed && id === userId) {
      armed = false;
      point.markReached();
      await point.released;
    }
    return original.call(SessionModel, id);
  });
  return { ...point, restore: () => revoke.mock.restore() };
}

const sessionsOf = (userId: number) => countRows('SELECT COUNT(*)::int AS n FROM sessions WHERE user_id = $1', [userId]);
const browsersOf = (userId: number) => countRows('SELECT COUNT(*)::int AS n FROM recognized_browsers WHERE user_id = $1', [userId]);

async function enrollMfa(userId: number): Promise<string> {
  const secret = totp.generateSecret();
  const hashes = await Promise.all(['aaaaabbbbb'].map((code) => bcrypt.hash(code, 4)));
  await pool.query(
    `UPDATE users SET mfa_enabled = TRUE, mfa_secret = $2, mfa_recovery_codes = $3, mfa_last_totp_step = NULL WHERE id = $1`,
    [userId, JSON.stringify(CredentialEncryption.encrypt(secret)), JSON.stringify(hashes)]
  );
  return secret;
}

const RESTRICTED_ROUTES: Array<[string, string]> = [
  ['GET', '/api/alerts'],
  ['GET', '/api/users'],
  ['POST', '/api/auth/me/mfa/setup'],
  ['GET', '/api/settings/onboarding'],
];

function assertRestricted(answer: Answer, reason: Reason, what: string): void {
  assert.equal(answer.status, 403, `${what}: ${JSON.stringify(answer.body)}`);
  assert.equal(answer.body.code, 'PASSWORD_CHANGE_REQUIRED', what);
  assert.equal(answer.body.reason, reason, what);
  assert.match(answer.body.message, /^Choose a new password before doing anything else/, what);
}

before(async () => {
  const db = await import('../config/database');
  pool = db.default;
  closePools = db.closePools;
  try {
    await pool.query('SELECT must_change_password, must_change_password_reason, must_change_password_since FROM users LIMIT 1');
    await pool.query('SELECT 1 FROM login_throttle LIMIT 1');
    dbReady = true;
  } catch {
    return;
  }
  UserModel = (await import('../models/User')).UserModel;
  SessionModel = (await import('../models/Session')).SessionModel;
  LogShipperModel = (await import('../models/LogShipper')).LogShipperModel;
  totp = await import('../services/auth/totp');
  policy = await import('../services/auth/signInPolicy');
  authEvents = await import('../services/auth/authEvents');
  CredentialEncryption = (await import('../services/credentials/credentialEncryption')).CredentialEncryption;
  policy.reloadSignInSettings();

  const { logger } = await import('../utils/logger');
  for (const transport of logger.transports) {
    const was = transport.silent;
    transport.silent = true;
    restoreAfter.push(() => (transport.silent = was));
  }
  const { NotificationService } = await import('../services/notifications/notificationService');
  const notify = mock.method(NotificationService, 'notifyAlert', async (alert: { title: string }) => {
    notified.push(alert.title);
  });
  restoreAfter.push(() => notify.mock.restore());

  const app = (await import('../app')).default;
  const { listenProxySocket } = await import('../net/apiListeners');
  socketDir = fs.mkdtempSync(path.join(os.tmpdir(), 'siembox-pcr-'));
  socketPath = path.join(socketDir, 'api.sock');
  const quiet = { info: () => undefined, warn: () => undefined, error: () => undefined } as never;
  socketServer = (await listenProxySocket(app, socketPath, quiet)).server;
  assert.ok(socketServer, 'the proxy socket listens');
});

after(async () => {
  for (const restore of restoreAfter) restore();
  if (socketServer) {
    socketServer.closeAllConnections();
    await new Promise<void>((resolve) => socketServer!.close(() => resolve()));
  }
  if (socketDir) fs.rmSync(socketDir, { recursive: true, force: true });
  if (dbReady) {
    const acctKeys = usernames.map((name) => `acct:${policy.usernameHash(name)}`);
    const aipKeys = usernames.map((name) => `aip:${policy.usernameHash(name)}:%`);
    await pool.query(
      `DELETE FROM login_throttle WHERE user_id = ANY($1) OR network <<= $2::inet OR key = ANY($3) OR key LIKE ANY($4)`,
      [userIds, TEST_NET, acctKeys, aipKeys]
    );
    await pool.query(
      `DELETE FROM alerts WHERE source = 'siembox-auth' AND created_at >= $1 AND matched_data->>'user_id' = ANY($2)`,
      [startedAt, userIds.map(String)]
    );
    await pool.query('DELETE FROM raw_logs WHERE shipper_id = ANY($1) AND created_at >= $2', [shipperShortIds, startedAt]).catch(() =>
      pool.query('DELETE FROM raw_logs WHERE shipper_id = ANY($1)', [shipperShortIds])
    );
    await pool.query('DELETE FROM log_shippers WHERE id = ANY($1)', [shipperIds]);
    await pool.query('DELETE FROM application_errors WHERE user_id = ANY($1)', [userIds]);
    await pool.query(`DELETE FROM audit_logs WHERE timestamp >= $1 AND (user_id = ANY($2) OR (resource_type = 'user' AND resource_id = ANY($2)))`, [startedAt, userIds]);
    // Sessions and recognized browsers go with the users (ON DELETE CASCADE).
    await pool.query(
      `DELETE FROM users WHERE id = ANY($1)
          OR (username ~ '^pcr-[0-9a-f]{10}-' AND email LIKE '%@siembox.invalid' AND created_at < NOW() - INTERVAL '10 minutes')`,
      [userIds]
    );
  }
  authEvents?.stopRefusalSummary();
  await closePools?.();
});

// --- Enforcement ----------------------------------------------------------------

test('a restricted account signs in, and its session may only read /me, change the password or sign out', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const user = await createUser('enforce', 'admin', { requirePasswordChange: 'admin' });
  const signedIn = await login(user.username, PASSWORD);
  assert.equal(signedIn.status, 200);
  assert.equal(signedIn.body.passwordChangeRequired, true);
  assert.equal(signedIn.body.user.must_change_password, true);
  assert.equal(signedIn.body.user.must_change_password_reason, 'admin');
  assert.ok(signedIn.body.user.must_change_password_since);
  assert.ok(!('password_hash' in signedIn.body.user));
  const token: string = signedIn.body.token;
  assert.match(token, /^[0-9a-f]{64}$/);

  const success = await auditRows(`action = 'auth.login.success' AND user_id = $2`, [user.id]);
  assert.equal(success.length, 1);
  assert.equal(success[0].details.passwordChangeRequired, 'admin');

  const me = await call('GET', '/api/auth/me', { token });
  assert.equal(me.status, 200);
  assert.equal(me.body.must_change_password, true);
  assert.equal(me.body.must_change_password_reason, 'admin');

  const errorsBefore = await countRows('SELECT COUNT(*)::int AS n FROM application_errors WHERE user_id = $1', [user.id]);
  for (const [method, url] of RESTRICTED_ROUTES) {
    assertRestricted(await call(method, url, { token, body: method === 'GET' ? undefined : {} }), 'admin', `${method} ${url}`);
  }
  // Give a fire-and-forget errorHandler write the time it would need.
  await new Promise((resolve) => setTimeout(resolve, 300));
  assert.equal(
    await countRows('SELECT COUNT(*)::int AS n FROM application_errors WHERE user_id = $1', [user.id]),
    errorsBefore,
    'no application_errors row for a refused request'
  );
  assert.equal((await auditRows(`action = 'access.denied' AND user_id = $2`, [user.id])).length, 0, 'no access.denied row');

  const out = await call('POST', '/api/auth/logout', { token, body: {} });
  assert.equal(out.status, 200);
  assert.equal((await call('GET', '/api/auth/me', { token })).status, 401, 'signed out');
});

test('an existing session is restricted the moment its account is flagged', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const user = await createUser('existing', 'admin');
  const token = (await SessionModel.create(user.id, 1)).token;
  assert.equal((await call('GET', '/api/alerts', { token })).status, 200);
  const since = await UserModel.requirePasswordChange(user.id, 'default');
  assert.ok(since instanceof Date);
  assertRestricted(await call('GET', '/api/alerts', { token }), 'default', 'the old session');
  // Already flagged: nothing changes, the reason and date are kept.
  assert.equal(await UserModel.requirePasswordChange(user.id, 'admin'), null);
  const row = await flags(user.id);
  assert.equal(row.reason, 'default');
  assert.equal(row.since.getTime(), since!.getTime());
});

test('requirePasswordChange with ifHash flags only while the hash is unchanged', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const user = await createUser('cas', 'admin');
  assert.equal(await UserModel.requirePasswordChange(user.id, 'default', { ifHash: 'not-the-hash' }), null);
  assert.equal((await flags(user.id)).must, false);
  const { password_hash: hash } = (await pool.query('SELECT password_hash FROM users WHERE id = $1', [user.id])).rows[0];
  assert.ok(await UserModel.requirePasswordChange(user.id, 'default', { ifHash: hash }));
  assert.equal((await flags(user.id)).must, true);
});

// --- Sign-in detection ------------------------------------------------------------

test('signing in with "changeme" flags the account once (any role), with one audit row and one alert', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const viewer = await createUser('default-viewer', 'viewer');
  await setDefaultPassword(viewer.id);
  const earlier = (await SessionModel.create(viewer.id, 1)).token;
  assert.equal((await call('GET', '/api/alerts', { token: earlier })).status, 200, 'unrestricted until found');
  const notifiedBefore = notified.length;

  const first = await login(viewer.username, 'changeme');
  assert.equal(first.status, 200);
  assert.equal(first.body.passwordChangeRequired, true);
  assert.equal(first.body.user.must_change_password_reason, 'default');
  const row = await flags(viewer.id);
  assert.equal(row.must, true);
  assert.equal(row.reason, 'default');
  const rows = await auditRows(`action = 'auth.password.change_required' AND user_id = $2`, [viewer.id]);
  assert.equal(rows.length, 1);
  assert.deepEqual({ by: rows[0].details.by, reason: rows[0].details.reason }, { by: 'sign-in', reason: 'default' });
  const alerts = await eventually(() => defaultPasswordAlerts(viewer.id), (list) => list.length > 0);
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].severity, 'high', 'not an admin');
  assert.equal(alerts[0].title, `${viewer.username} uses SIEMBox's default password`);
  assert.equal(alerts[0].matched_data.found, 'sign-in');
  assert.equal(notified.length - notifiedBefore, 1, 'one notification');
  assertRestricted(await call('GET', '/api/alerts', { token: earlier }), 'default', 'the session from before');

  // Again: no new row, no new alert, the date kept.
  const second = await login(viewer.username, 'changeme');
  assert.equal(second.status, 200);
  assert.equal(second.body.passwordChangeRequired, true);
  assert.equal((await auditRows(`action = 'auth.password.change_required' AND user_id = $2`, [viewer.id])).length, 1);
  await new Promise((resolve) => setTimeout(resolve, 200));
  assert.equal((await defaultPasswordAlerts(viewer.id)).length, 1);
  assert.equal(notified.length - notifiedBefore, 1);
  assert.equal((await flags(viewer.id)).since.getTime(), row.since.getTime());
});

test('an account already flagged for another reason keeps it when it signs in with "changeme"', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const admin = await createUser('flagged-admin', 'admin', { requirePasswordChange: 'admin' });
  await setDefaultPassword(admin.id);
  const answer = await login(admin.username, 'changeme');
  assert.equal(answer.status, 200);
  assert.equal(answer.body.user.must_change_password_reason, 'admin');
  assert.equal((await flags(admin.id)).reason, 'admin');
  assert.equal((await auditRows(`action = 'auth.password.change_required' AND user_id = $2`, [admin.id])).length, 0);
});

test('an admin found on "changeme" at sign-in raises a critical alert', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const admin = await createUser('default-admin', 'admin');
  await setDefaultPassword(admin.id);
  assert.equal((await login(admin.username, 'changeme')).body.passwordChangeRequired, true);
  const alerts = await eventually(() => defaultPasswordAlerts(admin.id), (list) => list.length > 0);
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].severity, 'critical');
  assert.match(alerts[0].event_id, /^siembox-auth:default-password:[0-9a-f]{16}:\d+$/);
  assert.ok(
    alerts[0].description.includes(`run docker exec siembox-backend node dist/scripts/auth-admin.js reset-password ${admin.username} `),
    alerts[0].description
  );
});

test('at boot, the default-password alert is raised for enabled accounts only (a disabled one cannot sign in)', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const { raiseDefaultPasswordAlerts } = await import('../services/auth/defaultPasswordAlerts');
  const active = await createUser('boot-active', 'admin', { requirePasswordChange: 'default' });
  const dormant = await createUser('boot-dormant', 'admin', { requirePasswordChange: 'default', enabled: false });
  assert.equal(await raiseDefaultPasswordAlerts({ onlyUserIds: [active.id, dormant.id] }), 1);
  const [alert] = await eventually(() => defaultPasswordAlerts(active.id), (list) => list.length > 0);
  assert.equal(alert.matched_data.found, 'startup');
  assert.ok(alert.description.includes('(at startup)'), alert.description);
  assert.ok(alert.description.includes(`node dist/scripts/auth-admin.js reset-password ${active.username}`), alert.description);
  assert.equal((await defaultPasswordAlerts(dormant.id)).length, 0, 'no alert to sign in as an account that cannot');
  assert.equal(await raiseDefaultPasswordAlerts({ onlyUserIds: [active.id, dormant.id] }), 0, 'once per flag');
});

test('a disabled account flagged "default" raises the alert when an admin enables it, once per flag', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const admin = await createUser('enabler', 'admin');
  const token = (await SessionModel.create(admin.id, 1)).token;
  const dormant = await createUser('enable-dormant', 'admin', { requirePasswordChange: 'default', enabled: false });
  await setDefaultPassword(dormant.id);
  const notifiedBefore = notified.length;

  const enabled = await call('PUT', `/api/users/${dormant.id}`, { token, body: { enabled: true } });
  assert.equal(enabled.status, 200, JSON.stringify(enabled.body));
  const alerts = await eventually(() => defaultPasswordAlerts(dormant.id), (list) => list.length > 0);
  assert.equal(alerts.length, 1, 'raised as the account becomes usable, not at the next restart');
  assert.equal(alerts[0].severity, 'critical');
  assert.equal(alerts[0].matched_data.found, 'enabled');
  assert.equal(alerts[0].matched_data.by, admin.username);
  assert.ok(alerts[0].description.includes(`(when ${admin.username} enabled it)`), alerts[0].description);
  assert.ok(alerts[0].description.includes(`reset-password ${dormant.username}`), alerts[0].description);
  assert.equal(notified.length - notifiedBefore, 1, 'one notification');

  // Disabled and enabled again, a restart, a sign-in with "changeme": the same flag, nothing new.
  assert.equal((await call('PUT', `/api/users/${dormant.id}`, { token, body: { enabled: false } })).status, 200);
  assert.equal((await call('PUT', `/api/users/${dormant.id}`, { token, body: { enabled: true } })).status, 200);
  const { raiseDefaultPasswordAlerts } = await import('../services/auth/defaultPasswordAlerts');
  assert.equal(await raiseDefaultPasswordAlerts({ onlyUserIds: [dormant.id] }), 0);
  assert.equal((await login(dormant.username, 'changeme')).body.passwordChangeRequired, true);
  await new Promise((resolve) => setTimeout(resolve, 200));
  assert.equal((await defaultPasswordAlerts(dormant.id)).length, 1);
  assert.equal(notified.length - notifiedBefore, 1);

  // Enabled with a new password: the flag is the admin's now, so no default-password alert.
  const reset = await createUser('enable-reset', 'admin', { requirePasswordChange: 'default', enabled: false });
  const resetAnswer = await call('PUT', `/api/users/${reset.id}`, { token, body: { enabled: true, password: `${PASSWORD}-new` } });
  assert.equal(resetAnswer.status, 200, JSON.stringify(resetAnswer.body));
  assert.equal(resetAnswer.body.must_change_password_reason, 'admin');
  // Flagged for another reason, or never disabled: nothing.
  const other = await createUser('enable-other', 'admin', { requirePasswordChange: 'admin', enabled: false });
  assert.equal((await call('PUT', `/api/users/${other.id}`, { token, body: { enabled: true } })).status, 200);
  await new Promise((resolve) => setTimeout(resolve, 200));
  assert.equal((await defaultPasswordAlerts(reset.id)).length, 0);
  assert.equal((await defaultPasswordAlerts(other.id)).length, 0);
});

test('a sign-in with "changeme" to an account already flagged "default" raises the alert it may have missed', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  // Flagged while disabled, then enabled outside the API (SQL, a restore):
  // nothing raised it yet.
  const dormant = await createUser('missed', 'admin', { requirePasswordChange: 'default', enabled: false });
  await setDefaultPassword(dormant.id);
  await pool.query('UPDATE users SET enabled = TRUE WHERE id = $1', [dormant.id]);
  const since = (await flags(dormant.id)).since;

  const answer = await login(dormant.username, 'changeme');
  assert.equal(answer.status, 200);
  assert.equal(answer.body.passwordChangeRequired, true);
  const alerts = await eventually(() => defaultPasswordAlerts(dormant.id), (list) => list.length > 0);
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].matched_data.found, 'sign-in');
  assert.equal((await flags(dormant.id)).since.getTime(), since.getTime(), 'the flag and its date are kept');
  assert.equal((await auditRows(`action = 'auth.password.change_required' AND user_id = $2`, [dormant.id])).length, 0, 'not flagged again');

  // The right password that isn't "changeme" raises nothing.
  const other = await createUser('missed-other', 'admin', { requirePasswordChange: 'default' });
  assert.equal((await login(other.username, PASSWORD)).body.passwordChangeRequired, true);
  await new Promise((resolve) => setTimeout(resolve, 200));
  assert.equal((await defaultPasswordAlerts(other.id)).length, 0);
});

// --- The change ----------------------------------------------------------------------

test('the forced change: wrong, default, unchanged, then success clears the flag and signs out everywhere', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const user = await createUser('change', 'admin', { requirePasswordChange: 'admin' });
  const signedIn = await login(user.username, PASSWORD);
  const token: string = signedIn.body.token;
  assert.ok(signedIn.body.browserToken, 'a browser token is issued as usual');
  const other = (await SessionModel.create(user.id, 1)).token;
  const change = (currentPassword: string, newPassword: string) =>
    call('PUT', '/api/auth/me/password', { token, body: { currentPassword, newPassword } });

  const wrong = await change('not the password', 'a brand new password');
  assert.equal(wrong.status, 400);
  assert.equal(wrong.body.message, 'Current password is incorrect');
  assert.equal((await flags(user.id)).must, true);
  assert.equal((await call('GET', '/api/auth/me', { token })).status, 200, 'the session is kept');

  for (const next of ['changeme', 'CHANGEME']) {
    const refused = await change(PASSWORD, next);
    assert.equal(refused.status, 400, next);
    assert.equal(refused.body.message, "The default password can't be used");
  }
  const same = await change(PASSWORD, PASSWORD);
  assert.equal(same.status, 400);
  assert.equal(same.body.message, 'New password must be different from the current one');
  assert.equal((await flags(user.id)).must, true);

  const done = await change(PASSWORD, `${PASSWORD}-mine`);
  assert.equal(done.status, 200, JSON.stringify(done.body));
  assert.equal(done.body.message, 'Password updated. Sign in again with the new password.');
  const row = await flags(user.id);
  assert.deepEqual({ must: row.must, reason: row.reason, since: row.since }, { must: false, reason: null, since: null });
  assert.ok(row.password_changed_at, 'password_changed_at is set');
  for (const session of [token, other]) assert.equal((await call('GET', '/api/auth/me', { token: session })).status, 401);
  assert.equal(await countRows('SELECT COUNT(*)::int AS n FROM recognized_browsers WHERE user_id = $1', [user.id]), 0);
  const changed = await auditRows(`action = 'auth.password.changed' AND user_id = $2`, [user.id]);
  assert.equal(changed.length, 1);
  assert.equal(changed[0].details.forced, true);
  assert.equal(changed[0].details.reason, 'admin');

  const again = await login(user.username, `${PASSWORD}-mine`);
  assert.equal(again.status, 200);
  assert.equal(again.body.passwordChangeRequired, undefined);
  assert.equal(again.body.user.must_change_password, false);
  assert.equal((await call('GET', '/api/alerts', { token: again.body.token })).status, 200);
  assert.equal((await login(user.username, PASSWORD)).status, 401, 'the old password is gone');
});

test('a voluntary change is audited without forced', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const user = await createUser('voluntary');
  const token = (await SessionModel.create(user.id, 1)).token;
  const done = await call('PUT', '/api/auth/me/password', { token, body: { currentPassword: PASSWORD, newPassword: `${PASSWORD}-2` } });
  assert.equal(done.status, 200);
  const [row] = await auditRows(`action = 'auth.password.changed' AND user_id = $2`, [user.id]);
  assert.equal(row.details.forced, undefined);
});

test('five wrong current passwords pause the forced change (429), and the session stays restricted', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const user = await createUser('change-paused', 'viewer', { requirePasswordChange: 'cli' });
  const token = (await SessionModel.create(user.id, 1)).token;
  const statuses: number[] = [];
  let last: Answer | null = null;
  for (let i = 0; i < 5; i++) {
    last = await call('PUT', '/api/auth/me/password', { token, body: { currentPassword: `wrong-${i}`, newPassword: 'a brand new password' } });
    statuses.push(last.status);
  }
  assert.deepEqual(statuses, [400, 400, 400, 400, 429]);
  assert.equal(last!.body.code, 'SIGNIN_PAUSED');
  assert.equal(last!.body.reason, 'current_password');
  assertRestricted(await call('GET', '/api/alerts', { token }), 'cli', 'still restricted');
});

// --- Races: a sign-in or a request still running while the password changes ----------

test('a sign-in with the old password still running when it changes gets no session, and flags nothing', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  // temporary: flagged 'admin'; default: on "changeme", flagged at the owner's
  // sign-in; found: on "changeme", unflagged, the owner on a session from before.
  for (const kind of ['temporary', 'default', 'found'] as const) {
    const password = kind === 'temporary' ? PASSWORD : 'changeme';
    const user = await createUser(`race-signin-${kind}`, 'admin', { requirePasswordChange: kind === 'temporary' ? 'admin' : null });
    if (kind !== 'temporary') await setDefaultPassword(user.id);
    let ownerToken: string;
    if (kind === 'found') {
      ownerToken = (await SessionModel.create(user.id, 1)).token;
    } else {
      const owner = await login(user.username, password);
      assert.equal(owner.body.passwordChangeRequired, true, kind);
      ownerToken = owner.body.token;
    }

    // Someone else who knows the password signs in; their sign-in is held
    // after its password check while the owner changes the password.
    const held = holdNextPasswordCheck(password);
    let other: Answer;
    try {
      const pending = login(user.username, password);
      await held.reached;
      const changed = await call('PUT', '/api/auth/me/password', {
        token: ownerToken,
        body: { currentPassword: password, newPassword: `${PASSWORD}-${kind}-mine` },
      });
      assert.equal(changed.status, 200, `${kind}: ${JSON.stringify(changed.body)}`);
      held.release();
      other = await pending;
    } finally {
      held.release();
      held.restore();
    }
    assert.equal(other.status, 401, `${kind}: ${JSON.stringify(other.body)}`);
    assert.equal(other.body.message, 'Invalid username or password', kind);
    assert.equal(other.body.token, undefined, kind);
    assert.equal(await sessionsOf(user.id), 0, `${kind}: no session outlives the password it was earned with`);
    assert.equal(await browsersOf(user.id), 0, `${kind}: nor a recognized browser`);
    assert.equal((await flags(user.id)).must, false, `${kind}: the new password is not flagged`);
    const refused = await auditRows(`action = 'auth.login.failure' AND user_id = $2`, [user.id]);
    assert.deepEqual(
      refused.map((row) => [row.response_status, row.details.reason]),
      [[401, 'password_changed']],
      kind
    );
    const again = await login(user.username, `${PASSWORD}-${kind}-mine`);
    assert.equal(again.status, 200, kind);
    assert.equal(again.body.passwordChangeRequired, undefined, kind);
  }
});

test('createIfPasswordHash waits for a password change in progress, then creates nothing', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const user = await createUser('race-lock');
  const hashOf = async () => (await pool.query('SELECT password_hash FROM users WHERE id = $1', [user.id])).rows[0].password_hash;
  const oldHash: string = await hashOf();

  // What UserModel's change does: lock the row, sign out, set the new hash.
  const change = await pool.connect();
  let settled = false;
  let pending: Promise<unknown> | null = null;
  try {
    await change.query('BEGIN');
    await change.query('SELECT id FROM users WHERE id = $1 FOR UPDATE', [user.id]);
    await change.query('DELETE FROM sessions WHERE user_id = $1', [user.id]);
    await change.query('UPDATE users SET password_hash = $2 WHERE id = $1', [user.id, await bcrypt.hash('another one 1', 4)]);
    pending = SessionModel.createIfPasswordHash(user.id, oldHash, 1).finally(() => (settled = true));
    await new Promise((resolve) => setTimeout(resolve, 300));
    assert.equal(settled, false, 'the sign-in waits for the change to finish');
    await change.query('COMMIT');
    assert.equal(await pending, null, 'and then finds the new hash');
  } finally {
    await change.query('ROLLBACK').catch(() => undefined);
    change.release();
    await pending?.catch(() => undefined);
  }
  assert.equal(await sessionsOf(user.id), 0);
  assert.ok(await SessionModel.createIfPasswordHash(user.id, await hashOf(), 1), 'the current hash gets a session');
  assert.equal(await SessionModel.createIfPasswordHash(user.id + 1_000_000, oldHash, 1), null, 'no account, no session');
});

test('a restricted session gets nothing while the change or reset that lifts the restriction is finishing', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const admin = await createUser('race-req-admin', 'admin');
  const adminToken = (await SessionModel.create(admin.id, 1)).token;
  for (const path of ['self', 'admin-reset'] as const) {
    const user = await createUser(`race-req-${path}`, 'admin', { requirePasswordChange: 'admin' });
    const restricted = (await SessionModel.create(user.id, 1)).token;
    assertRestricted(await call('GET', '/api/users', { token: restricted }), 'admin', path);

    // The change has saved the new password and lifted the requirement; it is
    // held where it goes on to sign the account out (revokeAccountAccess).
    const held = holdNextSessionRevoke(user.id);
    try {
      const pending =
        path === 'self'
          ? call('PUT', '/api/auth/me/password', { token: restricted, body: { currentPassword: PASSWORD, newPassword: `${PASSWORD}-own` } })
          : call('PUT', `/api/users/${user.id}`, { token: adminToken, body: { password: `${PASSWORD}-set`, mustChangePassword: false } });
      await held.reached;
      for (const [method, url] of [['GET', '/api/users'], ['GET', '/api/alerts'], ['POST', '/api/auth/me/mfa/setup']] as const) {
        const during = await call(method, url, { token: restricted, body: method === 'GET' ? undefined : {} });
        assert.equal(during.status, 401, `${path} ${method} ${url} while the change finishes: ${JSON.stringify(during.body)}`);
      }
      held.release();
      assert.equal((await pending).status, 200, path);
    } finally {
      held.release();
      held.restore();
    }
    assert.equal((await flags(user.id)).must, false, path);
    assert.equal((await call('GET', '/api/users', { token: restricted })).status, 401, path);
  }
  const resets = await auditRows(`action = 'user.password_reset' AND user_id = $2`, [admin.id]);
  assert.equal(resets.length, 1);
  assert.equal(resets[0].details.sessionsRevoked, 1, 'the session signed out in the transaction is counted');
});

// --- MFA, disabled ------------------------------------------------------------------

test('MFA comes first, and MFA cannot be changed while restricted', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const user = await createUser('mfa', 'viewer', { requirePasswordChange: 'admin' });
  const secret = await enrollMfa(user.id);
  const noCode = await login(user.username, PASSWORD);
  assert.equal(noCode.status, 401);
  assert.equal(noCode.body.mfaRequired, true);
  assert.equal(noCode.body.token, undefined);
  const withCode = await login(user.username, PASSWORD, { code: totp.totp(secret) });
  assert.equal(withCode.status, 200);
  assert.equal(withCode.body.passwordChangeRequired, true);
  const token: string = withCode.body.token;
  assertRestricted(await call('POST', '/api/auth/me/mfa/disable', { token, body: { code: '123456' } }), 'admin', 'disable');
  assertRestricted(await call('POST', '/api/auth/me/mfa/enable', { token, body: { code: '123456' } }), 'admin', 'enable');
  assertRestricted(await call('POST', '/api/auth/me/mfa/setup', { token, body: {} }), 'admin', 'setup');
  assert.equal((await flags(user.id)).must, true);
});

test('an MFA account on "changeme" is flagged at the password step, before the code', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const user = await createUser('mfa-default');
  await enrollMfa(user.id);
  await setDefaultPassword(user.id);
  const noCode = await login(user.username, 'changeme');
  assert.equal(noCode.status, 401);
  assert.equal(noCode.body.mfaRequired, true);
  assert.equal((await flags(user.id)).reason, 'default');
});

test('a restricted, disabled account with the right password still gets 403 Account is disabled', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const user = await createUser('disabled', 'viewer', { requirePasswordChange: 'admin', enabled: false });
  const answer = await login(user.username, PASSWORD);
  assert.equal(answer.status, 403);
  assert.equal(answer.body.message, 'Account is disabled');
  assert.equal(answer.body.code, undefined);
});

// --- Admin API --------------------------------------------------------------------------

test('admin API: passwords an admin sets are temporary by default; mustChangePassword only with a password', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const admin = await createUser('api-admin', 'admin');
  const adminToken = (await SessionModel.create(admin.id, 1)).token;
  const create = (suffix: string, extra: Record<string, unknown> = {}) => {
    const username = `pcr-${tag}-${suffix}`;
    usernames.push(username);
    return call('POST', '/api/users', {
      token: adminToken,
      body: { username, email: `${username}@siembox.invalid`, password: PASSWORD, role: 'viewer', ...extra },
    });
  };

  const byDefault = await create('api-default');
  assert.equal(byDefault.status, 201, JSON.stringify(byDefault.body));
  userIds.push(byDefault.body.id);
  assert.equal(byDefault.body.must_change_password, true);
  assert.equal(byDefault.body.must_change_password_reason, 'admin');
  assert.equal((await flags(byDefault.body.id)).reason, 'admin');
  assert.equal((await login(byDefault.body.username, PASSWORD)).body.passwordChangeRequired, true);

  const optOut = await create('api-optout', { mustChangePassword: false });
  assert.equal(optOut.status, 201);
  userIds.push(optOut.body.id);
  assert.equal((await flags(optOut.body.id)).must, false);
  assert.equal((await login(optOut.body.username, PASSWORD)).body.passwordChangeRequired, undefined);

  const created = await auditRows(`action = 'user.created' AND resource_id = ANY($2)`, [[byDefault.body.id, optOut.body.id]]);
  assert.deepEqual(
    created.map((row) => row.details.passwordChangeRequired),
    ['admin', null]
  );

  const notBoolean = await create('api-yes', { mustChangePassword: 'yes' });
  assert.equal(notBoolean.status, 400);
  assert.equal(notBoolean.body.message, 'mustChangePassword must be true or false');
  for (const password of ['changeme', 'ChangeMe']) {
    const refused = await create(`api-default-pw-${password}`, { password });
    assert.equal(refused.status, 400);
    assert.equal(refused.body.message, "Password can't be the default password");
  }

  // Reset with the default: flagged 'admin', signed out.
  const target = await createUser('api-target');
  const targetToken = (await SessionModel.create(target.id, 1)).token;
  const reset = await call('PUT', `/api/users/${target.id}`, { token: adminToken, body: { password: `${PASSWORD}-tmp` } });
  assert.equal(reset.status, 200);
  assert.equal(reset.body.must_change_password, true);
  assert.equal((await flags(target.id)).reason, 'admin');
  assert.equal((await call('GET', '/api/auth/me', { token: targetToken })).status, 401, 'signed out everywhere');
  const resetRows = await auditRows(`action = 'user.password_reset' AND resource_id = $2`, [target.id]);
  assert.equal(resetRows.length, 1);
  assert.equal(resetRows[0].details.passwordChangeRequired, 'admin');
  assert.equal((await call('PUT', `/api/users/${target.id}`, { token: adminToken, body: { password: 'changeme' } })).status, 400);

  // Email only: unchanged. The field without a password: 400.
  assert.equal((await call('PUT', `/api/users/${target.id}`, { token: adminToken, body: { email: `${target.username}-2@siembox.invalid` } })).status, 200);
  assert.equal((await flags(target.id)).reason, 'admin');
  for (const value of [true, false]) {
    const alone = await call('PUT', `/api/users/${target.id}`, { token: adminToken, body: { mustChangePassword: value } });
    assert.equal(alone.status, 400);
    assert.equal(alone.body.message, 'mustChangePassword applies only when setting a password');
  }
  assert.equal(
    (await call('PUT', `/api/users/${target.id}`, { token: adminToken, body: { password: `${PASSWORD}-x`, mustChangePassword: 1 } })).status,
    400
  );

  // A reset with the requirement off clears it, even for an account found on the default.
  await UserModel.requirePasswordChange(target.id, 'default');
  await pool.query(`UPDATE users SET must_change_password_reason = 'default' WHERE id = $1`, [target.id]);
  const cleared = await call('PUT', `/api/users/${target.id}`, {
    token: adminToken,
    body: { password: `${PASSWORD}-final`, mustChangePassword: false },
  });
  assert.equal(cleared.status, 200);
  const row = await flags(target.id);
  assert.deepEqual({ must: row.must, reason: row.reason, since: row.since }, { must: false, reason: null, since: null });
  const lastReset = (await auditRows(`action = 'user.password_reset' AND resource_id = $2`, [target.id])).pop();
  assert.equal(lastReset.details.passwordChangeRequired, null);

  const list = await call('GET', '/api/users', { token: adminToken });
  const listed = list.body.find((u: { id: number }) => u.id === byDefault.body.id);
  assert.equal(listed.must_change_password, true);
  assert.equal(listed.must_change_password_reason, 'admin');
  assert.ok(listed.must_change_password_since);
  const one = await call('GET', `/api/users/${byDefault.body.id}`, { token: adminToken });
  assert.equal(one.body.must_change_password_reason, 'admin');
});

// --- CLI -------------------------------------------------------------------------------------

test('the recovery CLI: reset-password always requires a change, and status says so', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const { main } = await import('../scripts/auth-admin');
  const run = async (...argv: string[]) => {
    const out: string[] = [];
    const err: string[] = [];
    const code = await main(argv, { out: (l) => out.push(l), err: (l) => err.push(l) });
    return { code, out: out.join('\n'), err: err.join('\n') };
  };
  const user = await createUser('cli', 'admin');
  assert.match((await run('status', user.username)).out, /^password change required: no$/m);

  const reset = await run('reset-password', user.username);
  assert.equal(reset.code, 0, reset.err);
  assert.match(reset.out, /They must choose a new password at their next sign-in \(MFA, if on, is still asked first\)\./);
  const password = /\(shown only now\): (\S{20})$/m.exec(reset.out)?.[1];
  assert.ok(password, reset.out);
  const [row] = await auditRows(`action = 'user.password_reset' AND resource_id = $2`, [user.id]);
  assert.equal(row.details.by, 'cli');
  assert.equal(row.details.passwordChangeRequired, 'cli');
  assert.equal((await flags(user.id)).reason, 'cli');
  assert.match((await run('status', user.username)).out, /^password change required: yes \(cli, since \d{4}-\d\d-\d\dT[\d:.]+Z\)$/m);

  const signedIn = await login(user.username, password!);
  assert.equal(signedIn.status, 200);
  assert.equal(signedIn.body.passwordChangeRequired, true);
  assert.equal(signedIn.body.user.must_change_password_reason, 'cli');
});

// --- Agents ----------------------------------------------------------------------------------

test('shipper keys are not sessions: pushes and config work while an admin is restricted', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const admin = await createUser('agents', 'admin', { requirePasswordChange: 'default' });
  const session = (await SessionModel.create(admin.id, 1)).token;
  assertRestricted(await call('GET', '/api/shippers', { token: session }), 'default', 'the management API');

  const apiKey = crypto.randomBytes(32).toString('hex');
  const shipper = await LogShipperModel.create({ name: `pcr-${tag}-shipper`, description: 'password change test', api_key: apiKey });
  shipperIds.push(shipper.id);
  const pushKey = crypto.randomBytes(32).toString('hex');
  const pushHash = crypto.createHash('sha256').update(pushKey).digest('hex');
  shipperShortIds.push(pushHash.slice(0, 8));
  await LogShipperModel.setHttpPushKey(shipper.id, pushHash);

  const push = (bearer: string) =>
    call('POST', '/api/shippers/logs', {
      headers: { 'X-Shipper-ID': String(shipper.id), Authorization: `Bearer ${bearer}` },
      body: { message: `pcr ${tag} test log`, event_id: crypto.randomBytes(8).toString('hex') },
    });
  const pushed = await push(pushKey);
  assert.equal(pushed.status, 202, JSON.stringify(pushed.body));
  assert.equal(pushed.body.accepted, 1);
  assert.equal((await call('GET', `/api/shippers/config/${apiKey}`)).status, 200);

  // A restricted session sent as a push key is refused exactly like any other wrong key.
  const withSession = await push(session);
  const withJunk = await push(crypto.randomBytes(32).toString('hex'));
  assert.equal(withSession.status, 401);
  assert.deepEqual(withSession.body, withJunk.body);
  assert.equal(withSession.body.code, undefined);
});

// --- Model -----------------------------------------------------------------------------------

test('UserModel.update refuses a new password without a decision on requirePasswordChange', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const user = await createUser('guard');
  await assert.rejects(UserModel.update(user.id, { password: 'something new 1' } as never), /requirePasswordChange/);
  assert.equal(await (await import('bcrypt')).compare(PASSWORD, (await pool.query('SELECT password_hash FROM users WHERE id = $1', [user.id])).rows[0].password_hash), true);
  // Without a password, the requirement is left alone.
  await UserModel.requirePasswordChange(user.id, 'admin');
  await UserModel.update(user.id, { email: `${user.username}-guard@siembox.invalid` });
  assert.equal((await flags(user.id)).reason, 'admin');
});
