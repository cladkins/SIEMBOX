/**
 * Display links belong to the install, not to the admin who made them
 * (docs/architecture/BIG-DISPLAY.md §4.5), against a real Postgres through
 * the real app on the proxy socket:
 *
 * - the creator changing their password, an `auth-admin reset-password`, and
 *   their sessions ending or being cleaned up leave their links working;
 * - while the creator must change their password, their screens stay at 200
 *   and their own admin calls answer 403 PASSWORD_CHANGE_REQUIRED;
 * - deleting the creator sets created_by (and updated_by) to NULL, the list
 *   says so, and the link keeps working;
 * - 50 failed display lookups from one address add no login_throttle rows and
 *   no auth.* audit rows, and a sign-in from that address then succeeds.
 *
 * Skips itself when Postgres (with migration 042) isn't reachable. Each test
 * holds the display test lock shared (displayLinks.db.test.ts takes it
 * exclusive around the 50-link limit and `revoke-display-link all`). Users,
 * links, sessions, counters and audit rows it creates are removed again
 * (bdi-<tag>-...; client addresses in 100.65.0.0/16).
 * Run with `npm test` (tsx --test).
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

process.env.CREDENTIAL_ENCRYPTION_KEY ||= crypto.randomBytes(32).toString('hex');

const SKIP = 'Postgres with migration 042 (display_links) is not reachable';
const tag = crypto.randomBytes(4).toString('hex');
const PASSWORD = `pw-${crypto.randomBytes(9).toString('hex')}`;
const TEST_NET = '100.65.0.0/16';
const DISPLAY_TEST_LOCK = 42_042_042;
const startedAt = new Date();

let dbReady = false;
let pool: typeof import('../config/database').default;
let closePools: () => Promise<void>;
let UserModel: typeof import('../models/User').UserModel;
let SessionModel: typeof import('../models/Session').SessionModel;
let cli: typeof import('../scripts/auth-admin');
let socketServer: http.Server | null = null;
let socketPath = '';
let socketDir = '';
const userIds: number[] = [];
const linkIds: number[] = [];
const restoreAfter: Array<() => void> = [];
let nextAddress = 1;

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- assertions read whatever the API sent
type Json = Record<string, any>;
interface Answer {
  status: number;
  body: Json;
}

function address(): string {
  const n = nextAddress++;
  return `100.65.${Math.floor(n / 250) + 1}.${(n % 250) + 1}`;
}

function call(method: string, urlPath: string, opts: { body?: unknown; token?: string; display?: string; xff?: string } = {}): Promise<Answer> {
  const payload = opts.body === undefined ? undefined : JSON.stringify(opts.body);
  const headers: Record<string, string> = { 'X-Forwarded-For': opts.xff ?? address() };
  if (payload !== undefined) {
    headers['Content-Type'] = 'application/json';
    headers['Content-Length'] = String(Buffer.byteLength(payload));
  }
  if (opts.token) headers.Authorization = `Bearer ${opts.token}`;
  if (opts.display) headers['X-Display-Token'] = opts.display;
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

const snapshot = (display: string, xff?: string) => call('GET', '/api/display/snapshot', { display, xff });

async function createAdmin(suffix: string) {
  const username = `bdi-${tag}-${suffix}`;
  const user = await UserModel.create({
    username,
    email: `${username}@siembox.invalid`,
    password: PASSWORD,
    role: 'admin',
    enabled: true,
    requirePasswordChange: null,
  });
  userIds.push(user.id);
  return { ...user, token: (await SessionModel.create(user.id)).token };
}

async function createLink(sessionToken: string, name: string): Promise<{ id: number; token: string }> {
  const res = await call('POST', '/api/display-links', {
    token: sessionToken,
    body: { name: `bdi-${tag}-${name}`, config: { views: [{ title: 'Wall', panels: [{ id: 'open_alerts' }] }] } },
  });
  assert.equal(res.status, 201, JSON.stringify(res.body));
  linkIds.push(res.body.link.id);
  return { id: res.body.link.id, token: res.body.token };
}

async function assertWorks(display: string, what: string): Promise<void> {
  const res = await snapshot(display);
  assert.equal(res.status, 200, `${what}: ${JSON.stringify(res.body)}`);
  assert.ok(res.body.display, what);
}

/** Run a test body while holding the display test lock shared. */
async function sharedLock<T>(work: () => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('SELECT pg_advisory_lock_shared($1)', [DISPLAY_TEST_LOCK]);
    try {
      return await work();
    } finally {
      await client.query('SELECT pg_advisory_unlock_shared($1)', [DISPLAY_TEST_LOCK]);
    }
  } finally {
    client.release();
  }
}

const quietIo = () => {
  const out: string[] = [];
  return { out, io: { out: (line: string) => out.push(line), err: (line: string) => out.push(line) } };
};

before(async () => {
  const db = await import('../config/database');
  pool = db.default;
  closePools = db.closePools;
  try {
    await pool.query('SELECT token_hash FROM display_links LIMIT 1');
    await pool.query('SELECT must_change_password FROM users LIMIT 1');
    dbReady = true;
  } catch {
    return;
  }
  UserModel = (await import('../models/User')).UserModel;
  SessionModel = (await import('../models/Session')).SessionModel;
  cli = await import('../scripts/auth-admin');
  (await import('../services/auth/signInPolicy')).reloadSignInSettings();

  const { logger } = await import('../utils/logger');
  for (const transport of logger.transports) {
    const was = transport.silent;
    transport.silent = true;
    restoreAfter.push(() => (transport.silent = was));
  }

  const app = (await import('../app')).default;
  const { listenProxySocket } = await import('../net/apiListeners');
  socketDir = fs.mkdtempSync(path.join(os.tmpdir(), 'siembox-bdi-'));
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
    await pool.query(`DELETE FROM audit_logs WHERE resource_type = 'display_link' AND resource_id = ANY($1)`, [linkIds]);
    await pool.query('DELETE FROM display_links WHERE id = ANY($1)', [linkIds]);
    await pool.query(
      `DELETE FROM audit_logs WHERE timestamp >= $1 AND (user_id = ANY($2) OR (resource_type = 'user' AND resource_id = ANY($2)) OR ip_address <<= $3::inet)`,
      [startedAt, userIds, TEST_NET]
    );
    await pool.query('DELETE FROM login_throttle WHERE user_id = ANY($1) OR network <<= $2::inet', [userIds, TEST_NET]);
    const { usernameHash } = await import('../services/auth/signInPolicy');
    const names = (await pool.query('SELECT username FROM users WHERE id = ANY($1)', [userIds])).rows.map((r) => r.username as string);
    if (names.length > 0) {
      await pool.query('DELETE FROM login_throttle WHERE key = ANY($1) OR key LIKE ANY($2)', [
        names.map((name) => `acct:${usernameHash(name)}`),
        names.map((name) => `aip:${usernameHash(name)}:%`),
      ]);
    }
    await pool.query('DELETE FROM application_errors WHERE user_id = ANY($1)', [userIds]);
    await pool.query('DELETE FROM users WHERE id = ANY($1)', [userIds]);
  }
  await closePools();
});

test("the creator's password change, a CLI reset and their sessions ending leave their links working", async (t) => {
  if (!dbReady) return t.skip(SKIP);
  await sharedLock(async () => {
    const creator = await createAdmin('changer');
    const { token } = await createLink(creator.token, 'changer-wall');
    await assertWorks(token, 'just created');

    const changed = await call('PUT', '/api/auth/me/password', {
      token: creator.token,
      body: { currentPassword: PASSWORD, newPassword: `${PASSWORD}-new` },
    });
    assert.equal(changed.status, 200, JSON.stringify(changed.body));
    assert.equal((await call('GET', '/api/auth/me', { token: creator.token })).status, 401, 'the change signed the creator out');
    await assertWorks(token, "after the creator's own password change");

    const { io } = quietIo();
    assert.equal(await cli.main(['reset-password', creator.username], io), 0);
    await assertWorks(token, 'after auth-admin reset-password');

    await SessionModel.create(creator.id, -1); // one that has already expired
    assert.ok((await SessionModel.deleteExpired()) >= 1, 'session cleanup ran');
    await SessionModel.deleteAllForUser(creator.id);
    await assertWorks(token, "after the creator's sessions are gone");
  });
});

test('while the creator must change their password, their screens stay at 200 and their admin calls get PASSWORD_CHANGE_REQUIRED', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  await sharedLock(async () => {
    const creator = await createAdmin('restricted');
    const { id, token } = await createLink(creator.token, 'restricted-wall');
    assert.ok(await UserModel.requirePasswordChange(creator.id, 'admin'));
    for (const [method, urlPath] of [
      ['GET', '/api/display-links'],
      ['GET', `/api/display-links/${id}`],
      ['POST', `/api/display-links/${id}/rotate`],
    ] as const) {
      const refused = await call(method, urlPath, { token: creator.token });
      assert.equal(refused.status, 403, `${method} ${urlPath}`);
      assert.equal(refused.body.code, 'PASSWORD_CHANGE_REQUIRED');
    }
    for (let i = 0; i < 3; i++) await assertWorks(token, 'a screen of a restricted creator');
  });
});

test('deleting the creator keeps the link: created_by becomes NULL and the screen keeps working', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  await sharedLock(async () => {
    const creator = await createAdmin('leaver');
    const other = await createAdmin('stayer');
    const { id, token } = await createLink(creator.token, 'leaver-wall');
    assert.equal((await call('PUT', `/api/display-links/${id}`, { token: creator.token, body: { enabled: true } })).status, 200);

    const deleted = await call('DELETE', `/api/users/${creator.id}`, { token: other.token });
    assert.equal(deleted.status, 200, JSON.stringify(deleted.body));
    const row = (await pool.query('SELECT created_by, updated_by, revoked_at FROM display_links WHERE id = $1', [id])).rows[0];
    assert.deepEqual(row, { created_by: null, updated_by: null, revoked_at: null });
    await assertWorks(token, 'after its creator was deleted');

    // The screen's use is recorded after its response is sent, so give that
    // write a moment to land before reading the status.
    let link = (await call('GET', `/api/display-links/${id}`, { token: other.token })).body.link;
    for (let i = 0; i < 40 && link.status !== 'live'; i++) {
      await new Promise((resolve) => setTimeout(resolve, 50));
      link = (await call('GET', `/api/display-links/${id}`, { token: other.token })).body.link;
    }
    assert.equal(link.created_by, null, 'the list says "deleted user"');
    assert.equal(link.status, 'live');
    const { out, io } = quietIo();
    assert.equal(await cli.main(['display-links'], io), 0);
    assert.ok(out.some((line) => line.includes(`bdi-${tag}-leaver-wall`) && line.endsWith('created by deleted user')), out.join('\n'));
  });
});

test('50 failed display lookups from one address add no sign-in counters, and a sign-in from there succeeds', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  await sharedLock(async () => {
    const admin = await createAdmin('signer');
    const from = '100.65.200.1';
    const counters = async () =>
      (await pool.query('SELECT COUNT(*)::int AS n FROM login_throttle WHERE network = $1::inet OR key LIKE $2', [from, `%${from}%`])).rows[0].n;
    assert.equal(await counters(), 0);

    const statuses: number[] = [];
    for (let i = 0; i < 50; i++) {
      const token = i % 2 ? 'sbd1_' + crypto.randomBytes(32).toString('base64url') : 'not-a-display-link';
      statuses.push((await snapshot(token, from)).status);
    }
    assert.deepEqual(statuses.slice(0, 30), new Array(30).fill(401), 'answered until the limit');
    assert.deepEqual(statuses.slice(30), new Array(20).fill(429), 'then limited, by the display limiter alone');

    assert.equal(await counters(), 0, 'no login_throttle row');
    const authRows = await pool.query(
      `SELECT COUNT(*)::int AS n FROM audit_logs WHERE timestamp >= $1 AND ip_address = $2::inet AND action LIKE 'auth.%'`,
      [startedAt, from]
    );
    assert.equal(authRows.rows[0].n, 0, 'no auth.* audit row');

    const signIn = await call('POST', '/api/auth/login', { xff: from, body: { username: admin.username, password: PASSWORD } });
    assert.equal(signIn.status, 200, JSON.stringify(signIn.body));
    assert.ok(signIn.body.token, 'a session');
    assert.equal((await call('GET', '/api/display-links', { token: signIn.body.token, xff: from })).status, 200, 'and it works from there');
  });
});
