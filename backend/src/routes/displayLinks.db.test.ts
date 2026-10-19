/**
 * Display links end to end, against a real Postgres through the real app: the
 * proxy socket (as the bundled nginx reaches it, with X-Forwarded-For) and
 * direct TCP.
 *
 * - create answers the secret once (no-store); no column but token_hash, and
 *   no list, get or audit row, holds it or its hash; lookup by hash;
 * - the screen's snapshot: the layout from the link's own row, the server's
 *   clock and version, and one envelope per panel;
 * - rotate stops the old secret at once (INVALID) and forgets its devices;
 *   pause is 403 and resume restores it; an expiry that passed is EXPIRED and
 *   extending it revives the link; revoke is REVOKED, can't be undone or
 *   changed, and frees the name;
 * - live names are unique case-insensitively; at most 50 live links;
 *   config_version moves only when the config does; validation answers name
 *   the field; bodies over 32 kB get 413;
 * - allowed_cidrs allow and refuse by the client address nginx passes on (a
 *   direct caller's X-Forwarded-For is ignored), auditing a refused network
 *   once per address;
 * - a screen's use is written once a minute per device however often it
 *   polls; its devices are trimmed to 20, the first sightings audited;
 * - every admin action is audited; the recovery CLI lists and revokes.
 *
 * Skips itself when Postgres (with migration 042) isn't reachable. It shares
 * display_links with displayIndependence.db.test.ts, which runs at the same
 * time: the 50-link limit and `revoke-display-link all` run under an
 * exclusive advisory lock that file takes shared. Links, users, sessions and
 * audit rows it creates are removed again (bdl-<tag>-...; client addresses in
 * 100.64.0.0/16 and fd00:d15b::/32).
 * Run with `npm test` (tsx --test).
 */
import { test, before, after, mock } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';

const SKIP = 'Postgres with migration 042 (display_links) is not reachable';
const tag = crypto.randomBytes(4).toString('hex');
const startedAt = new Date();
/** Held exclusive here around the live-link limit and `revoke-display-link all`; shared by displayIndependence.db.test.ts. */
const DISPLAY_TEST_LOCK = 42_042_042;

let dbReady = false;
let pool: typeof import('../config/database').default;
let closePools: () => Promise<void>;
let DisplayLinkModel: typeof import('../models/DisplayLink').DisplayLinkModel;
let resetDisplayAuthState: () => void;
let cli: typeof import('../scripts/auth-admin');
let appVersion = '';

let socketServer: http.Server | null = null;
let tcpServer: http.Server | null = null;
let tcpPort = 0;
let socketPath = '';
let socketDir = '';
const userIds: number[] = [];
const linkIds = new Set<number>();
/** Every secret this file was given, to prove none was stored or logged. */
const secrets: string[] = [];
const restoreAfter: Array<() => void> = [];
let adminToken = '';
let viewerToken = '';
let adminId = 0;
let nextAddress = 1;

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- assertions read whatever the API sent
type Json = Record<string, any>;
interface Answer {
  status: number;
  body: Json;
  headers: http.IncomingHttpHeaders;
  text: string;
}

const sha = (value: string) => crypto.createHash('sha256').update(value).digest('hex');
const CONFIG = { views: [{ title: 'Overview', panels: [{ id: 'open_alerts' }, { id: 'recent_alerts' }, { id: 'ingest' }] }] };

/** A client address of its own for each call, so no limiter bucket is shared. */
function address(): string {
  const n = nextAddress++;
  return `100.64.${Math.floor(n / 250) + 100}.${(n % 250) + 1}`;
}

function call(
  method: string,
  urlPath: string,
  opts: { body?: unknown; raw?: string; token?: string; display?: string; xff?: string; via?: 'socket' | 'tcp'; headers?: Record<string, string> } = {}
): Promise<Answer> {
  const payload = opts.raw ?? (opts.body === undefined ? undefined : JSON.stringify(opts.body));
  const headers: Record<string, string> = { 'X-Forwarded-For': opts.xff ?? address(), 'User-Agent': `bdl-${tag}`, ...(opts.headers ?? {}) };
  if (payload !== undefined) {
    headers['Content-Type'] = 'application/json';
    // Node's client frames a GET body only with a length.
    headers['Content-Length'] = String(Buffer.byteLength(payload));
  }
  if (opts.token) headers.Authorization = `Bearer ${opts.token}`;
  if (opts.display) headers['X-Display-Token'] = opts.display;
  const target = opts.via === 'tcp' ? { host: '127.0.0.1', port: tcpPort } : { socketPath };
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
        resolve({ status: res.statusCode ?? 0, body, headers: res.headers, text });
      });
    });
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

const admin = (method: string, urlPath: string, body?: unknown) => call(method, urlPath, { token: adminToken, body });
const snapshot = (display: string, xff?: string, via?: 'socket' | 'tcp') => call('GET', '/api/display/snapshot', { display, xff, via });

/** Create a link through the API; its secret is remembered. */
async function createLink(name: string, extra: Json = {}): Promise<{ id: number; token: string; body: Json }> {
  const res = await admin('POST', '/api/display-links', { name: `bdl-${tag}-${name}`, config: CONFIG, ...extra });
  assert.equal(res.status, 201, JSON.stringify(res.body));
  linkIds.add(res.body.link.id);
  secrets.push(res.body.token);
  return { id: res.body.link.id, token: res.body.token, body: res.body };
}

function assertRefused(answer: Answer, status: number, code: string, what = code): void {
  assert.equal(answer.status, status, `${what}: ${JSON.stringify(answer.body)}`);
  assert.equal(answer.body.code, code, what);
}

async function auditRows(linkId: number, action?: string) {
  const res = await pool.query(
    `SELECT action, user_id, resource_id, host(ip_address) AS ip, response_status, details, request_body::text AS request_body
       FROM audit_logs
      WHERE timestamp >= $1 AND resource_type = 'display_link' AND resource_id = $2 AND ($3::text IS NULL OR action = $3)
      ORDER BY id`,
    [startedAt, linkId, action ?? null]
  );
  return res.rows;
}

async function eventually<T>(read: () => Promise<T>, done: (value: T) => boolean, ms = 3000): Promise<T> {
  const deadline = Date.now() + ms;
  for (;;) {
    const value = await read();
    if (done(value) || Date.now() > deadline) return value;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
}

const clientRows = async (linkId: number) =>
  (await pool.query('SELECT host(ip) AS ip, user_agent, first_seen, last_seen FROM display_link_clients WHERE link_id = $1 ORDER BY last_seen', [linkId])).rows;

async function withDisplayLock<T>(work: () => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('SELECT pg_advisory_lock($1)', [DISPLAY_TEST_LOCK]);
    try {
      return await work();
    } finally {
      await client.query('SELECT pg_advisory_unlock($1)', [DISPLAY_TEST_LOCK]);
    }
  } finally {
    client.release();
  }
}

before(async () => {
  const db = await import('../config/database');
  pool = db.default;
  closePools = db.closePools;
  try {
    await pool.query('SELECT token_hash, allowed_cidrs FROM display_links LIMIT 1');
    await pool.query('SELECT 1 FROM display_link_clients LIMIT 1');
    dbReady = true;
  } catch {
    return;
  }
  DisplayLinkModel = (await import('../models/DisplayLink')).DisplayLinkModel;
  resetDisplayAuthState = (await import('../middleware/displayAuth')).resetDisplayAuthState;
  cli = await import('../scripts/auth-admin');
  appVersion = (await import('../utils/appVersion')).APP_VERSION;
  const { UserModel } = await import('../models/User');
  const { SessionModel } = await import('../models/Session');

  const { logger } = await import('../utils/logger');
  for (const transport of logger.transports) {
    const was = transport.silent;
    transport.silent = true;
    restoreAfter.push(() => (transport.silent = was));
  }

  const password = `pw-${crypto.randomBytes(9).toString('hex')}`;
  const adminUser = await UserModel.create({
    username: `bdl-${tag}-admin`,
    email: `bdl-${tag}-admin@siembox.invalid`,
    password,
    role: 'admin',
    enabled: true,
    requirePasswordChange: null,
  });
  const viewer = await UserModel.create({
    username: `bdl-${tag}-viewer`,
    email: `bdl-${tag}-viewer@siembox.invalid`,
    password,
    role: 'viewer',
    enabled: true,
    requirePasswordChange: null,
  });
  userIds.push(adminUser.id, viewer.id);
  adminId = adminUser.id;
  adminToken = (await SessionModel.create(adminUser.id)).token;
  viewerToken = (await SessionModel.create(viewer.id)).token;

  const app = (await import('../app')).default;
  const { createApiServer, listenProxySocket } = await import('../net/apiListeners');
  socketDir = fs.mkdtempSync(path.join(os.tmpdir(), 'siembox-bdl-'));
  socketPath = path.join(socketDir, 'api.sock');
  const quiet = { info: () => undefined, warn: () => undefined, error: () => undefined } as never;
  socketServer = (await listenProxySocket(app, socketPath, quiet)).server;
  assert.ok(socketServer, 'the proxy socket listens');
  tcpServer = createApiServer(app);
  tcpServer.listen(0, '127.0.0.1');
  await once(tcpServer, 'listening');
  tcpPort = (tcpServer.address() as AddressInfo).port;
});

after(async () => {
  for (const restore of restoreAfter) restore();
  for (const server of [socketServer, tcpServer]) {
    if (server) {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  }
  if (socketDir) fs.rmSync(socketDir, { recursive: true, force: true });
  if (dbReady) {
    const ids = [...linkIds];
    await pool.query(`DELETE FROM audit_logs WHERE resource_type = 'display_link' AND resource_id = ANY($1)`, [ids]);
    await pool.query('DELETE FROM display_links WHERE id = ANY($1)', [ids]);
    await pool.query('DELETE FROM audit_logs WHERE user_id = ANY($1)', [userIds]);
    await pool.query('DELETE FROM application_errors WHERE user_id = ANY($1)', [userIds]);
    await pool.query('DELETE FROM users WHERE id = ANY($1)', [userIds]);
  }
  await closePools();
});

test('create answers the secret once; nothing stored or listed holds it or its hash; lookup is by hash', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const created = await createLink('NOC wall left');
  const { token, body } = created;
  assert.match(token, /^sbd1_[A-Za-z0-9_-]{43}$/);
  assert.equal(body.path, `/display#k=${token}`);
  const res = await admin('GET', `/api/display-links/${created.id}`);
  assert.equal(res.headers['cache-control'], 'no-store');
  const link = body.link;
  assert.equal(link.name, `bdl-${tag}-NOC wall left`);
  assert.equal(link.token_hint, token.slice(-4));
  assert.equal(link.status, 'never_used');
  assert.equal(link.privacy, 'operations', 'the default privacy is the operations room');
  assert.equal(link.enabled, true);
  assert.equal(link.expires_at, null, 'never expires unless an admin sets a date');
  assert.deepEqual(link.allowed_cidrs, []);
  assert.deepEqual(link.created_by, { id: adminId, username: `bdl-${tag}-admin` });
  assert.deepEqual(link.panel_keys, ['open_alerts', 'recent_alerts:high', 'ingest']);
  assert.equal(link.view_count, 1);
  assert.equal(link.config_version, 1);
  assert.deepEqual(link.config.views[0].panels[1], { id: 'recent_alerts', min_severity: 'high' }, 'stored with its defaults');
  assert.deepEqual(link.clients, []);

  const list = await admin('GET', '/api/display-links');
  assert.equal(list.status, 200);
  assert.equal(list.body.limit, 50);
  assert.ok(list.body.links.some((l: Json) => l.id === created.id));
  for (const answer of [list, res]) {
    assert.equal(answer.text.includes(token), false, 'no secret in list or get');
    assert.equal(answer.text.includes(sha(token)), false, 'nor its hash');
    assert.equal(answer.text.includes('token_hash'), false);
  }

  const row = (await pool.query('SELECT token_hash, row_to_json(l)::text AS whole FROM display_links l WHERE id = $1', [created.id])).rows[0];
  assert.equal(row.token_hash, sha(token), 'only the sha256 is stored');
  assert.equal(row.whole.includes(token), false, 'no column holds the secret');
  assert.equal((row.whole.match(new RegExp(sha(token), 'g')) ?? []).length, 1, 'the hash is in token_hash alone');

  const found = await DisplayLinkModel.findForAuth(sha(token), '100.64.0.1');
  assert.equal(found?.id, created.id);
  assert.equal(found?.address_allowed, true, 'no allow-list: any address');
  assert.equal((await DisplayLinkModel.findForAuth(sha(token), null))?.address_allowed, true, 'and no address');
  assert.equal(await DisplayLinkModel.findForAuth(sha(token + 'x'), '100.64.0.1'), null);
});

test("the screen's snapshot: its layout, the server's clock and version, and its panels", async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const { token } = await createLink('snapshot', {
    config: { privacy: 'public', refresh_seconds: 60, timezone: 'Europe/London', views: [{ title: 'Lobby', panels: [{ id: 'open_alerts' }, { id: 'threat_map', window_days: 7 }] }] },
  });
  const before = Date.now();
  const res = await snapshot(token);
  assert.equal(res.status, 200, JSON.stringify(res.body));
  assert.equal(res.headers['cache-control'], 'no-store');
  assert.deepEqual(res.body.display, {
    name: `bdl-${tag}-snapshot`,
    config_version: 1,
    privacy: 'public',
    refresh_seconds: 60,
    rotation: { enabled: true, seconds: 20 },
    timezone: 'Europe/London',
    clock: true,
    burn_in_shift: true,
    views: [{ title: 'Lobby', panels: ['open_alerts', 'threat_map:7'] }],
  });
  // The panels themselves are covered by displayPrivacy.db.test.ts and services/display/*.test.ts.
  assert.deepEqual(Object.keys(res.body.panels).sort(), ['open_alerts', 'threat_map:7']);
  assert.equal(res.body.panels.open_alerts.state, 'ok', JSON.stringify(res.body.panels.open_alerts));
  assert.equal(res.body.panels['threat_map:7'].data.window_days, 7);
  assert.ok(Array.isArray(res.body.alarms) && res.body.alarms.length <= 4);
  assert.deepEqual(res.body.attributions, ['dbip']);
  assert.equal(res.body.app_version, appVersion);
  const serverTime = Date.parse(res.body.server_time);
  assert.ok(serverTime >= before - 1000 && serverTime <= Date.now() + 1000, res.body.server_time);
  assert.equal(new Date(serverTime).toISOString(), res.body.server_time, 'ISO 8601');
  assert.equal(res.text.includes(token), false);

  // A session is not a display credential, and a display token opens nothing else.
  assertRefused(await call('GET', '/api/display/snapshot', { token: adminToken }), 401, 'DISPLAY_TOKEN_REQUIRED');
  const elsewhere = await call('GET', '/api/display-links', { display: token });
  assert.deepEqual([elsewhere.status, elsewhere.body.message], [401, 'Authentication required']);
  const asBearer = await call('GET', '/api/alerts', { headers: { Authorization: `Bearer ${token}` } });
  assert.deepEqual([asBearer.status, asBearer.body.message], [401, 'Invalid or expired session']);
});

test('a stored config that no longer validates: the screen gets DISPLAY_CONFIG_INVALID, the error log one row, the list still loads', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const { id, token } = await createLink('broken');
  // As a newer version's panel kind would read after a downgrade.
  await pool.query(`UPDATE display_links SET config = '{"views":[{"title":"A","panels":[{"id":"future_graph"}]}]}' WHERE id = $1`, [id]);
  // Only display rows: other test files run in parallel against this database and log their own errors.
  const displayErrors = `SELECT COUNT(*)::int AS n FROM application_errors WHERE endpoint ILIKE '%display%'`;
  const errorsBefore = (await pool.query(displayErrors)).rows[0].n;
  for (let i = 0; i < 5; i++) {
    const res = await snapshot(token);
    assert.equal(res.status, 500);
    assert.equal(res.body.code, 'DISPLAY_CONFIG_INVALID');
    assert.equal(res.headers['cache-control'], 'no-store');
  }
  const errorsAfter = (await pool.query(displayErrors)).rows[0].n;
  assert.equal(errorsAfter, errorsBefore, 'a polling screen adds no application_errors rows');
  const link = (await admin('GET', `/api/display-links/${id}`)).body.link;
  assert.deepEqual([link.config, link.view_count, link.panel_keys, link.privacy], [null, 0, [], 'operations']);
  const fixed = await admin('PUT', `/api/display-links/${id}`, { config: CONFIG });
  assert.equal(fixed.status, 200, 'saving it again repairs it');
  assert.equal((await snapshot(token)).status, 200);
});

test('rotate stops the old secret at once and forgets its devices; the new one works', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const { id, token } = await createLink('rotate');
  assert.equal((await snapshot(token, '100.64.1.1')).status, 200);
  await eventually(() => clientRows(id), (rows) => rows.length === 1);
  const before = (await pool.query('SELECT token_rotated_at, token_hint FROM display_links WHERE id = $1', [id])).rows[0];

  const rotated = await admin('POST', `/api/display-links/${id}/rotate`);
  assert.equal(rotated.status, 200, JSON.stringify(rotated.body));
  assert.equal(rotated.headers['cache-control'], 'no-store');
  const fresh = rotated.body.token;
  secrets.push(fresh);
  assert.match(fresh, /^sbd1_[A-Za-z0-9_-]{43}$/);
  assert.notEqual(fresh, token);
  assert.equal(rotated.body.path, `/display#k=${fresh}`);
  assert.equal(rotated.body.link.token_hint, fresh.slice(-4));
  assert.equal(rotated.body.link.status, 'never_used', 'the old secret`s use is forgotten');
  assert.deepEqual(rotated.body.link.clients, []);
  const after = (await pool.query('SELECT token_rotated_at, token_hash FROM display_links WHERE id = $1', [id])).rows[0];
  assert.ok(after.token_rotated_at > before.token_rotated_at);
  assert.equal(after.token_hash, sha(fresh));

  assertRefused(await snapshot(token, '100.64.1.1'), 401, 'DISPLAY_LINK_INVALID', 'the old secret');
  assert.equal((await snapshot(fresh, '100.64.1.1')).status, 200, 'the new secret');
  // The same device with the new secret is a first sighting again, at once.
  const rows = await eventually(() => clientRows(id), (r) => r.length === 1);
  assert.deepEqual(rows.map((r) => r.ip), ['100.64.1.1']);
});

test("a screen's use still being written when its link is rotated or revoked is not recorded against the link", async (t) => {
  if (!dbReady) return t.skip(SKIP);
  for (const action of ['rotate', 'revoke'] as const) {
    const { id, token } = await createLink(`inflight-${action}`);
    // Hold the use's write until the admin's change has committed.
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    let written!: Promise<unknown>;
    const real = DisplayLinkModel.touch.bind(DisplayLinkModel);
    const touch = mock.method(DisplayLinkModel, 'touch', (...args: Parameters<typeof real>) => {
      written = gate.then(() => real(...args));
      return written;
    });
    try {
      assert.equal((await snapshot(token, '100.64.40.1')).status, 200, action);
      assert.equal(touch.mock.callCount(), 1);
      const changed = action === 'rotate' ? await admin('POST', `/api/display-links/${id}/rotate`) : await admin('DELETE', `/api/display-links/${id}`);
      assert.equal(changed.status, 200, JSON.stringify(changed.body));
      if (action === 'rotate') secrets.push(changed.body.token);
      release();
      await written;
      await new Promise((resolve) => setTimeout(resolve, 50));
    } finally {
      touch.mock.restore();
    }
    assert.deepEqual(await clientRows(id), [], `${action}: the old secret's device is not listed`);
    const row = (await pool.query('SELECT last_used_at FROM display_links WHERE id = $1', [id])).rows[0];
    assert.equal(row.last_used_at, null, `${action}: last_used_at is not set by the old secret`);
    if (action === 'rotate') assert.equal((await admin('GET', `/api/display-links/${id}`)).body.link.status, 'never_used');
    assert.equal((await auditRows(id, 'display_link.client_first_seen')).length, 0, `${action}: no first sighting audited`);
  }
});

test('pause is 403 and resume restores it; an expiry that passed is EXPIRED, and extending it revives the link', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const { id, token } = await createLink('pause');
  const paused = await admin('PUT', `/api/display-links/${id}`, { enabled: false });
  assert.equal(paused.status, 200);
  assert.equal(paused.body.link.status, 'paused');
  assertRefused(await snapshot(token), 403, 'DISPLAY_LINK_PAUSED');
  assert.equal((await admin('PUT', `/api/display-links/${id}`, { enabled: true })).status, 200);
  assert.equal((await snapshot(token)).status, 200, 'resumed');

  // An admin can't set a date in the past; one that passes is the same as one that was set.
  const past = await admin('PUT', `/api/display-links/${id}`, { expires_at: '2020-01-01T00:00:00Z' });
  assert.deepEqual([past.status, past.body.code, past.body.field], [400, 'DISPLAY_LINK_BAD_REQUEST', 'expires_at']);
  const soon = new Date(Date.now() + 3600_000).toISOString();
  assert.equal((await admin('PUT', `/api/display-links/${id}`, { expires_at: soon })).body.link.expires_at, soon);
  assert.equal((await snapshot(token)).status, 200, 'not yet');
  await pool.query(`UPDATE display_links SET expires_at = NOW() - INTERVAL '1 second' WHERE id = $1`, [id]);
  const expired = await snapshot(token);
  assertRefused(expired, 401, 'DISPLAY_LINK_EXPIRED');
  assert.ok(Date.parse(expired.body.expires_at) < Date.now(), 'says when');
  assert.equal((await admin('GET', `/api/display-links/${id}`)).body.link.status, 'expired');

  const later = new Date(Date.now() + 30 * 86_400_000).toISOString();
  assert.equal((await admin('PUT', `/api/display-links/${id}`, { expires_at: later })).status, 200);
  assert.equal((await snapshot(token)).status, 200, 'extended: the same link works again');
  assert.equal((await admin('PUT', `/api/display-links/${id}`, { expires_at: null })).body.link.expires_at, null, 'never');
  assert.equal((await snapshot(token)).status, 200);

  const paused2 = await auditRows(id, 'display_link.paused');
  const resumed = await auditRows(id, 'display_link.resumed');
  assert.equal(paused2.length, 1);
  assert.equal(resumed.length, 1);
  assert.deepEqual(paused2[0].details.enabled, { from: true, to: false });
  assert.deepEqual(paused2[0].details.changed, ['enabled']);
  const updates = await auditRows(id, 'display_link.updated');
  assert.equal(updates.length, 3, 'each expiry change');
  assert.deepEqual(updates[0].details.expires_at, { from: null, to: soon });
  assert.deepEqual(updates[2].details.expires_at.to, null);
});

test("revoke is REVOKED, final, and frees the name; a revoked link can't be changed or rotated", async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const { id, token } = await createLink('Lobby');
  const revoked = await admin('DELETE', `/api/display-links/${id}`);
  assert.deepEqual([revoked.status, revoked.body], [200, { revoked: true }]);
  assertRefused(await snapshot(token), 401, 'DISPLAY_LINK_REVOKED');
  const row = (await pool.query('SELECT revoked_at, token_hash FROM display_links WHERE id = $1', [id])).rows[0];
  assert.ok(row.revoked_at, 'the row stays');
  assertRefused(await admin('PUT', `/api/display-links/${id}`, { enabled: true }), 409, 'DISPLAY_LINK_REVOKED');
  assertRefused(await admin('POST', `/api/display-links/${id}/rotate`), 409, 'DISPLAY_LINK_REVOKED');
  assertRefused(await admin('DELETE', `/api/display-links/${id}`), 409, 'DISPLAY_LINK_REVOKED');
  assert.equal((await admin('GET', `/api/display-links/${id}`)).body.link.status, 'revoked');

  const live = await admin('GET', '/api/display-links');
  assert.equal(live.body.links.some((l: Json) => l.id === id), false, 'the list leaves revoked links out');
  const all = await admin('GET', '/api/display-links?include_revoked=true');
  assert.equal(all.body.links.find((l: Json) => l.id === id)?.status, 'revoked');

  const again = await createLink('lobby');
  assert.notEqual(again.id, id, 'the name is free again');
  assertRefused(await admin('GET', '/api/display-links/999999999'), 404, 'DISPLAY_LINK_NOT_FOUND');
  assertRefused(await admin('PUT', '/api/display-links/abc', { enabled: true }), 404, 'DISPLAY_LINK_NOT_FOUND');
  assertRefused(await admin('POST', '/api/display-links/0/rotate'), 404, 'DISPLAY_LINK_NOT_FOUND');
});

test('live names are unique whatever their case; config_version moves only when the config does', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const first = await createLink('NOC Wall');
  const clash = await admin('POST', '/api/display-links', { name: `bdl-${tag}-noc wall`, config: CONFIG });
  assertRefused(clash, 409, 'DISPLAY_LINK_NAME_TAKEN');
  const other = await createLink('Ops');
  assertRefused(await admin('PUT', `/api/display-links/${other.id}`, { name: `BDL-${tag}-NOC WALL` }), 409, 'DISPLAY_LINK_NAME_TAKEN');

  const same = await admin('PUT', `/api/display-links/${first.id}`, { config: { views: [{ panels: [{ id: 'open_alerts' }, { id: 'recent_alerts', min_severity: 'high' }, { id: 'ingest' }], title: 'Overview' }] } });
  assert.equal(same.body.link.config_version, 1, 'the same config, spelled differently');
  const renamed = await admin('PUT', `/api/display-links/${first.id}`, { name: `bdl-${tag}-NOC Wall East` });
  assert.equal(renamed.body.link.config_version, 1, 'a rename is no layout change');
  const changed = await admin('PUT', `/api/display-links/${first.id}`, { config: { privacy: 'public', views: [{ title: 'Lobby', panels: [{ id: 'alert_pulse' }] }] } });
  assert.equal(changed.status, 200, JSON.stringify(changed.body));
  assert.equal(changed.body.link.config_version, 2);
  assert.equal(changed.body.link.privacy, 'public');
  const shown = await snapshot(first.token);
  assert.equal(shown.body.display.config_version, 2, 'the screen sees the new layout at its next refresh');
  assert.deepEqual(shown.body.display.views, [{ title: 'Lobby', panels: ['alert_pulse'] }]);

  const audit = await auditRows(first.id, 'display_link.updated');
  const privacy = audit.find((row) => row.details.privacy);
  assert.deepEqual(privacy?.details.privacy, { from: 'operations', to: 'public' });
  assert.deepEqual(privacy?.details.changed, ['config']);
  const rename = audit.find((row) => row.details.changed.includes('name'));
  assert.deepEqual(rename?.details.name_change, { from: `bdl-${tag}-NOC Wall`, to: `bdl-${tag}-NOC Wall East` });
});

test('validation answers name the field; bodies over 32 kB are refused; only admins manage links', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const endpoints = await admin('POST', '/api/display-links', { name: `bdl-${tag}-edr`, config: { views: [{ title: 'A', panels: [{ id: 'endpoints' }] }] } });
  assert.deepEqual(
    [endpoints.status, endpoints.body.code, endpoints.body.field],
    [400, 'DISPLAY_CONFIG_INVALID', 'config.views[0].panels[0].id']
  );
  assert.match(endpoints.body.message, /Endpoint health is admin-only/);
  const publicRules = await admin('POST', '/api/display-links', {
    name: `bdl-${tag}-lobby-rules`,
    config: { privacy: 'public', views: [{ title: 'A', panels: [{ id: 'top_rules' }] }] },
  });
  assert.deepEqual([publicRules.status, publicRules.body.field], [400, 'config.views[0].panels[0].id']);
  const unknown = await admin('POST', '/api/display-links', { name: `bdl-${tag}-x`, config: CONFIG, owner: 'me' });
  assert.deepEqual([unknown.status, unknown.body.code, unknown.body.field], [400, 'DISPLAY_LINK_BAD_REQUEST', 'owner']);
  const cidr = await admin('POST', '/api/display-links', { name: `bdl-${tag}-x`, config: CONFIG, allowed_cidrs: ['10.0.0.0/8', 'lan'] });
  assert.deepEqual([cidr.status, cidr.body.field], [400, 'allowed_cidrs[1]']);

  const huge = JSON.stringify({ name: `bdl-${tag}-huge`, config: { ...CONFIG, pad: 'x'.repeat(33 * 1024) } });
  const tooLarge = await call('POST', '/api/display-links', { token: adminToken, raw: huge });
  assert.equal(tooLarge.status, 413, 'over 32 kB');
  const bigConfig = await admin('POST', '/api/display-links', { name: `bdl-${tag}-big`, config: { ...CONFIG, pad: 'x'.repeat(17 * 1024) } });
  assert.deepEqual([bigConfig.status, bigConfig.body.field], [400, 'config'], 'under 32 kB but a config over 16 kB');
  const tooLargeGet = await call('GET', '/api/display/snapshot', { raw: JSON.stringify({ pad: 'x'.repeat(33 * 1024) }) });
  assert.equal(tooLargeGet.status, 413, 'the screen route has the same cap: ' + tooLargeGet.text);

  const viewer = await call('GET', '/api/display-links', { token: viewerToken });
  assert.equal(viewer.status, 403);
  const viewerCreate = await call('POST', '/api/display-links', { token: viewerToken, body: { name: `bdl-${tag}-v`, config: CONFIG } });
  assert.equal(viewerCreate.status, 403);
  assert.equal((await pool.query('SELECT COUNT(*)::int AS n FROM display_links WHERE name LIKE $1', [`bdl-${tag}-v`])).rows[0].n, 0);
});

test('allowed networks: by the address nginx passes on, never a direct caller`s X-Forwarded-For; refusals audited once per address', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const { id, token } = await createLink('fenced', { allowed_cidrs: ['100.64.10.7/24', 'fd00:d15b::/32'] });
  const link = (await admin('GET', `/api/display-links/${id}`)).body.link;
  assert.deepEqual(link.allowed_cidrs, ['100.64.10.0/24', 'fd00:d15b::/32'], 'normalized to network form');

  assert.equal((await snapshot(token, '100.64.10.7')).status, 200, 'inside');
  assert.equal((await snapshot(token, 'fd00:d15b::5')).status, 200, 'inside, IPv6');
  assertRefused(await snapshot(token, '100.64.11.7'), 403, 'DISPLAY_NETWORK_NOT_ALLOWED');
  assertRefused(await snapshot(token, '100.64.11.7'), 403, 'DISPLAY_NETWORK_NOT_ALLOWED');
  assertRefused(await snapshot(token, '100.64.11.8'), 403, 'DISPLAY_NETWORK_NOT_ALLOWED');
  // Direct TCP: the peer is 127.0.0.1, whatever X-Forwarded-For claims.
  assertRefused(await snapshot(token, '100.64.10.7', 'tcp'), 403, 'DISPLAY_NETWORK_NOT_ALLOWED');
  // Only paused and fenced are 403; neither counts against the failed-lookup limiter, so this address can keep trying.
  const refusedRows = await eventually(() => auditRows(id, 'display_link.refused_network'), (rows) => rows.length >= 3);
  assert.deepEqual(refusedRows.map((row) => row.ip).sort(), ['100.64.11.7', '100.64.11.8', '127.0.0.1']);
  assert.ok(refusedRows.every((row) => row.user_id === null && row.response_status === 403 && row.details.name === `bdl-${tag}-fenced`));

  assert.equal((await admin('PUT', `/api/display-links/${id}`, { allowed_cidrs: [] })).status, 200);
  assert.equal((await snapshot(token, '100.64.11.7')).status, 200, 'an empty list allows any network');
  const update = (await auditRows(id, 'display_link.updated')).at(-1);
  assert.deepEqual(update.details.allowed_cidrs, { from: ['100.64.10.0/24', 'fd00:d15b::/32'], to: [] });

  // With an allow-list, a request with no address at all is refused (COALESCE in findForAuth).
  await pool.query(`UPDATE display_links SET allowed_cidrs = '{100.64.10.0/24}' WHERE id = $1`, [id]);
  assert.equal((await DisplayLinkModel.findForAuth(sha(token), null))?.address_allowed, false);
});

test("a screen's use is written once a minute per device however often it polls", async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const { id, token } = await createLink('poller');
  const touch = mock.method(DisplayLinkModel, 'touch');
  try {
    for (let i = 0; i < 10; i++) assert.equal((await snapshot(token, '100.64.20.1')).status, 200);
    const rows = await eventually(() => clientRows(id), (r) => r.length === 1);
    assert.equal(touch.mock.callCount(), 1, 'one write for ten polls');
    assert.equal(rows[0].user_agent, `bdl-${tag}`);
    const firstSeen = rows[0].last_seen;
    const used = (await pool.query('SELECT last_used_at FROM display_links WHERE id = $1', [id])).rows[0].last_used_at;
    assert.ok(used, 'last_used_at is set');
    assert.equal((await admin('GET', `/api/display-links/${id}`)).body.link.status, 'live');

    const realNow = Date.now;
    const later = mock.method(Date, 'now', () => realNow() + 61_000);
    try {
      assert.equal((await snapshot(token, '100.64.20.1')).status, 200);
    } finally {
      later.mock.restore();
    }
    const after = await eventually(() => clientRows(id), (r) => r[0].last_seen > firstSeen);
    assert.equal(touch.mock.callCount(), 2, 'a minute later, the next write');
    assert.ok(after[0].last_seen > firstSeen);
    assert.equal(after.length, 1);
  } finally {
    touch.mock.restore();
  }
  const first = await auditRows(id, 'display_link.client_first_seen');
  assert.equal(first.length, 1, 'the first sighting only');
  assert.equal(first[0].ip, '100.64.20.1');
});

test('a link keeps its 20 most recently seen devices; first sightings are audited, at most 10 an hour', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const { id, token } = await createLink('crowd');
  for (let i = 1; i <= 22; i++) {
    assert.equal((await snapshot(token, `100.64.30.${i}`)).status, 200);
    // Let each write (and its audit row) land, so "most recently seen" and
    // "first" are the order the screens came in.
    await eventually(() => clientRows(id), (rows) => rows.some((r) => r.ip === `100.64.30.${i}`));
    if (i <= 10) await eventually(() => auditRows(id, 'display_link.client_first_seen'), (r) => r.length === i);
  }
  await new Promise((resolve) => setTimeout(resolve, 100));
  const rows = await eventually(() => clientRows(id), (r) => r.length === 20);
  assert.equal(rows.length, 20);
  const ips = rows.map((r) => r.ip);
  assert.equal(ips.includes('100.64.30.1'), false, 'the least recently seen go first');
  assert.equal(ips.includes('100.64.30.2'), false);
  assert.ok(ips.includes('100.64.30.22'));
  const link = (await admin('GET', `/api/display-links/${id}`)).body.link;
  assert.equal(link.clients.length, 20);
  assert.equal(link.clients[0].ip, '100.64.30.22', 'most recent first');
  assert.equal(link.clients_24h, 20);
  assert.deepEqual(link.last_client, { ip: '100.64.30.22', user_agent: `bdl-${tag}` });
  const audited = await eventually(() => auditRows(id, 'display_link.client_first_seen'), (r) => r.length >= 10);
  assert.equal(audited.length, 10);
  assert.deepEqual(audited.map((row) => row.ip), Array.from({ length: 10 }, (_, i) => `100.64.30.${i + 1}`));
});

test('at most 50 live links', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const { parseDisplayConfig } = await import('../services/display/config');
  const parsed = parseDisplayConfig(CONFIG);
  assert.ok(parsed.ok);
  const config = parsed.value;
  await withDisplayLock(async () => {
    const live = await DisplayLinkModel.countLive();
    const fillers: number[] = [];
    try {
      for (let i = live; i < 50; i++) {
        const { link } = await DisplayLinkModel.create({ name: `bdl-${tag}-filler-${i}`, config, expiresAt: null, allowedCidrs: [], userId: adminId });
        fillers.push(link.id);
        linkIds.add(link.id);
      }
      assert.equal(await DisplayLinkModel.countLive(), 50);
      const refused = await admin('POST', '/api/display-links', { name: `bdl-${tag}-one-too-many`, config: CONFIG });
      assertRefused(refused, 409, 'DISPLAY_LINK_LIMIT');
      assert.match(refused.body.message, /50 display links/);
      // A revoked link doesn't count.
      if (fillers.length > 0) {
        assert.equal((await admin('DELETE', `/api/display-links/${fillers.pop()}`)).status, 200);
        await createLink('one-more');
      }
    } finally {
      for (const id of fillers) await DisplayLinkModel.revoke(id, adminId).catch(() => undefined);
    }
  });
});

test('every admin action is audited, and no audit row holds a secret or its hash', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const { id, token } = await createLink('audited', { expires_at: new Date(Date.now() + 86_400_000).toISOString() });
  await admin('PUT', `/api/display-links/${id}`, { enabled: false });
  await admin('PUT', `/api/display-links/${id}`, { enabled: true });
  await admin('PUT', `/api/display-links/${id}`, { name: `bdl-${tag}-audited-2`, allowed_cidrs: ['100.64.40.0/24'] });
  const rotated = await admin('POST', `/api/display-links/${id}/rotate`);
  secrets.push(rotated.body.token);
  await admin('DELETE', `/api/display-links/${id}`);
  const rows = await auditRows(id);
  assert.deepEqual(
    rows.map((row) => row.action),
    ['display_link.created', 'display_link.paused', 'display_link.resumed', 'display_link.updated', 'display_link.rotated', 'display_link.revoked']
  );
  for (const row of rows) {
    assert.equal(row.user_id, adminId);
    assert.ok(row.details.name, `${row.action} names the link`);
    assert.ok(['proxy-socket', 'trusted-proxy', 'direct'].includes(row.details.via));
    assert.match(row.ip, /^100\.64\./);
  }
  const created = rows[0];
  assert.equal(created.response_status, 201);
  assert.deepEqual(created.details.panel_keys, ['open_alerts', 'recent_alerts:high', 'ingest']);
  assert.equal(created.details.privacy, 'operations');
  const update = rows[3];
  assert.deepEqual(update.details.changed.sort(), ['allowed_cidrs', 'name']);
  assert.deepEqual(update.details.allowed_cidrs, { from: [], to: ['100.64.40.0/24'] });

  // Every row this file caused, against every secret it was given.
  const all = (
    await pool.query(
      `SELECT action, details::text AS details, request_body::text AS request_body FROM audit_logs
        WHERE timestamp >= $1 AND resource_type = 'display_link' AND resource_id = ANY($2)`,
      [startedAt, [...linkIds]]
    )
  ).rows;
  assert.ok(all.length > 20, `${all.length} rows`);
  assert.ok(secrets.length >= 10);
  for (const row of all) {
    for (const secret of [...secrets, token]) {
      for (const text of [row.details ?? '', row.request_body ?? '']) {
        assert.equal(text.includes(secret), false, `${row.action} holds a secret`);
        assert.equal(text.includes(sha(secret)), false, `${row.action} holds a secret's hash`);
        assert.equal(text.includes(secret.slice(5, 20)), false, `${row.action} holds part of a secret`);
      }
    }
  }
});

test('the recovery CLI lists links and revokes one, or every live one', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const one = await createLink('cli-one');
  const two = await createLink('cli-two');
  const out: string[] = [];
  const err: string[] = [];
  const io = { out: (line: string) => out.push(line), err: (line: string) => err.push(line) };

  assert.equal(await cli.main(['display-links'], io), 0);
  const line = out.find((l) => l.includes(`bdl-${tag}-cli-one`));
  assert.ok(line, out.join('\n'));
  assert.match(line, new RegExp(`^\\s*${one.id}\\s+bdl-${tag}-cli-one\\s+never_used\\s+last used never\\s+created by bdl-${tag}-admin$`));
  assert.equal(out.join('\n').includes(one.token), false, 'never a secret');

  out.length = 0;
  assert.equal(await cli.main(['revoke-display-link', String(one.id)], io), 0);
  assert.match(out[0], new RegExp(`^Revoked display link ${one.id} \\(bdl-${tag}-cli-one\\)`));
  assertRefused(await snapshot(one.token), 401, 'DISPLAY_LINK_REVOKED');
  const [row] = await auditRows(one.id, 'display_link.revoked');
  assert.deepEqual([row.user_id, row.details.by, row.details.name, row.ip], [null, 'cli', `bdl-${tag}-cli-one`, null]);
  assert.equal(await cli.main(['revoke-display-link', String(one.id)], io), 1);
  assert.match(err.at(-1)!, /already revoked/);
  assert.equal(await cli.main(['revoke-display-link', '999999999'], io), 1);
  assert.equal(await cli.main(['revoke-display-link', 'some'], io), 1);
  assert.equal(await cli.main(['revoke-display-link'], io), 1);

  out.length = 0;
  assert.equal(await cli.main(['display-links', '--all'], io), 0);
  assert.ok(out.some((l) => l.includes(`bdl-${tag}-cli-one`) && l.includes('revoked')));

  await withDisplayLock(async () => {
    // `all` revokes every live link in the database: put back the ones this file didn't make.
    const others = (await pool.query('SELECT id FROM display_links WHERE revoked_at IS NULL AND NOT (id = ANY($1))', [[...linkIds]])).rows.map((r) => r.id);
    try {
      out.length = 0;
      assert.equal(await cli.main(['revoke-display-link', 'all'], io), 0);
      assert.match(out[0], /^Revoked \d+ display link\(s\)/);
      assertRefused(await snapshot(two.token), 401, 'DISPLAY_LINK_REVOKED');
      assert.equal(await DisplayLinkModel.countLive(), 0);
      assert.equal((await auditRows(two.id, 'display_link.revoked'))[0].details.by, 'cli');
    } finally {
      await pool.query('UPDATE display_links SET revoked_at = NULL WHERE id = ANY($1)', [others]);
      await pool.query(`DELETE FROM audit_logs WHERE action = 'display_link.revoked' AND resource_id = ANY($1) AND timestamp >= $2`, [others, startedAt]);
    }
  });
  resetDisplayAuthState();
});
