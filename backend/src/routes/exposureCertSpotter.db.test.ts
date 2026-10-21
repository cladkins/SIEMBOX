/**
 * The optional Cert Spotter API key end to end: the real app on an ephemeral
 * port, a real Postgres, one user (and session) per role. Nothing leaves the
 * machine: the CT source is built with fake transports.
 *
 * Covers GET/PUT /api/exposure/providers/certspotter (open view, admin-only
 * writes; viewer, analyst and operator refused), validation, clearing, the key
 * stored encrypted and never returned by any route (including the raw
 * GET /api/settings listing) or written to a log, the key reaching Cert
 * Spotter (and only Cert Spotter) as a Bearer token from the domain monitor's
 * source, and a key change lifting a rate-limit pause.
 *
 * Owns the exposure_certspotter_key row while it runs: its raw value is saved
 * first and restored after. Every user and session created here is removed
 * again. Skips itself without Postgres. Run with `npm test`.
 */
import { test, before, after, mock } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { once } from 'node:events';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import app from '../app';
import pool, { closePools } from '../config/database';
import { UserModel } from '../models/User';
import { SessionModel } from '../models/Session';
import { logger } from '../utils/logger';
import { getCertSpotterApiKey } from '../services/exposure/settings';
import { createDefaultCtSource } from '../services/exposure/domainMonitor/ctFallback';
import {
  certSpotterPausedUntil,
  resetCertSpotterRateLimit,
} from '../services/exposure/domainMonitor/certSpotter';
import { createPacer } from '../services/exposure/domainMonitor/ct';
import type { HttpGet, HttpGetOptions } from '../services/exposure/domainMonitor/http';

const ROLES = ['admin', 'operator', 'analyst', 'viewer'] as const;
type Role = (typeof ROLES)[number];
const SKIP = 'Postgres with the exposure schema is not reachable';
const OWNED = 'exposure_certspotter_key';
const PATH = '/api/exposure/providers/certspotter';
// Never sent anywhere: every transport here is fake.
const API_KEY = `123_${crypto.randomBytes(12).toString('hex')}`;
const OTHER_KEY = `456_${crypto.randomBytes(12).toString('hex')}`;
const secretTexts = [API_KEY, OTHER_KEY, API_KEY.slice(4), OTHER_KEY.slice(4)];

if (!process.env.CREDENTIAL_ENCRYPTION_KEY) {
  process.env.CREDENTIAL_ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');
}

// Everything logged while this file runs, to check the key never is.
const logged: string[] = [];
for (const level of ['error', 'warn', 'info', 'http', 'verbose', 'debug', 'log'] as const) {
  const original = (logger as any)[level].bind(logger);
  mock.method(logger, level, (...args: unknown[]) => {
    logged.push(args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' '));
    return original(...args);
  });
}

const tag = crypto.randomBytes(5).toString('hex');
const name = `certspotter-${tag}`;
let dbReady = false;
let server: Server | undefined;
let base = '';
const tokens = {} as Record<Role, string>;
const userIds: number[] = [];
let saved: { value: string; created_at: Date; updated_at: Date } | null = null;

before(async () => {
  try {
    for (const table of ['sessions', 'system_settings', 'users']) {
      await pool.query(`SELECT 1 FROM ${table} LIMIT 1`);
    }
    dbReady = true;
  } catch {
    return;
  }
  const r = await pool.query('SELECT value, created_at, updated_at FROM system_settings WHERE key = $1', [OWNED]);
  saved = r.rows[0] ?? null;
  await pool.query('DELETE FROM system_settings WHERE key = $1', [OWNED]);
  for (const role of ROLES) {
    const user = await UserModel.create({
      username: `${name}-${role}`,
      email: `${name}-${role}@siembox.invalid`,
      password: crypto.randomBytes(16).toString('hex'),
      role,
    });
    userIds.push(user.id);
    tokens[role] = (await SessionModel.create(user.id, 1)).token;
  }
  server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  if (dbReady) {
    await pool.query('DELETE FROM system_settings WHERE key = $1', [OWNED]);
    if (saved) {
      await pool.query(
        'INSERT INTO system_settings (key, value, created_at, updated_at) VALUES ($1, $2, $3, $4)',
        [OWNED, saved.value, saved.created_at, saved.updated_at]
      );
    }
    await pool.query('DELETE FROM application_errors WHERE user_id = ANY($1)', [userIds]);
    await pool.query('DELETE FROM users WHERE id = ANY($1)', [userIds]); // sessions cascade
  }
  resetCertSpotterRateLimit();
  await closePools();
});

async function call(role: Role, method: string, path: string, body?: unknown) {
  const headers: Record<string, string> = { Authorization: `Bearer ${tokens[role]}` };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text();
  // Whatever the route and outcome, the API key never comes back.
  for (const secret of secretTexts) assert.ok(!text.includes(secret), `${method} ${path} must not echo the key`);
  let json: any;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  return { status: res.status, json };
}

async function storedValue(): Promise<string> {
  const r = await pool.query('SELECT value FROM system_settings WHERE key = $1', [OWNED]);
  return r.rows[0]?.value ?? '';
}

const VIEW_KEYS = ['apiKeysUrl', 'configured', 'docsUrl', 'label', 'name', 'rate_limited_until', 'signupUrl', 'usable'];

test('every role can see whether a key is saved; only an admin can set or clear it', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  for (const role of ROLES) {
    const r = await call(role, 'GET', PATH);
    assert.equal(r.status, 200, `${role} GET`);
    assert.deepEqual(Object.keys(r.json).sort(), VIEW_KEYS);
    assert.equal(r.json.configured, false);
    assert.equal(r.json.name, 'certspotter');
  }
  for (const role of ['operator', 'analyst', 'viewer'] as const) {
    for (const body of [{ api_key: API_KEY }, { api_key: null }, { api_key: '' }]) {
      assert.equal((await call(role, 'PUT', PATH, body)).status, 403, `${role} PUT ${JSON.stringify(body)}`);
    }
  }
  assert.equal(await storedValue(), '', 'a refused request writes nothing');
});

test('validation: a key must be a string of token characters; null or "" clears', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  for (const body of [{}, { api_key: 42 }, { api_key: ['x'] }, { api_key: 'short' }, { api_key: 'has space inside' }, { api_key: 'a\r\nb-header-injection' }, { api_key: 'x'.repeat(300) }]) {
    const r = await call('admin', 'PUT', PATH, body);
    assert.equal(r.status, 400, JSON.stringify(body));
    assert.match(r.json.message, /api_key/);
  }
  assert.equal(await storedValue(), '');
});

test('an admin saves the key: stored encrypted, reported only as configured, never returned or logged', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const r = await call('admin', 'PUT', PATH, { api_key: `  ${API_KEY}  ` });
  assert.equal(r.status, 200);
  assert.deepEqual(Object.keys(r.json).sort(), VIEW_KEYS);
  assert.equal(r.json.configured, true);
  assert.equal(r.json.usable, true);

  const raw = await storedValue();
  assert.ok(!raw.includes(API_KEY) && !raw.includes(API_KEY.slice(4)), 'not stored in clear text');
  assert.deepEqual(Object.keys(JSON.parse(raw)).sort(), ['authTag', 'encrypted', 'iv']);
  assert.equal(await getCertSpotterApiKey(), API_KEY, 'trimmed, and it decrypts');

  for (const role of ROLES) {
    const view = await call(role, 'GET', PATH);
    assert.equal(view.json.configured, true, role);
  }
  // The raw settings listing withholds it too (the envelope would give the key back).
  const listing = await call('admin', 'GET', '/api/settings');
  assert.equal(listing.status, 200);
  const row = (listing.json as any[]).find((s) => s.setting_key === OWNED);
  assert.deepEqual(row, { setting_key: OWNED, setting_value: '[redacted]', redacted: true, configured: true });
  // Nor do the other Digital Risk reads.
  for (const path of ['/api/exposure/status', '/api/exposure/settings', '/api/exposure/providers']) {
    assert.equal((await call('admin', 'GET', path)).status, 200, path);
  }
});

test('the domain monitor sends the key to Cert Spotter only, as a Bearer token', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  assert.equal((await call('admin', 'PUT', PATH, { api_key: API_KEY })).status, 200);
  const seen: Array<{ host: string; options: HttpGetOptions }> = [];
  const record =
    (answer: () => Promise<any>): HttpGet =>
    async (url, options) => {
      seen.push({ host: url.host, options });
      return answer();
    };
  const pacer = createPacer(0, async () => undefined);
  const crtshDown = record(async () => ({ status: 502, headers: {}, body: Buffer.alloc(0) }));
  const emptyPage = record(async () => ({ status: 200, headers: {}, body: Buffer.from('[]') }));
  const source = await createDefaultCtSource({ crtshTransport: crtshDown, certSpotterTransport: emptyPage, pacer });
  const answer = await source.certificatesFor('example.com');
  assert.ok(!Array.isArray(answer));
  assert.equal(answer.source, 'certspotter');
  assert.deepEqual(
    seen.map((s) => [s.host, s.options.headers?.Authorization ?? null]),
    [
      ['crt.sh', null],
      ['api.certspotter.com', `Bearer ${API_KEY}`],
    ]
  );

  // Cleared: Cert Spotter is still asked, unauthenticated.
  assert.equal((await call('admin', 'PUT', PATH, { api_key: null })).status, 200);
  seen.length = 0;
  const unkeyed = await createDefaultCtSource({ crtshTransport: crtshDown, certSpotterTransport: emptyPage, pacer });
  await unkeyed.certificatesFor('example.com');
  assert.deepEqual(seen.map((s) => [s.host, s.options.headers ?? null]), [
    ['crt.sh', null],
    ['api.certspotter.com', null],
  ]);
});

test('clearing: null and "" remove the key; a new key lifts a rate-limit pause', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  for (const clear of [null, '']) {
    assert.equal((await call('admin', 'PUT', PATH, { api_key: API_KEY })).status, 200);
    const r = await call('admin', 'PUT', PATH, { api_key: clear });
    assert.equal(r.status, 200);
    assert.equal(r.json.configured, false);
    assert.equal(r.json.usable, false);
    assert.equal(await storedValue(), '');
    assert.equal(await getCertSpotterApiKey(), undefined);
  }

  // A 429 pauses Cert Spotter; the view says until when, and a key change starts afresh.
  const pacer = createPacer(0, async () => undefined);
  const limited: HttpGet = async (url) =>
    url.host === 'crt.sh'
      ? { status: 503, headers: {}, body: Buffer.alloc(0) }
      : { status: 429, headers: { 'retry-after': '3600' }, body: Buffer.alloc(0) };
  const source = await createDefaultCtSource({ crtshTransport: limited, certSpotterTransport: limited, pacer });
  await assert.rejects(source.certificatesFor('example.com'), /add one in Settings → Digital Risk/);
  assert.ok(certSpotterPausedUntil() !== null);
  const paused = await call('viewer', 'GET', PATH);
  assert.ok(Date.parse(paused.json.rate_limited_until) > Date.now() + 3_000_000);
  const saved = await call('admin', 'PUT', PATH, { api_key: OTHER_KEY });
  assert.equal(saved.json.rate_limited_until, null);
  assert.equal(certSpotterPausedUntil(), null);
});

test('an unreadable stored key is reported as not usable and warned about without its value', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  // A hand-edited row holding a plain-text key (not an envelope).
  await pool.query(
    `INSERT INTO system_settings (key, value) VALUES ($1, $2)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
    [OWNED, API_KEY]
  );
  const view = await call('admin', 'GET', PATH);
  assert.equal(view.json.configured, true);
  assert.equal(view.json.usable, false);
  const before = logged.length;
  assert.equal(await getCertSpotterApiKey(), undefined, 'not used as a key');
  assert.ok(
    logged.slice(before).some((line) => /stored Cert Spotter API key is not an encrypted value/.test(line)),
    'the operator is told to re-enter it'
  );
  await pool.query('DELETE FROM system_settings WHERE key = $1', [OWNED]);
});

test('nothing logged while this file ran carries a key', (t) => {
  if (!dbReady) return t.skip(SKIP);
  assert.ok(logged.length > 0, 'the requests were logged');
  for (const line of logged) {
    for (const secret of secretTexts) assert.ok(!line.includes(secret), `logged: ${line.slice(0, 200)}`);
  }
});
