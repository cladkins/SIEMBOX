/**
 * GET/PUT /api/settings/public-url end to end: the real app on an ephemeral
 * port, a real Postgres, one user per role. Only admins read or change the
 * setting; an invalid value is a 400 naming the problem and changes nothing;
 * a valid one is stored normalised; the setting wins over SIEMBOX_PUBLIC_URL
 * and clearing it falls back to the env var. Then the link reaches a real
 * channel: the test alert is sent to an ntfy channel served by this test, whose
 * request carries the alert-list link in the Click header and the body.
 *
 * The public_url row, SIEMBOX_PUBLIC_URL and the enabled channels are put back
 * as they were. Skips itself when Postgres isn't reachable. Run with `npm test`.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import http from 'node:http';
import { once } from 'node:events';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import app from '../app';
import pool, { closePools } from '../config/database';
import { UserModel } from '../models/User';
import { SessionModel } from '../models/Session';
import { getPublicUrl, PUBLIC_URL_ENV, PUBLIC_URL_SETTING_KEY } from '../services/settings/publicUrl';

const ROLES = ['admin', 'operator', 'analyst', 'viewer'] as const;
type Role = (typeof ROLES)[number];
const SKIP = 'Postgres with the settings schema is not reachable';

let dbReady = false;
let server: Server | undefined;
let base = '';
const tag = crypto.randomBytes(6).toString('hex');
const tokens = {} as Record<Role, string>;
const userIds: number[] = [];
let savedSetting: string | null = null;
const savedEnv = process.env[PUBLIC_URL_ENV];
let disabledChannels: number[] = [];

before(async () => {
  try {
    for (const table of ['system_settings', 'sessions', 'notification_channels']) {
      await pool.query(`SELECT 1 FROM ${table} LIMIT 1`);
    }
    dbReady = true;
  } catch {
    return;
  }
  delete process.env[PUBLIC_URL_ENV];
  const stored = await pool.query('SELECT value FROM system_settings WHERE key = $1', [PUBLIC_URL_SETTING_KEY]);
  savedSetting = stored.rowCount ? stored.rows[0].value : null;
  await pool.query('DELETE FROM system_settings WHERE key = $1', [PUBLIC_URL_SETTING_KEY]);
  for (const role of ROLES) {
    const user = await UserModel.create({
      username: `publicurl-${tag}-${role}`,
      email: `publicurl-${tag}-${role}@siembox.invalid`,
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
  if (savedEnv === undefined) delete process.env[PUBLIC_URL_ENV];
  else process.env[PUBLIC_URL_ENV] = savedEnv;
  if (dbReady) {
    await pool.query('DELETE FROM system_settings WHERE key = $1', [PUBLIC_URL_SETTING_KEY]);
    if (savedSetting !== null) {
      await pool.query('INSERT INTO system_settings (key, value) VALUES ($1, $2)', [PUBLIC_URL_SETTING_KEY, savedSetting]);
    }
    await pool.query(`DELETE FROM notification_channels WHERE name = $1`, [`publicurl-${tag}`]);
    if (disabledChannels.length) {
      await pool.query('UPDATE notification_channels SET enabled = true WHERE id = ANY($1)', [disabledChannels]);
    }
    // 403s are logged to application_errors fire-and-forget; give them a moment, then remove them with the users.
    await new Promise((resolve) => setTimeout(resolve, 300));
    await pool.query('DELETE FROM application_errors WHERE user_id = ANY($1)', [userIds]);
    await pool.query('DELETE FROM users WHERE id = ANY($1)', [userIds]);
  }
  await closePools();
});

async function call(
  role: Role,
  method: 'GET' | 'PUT' | 'POST',
  path: string,
  body?: unknown
): Promise<{ status: number; json: any }> {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { Authorization: `Bearer ${tokens[role]}`, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, json: await res.json() };
}

const put = (role: Role, body: unknown) => call(role, 'PUT', '/api/settings/public-url', body);
const get = (role: Role) => call(role, 'GET', '/api/settings/public-url');

async function storedValue(): Promise<string | null> {
  const r = await pool.query('SELECT value FROM system_settings WHERE key = $1', [PUBLIC_URL_SETTING_KEY]);
  return r.rowCount ? r.rows[0].value : null;
}

test('only admins read or change the public URL', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  for (const role of ['viewer', 'analyst', 'operator'] as const) {
    assert.equal((await get(role)).status, 403, `${role} cannot read it`);
    assert.equal((await put(role, { public_url: 'https://evil.example' })).status, 403, `${role} cannot set it`);
  }
  assert.equal(await storedValue(), null, 'nothing was stored');
  const r = await get('admin');
  assert.equal(r.status, 200);
  assert.deepEqual(r.json, { public_url: '', env_public_url: '', effective_public_url: '', source: 'none' });
});

test('an invalid value is a 400 naming the problem, and nothing is stored', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const cases: Array<[unknown, RegExp]> = [
    [{ public_url: 'javascript:alert(1)' }, /http:\/\/ or https:\/\//],
    [{ public_url: 'https://u:p@siem.example.com' }, /username or password/],
    [{ public_url: 'https://siem.example.com/?a=1' }, /query string/],
    [{ public_url: 'https://siem.example.com/#x' }, /fragment/],
    [{ public_url: '/siembox' }, /absolute URL/],
    [{ public_url: `https://siem.example.com/${'a'.repeat(2048)}` }, /at most 2048/],
    [{ public_url: 5 }, /must be a string/],
    [{}, /Expected a JSON object/],
    [['https://siem.example.com'], /Expected a JSON object/],
  ];
  for (const [body, pattern] of cases) {
    const r = await put('admin', body);
    assert.equal(r.status, 400, JSON.stringify(body).slice(0, 60));
    assert.match(r.json.message, pattern);
  }
  assert.equal(await storedValue(), null);
});

test('a valid value is stored normalised; the setting wins over the env var; clearing falls back', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  process.env[PUBLIC_URL_ENV] = 'https://env.example.com/';
  try {
    let r = await get('admin');
    assert.equal(r.json.effective_public_url, 'https://env.example.com');
    assert.equal(r.json.source, 'env');
    assert.equal(await getPublicUrl(), 'https://env.example.com');

    r = await put('admin', { public_url: '  HTTPS://SIEM.Example.com/SIEMBox/  ' });
    assert.equal(r.status, 200);
    assert.deepEqual(r.json, {
      public_url: 'https://siem.example.com/SIEMBox',
      env_public_url: 'https://env.example.com',
      effective_public_url: 'https://siem.example.com/SIEMBox',
      source: 'setting',
    });
    assert.equal(await storedValue(), 'https://siem.example.com/SIEMBox');
    assert.equal(await getPublicUrl(), 'https://siem.example.com/SIEMBox');

    // GET /api/settings lists it in clear, like the other non-secret settings.
    const all = await call('admin', 'GET', '/api/settings');
    const row = (all.json as Array<{ setting_key: string }>).find((x) => x.setting_key === PUBLIC_URL_SETTING_KEY);
    assert.deepEqual(row, { setting_key: 'public_url', setting_value: 'https://siem.example.com/SIEMBox', redacted: false });

    r = await put('admin', { public_url: '' });
    assert.equal(r.status, 200);
    assert.equal(await storedValue(), null, 'clearing removes the row');
    assert.equal(r.json.source, 'env');
    assert.equal(await getPublicUrl(), 'https://env.example.com');

    delete process.env[PUBLIC_URL_ENV];
    assert.equal(await getPublicUrl(), null);
    r = await put('admin', { public_url: null });
    assert.equal(r.json.source, 'none');
  } finally {
    delete process.env[PUBLIC_URL_ENV];
  }
});

test('the test alert reaches ntfy with the link as Click and in the body; without a public URL, no link', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const received: Array<{ headers: http.IncomingHttpHeaders; body: string }> = [];
  const ntfy = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      received.push({ headers: req.headers, body });
      res.end('{}');
    });
  });
  ntfy.listen(0, '127.0.0.1');
  await once(ntfy, 'listening');
  try {
    // Only this test's channel is enabled while it runs.
    const enabled = await pool.query('UPDATE notification_channels SET enabled = false WHERE enabled RETURNING id');
    disabledChannels = enabled.rows.map((row) => row.id as number);
    await pool.query(
      `INSERT INTO notification_channels (name, channel_type, enabled, config) VALUES ($1, 'ntfy', true, $2)`,
      [`publicurl-${tag}`, JSON.stringify({ server_url: `http://127.0.0.1:${(ntfy.address() as AddressInfo).port}`, topic: 't' })]
    );

    let r = await call('admin', 'POST', '/api/notifications/test-alert');
    assert.equal(r.status, 200);
    assert.equal(r.json.link, null);
    assert.match(r.json.message, /no link: set the public URL in Settings -> System/);
    assert.equal(received.length, 1);
    assert.equal(received[0].headers.click, undefined);
    assert.doesNotMatch(received[0].body, /https?:\/\//);

    await put('admin', { public_url: 'https://siem.example.com/' });
    r = await call('admin', 'POST', '/api/notifications/test-alert');
    assert.equal(r.json.link, 'https://siem.example.com/alerts');
    assert.match(r.json.message, /linking to https:\/\/siem\.example\.com\/alerts/);
    assert.equal(received.length, 2);
    assert.equal(received[1].headers.click, 'https://siem.example.com/alerts');
    assert.ok(received[1].body.endsWith('\n\nAll alerts: https://siem.example.com/alerts'));
  } finally {
    await new Promise<void>((resolve) => ntfy.close(() => resolve()));
  }
});
