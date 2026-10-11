/**
 * Role gating and api_key redaction on /api/shippers, end to end: the real app
 * on an ephemeral port, a real Postgres, one user per role holding a session
 * token (as login would issue), and a throwaway shipper with a test key. When
 * Postgres (or the shipper schema) isn't reachable these tests skip themselves
 * so `npm test` stays green on a machine without a database. Every row created
 * here is removed again. Run with `npm test` (tsx --test).
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { once } from 'node:events';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import app from '../app';
import pool, { closePools } from '../config/database';
import { UserModel } from '../models/User';
import { SessionModel } from '../models/Session';
import { LogShipperModel } from '../models/LogShipper';

const ROLES = ['admin', 'operator', 'analyst', 'viewer'] as const;
type Role = (typeof ROLES)[number];
const SKIP = 'Postgres with the shipper schema is not reachable';

let dbReady = false;
let server: Server | undefined;
let base = '';
const tag = crypto.randomBytes(6).toString('hex');
const tokens = {} as Record<Role, string>;
const userIds: number[] = [];
const shipperIds: number[] = [];
let shipperId = 0;
let shipperKey = '';

before(async () => {
  try {
    await pool.query('SELECT http_push_key_hash FROM log_shippers LIMIT 1');
    await pool.query('SELECT token FROM sessions LIMIT 1');
    dbReady = true;
  } catch {
    return;
  }
  for (const role of ROLES) {
    const user = await UserModel.create({
      username: `authz-${role}-${tag}`,
      email: `authz-${role}-${tag}@siembox.invalid`,
      password: crypto.randomBytes(16).toString('hex'),
      role,
    });
    userIds.push(user.id);
    tokens[role] = (await SessionModel.create(user.id, 1)).token;
  }
  shipperKey = crypto.randomBytes(32).toString('hex');
  const shipper = await LogShipperModel.create({ name: `authz-${tag}`, description: 'route auth test', api_key: shipperKey });
  shipperId = shipper.id;
  shipperIds.push(shipper.id);

  server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  if (dbReady) {
    await pool.query('DELETE FROM log_shippers WHERE id = ANY($1)', [shipperIds]);
    // 403s are logged to application_errors with the caller's user id
    // (fire-and-forget, so one may land late) and that FK doesn't cascade.
    for (let attempt = 0; ; attempt++) {
      await pool.query('DELETE FROM application_errors WHERE user_id = ANY($1)', [userIds]);
      try {
        await pool.query('DELETE FROM users WHERE id = ANY($1)', [userIds]);
        break;
      } catch (err) {
        if (attempt >= 20) throw err;
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    }
  }
  await closePools();
});

async function call(role: Role | null, method: string, path: string, body?: unknown) {
  const headers: Record<string, string> = {};
  if (role) headers.Authorization = `Bearer ${tokens[role]}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(base + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, json: (await res.json().catch(() => null)) as any };
}

async function dbShipper(id: number) {
  const r = await pool.query(
    'SELECT api_key, description, status, http_push_key_hash FROM log_shippers WHERE id = $1',
    [id]
  );
  return r.rows[0];
}

test('every role can list shippers; only admin and operator get api_key', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  for (const role of ROLES) {
    const r = await call(role, 'GET', '/api/shippers');
    assert.equal(r.status, 200, role);
    const mine = r.json.find((s: any) => s.id === shipperId);
    assert.ok(mine, `${role} sees the test shipper`);
    assert.ok(r.json.every((s: any) => !('http_push_key_hash' in s)), 'push-key hash never leaves the server');
    if (role === 'admin' || role === 'operator') {
      assert.equal(mine.api_key, shipperKey, role);
    } else {
      assert.ok(r.json.every((s: any) => !('api_key' in s)), `${role} gets no api_key on any row`);
    }
  }
});

test('shipper detail carries api_key only for admin and operator', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  for (const role of ROLES) {
    const r = await call(role, 'GET', `/api/shippers/${shipperId}`);
    assert.equal(r.status, 200, role);
    assert.ok(Array.isArray(r.json.sources) && Array.isArray(r.json.volumes), 'the UI still gets sources and volumes');
    assert.ok(!('http_push_key_hash' in r.json));
    assert.equal('api_key' in r.json, role === 'admin' || role === 'operator', role);
  }
});

test('analyst and viewer get 403 on every shipper write, and nothing changes', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const before = await dbShipper(shipperId);
  const writes: Array<[string, string, unknown?]> = [
    ['POST', '/api/shippers', { name: `authz-denied-${tag}` }],
    ['PUT', `/api/shippers/${shipperId}`, { description: 'changed' }],
    ['DELETE', `/api/shippers/${shipperId}`],
    ['POST', `/api/shippers/${shipperId}/sources`, { source_type: 'file', file_path: '/x.log', tag: 'x' }],
    ['PUT', '/api/shippers/sources/1', { enabled: false }],
    ['DELETE', '/api/shippers/sources/1'],
    ['POST', `/api/shippers/${shipperId}/volumes`, { host_path: '/a', container_path: '/b' }],
    ['DELETE', '/api/shippers/volumes/1'],
    ['POST', `/api/shippers/${shipperId}/regenerate-key`],
  ];
  for (const role of ['analyst', 'viewer'] as const) {
    for (const [method, path, body] of writes) {
      assert.equal((await call(role, method, path, body)).status, 403, `${role} ${method} ${path}`);
    }
  }
  assert.deepEqual(await dbShipper(shipperId), before);
  const created = await pool.query('SELECT 1 FROM log_shippers WHERE name = $1', [`authz-denied-${tag}`]);
  assert.equal(created.rowCount, 0);
});

test('operator can create, edit and delete a shipper, but not rotate its key', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const created = await call('operator', 'POST', '/api/shippers', { name: `authz-op-${tag}` });
  assert.equal(created.status, 201);
  shipperIds.push(created.json.id);
  assert.match(created.json.api_key, /^[0-9a-f]{64}$/, 'the creator gets the new key');
  assert.ok(!('http_push_key_hash' in created.json));
  assert.equal(created.json.http_push_enabled, false);
  const id = created.json.id;
  const key = created.json.api_key;

  const edited = await call('operator', 'PUT', `/api/shippers/${id}`, {
    description: 'edited',
    api_key: 'f'.repeat(64),
    http_push_key_hash: 'e'.repeat(64),
    status: 'error',
    'name = name, api_key': 'x',
  });
  assert.equal(edited.status, 200);
  assert.equal(edited.json.description, 'edited');
  assert.ok(!('http_push_key_hash' in edited.json));
  const row = await dbShipper(id);
  assert.equal(row.description, 'edited');
  assert.equal(row.api_key, key, 'api_key is not editable');
  assert.equal(row.http_push_key_hash, null, 'the push key is not editable here');
  assert.equal(row.status, 'pending', 'status is reported by the shipper, not editable');

  assert.equal((await call('operator', 'PUT', `/api/shippers/${id}`, { api_key: 'x' })).status, 400);
  assert.equal((await call('operator', 'POST', `/api/shippers/${id}/regenerate-key`)).status, 403);
  assert.equal((await call('operator', 'DELETE', `/api/shippers/${id}`)).status, 200);
  assert.equal(await dbShipper(id), undefined);
});

test('shipper-facing endpoints work with the shipper key and no login', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const config = await call(null, 'GET', `/api/shippers/config/${shipperKey}`);
  assert.equal(config.status, 200);
  assert.equal(config.json.id, shipperId);
  assert.ok(Array.isArray(config.json.sources));
  const jobs = await call(null, 'GET', `/api/shippers/scan-jobs/${shipperKey}`);
  assert.equal(jobs.status, 200);
  assert.ok(Array.isArray(jobs.json.jobs));
  const register = await call(null, 'POST', '/api/shippers/register', { api_key: shipperKey, version: 'authz-test' });
  assert.equal(register.status, 200);
  assert.equal((await call(null, 'GET', `/api/shippers/config/${'0'.repeat(64)}`)).status, 404, 'an unknown key is still refused');
});

test('admin can rotate the syslog key', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const r = await call('admin', 'POST', `/api/shippers/${shipperId}/regenerate-key`);
  assert.equal(r.status, 200);
  assert.match(r.json.api_key, /^[0-9a-f]{64}$/);
  assert.notEqual(r.json.api_key, shipperKey);
  assert.equal((await dbShipper(shipperId)).api_key, r.json.api_key);
  shipperKey = r.json.api_key;
});

test('a token with no session behind it is 401', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const res = await fetch(`${base}/api/shippers`, { headers: { Authorization: `Bearer ${'0'.repeat(64)}` } });
  assert.equal(res.status, 401);
});
