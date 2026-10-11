/**
 * Role gates on the scan and asset write routes, end to end: the real app on an
 * ephemeral port, a real Postgres, and one user per role holding a session token
 * (as login would issue). For each route family a refused role gets 403 and
 * nothing changes, and an allowed role gets past the gate: a 2xx where the call
 * only touches rows this test owns (an asset on a free TEST-NET-2 address, a
 * disabled schedule), otherwise the route's own 400 validation, which runs only
 * after the gate and writes nothing. Denials on scan gates land in audit_logs.
 * Skips itself when Postgres isn't reachable. Every row created here (users,
 * sessions, assets, schedules, audit and error-log rows) is removed again.
 * Run with `npm test` (tsx --test).
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

const ROLES = ['admin', 'operator', 'analyst', 'viewer'] as const;
type Role = (typeof ROLES)[number];
const SKIP = 'Postgres with the scan schema is not reachable';

let dbReady = false;
let server: Server | undefined;
let base = '';
const tag = crypto.randomBytes(6).toString('hex');
const name = `scanauthz-${tag}`;
const tokens = {} as Record<Role, string>;
const userIds: number[] = [];
const assetIds: number[] = [];
const scheduleIds: number[] = [];
/** 403 responses so far; each one is logged to application_errors (see after()). */
let denials = 0;

before(async () => {
  try {
    for (const table of ['sessions', 'assets', 'scheduled_scans', 'audit_logs', 'application_errors']) {
      await pool.query(`SELECT 1 FROM ${table} LIMIT 1`);
    }
    dbReady = true;
  } catch {
    return;
  }
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
    await pool.query('DELETE FROM assets WHERE id = ANY($1) OR hostname LIKE $2', [assetIds, `${name}%`]);
    await pool.query('DELETE FROM scheduled_scans WHERE id = ANY($1) OR name LIKE $2', [scheduleIds, `${name}%`]);
    // Scan-gate denials are written to audit_logs before the 403 is sent. Every
    // 403 is also logged to application_errors, fire-and-forget: wait until those
    // rows have landed, then delete both before the users (deleting a user only
    // nulls user_id, ON DELETE SET NULL, which would leave orphan rows).
    for (let attempt = 0; attempt < 50; attempt++) {
      const logged = await pool.query('SELECT count(*)::int AS n FROM application_errors WHERE user_id = ANY($1)', [userIds]);
      if (logged.rows[0].n >= denials) break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    await pool.query('DELETE FROM application_errors WHERE user_id = ANY($1)', [userIds]);
    await pool.query('DELETE FROM audit_logs WHERE user_id = ANY($1)', [userIds]);
    await pool.query('DELETE FROM users WHERE id = ANY($1)', [userIds]); // sessions cascade
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
  if (res.status === 403) denials++;
  return { status: res.status, json: (await res.json().catch(() => null)) as any };
}

/** `roles` all get 403 from `method path`. */
async function refused(roles: readonly Role[], method: string, path: string, body?: unknown) {
  for (const role of roles) {
    assert.equal((await call(role, method, path, body)).status, 403, `${role} ${method} ${path} is refused`);
  }
}

/** `roles` all get past the gate, to the route's own 400 validation. */
async function pastTheGate(roles: readonly Role[], method: string, path: string, body?: unknown) {
  for (const role of roles) {
    assert.equal((await call(role, method, path, body)).status, 400, `${role} ${method} ${path} reaches validation`);
  }
}

async function assetRow(id: number) {
  return (await pool.query('SELECT id, ip_address, hostname, updated_at FROM assets WHERE id = $1', [id])).rows[0];
}

async function scheduleRow(id: number) {
  return (await pool.query('SELECT * FROM scheduled_scans WHERE id = $1', [id])).rows[0];
}

/** A TEST-NET-2 address no asset has (POST /api/assets upserts on ip_address). */
async function freeTestNetAddress(): Promise<string> {
  const start = crypto.randomInt(1, 255);
  for (let i = 0; i < 254; i++) {
    const ip = `198.51.100.${((start + i) % 254) + 1}`;
    const taken = await pool.query('SELECT 1 FROM assets WHERE ip_address = $1::inet', [ip]);
    if (taken.rowCount === 0) return ip;
  }
  throw new Error('no free 198.51.100.0/24 address for the test asset');
}

test('asset writes: viewer refused, analyst, operator and admin allowed', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const ip = await freeTestNetAddress();
  await refused(['viewer'], 'POST', '/api/assets', { ip_address: ip, hostname: name });
  assert.equal((await pool.query('SELECT 1 FROM assets WHERE ip_address = $1::inet', [ip])).rowCount, 0, 'nothing was created');

  const created = await call('analyst', 'POST', '/api/assets', { ip_address: ip, hostname: name });
  assert.equal(created.status, 201);
  assetIds.push(created.json.id);
  const id = created.json.id;

  const before = await assetRow(id);
  await refused(['viewer'], 'PUT', `/api/assets/${id}`, { hostname: `${name}-changed` });
  await refused(['viewer'], 'DELETE', `/api/assets/${id}`);
  await refused(['viewer'], 'POST', '/api/assets/discover');
  await refused(['viewer'], 'POST', '/api/assets/scan', { targets: [ip] });
  assert.deepEqual(await assetRow(id), before, 'the asset is unchanged');

  const updated = await call('operator', 'PUT', `/api/assets/${id}`, { hostname: `${name}-op` });
  assert.equal(updated.status, 200);
  assert.equal((await assetRow(id)).hostname, `${name}-op`);
  await pastTheGate(['analyst', 'operator', 'admin'], 'POST', '/api/assets/scan', { targets: [] });

  assert.equal((await call('admin', 'DELETE', `/api/assets/${id}`)).status, 204);
  assert.equal(await assetRow(id), undefined);
});

test('vulnerability writes: scans and status changes need admin or operator; template refresh admits analysts', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  await refused(['analyst', 'viewer'], 'POST', '/api/vulnerabilities/scans', { target: '192.0.2.1' });
  await refused(['analyst', 'viewer'], 'POST', '/api/vulnerabilities/scans/abc/cancel');
  await refused(['analyst', 'viewer'], 'PATCH', '/api/vulnerabilities/1/1', { status: 'patched' });
  await refused(['analyst', 'viewer'], 'POST', '/api/vulnerabilities/templates/download');
  await refused(['viewer'], 'POST', '/api/vulnerabilities/templates/refresh');
  await pastTheGate(['operator', 'admin'], 'POST', '/api/vulnerabilities/scans', {});
  await pastTheGate(['operator', 'admin'], 'POST', '/api/vulnerabilities/scans/abc/cancel');
  await pastTheGate(['operator', 'admin'], 'PATCH', '/api/vulnerabilities/1/1', { status: 'bogus' });
});

test('scheduled scans: only admin and operator create, change, run or delete', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const schedule = {
    name,
    scan_type: 'asset',
    scan_options: { targets: ['192.0.2.1'] },
    interval_minutes: 1440,
    enabled: false,
  };
  await refused(['analyst', 'viewer'], 'POST', '/api/scheduled-scans', schedule);
  assert.equal((await pool.query('SELECT 1 FROM scheduled_scans WHERE name = $1', [name])).rowCount, 0, 'nothing was created');

  const created = await call('operator', 'POST', '/api/scheduled-scans', schedule);
  assert.equal(created.status, 201);
  scheduleIds.push(created.json.id);
  const id = created.json.id;

  const before = await scheduleRow(id);
  await refused(['analyst', 'viewer'], 'PUT', `/api/scheduled-scans/${id}`, { enabled: true });
  await refused(['analyst', 'viewer'], 'POST', `/api/scheduled-scans/${id}/run`);
  await refused(['analyst', 'viewer'], 'DELETE', `/api/scheduled-scans/${id}`);
  assert.deepEqual(await scheduleRow(id), before, 'the schedule is unchanged and did not run');

  const renamed = await call('operator', 'PUT', `/api/scheduled-scans/${id}`, { name: `${name}-renamed` });
  assert.equal(renamed.status, 200);
  assert.equal(renamed.json.name, `${name}-renamed`);
  assert.equal((await call('admin', 'DELETE', `/api/scheduled-scans/${id}`)).status, 200);
  assert.equal(await scheduleRow(id), undefined);
});

test('log discovery: scans and source triage need admin or operator; scope stays admin-only', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  await refused(['analyst', 'viewer'], 'POST', '/api/log-discovery/scans', { mode: 'passive' });
  await refused(['analyst', 'viewer'], 'POST', '/api/log-discovery/scans/abc/cancel');
  for (const action of ['confirm', 'ignore', 'onboard/confirm']) {
    await refused(['analyst', 'viewer'], 'POST', `/api/log-discovery/sources/abc/${action}`, { confirm: true });
    await pastTheGate(['operator', 'admin'], 'POST', `/api/log-discovery/sources/abc/${action}`, { confirm: true });
  }
  await pastTheGate(['operator', 'admin'], 'POST', '/api/log-discovery/scans', { mode: 'bogus' });
  await pastTheGate(['operator', 'admin'], 'POST', '/api/log-discovery/scans/abc/cancel');
  await refused(['operator', 'analyst', 'viewer'], 'PUT', '/api/log-discovery/scope/cidrs', { cidrs: 'x' });
  await pastTheGate(['admin'], 'PUT', '/api/log-discovery/scope/cidrs', { cidrs: 'x' });
});

test('container scans need admin or operator', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  await refused(['analyst', 'viewer'], 'POST', '/api/containers/scan', { image_ref: 'nginx:latest' });
  await pastTheGate(['operator', 'admin'], 'POST', '/api/containers/scan', {});
});

test('reads stay open to every role', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  for (const role of ROLES) {
    for (const path of ['/api/assets?limit=1', '/api/vulnerabilities/scans?limit=1', '/api/scheduled-scans', '/api/log-discovery/scans', '/api/containers/scans?limit=1']) {
      assert.equal((await call(role, 'GET', path)).status, 200, `${role} GET ${path}`);
    }
  }
});

test('scan-gate denials are recorded in audit_logs', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const r = await pool.query(
    `SELECT DISTINCT resource_type FROM audit_logs
      WHERE user_id = ANY($1) AND action = 'access.denied' AND response_status = 403`,
    [userIds]
  );
  const types = r.rows.map((row) => row.resource_type).sort();
  for (const expected of ['asset', 'asset_scan', 'container_scan', 'discovery_scan', 'nuclei_templates', 'remediation', 'scheduled_scan', 'vuln_scan']) {
    assert.ok(types.includes(expected), `a denial of resource ${expected} was audited (got ${types.join(', ')})`);
  }
});

test('without a login every family answers 401', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  for (const [method, path] of [
    ['POST', '/api/assets'],
    ['POST', '/api/vulnerabilities/scans'],
    ['POST', '/api/scheduled-scans'],
    ['POST', '/api/log-discovery/scans'],
    ['POST', '/api/containers/scan'],
  ]) {
    assert.equal((await call(null, method, path, {})).status, 401, `${method} ${path}`);
  }
});
