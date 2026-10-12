/**
 * Role gates on the scan and asset write routes, end to end: the real app on an
 * ephemeral port, a real Postgres, and one user per role holding a session token
 * (as login would issue). For each route family a refused role gets 403 and
 * nothing changes, and an allowed role gets past the gate: a 2xx where the call
 * only touches rows this test owns (an asset on a free TEST-NET-2 address, a
 * disabled schedule) or a stubbed service, otherwise the route's own 400
 * validation, which runs only after the gate and writes nothing.
 *
 * Every 403 probe stays harmless even if its gate goes missing: it aims at this
 * test's own rows, or sends a body the handler rejects with 400 before doing any
 * work, or (POST /api/assets/discover and POST /api/vulnerabilities/templates/download,
 * which check nothing in the request) reaches a service stubbed below. So a
 * broken gate fails the test without starting a scan or touching anyone's data.
 *
 * Denials on scan gates land in audit_logs, with the caller's TCP address even
 * when it sends X-Forwarded-For. Skips itself when Postgres isn't reachable. Every row created here
 * (users, sessions, assets, schedules, audit and error-log rows) is removed
 * again, along with what an interrupted earlier run left behind.
 * Run with `npm test` (tsx --test).
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
import { AutoDiscoveryService } from '../services/assets/autoDiscoveryService';
import { TemplateService } from '../services/scanner/templateService';

const ROLES = ['admin', 'operator', 'analyst', 'viewer'] as const;
type Role = (typeof ROLES)[number];
const SKIP = 'Postgres with the scan schema is not reachable';
/** Usernames this test gives its users (scanauthz-<tag>-<role>), any tag. */
const TEST_USER_NAME = '^scanauthz-[0-9a-f]{12}-(admin|operator|analyst|viewer)$';
/** Hostnames and schedule names this test uses (scanauthz-<tag>, -op, -changed, -renamed), any tag. */
const TEST_ROW_NAME = '^scanauthz-[0-9a-f]{12}(-op|-changed|-renamed)?$';

// Stand-ins for the two handlers that start work without validating the request.
// The real services mark assets offline and upsert assets from the logs, or
// fetch the nuclei-templates repository.
const runFullDiscovery = mock.method(AutoDiscoveryService, 'runFullDiscovery', async () => ({
  discovered: 0,
  staleMarked: 0,
  enriched: 0,
}));
const downloadTemplates = mock.method(TemplateService, 'downloadTemplates', async () => ({
  success: true,
  message: 'stubbed by scanRouteGates.db.test.ts',
}));
mock.method(TemplateService, 'getStats', async () => ({ totalTemplates: 0, categories: 0, tags: 0, severityCounts: {} }));

let dbReady = false;
let server: Server | undefined;
let base = '';
const tag = crypto.randomBytes(6).toString('hex');
const name = `scanauthz-${tag}`;
const tokens = {} as Record<Role, string>;
const userIdOf = {} as Record<Role, number>;
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
    userIdOf[role] = user.id;
    tokens[role] = (await SessionModel.create(user.id, 1)).token;
  }
  server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  if (dbReady) {
    // Leftovers of an interrupted earlier run go too, but only once they are
    // older than 10 minutes: a run going on in parallel against the same
    // database keeps its own.
    const stale = `created_at < NOW() - INTERVAL '10 minutes'`;
    await pool.query(
      `DELETE FROM assets WHERE id = ANY($1) OR hostname LIKE $2
          OR (hostname ~ $3 AND ip_address << '198.51.100.0/24'::inet AND ${stale})`,
      [assetIds, `${name}%`, TEST_ROW_NAME]
    );
    await pool.query(
      `DELETE FROM scheduled_scans WHERE id = ANY($1) OR name LIKE $2 OR (name ~ $3 AND ${stale})`,
      [scheduleIds, `${name}%`, TEST_ROW_NAME]
    );
    // Scan-gate denials are written to audit_logs before the 403 is sent. Every
    // 403 is also logged to application_errors, fire-and-forget: wait until those
    // rows have landed, then delete both before the users (deleting a user only
    // nulls user_id, ON DELETE SET NULL, which would leave orphan rows).
    for (let attempt = 0; attempt < 50; attempt++) {
      const logged = await pool.query('SELECT count(*)::int AS n FROM application_errors WHERE user_id = ANY($1)', [userIds]);
      if (logged.rows[0].n >= denials) break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    const leftover = await pool.query(
      `SELECT id FROM users WHERE username ~ $1 AND email LIKE '%@siembox.invalid' AND ${stale}`,
      [TEST_USER_NAME]
    );
    const doomed = [...userIds, ...leftover.rows.map((row) => row.id as number)];
    await pool.query('DELETE FROM application_errors WHERE user_id = ANY($1)', [doomed]);
    await pool.query('DELETE FROM audit_logs WHERE user_id = ANY($1)', [doomed]);
    await pool.query('DELETE FROM users WHERE id = ANY($1)', [doomed]); // sessions cascade
  }
  await closePools();
});

async function call(role: Role | null, method: string, path: string, body?: unknown, extraHeaders: Record<string, string> = {}) {
  const headers: Record<string, string> = { ...extraHeaders };
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
  await refused(['viewer'], 'POST', '/api/assets/scan', { targets: [] });
  await refused(['viewer'], 'POST', '/api/assets/discover');
  assert.deepEqual(await assetRow(id), before, 'the asset is unchanged');
  assert.equal(runFullDiscovery.mock.callCount(), 0, 'the refused discovery never reached its handler');

  const updated = await call('operator', 'PUT', `/api/assets/${id}`, { hostname: `${name}-op` });
  assert.equal(updated.status, 200);
  assert.equal((await assetRow(id)).hostname, `${name}-op`);
  await pastTheGate(['analyst', 'operator', 'admin'], 'POST', '/api/assets/scan', { targets: [] });
  assert.equal((await call('analyst', 'POST', '/api/assets/discover')).status, 200);
  assert.equal(runFullDiscovery.mock.callCount(), 1, 'an analyst reaches the (stubbed) discovery');

  assert.equal((await call('admin', 'DELETE', `/api/assets/${id}`)).status, 204);
  assert.equal(await assetRow(id), undefined);
});

test('vulnerability writes: scans and status changes need admin or operator; template refresh admits analysts', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  await refused(['analyst', 'viewer'], 'POST', '/api/vulnerabilities/scans', {});
  await refused(['analyst', 'viewer'], 'POST', '/api/vulnerabilities/scans/abc/cancel');
  await refused(['analyst', 'viewer'], 'PATCH', '/api/vulnerabilities/1/1', { status: 'bogus' });
  await refused(['analyst', 'viewer'], 'POST', '/api/vulnerabilities/templates/download');
  await refused(['viewer'], 'POST', '/api/vulnerabilities/templates/refresh');
  assert.equal(downloadTemplates.mock.callCount(), 0, 'the refused downloads never reached their handler');
  await pastTheGate(['operator', 'admin'], 'POST', '/api/vulnerabilities/scans', {});
  await pastTheGate(['operator', 'admin'], 'POST', '/api/vulnerabilities/scans/abc/cancel');
  await pastTheGate(['operator', 'admin'], 'PATCH', '/api/vulnerabilities/1/1', { status: 'bogus' });
  assert.equal((await call('operator', 'POST', '/api/vulnerabilities/templates/download')).status, 200);
  assert.equal(downloadTemplates.mock.callCount(), 1, 'an operator reaches the (stubbed) download');
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
  // Not this schedule's id: a run that got past a missing gate would start a scan.
  await refused(['analyst', 'viewer'], 'POST', '/api/scheduled-scans/abc/run');
  await refused(['analyst', 'viewer'], 'DELETE', `/api/scheduled-scans/${id}`);
  assert.deepEqual(await scheduleRow(id), before, 'the schedule is unchanged');
  await pastTheGate(['operator', 'admin'], 'POST', '/api/scheduled-scans/abc/run');

  const renamed = await call('operator', 'PUT', `/api/scheduled-scans/${id}`, { name: `${name}-renamed` });
  assert.equal(renamed.status, 200);
  assert.equal(renamed.json.name, `${name}-renamed`);
  assert.equal((await call('admin', 'DELETE', `/api/scheduled-scans/${id}`)).status, 200);
  assert.equal(await scheduleRow(id), undefined);
});

test('log discovery: scans and source triage need admin or operator; scope stays admin-only', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  await refused(['analyst', 'viewer'], 'POST', '/api/log-discovery/scans', { mode: 'bogus' });
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
  await refused(['analyst', 'viewer'], 'POST', '/api/containers/scan', {});
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

test('a denial on a direct call is audited with the caller\'s TCP address, whatever X-Forwarded-For says', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  // A direct caller cannot pick its address (net/clientAddress.ts): the
  // header is ignored, so there is no forged address to record and no separate
  // peer to keep. audit_logs.ip_address is INET.
  const agent = `${name}-xff`;
  for (const forwarded of ['not-an-ip', '10.9.9.9', '198.51.100.7, 10.9.9.9']) {
    const r = await call('viewer', 'POST', '/api/containers/scan', {}, {
      'X-Forwarded-For': forwarded,
      'User-Agent': `${agent} ${forwarded}`,
    });
    assert.equal(r.status, 403);
  }
  const rows = await pool.query(
    `SELECT user_agent, host(ip_address) AS ip, details->>'peerAddress' AS peer
       FROM audit_logs
      WHERE user_id = $1 AND action = 'access.denied' AND user_agent LIKE $2
      ORDER BY id`,
    [userIdOf.viewer, `${agent} %`]
  );
  assert.deepEqual(rows.rows, [
    { user_agent: `${agent} not-an-ip`, ip: '127.0.0.1', peer: null },
    { user_agent: `${agent} 10.9.9.9`, ip: '127.0.0.1', peer: null },
    { user_agent: `${agent} 198.51.100.7, 10.9.9.9`, ip: '127.0.0.1', peer: null },
  ]);
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
