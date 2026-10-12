/**
 * PATCH /api/log-discovery/sources/:id end to end: the real app on an ephemeral
 * port, a real Postgres, and one user per role holding a session token.
 *
 * - A manual source's address, port, HTTPS and endpoint are stored where the
 *   poller reads them (address + evidence); a scan-discovered source's go to
 *   poll_overrides, survive a re-scan, and its address can't change.
 * - A new endpoint or address clears the poll cursor; port/HTTPS changes keep it.
 * - The stored credential is never changed or returned.
 * - Only admins get past the gate; other roles get 403 and nothing changes.
 * - GET /sources and GET /sources/:id/poller show the URL being polled.
 *
 * - run-now polls a fake Home Assistant OS on 127.0.0.1 end to end: the 404 from
 *   /api/error_log falls back to the Supervisor endpoint, the choice is
 *   remembered, raw_logs get Home Assistant's native lines, and a refused
 *   connection is reported with the URL.
 *
 * Only that one test polls, and only its own local server. The other sources use
 * TEST-NET-3 addresses (203.0.113.0/24) no other row has. Skips itself when
 * Postgres isn't reachable; removes every row it created (polled lines, sources
 * and their pollers, the scan, users and their sessions, audit and error-log rows).
 * Run with `npm test` (tsx --test).
 */
import { test, before, after } from 'node:test';
import type { TestContext } from 'node:test';
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
import { DiscoveryScanModel } from '../models/DiscoveryScan';
import { DiscoverySourceModel } from '../models/DiscoverySource';
import { DiscoverySourcePollerModel } from '../models/DiscoverySourcePoller';

// The poller's credential is encrypted with this key; only set when the
// environment has none, so a developer's own key is never replaced.
process.env.CREDENTIAL_ENCRYPTION_KEY ||= crypto.randomBytes(32).toString('hex');

const ROLES = ['admin', 'operator', 'analyst', 'viewer'] as const;
type Role = (typeof ROLES)[number];
const SKIP = 'Postgres with the log discovery schema is not reachable';
const SECRET = `llat-${crypto.randomBytes(12).toString('hex')}`;
const SCAN_EVIDENCE = {
  discovery_methods: ['active_probe'],
  matched_signals: ['port 8123', 'http /manifest.json'],
  http_responses: [{ port: 8123, path: '/manifest.json', status: 200 }],
  tls_subjects: [],
  mdns_services: [],
  ssdp_services: [],
};

let dbReady = false;
let server: Server | undefined;
let base = '';
const tag = crypto.randomBytes(6).toString('hex');
const tokens = {} as Record<Role, string>;
const userIds: number[] = [];
const sourceIds = new Set<number>();
let scanId: number | null = null;
let denials = 0;

before(async () => {
  try {
    for (const table of ['sessions', 'discovery_sources', 'discovery_source_pollers', 'application_errors']) {
      await pool.query(`SELECT 1 FROM ${table} LIMIT 1`);
    }
    await pool.query('SELECT poll_overrides FROM discovery_sources LIMIT 1');
    dbReady = true;
  } catch {
    return;
  }
  for (const role of ROLES) {
    const user = await UserModel.create({
      username: `ldedit-${tag}-${role}`,
      email: `ldedit-${tag}-${role}@siembox.invalid`,
      password: crypto.randomBytes(16).toString('hex'),
      role,
    });
    userIds.push(user.id);
    tokens[role] = (await SessionModel.create(user.id, 1)).token;
  }
  scanId = (await DiscoveryScanModel.create('passive', [], null)).id;
  server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  if (dbReady) {
    // Polled lines first: deleting a source only nulls raw_logs.discovery_source_id.
    await pool.query('DELETE FROM raw_logs WHERE discovery_source_id = ANY($1)', [[...sourceIds]]); // parsed_logs cascade
    await pool.query('DELETE FROM discovery_sources WHERE id = ANY($1)', [[...sourceIds]]); // pollers cascade
    if (scanId !== null) await pool.query('DELETE FROM discovery_scans WHERE id = $1', [scanId]);
    // Every 403 is logged to application_errors, fire-and-forget: wait for those
    // rows, then delete them (and any audit rows) before the users.
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

function ready(t: TestContext): boolean {
  if (!dbReady) t.skip(SKIP);
  return dbReady;
}

async function call(role: Role | null, method: string, path: string, body?: unknown) {
  const headers: Record<string, string> = {};
  if (role) headers.Authorization = `Bearer ${tokens[role]}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  if (res.status === 403) denials++;
  const text = await res.text();
  let json: any = null;
  try {
    json = JSON.parse(text);
  } catch {
    // not JSON
  }
  return { status: res.status, json, text };
}

/** A TEST-NET-3 address no discovery source has. */
async function freeAddress(): Promise<string> {
  const start = crypto.randomInt(1, 255);
  for (let i = 0; i < 254; i++) {
    const ip = `203.0.113.${((start + i) % 254) + 1}`;
    const taken = await pool.query('SELECT 1 FROM discovery_sources WHERE ip_address = $1::inet', [ip]);
    if (taken.rowCount === 0) return ip;
  }
  throw new Error('no free 203.0.113.0/24 address for the test source');
}

async function manualSource(): Promise<{ id: number; ip: string }> {
  const ip = await freeAddress();
  const row = await DiscoverySourceModel.upsertManual({
    ip_address: ip,
    hostname: `ldedit-${tag}`,
    fingerprint_id: 'home-assistant',
    target_port: 8123,
    tls: false,
    security_value: 6,
  });
  sourceIds.add(row.id);
  return { id: row.id, ip };
}

async function scannedSource(fingerprintId = 'home-assistant'): Promise<{ id: number; ip: string }> {
  const ip = await freeAddress();
  const row = await DiscoverySourceModel.upsert({
    ip_address: ip,
    open_ports: [8123],
    matched_fingerprint_id: fingerprintId,
    confidence: 90,
    is_guess: false,
    security_value: 6,
    evidence: SCAN_EVIDENCE,
    last_scan_id: scanId!,
  });
  sourceIds.add(row.id);
  return { id: row.id, ip };
}

async function withPoller(id: number, cursor: string | null = 'tail line 1\ntail line 2\ntail line 3') {
  await DiscoverySourcePollerModel.upsertCredential(id, { fingerprintId: 'home-assistant', method: 'api_pull', secret: SECRET });
  await pool.query('UPDATE discovery_source_pollers SET poll_cursor = $2 WHERE discovery_source_id = $1', [id, cursor]);
}

async function sourceRow(id: number) {
  return (await pool.query('SELECT host(ip_address) AS ip, open_ports, evidence, poll_overrides FROM discovery_sources WHERE id = $1', [id]))
    .rows[0];
}

async function pollerRow(id: number) {
  return (
    await pool.query(
      `SELECT poll_cursor, encrypted_credential, encryption_iv, encryption_auth_tag, credential_username, enabled, poll_interval_minutes
         FROM discovery_source_pollers WHERE discovery_source_id = $1`,
      [id]
    )
  ).rows[0];
}

/** No credential material in an API response, in any form. */
function assertNoCredential(text: string) {
  assert.ok(!text.includes(SECRET), 'the token never appears in a response');
  for (const key of ['encrypted_credential', 'encryption_iv', 'encryption_auth_tag', '"secret"']) {
    assert.ok(!text.includes(key), `${key} never appears in a response`);
  }
}

test('admin edits a manual source: saved where the poller reads it; cursor reset only on endpoint/address change; credential untouched', async (t) => {
  if (!ready(t)) return;
  const { id, ip } = await manualSource();
  await withPoller(id);
  const before = await pollerRow(id);

  // Port + HTTPS: stored in evidence (with open_ports), the cursor kept.
  let r = await call('admin', 'PATCH', `/api/log-discovery/sources/${id}`, { port: 8124, tls: true });
  assert.equal(r.status, 200, r.text);
  assertNoCredential(r.text);
  assert.deepEqual((await sourceRow(id)).evidence, { manual: true, target_port: 8124, tls: true });
  assert.deepEqual((await sourceRow(id)).open_ports, [8124]);
  assert.equal((await pollerRow(id)).poll_cursor, before.poll_cursor, 'port/HTTPS changes keep the cursor');
  assert.equal(r.json.target.effective_url, `https://${ip}:8124/api/error_log`);
  assert.equal(r.json.target.manual, true);
  assert.equal(r.json.poller.configured, true);
  assert.equal(r.json.source.id, id);

  // Endpoint: stored, the cursor reset, nothing else in the poller row touched.
  r = await call('admin', 'PATCH', `/api/log-discovery/sources/${id}`, { endpoint: '/api/hassio/core/logs' });
  assert.equal(r.status, 200, r.text);
  assert.equal((await sourceRow(id)).evidence.endpoint, '/api/hassio/core/logs');
  assert.equal(r.json.target.effective_url, `https://${ip}:8124/api/hassio/core/logs`);
  assert.deepEqual(r.json.target.overrides, { port: 8124, tls: true, endpoint: '/api/hassio/core/logs' });
  const afterEndpoint = await pollerRow(id);
  assert.equal(afterEndpoint.poll_cursor, null, 'a new endpoint starts from a fresh cursor');
  assert.deepEqual({ ...afterEndpoint, poll_cursor: before.poll_cursor }, before, 'credential, schedule and state untouched');

  // Address: the row moves, the cursor resets again, the credential stays.
  await pool.query('UPDATE discovery_source_pollers SET poll_cursor = $2 WHERE discovery_source_id = $1', [id, 'x']);
  const newIp = await freeAddress();
  r = await call('admin', 'PATCH', `/api/log-discovery/sources/${id}`, { ip_address: newIp });
  assert.equal(r.status, 200, r.text);
  assert.equal((await sourceRow(id)).ip, newIp);
  assert.equal((await pollerRow(id)).poll_cursor, null);
  assert.equal((await pollerRow(id)).encrypted_credential, before.encrypted_credential);
  assert.equal(r.json.target.effective_url, `https://${newIp}:8124/api/hassio/core/logs`);

  // Clearing the endpoint and the port: back to the fingerprint defaults (8123, its endpoint).
  r = await call('admin', 'PATCH', `/api/log-discovery/sources/${id}`, { endpoint: '', port: null });
  assert.equal(r.status, 200, r.text);
  assert.deepEqual((await sourceRow(id)).evidence, { manual: true, target_port: 8123, tls: true });
  assert.equal(r.json.target.effective_url, `https://${newIp}:8123/api/error_log`);
});

test("a discovered source's overrides go to poll_overrides, survive a re-scan, reset cleanly, and its address can't change", async (t) => {
  if (!ready(t)) return;
  const { id, ip } = await scannedSource();
  await withPoller(id);

  let r = await call('admin', 'PATCH', `/api/log-discovery/sources/${id}`, { port: 8443, tls: true });
  assert.equal(r.status, 200, r.text);
  let row = await sourceRow(id);
  assert.deepEqual(row.poll_overrides, { port: 8443, tls: true });
  assert.deepEqual(row.evidence, SCAN_EVIDENCE, 'the scan-owned evidence is untouched');
  assert.equal(row.ip, ip);
  assert.equal(r.json.target.effective_url, `https://${ip}:8443/api/error_log`);
  assert.equal(r.json.target.manual, false);
  assert.notEqual((await pollerRow(id)).poll_cursor, null, 'port/HTTPS changes keep the cursor');

  // Another host: refused, nothing changes. The same address sent back is fine.
  r = await call('admin', 'PATCH', `/api/log-discovery/sources/${id}`, { ip_address: await freeAddress(), port: 1 });
  assert.equal(r.status, 403);
  assert.deepEqual(await sourceRow(id), row);
  r = await call('admin', 'PATCH', `/api/log-discovery/sources/${id}`, { ip_address: ip, endpoint: '/api/hassio/core/logs' });
  assert.equal(r.status, 200, r.text);
  assert.deepEqual((await sourceRow(id)).poll_overrides, { port: 8443, tls: true, endpoint: '/api/hassio/core/logs' });
  assert.equal((await pollerRow(id)).poll_cursor, null);

  // A re-scan of the host rewrites evidence but never the overrides.
  await DiscoverySourceModel.upsert({
    ip_address: ip,
    open_ports: [8123, 443],
    matched_fingerprint_id: 'home-assistant',
    confidence: 95,
    is_guess: false,
    security_value: 6,
    evidence: { ...SCAN_EVIDENCE, discovery_methods: ['mdns'] },
    last_scan_id: scanId!,
  });
  row = await sourceRow(id);
  assert.deepEqual(row.poll_overrides, { port: 8443, tls: true, endpoint: '/api/hassio/core/logs' });
  assert.deepEqual(row.evidence.discovery_methods, ['mdns']);

  // Resetting every override restores the exact default URL.
  r = await call('admin', 'PATCH', `/api/log-discovery/sources/${id}`, { port: null, tls: null, endpoint: null });
  assert.equal(r.status, 200, r.text);
  assert.equal((await sourceRow(id)).poll_overrides, null);
  assert.equal(r.json.target.effective_url, `http://${ip}:8123/api/error_log`);
});

test("a re-scan keeps a manual source's target and manual flag", async (t) => {
  if (!ready(t)) return;
  const { id, ip } = await manualSource();
  assert.equal((await call('admin', 'PATCH', `/api/log-discovery/sources/${id}`, { port: 8124, endpoint: '/api/hassio/core/logs' })).status, 200);

  await DiscoverySourceModel.upsert({
    ip_address: ip,
    open_ports: [8124],
    matched_fingerprint_id: 'home-assistant',
    confidence: 80,
    is_guess: false,
    security_value: 6,
    evidence: SCAN_EVIDENCE,
    last_scan_id: scanId!,
  });
  const { evidence } = await sourceRow(id);
  assert.deepEqual(evidence, {
    ...SCAN_EVIDENCE,
    manual: true,
    target_port: 8124,
    tls: false,
    endpoint: '/api/hassio/core/logs',
  });
  const r = await call('admin', 'GET', `/api/log-discovery/sources/${id}/poller`);
  assert.equal(r.json.target.effective_url, `http://${ip}:8124/api/hassio/core/logs`);
});

test('bad input is a 400 with a reason; unknown source 404; an address in use 409; no API pull method 400', async (t) => {
  if (!ready(t)) return;
  const { id } = await manualSource();
  const other = await scannedSource();
  const path = `/api/log-discovery/sources/${id}`;
  const cases: Array<[unknown, RegExp]> = [
    [{ endpoint: 'http://evil.example/api/error_log' }, /single "\/"/],
    [{ endpoint: '/api/../config' }, /"\." or "\.\."/],
    [{ endpoint: '/api/error_log\r\nX-Injected: 1' }, /control characters/],
    [{ port: 0 }, /between 1 and 65535/],
    [{ port: 65536 }, /between 1 and 65535/],
    [{ tls: 'yes' }, /tls must be a boolean/],
    [{ ip_address: 'homeassistant.local' }, /literal IPv4 or IPv6/],
    [{}, /Nothing to change/],
  ];
  const before = await sourceRow(id);
  for (const [body, message] of cases) {
    const r = await call('admin', 'PATCH', path, body);
    assert.equal(r.status, 400, JSON.stringify(body));
    assert.match(r.json.message, message);
  }
  assert.deepEqual(await sourceRow(id), before, 'nothing was saved');

  assert.equal((await call('admin', 'PATCH', '/api/log-discovery/sources/2147483646', { port: 1 })).status, 404);
  assert.equal((await call('admin', 'PATCH', '/api/log-discovery/sources/abc', { port: 1 })).status, 400);

  const taken = await call('admin', 'PATCH', path, { ip_address: other.ip });
  assert.equal(taken.status, 409);
  assert.match(taken.json.message, /already has the address/);

  const opnsense = await scannedSource('opnsense');
  const noApi = await call('admin', 'PATCH', `/api/log-discovery/sources/${opnsense.id}`, { port: 8443 });
  assert.equal(noApi.status, 400);
  assert.match(noApi.json.message, /no API pull method/);
});

test('only an admin can edit: operator, analyst and viewer get 403 and nothing changes; no login is 401', async (t) => {
  if (!ready(t)) return;
  const { id } = await manualSource();
  await withPoller(id);
  const before = { source: await sourceRow(id), poller: await pollerRow(id) };
  for (const role of ['operator', 'analyst', 'viewer'] as const) {
    const r = await call(role, 'PATCH', `/api/log-discovery/sources/${id}`, { port: 9999, endpoint: '/x', ip_address: await freeAddress() });
    assert.equal(r.status, 403, role);
  }
  assert.equal((await call(null, 'PATCH', `/api/log-discovery/sources/${id}`, { port: 9999 })).status, 401);
  assert.deepEqual({ source: await sourceRow(id), poller: await pollerRow(id) }, before);
});

test('reads show the URL being polled and the last error to every role, never the credential', async (t) => {
  if (!ready(t)) return;
  const { id, ip } = await scannedSource();
  await withPoller(id);
  await DiscoverySourcePollerModel.recordResult(id, { ok: false, count: 0, error: 'HTTP 404 from Home Assistant /api/error_log' });
  await call('admin', 'PATCH', `/api/log-discovery/sources/${id}`, { port: 8124 });

  for (const role of ROLES) {
    const poller = await call(role, 'GET', `/api/log-discovery/sources/${id}/poller`);
    assert.equal(poller.status, 200, role);
    assertNoCredential(poller.text);
    assert.equal(poller.json.configured, true);
    assert.equal(poller.json.last_error, 'HTTP 404 from Home Assistant /api/error_log');
    assert.deepEqual(poller.json.target, {
      fingerprint_id: 'home-assistant',
      manual: false,
      ip_address: ip,
      port: 8124,
      tls: false,
      effective_url: `http://${ip}:8124/api/error_log`,
      overrides: { port: 8124, tls: null, endpoint: null },
      defaults: { port: 8123, tls: false, endpoint: '/api/error_log' },
    });

    const list = await call(role, 'GET', '/api/log-discovery/sources');
    assert.equal(list.status, 200);
    assertNoCredential(list.text);
    const listed = [...list.json.top, ...list.json.advanced].find((s: any) => s.id === id);
    assert.equal(listed.poller.effective_url, `http://${ip}:8124/api/error_log`);
    assert.equal(listed.poller.last_error, 'HTTP 404 from Home Assistant /api/error_log');
    assert.equal(listed.poller_cursor, undefined, 'internal poller columns are not exposed');
  }

  // A source without a poller still describes its target (for the edit dialog).
  const bare = await manualSource();
  const r = await call('viewer', 'GET', `/api/log-discovery/sources/${bare.id}/poller`);
  assert.equal(r.json.configured, false);
  assert.equal(r.json.target.effective_url, `http://${bare.ip}:8123/api/error_log`);
});

test('run-now on a Home Assistant OS source: Supervisor fallback, remembered, native lines stored, refused connection named', async (t) => {
  if (!ready(t)) return;
  if ((await pool.query(`SELECT 1 FROM discovery_sources WHERE ip_address = '127.0.0.1'`)).rowCount) {
    return t.skip('a discovery source already uses 127.0.0.1');
  }
  // Plain INFO lines (no bans or failed logins), so no detection rule can fire on them.
  const lines = [
    '2026-10-12 14:02:57.913 INFO (MainThread) [homeassistant.bootstrap] Home Assistant initialized in 12.31s',
    '2026-10-12 14:02:58.120 INFO (MainThread) [homeassistant.setup] Setting up http',
    '2026-10-12 14:02:58.533 INFO (MainThread) [homeassistant.setup] Setup of domain http took 0.41 seconds',
  ];
  // A fake Home Assistant OS: no log file (404), the Core log through the Supervisor
  // proxy for the right token, with colours unless ?no_colors is asked for.
  const seen: string[] = [];
  const ha = http.createServer((req, res) => {
    seen.push(`${req.url} ${req.headers.range ?? '-'}`);
    if (!req.url?.startsWith('/api/hassio/core/logs')) return void res.writeHead(404).end('404: Not Found');
    if (req.headers.authorization !== `Bearer ${SECRET}`) return void res.writeHead(401).end('401: Unauthorized');
    const plain = req.url.includes('no_colors');
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(lines.map((l) => (plain ? l : `\u001b[32m${l}\u001b[0m`)).join('\n'));
  });
  ha.listen(0, '127.0.0.1');
  await once(ha, 'listening');
  const port = (ha.address() as AddressInfo).port;

  const row = await DiscoverySourceModel.upsertManual({
    ip_address: '127.0.0.1',
    hostname: `ldedit-${tag}-ha`,
    fingerprint_id: 'home-assistant',
    target_port: port,
    tls: false,
    security_value: 6,
  });
  sourceIds.add(row.id);
  await withPoller(row.id, null);
  const runNow = async () => (await call('admin', 'POST', `/api/log-discovery/sources/${row.id}/poller/run-now`)).json;
  try {
    assert.deepEqual(await runNow(), { ok: true, count: 3 });
    lines.push('2026-10-12 14:05:00.250 INFO (MainThread) [homeassistant.components.automation.porch] Porch light: Running automation actions');
    assert.deepEqual(await runNow(), { ok: true, count: 1 }, 'only the new line');
    assert.deepEqual(seen, [
      '/api/error_log -',
      '/api/hassio/core/logs?no_colors entries=:-499:500',
      '/api/hassio/core/logs?no_colors entries=:-499:500',
    ], 'one 404, then straight to the remembered Supervisor endpoint');

    const stored = await pool.query('SELECT raw_message, app_name FROM raw_logs WHERE discovery_source_id = $1 ORDER BY id', [row.id]);
    assert.deepEqual(stored.rows.map((r) => r.raw_message), lines, "Home Assistant's own lines, colour codes removed");
    assert.ok(stored.rows.every((r) => r.app_name === 'home-assistant'));
    const status = await call('admin', 'GET', `/api/log-discovery/sources/${row.id}/poller`);
    assert.equal(status.json.target.effective_url, `http://127.0.0.1:${port}/api/hassio/core/logs`);
  } finally {
    await new Promise<void>((resolve) => ha.close(() => resolve()));
  }

  // Nothing listens there now: the error names the URL it tried, and is stored.
  const refused = await runNow();
  assert.equal(refused.ok, false);
  assert.match(refused.error, new RegExp(`^Couldn't connect to http://127\\.0\\.0\\.1:${port}/api/hassio/core/logs: connection refused`));
  assert.equal((await pollerRow(row.id)).poll_cursor !== null, true, 'a failed poll keeps the last good cursor');
  const listed = await call('admin', 'GET', `/api/log-discovery/sources/${row.id}/poller`);
  assert.equal(listed.json.last_error, refused.error);
});
