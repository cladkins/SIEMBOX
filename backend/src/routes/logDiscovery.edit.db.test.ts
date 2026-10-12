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
 * - A token is only ever sent to the address it was entered for, also when an
 *   edit lands while polls run: the scheduled cycle reads each source's token
 *   and address together when its turn comes, a poll still running when its
 *   source moves does not undo the move's cursor reset, and two overlapping
 *   edits are refused (409) rather than combined.
 * - A token save or an edit made from a view of the source's old address (an
 *   Edit dialog opened before another admin moved it) is refused (409), also
 *   when the save and the move run at the same moment.
 *
 * Only the polling tests poll, and only their own local servers (127.0.0.1, or
 * other 127/8 addresses where the host has them). The other sources use
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
import { CredentialEncryption } from '../services/credentials/credentialEncryption';
import { pollDueSources } from '../services/logDiscovery/apiPoll/poller';

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

  // Address: a saved token never follows the source to a new host. Without the
  // token again the move is refused and nothing changes...
  await pool.query('UPDATE discovery_source_pollers SET poll_cursor = $2 WHERE discovery_source_id = $1', [id, 'x']);
  const newIp = await freeAddress();
  const rowBeforeMove = await sourceRow(id);
  const pollerBeforeMove = await pollerRow(id);
  r = await call('admin', 'PATCH', `/api/log-discovery/sources/${id}`, { ip_address: newIp });
  assert.equal(r.status, 400, r.text);
  assert.match(r.json.message, /needs the token again/);
  assert.deepEqual(await sourceRow(id), rowBeforeMove, 'the address did not change');
  assert.deepEqual(await pollerRow(id), pollerBeforeMove, 'the credential and cursor did not change');

  // ...and with it, the move and the token swap land together; the schedule is kept.
  const NEW_SECRET = 'replacement-token-for-the-new-address';
  r = await call('admin', 'PATCH', `/api/log-discovery/sources/${id}`, { ip_address: newIp, credential: { secret: NEW_SECRET } });
  assert.equal(r.status, 200, r.text);
  assertNoCredential(r.text);
  assert.ok(!r.text.includes(NEW_SECRET), 'the new token is never echoed');
  assert.equal((await sourceRow(id)).ip, newIp);
  const moved = await pollerRow(id);
  assert.equal(moved.poll_cursor, null);
  assert.notEqual(moved.encrypted_credential, before.encrypted_credential, 'the old ciphertext is gone');
  assert.equal(
    DiscoverySourcePollerModel.decryptCredential({ ...moved } as Parameters<typeof DiscoverySourcePollerModel.decryptCredential>[0]).secret,
    NEW_SECRET
  );
  assert.equal(moved.credential_username, null);
  assert.equal(moved.enabled, before.enabled);
  assert.equal(moved.poll_interval_minutes, before.poll_interval_minutes);
  assert.equal(r.json.target.effective_url, `https://${newIp}:8124/api/hassio/core/logs`);

  // Clearing the endpoint and the port: back to the fingerprint defaults (8123, its endpoint).
  r = await call('admin', 'PATCH', `/api/log-discovery/sources/${id}`, { endpoint: '', port: null });
  assert.equal(r.status, 200, r.text);
  assert.deepEqual((await sourceRow(id)).evidence, { manual: true, target_port: 8123, tls: true });
  assert.equal(r.json.target.effective_url, `https://${newIp}:8123/api/error_log`);
});

test('the credential field: only with an address change, only for a source with a saved token, and well-formed', async (t) => {
  if (!ready(t)) return;
  const path = (id: number) => `/api/log-discovery/sources/${id}`;

  // No saved token yet: the address can change freely (there is nothing to leak),
  // but a credential is refused (save it with the credential route instead).
  const bare = await manualSource();
  let r = await call('admin', 'PATCH', path(bare.id), { ip_address: await freeAddress() });
  assert.equal(r.status, 200, r.text);
  r = await call('admin', 'PATCH', path(bare.id), { ip_address: await freeAddress(), credential: { secret: 'x' } });
  assert.equal(r.status, 400, r.text);
  assert.match(r.json.message, /no saved token yet/);

  const saved = await manualSource();
  await withPoller(saved.id);
  const before = { source: await sourceRow(saved.id), poller: await pollerRow(saved.id) };
  const cases: Array<[unknown, RegExp]> = [
    [{ port: 8124, credential: { secret: 'x' } }, /only accepted with an address change/],
    [{ ip_address: await freeAddress(), credential: 'token' }, /credential must be an object/],
    [{ ip_address: await freeAddress(), credential: { secret: '   ' } }, /non-empty string/],
    [{ ip_address: await freeAddress(), credential: { secret: 'x'.repeat(4097) } }, /at most 4096/],
    [{ ip_address: await freeAddress(), credential: { secret: 'x', username: 42 } }, /username must be a string/],
    // The column is VARCHAR(255): one more is a 400, not a database error.
    [{ ip_address: await freeAddress(), credential: { secret: 'x', username: 'u'.repeat(256) } }, /username must be at most 255/],
  ];
  for (const [body, message] of cases) {
    r = await call('admin', 'PATCH', path(saved.id), body);
    assert.equal(r.status, 400, JSON.stringify(body));
    assert.match(r.json.message, message);
  }
  // The credential route has the same limit.
  r = await call('admin', 'POST', `${path(saved.id)}/poller/credential`, { secret: 'x', username: 'u'.repeat(256) });
  assert.equal(r.status, 400, r.text);
  assert.match(r.json.message, /username must be at most 255/);
  assert.deepEqual(await sourceRow(saved.id), before.source, 'nothing was saved');
  assert.deepEqual(await pollerRow(saved.id), before.poller, 'the credential was not touched');

  // Basic auth: the username travels with the secret, up to the column's 255 characters.
  r = await call('admin', 'PATCH', path(saved.id), {
    ip_address: await freeAddress(),
    credential: { secret: 'basic-pass', username: 'siembox' },
  });
  assert.equal(r.status, 200, r.text);
  assert.equal((await pollerRow(saved.id)).credential_username, 'siembox');
  r = await call('admin', 'PATCH', path(saved.id), {
    ip_address: await freeAddress(),
    credential: { secret: 'basic-pass', username: 'u'.repeat(255) },
  });
  assert.equal(r.status, 200, r.text);
  assert.equal((await pollerRow(saved.id)).credential_username, 'u'.repeat(255));
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
    // Each journal line ends with a newline, as the Supervisor writes it.
    res.end(lines.map((l) => `${plain ? l : `\u001b[32m${l}\u001b[0m`}\n`).join(''));
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
      '/api/error_log bytes=-5242880',
      '/api/hassio/core/logs?no_colors entries=:-2499:2500',
      '/api/hassio/core/logs?no_colors entries=:-502:503',
    ], 'one 404, then straight to the remembered Supervisor endpoint (500 new entries plus the 3-line tail window)');

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

// ---------------------------------------------------------------------------
// Edits that land while a poll runs, or while another edit is in flight
// ---------------------------------------------------------------------------

/** `n` loopback addresses (127.x.y.z, not 127.0.0.1) that no discovery source has. */
async function freeLoopbacks(n: number): Promise<string[]> {
  const found: string[] = [];
  while (found.length < n) {
    const ip = `127.${crypto.randomInt(1, 255)}.${crypto.randomInt(0, 256)}.${crypto.randomInt(1, 255)}`;
    if (found.includes(ip)) continue;
    const taken = await pool.query('SELECT 1 FROM discovery_sources WHERE ip_address = $1::inet', [ip]);
    if (taken.rowCount === 0) found.push(ip);
  }
  return found;
}

const NO_LOOPBACK_ALIASES = 'this host has no loopback addresses besides 127.0.0.1';

interface FakeHomeAssistant {
  port: number;
  /** The Authorization header of every request it got. */
  auth: string[];
  /** Resolves when its first request arrives. */
  arrived: Promise<void>;
  /** Lets held requests answer. */
  release: () => void;
  close: () => Promise<void>;
}

/**
 * A fake Home Assistant whose /api/error_log answers `lines` (plain INFO lines,
 * so no detection rule fires); with hold, only after release(). Null when the
 * host can't listen on `ip` (only 127.0.0.1 exists on some systems).
 */
async function startFakeHomeAssistant(ip: string, opts: { hold?: boolean; lines?: string[] } = {}): Promise<FakeHomeAssistant | null> {
  const lines = opts.lines ?? ['2026-10-12 14:02:57.913 INFO (MainThread) [homeassistant.bootstrap] Home Assistant initialized in 12.31s'];
  const auth: string[] = [];
  let release!: () => void;
  const released = new Promise<void>((resolve) => (release = resolve));
  let arrive!: () => void;
  const arrived = new Promise<void>((resolve) => (arrive = resolve));
  const server = http.createServer(async (req, res) => {
    auth.push(String(req.headers.authorization ?? ''));
    arrive();
    if (opts.hold) await released;
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(lines.map((line) => `${line}\n`).join('')); // every record ends with a newline, as in home-assistant.log
  });
  try {
    server.listen(0, ip);
    await once(server, 'listening');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'EADDRNOTAVAIL') return null;
    throw err;
  }
  return {
    port: (server.address() as AddressInfo).port,
    auth,
    arrived,
    release,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

async function manualSourceAt(ip: string, port: number) {
  const row = await DiscoverySourceModel.upsertManual({
    ip_address: ip,
    hostname: `ldedit-${tag}-polled`,
    fingerprint_id: 'home-assistant',
    target_port: port,
    tls: false,
    security_value: 6,
  });
  sourceIds.add(row.id);
  return row;
}

async function saveToken(id: number, secret: string) {
  await DiscoverySourcePollerModel.upsertCredential(id, { fingerprintId: 'home-assistant', method: 'api_pull', secret });
}

test("the scheduled cycle reads each source's token with its address when its turn comes: a move during the cycle never sends the old token to the new address", async (t) => {
  if (!ready(t)) return;
  const [slowIp, oldIp, newIp] = await freeLoopbacks(3);
  const slow = await startFakeHomeAssistant(slowIp, { hold: true });
  const oldHost = slow && (await startFakeHomeAssistant(oldIp));
  const newHost = oldHost && (await startFakeHomeAssistant(newIp));
  try {
    if (!slow || !oldHost || !newHost) return t.skip(NO_LOOPBACK_ALIASES);
    // A is created first, so the cycle (in id order) polls it first, and takes its time.
    const a = await manualSourceAt(slowIp, slow.port);
    const b = await manualSourceAt(oldIp, oldHost.port);
    await saveToken(a.id, 'TOKEN-A');
    await saveToken(b.id, 'OLD-TOKEN-B');
    // Only these two: sources of other test files may be due as well.
    const findDueIds = DiscoverySourcePollerModel.findDueIds.bind(DiscoverySourcePollerModel);
    t.mock.method(DiscoverySourcePollerModel, 'findDueIds', async () =>
      (await findDueIds()).filter((id) => id === a.id || id === b.id)
    );

    const cycle = pollDueSources();
    await slow.arrived; // the cycle is in A's poll; B's turn comes next
    const moved = await call('admin', 'PATCH', `/api/log-discovery/sources/${b.id}`, {
      ip_address: newIp,
      port: newHost.port,
      credential: { secret: 'NEW-TOKEN-B' },
    });
    assert.equal(moved.status, 200, moved.text);
    slow.release();
    assert.deepEqual(await cycle, { polled: 2 });

    assert.deepEqual(slow.auth, ['Bearer TOKEN-A']);
    assert.deepEqual(oldHost.auth, [], 'B was moved before its turn');
    assert.deepEqual(newHost.auth, ['Bearer NEW-TOKEN-B'], 'the new address only gets the token entered for it');
  } finally {
    slow?.release();
    await Promise.all([slow?.close(), oldHost?.close(), newHost?.close()]);
  }
});

test("a poll still running when its source moves does not undo the move's cursor reset", async (t) => {
  if (!ready(t)) return;
  const [oldIp] = await freeLoopbacks(1);
  const oldLines = [1, 2, 3].map((n) => `2026-10-12 14:0${n}:00.000 INFO (MainThread) [homeassistant.core] Line ${n} of the old host`);
  const oldHost = await startFakeHomeAssistant(oldIp, { hold: true, lines: oldLines });
  try {
    if (!oldHost) return t.skip(NO_LOOPBACK_ALIASES);
    const source = await manualSourceAt(oldIp, oldHost.port);
    await saveToken(source.id, 'OLD-TOKEN');

    const run = call('admin', 'POST', `/api/log-discovery/sources/${source.id}/poller/run-now`);
    await oldHost.arrived; // the poll is waiting for the old host's answer
    const moved = await call('admin', 'PATCH', `/api/log-discovery/sources/${source.id}`, {
      ip_address: await freeAddress(),
      credential: { secret: 'NEW-TOKEN' },
    });
    assert.equal(moved.status, 200, moved.text);
    assert.equal((await pollerRow(source.id)).poll_cursor, null, 'the move reset the cursor');

    oldHost.release();
    assert.deepEqual((await run).json, { ok: true, count: 3 }, "the old host's lines are still stored");
    const after = (
      await pool.query('SELECT poll_cursor, last_status, last_event_count FROM discovery_source_pollers WHERE discovery_source_id = $1', [
        source.id,
      ])
    ).rows[0];
    assert.equal(after.poll_cursor, null, "but its cursor doesn't replace the reset: the new address starts fresh");
    assert.equal(after.last_status, 'ok', 'the poll itself is still recorded');
    assert.equal(after.last_event_count, 3);
  } finally {
    oldHost?.release();
    await oldHost?.close();
  }
});

/** Holds the first DiscoverySourceModel.updateManualTarget call -- after the edit route's checks, before its write -- until release(). */
function holdFirstManualUpdate(t: TestContext) {
  const update = DiscoverySourceModel.updateManualTarget.bind(DiscoverySourceModel);
  let release!: () => void;
  const released = new Promise<void>((resolve) => (release = resolve));
  let arrive!: () => void;
  const arrived = new Promise<void>((resolve) => (arrive = resolve));
  let first = true;
  t.mock.method(DiscoverySourceModel, 'updateManualTarget', async (...args: Parameters<typeof update>) => {
    if (first) {
      first = false;
      arrive();
      await released;
    }
    return update(...args);
  });
  return { arrived, release };
}

test('an edit checked before another edit moved the source is refused (409): its stale address is never written back under the new token', async (t) => {
  if (!ready(t)) return;
  const { id } = await manualSource();
  await withPoller(id);
  const path = `/api/log-discovery/sources/${id}`;

  const held = holdFirstManualUpdate(t);
  const stale = call('admin', 'PATCH', path, { port: 8124 }); // checked against the current address, then held
  await held.arrived;
  const newIp = await freeAddress();
  const moved = await call('admin', 'PATCH', path, { ip_address: newIp, credential: { secret: 'NEW-TOKEN' } });
  assert.equal(moved.status, 200, moved.text);
  held.release();

  const r = await stale;
  assert.equal(r.status, 409, r.text);
  assert.match(r.json.message, /changed while it was being edited.*nothing was saved/);
  const row = await sourceRow(id);
  assert.equal(row.ip, newIp, 'the move stands');
  assert.equal(row.evidence.target_port, 8123, 'the refused edit changed nothing');
  const poller = (await pool.query('SELECT * FROM discovery_source_pollers WHERE discovery_source_id = $1', [id])).rows[0];
  assert.equal(DiscoverySourcePollerModel.decryptCredential(poller).secret, 'NEW-TOKEN', 'the token entered for the new address');
});

test('a move without a token is refused (409) when a token was saved after its check: a saved token never follows a move', async (t) => {
  if (!ready(t)) return;
  const { id, ip } = await manualSource(); // no saved token yet, so a move needs none
  const held = holdFirstManualUpdate(t);
  const move = call('admin', 'PATCH', `/api/log-discovery/sources/${id}`, { ip_address: await freeAddress() });
  await held.arrived;
  const saved = await call('admin', 'POST', `/api/log-discovery/sources/${id}/poller/credential`, { secret: SECRET });
  assert.equal(saved.status, 200, saved.text);
  held.release();

  const r = await move;
  assert.equal(r.status, 409, r.text);
  assert.equal((await sourceRow(id)).ip, ip, 'the source stays at the address its token was saved for');
  assert.ok(await pollerRow(id), 'the token is saved');
});

// ---------------------------------------------------------------------------
// Saves and edits made from a view of the old address
// ---------------------------------------------------------------------------

async function storedSecret(id: number): Promise<string | null> {
  const row = (await pool.query('SELECT * FROM discovery_source_pollers WHERE discovery_source_id = $1', [id])).rows[0];
  return row ? DiscoverySourcePollerModel.decryptCredential(row).secret : null;
}

/** Only `id` is due in pollDueSources (sources of other test files may be due as well). */
function onlyDue(t: TestContext, id: number) {
  const findDueIds = DiscoverySourcePollerModel.findDueIds.bind(DiscoverySourcePollerModel);
  t.mock.method(DiscoverySourcePollerModel, 'findDueIds', async () => (await findDueIds()).filter((due) => due === id));
}

/** Resolves once a request of this database waits for a row lock on a Log Discovery table (held by the test's open transaction). */
async function lockWaiter(): Promise<void> {
  for (let attempt = 0; attempt < 250; attempt++) {
    const waiting = await pool.query(
      `SELECT 1 FROM pg_stat_activity
        WHERE datname = current_database() AND pid <> pg_backend_pid()
          AND wait_event_type = 'Lock' AND query ILIKE '%discovery_source%'`
    );
    if (waiting.rowCount) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error('no request waited for the lock');
}

test('a token entered while the source was shown at its old address is refused (409) after another admin moved it: it never reaches the new address', async (t) => {
  if (!ready(t)) return;
  const [ipA, ipC] = await freeLoopbacks(2);
  const hostA = await startFakeHomeAssistant(ipA);
  const hostC = hostA && (await startFakeHomeAssistant(ipC));
  try {
    if (!hostA || !hostC) return t.skip(NO_LOOPBACK_ALIASES);
    const source = await manualSourceAt(ipA, hostA.port);
    const path = `/api/log-discovery/sources/${source.id}`;
    let r = await call('admin', 'POST', `${path}/poller/credential`, { secret: 'TOKEN-FOR-A', expected_ip_address: ipA });
    assert.equal(r.status, 200, r.text);

    // Admin 1 opens Edit: the source is at A. Admin 2 then moves it to C, with C's token.
    const view = (await call('admin', 'GET', `${path}/poller`)).json.target;
    assert.equal(view.ip_address, ipA);
    r = await call('admin', 'PATCH', path, {
      ip_address: ipC,
      port: hostC.port,
      credential: { secret: 'TOKEN-FOR-C' },
      expected_ip_address: ipA,
    });
    assert.equal(r.status, 200, r.text);

    // Admin 1 pastes a new token for the Home Assistant at A, as the dialog sends it.
    r = await call('admin', 'POST', `${path}/poller/credential`, { secret: 'ROTATED-TOKEN-FOR-A', expected_ip_address: view.ip_address });
    assert.equal(r.status, 409, r.text);
    assert.match(r.json.message, /no longer at the address this token was entered for.*not saved/);
    assert.equal(await storedSecret(source.id), 'TOKEN-FOR-C', "C's token stands");

    const polled = await call('admin', 'POST', `${path}/poller/run-now`);
    assert.equal(polled.json?.ok, true, polled.text);
    assert.deepEqual(hostC.auth, ['Bearer TOKEN-FOR-C'], 'C only ever gets the token entered for it');
    assert.deepEqual(hostA.auth, []);

    // Entered for C (the address the source has now), the same save goes through.
    r = await call('admin', 'POST', `${path}/poller/credential`, { secret: 'ROTATED-TOKEN-FOR-C', expected_ip_address: ipC });
    assert.equal(r.status, 200, r.text);
    assert.equal(await storedSecret(source.id), 'ROTATED-TOKEN-FOR-C');
  } finally {
    await Promise.all([hostA?.close(), hostC?.close()]);
  }
});

test('after a move without a token, a token entered for the old address is refused (409): nothing is saved and the new address gets no request', async (t) => {
  if (!ready(t)) return;
  const [ipA, ipC] = await freeLoopbacks(2);
  const hostC = await startFakeHomeAssistant(ipC);
  try {
    if (!hostC) return t.skip(NO_LOOPBACK_ALIASES);
    const source = await manualSourceAt(ipA, 8123); // no saved token, so a move needs none
    const path = `/api/log-discovery/sources/${source.id}`;
    let r = await call('admin', 'PATCH', path, { ip_address: ipC, port: hostC.port, expected_ip_address: ipA });
    assert.equal(r.status, 200, r.text);

    r = await call('admin', 'POST', `${path}/poller/credential`, { secret: 'TOKEN-TYPED-FOR-A', expected_ip_address: ipA });
    assert.equal(r.status, 409, r.text);
    assert.equal(await pollerRow(source.id), undefined, 'no token was saved');
    onlyDue(t, source.id);
    assert.deepEqual(await pollDueSources(), { polled: 0 });
    assert.deepEqual(hostC.auth, []);

    // Without expected_ip_address (an API client), a token is saved for the address the source has now.
    r = await call('admin', 'POST', `${path}/poller/credential`, { secret: 'TOKEN-FOR-C' });
    assert.equal(r.status, 200, r.text);
    assert.deepEqual(await pollDueSources(), { polled: 1 });
    assert.deepEqual(hostC.auth, ['Bearer TOKEN-FOR-C']);
  } finally {
    await hostC?.close();
  }
});

test('a move without a token that waits behind a token save in progress is refused (409) once the save commits', async (t) => {
  if (!ready(t)) return;
  const { id, ip } = await manualSource(); // no saved token, so a move needs none
  const newIp = await freeAddress();
  const save = await pool.connect();
  try {
    // A token save that has written its row but not committed yet, as
    // POST .../poller/credential does for the length of its statement.
    await save.query('BEGIN');
    const enc = CredentialEncryption.encrypt(SECRET);
    await save.query(
      `INSERT INTO discovery_source_pollers (discovery_source_id, fingerprint_id, log_access_method, encrypted_credential, encryption_iv, encryption_auth_tag)
       VALUES ($1, 'home-assistant', 'api_pull', $2, $3, $4)`,
      [id, enc.encrypted, enc.iv, enc.authTag]
    );
    const move = call('admin', 'PATCH', `/api/log-discovery/sources/${id}`, { ip_address: newIp, expected_ip_address: ip });
    await lockWaiter(); // the move waits for the save's lock on the source row
    await save.query('COMMIT');

    const r = await move;
    assert.equal(r.status, 409, r.text);
    assert.equal((await sourceRow(id)).ip, ip, 'the source stays at the address its token was saved for');
    assert.equal(await storedSecret(id), SECRET);
  } finally {
    await save.query('ROLLBACK').catch(() => {}); // only if the test failed before the COMMIT
    save.release();
  }
});

test('a token save that waits behind a move in progress is refused (409) once the move commits', async (t) => {
  if (!ready(t)) return;
  const { id, ip } = await manualSource();
  const newIp = await freeAddress();
  const move = await pool.connect();
  try {
    // A move that has changed the address but not committed yet.
    await move.query('BEGIN');
    await move.query('UPDATE discovery_sources SET ip_address = $2 WHERE id = $1', [id, newIp]);
    const save = call('admin', 'POST', `/api/log-discovery/sources/${id}/poller/credential`, {
      secret: 'TOKEN-TYPED-FOR-THE-OLD-ADDRESS',
      expected_ip_address: ip,
    });
    await lockWaiter(); // the save waits for the move's lock on the source row
    await move.query('COMMIT');

    const r = await save;
    assert.equal(r.status, 409, r.text);
    assert.equal(await pollerRow(id), undefined, 'no token was saved for the moved source');
  } finally {
    await move.query('ROLLBACK').catch(() => {}); // only if the test failed before the COMMIT
    move.release();
  }
});

test('an edit sent with the address it was loaded with is refused (409) once the source moved; nothing changes', async (t) => {
  if (!ready(t)) return;
  const { id, ip } = await manualSource();
  await withPoller(id);
  const path = `/api/log-discovery/sources/${id}`;
  const newIp = await freeAddress();
  let r = await call('admin', 'PATCH', path, { ip_address: newIp, credential: { secret: 'NEW-TOKEN' }, expected_ip_address: ip });
  assert.equal(r.status, 200, r.text);

  // An Edit dialog still open on the old address saves a port change.
  const before = { source: await sourceRow(id), poller: await pollerRow(id) };
  r = await call('admin', 'PATCH', path, { port: 8124, expected_ip_address: ip });
  assert.equal(r.status, 409, r.text);
  assert.match(r.json.message, /changed while it was being edited.*nothing was saved/);
  assert.deepEqual({ source: await sourceRow(id), poller: await pollerRow(id) }, before, 'nothing changed');

  // Sent with the address the source has now, it applies.
  r = await call('admin', 'PATCH', path, { port: 8124, expected_ip_address: newIp });
  assert.equal(r.status, 200, r.text);
  assert.equal((await sourceRow(id)).evidence.target_port, 8124);

  // A malformed expected_ip_address is a 400 on both routes, and nothing is saved.
  const malformed: Array<[string, string, unknown]> = [
    ['PATCH', path, { port: 8125, expected_ip_address: 'homeassistant.local' }],
    ['POST', `${path}/poller/credential`, { secret: 'x', expected_ip_address: '203.0.113.0/24' }],
  ];
  for (const [method, url, body] of malformed) {
    r = await call('admin', method, url, body);
    assert.equal(r.status, 400, `${method} ${r.text}`);
    assert.match(r.json.message, /expected_ip_address must be a literal IPv4 or IPv6 address/);
  }
  assert.equal((await sourceRow(id)).evidence.target_port, 8124);
  assert.equal(await storedSecret(id), 'NEW-TOKEN');
});
