/**
 * Suggested scans, end to end: the real app on an ephemeral port and a real
 * Postgres. GET lists the suggestions for every role; "Add" (operators and
 * admins; analysts and viewers get an audited 403) creates a DISABLED
 * scheduled scan of the suggestion's type with its options and calendar
 * timing in the caller's time zone and no targets, or an unassigned endpoint
 * scan policy. Such a schedule cannot be enabled or run until its targets are
 * filled in; log discovery schedules are a scheduled-scan type of their own.
 *
 * The catalog read is primed from a getter that fails, so the route serves
 * the bundled starter set from the cache and no test touches the network.
 * Nothing created here is enabled with a due next run, so the dispatcher never
 * starts one. Skips itself when Postgres isn't reachable. Rows created here are
 * removed again, with what an interrupted run left behind.
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
import { clearScanCatalogCache, fetchScanCatalog } from '../services/scanSuggestions/scanCatalog';
import { BUNDLED_SCAN_DOCS } from '../services/scanSuggestions/bundledScans';

const ROLES = ['admin', 'operator', 'analyst', 'viewer'] as const;
type Role = (typeof ROLES)[number];
const SKIP = 'Postgres with the scheduled-scan and scan-policy schema is not reachable';
const TEST_NAME = '^scansuggest-[0-9a-f]{12}';

let dbReady = false;
let server: Server | undefined;
let base = '';
const tag = crypto.randomBytes(6).toString('hex');
const name = `scansuggest-${tag}`;
const tokens = {} as Record<Role, string>;
const userIds: number[] = [];

before(async () => {
  try {
    await pool.query('SELECT schedule FROM scheduled_scans LIMIT 1');
    await pool.query('SELECT performance FROM edr_scan_policies LIMIT 1');
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
  clearScanCatalogCache();
  await fetchScanCatalog({
    force: true,
    get: async () => {
      throw new Error('offline in scanSuggestions.db.test');
    },
  });
  server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  if (dbReady) {
    const stale = `created_at < NOW() - INTERVAL '10 minutes'`;
    const leftover = await pool.query(`SELECT id FROM users WHERE username ~ $1 AND email LIKE '%@siembox.invalid' AND ${stale}`, [TEST_NAME]);
    const doomed = [...userIds, ...leftover.rows.map((row) => row.id as number)];
    await pool.query('DELETE FROM scheduled_scans WHERE created_by = ANY($1) OR name LIKE $2', [doomed, `${name}%`]);
    await pool.query('DELETE FROM edr_scan_policies WHERE NOT is_default AND created_by = ANY($1)', [doomed]);
    await pool.query('DELETE FROM audit_logs WHERE user_id = ANY($1)', [doomed]);
    await pool.query('DELETE FROM application_errors WHERE user_id = ANY($1)', [doomed]);
    await pool.query('DELETE FROM users WHERE id = ANY($1)', [doomed]);
  }
  clearScanCatalogCache();
  await closePools();
});

async function call(role: Role, method: string, path: string, body?: unknown) {
  const res = await fetch(base + path, {
    method,
    headers: { Authorization: `Bearer ${tokens[role]}`, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, json: (await res.json().catch(() => null)) as any };
}

async function scheduleRow(id: number) {
  return (await pool.query('SELECT * FROM scheduled_scans WHERE id = $1', [id])).rows[0];
}

test('every role lists the suggestions (here, the bundled starter set)', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  for (const role of ROLES) {
    const r = await call(role, 'GET', '/api/scan-suggestions');
    assert.equal(r.status, 200, role);
    assert.equal(r.json.source, 'bundled');
    assert.equal(r.json.suggestions.length, BUNDLED_SCAN_DOCS.length);
    assert.ok(r.json.suggestions.every((s: any) => s.id && s.kind && Array.isArray(s.inputs)));
  }
});

test('analysts and viewers cannot add a suggestion (audited 403, nothing created)', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const before = (await pool.query('SELECT COUNT(*)::int AS n FROM scheduled_scans WHERE created_by = ANY($1)', [userIds])).rows[0].n;
  for (const role of ['analyst', 'viewer'] as const) {
    for (const id of ['asset-host-discovery-daily', 'endpoint-servers-nightly-full']) {
      const r = await call(role, 'POST', `/api/scan-suggestions/${id}/add`, { timezone: 'UTC' });
      assert.equal(r.status, 403, `${role} ${id}`);
    }
  }
  const after = (await pool.query('SELECT COUNT(*)::int AS n FROM scheduled_scans WHERE created_by = ANY($1)', [userIds])).rows[0].n;
  assert.equal(after, before);
  const policies = await pool.query('SELECT 1 FROM edr_scan_policies WHERE created_by = ANY($1)', [userIds]);
  assert.equal(policies.rowCount, 0);
  const denied = await pool.query(
    `SELECT COUNT(*)::int AS n FROM audit_logs WHERE action = 'access.denied' AND resource_type = 'scan_suggestion' AND user_id = ANY($1)`,
    [userIds]
  );
  assert.equal(denied.rows[0].n, 4);
});

test('adding an asset suggestion: a disabled schedule, its options and timing in the caller\'s zone, no targets', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const r = await call('operator', 'POST', '/api/scan-suggestions/asset-host-discovery-daily/add', { timezone: 'America/Chicago' });
  assert.equal(r.status, 201, JSON.stringify(r.json));
  const s = r.json.scheduled_scan;
  assert.equal(r.json.kind, 'asset');
  assert.equal(s.scan_type, 'asset');
  assert.equal(s.enabled, false);
  assert.equal(s.name, 'Daily host discovery (ping sweep)');
  assert.deepEqual(s.scan_options, { scanType: 'ping' });
  assert.deepEqual(s.schedule, { frequency: 'daily', time: '01:15', timezone: 'America/Chicago' });
  assert.equal(s.interval_minutes, null);
  assert.deepEqual(r.json.inputs.map((i: any) => i.field), ['targets', 'shipper']);

  const audit = await pool.query(`SELECT resource_id, details FROM audit_logs WHERE action = 'scan_suggestion.add' AND resource_id = $1`, [s.id]);
  assert.equal(audit.rows[0]?.details?.suggestion_id, 'asset-host-discovery-daily');

  const list = await call('operator', 'GET', '/api/scheduled-scans');
  assert.deepEqual(list.json.find((x: any) => x.id === s.id).missing_inputs, ['targets']);

  // Not enabled or run until the targets are in.
  const enable = await call('operator', 'PUT', `/api/scheduled-scans/${s.id}`, { enabled: true });
  assert.equal(enable.status, 400);
  assert.match(enable.json.message ?? enable.json.error, /Fill in targets/);
  const run = await call('operator', 'POST', `/api/scheduled-scans/${s.id}/run`);
  assert.equal(run.status, 400);
  assert.equal((await scheduleRow(s.id)).enabled, false);
  const blank = await call('operator', 'PUT', `/api/scheduled-scans/${s.id}`, { scan_options: { scanType: 'ping', targets: [] } });
  assert.equal(blank.status, 400);

  // Filled in from the edit dialog: saved and enabled.
  const filled = await call('operator', 'PUT', `/api/scheduled-scans/${s.id}`, { scan_options: { scanType: 'ping', targets: ['192.0.2.0/28'] }, enabled: true });
  assert.equal(filled.status, 200, JSON.stringify(filled.json));
  assert.equal(filled.json.enabled, true);
  assert.deepEqual(filled.json.schedule, s.schedule, 'timing unchanged');
  assert.ok(new Date(filled.json.next_run_at).getTime() > Date.now() - 60_000);
  assert.equal((await call('operator', 'PUT', `/api/scheduled-scans/${s.id}`, { enabled: false })).status, 200);
});

test('vulnerability, container and log discovery suggestions keep their options; time zone defaults to UTC', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const vuln = await call('admin', 'POST', '/api/scan-suggestions/vuln-known-exploited-daily/add', {});
  assert.equal(vuln.status, 201, JSON.stringify(vuln.json));
  assert.equal(vuln.json.scheduled_scan.scan_type, 'vulnerability');
  assert.equal(vuln.json.scheduled_scan.schedule.timezone, 'UTC');
  assert.deepEqual(vuln.json.scheduled_scan.scan_options, {
    templateSelection: { tags: ['kev'], excludeTags: ['intrusive', 'dos', 'fuzz'] },
    rateLimit: 100,
  });
  assert.equal(vuln.json.scheduled_scan.enabled, false);

  // All images: nothing to fill in, so it can be enabled as it is.
  const container = await call('operator', 'POST', '/api/scan-suggestions/container-all-images-nightly/add', { timezone: 'Europe/Berlin' });
  assert.equal(container.status, 201);
  assert.deepEqual(container.json.scheduled_scan.scan_options, { all_images: true });
  assert.equal(container.json.scheduled_scan.enabled, false);
  const list = await call('operator', 'GET', '/api/scheduled-scans');
  assert.deepEqual(list.json.find((x: any) => x.id === container.json.scheduled_scan.id).missing_inputs, []);

  const disc = await call('operator', 'POST', '/api/scan-suggestions/logdisc-passive-daily/add', { timezone: 'Asia/Tokyo' });
  assert.equal(disc.status, 201);
  assert.equal(disc.json.scheduled_scan.scan_type, 'log_discovery');
  assert.deepEqual(disc.json.scheduled_scan.scan_options, { mode: 'passive' });
  assert.deepEqual(disc.json.scheduled_scan.schedule, { frequency: 'daily', time: '00:45', timezone: 'Asia/Tokyo' });

  assert.equal((await call('operator', 'POST', '/api/scan-suggestions/vuln-known-exploited-daily/add', { timezone: '+05:00' })).status, 400);
  assert.equal((await call('operator', 'POST', '/api/scan-suggestions/no-such-suggestion/add', {})).status, 404);
  assert.equal((await call('operator', 'POST', '/api/scan-suggestions/BAD..id/add', {})).status, 400);
});

test('an endpoint policy suggestion becomes an unassigned named policy; a taken name gets a number', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const first = await call('operator', 'POST', '/api/scan-suggestions/endpoint-servers-nightly-full/add', { timezone: 'America/New_York' });
  assert.equal(first.status, 201, JSON.stringify(first.json));
  const p = first.json.policy;
  assert.equal(first.json.kind, 'endpoint_policy');
  assert.equal(p.is_default, false);
  assert.equal(p.name, 'Servers — nightly full');
  assert.deepEqual(p.scans.vuln, {
    enabled: true,
    schedule: { frequency: 'daily', time: '02:00', timezone: 'America/New_York' },
    interval_minutes: null,
    window: { start: '00:00', end: '06:00', timezone: 'America/New_York' },
  });
  assert.deepEqual(p.scans.inventory, { enabled: true, schedule: null, interval_minutes: 60, window: null });
  const assigned = await pool.query('SELECT COUNT(*)::int AS n FROM edr_agents WHERE scan_policy_id = $1', [p.id]);
  assert.equal(assigned.rows[0].n, 0, 'no endpoint follows it yet');

  const second = await call('admin', 'POST', '/api/scan-suggestions/endpoint-servers-nightly-full/add', { timezone: 'UTC' });
  assert.equal(second.status, 201);
  assert.equal(second.json.policy.name, 'Servers — nightly full (2)');
  const listed = await call('operator', 'GET', '/api/edr/scan-policies');
  assert.ok(listed.json.policies.some((x: any) => x.id === p.id && (x.endpoint_count ?? 0) === 0));
});

test('log discovery is a scheduled-scan type: manual CIDRs checked, saved scope used without them', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const bad = await call('operator', 'POST', '/api/scheduled-scans', {
    name: `${name}-disc-bad`,
    scan_type: 'log_discovery',
    scan_options: { mode: 'active', manual_cidrs: ['not-a-cidr'] },
    schedule: { frequency: 'daily', time: '03:00', timezone: 'UTC' },
    enabled: false,
  });
  assert.equal(bad.status, 400);
  assert.match(bad.json.message ?? bad.json.error, /manual_cidrs/);
  const mode = await call('operator', 'POST', '/api/scheduled-scans', {
    name: `${name}-disc-mode`,
    scan_type: 'log_discovery',
    scan_options: { mode: 'loud' },
    schedule: { frequency: 'daily', time: '03:00', timezone: 'UTC' },
    enabled: false,
  });
  assert.equal(mode.status, 400);
  const ok = await call('operator', 'POST', '/api/scheduled-scans', {
    name: `${name}-disc`,
    scan_type: 'log_discovery',
    scan_options: { mode: 'full', manual_cidrs: ['192.168.50.0/24'] },
    schedule: { frequency: 'weekly', days: [2], time: '03:00', timezone: 'UTC' },
    enabled: false,
  });
  assert.equal(ok.status, 201, JSON.stringify(ok.json));
  assert.equal(ok.json.scan_type, 'log_discovery');
  const publicCidr = await call('operator', 'PUT', `/api/scheduled-scans/${ok.json.id}`, { scan_options: { mode: 'full', manual_cidrs: ['8.8.8.0/24'] } });
  assert.equal(publicCidr.status, 400, 'public CIDRs need confirming, as on the Log Discovery page');
  const unknown = await call('operator', 'POST', '/api/scheduled-scans', {
    name: `${name}-x`,
    scan_type: 'portscan',
    scan_options: {},
    interval_minutes: 60,
  });
  assert.equal(unknown.status, 400);
  assert.match(unknown.json.message ?? unknown.json.error, /asset, vulnerability, container, log_discovery/);
});
