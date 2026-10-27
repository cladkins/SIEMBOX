/**
 * Endpoint scan policies end to end: the real app on an ephemeral port, a real
 * Postgres, one user per role with a session, and endpoint agents with known
 * keys calling the agent routes as the Go agent does.
 *
 * - policy CRUD: who may write (operators and admins), validation, unique
 *   names, the default can be edited but not deleted, deleting a named policy
 *   moves its endpoints back to the default;
 * - an endpoint's effective policy: default -> named policy -> per-type override;
 *   bulk assignment; config_version rises so agents re-pull their config;
 * - the agent config's scan_policy (managed, policy name, enabled per type);
 * - heartbeat: a policy_scans agent is issued its due scans as scan_requests
 *   (trigger policy), once while outstanding; its reports finish them and the
 *   history names the policy; an agent without the capability gets none;
 * - due computation over time (service level, injected clock): catch-up once
 *   after being offline, a window that holds a due run, a disabled type.
 *
 * Skips itself when Postgres isn't reachable. The default policy is restored
 * and every row created here (users, agents, policies, audit rows) removed.
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
import { EdrAgentModel, sha256hex } from '../models/EdrAgent';
import { issueDuePolicyScans, BUILTIN_DEFAULT_SCANS, type PolicyScans } from '../services/edr/scanPolicies';

const ROLES = ['admin', 'operator', 'analyst'] as const;
type Role = (typeof ROLES)[number];
const SKIP = 'Postgres with migration 054 (edr_scan_policies) is not reachable';
const tag = crypto.randomBytes(5).toString('hex');
const name = `scanpol-${tag}`;

let dbReady = false;
let server: Server | undefined;
let base = '';
const tokens = {} as Record<Role, string>;
const userIds: number[] = [];
const policyIds: number[] = [];
let defaultPolicy: { id: number; name: string; description: string | null; scans: unknown } | null = null;

interface TestAgent {
  id: string;
  key: string;
}
const agents: TestAgent[] = [];

async function makeAgent(): Promise<TestAgent> {
  const a = { id: crypto.randomUUID(), key: crypto.randomBytes(32).toString('hex') };
  await EdrAgentModel.create({ agent_id: a.id, api_key_hash: sha256hex(a.key), asset_id: null, hostname: `${name}-host` });
  agents.push(a);
  return a;
}

before(async () => {
  try {
    await pool.query('SELECT 1 FROM edr_scan_policies LIMIT 1');
    await pool.query('SELECT 1 FROM edr_agent_policy_runs LIMIT 1');
    dbReady = true;
  } catch {
    return;
  }
  const d = await pool.query('SELECT id, name, description, scans FROM edr_scan_policies WHERE is_default');
  defaultPolicy = d.rows[0];
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
    if (defaultPolicy) {
      await pool.query('UPDATE edr_scan_policies SET name = $2, description = $3, scans = $4::jsonb WHERE id = $1', [
        defaultPolicy.id, defaultPolicy.name, defaultPolicy.description, JSON.stringify(defaultPolicy.scans),
      ]);
    }
    await pool.query('DELETE FROM edr_agents WHERE agent_id = ANY($1::uuid[])', [agents.map((a) => a.id)]);
    await pool.query('DELETE FROM edr_scan_policies WHERE id = ANY($1) OR name LIKE $2', [policyIds, `${name}%`]);
    for (let attempt = 0; attempt < 30; attempt++) {
      // 403s are logged to application_errors fire-and-forget; let them land.
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    await pool.query('DELETE FROM application_errors WHERE user_id = ANY($1)', [userIds]);
    await pool.query('DELETE FROM audit_logs WHERE user_id = ANY($1)', [userIds]);
    await pool.query('DELETE FROM users WHERE id = ANY($1)', [userIds]);
  }
  await closePools();
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- assertions read whatever the API sent
type Json = any;

async function call(role: Role, method: string, path: string, body?: unknown): Promise<{ status: number; body: Json }> {
  const headers: Record<string, string> = { Authorization: `Bearer ${tokens[role]}` };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

async function agentCall(a: TestAgent, method: string, path: string, body?: unknown): Promise<{ status: number; body: Json }> {
  const headers: Record<string, string> = { Authorization: `Bearer ${a.key}`, 'X-Agent-ID': a.id };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

const heartbeat = (a: TestAgent, capabilities: string[]) =>
  agentCall(a, 'POST', `/api/edr/agents/${a.id}/heartbeat`, { status: 'online', agent_version: '0.0.22', capabilities });

const POLICY_CAPS = ['adhoc_scans', 'policy_scans'];

function scans(overrides: Partial<PolicyScans> = {}): PolicyScans {
  return { ...BUILTIN_DEFAULT_SCANS, ...overrides };
}

const configVersion = async (a: TestAgent) =>
  (await pool.query('SELECT config_version FROM edr_agents WHERE agent_id = $1', [a.id])).rows[0].config_version as number;

const dailyAt = (time: string) => ({
  enabled: true,
  schedule: { frequency: 'daily', time, timezone: 'UTC' },
  interval_minutes: null,
  window: null,
});

test('policy CRUD: operators and admins write, analysts read; validation and names', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const list = await call('analyst', 'GET', '/api/edr/scan-policies');
  assert.equal(list.status, 200);
  assert.equal(list.body.policies[0].is_default, true);
  assert.equal(list.body.min_agent_version, '0.0.22');
  assert.deepEqual(Object.keys(list.body.policies[0].scans), ['vuln', 'yara', 'packages', 'inventory']);

  const body = { name: `${name}-servers`, description: 'nightly', scans: scans({ vuln: dailyAt('02:00') }) };
  assert.equal((await call('analyst', 'POST', '/api/edr/scan-policies', body)).status, 403);
  const created = await call('operator', 'POST', '/api/edr/scan-policies', body);
  assert.equal(created.status, 201, JSON.stringify(created.body));
  policyIds.push(created.body.policy.id);
  assert.equal(created.body.policy.is_default, false);
  assert.deepEqual(created.body.policy.scans.vuln.schedule, { frequency: 'daily', timezone: 'UTC', time: '02:00' });

  const dup = await call('admin', 'POST', '/api/edr/scan-policies', { ...body, name: body.name.toUpperCase() });
  assert.equal(dup.status, 409);
  const bad = await call('admin', 'POST', '/api/edr/scan-policies', { name: `${name}-bad`, scans: { vuln: BUILTIN_DEFAULT_SCANS.vuln } });
  assert.equal(bad.status, 400);
  assert.match(bad.body.message ?? bad.body.error, /scans.yara is required/);
  const badWindow = await call('admin', 'POST', '/api/edr/scan-policies', {
    name: `${name}-bad`,
    scans: scans({ yara: { ...BUILTIN_DEFAULT_SCANS.yara, window: { start: '01:00', end: '01:00', timezone: 'UTC' } } }),
  });
  assert.equal(badWindow.status, 400);
  assert.equal((await call('admin', 'POST', '/api/edr/scan-policies', { scans: scans() })).status, 400);

  const renamed = await call('admin', 'PUT', `/api/edr/scan-policies/${created.body.policy.id}`, { name: `${name}-servers2` });
  assert.equal(renamed.status, 200);
  assert.equal(renamed.body.policy.name, `${name}-servers2`);
  assert.deepEqual(renamed.body.policy.scans.vuln, created.body.policy.scans.vuln, 'a rename keeps the scans');
  assert.equal((await call('analyst', 'PUT', `/api/edr/scan-policies/${created.body.policy.id}`, { name: 'x' })).status, 403);
  assert.equal((await call('admin', 'GET', '/api/edr/scan-policies/999999999')).status, 404);
  assert.equal((await call('admin', 'GET', '/api/edr/scan-policies/abc')).status, 404);

  // The default: editable, never deletable.
  const def = list.body.policies[0];
  assert.equal((await call('admin', 'DELETE', `/api/edr/scan-policies/${def.id}`)).status, 400);
  const edited = await call('operator', 'PUT', `/api/edr/scan-policies/${def.id}`, { scans: scans({ packages: { ...BUILTIN_DEFAULT_SCANS.packages, enabled: false } }) });
  assert.equal(edited.status, 200);
  assert.equal(edited.body.policy.scans.packages.enabled, false);
  await call('operator', 'PUT', `/api/edr/scan-policies/${def.id}`, { scans: scans() });

  const preview = await call('operator', 'POST', '/api/edr/scan-policies/preview', { spec: dailyAt('03:00'), count: 2 });
  assert.equal(preview.status, 200);
  assert.equal(preview.body.next_runs.length, 2);
  assert.ok(preview.body.next_runs.every((r: string) => r.endsWith('T03:00:00.000Z')));
  assert.equal((await call('analyst', 'POST', '/api/edr/scan-policies/preview', { spec: dailyAt('03:00') })).status, 403);
  assert.equal((await call('operator', 'POST', '/api/edr/scan-policies/preview', { spec: { enabled: true } })).status, 400);

  // The audit trail names each write.
  const audit = await pool.query(
    `SELECT action FROM audit_logs WHERE user_id = ANY($1) AND action LIKE 'edr.scan_policy.%' ORDER BY id`,
    [userIds]
  );
  assert.ok(audit.rows.some((r) => r.action === 'edr.scan_policy.create'));
  assert.ok(audit.rows.some((r) => r.action === 'edr.scan_policy.update'));
});

test('effective policy: default -> named -> override; assignment bumps config_version', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const a = await makeAgent();
  const b = await makeAgent();
  const pol = await call('admin', 'POST', '/api/edr/scan-policies', {
    name: `${name}-weekly`,
    scans: scans({ vuln: { enabled: true, schedule: { frequency: 'weekly', time: '01:30', days: [0], timezone: 'UTC' }, interval_minutes: null, window: null } }),
  });
  assert.equal(pol.status, 201);
  policyIds.push(pol.body.policy.id);

  let view = await call('analyst', 'GET', `/api/edr/agents/${a.id}/scan-policy`);
  assert.equal(view.status, 200);
  assert.equal(view.body.policy.is_default, true);
  assert.equal(view.body.assigned_policy_id, null);
  assert.equal(view.body.managed, false, 'no capability reported yet');
  assert.ok(view.body.local_intervals);
  assert.deepEqual(view.body.scans.map((s: Json) => [s.scan_type, s.source]), [
    ['vuln', 'policy'], ['yara', 'policy'], ['packages', 'policy'], ['inventory', 'policy'],
  ]);
  assert.equal(view.body.scans[0].spec.interval_minutes, 1440);

  // Bulk assignment: analysts may not; the named policy then applies.
  const before = await configVersion(a);
  assert.equal((await call('analyst', 'POST', '/api/edr/agents/scan-policy', { agent_ids: [a.id], policy_id: pol.body.policy.id })).status, 403);
  const missing = crypto.randomUUID();
  const assigned = await call('operator', 'POST', '/api/edr/agents/scan-policy', { agent_ids: [a.id, b.id, missing], policy_id: pol.body.policy.id });
  assert.equal(assigned.status, 200, JSON.stringify(assigned.body));
  assert.equal(assigned.body.agents, 2);
  assert.deepEqual(assigned.body.missing, [missing]);
  assert.equal(await configVersion(a), before + 1);
  assert.equal((await call('operator', 'POST', '/api/edr/agents/scan-policy', { agent_ids: [a.id], policy_id: 999999999 })).status, 400);
  assert.equal((await call('operator', 'POST', '/api/edr/agents/scan-policy', { agent_ids: ['nope'], policy_id: null })).status, 400);

  view = await call('analyst', 'GET', `/api/edr/agents/${a.id}/scan-policy`);
  assert.equal(view.body.policy.name, `${name}-weekly`);
  assert.equal(view.body.scans[0].spec.schedule.frequency, 'weekly');

  // Override one type on one endpoint.
  const override = { vuln: dailyAt('04:15'), yara: { ...BUILTIN_DEFAULT_SCANS.yara, enabled: false } };
  assert.equal((await call('analyst', 'PUT', `/api/edr/agents/${a.id}/scan-policy`, { overrides: override })).status, 403);
  const set = await call('operator', 'PUT', `/api/edr/agents/${a.id}/scan-policy`, { overrides: override });
  assert.equal(set.status, 200, JSON.stringify(set.body));
  assert.deepEqual(set.body.scans.map((s: Json) => [s.scan_type, s.source, s.spec.enabled]), [
    ['vuln', 'override', true], ['yara', 'override', false], ['packages', 'policy', true], ['inventory', 'policy', true],
  ]);
  assert.deepEqual(set.body.scans[1].next_runs, [], 'a disabled type has no next runs');
  assert.equal((await call('operator', 'PUT', `/api/edr/agents/${a.id}/scan-policy`, { overrides: { nmap: dailyAt('01:00') } })).status, 400);
  assert.equal((await call('operator', 'PUT', `/api/edr/agents/${a.id}/scan-policy`, {})).status, 400);
  assert.equal((await call('operator', 'PUT', `/api/edr/agents/${crypto.randomUUID()}/scan-policy`, { overrides: null })).status, 404);

  // The other endpoint on the same policy has no override.
  const other = await call('analyst', 'GET', `/api/edr/agents/${b.id}/scan-policy`);
  assert.equal(other.body.scans[0].source, 'policy');

  // The list shows the policy name and the override count.
  const list = await call('analyst', 'GET', '/api/edr/agents');
  const row = list.body.agents.find((x: Json) => x.agent_id === a.id);
  assert.equal(row.scan_policy_name, `${name}-weekly`);
  assert.equal(row.scan_policy_override_count, 2);
  const policies = await call('analyst', 'GET', '/api/edr/scan-policies');
  assert.equal(policies.body.policies.find((p: Json) => p.id === pol.body.policy.id).endpoint_count, 2);

  // Deleting the policy moves both endpoints back to the default (and bumps them).
  const v = await configVersion(b);
  const del = await call('operator', 'DELETE', `/api/edr/scan-policies/${pol.body.policy.id}`);
  assert.equal(del.status, 200);
  assert.equal(del.body.endpoints, 2);
  assert.equal(await configVersion(b), v + 1);
  view = await call('analyst', 'GET', `/api/edr/agents/${a.id}/scan-policy`);
  assert.equal(view.body.policy.is_default, true);
  assert.equal(view.body.scans[0].source, 'override', 'overrides survive the policy');

  // Clearing overrides and assigning the default by its id.
  const cleared = await call('admin', 'PUT', `/api/edr/agents/${a.id}/scan-policy`, { overrides: {}, policy_id: view.body.policy.id });
  assert.equal(cleared.status, 200);
  assert.equal(cleared.body.assigned_policy_id, null, 'the default is stored as no assignment');
  assert.deepEqual(cleared.body.overrides, {});
});

test('agent config carries scan_policy: managed, policy name, enabled per type', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const a = await makeAgent();
  const pol = await call('admin', 'POST', '/api/edr/scan-policies', {
    name: `${name}-novuln`,
    scans: scans({ vuln: { ...BUILTIN_DEFAULT_SCANS.vuln, enabled: false } }),
  });
  policyIds.push(pol.body.policy.id);
  let cfg = await agentCall(a, 'GET', `/api/edr/agents/${a.id}/config`);
  assert.equal(cfg.status, 200);
  assert.deepEqual(cfg.body.scan_policy, {
    managed: true,
    policy: 'Default',
    scans: { vuln: { enabled: true }, yara: { enabled: true }, packages: { enabled: true }, inventory: { enabled: true } },
  });
  // The intervals older agents use are still sent.
  assert.equal(typeof cfg.body.inventory_interval_seconds, 'number');
  assert.equal(typeof cfg.body.vuln_scan_interval_seconds, 'number');
  const v1 = cfg.body.config_version;

  await call('admin', 'PUT', `/api/edr/agents/${a.id}/scan-policy`, { policy_id: pol.body.policy.id });
  const hb = await heartbeat(a, POLICY_CAPS);
  assert.ok(hb.body.config_version > v1, 'the heartbeat tells the agent to re-pull');
  cfg = await agentCall(a, 'GET', `/api/edr/agents/${a.id}/config`);
  assert.equal(cfg.body.scan_policy.policy, `${name}-novuln`);
  assert.equal(cfg.body.scan_policy.scans.vuln.enabled, false);
  assert.equal(cfg.body.config_version, hb.body.config_version);
});

test('heartbeat issues due policy scans to capable agents, once; reports finish them', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const a = await makeAgent();
  // A policy with packages off: three baseline runs on the first heartbeat.
  const pol = await call('admin', 'POST', '/api/edr/scan-policies', {
    name: `${name}-three`,
    scans: scans({ packages: { ...BUILTIN_DEFAULT_SCANS.packages, enabled: false } }),
  });
  policyIds.push(pol.body.policy.id);
  await call('admin', 'PUT', `/api/edr/agents/${a.id}/scan-policy`, { policy_id: pol.body.policy.id });

  const first = await heartbeat(a, POLICY_CAPS);
  assert.equal(first.status, 200);
  const reqs = first.body.scan_requests;
  assert.deepEqual(reqs.map((r: Json) => [r.scan_type, r.trigger]).sort(), [
    ['inventory', 'policy'], ['vuln', 'policy'], ['yara', 'policy'],
  ]);
  // Still pending: served again, but not issued twice.
  const second = await heartbeat(a, POLICY_CAPS);
  assert.deepEqual(second.body.scan_requests.map((r: Json) => r.scan_id).sort(), reqs.map((r: Json) => r.scan_id).sort());
  const count = await pool.query(`SELECT COUNT(*)::int AS n FROM edr_agent_scans WHERE agent_id = $1 AND trigger = 'policy'`, [a.id]);
  assert.equal(count.rows[0].n, 3);

  // The agent runs one and reports it as it reports a console request.
  const inv = reqs.find((r: Json) => r.scan_type === 'inventory');
  const started = new Date().toISOString();
  const run = await agentCall(a, 'POST', '/api/edr/scans', { agent_id: a.id, scan_id: inv.scan_id, scan_type: 'inventory', trigger: 'policy', status: 'running', started_at: started });
  assert.equal(run.body.accepted, true);
  const done = await agentCall(a, 'POST', '/api/edr/scans', {
    agent_id: a.id, scan_id: inv.scan_id, scan_type: 'inventory', trigger: 'policy', status: 'succeeded',
    started_at: started, completed_at: new Date().toISOString(), summary: { software: 3 },
  });
  assert.equal(done.body.status, 'succeeded');
  // A report without scan_id can't claim to be a policy run.
  assert.equal((await agentCall(a, 'POST', '/api/edr/scans', { agent_id: a.id, scan_type: 'vuln', trigger: 'policy', status: 'running' })).status, 400);

  const history = await call('analyst', 'GET', `/api/edr/agents/${a.id}/scans?type=inventory`);
  assert.equal(history.body.scans[0].trigger, 'policy');
  assert.equal(history.body.scans[0].policy_name, `${name}-three`);
  assert.equal(history.body.scans[0].policy_source, 'policy');
  assert.equal(history.body.scans[0].status, 'succeeded');

  // Inventory is not due again for an hour: the next heartbeat issues nothing new.
  const third = await heartbeat(a, POLICY_CAPS);
  assert.ok(!third.body.scan_requests.some((r: Json) => r.scan_type === 'inventory'));
  const view = await call('analyst', 'GET', `/api/edr/agents/${a.id}/scan-policy`);
  assert.equal(view.body.managed, true);
  const invView = view.body.scans.find((s: Json) => s.scan_type === 'inventory');
  assert.equal(invView.last_run.status, 'succeeded');
  const nextMs = new Date(invView.next_runs[0]).getTime();
  assert.ok(Math.abs(nextMs - (Date.now() + 3600_000)) < 120_000, `next inventory in about an hour: ${invView.next_runs[0]}`);
  assert.equal(view.body.scans.find((s: Json) => s.scan_type === 'packages').next_runs.length, 0);
});

test('an agent without policy_scans keeps its own intervals: no policy scans issued', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const a = await makeAgent();
  const hb = await heartbeat(a, ['adhoc_scans']);
  assert.equal(hb.status, 200);
  assert.deepEqual(hb.body.scan_requests, []);
  const none = await heartbeat(a, []);
  assert.deepEqual(none.body.scan_requests, []);
  const rows = await pool.query(`SELECT COUNT(*)::int AS n FROM edr_agent_scans WHERE agent_id = $1`, [a.id]);
  assert.equal(rows.rows[0].n, 0);
  const state = await pool.query(`SELECT COUNT(*)::int AS n FROM edr_agent_policy_runs WHERE agent_id = $1`, [a.id]);
  assert.equal(state.rows[0].n, 0);
  const view = await call('analyst', 'GET', `/api/edr/agents/${a.id}/scan-policy`);
  assert.equal(view.body.managed, false);
  assert.equal(view.body.local_intervals.inventory_seconds, 3600);
  // Console requests still work for it.
  const req = await call('analyst', 'POST', `/api/edr/agents/${a.id}/scans`, { types: ['vuln'] });
  assert.equal(req.status, 200);
  const served = await heartbeat(a, ['adhoc_scans']);
  assert.deepEqual(served.body.scan_requests.map((r: Json) => [r.scan_type, r.trigger]), [['vuln', 'console']]);
});

test('due computation over time: catch-up once, windows, disabled types', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const a = await makeAgent();
  await pool.query(`UPDATE edr_agents SET capabilities = $2 WHERE agent_id = $1`, [a.id, POLICY_CAPS]);
  const off = (s: keyof PolicyScans) => ({ ...BUILTIN_DEFAULT_SCANS[s], enabled: false });
  const pol = await call('admin', 'POST', '/api/edr/scan-policies', {
    name: `${name}-clock`,
    scans: scans({
      vuln: dailyAt('02:00'),
      yara: { enabled: true, schedule: null, interval_minutes: 60, window: { start: '22:00', end: '06:00', timezone: 'UTC' } },
      packages: off('packages'),
      inventory: off('inventory'),
    }),
  });
  policyIds.push(pol.body.policy.id);
  await call('admin', 'PUT', `/api/edr/agents/${a.id}/scan-policy`, { policy_id: pol.body.policy.id });

  const policyRows = async () =>
    (await pool.query(`SELECT scan_type, status, requested_at FROM edr_agent_scans WHERE agent_id = $1 AND trigger = 'policy' ORDER BY requested_at, scan_type`, [a.id])).rows;
  const finishAll = () => pool.query(`UPDATE edr_agent_scans SET status = 'succeeded', completed_at = requested_at WHERE agent_id = $1 AND status IN ('pending', 'running')`, [a.id]);

  // Times on days after today (UTC), so the real-clock expiry of pending rows never touches them.
  const day0 = Date.UTC(new Date().getUTCFullYear(), new Date().getUTCMonth(), new Date().getUTCDate() + 1);
  const at = (day: number, hhmm: string) =>
    new Date(day0 + day * 86_400_000 + (Number(hhmm.slice(0, 2)) * 60 + Number(hhmm.slice(3))) * 60_000);

  // Noon, first heartbeat: the vuln baseline runs; yara is due but waits for 22:00.
  assert.equal(await issueDuePolicyScans(a.id, at(0, '12:00')), 1);
  assert.deepEqual((await policyRows()).map((r) => r.scan_type), ['vuln']);
  const waiting = await pool.query(`SELECT next_due_at FROM edr_agent_policy_runs WHERE agent_id = $1 AND scan_type = 'yara'`, [a.id]);
  assert.equal(waiting.rows[0].next_due_at.toISOString(), at(0, '12:00').toISOString());
  await finishAll();

  // 22:00: yara runs; 23:00 again; vuln not before 02:00.
  assert.equal(await issueDuePolicyScans(a.id, at(0, '22:00')), 1);
  await finishAll();
  assert.equal(await issueDuePolicyScans(a.id, at(0, '22:30')), 0);
  assert.equal(await issueDuePolicyScans(a.id, at(0, '23:00')), 1);
  // Not finished: the 00:00 yara run is skipped while it's outstanding.
  assert.equal(await issueDuePolicyScans(a.id, at(1, '00:00')), 0);
  await finishAll();

  // Offline from 00:30 until five days later at 12:00: one vuln run (catch-up), yara waits for its window.
  assert.equal(await issueDuePolicyScans(a.id, at(6, '12:00')), 1);
  const rows = await policyRows();
  assert.equal(rows.at(-1)!.scan_type, 'vuln');
  assert.equal(rows.at(-1)!.requested_at.toISOString(), at(6, '12:00').toISOString());
  assert.equal(rows.filter((r) => r.scan_type === 'vuln').length, 2);
  await finishAll();
  assert.equal(await issueDuePolicyScans(a.id, at(6, '13:00')), 0);
  assert.equal(await issueDuePolicyScans(a.id, at(7, '02:00')), 2, 'vuln at 02:00 and yara inside the window');
  // Packages and inventory are off: never issued.
  assert.equal((await policyRows()).filter((r) => r.scan_type === 'packages' || r.scan_type === 'inventory').length, 0);
});
