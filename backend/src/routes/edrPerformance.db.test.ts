/**
 * Endpoint performance end to end: the real app on an ephemeral port, a real
 * Postgres, one user per role with a session, and endpoint agents with known
 * keys posting to POST /api/edr/metrics as the Go agent does.
 *
 * - ingest: samples stored once (a re-sent batch stores nothing), bad samples
 *   counted as rejected, the newest numbers reach the Endpoints list;
 * - hourly rollups: recomputed from the raw rows of each hour a batch touched
 *   (a late sample for an earlier hour updates that hour), idempotent;
 * - reads: raw ranges bucketed, long ranges from rollups, process snapshots;
 *   who may read (analyst and up) and who may change thresholds (operators and
 *   admins, through the scan policy);
 * - thresholds: one alert per endpoint, metric and mount while it is open,
 *   recovery noted on the alert and the slot freed, a re-breach is a new
 *   alert; sustained CPU needs the whole window; turning a threshold off
 *   releases its open alert;
 * - retention: raw and process rows past 7 days, rollups past 90 days.
 *
 * Skips itself when Postgres isn't reachable. Every row created here is removed.
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
import { ingestMetrics, evaluatePerformance, prunePerformance, rollupHours } from '../services/edr/edrPerformance';
import { BUILTIN_DEFAULT_PERFORMANCE, type PolicyPerformance } from '../services/edr/perfConfig';
import { BUILTIN_DEFAULT_SCANS } from '../services/edr/scanPolicies';

const ROLES = ['admin', 'operator', 'analyst', 'viewer'] as const;
type Role = (typeof ROLES)[number];
const SKIP = 'Postgres with migration 055 (edr_perf_samples) is not reachable';
const tag = crypto.randomBytes(5).toString('hex');
const name = `perf-${tag}`;

let dbReady = false;
let server: Server | undefined;
let base = '';
const tokens = {} as Record<Role, string>;
const userIds: number[] = [];
const policyIds: number[] = [];

interface TestAgent {
  id: string;
  key: string;
}
const agents: TestAgent[] = [];

async function makeAgent(capabilities: string[] | null = ['perf_metrics']): Promise<TestAgent> {
  const a = { id: crypto.randomUUID(), key: crypto.randomBytes(32).toString('hex') };
  await EdrAgentModel.create({ agent_id: a.id, api_key_hash: sha256hex(a.key), asset_id: null, hostname: `${name}-host` });
  if (capabilities) await pool.query('UPDATE edr_agents SET capabilities = $2 WHERE agent_id = $1', [a.id, capabilities]);
  agents.push(a);
  return a;
}

before(async () => {
  try {
    await pool.query('SELECT 1 FROM edr_perf_samples LIMIT 1');
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
  server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  if (dbReady) {
    const ids = agents.map((a) => a.id);
    await pool.query(`DELETE FROM alerts WHERE source = 'edr-perf' AND matched_data->>'agent_id' = ANY($1)`, [ids]);
    await pool.query('DELETE FROM edr_agents WHERE agent_id = ANY($1::uuid[])', [ids]);
    await pool.query('DELETE FROM edr_scan_policies WHERE id = ANY($1) OR name LIKE $2', [policyIds, `${name}%`]);
    await new Promise((resolve) => setTimeout(resolve, 500)); // fire-and-forget audit/error rows land
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

/** The current minute (samples must be recent to be stored and evaluated). */
const NOW = new Date(Math.floor(Date.now() / 60_000) * 60_000);
const at = (minutesAgo: number) => new Date(NOW.getTime() - minutesAgo * 60_000).toISOString();

function sample(minutesAgo: number, over: Record<string, unknown> = {}) {
  return {
    ts: at(minutesAgo),
    cpu_pct: 20,
    cpu_count: 4,
    mem_total: 8_000_000_000,
    mem_used: 2_000_000_000,
    swap_total: 0,
    swap_used: 0,
    load1: 0.5,
    load5: 0.4,
    load15: 0.3,
    uptime_seconds: 86_400,
    disks: [{ mount: '/', fs: 'ext4', total: 100_000, used: 40_000, free: 60_000 }],
    net: [{ iface: 'eth0', rx_bps: 1000, tx_bps: 500 }],
    ...over,
  };
}
const disk = (pct: number, mount = '/') => ({ mount, fs: 'ext4', total: 100_000, used: pct * 1000, free: (100 - pct) * 1000 });

const openStates = async (a: TestAgent) =>
  (await pool.query('SELECT metric, target, alert_id FROM edr_perf_alert_state WHERE agent_id = $1 ORDER BY metric, target', [a.id])).rows;
const perfAlerts = async (a: TestAgent) =>
  (
    await pool.query(
      `SELECT id, severity, title, description, matched_data, asset_id FROM alerts
        WHERE source = 'edr-perf' AND matched_data->>'agent_id' = $1 ORDER BY id`,
      [a.id]
    )
  ).rows;

async function policyWith(performance: PolicyPerformance, agent: TestAgent): Promise<number> {
  const r = await call('operator', 'POST', '/api/edr/scan-policies', {
    name: `${name}-${crypto.randomBytes(3).toString('hex')}`,
    scans: BUILTIN_DEFAULT_SCANS,
    performance,
  });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  policyIds.push(r.body.policy.id);
  const assign = await call('operator', 'POST', '/api/edr/agents/scan-policy', { agent_ids: [agent.id], policy_id: r.body.policy.id });
  assert.equal(assign.status, 200);
  return r.body.policy.id;
}

function perf(thresholds: Partial<PolicyPerformance['thresholds']>, over: Partial<PolicyPerformance> = {}): PolicyPerformance {
  return { ...BUILTIN_DEFAULT_PERFORMANCE, ...over, thresholds: { ...BUILTIN_DEFAULT_PERFORMANCE.thresholds, ...thresholds } };
}

test('ingest over HTTP: stored once, rejects counted, newest numbers reach the list', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const a = await makeAgent();
  const batch = {
    agent_id: a.id,
    samples: [sample(2), sample(1), sample(0, { cpu_pct: 33.3 }), { ts: 'nope' }, sample(0, { ts: at(-30) })],
    processes: [{ ts: at(0), by_cpu: [{ pid: 42, name: 'nginx', user: 'www', cpu_pct: 12, mem_rss: 1000, mem_pct: 0.1 }], by_mem: [] }],
  };
  const first = await agentCall(a, 'POST', '/api/edr/metrics', batch);
  assert.equal(first.status, 200, JSON.stringify(first.body));
  assert.equal(first.body.accepted, 3);
  assert.equal(first.body.rejected, 2, 'a bad time and one 30 minutes in the future');
  assert.equal(first.body.processes, 1);

  // The agent re-sends after a timeout it misread: nothing is stored twice.
  const again = await agentCall(a, 'POST', '/api/edr/metrics', batch);
  assert.equal(again.body.accepted, 0);
  assert.equal(again.body.duplicate, 3);
  assert.equal(again.body.processes, 0);
  const count = await pool.query('SELECT COUNT(*)::int AS n FROM edr_perf_samples WHERE agent_id = $1', [a.id]);
  assert.equal(count.rows[0].n, 3);

  // Another agent's id in the body, a missing key, a malformed body.
  const other = await makeAgent();
  assert.equal((await agentCall(a, 'POST', '/api/edr/metrics', { ...batch, agent_id: other.id })).status, 403);
  const noKey = await fetch(`${base}/api/edr/metrics`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
  assert.equal(noKey.status, 401);
  assert.equal((await agentCall(a, 'POST', '/api/edr/metrics', { samples: 'x' })).status, 400);
  assert.equal(
    (await agentCall(a, 'POST', '/api/edr/metrics', { samples: Array.from({ length: 1441 }, () => sample(0)) })).status,
    400
  );

  const list = await call('analyst', 'GET', '/api/edr/agents');
  const row = list.body.agents.find((x: Json) => x.agent_id === a.id);
  assert.equal(Number(row.perf_cpu_pct).toFixed(1), '33.3');
  assert.equal(Number(row.perf_mem_pct), 25);
  assert.equal(Number(row.perf_disk_max_pct), 40);
  assert.equal(row.perf_disk_max_mount, '/');
  assert.equal(row.perf_alerts_open, 0);

  // An older batch arriving late does not move the list's numbers back.
  await agentCall(a, 'POST', '/api/edr/metrics', { samples: [sample(5, { cpu_pct: 99 })] });
  const list2 = await call('analyst', 'GET', '/api/edr/agents');
  assert.equal(Number(list2.body.agents.find((x: Json) => x.agent_id === a.id).perf_cpu_pct).toFixed(1), '33.3');
});

test('hourly rollups: from the raw rows of each touched hour, late samples included, idempotent', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const a = await makeAgent();
  // Three samples in one past hour and one in the hour after.
  const hour = new Date(Math.floor((NOW.getTime() - 3 * 3_600_000) / 3_600_000) * 3_600_000);
  const ts = (min: number) => new Date(hour.getTime() + min * 60_000).toISOString();
  const now = NOW;
  await ingestMetrics(
    a.id,
    {
      samples: [
        { ...sample(0), ts: ts(0), cpu_pct: 10, disks: [disk(40)], net: [{ iface: 'eth0', rx_bps: 100, tx_bps: 10 }] },
        { ...sample(0), ts: ts(1), cpu_pct: 20, disks: [disk(50)], net: [{ iface: 'eth0', rx_bps: 300, tx_bps: 30 }] },
        { ...sample(0), ts: ts(60), cpu_pct: 70 },
      ],
    },
    now
  );
  const read = async () =>
    (
      await pool.query('SELECT hour, samples, cpu_avg, cpu_max, disks, net FROM edr_perf_hourly WHERE agent_id = $1 ORDER BY hour', [a.id])
    ).rows;
  let rows = await read();
  assert.equal(rows.length, 2);
  assert.equal(rows[0].samples, 2);
  assert.equal(Number(rows[0].cpu_avg), 15);
  assert.equal(Number(rows[0].cpu_max), 20);
  assert.deepEqual(rows[0].disks, [{ mount: '/', pct_avg: 45, pct_max: 50, used: 50000, total: 100000 }]);
  assert.deepEqual(rows[0].net, [{ iface: 'eth0', rx_avg: 200, tx_avg: 20, rx_max: 300, tx_max: 30 }]);

  // A late spooled sample for the first hour updates it.
  await ingestMetrics(a.id, { samples: [{ ...sample(0), ts: ts(30), cpu_pct: 90 }] }, now);
  rows = await read();
  assert.equal(rows[0].samples, 3);
  assert.equal(Number(rows[0].cpu_avg).toFixed(2), '40.00');
  assert.equal(Number(rows[0].cpu_max), 90);
  // Recomputing is idempotent.
  await rollupHours(a.id, [hour.toISOString()]);
  assert.equal((await read())[0].samples, 3);
});

test('reads: charts per range, processes, role gates', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const a = await makeAgent();
  const samples = Array.from({ length: 30 }, (_, i) =>
    sample(29 - i, { cpu_pct: i, disks: [disk(40), disk(70, '/data')], net: [{ iface: 'eth0', rx_bps: i * 10, tx_bps: 1 }] })
  );
  await agentCall(a, 'POST', '/api/edr/metrics', {
    samples,
    processes: [
      { ts: at(10), by_cpu: [{ pid: 1, name: 'old', cpu_pct: 1, mem_rss: 1, mem_pct: 0 }], by_mem: [] },
      { ts: at(0), by_cpu: [{ pid: 2, name: 'new', cpu_pct: 2, mem_rss: 2, mem_pct: 0 }], by_mem: [{ pid: 2, name: 'new', cpu_pct: 2, mem_rss: 2, mem_pct: 0 }] },
    ],
  });

  const r1 = await call('analyst', 'GET', `/api/edr/agents/${a.id}/performance?range=1h`);
  assert.equal(r1.status, 200, JSON.stringify(r1.body));
  assert.equal(r1.body.source, 'raw');
  assert.equal(r1.body.bucket_seconds, 60);
  assert.equal(r1.body.points.length, 30);
  assert.equal(r1.body.points[29].cpu, 29);
  assert.equal(r1.body.points[0].mem_pct, 25);
  assert.equal(r1.body.supported, true);
  assert.deepEqual(r1.body.disks.map((d: Json) => d.mount), ['/', '/data']);
  assert.equal(r1.body.disks[1].points[0].pct, 70);
  assert.equal(r1.body.net[0].iface, 'eth0');
  assert.equal(r1.body.latest.cpu_pct, 29);
  assert.equal(r1.body.policy, 'Default');
  assert.deepEqual(Object.keys(r1.body.performance.thresholds), ['cpu', 'memory', 'disk']);

  const r24 = await call('operator', 'GET', `/api/edr/agents/${a.id}/performance?range=24h`);
  assert.equal(r24.body.bucket_seconds, 300);
  assert.ok(r24.body.points.length >= 6 && r24.body.points.length <= 7, `5-minute buckets: ${r24.body.points.length}`);
  const r7 = await call('admin', 'GET', `/api/edr/agents/${a.id}/performance?range=7d`);
  assert.equal(r7.body.source, 'hourly');
  const total = r7.body.points.reduce((n: number, p: Json) => n + p.samples, 0);
  assert.equal(total, 30, 'every sample is in a rollup');
  const avg = r7.body.points.reduce((n: number, p: Json) => n + p.cpu * p.samples, 0) / total;
  assert.equal(avg.toFixed(2), '14.50', 'weighted by sample count');

  assert.equal((await call('viewer', 'GET', `/api/edr/agents/${a.id}/performance`)).status, 403);
  assert.equal((await call('analyst', 'GET', `/api/edr/agents/${a.id}/performance?range=2y`)).status, 400);
  assert.equal((await call('analyst', 'GET', `/api/edr/agents/${crypto.randomUUID()}/performance`)).status, 404);
  assert.equal((await call('analyst', 'GET', '/api/edr/agents/not-a-uuid/performance')).status, 404);

  const p = await call('analyst', 'GET', `/api/edr/agents/${a.id}/processes?range=1h`);
  assert.equal(p.status, 200);
  assert.equal(p.body.times.length, 2);
  assert.equal(p.body.snapshot.by_cpu[0].name, 'new');
  const older = await call('analyst', 'GET', `/api/edr/agents/${a.id}/processes?range=1h&at=${encodeURIComponent(at(5))}`);
  assert.equal(older.body.snapshot.by_cpu[0].name, 'old');
  assert.equal((await call('analyst', 'GET', `/api/edr/agents/${a.id}/processes?at=yesterday`)).status, 400);
  assert.equal((await call('viewer', 'GET', `/api/edr/agents/${a.id}/processes`)).status, 403);

  // An agent without the capability is flagged for the UI.
  const old = await makeAgent(['adhoc_scans', 'policy_scans']);
  const r = await call('analyst', 'GET', `/api/edr/agents/${old.id}/performance`);
  assert.equal(r.body.supported, false);
  assert.equal(r.body.min_agent_version, '0.0.23');
  assert.deepEqual(r.body.points, []);
});

test('performance settings live in the scan policy: operators and admins edit, agent config follows', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const a = await makeAgent();
  const body = { name: `${name}-quiet`, scans: BUILTIN_DEFAULT_SCANS, performance: perf({}, { processes: false }) };
  assert.equal((await call('analyst', 'POST', '/api/edr/scan-policies', body)).status, 403);
  const bad = await call('operator', 'POST', '/api/edr/scan-policies', {
    ...body,
    performance: perf({ disk: { enabled: true, percent: 150, minutes: 0, severity: 'high' } }),
  });
  assert.equal(bad.status, 400);
  assert.match(bad.body.error ?? bad.body.message, /percent/);
  const created = await call('operator', 'POST', '/api/edr/scan-policies', body);
  assert.equal(created.status, 201);
  policyIds.push(created.body.policy.id);
  assert.equal(created.body.policy.performance.processes, false);

  // Without one, a new policy gets the defaults.
  const plain = await call('admin', 'POST', '/api/edr/scan-policies', { name: `${name}-plain`, scans: BUILTIN_DEFAULT_SCANS });
  policyIds.push(plain.body.policy.id);
  assert.deepEqual(plain.body.policy.performance, BUILTIN_DEFAULT_PERFORMANCE);

  const cfg = async () => (await agentCall(a, 'GET', `/api/edr/agents/${a.id}/config`)).body;
  assert.deepEqual((await cfg()).performance, {
    enabled: true, processes: true, sample_interval_seconds: 60, send_interval_seconds: 60, process_interval_seconds: 300, top_processes: 10,
  });
  const before = (await pool.query('SELECT config_version FROM edr_agents WHERE agent_id = $1', [a.id])).rows[0].config_version;
  await call('operator', 'POST', '/api/edr/agents/scan-policy', { agent_ids: [a.id], policy_id: created.body.policy.id });
  assert.equal((await cfg()).performance.processes, false);
  // Turning metrics off raises config_version so the agent re-pulls.
  const off = await call('admin', 'PUT', `/api/edr/scan-policies/${created.body.policy.id}`, { performance: perf({}, { metrics: false }) });
  assert.equal(off.status, 200);
  const afterV = (await pool.query('SELECT config_version FROM edr_agents WHERE agent_id = $1', [a.id])).rows[0].config_version;
  assert.ok(afterV > before);
  assert.equal((await cfg()).performance.enabled, false);
  assert.equal((await call('analyst', 'PUT', `/api/edr/scan-policies/${created.body.policy.id}`, { performance: perf({}) })).status, 403);
  // Editing the scans alone keeps the performance settings.
  const kept = await call('operator', 'PUT', `/api/edr/scan-policies/${created.body.policy.id}`, { description: 'x' });
  assert.equal(kept.body.policy.performance.metrics, false);
});

test('disk threshold: one alert while open, recovery noted, re-breach is a new alert', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const a = await makeAgent();
  await policyWith(perf({ cpu: { ...BUILTIN_DEFAULT_PERFORMANCE.thresholds.cpu, enabled: false } }), a);
  const send = (minutesAgo: number, disks: unknown[]) => ingestMetrics(a.id, { samples: [sample(minutesAgo, { disks })] }, NOW);

  let r = await send(10, [disk(92), disk(50, '/data')]);
  assert.equal(r.alerts_opened, 1);
  // Still full, a minute later and again: no second alert, however many samples.
  for (const m of [9, 8, 7]) assert.equal((await send(m, [disk(95), disk(91, '/data')])).alerts_opened, m === 9 ? 1 : 0);
  let alerts = await perfAlerts(a);
  assert.equal(alerts.length, 2, 'one for /, one for /data');
  assert.deepEqual((await openStates(a)).map((s: Json) => s.target), ['/', '/data']);
  const root = alerts.find((x: Json) => x.matched_data.mount === '/');
  assert.equal(root.severity, 'high');
  assert.match(root.title, /^Disk \/ 92% full on perf-/);
  assert.equal(root.matched_data.performance_state, 'open');
  assert.equal(root.matched_data.threshold_percent, 90);

  // Inside the hysteresis margin (88%): still open.
  r = await send(6, [disk(88), disk(91, '/data')]);
  assert.equal(r.alerts_recovered, 0);
  // Below 87%: recovered, noted on the alert, slot freed.
  r = await send(5, [disk(80), disk(91, '/data')]);
  assert.equal(r.alerts_recovered, 1);
  alerts = await perfAlerts(a);
  const rec = alerts.find((x: Json) => x.id === root.id);
  assert.equal(rec.matched_data.performance_state, 'recovered');
  assert.equal(rec.matched_data.recovered_value, 80);
  assert.match(rec.description, /Recovered at .*: 80%/);
  assert.deepEqual((await openStates(a)).map((s: Json) => s.target), ['/data']);

  // Full again: a new episode, a new alert.
  r = await send(4, [disk(93), disk(91, '/data')]);
  assert.equal(r.alerts_opened, 1);
  assert.equal((await perfAlerts(a)).length, 3);

  // The Performance tab lists what is open, the list counts it.
  const view = await call('analyst', 'GET', `/api/edr/agents/${a.id}/performance?range=1h`);
  assert.equal(view.body.open_alerts.length, 2);
  const list = await call('analyst', 'GET', '/api/edr/agents');
  assert.equal(list.body.agents.find((x: Json) => x.agent_id === a.id).perf_alerts_open, 2);

  // The same breaching sample evaluated again with its slot lost does not raise its alert
  // twice: / (opened on the newest sample) is re-linked to its alert. (/data opened on an
  // earlier sample, so losing its slot means a new one: the slot is the source of truth.)
  await pool.query('DELETE FROM edr_perf_alert_state WHERE agent_id = $1', [a.id]);
  assert.equal((await evaluatePerformance(a.id, NOW)).opened, 1);
  assert.equal((await perfAlerts(a)).length, 4);
  assert.ok((await openStates(a)).every((s: Json) => s.alert_id !== null));

  // Concurrent evaluations of a new breach raise it once.
  await pool.query('DELETE FROM edr_perf_alert_state WHERE agent_id = $1', [a.id]);
  await pool.query(
    `INSERT INTO edr_perf_samples (agent_id, ts, cpu_pct, mem_total, mem_used, disks)
     VALUES ($1, $2, 1, 10, 1, $3::jsonb)`,
    [a.id, at(3), JSON.stringify([{ mount: '/', pct: 97 }, { mount: '/data', pct: 97 }])]
  );
  const results = await Promise.all([evaluatePerformance(a.id, NOW), evaluatePerformance(a.id, NOW), evaluatePerformance(a.id, NOW)]);
  assert.equal(results.reduce((n, x) => n + x.opened, 0), 2, 'one per mount, whichever call claimed it');
  assert.equal((await openStates(a)).length, 2);
});

test('sustained CPU needs the whole window; memory; turning a threshold off releases its alert', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const a = await makeAgent();
  const policyId = await policyWith(
    perf({
      cpu: { enabled: true, percent: 95, minutes: 5, severity: 'medium' },
      memory: { enabled: true, percent: 80, minutes: 0, severity: 'low' },
      disk: { ...BUILTIN_DEFAULT_PERFORMANCE.thresholds.disk, enabled: false },
    }),
    a
  );
  const send = (minutesAgo: number, over: Record<string, unknown> = {}) =>
    ingestMetrics(a.id, { samples: [sample(minutesAgo, { disks: [disk(99)], ...over })] }, NOW);

  // Four high minutes: not yet (5 sustained). The fifth: alert.
  for (const m of [9, 8, 7, 6]) assert.equal((await send(m, { cpu_pct: 99 })).alerts_opened, 0, `minute ${m}`);
  assert.equal((await send(5, { cpu_pct: 99 })).alerts_opened, 1);
  // A dip, then high again: still the same open alert.
  await send(4, { cpu_pct: 50 });
  await send(3, { cpu_pct: 99 });
  let alerts = await perfAlerts(a);
  assert.equal(alerts.length, 1);
  assert.match(alerts[0].title, /^CPU above 95% for 5 minutes on /);
  assert.equal(alerts[0].severity, 'medium');
  assert.equal(alerts.some((x: Json) => x.matched_data.metric === 'disk'), false, 'disk threshold off');

  // Memory over 80% at once (0 minutes).
  assert.equal((await send(2, { cpu_pct: 99, mem_used: 7_000_000_000 })).alerts_opened, 1);
  assert.deepEqual((await openStates(a)).map((s: Json) => s.metric), ['cpu', 'memory']);

  // Turn CPU off: its open alert is released and noted; memory stays.
  await call('operator', 'PUT', `/api/edr/scan-policies/${policyId}`, {
    performance: perf({
      cpu: { enabled: false, percent: 95, minutes: 5, severity: 'medium' },
      memory: { enabled: true, percent: 80, minutes: 0, severity: 'low' },
      disk: { ...BUILTIN_DEFAULT_PERFORMANCE.thresholds.disk, enabled: false },
    }),
  });
  const r = await send(1, { cpu_pct: 99, mem_used: 7_000_000_000 });
  assert.equal(r.alerts_recovered, 1);
  assert.deepEqual((await openStates(a)).map((s: Json) => s.metric), ['memory']);
  alerts = await perfAlerts(a);
  assert.equal(alerts.find((x: Json) => x.matched_data.metric === 'cpu').matched_data.performance_state, 'threshold_off');

  // Old data replayed much later is stored but not evaluated.
  const b = await makeAgent();
  await policyWith(perf({ disk: { enabled: true, percent: 90, minutes: 0, severity: 'high' } }), b);
  const replay = await ingestMetrics(b.id, { samples: [sample(120, { disks: [disk(99)] })] }, NOW);
  assert.equal(replay.accepted, 1);
  assert.equal(replay.alerts_opened, 0);
});

test('retention: raw and process rows past 7 days, rollups past 90', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const a = await makeAgent();
  const day = 86_400_000;
  const old = (days: number) => new Date(NOW.getTime() - days * day);
  for (const d of [8, 1]) {
    await pool.query(
      `INSERT INTO edr_perf_samples (agent_id, ts, cpu_pct, mem_total, mem_used) VALUES ($1, $2, 1, 10, 1)`,
      [a.id, old(d)]
    );
    await pool.query(`INSERT INTO edr_perf_processes (agent_id, ts) VALUES ($1, $2)`, [a.id, old(d)]);
  }
  for (const d of [91, 30]) {
    await pool.query(
      `INSERT INTO edr_perf_hourly (agent_id, hour, samples, cpu_avg, cpu_max, mem_used_avg, mem_used_max, mem_total)
       VALUES ($1, $2, 60, 1, 1, 1, 1, 10)`,
      [a.id, old(d)]
    );
  }
  const pruned = await prunePerformance(NOW);
  assert.ok(pruned.samples >= 1 && pruned.hourly >= 1 && pruned.processes >= 1);
  const left = async (table: string, col: string) =>
    (await pool.query(`SELECT COUNT(*)::int AS n FROM ${table} WHERE agent_id = $1 AND ${col} < $2`, [a.id, old(7)])).rows[0].n;
  assert.equal(await left('edr_perf_samples', 'ts'), 0);
  assert.equal(await left('edr_perf_processes', 'ts'), 0);
  assert.equal(await left('edr_perf_hourly', 'hour'), 1, 'the 30-day-old rollup stays');
  const kept = await pool.query('SELECT COUNT(*)::int AS n FROM edr_perf_samples WHERE agent_id = $1', [a.id]);
  assert.equal(kept.rows[0].n, 1);
});
