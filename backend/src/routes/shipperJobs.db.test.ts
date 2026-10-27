/**
 * Shipper scan-job safety, end to end on a real Postgres and the real app:
 *
 * - expiry: a queued shipper job older than the window is never handed out by
 *   the job-pull (nmap, nuclei and discovery claims), and the sweep marks it
 *   'expired' with the reason, leaving fresh, running and backend-run rows be;
 * - the Shippers page's job list (GET /api/shippers/:id/jobs) and count badge,
 *   and its Cancel (POST /api/shippers/:id/jobs/:kind/:scanId/cancel): analyst
 *   and up for an asset scan, operator and up for the rest, never another
 *   shipper's job, and results a shipper posts for a cancelled job are ignored;
 * - the public-target guard on POST /api/assets/scan, /api/vulnerabilities/scans,
 *   /api/log-discovery/scans and /api/scheduled-scans, and the confirmation it
 *   stores and audits;
 * - a due schedule whose previous run is still queued for its shipper doesn't
 *   queue another;
 * - GET/PUT /api/settings/shipper-jobs.
 *
 * Every scan created here is dispatched to this test's own shipper, so nothing
 * runs nmap or nuclei. Skips itself when Postgres isn't reachable. Every row
 * created here is removed again, with what an interrupted earlier run left.
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
import { LogShipperModel } from '../models/LogShipper';
import { ScheduledScanModel } from '../models/ScheduledScan';
import {
  SHIPPER_JOB_EXPIRY_SETTING_KEY,
  expireStaleShipperJobs,
  getShipperJobExpiryHours,
} from '../services/scanner/shipperJobs';
import { NmapScanner } from '../services/scanner/nmapScanner';
import { NucleiScanner } from '../services/scanner/nucleiScanner';
import { claimDiscoveryJobsForShipper } from '../services/logDiscovery/discoveryScanService';
import { runDueScheduledScans } from '../jobs/scheduledScans';

const ROLES = ['admin', 'operator', 'analyst', 'viewer'] as const;
type Role = (typeof ROLES)[number];
const SKIP = 'Postgres with the scan schema is not reachable';
const TEST_NAME = '^shipjobs-[0-9a-f]{12}';

let dbReady = false;
let server: Server | undefined;
let base = '';
const tag = crypto.randomBytes(6).toString('hex');
const name = `shipjobs-${tag}`;
const tokens = {} as Record<Role, string>;
const userIdOf = {} as Record<Role, number>;
const userIds: number[] = [];
let shipperId = 0;
let shipperKey = '';
let otherShipperId = 0;
let savedExpiry: string | null = null;
let denials = 0;

before(async () => {
  try {
    await pool.query('SELECT scan_options, assigned_shipper_id FROM discovery_scans LIMIT 1');
    await pool.query('SELECT assigned_shipper_id, claimed_at FROM vulnerability_scans LIMIT 1');
    await pool.query('SELECT token FROM sessions LIMIT 1');
    dbReady = true;
  } catch {
    return;
  }
  const saved = await pool.query('SELECT value FROM system_settings WHERE key = $1', [SHIPPER_JOB_EXPIRY_SETTING_KEY]);
  savedExpiry = saved.rows[0]?.value ?? null;
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
  shipperKey = crypto.randomBytes(32).toString('hex');
  shipperId = (await LogShipperModel.create({ name, description: 'shipper job test', api_key: shipperKey })).id;
  otherShipperId = (
    await LogShipperModel.create({ name: `${name}-other`, description: 'shipper job test', api_key: crypto.randomBytes(32).toString('hex') })
  ).id;
  server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  if (dbReady) {
    const stale = `created_at < NOW() - INTERVAL '10 minutes'`;
    if (savedExpiry === null) {
      await pool.query('DELETE FROM system_settings WHERE key = $1', [SHIPPER_JOB_EXPIRY_SETTING_KEY]);
    } else {
      await pool.query('UPDATE system_settings SET value = $2 WHERE key = $1', [SHIPPER_JOB_EXPIRY_SETTING_KEY, savedExpiry]);
    }
    const shippers = await pool.query(
      `SELECT id FROM log_shippers WHERE id = ANY($1) OR (name ~ $2 AND ${stale})`,
      [[shipperId, otherShipperId], TEST_NAME]
    );
    const shipperIdsToDrop = shippers.rows.map((r) => r.id as number);
    await pool.query('DELETE FROM vulnerability_scans WHERE assigned_shipper_id = ANY($1)', [shipperIdsToDrop]);
    await pool.query('DELETE FROM discovery_scans WHERE assigned_shipper_id = ANY($1)', [shipperIdsToDrop]);
    await pool.query(`DELETE FROM scheduled_scans WHERE name LIKE $1 OR (name ~ $2 AND ${stale})`, [`${name}%`, TEST_NAME]);
    await pool.query('DELETE FROM log_shippers WHERE id = ANY($1)', [shipperIdsToDrop]);
    for (let attempt = 0; attempt < 50; attempt++) {
      const logged = await pool.query('SELECT count(*)::int AS n FROM application_errors WHERE user_id = ANY($1)', [userIds]);
      if (logged.rows[0].n >= denials) break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    const leftover = await pool.query(
      `SELECT id FROM users WHERE username ~ $1 AND email LIKE '%@siembox.invalid' AND ${stale}`,
      [TEST_NAME]
    );
    const doomed = [...userIds, ...leftover.rows.map((row) => row.id as number)];
    await pool.query('DELETE FROM vulnerability_scans WHERE initiated_by = ANY($1)', [doomed]);
    await pool.query('DELETE FROM application_errors WHERE user_id = ANY($1)', [doomed]);
    await pool.query('DELETE FROM audit_logs WHERE user_id = ANY($1)', [doomed]);
    await pool.query('DELETE FROM users WHERE id = ANY($1)', [doomed]);
  }
  await closePools();
});

async function call(role: Role | null, method: string, path: string, body?: unknown) {
  const headers: Record<string, string> = {};
  if (role) headers.Authorization = `Bearer ${tokens[role]}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  if (res.status === 403) denials++;
  return { status: res.status, json: (await res.json().catch(() => null)) as any };
}

/** A vulnerability_scans row queued for `shipper`, created `hoursAgo` hours ago. */
async function queuedScan(
  kind: 'nmap' | 'nuclei',
  hoursAgo: number,
  opts: { shipper?: number | null; status?: string; targets?: string[]; origin?: unknown } = {}
): Promise<number> {
  const targets = opts.targets ?? ['10.20.30.0/24'];
  const scanOptions =
    kind === 'nmap'
      ? { targets, scanType: 'ping', ...(opts.origin ? { origin: opts.origin } : {}) }
      : { target: targets[0], templateSelection: { tags: ['cve'] }, ...(opts.origin ? { origin: opts.origin } : {}) };
  const r = await pool.query(
    `INSERT INTO vulnerability_scans (scan_type, target, status, initiated_by, scan_options, assigned_shipper_id, created_at)
     VALUES ($1, $2, $3, $4, $5, $6, NOW() - make_interval(hours => $7::int)) RETURNING id`,
    [
      kind === 'nmap' ? 'asset_discovery' : 'vulnerability',
      targets.join(', '),
      opts.status ?? 'queued',
      userIdOf.analyst,
      JSON.stringify(scanOptions),
      opts.shipper === undefined ? shipperId : opts.shipper,
      hoursAgo,
    ]
  );
  return r.rows[0].id;
}

async function queuedDiscovery(hoursAgo: number, shipper = shipperId): Promise<number> {
  const r = await pool.query(
    `INSERT INTO discovery_scans (mode, cidrs, status, created_by, assigned_shipper_id, created_at)
     VALUES ('full', '["10.20.31.0/24"]', 'queued', $1, $2, NOW() - make_interval(hours => $3::int)) RETURNING id`,
    [userIdOf.operator, shipper, hoursAgo]
  );
  return r.rows[0].id;
}

async function statusOf(table: 'vulnerability_scans' | 'discovery_scans', id: number) {
  return (await pool.query(`SELECT status, error_message FROM ${table} WHERE id = $1`, [id])).rows[0];
}

test('the claim queries never hand out a job older than the window', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const oldNmap = await queuedScan('nmap', 25);
  const oldNuclei = await queuedScan('nuclei', 25);
  const oldDiscovery = await queuedDiscovery(25);
  const freshNmap = await queuedScan('nmap', 1);

  // Claim directly (no sweep first): the stale rows are skipped and stay queued.
  const nmap = await NmapScanner.claimScanJobsForShipper(shipperId, 24);
  const nuclei = await NucleiScanner.claimScanJobsForShipper(shipperId, 24);
  const discovery = await claimDiscoveryJobsForShipper(shipperId, 24);
  assert.deepEqual(nmap.map((j) => j.scanId), [freshNmap]);
  assert.deepEqual(nuclei, []);
  assert.deepEqual(discovery, []);
  assert.equal((await statusOf('vulnerability_scans', oldNmap)).status, 'queued');
  assert.equal((await statusOf('vulnerability_scans', oldNuclei)).status, 'queued');
  assert.equal((await statusOf('discovery_scans', oldDiscovery)).status, 'queued');
  assert.equal((await statusOf('vulnerability_scans', freshNmap)).status, 'running');

  // A wider window would have handed them out: the cut-off is the window.
  const wide = await NucleiScanner.claimScanJobsForShipper(shipperId, 48);
  assert.deepEqual(wide.map((j) => j.scanId), [oldNuclei]);
});

test('the sweep marks stale queued shipper jobs expired, and nothing else', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const stale = await queuedScan('nmap', 30);
  const staleDiscovery = await queuedDiscovery(30);
  const fresh = await queuedScan('nmap', 2);
  const staleRunning = await queuedScan('nmap', 30, { status: 'running' });
  const staleBackend = await queuedScan('nmap', 30, { shipper: null });

  const result = await expireStaleShipperJobs({ maxAgeHours: 24 });
  assert.ok(result.scans.includes(stale));
  assert.ok(result.discoveryScans.includes(staleDiscovery));
  for (const id of [fresh, staleRunning, staleBackend]) assert.ok(!result.scans.includes(id), `scan ${id}`);

  const expired = await statusOf('vulnerability_scans', stale);
  assert.equal(expired.status, 'expired');
  assert.match(expired.error_message, /did not pick this job up within 24 h/);
  assert.equal((await statusOf('discovery_scans', staleDiscovery)).status, 'expired');
  assert.equal((await statusOf('vulnerability_scans', fresh)).status, 'queued');
  assert.equal((await statusOf('vulnerability_scans', staleRunning)).status, 'running');
  assert.equal((await statusOf('vulnerability_scans', staleBackend)).status, 'queued');

  // Idempotent: a second sweep changes nothing more.
  const again = await expireStaleShipperJobs({ maxAgeHours: 24 });
  assert.ok(!again.scans.includes(stale));
  await pool.query('DELETE FROM vulnerability_scans WHERE id = $1', [staleBackend]);
});

test('a shipper back after a week gets no week-old work from the job-pull', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  // Clear anything earlier tests left queued for this shipper.
  await pool.query(`UPDATE vulnerability_scans SET status = 'completed' WHERE assigned_shipper_id = $1 AND status = 'queued'`, [shipperId]);
  await pool.query(`UPDATE discovery_scans SET status = 'completed' WHERE assigned_shipper_id = $1 AND status = 'queued'`, [shipperId]);
  const weekOld = await queuedScan('nmap', 24 * 7, { targets: ['192.169.1.0/24'] });
  const weekOldDiscovery = await queuedDiscovery(24 * 7);
  const today = await queuedScan('nuclei', 0);

  const pull = await call(null, 'GET', `/api/shippers/scan-jobs/${shipperKey}`);
  assert.equal(pull.status, 200);
  assert.deepEqual(pull.json.jobs.map((j: any) => j.scanId), [today]);
  assert.equal((await statusOf('vulnerability_scans', weekOld)).status, 'expired', 'expired by the pull itself');
  assert.equal((await statusOf('discovery_scans', weekOldDiscovery)).status, 'expired');

  // The expired job is shown, with its reason, on the Shippers page.
  const list = await call('viewer', 'GET', `/api/shippers/${shipperId}/jobs`);
  assert.equal(list.status, 200);
  const shown = list.json.jobs.find((j: any) => j.scanId === weekOld && j.kind === 'nmap');
  assert.equal(shown.status, 'expired');
  assert.match(shown.errorMessage, /Expired without running/);
});

test('job list, count badge and cancel with per-kind role gates', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const nmapJob = await queuedScan('nmap', 1, {
    targets: ['10.20.32.0/24'],
    origin: { page: 'scheduled_scans', scheduledScanId: 1, scheduledScanName: 'Nightly' },
  });
  const nucleiJob = await queuedScan('nuclei', 1, { targets: ['https://10.20.32.5'] });
  const discoveryJob = await queuedDiscovery(1);
  const otherJob = await queuedScan('nmap', 1, { shipper: otherShipperId });

  const list = await call('viewer', 'GET', `/api/shippers/${shipperId}/jobs`);
  assert.equal(list.status, 200);
  const byId = (kind: string, id: number) => list.json.jobs.find((j: any) => j.kind === kind && j.scanId === id);
  const n = byId('nmap', nmapJob);
  assert.deepEqual(n.targets, ['10.20.32.0/24']);
  assert.equal(n.status, 'queued');
  assert.equal(n.createdByUsername, `${name}-analyst`);
  assert.deepEqual(n.origin, { page: 'scheduled_scans', scheduledScanId: 1, scheduledScanName: 'Nightly' });
  assert.ok(n.expiresAt && Date.parse(n.expiresAt) > Date.now());
  assert.ok(n.ageSeconds >= 3500);
  assert.equal(byId('nuclei', nucleiJob).origin.page, 'vulnerability_scanning');
  assert.equal(byId('discovery', discoveryJob).origin.page, 'log_discovery');
  assert.equal(byId('nmap', otherJob), undefined, "another shipper's job isn't listed");

  const shippers = await call('viewer', 'GET', '/api/shippers');
  const row = shippers.json.find((s: any) => s.id === shipperId);
  assert.ok(row.queued_jobs >= 3, `queued_jobs ${row.queued_jobs}`);
  assert.equal(typeof row.running_jobs, 'number');

  const cancel = (role: Role, kind: string, id: number, shipper = shipperId) =>
    call(role, 'POST', `/api/shippers/${shipper}/jobs/${kind}/${id}/cancel`);

  assert.equal((await cancel('viewer', 'nmap', nmapJob)).status, 403);
  assert.equal((await cancel('analyst', 'nuclei', nucleiJob)).status, 403, 'a vuln scan needs operator');
  assert.equal((await cancel('analyst', 'discovery', discoveryJob)).status, 403, 'a discovery sweep needs operator');
  assert.equal((await statusOf('vulnerability_scans', nucleiJob)).status, 'queued');
  const denied = await pool.query(
    `SELECT 1 FROM audit_logs WHERE user_id = $1 AND action = 'access.denied' AND resource_type = 'shipper_job' AND resource_id = $2`,
    [userIdOf.analyst, nucleiJob]
  );
  assert.equal(denied.rowCount, 1, 'the in-handler refusal is audited');

  assert.equal((await cancel('admin', 'nmap', otherJob)).status, 404, "never another shipper's job");
  assert.equal((await cancel('admin', 'nuclei', nmapJob)).status, 404, 'kind must match the row');
  assert.equal((await cancel('admin', 'bogus', nmapJob)).status, 400);

  const ok = await cancel('analyst', 'nmap', nmapJob);
  assert.equal(ok.status, 200);
  assert.deepEqual(ok.json, { cancelled: true, status: 'cancelled', previous_status: 'queued' });
  const cancelled = await statusOf('vulnerability_scans', nmapJob);
  assert.equal(cancelled.status, 'cancelled');
  assert.match(cancelled.error_message, new RegExp(`Cancelled by ${name}-analyst from the Shippers page`));
  assert.equal((await cancel('analyst', 'nmap', nmapJob)).json.cancelled, false, 'a second cancel is a no-op');

  assert.equal((await cancel('operator', 'nuclei', nucleiJob)).json.status, 'cancelled');
  const d = await cancel('operator', 'discovery', discoveryJob);
  assert.equal(d.json.cancelled, true);
  assert.equal((await statusOf('discovery_scans', discoveryJob)).status, 'failed');

  // A running job cancelled from here: whatever the shipper posts later is ignored.
  const running = await queuedScan('nmap', 0, { status: 'running' });
  assert.equal((await cancel('analyst', 'nmap', running)).json.previous_status, 'running');
  const late = await call(null, 'POST', '/api/shippers/scan-results', { api_key: shipperKey, scan_id: running, xml: '<nmaprun></nmaprun>' });
  assert.equal(late.status, 200);
  assert.deepEqual(late.json, { status: 'cancelled', ignored: true });
  assert.equal((await statusOf('vulnerability_scans', running)).status, 'cancelled');

  const runningDiscovery = await queuedDiscovery(0);
  await pool.query(`UPDATE discovery_scans SET status = 'running' WHERE id = $1`, [runningDiscovery]);
  await cancel('operator', 'discovery', runningDiscovery);
  const lateDiscovery = await call(null, 'POST', '/api/shippers/discovery-results', {
    api_key: shipperKey,
    scan_id: runningDiscovery,
    signals: [],
  });
  assert.deepEqual(lateDiscovery.json, { status: 'failed', ignored: true });

  assert.equal((await call('viewer', 'GET', '/api/shippers/999999999/jobs')).status, 404);
});

test('public targets are refused without confirmation, and recorded with it', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  // Asset scan, dispatched to the test shipper so nothing runs.
  const refused = await call('analyst', 'POST', '/api/assets/scan', {
    targets: ['10.0.0.1', '192.169.1.0/24'],
    scanType: 'ping',
    assignedShipperId: shipperId,
  });
  assert.equal(refused.status, 400);
  assert.equal(refused.json.code, 'PUBLIC_TARGETS_UNCONFIRMED');
  assert.deepEqual(refused.json.public_targets, [{ target: '192.169.1.0/24', suggestion: '192.168.1.0/24' }]);
  assert.match(refused.json.error, /did you mean 192\.168\.1\.0\/24/);
  const none = await pool.query(`SELECT 1 FROM vulnerability_scans WHERE assigned_shipper_id = $1 AND target LIKE '%192.169.1.0/24%' AND status = 'queued'`, [shipperId]);
  assert.equal(none.rowCount, 0, 'nothing was queued');

  const privateOnly = await call('analyst', 'POST', '/api/assets/scan', {
    targets: ['192.168.77.0/24', 'nas.lan'],
    scanType: 'ping',
    assignedShipperId: shipperId,
  });
  assert.equal(privateOnly.status, 202, 'private ranges and hostnames need no confirmation');

  const confirmed = await call('analyst', 'POST', '/api/assets/scan', {
    targets: ['192.169.1.0/24'],
    scanType: 'ping',
    assignedShipperId: shipperId,
    allow_public_targets: true,
  });
  assert.equal(confirmed.status, 202);
  const stored = (await pool.query('SELECT scan_options FROM vulnerability_scans WHERE id = $1', [confirmed.json.scanId])).rows[0].scan_options;
  assert.deepEqual(stored.origin, { page: 'assets' });
  assert.equal(stored.publicTargetsConfirmation.confirmedBy, userIdOf.analyst);
  assert.equal(stored.publicTargetsConfirmation.confirmedByUsername, `${name}-analyst`);
  assert.deepEqual(stored.publicTargetsConfirmation.publicTargets, ['192.169.1.0/24']);
  const audit = await pool.query(
    `SELECT details FROM audit_logs WHERE user_id = $1 AND action = 'scan.public_targets.confirmed' AND resource_id = $2`,
    [userIdOf.analyst, confirmed.json.scanId]
  );
  assert.equal(audit.rowCount, 1);
  assert.deepEqual(audit.rows[0].details.publicTargets, ['192.169.1.0/24']);

  // Vulnerability scan.
  const vuln = await call('operator', 'POST', '/api/vulnerabilities/scans', {
    target: 'https://8.8.8.8',
    assignedShipperId: shipperId,
  });
  assert.equal(vuln.status, 400);
  assert.deepEqual(vuln.json.public_targets, [{ target: 'https://8.8.8.8' }]);
  const vulnOk = await call('operator', 'POST', '/api/vulnerabilities/scans', {
    target: 'https://8.8.8.8',
    assignedShipperId: shipperId,
    allow_public_targets: true,
  });
  assert.equal(vulnOk.status, 202);

  // Log discovery (explicit CIDRs; the scope is not touched).
  const disc = await call('operator', 'POST', '/api/log-discovery/scans', {
    mode: 'active',
    manual_cidrs: ['172.32.0.0/24'],
    assignedShipperId: shipperId,
  });
  assert.equal(disc.status, 400);
  assert.deepEqual(disc.json.public_targets, [{ target: '172.32.0.0/24', suggestion: '172.31.0.0/24' }]);
  const discOk = await call('operator', 'POST', '/api/log-discovery/scans', {
    mode: 'active',
    manual_cidrs: ['172.32.0.0/24'],
    assignedShipperId: shipperId,
    allow_public_targets: true,
  });
  assert.equal(discOk.status, 202);
  const discRow = (await pool.query('SELECT scan_options FROM discovery_scans WHERE id = $1', [discOk.json.scan_id])).rows[0];
  assert.equal(discRow.scan_options.origin.page, 'log_discovery');
  assert.deepEqual(discRow.scan_options.publicTargetsConfirmation.publicTargets, ['172.32.0.0/24']);
});

test('scheduled scans: public targets need confirming on create and on edit; legacy ones keep running, badged', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const body = {
    name: `${name}-sched`,
    scan_type: 'asset',
    scan_options: { targets: ['192.169.1.0/24'], scanType: 'ping', assignedShipperId: shipperId },
    interval_minutes: 60,
    enabled: false,
  };
  const refused = await call('operator', 'POST', '/api/scheduled-scans', body);
  assert.equal(refused.status, 400);
  assert.equal(refused.json.code, 'PUBLIC_TARGETS_UNCONFIRMED');

  const created = await call('operator', 'POST', '/api/scheduled-scans', {
    ...body,
    scan_options: { ...body.scan_options, publicTargetsConfirmation: { confirmedBy: 1 } },
    allow_public_targets: true,
  });
  assert.equal(created.status, 201);
  assert.equal(created.json.scan_options.publicTargetsConfirmation.confirmedBy, userIdOf.operator, "the server's record, not the client's");

  // A schedule saved before the check (no confirmation stored).
  const legacy = await ScheduledScanModel.create({
    name: `${name}-legacy`,
    scan_type: 'asset',
    scan_options: { targets: ['8.8.8.0/24'], scanType: 'ping', assignedShipperId: shipperId },
    interval_minutes: 60,
    enabled: false,
  });
  const list = await call('viewer', 'GET', '/api/scheduled-scans');
  assert.deepEqual(list.json.find((s: any) => s.id === legacy.id).public_targets, ['8.8.8.0/24']);

  // Toggling enabled doesn't touch the targets: no confirmation needed.
  assert.equal((await call('operator', 'PUT', `/api/scheduled-scans/${legacy.id}`, { enabled: false })).status, 200);
  // Saving the options does.
  const edit = await call('operator', 'PUT', `/api/scheduled-scans/${legacy.id}`, { scan_options: legacy.scan_options });
  assert.equal(edit.status, 400);
  const editOk = await call('operator', 'PUT', `/api/scheduled-scans/${legacy.id}`, {
    scan_options: legacy.scan_options,
    allow_public_targets: true,
  });
  assert.equal(editOk.status, 200);
  assert.deepEqual(editOk.json.scan_options.publicTargetsConfirmation.publicTargets, ['8.8.8.0/24']);

  // The legacy schedule still fires (dispatched to the test shipper), carrying its origin.
  const scanId = (await call('operator', 'POST', `/api/scheduled-scans/${legacy.id}/run`)).json.scanId;
  const opts = (await pool.query('SELECT scan_options FROM vulnerability_scans WHERE id = $1', [scanId])).rows[0].scan_options;
  assert.deepEqual(opts.origin, { page: 'scheduled_scans', scheduledScanId: legacy.id, scheduledScanName: `${name}-legacy` });
});

test('a due schedule whose previous run is still queued for its shipper does not queue another', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const schedule = await ScheduledScanModel.create({
    name: `${name}-dedupe`,
    scan_type: 'asset',
    scan_options: { targets: ['10.20.33.0/24'], scanType: 'ping', assignedShipperId: shipperId },
    interval_minutes: 60,
    enabled: true,
  });
  const due = async () => pool.query(`UPDATE scheduled_scans SET next_run_at = NOW() - INTERVAL '1 minute' WHERE id = $1`, [schedule.id]);
  const runs = async () =>
    (await pool.query(`SELECT id, status FROM vulnerability_scans WHERE scan_options->'origin'->>'scheduledScanId' = $1 ORDER BY id`, [String(schedule.id)])).rows;

  try {
    await due();
    await runDueScheduledScans();
    const first = await runs();
    assert.equal(first.length, 1);
    assert.equal(first[0].status, 'queued');

    // Due again while the first is still queued: no second job, but the schedule rolls forward.
    await due();
    await runDueScheduledScans();
    assert.equal((await runs()).length, 1);
    const after1 = await ScheduledScanModel.findById(schedule.id);
    assert.equal(after1!.last_scan_id, first[0].id);
    assert.ok(Date.parse(after1!.next_run_at) > Date.now());

    // "Run now" says so too.
    const now = await call('operator', 'POST', `/api/scheduled-scans/${schedule.id}/run`);
    assert.equal(now.status, 409);
    assert.equal(now.json.scanId, first[0].id);

    // Once the shipper picks it up, the next due run queues normally.
    await pool.query(`UPDATE vulnerability_scans SET status = 'running' WHERE id = $1`, [first[0].id]);
    await due();
    await runDueScheduledScans();
    assert.equal((await runs()).length, 2);
  } finally {
    await pool.query('UPDATE scheduled_scans SET enabled = false WHERE id = $1', [schedule.id]);
  }
});

test('GET/PUT /api/settings/shipper-jobs', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  assert.equal((await call('operator', 'GET', '/api/settings/shipper-jobs')).status, 403);
  const got = await call('admin', 'GET', '/api/settings/shipper-jobs');
  assert.equal(got.status, 200);
  assert.equal(got.json.default_expiry_hours, 24);
  for (const bad of [0, 721, 1.5, '12h', null]) {
    assert.equal((await call('admin', 'PUT', '/api/settings/shipper-jobs', { expiry_hours: bad })).status, 400, String(bad));
  }
  const put = await call('admin', 'PUT', '/api/settings/shipper-jobs', { expiry_hours: 6 });
  assert.equal(put.status, 200);
  assert.equal(await getShipperJobExpiryHours(), 6);

  // The window applies to the claims at once: a 7-hour-old job is now stale.
  await pool.query(`UPDATE vulnerability_scans SET status = 'completed' WHERE assigned_shipper_id = $1 AND status = 'queued'`, [shipperId]);
  const sevenHours = await queuedScan('nmap', 7);
  const pull = await call(null, 'GET', `/api/shippers/scan-jobs/${shipperKey}`);
  assert.ok(!pull.json.jobs.some((j: any) => j.scanId === sevenHours));
  const expired = await statusOf('vulnerability_scans', sevenHours);
  assert.equal(expired.status, 'expired');
  assert.match(expired.error_message, /within 6 h/);

  // A broken stored value falls back to the default rather than stopping expiry.
  await pool.query('UPDATE system_settings SET value = $2 WHERE key = $1', [SHIPPER_JOB_EXPIRY_SETTING_KEY, 'soon']);
  assert.equal(await getShipperJobExpiryHours(), 24);
});
