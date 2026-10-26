/**
 * Endpoint scan history and on-demand scans (migration 050) on a real
 * Postgres: console requests (one outstanding per agent and type, a re-click
 * returns it), serving them in the heartbeat, the agent's start/finish
 * reports (including cancelled and expired requests), its own scheduled runs,
 * expiry, the summaries the vulnerability / package / inventory ingests write
 * into the run's row, history filters, bulk requests and retention.
 *
 * Skips itself when Postgres isn't reachable. Every row created here is
 * removed again (the agents' scans and packages cascade). Run with `npm test`.
 */
import { test, before, after, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import pool, { closePools } from '../../config/database';
import { EdrAgentModel } from '../../models/EdrAgent';
import { ApiError } from '../../middleware/errorHandler';
import {
  requestScans,
  requestScansBulk,
  cancelScan,
  listScans,
  pendingScanRequests,
  reportScan,
  expireStaleScans,
  pruneScanHistory,
  parseScanTypes,
  sanitizeSummary,
  parseCapabilities,
  supportsAdhocScans,
  BULK_SCAN_MAX_AGENTS,
  EDR_SCAN_HISTORY_PER_TYPE,
} from './edrScans';
import { ingestInventory, ingestVulnerabilities, inventoryHash } from './edrService';
import { ingestPackages } from './edrPackages';

const SKIP = 'Postgres with the SIEMBox schema is not reachable';
const tag = crypto.randomBytes(5).toString('hex');
const vulnPrefix = `EDRS-${tag}-`;
let dbReady = false;
let assetId = 0;
let userId: number | null = null;
const agentId = crypto.randomUUID();
const otherAgent = crypto.randomUUID();
const ip = `198.19.${crypto.randomInt(0, 256)}.${crypto.randomInt(1, 255)}`;

before(async () => {
  try {
    await pool.query('SELECT 1 FROM edr_agent_scans LIMIT 1');
    dbReady = true;
  } catch {
    return;
  }
  const asset = await pool.query(
    `INSERT INTO assets (ip_address, hostname, status) VALUES ($1, $2, 'active') RETURNING id`,
    [ip, `edr-scans-${tag}`]
  );
  assetId = asset.rows[0].id;
  const u = await pool.query(
    `INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, 'x', 'analyst') RETURNING id`,
    [`scan-analyst-${tag}`, `scan-${tag}@example.invalid`]
  );
  userId = u.rows[0].id;
  for (const id of [agentId, otherAgent]) {
    await EdrAgentModel.create({ agent_id: id, api_key_hash: crypto.randomBytes(32).toString('hex'), asset_id: id === agentId ? assetId : null, ip });
  }
});

after(async () => {
  if (dbReady) {
    await pool.query('DELETE FROM edr_agents WHERE agent_id = ANY($1::uuid[])', [[agentId, otherAgent]]);
    await pool.query('DELETE FROM assets WHERE id = $1 OR ip_address = $2', [assetId, ip]);
    await pool.query('DELETE FROM vulnerabilities WHERE cve_id LIKE $1', [`${vulnPrefix}%`]);
    if (userId) await pool.query('DELETE FROM users WHERE id = $1', [userId]);
  }
  await closePools();
});

function skipUnlessDb(t: TestContext): boolean {
  if (dbReady) return false;
  t.skip(SKIP);
  return true;
}

const clear = () => pool.query('DELETE FROM edr_agent_scans WHERE agent_id = ANY($1::uuid[])', [[agentId, otherAgent]]);
const row = async (id: string) => (await pool.query('SELECT * FROM edr_agent_scans WHERE id = $1', [id])).rows[0];

async function rejects(p: Promise<unknown>, status: number) {
  await assert.rejects(p, (e: unknown) => e instanceof ApiError && e.statusCode === status);
}

test('validation helpers', () => {
  assert.deepEqual(parseScanTypes(['vuln', 'yara', 'vuln']), ['vuln', 'yara']);
  assert.throws(() => parseScanTypes([]), ApiError);
  assert.throws(() => parseScanTypes(['nmap']), ApiError);
  assert.throws(() => parseScanTypes('vuln'), ApiError);
  assert.deepEqual(sanitizeSummary({ hits: 2, full: true, note: 'x'.repeat(500), Bad: 1, nested: { a: 1 }, nan: NaN }), {
    hits: 2,
    full: true,
    note: 'x'.repeat(200),
  });
  assert.equal(sanitizeSummary([1]), null);
  assert.equal(sanitizeSummary({}), null);
  assert.deepEqual(parseCapabilities(['adhoc_scans', 'adhoc_scans', 7, 'Bad Cap']), ['adhoc_scans']);
  assert.equal(parseCapabilities('adhoc_scans'), undefined);
  assert.equal(supportsAdhocScans({ capabilities: ['adhoc_scans'] }), true);
  assert.equal(supportsAdhocScans({ capabilities: null }), false);
});

test('inventoryHash ignores collected_at, key order and software order', () => {
  const a = { hostname: 'h', os: 'linux', collected_at: '2026-01-01T00:00:00Z', software: [{ name: 'a', version: '1' }, { name: 'b', version: '2' }] };
  const b = { os: 'linux', hostname: 'h', collected_at: '2026-02-02T00:00:00Z', software: [{ version: '2', name: 'b' }, { name: 'a', version: '1' }] };
  assert.equal(inventoryHash(a), inventoryHash(b));
  assert.notEqual(inventoryHash(a), inventoryHash({ ...a, os: 'darwin' }));
});

test('a console request is created once per type; a re-click returns it', async (t) => {
  if (skipUnlessDb(t)) return;
  await clear();
  const first = await requestScans(agentId, ['vuln', 'yara'], userId);
  assert.equal(first.created, 2);
  assert.deepEqual(first.scans.map((s) => [s.scan_type, s.status, s.trigger, s.created]), [
    ['vuln', 'pending', 'console', true],
    ['yara', 'pending', 'console', true],
  ]);
  assert.equal(first.scans[0].requested_by_username, `scan-analyst-${tag}`);
  const again = await requestScans(agentId, ['vuln', 'packages'], userId);
  assert.equal(again.created, 1);
  assert.equal(again.scans[0].id, first.scans[0].id);
  assert.equal(again.scans[0].created, false);
  await rejects(requestScans(crypto.randomUUID(), ['vuln'], userId), 404);
  await rejects(requestScans('not-a-uuid', ['vuln'], userId), 404);

  const served = await pendingScanRequests(agentId);
  assert.deepEqual(served.map((r) => r.scan_type).sort(), ['packages', 'vuln', 'yara']);
  assert.ok(served.every((r) => typeof r.scan_id === 'string' && r.requested_at));
  assert.deepEqual(await pendingScanRequests(otherAgent), []);
});

test('the agent reports start and finish; finished requests stop being served', async (t) => {
  if (skipUnlessDb(t)) return;
  await clear();
  const { scans } = await requestScans(agentId, ['yara'], userId);
  const id = scans[0].id as string;
  const started = new Date(Date.now() - 5000).toISOString();
  assert.deepEqual(await reportScan(agentId, { scan_id: id, scan_type: 'yara', status: 'running', started_at: started }), {
    scan_id: id, status: 'running', accepted: true,
  });
  assert.deepEqual(await pendingScanRequests(agentId), []);
  // Still outstanding while running: a new click returns it.
  const again = await requestScans(agentId, ['yara'], userId);
  assert.equal(again.scans[0].id, id);
  assert.equal(again.created, 0);
  // Repeated running report: harmless.
  assert.equal((await reportScan(agentId, { scan_id: id, scan_type: 'yara', status: 'running' })).accepted, true);
  // Another agent cannot report this scan; the type must match.
  await rejects(reportScan(otherAgent, { scan_id: id, scan_type: 'yara', status: 'succeeded' }), 404);
  await rejects(reportScan(agentId, { scan_id: id, scan_type: 'vuln', status: 'succeeded' }), 400);

  const done = await reportScan(agentId, {
    scan_id: id, scan_type: 'yara', status: 'succeeded', completed_at: new Date().toISOString(),
    summary: { hits: 3, new_hits: 1, full: true },
  });
  assert.deepEqual(done, { scan_id: id, status: 'succeeded', accepted: true });
  const r = await row(id);
  assert.deepEqual(r.summary, { hits: 3, new_hits: 1, full: true });
  assert.equal(new Date(r.started_at).toISOString(), started);
  // A duplicate finish changes nothing.
  assert.deepEqual(await reportScan(agentId, { scan_id: id, scan_type: 'yara', status: 'failed', error: 'late' }), {
    scan_id: id, status: 'succeeded', accepted: false,
  });
  // Now a new click creates a new request.
  const fresh = await requestScans(agentId, ['yara'], userId);
  assert.equal(fresh.created, 1);
  assert.notEqual(fresh.scans[0].id, id);

  const list = await listScans(agentId);
  assert.equal(list.total, 2);
  assert.equal(list.outstanding, 1);
  const finished = list.scans.find((s: any) => s.id === id);
  assert.ok(finished.duration_ms >= 4000);
});

test('a failed run keeps its error (clipped)', async (t) => {
  if (skipUnlessDb(t)) return;
  await clear();
  const { scans } = await requestScans(agentId, ['vuln'], userId);
  const res = await reportScan(agentId, { scan_id: scans[0].id, scan_type: 'vuln', status: 'failed', error: 'grype: ' + 'e'.repeat(900) });
  assert.equal(res.status, 'failed');
  const r = await row(scans[0].id as string);
  assert.equal(r.error.length, 500);
  assert.ok(r.started_at && r.completed_at);
});

test('cancel: only a pending request; the agent is told it was cancelled', async (t) => {
  if (skipUnlessDb(t)) return;
  await clear();
  const { scans } = await requestScans(agentId, ['packages', 'inventory'], userId);
  const [pkg, inv] = scans.map((s) => s.id as string);
  const cancelled = await cancelScan(agentId, pkg);
  assert.equal(cancelled.status, 'cancelled');
  await rejects(cancelScan(agentId, pkg), 409);
  await rejects(cancelScan(otherAgent, inv), 404);
  await rejects(cancelScan(agentId, crypto.randomUUID()), 404);
  // The agent fetched it before the cancel: its start report is refused, it skips the run.
  assert.deepEqual(await reportScan(agentId, { scan_id: pkg, scan_type: 'packages', status: 'running' }), {
    scan_id: pkg, status: 'cancelled', accepted: false,
  });
  assert.equal((await reportScan(agentId, { scan_id: pkg, scan_type: 'packages', status: 'succeeded' })).accepted, false);
  assert.deepEqual((await pendingScanRequests(agentId)).map((r) => r.scan_id), [inv]);
  // Running requests cannot be cancelled.
  await reportScan(agentId, { scan_id: inv, scan_type: 'inventory', status: 'running' });
  await rejects(cancelScan(agentId, inv), 409);
});

test('requests never picked up, and runs never finished, expire', async (t) => {
  if (skipUnlessDb(t)) return;
  await clear();
  const { scans } = await requestScans(agentId, ['vuln', 'yara'], userId);
  const [vuln, yara] = scans.map((s) => s.id as string);
  await pool.query(`UPDATE edr_agent_scans SET requested_at = NOW() - INTERVAL '25 hours' WHERE id = $1`, [vuln]);
  await reportScan(agentId, { scan_id: yara, scan_type: 'yara', status: 'running' });
  await pool.query(`UPDATE edr_agent_scans SET started_at = NOW() - INTERVAL '13 hours' WHERE id = $1`, [yara]);
  // Served list expires first: the stale request is not handed out.
  assert.deepEqual(await pendingScanRequests(agentId), []);
  assert.equal(await expireStaleScans(agentId), 0); // already done by the call above
  const v = await row(vuln);
  const y = await row(yara);
  assert.equal(v.status, 'expired');
  assert.match(v.error, /did not pick up/);
  assert.equal(y.status, 'expired');
  assert.match(y.error, /did not report the scan finished/);
  // An expired request no longer blocks a new one.
  assert.equal((await requestScans(agentId, ['vuln'], userId)).created, 1);
  // A late start report of an expired request is refused; a late finish is recorded.
  assert.equal((await reportScan(agentId, { scan_id: vuln, scan_type: 'vuln', status: 'running' })).accepted, false);
  const late = await reportScan(agentId, { scan_id: yara, scan_type: 'yara', status: 'succeeded', summary: { hits: 0 } });
  assert.deepEqual(late, { scan_id: yara, status: 'succeeded', accepted: true });
  assert.equal((await row(yara)).error, null);
});

test('scheduled and startup runs create their own rows', async (t) => {
  if (skipUnlessDb(t)) return;
  await clear();
  const start = await reportScan(agentId, { scan_type: 'inventory', trigger: 'startup', status: 'running' });
  assert.equal(start.status, 'running');
  assert.equal(start.accepted, true);
  const r = await row(start.scan_id);
  assert.equal(r.trigger, 'startup');
  assert.equal(r.requested_by, null);
  // A scheduled run is not served back to the agent, and does not block a console request.
  assert.deepEqual(await pendingScanRequests(agentId), []);
  assert.equal((await requestScans(agentId, ['inventory'], userId)).created, 1);
  await reportScan(agentId, { scan_id: start.scan_id, scan_type: 'inventory', status: 'succeeded' });

  // One-shot: a finished run reported in one go (an incremental YARA pass with hits).
  const startedAt = new Date(Date.now() - 2000).toISOString();
  const shot = await reportScan(agentId, {
    scan_type: 'yara', status: 'succeeded', started_at: startedAt, completed_at: new Date().toISOString(), summary: { hits: 1, full: false },
  });
  const s = await row(shot.scan_id);
  assert.equal(s.trigger, 'schedule');
  assert.equal(s.status, 'succeeded');
  assert.equal(new Date(s.requested_at).toISOString(), startedAt);

  await rejects(reportScan(agentId, { scan_type: 'vuln', trigger: 'console', status: 'running' }), 400);
  await rejects(reportScan(agentId, { scan_type: 'nmap', status: 'running' }), 400);
  await rejects(reportScan(agentId, { scan_type: 'vuln', status: 'pending' }), 400);
  await rejects(reportScan(agentId, { scan_id: 'nope', scan_type: 'vuln', status: 'running' }), 400);
  await rejects(reportScan(agentId, { scan_id: crypto.randomUUID(), scan_type: 'vuln', status: 'running' }), 404);
});

test('history filters and paging', async (t) => {
  if (skipUnlessDb(t)) return;
  await clear();
  for (let i = 0; i < 5; i++) {
    await reportScan(agentId, { scan_type: i % 2 ? 'vuln' : 'yara', status: i === 4 ? 'failed' : 'succeeded', started_at: new Date(Date.now() - i * 60_000).toISOString() });
  }
  const all = await listScans(agentId, { limit: 2 });
  assert.equal(all.total, 5);
  assert.equal(all.scans.length, 2);
  assert.ok(new Date(all.scans[0].requested_at) >= new Date(all.scans[1].requested_at));
  assert.equal((await listScans(agentId, { limit: 2, offset: 4 })).scans.length, 1);
  assert.equal((await listScans(agentId, { type: 'vuln' })).total, 2);
  assert.equal((await listScans(agentId, { status: 'failed' })).total, 1);
  assert.equal(all.supports_adhoc, false);
  await rejects(listScans(agentId, { type: 'nmap' }), 400);
  await rejects(listScans(agentId, { status: 'done' }), 400);
  await rejects(listScans(crypto.randomUUID()), 404);

  // A capable agent says so in its heartbeat.
  await EdrAgentModel.heartbeat(agentId, 'online', '0.0.20', null, ['adhoc_scans']);
  assert.equal((await listScans(agentId)).supports_adhoc, true);
  // A heartbeat without the field keeps the stored capabilities.
  await EdrAgentModel.heartbeat(agentId, 'online', '0.0.20', null, undefined);
  assert.equal((await listScans(agentId)).supports_adhoc, true);
});

test('bulk requests: bounded, skips outstanding, reports unknown ids', async (t) => {
  if (skipUnlessDb(t)) return;
  await clear();
  await requestScans(agentId, ['vuln'], userId);
  const missing = crypto.randomUUID();
  const res = await requestScansBulk([agentId, otherAgent, missing, agentId.toUpperCase()], ['vuln', 'packages'], userId);
  assert.deepEqual(res, { agents: 2, created: 3, already_outstanding: 1, missing: [missing] });
  const many = Array.from({ length: BULK_SCAN_MAX_AGENTS + 1 }, () => crypto.randomUUID());
  await rejects(requestScansBulk(many, ['vuln'], userId), 400);
  await rejects(requestScansBulk([], ['vuln'], userId), 400);
  await rejects(requestScansBulk(['x'], ['vuln'], userId), 400);
  assert.equal((await requestScansBulk([missing], ['vuln'], userId)).agents, 0);
});

test('ingests write their summary into the scan row', async (t) => {
  if (skipUnlessDb(t)) return;
  await clear();
  await pool.query('UPDATE edr_agents SET last_vuln_ingest_at = NULL, inventory_hash = NULL WHERE agent_id = $1', [agentId]);

  // Packages: first snapshot, then one removed + one added, then unchanged.
  const pk = (await requestScans(agentId, ['packages'], userId)).scans[0].id as string;
  await ingestPackages(agentId, { scan_id: pk, packages: [{ name: 'a', version: '1', type: 'deb' }, { name: 'b', version: '1', type: 'deb' }] });
  assert.deepEqual((await row(pk)).summary, { packages: 2, added: 2, removed: 0, unchanged: 0 });
  await reportScan(agentId, { scan_id: pk, scan_type: 'packages', status: 'succeeded', summary: { packages: 99, sources: 'dpkg' } });
  assert.deepEqual((await row(pk)).summary, { packages: 2, added: 2, removed: 0, unchanged: 0, sources: 'dpkg' });
  const pk2 = (await reportScan(agentId, { scan_type: 'packages', status: 'running' })).scan_id;
  await ingestPackages(agentId, { scan_id: pk2, packages: [{ name: 'a', version: '1', type: 'deb' }, { name: 'c', version: '1', type: 'deb' }] });
  assert.deepEqual((await row(pk2)).summary, { packages: 2, added: 1, removed: 1, unchanged: 1 });
  const hash = (await pool.query('SELECT snapshot_hash FROM edr_agent_package_snapshots WHERE agent_id = $1', [agentId])).rows[0].snapshot_hash;
  const pk3 = (await reportScan(agentId, { scan_type: 'packages', status: 'running' })).scan_id;
  await ingestPackages(agentId, { scan_id: pk3, snapshot_hash: hash });
  assert.deepEqual((await row(pk3)).summary, { packages: 2, added: 0, removed: 0, unchanged: 2 });
  // Another agent's scan id is ignored.
  await ingestPackages(otherAgent, { scan_id: pk3, packages: [{ name: 'z', version: '1' }] });
  assert.deepEqual((await row(pk3)).summary, { packages: 2, added: 0, removed: 0, unchanged: 2 });

  // Inventory: changed the first time, unchanged when only collected_at moves.
  const inventory = { hostname: `edr-scans-${tag}`, ip, os: 'linux', software: [{ name: 'a', version: '1' }] };
  const in1 = (await reportScan(agentId, { scan_type: 'inventory', status: 'running' })).scan_id;
  await ingestInventory(agentId, { ...inventory, collected_at: '2026-10-01T00:00:00Z' }, in1);
  assert.deepEqual((await row(in1)).summary, { changed: true, software: 1 });
  const in2 = (await reportScan(agentId, { scan_type: 'inventory', status: 'running' })).scan_id;
  await ingestInventory(agentId, { ...inventory, collected_at: '2026-10-01T01:00:00Z' }, in2);
  assert.deepEqual((await row(in2)).summary, { changed: false, software: 1 });

  // Vulnerabilities: new vs already known, and the previous report's findings it no longer holds.
  const v = (i: number) => ({ cve: `${vulnPrefix}${i}`, package: 'p', installed_version: '1', severity: 'high' });
  const v1 = (await reportScan(agentId, { scan_type: 'vuln', status: 'running' })).scan_id;
  await ingestVulnerabilities(agentId, { scan_id: v1, vulnerabilities: [v(1), v(2), v(3)] });
  assert.deepEqual((await row(v1)).summary, { findings: 3, new: 3, resolved: 0, stored: 3 });
  const v2 = (await reportScan(agentId, { scan_type: 'vuln', status: 'running' })).scan_id;
  await ingestVulnerabilities(agentId, { scan_id: v2, vulnerabilities: [v(2), v(3), v(4), v(4)] });
  assert.deepEqual((await row(v2)).summary, { findings: 3, new: 1, resolved: 1, stored: 3 });
  // The agent's own count does not overwrite the server's.
  await reportScan(agentId, { scan_id: v2, scan_type: 'vuln', status: 'succeeded', summary: { findings: 4 } });
  assert.equal((await row(v2)).summary.findings, 3);
});

test('retention keeps the newest rows per type and never outstanding ones', async (t) => {
  if (skipUnlessDb(t)) return;
  await clear();
  await pool.query(
    `INSERT INTO edr_agent_scans (agent_id, scan_type, trigger, status, requested_at)
     SELECT $1, 'inventory', 'schedule', 'succeeded', NOW() - (g || ' minutes')::interval FROM generate_series(1, $2::int) g`,
    [agentId, EDR_SCAN_HISTORY_PER_TYPE + 5]
  );
  await pool.query(
    `INSERT INTO edr_agent_scans (agent_id, scan_type, trigger, status, requested_at) VALUES
       ($1, 'vuln', 'schedule', 'succeeded', NOW() - INTERVAL '91 days'),
       ($1, 'vuln', 'schedule', 'succeeded', NOW() - INTERVAL '1 day')`,
    [agentId]
  );
  const { scans } = await requestScans(agentId, ['yara'], userId);
  await pool.query(`UPDATE edr_agent_scans SET requested_at = NOW() - INTERVAL '100 days' WHERE id = $1`, [scans[0].id]);
  // Prune on its own (expiry would also flip that old pending row).
  const pruned = await pruneScanHistory();
  assert.ok(pruned >= 6, `pruned ${pruned}`);
  const counts = await pool.query(
    `SELECT scan_type, COUNT(*)::int AS n FROM edr_agent_scans WHERE agent_id = $1 GROUP BY scan_type ORDER BY scan_type`,
    [agentId]
  );
  assert.deepEqual(counts.rows, [
    { scan_type: 'inventory', n: EDR_SCAN_HISTORY_PER_TYPE },
    { scan_type: 'vuln', n: 1 },
    { scan_type: 'yara', n: 1 },
  ]);
});
