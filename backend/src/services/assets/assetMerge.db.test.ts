/**
 * Merging duplicate assets on a real Postgres (assetMerge.ts):
 *   - every foreign key to assets(id) is one the merge moves;
 *   - a manual merge moves findings (one per vulnerability: earliest first,
 *     latest last, open if any was open, newest evidence, notes kept, risk at
 *     the highest criticality), services (newest per port), alerts, endpoint
 *     agents, Application Monitoring rows and vulnerability links, deletes the
 *     merged rows, records them on the kept one and writes one audit row;
 *   - dry_run changes nothing; bad ids are refused;
 *   - "Possible duplicates" hints (same MAC, same short host name, same agent);
 *   - the HTTP routes and their role gates (viewers may read hints, not merge).
 *
 * Skips itself when Postgres isn't reachable. Every row created here is
 * removed again. Run with `npm test` (tsx --test).
 */
import { test, before, after, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { once } from 'node:events';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import app from '../../app';
import pool, { closePools } from '../../config/database';
import { UserModel } from '../../models/User';
import { SessionModel } from '../../models/Session';
import { EdrAgentModel } from '../../models/EdrAgent';
import { findDuplicateHints, mergeAssets, MERGED_FOREIGN_KEYS } from './assetMerge';

const SKIP = 'Postgres with the SIEMBox schema is not reachable';
const tag = crypto.randomBytes(5).toString('hex');
const prefix = `MRG-${tag}-`;
const ROLES = ['admin', 'operator', 'analyst', 'viewer'] as const;
type Role = (typeof ROLES)[number];

let dbReady = false;
let server: Server | undefined;
let base = '';
const tokens = {} as Record<Role, string>;
const userIds: number[] = [];
const assetIds: number[] = [];
const agentIds: string[] = [];
const usedIps = new Set<string>();

function ip(): string {
  for (;;) {
    const v = `198.19.${crypto.randomInt(0, 256)}.${crypto.randomInt(1, 255)}`;
    if (!usedIps.has(v)) {
      usedIps.add(v);
      return v;
    }
  }
}
/** A globally administered unicast MAC no other file uses. */
const hwMac = () => `00:${crypto.randomBytes(5).toString('hex').match(/../g)!.join(':')}`;

async function asset(over: Record<string, unknown> = {}): Promise<number> {
  const r = await pool.query(
    `INSERT INTO assets (ip_address, hostname, mac_address, criticality, discovery_method, asset_type, first_seen, last_seen, metadata, tags)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`,
    [over.ip ?? ip(), over.hostname ?? null, over.mac ?? null, over.criticality ?? 'medium', over.discovery_method ?? 'nmap',
     over.asset_type ?? 'server', over.first_seen ?? new Date('2026-01-01T00:00:00Z'), over.last_seen ?? new Date('2026-01-01T00:00:00Z'),
     over.metadata ? JSON.stringify(over.metadata) : null, over.tags ?? null]
  );
  assetIds.push(r.rows[0].id);
  return r.rows[0].id;
}

async function vuln(n: string, cvss = 8): Promise<number> {
  const r = await pool.query(
    `INSERT INTO vulnerabilities (cve_id, severity, title, cvss_score) VALUES ($1, 'high', $1, $2) RETURNING id`,
    [`${prefix}${n}`, cvss]
  );
  return r.rows[0].id;
}

async function finding(assetId: number, vulnId: number, f: { status: string; first: string; last: string; evidence?: string; notes?: string; patched?: boolean }) {
  await pool.query(
    `INSERT INTO asset_vulnerabilities (asset_id, vulnerability_id, status, first_detected, last_detected, evidence, notes, patched_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [assetId, vulnId, f.status, f.first, f.last, f.evidence ?? null, f.notes ?? null, f.patched ? new Date() : null]
  );
}

before(async () => {
  try {
    await pool.query('SELECT 1 FROM application_inventory LIMIT 1');
    await pool.query('SELECT 1 FROM edr_agents LIMIT 1');
    dbReady = true;
  } catch {
    return;
  }
  for (const role of ROLES) {
    const user = await UserModel.create({
      username: `merge-${tag}-${role}`,
      email: `merge-${tag}-${role}@siembox.invalid`,
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
    await pool.query('DELETE FROM edr_agents WHERE agent_id = ANY($1::uuid[])', [agentIds]);
    await pool.query(`DELETE FROM alerts WHERE title LIKE $1`, [`${prefix}%`]);
    await pool.query(`DELETE FROM application_inventory WHERE app_id LIKE $1`, [`${prefix}%`]);
    await pool.query(`DELETE FROM application_vuln_links WHERE app_id LIKE $1`, [`${prefix}%`]);
    await pool.query('DELETE FROM assets WHERE id = ANY($1)', [assetIds]);
    await pool.query('DELETE FROM vulnerabilities WHERE cve_id LIKE $1', [`${prefix}%`]);
    await pool.query(`DELETE FROM audit_logs WHERE action = 'asset.merge' AND resource_id = ANY($1)`, [assetIds]);
    await new Promise((resolve) => setTimeout(resolve, 300)); // 403 audit/error rows land fire-and-forget
    await pool.query('DELETE FROM application_errors WHERE user_id = ANY($1)', [userIds]);
    await pool.query('DELETE FROM audit_logs WHERE user_id = ANY($1)', [userIds]);
    await pool.query('DELETE FROM users WHERE id = ANY($1)', [userIds]);
  }
  await closePools();
});

function skipUnlessDb(t: TestContext): boolean {
  if (dbReady) return false;
  t.skip(SKIP);
  return true;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- assertions read whatever the API sent
type Json = any;

async function call(role: Role, method: string, path: string, body?: unknown): Promise<{ status: number; body: Json }> {
  const headers: Record<string, string> = { Authorization: `Bearer ${tokens[role]}` };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

test('every foreign key to assets(id) is one the merge moves', async (t) => {
  if (skipUnlessDb(t)) return;
  const r = await pool.query(
    `SELECT c.conrelid::regclass::text || '.' || a.attname AS fk
       FROM pg_constraint c JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
      WHERE c.contype = 'f' AND c.confrelid = 'assets'::regclass ORDER BY 1`
  );
  assert.deepEqual(r.rows.map((x) => x.fk), [...MERGED_FOREIGN_KEYS].sort(),
    'a new table references assets: move its rows in services/assets/assetMerge.ts and list it in MERGED_FOREIGN_KEYS');
});

test('a manual merge moves every referencing row, combining findings per vulnerability', async (t) => {
  if (skipUnlessDb(t)) return;
  const into = await asset({ hostname: 'kept-host', criticality: 'medium', tags: ['keep'], last_seen: new Date('2026-03-01T00:00:00Z') });
  const s1 = await asset({ hostname: 'dup-1', first_seen: new Date('2025-01-01T00:00:00Z'), tags: ['s1'] });
  const s2 = await asset({ criticality: 'critical', mac: hwMac(), last_seen: new Date('2026-04-01T00:00:00Z') });

  const v1 = await vuln('v1', 8);
  const v2 = await vuln('v2');
  const v3 = await vuln('v3');
  const v4 = await vuln('v4');
  // v1 everywhere: patched on the kept asset, open on s1, the newest evidence on s2.
  await finding(into, v1, { status: 'patched', first: '2026-01-05T00:00:00Z', last: '2026-01-10T00:00:00Z', notes: 'note-kept', evidence: 'kept-ev', patched: true });
  await finding(s1, v1, { status: 'open', first: '2026-01-01T00:00:00Z', last: '2026-01-03T00:00:00Z', notes: 'note-s1' });
  await finding(s2, v1, { status: 'accepted', first: '2026-01-02T00:00:00Z', last: '2026-02-01T00:00:00Z', evidence: 'newest-ev' });
  // v2 only on s1: moved as it is.
  await finding(s1, v2, { status: 'patched', first: '2026-01-01T00:00:00Z', last: '2026-01-02T00:00:00Z', patched: true });
  // v3 on both duplicates, neither open: the most recently detected row's status wins.
  await finding(s1, v3, { status: 'accepted', first: '2026-01-01T00:00:00Z', last: '2026-01-02T00:00:00Z' });
  await finding(s2, v3, { status: 'false_positive', first: '2026-01-03T00:00:00Z', last: '2026-01-04T00:00:00Z' });
  // v4 only on the kept asset: untouched (except its risk follows the raised criticality).
  await finding(into, v4, { status: 'open', first: '2026-01-01T00:00:00Z', last: '2026-01-01T00:00:00Z' });

  await pool.query(`INSERT INTO asset_services (asset_id, port, protocol, service_name, service_version, discovered_at, last_seen) VALUES
    ($1, 22, 'tcp', 'ssh', 'old', '2026-01-05T00:00:00Z', '2026-01-05T00:00:00Z'),
    ($2, 22, 'tcp', 'ssh', 'new', '2026-01-01T00:00:00Z', '2026-02-01T00:00:00Z'),
    ($3, 80, 'tcp', 'http', null, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`, [into, s1, s2]);
  const alert = await pool.query(
    `INSERT INTO alerts (severity, title, matched_data, status, asset_id, source) VALUES ('high', $1, '{}', 'new', $2, 'edr') RETURNING id`,
    [`${prefix}alert`, s1]
  );
  const agentId = crypto.randomUUID();
  agentIds.push(agentId);
  await EdrAgentModel.create({ agent_id: agentId, api_key_hash: crypto.randomBytes(32).toString('hex'), asset_id: s2 });
  const app1 = `${prefix}app1`;
  const app2 = `${prefix}app2`;
  await pool.query(`INSERT INTO application_inventory (app_id, loc_type, loc_key, source, version, events, first_seen, last_seen, evidence) VALUES
    ($1, 'asset', $3, 'edr_package', '1.0', 3, '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z', '{"from":"s1"}'),
    ($1, 'asset', $4, 'edr_package', '1.0', 5, '2026-01-03T00:00:00Z', '2026-01-04T00:00:00Z', '{"from":"s2"}'),
    ($2, 'asset', $3, 'os', '', 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', null)`, [app1, app2, String(s1), String(s2)]);
  await pool.query(`INSERT INTO application_vuln_links (app_id, asset_id, vulnerability_id, match) VALUES ($1, $2, $3, 'package')`, [app1, s1, v2]);

  const preview = await mergeAssets(into, [s1, s2], { mode: 'manual', dryRun: true, userId: userIds[0] });
  assert.equal(preview.dry_run, true);
  assert.deepEqual(preview.moved, {
    vulnerabilities: 5, vulnerabilities_combined: 2, services: 2, alerts: 1, agents: 1, application_locations: 3, application_vuln_links: 1,
  });
  assert.equal((await pool.query('SELECT COUNT(*)::int AS n FROM assets WHERE id = ANY($1)', [[s1, s2]])).rows[0].n, 2, 'dry run deletes nothing');

  const result = await mergeAssets(into, [s1, s2], { mode: 'manual', userId: userIds[0], ipAddress: '127.0.0.1', userAgent: 'test' });
  assert.equal(result.dry_run, false);
  assert.deepEqual(result.merged.map((m) => m.id), [s1, s2]);
  assert.deepEqual(result.merged.find((m) => m.id === s2)!.agents, [agentId]);

  assert.equal((await pool.query('SELECT COUNT(*)::int AS n FROM assets WHERE id = ANY($1)', [[s1, s2]])).rows[0].n, 0);
  const kept = (await pool.query('SELECT * FROM assets WHERE id = $1', [into])).rows[0];
  assert.equal(kept.hostname, 'kept-host');
  assert.equal(kept.criticality, 'critical');
  assert.equal(kept.first_seen.toISOString(), '2025-01-01T00:00:00.000Z');
  assert.equal(kept.last_seen.toISOString(), '2026-04-01T00:00:00.000Z');
  assert.ok(kept.mac_address, 'MAC filled from a duplicate');
  assert.deepEqual([...kept.tags].sort(), ['keep', 's1']);
  assert.deepEqual(kept.metadata.merged_assets.map((m: Json) => m.id), [s1, s2]);

  const findings = (await pool.query(
    `SELECT v.cve_id, av.* FROM asset_vulnerabilities av JOIN vulnerabilities v ON v.id = av.vulnerability_id
      WHERE av.vulnerability_id = ANY($1) ORDER BY v.cve_id`, [[v1, v2, v3, v4]]
  )).rows;
  assert.deepEqual(findings.map((f) => [f.cve_id, f.asset_id]), [[`${prefix}v1`, into], [`${prefix}v2`, into], [`${prefix}v3`, into], [`${prefix}v4`, into]]);
  const f1 = findings[0];
  assert.equal(f1.status, 'open', 'open if any was open');
  assert.equal(f1.patched_at, null);
  assert.equal(f1.first_detected.toISOString(), '2026-01-01T00:00:00.000Z');
  assert.equal(f1.last_detected.toISOString(), '2026-02-01T00:00:00.000Z');
  assert.equal(f1.evidence, 'newest-ev');
  assert.match(f1.notes, /note-kept/);
  assert.match(f1.notes, /note-s1/);
  assert.equal(Number(f1.risk_score), 10, 'cvss 8 x critical 1.5, capped at 10');
  assert.equal(findings[1].status, 'patched');
  assert.equal(findings[2].status, 'false_positive');
  assert.equal(Number(findings[3].risk_score), 10, "the kept asset's own findings follow its raised criticality");

  const services = (await pool.query('SELECT port, service_version, discovered_at FROM asset_services WHERE asset_id = $1 ORDER BY port', [into])).rows;
  assert.deepEqual(services.map((s) => [s.port, s.service_version]), [[22, 'new'], [80, null]]);
  assert.equal(services[0].discovered_at.toISOString(), '2026-01-01T00:00:00.000Z');

  assert.equal((await pool.query('SELECT asset_id FROM alerts WHERE id = $1', [alert.rows[0].id])).rows[0].asset_id, into);
  assert.equal((await EdrAgentModel.findById(agentId))!.asset_id, into);

  const inv = (await pool.query(
    `SELECT app_id, loc_key, events, first_seen, evidence FROM application_inventory WHERE app_id LIKE $1 ORDER BY app_id`, [`${prefix}%`]
  )).rows;
  assert.deepEqual(inv.map((r) => [r.app_id, r.loc_key, Number(r.events)]), [[app1, String(into), 5], [app2, String(into), 1]]);
  assert.equal(inv[0].first_seen.toISOString(), '2026-01-01T00:00:00.000Z');
  assert.deepEqual(inv[0].evidence, { from: 's2' });
  const links = (await pool.query('SELECT asset_id FROM application_vuln_links WHERE app_id = $1', [app1])).rows;
  assert.deepEqual(links.map((l) => l.asset_id), [into]);

  const audit = (await pool.query(`SELECT * FROM audit_logs WHERE action = 'asset.merge' AND resource_id = $1`, [into])).rows;
  assert.equal(audit.length, 1, 'one audit row (the dry run wrote none)');
  assert.equal(audit[0].user_id, userIds[0]);
  assert.equal(audit[0].details.mode, 'manual');
  assert.deepEqual(audit[0].details.merged.map((m: Json) => m.id), [s1, s2]);
  assert.equal(audit[0].details.moved.alerts, 1);
});

test('bad merge requests are refused and change nothing', async (t) => {
  if (skipUnlessDb(t)) return;
  const a = await asset();
  await assert.rejects(mergeAssets(a, [a], { mode: 'manual' }), /into itself/);
  await assert.rejects(mergeAssets(a, [2147483000], { mode: 'manual' }), (e: Json) => e.statusCode === 404);
  await assert.rejects(mergeAssets(2147483000, [a], { mode: 'manual' }), (e: Json) => e.statusCode === 404);
  assert.equal((await pool.query('SELECT COUNT(*)::int AS n FROM assets WHERE id = $1', [a])).rows[0].n, 1);
});

test('possible duplicates: same MAC, same short host name or same agent; hints only', async (t) => {
  if (skipUnlessDb(t)) return;
  const mac = hwMac();
  const host = `mbp-${tag}`;
  const self = await asset({ hostname: `${host.toUpperCase()}.localdomain`, mac, discovery_method: 'nmap' });
  const agentId = crypto.randomUUID();
  agentIds.push(agentId);
  // The agent reports the machine's own name, which differs from nmap's.
  await EdrAgentModel.create({ agent_id: agentId, api_key_hash: crypto.randomBytes(32).toString('hex'), asset_id: self, hostname: `${host}-own.local` });
  const byAgentName = await asset({ hostname: `${host}-OWN.lan`, discovery_method: 'edr_agent' });
  const byName = await asset({ hostname: `${host}.local` });
  const byTailnet = await asset({ hostname: `${host}.tailcb24f.ts.net` });
  const byMac = await asset({ hostname: 'other-name', mac: mac.toUpperCase().replace(/:/g, '-') });
  const byAgent = await asset({ discovery_method: 'edr_agent', metadata: { agent_id: agentId } });
  const unrelated = await asset({ hostname: `${host}-2.local` });

  const hints = (await findDuplicateHints(self))!;
  const ids = hints.map((h) => h.id);
  assert.deepEqual([...ids].sort((x, y) => x - y), [byName, byTailnet, byMac, byAgent, byAgentName].sort((x, y) => x - y));
  assert.deepEqual(hints.find((h) => h.id === byAgentName)!.reasons, ['same_hostname']);
  assert.ok(!ids.includes(unrelated));
  assert.deepEqual(hints.find((h) => h.id === byMac)!.reasons, ['same_mac']);
  assert.deepEqual(hints.find((h) => h.id === byName)!.reasons, ['same_hostname']);
  assert.deepEqual(hints.find((h) => h.id === byAgent)!.reasons, ['same_agent']);
  assert.equal(await findDuplicateHints(2147483000), null);
  // Nothing merged.
  assert.equal((await pool.query('SELECT COUNT(*)::int AS n FROM assets WHERE id = ANY($1)', [[byName, byTailnet, byMac, byAgent]])).rows[0].n, 4);
});

test('routes: anyone reads hints; analysts and up merge (audited refusal for viewers)', async (t) => {
  if (skipUnlessDb(t)) return;
  const into = await asset({ hostname: `route-${tag}.local` });
  const dup = await asset({ hostname: `route-${tag}.lan` });
  const dup2 = await asset({ hostname: `route-${tag}` });

  const hints = await call('viewer', 'GET', `/api/assets/${into}/duplicates`);
  assert.equal(hints.status, 200);
  assert.deepEqual(hints.body.duplicates.map((h: Json) => h.id).sort(), [dup, dup2].sort());
  assert.equal((await call('viewer', 'GET', '/api/assets/2147483000/duplicates')).status, 404);

  const refused = await call('viewer', 'POST', `/api/assets/${into}/merge`, { from: [dup] });
  assert.equal(refused.status, 403);
  await new Promise((resolve) => setTimeout(resolve, 100));
  const denied = await pool.query(`SELECT 1 FROM audit_logs WHERE action = 'access.denied' AND user_id = $1`, [userIds[3]]);
  assert.ok(denied.rows.length > 0, 'the refusal is audited');

  assert.equal((await call('analyst', 'POST', `/api/assets/${into}/merge`, { from: [] })).status, 400);
  assert.equal((await call('analyst', 'POST', `/api/assets/${into}/merge`, { from: [into] })).status, 400);
  assert.equal((await call('analyst', 'POST', `/api/assets/${into}/merge`, { from: [2147483000] })).status, 404);

  const dry = await call('analyst', 'POST', `/api/assets/${into}/merge`, { from: [dup], dry_run: true });
  assert.equal(dry.status, 200);
  assert.equal(dry.body.dry_run, true);
  assert.equal((await pool.query('SELECT COUNT(*)::int AS n FROM assets WHERE id = $1', [dup])).rows[0].n, 1);

  const done = await call('analyst', 'POST', `/api/assets/${into}/merge`, { from: [dup] });
  assert.equal(done.status, 200);
  assert.deepEqual(done.body.merged.map((m: Json) => m.id), [dup]);
  const done2 = await call('operator', 'POST', `/api/assets/${into}/merge`, { from: [String(dup2)] });
  assert.equal(done2.status, 200);
  const audit = (await pool.query(`SELECT user_id, details FROM audit_logs WHERE action = 'asset.merge' AND resource_id = $1 ORDER BY id`, [into])).rows;
  assert.deepEqual(audit.map((a) => a.user_id), [userIds[2], userIds[1]]);
  assert.equal((await call('admin', 'GET', `/api/assets/${into}/duplicates`)).body.duplicates.length, 0);
});
