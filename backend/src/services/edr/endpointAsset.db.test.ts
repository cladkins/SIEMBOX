/**
 * Sticky endpoint assets on a real Postgres (endpointAsset.ts via the ingest
 * functions the agent routes call):
 *   - an IP change moves the agent's asset to the new address (no new asset);
 *   - an address another device holds (nmap host with its own MAC, another
 *     agent's asset) is not taken: recorded in metadata.current_ip instead;
 *   - automatic merge of strong duplicates only (this agent's id in metadata,
 *     or an agent-created asset with this agent's hardware MAC), and not of an
 *     nmap host with the same host name, an asset with the same random MAC, an
 *     nmap host with the same MAC, another agent's asset, or an nmap host that
 *     recorded this agent but has a different hardware MAC;
 *   - an address held by a mergeable duplicate: merged, then taken;
 *   - the startup backfill merges once and is idempotent;
 *   - enrollment: a re-installed agent reuses its machine's agentless asset
 *     by MAC; otherwise the asset at its IP; otherwise a new one.
 *
 * Skips itself when Postgres isn't reachable. Every row created here is
 * removed again. Run with `npm test` (tsx --test).
 */
import { test, before, after, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import pool, { closePools } from '../../config/database';
import { EdrAgentModel } from '../../models/EdrAgent';
import { createEnrollmentToken, enrollAgent, ingestInventory } from './edrService';
import { runEndpointAssetBackfill } from './endpointAsset';

const SKIP = 'Postgres with the SIEMBox schema is not reachable';
const tag = crypto.randomBytes(5).toString('hex');
const prefix = `EPA-${tag}-`;
let dbReady = false;
const assetIds: number[] = [];
const agentIds: string[] = [];
const usedIps = new Set<string>();

function ip(): string {
  for (;;) {
    const v = `198.18.${crypto.randomInt(0, 256)}.${crypto.randomInt(1, 255)}`;
    if (!usedIps.has(v)) {
      usedIps.add(v);
      return v;
    }
  }
}
/** A globally administered unicast MAC (identifies hardware). */
const hwMac = () => `00:${crypto.randomBytes(5).toString('hex').match(/../g)!.join(':')}`;
/** A locally administered ("private Wi-Fi") MAC. */
const randomMac = () => `a6:${crypto.randomBytes(5).toString('hex').match(/../g)!.join(':')}`;

async function asset(over: Record<string, unknown> = {}): Promise<number> {
  const r = await pool.query(
    `INSERT INTO assets (ip_address, hostname, mac_address, discovery_method, asset_type, metadata)
     VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
    [over.ip ?? ip(), over.hostname ?? null, over.mac ?? null, over.discovery_method ?? 'nmap', over.asset_type ?? 'server',
     over.metadata ? JSON.stringify(over.metadata) : null]
  );
  assetIds.push(r.rows[0].id);
  return r.rows[0].id;
}

async function agent(assetId: number | null): Promise<string> {
  const id = crypto.randomUUID();
  agentIds.push(id);
  await EdrAgentModel.create({ agent_id: id, api_key_hash: crypto.randomBytes(32).toString('hex'), asset_id: assetId, hostname: `${prefix}host` });
  return id;
}

const exists = async (id: number) => (await pool.query('SELECT 1 FROM assets WHERE id = $1', [id])).rows.length === 1;
const assetRow = async (id: number) => (await pool.query('SELECT host(ip_address) AS ip, * FROM assets WHERE id = $1', [id])).rows[0];
const agentAsset = async (id: string) => (await EdrAgentModel.findById(id))!.asset_id;
const inventory = (o: { ip: string; mac?: string; hostname?: string }) => ({
  hostname: o.hostname ?? `${prefix}mbp.local`, os: 'darwin', os_version: '15.1', ip: o.ip, mac: o.mac ?? '', agent_version: '0.0.30',
  collected_at: new Date().toISOString(),
});

before(async () => {
  try {
    await pool.query('SELECT 1 FROM edr_agents LIMIT 1');
    dbReady = true;
  } catch {
    // skipped below
  }
});

after(async () => {
  if (dbReady) {
    const ours = await pool.query('SELECT asset_id FROM edr_agents WHERE agent_id = ANY($1::uuid[]) AND asset_id IS NOT NULL', [agentIds]);
    const all = [...assetIds, ...ours.rows.map((r) => r.asset_id)];
    await pool.query('DELETE FROM edr_agents WHERE agent_id = ANY($1::uuid[])', [agentIds]);
    await pool.query(`DELETE FROM audit_logs WHERE action = 'asset.merge' AND resource_id = ANY($1)`, [all]);
    await pool.query(`DELETE FROM assets WHERE id = ANY($1) OR metadata->>'agent_id' = ANY($2::text[])`, [all, agentIds]);
    await pool.query('DELETE FROM vulnerabilities WHERE cve_id LIKE $1', [`${prefix}%`]);
    await pool.query('DELETE FROM edr_enrollment_tokens WHERE label LIKE $1', [`${prefix}%`]);
  }
  await closePools();
});

function skipUnlessDb(t: TestContext): boolean {
  if (dbReady) return false;
  t.skip(SKIP);
  return true;
}

test('an IP change keeps the agent on its asset and moves the asset to the free address', async (t) => {
  if (skipUnlessDb(t)) return;
  const first = ip();
  const a = await asset({ ip: first, discovery_method: 'edr_agent', asset_type: 'endpoint' });
  const id = await agent(a);
  const next = ip();
  assert.equal(await ingestInventory(id, inventory({ ip: next })), a);
  assert.equal(await agentAsset(id), a);
  const row = await assetRow(a);
  assert.equal(row.ip, next);
  assert.equal(row.metadata.agent_id, id);
  assert.equal(row.metadata.current_ip, undefined);
  assert.ok(row.metadata.ip_history.some((h: { ip: string }) => h.ip === next));
  assert.equal((await pool.query('SELECT COUNT(*)::int AS n FROM assets WHERE ip_address = ANY($1::inet[])', [[first, next]])).rows[0].n, 1, 'no new asset');
  assert.equal((await EdrAgentModel.findById(id))!.ip, next);
});

test('an address another device holds is not taken; it is recorded as current_ip', async (t) => {
  if (skipUnlessDb(t)) return;
  const home = ip();
  const a = await asset({ ip: home, discovery_method: 'edr_agent', asset_type: 'endpoint' });
  const id = await agent(a);
  const agentMac = hwMac();
  // An nmap host with its own hardware MAC at the address the agent now reports.
  const busy = ip();
  const nmapHost = await asset({ ip: busy, hostname: 'printer', mac: hwMac() });
  await ingestInventory(id, inventory({ ip: busy, mac: agentMac }));
  assert.equal(await agentAsset(id), a);
  let row = await assetRow(a);
  assert.equal(row.ip, home, 'kept its own address');
  assert.equal(row.metadata.current_ip, busy);
  assert.ok(await exists(nmapHost));
  assert.equal((await assetRow(nmapHost)).hostname, 'printer', 'the other device is untouched');

  // Another agent's asset is never taken either.
  const otherIp = ip();
  const otherAsset = await asset({ ip: otherIp, discovery_method: 'edr_agent', metadata: { agent_id: id } });
  await agent(otherAsset);
  await ingestInventory(id, inventory({ ip: otherIp, mac: agentMac }));
  assert.ok(await exists(otherAsset), "another agent's asset is not merged even though it recorded this agent");
  row = await assetRow(a);
  assert.equal(row.ip, home);
  assert.equal(row.metadata.current_ip, otherIp);

  // A free address again: taken, current_ip cleared.
  const free = ip();
  await ingestInventory(id, inventory({ ip: free, mac: agentMac }));
  row = await assetRow(a);
  assert.equal(row.ip, free);
  assert.equal(row.metadata.current_ip, undefined);
});

test('automatic merge: strong duplicates only', async (t) => {
  if (skipUnlessDb(t)) return;
  const mac = hwMac();
  const rnd = randomMac();
  const a = await asset({ discovery_method: 'nmap', hostname: `${prefix}mbp.localdomain` });
  const id = await agent(a);
  const v = (await pool.query(`INSERT INTO vulnerabilities (cve_id, severity, title) VALUES ($1, 'high', 'x') RETURNING id`, [`${prefix}v`])).rows[0].id;

  // Merged: (a) this agent's id in metadata (agent-created; and an nmap host without a hardware MAC).
  const byAgentId = await asset({ discovery_method: 'edr_agent', metadata: { agent_id: id } });
  await pool.query(`INSERT INTO asset_vulnerabilities (asset_id, vulnerability_id, status) VALUES ($1, $2, 'open')`, [byAgentId, v]);
  const nmapByAgentId = await asset({ discovery_method: 'nmap', metadata: { agent_id: id }, mac: rnd });
  // Merged: (b) an agent-created asset with this agent's hardware MAC (from a removed agent).
  const byMac = await asset({ discovery_method: 'edr_agent', mac: mac.toUpperCase(), metadata: { agent_id: crypto.randomUUID() } });

  // Not merged:
  const sameHostname = await asset({ discovery_method: 'nmap', hostname: `${prefix}mbp.localdomain` });
  const sameRandomMac = await asset({ discovery_method: 'edr_agent', mac: rnd });
  const nmapSameMac = await asset({ discovery_method: 'nmap', mac });
  const otherAgents = await asset({ discovery_method: 'edr_agent', mac, metadata: { agent_id: id } });
  await agent(otherAgents);
  const nmapOtherHwMac = await asset({ discovery_method: 'nmap', metadata: { agent_id: id }, mac: hwMac() });

  await ingestInventory(id, inventory({ ip: (await assetRow(a)).ip, mac }));
  assert.equal(await agentAsset(id), a);
  for (const gone of [byAgentId, nmapByAgentId, byMac]) assert.equal(await exists(gone), false, `asset ${gone} merged`);
  for (const kept of [sameHostname, sameRandomMac, nmapSameMac, otherAgents, nmapOtherHwMac]) assert.equal(await exists(kept), true, `asset ${kept} not merged`);
  const moved = await pool.query('SELECT asset_id FROM asset_vulnerabilities WHERE vulnerability_id = $1', [v]);
  assert.deepEqual(moved.rows.map((r) => r.asset_id), [a], 'the duplicate\'s findings moved to the agent\'s asset');

  const audit = (await pool.query(`SELECT user_id, details FROM audit_logs WHERE action = 'asset.merge' AND resource_id = $1`, [a])).rows;
  assert.equal(audit.length, 1);
  assert.equal(audit[0].user_id, null);
  assert.equal(audit[0].details.mode, 'auto');
  assert.equal(audit[0].details.agent_id, id);
  assert.equal(audit[0].details.trigger, 'inventory');
  assert.deepEqual(audit[0].details.rules.map((r: { id: number; reason: string }) => [r.id, r.reason]),
    [[byAgentId, 'agent_id'], [nmapByAgentId, 'agent_id'], [byMac, 'mac']]);

  // A random MAC reported by the agent is never used to merge.
  const a2 = await asset({ discovery_method: 'edr_agent' });
  const id2 = await agent(a2);
  const dupRandom = await asset({ discovery_method: 'edr_agent', mac: rnd });
  await ingestInventory(id2, inventory({ ip: (await assetRow(a2)).ip, mac: rnd }));
  assert.equal(await exists(dupRandom), true);
});

test('an address held by a mergeable duplicate: merged, then taken', async (t) => {
  if (skipUnlessDb(t)) return;
  const a = await asset({ discovery_method: 'edr_agent' });
  const id = await agent(a);
  const there = ip();
  const dup = await asset({ ip: there, discovery_method: 'edr_agent', metadata: { agent_id: id } });
  await ingestInventory(id, inventory({ ip: there }));
  assert.equal(await exists(dup), false);
  const row = await assetRow(a);
  assert.equal(row.ip, there);
  assert.deepEqual(row.metadata.merged_assets.map((m: { id: number }) => m.id), [dup]);
});

test('the startup backfill merges each agent\'s leftovers once and is idempotent', async (t) => {
  if (skipUnlessDb(t)) return;
  const mac = hwMac();
  const a = await asset({ discovery_method: 'nmap', mac });
  const id = await agent(a);
  const d1 = await asset({ discovery_method: 'edr_agent', metadata: { agent_id: id } });
  const d2 = await asset({ discovery_method: 'edr_agent', mac, metadata: { agent_id: crypto.randomUUID() } });
  const hostnameOnly = await asset({ discovery_method: 'edr_agent', hostname: `${prefix}mbp.local` });

  const first = await runEndpointAssetBackfill([id]);
  assert.equal(first.agents, 1);
  assert.deepEqual(first.merges, [{ agent_id: id, into: a, from: [d1, d2] }]);
  assert.equal(await exists(d1), false);
  assert.equal(await exists(d2), false);
  assert.equal(await exists(hostnameOnly), true);
  const again = await runEndpointAssetBackfill([id]);
  assert.deepEqual(again.merges, []);
  const audit = await pool.query(`SELECT details FROM audit_logs WHERE action = 'asset.merge' AND resource_id = $1`, [a]);
  assert.equal(audit.rows.length, 1);
  assert.equal(audit.rows[0].details.trigger, 'backfill');
});

test('enrollment: reuse by hardware MAC, else the asset at the IP, else a new one', async (t) => {
  if (skipUnlessDb(t)) return;
  const enroll = async (body: Record<string, unknown>) => {
    const { token } = await createEnrollmentToken({ label: `${prefix}tok` });
    const r = await enrollAgent({ enrollment_token: token, hostname: `${prefix}mbp`, os: 'darwin', ...body });
    agentIds.push(r.agent_id);
    return r.agent_id;
  };
  // A re-installed agent: its old (agentless) asset has the machine's MAC.
  const mac = hwMac();
  const old = await asset({ discovery_method: 'edr_agent', mac, metadata: { agent_id: crypto.randomUUID() } });
  const reinstalled = await enroll({ ip: ip(), mac });
  assert.equal(await agentAsset(reinstalled), old);

  // No MAC: the asset at its IP (an nmap host there), as before.
  const at = ip();
  const nmapHost = await asset({ ip: at, discovery_method: 'nmap' });
  const fresh = await enroll({ ip: at });
  assert.equal(await agentAsset(fresh), nmapHost);
  assert.equal((await assetRow(nmapHost)).asset_type, 'endpoint');

  // A free IP: a new endpoint asset.
  const free = ip();
  const brandNew = await enroll({ ip: free });
  const row = await assetRow((await agentAsset(brandNew))!);
  assert.equal(row.ip, free);
  assert.equal(row.discovery_method, 'edr_agent');
  assert.equal(row.metadata.agent_id, brandNew);
});
