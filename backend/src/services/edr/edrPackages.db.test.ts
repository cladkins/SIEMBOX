/**
 * Endpoint package snapshots (migration 049) at a realistic size, on a real
 * Postgres: a host's 10,000 installed packages are stored well inside the
 * agent's 30 s request timeout; a new snapshot replaces the old one (packages
 * it no longer has are removed, the rest keep their first_seen); an unchanged
 * hash writes nothing, a hash-only report is answered either way, `force`
 * stores anyway; field lengths are clipped and duplicates collapse.
 *
 * Skips itself when Postgres isn't reachable. Every row created here is
 * removed again (the agent's rows cascade). Run with `npm test` (tsx --test).
 */
import { test, before, after, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import pool, { closePools } from '../../config/database';
import { EdrAgentModel } from '../../models/EdrAgent';
import { ingestPackages, listAgentPackages, normalizePackages, computeSnapshotHash, MAX_NAME, MAX_VERSION } from './edrPackages';

const SKIP = 'Postgres with the SIEMBox schema is not reachable';
let dbReady = false;
const agentId = crypto.randomUUID();

before(async () => {
  try {
    await pool.query('SELECT 1 FROM edr_agent_packages LIMIT 1');
    dbReady = true;
  } catch {
    return;
  }
  await EdrAgentModel.create({ agent_id: agentId, api_key_hash: crypto.randomBytes(32).toString('hex'), asset_id: null });
});

after(async () => {
  if (dbReady) await pool.query('DELETE FROM edr_agents WHERE agent_id = $1', [agentId]);
  await closePools();
});

function skipUnlessDb(t: TestContext): boolean {
  if (dbReady) return false;
  t.skip(SKIP);
  return true;
}

const TYPES = ['deb', 'rpm', 'apk', 'pypi', 'npm'];
function packages(n: number, version = (i: number) => `1.${i % 50}.${i}`) {
  const out = [];
  for (let i = 0; i < n; i++) out.push({ name: `pkg-${i}`, version: version(i), type: TYPES[i % TYPES.length] });
  return out;
}
const count = async () =>
  (await pool.query('SELECT COUNT(*)::int AS n FROM edr_agent_packages WHERE agent_id = $1', [agentId])).rows[0].n;
const meta = async () => (await pool.query('SELECT * FROM edr_agent_package_snapshots WHERE agent_id = $1', [agentId])).rows[0];

test('normalizePackages clips, cleans and de-duplicates', () => {
  const { rows, skipped } = normalizePackages([
    { name: 'libc6', version: '2.39', type: 'deb' },
    { name: 'libc6', version: '2.39', type: 'deb' }, // multi-arch: listed twice
    { name: 'x'.repeat(1000), version: 'v'.repeat(1000), type: 'DEB' },
    { name: 'a\u0000b', version: 7, type: 'not a type!' },
    { name: '', version: '1' },
    null,
    'string',
  ]);
  assert.equal(skipped, 3);
  assert.deepEqual(rows[0], { type: 'deb', name: 'libc6', version: '2.39' });
  assert.equal(rows.length, 3);
  assert.equal(rows[1].name.length, MAX_NAME);
  assert.equal(rows[1].version.length, MAX_VERSION);
  assert.equal(rows[1].type, 'deb');
  assert.deepEqual(rows[2], { type: '', name: 'ab', version: '7' });
  assert.equal(computeSnapshotHash(rows), computeSnapshotHash([...rows].reverse()), 'order does not matter');
});

test('a 10,000-package snapshot is stored quickly', async (t) => {
  if (skipUnlessDb(t)) return;
  const started = Date.now();
  const res = await ingestPackages(agentId, { snapshot_hash: 'h-1', collected_at: new Date().toISOString(), packages: packages(10_000) });
  const ms = Date.now() - started;
  t.diagnostic(`10,000 packages stored in ${ms} ms`);
  assert.equal(res.accepted, true);
  assert.equal(res.unchanged, false);
  assert.equal(res.stored, 10_000);
  assert.ok(ms < 15_000, `took ${ms} ms; the agent gives up at 30 s`);
  assert.equal(await count(), 10_000);
  const m = await meta();
  assert.equal(m.snapshot_hash, 'h-1');
  assert.equal(m.package_count, 10_000);
});

test('the same hash again writes nothing; hash-only is answered; force stores anyway', async (t) => {
  if (skipUnlessDb(t)) return;
  const before = await meta();
  const lastSeen = (await pool.query('SELECT MAX(last_seen) AS t FROM edr_agent_packages WHERE agent_id = $1', [agentId])).rows[0].t;

  const same = await ingestPackages(agentId, { snapshot_hash: 'h-1', packages: packages(10_000) });
  assert.deepEqual([same.accepted, same.unchanged, same.stored, same.package_count], [true, true, 0, 10_000]);
  const probe = await ingestPackages(agentId, { snapshot_hash: 'h-1' });
  assert.deepEqual([probe.accepted, probe.unchanged, probe.snapshot_required], [true, true, false]);
  const unknown = await ingestPackages(agentId, { snapshot_hash: 'h-other' });
  assert.deepEqual([unknown.accepted, unknown.unchanged, unknown.snapshot_required], [false, false, true]);
  assert.equal((await meta()).snapshot_hash, 'h-1', 'a hash-only report changes nothing');

  const after = await meta();
  assert.ok(new Date(after.reported_at) > new Date(before.reported_at), 'reported_at moves');
  assert.equal(String(after.stored_at), String(before.stored_at), 'stored_at does not');
  const lastSeen2 = (await pool.query('SELECT MAX(last_seen) AS t FROM edr_agent_packages WHERE agent_id = $1', [agentId])).rows[0].t;
  assert.equal(String(lastSeen2), String(lastSeen));

  const forced = await ingestPackages(agentId, { snapshot_hash: 'h-1', force: true, packages: packages(10_000) });
  assert.deepEqual([forced.unchanged, forced.stored, forced.removed], [false, 10_000, 0]);
});

test('a new snapshot replaces the old: dropped packages go, upgrades replace, first_seen stays', async (t) => {
  if (skipUnlessDb(t)) return;
  const firstSeen = (await pool.query(`SELECT first_seen FROM edr_agent_packages WHERE agent_id = $1 AND name = 'pkg-1'`, [agentId])).rows[0].first_seen;
  // 9,000 of them, and pkg-0 upgraded.
  const next = packages(9_000, (i) => (i === 0 ? '2.0.0' : `1.${i % 50}.${i}`));
  const started = Date.now();
  const res = await ingestPackages(agentId, { snapshot_hash: 'h-2', packages: next });
  t.diagnostic(`replacing snapshot (9,000 kept/upgraded, 1,001 removed) took ${Date.now() - started} ms`);
  assert.equal(res.stored, 9_000);
  assert.equal(res.removed, 1_001, '1,000 dropped + the old pkg-0 version');
  assert.equal(await count(), 9_000);
  const { rows } = await pool.query(`SELECT version FROM edr_agent_packages WHERE agent_id = $1 AND name = 'pkg-0'`, [agentId]);
  assert.deepEqual(rows.map((r) => r.version), ['2.0.0']);
  const kept = (await pool.query(`SELECT first_seen FROM edr_agent_packages WHERE agent_id = $1 AND name = 'pkg-1'`, [agentId])).rows[0].first_seen;
  assert.equal(String(kept), String(firstSeen));

  const list = await listAgentPackages(agentId, { q: 'pkg-0', limit: 5 });
  assert.equal(list.total, 1);
  assert.equal(list.packages[0].version, '2.0.0');
  assert.equal(list.snapshot.package_count, 9_000);
});

test('without a hash the server computes one; two reports from one agent at once leave one whole snapshot', async (t) => {
  if (skipUnlessDb(t)) return;
  const a = packages(3_000);
  const first = await ingestPackages(agentId, { packages: a });
  assert.equal(first.stored, 3_000);
  const again = await ingestPackages(agentId, { packages: [...a].reverse() });
  assert.equal(again.unchanged, true, 'same set, any order');

  const b = packages(2_000, () => '9.9.9');
  const results = await Promise.all([ingestPackages(agentId, { packages: b }), ingestPackages(agentId, { packages: a, force: true })]);
  assert.ok(results.every((r) => r.accepted));
  const n = await count();
  assert.ok(n === 3_000 || n === 2_000, `one snapshot or the other, not a mix (${n})`);
  assert.equal((await meta()).package_count, n);
});

test('an empty list is a snapshot of nothing; a non-array is refused', async (t) => {
  if (skipUnlessDb(t)) return;
  const res = await ingestPackages(agentId, { packages: [] });
  assert.equal(res.accepted, true);
  assert.equal(await count(), 0);
  await assert.rejects(ingestPackages(agentId, { packages: 'nope' }), /packages must be an array/);
  await assert.rejects(ingestPackages(agentId, {}), /packages must be an array/);
  await assert.rejects(ingestPackages(agentId, { snapshot_hash: 'bad hash with spaces' }), /malformed/);
});
