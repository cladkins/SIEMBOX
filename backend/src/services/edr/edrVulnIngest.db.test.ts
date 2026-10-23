/**
 * EDR vulnerability ingest at a realistic size, on a real Postgres: a host's
 * grype report of thousands of findings is stored in batches (well inside the
 * agent's 30 s request timeout), with the same per-row results as the old
 * one-upsert-per-finding loop: duplicate identifiers collapse to the last
 * report, a re-sent report updates rather than duplicates, and a value a
 * column refuses costs only that finding.
 *
 * Skips itself when Postgres isn't reachable. Every row created here is
 * removed again. Run with `npm test` (tsx --test).
 */
import { test, before, after, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import pool, { closePools } from '../../config/database';
import { EdrAgentModel } from '../../models/EdrAgent';
import { ingestVulnerabilities } from './edrService';

const SKIP = 'Postgres with the SIEMBox schema is not reachable';
const tag = crypto.randomBytes(5).toString('hex');
const prefix = `EDRT-${tag}-`; // vulnerability ids this file owns
let dbReady = false;
let assetId = 0;
const agentId = crypto.randomUUID();

before(async () => {
  try {
    await pool.query('SELECT 1 FROM edr_agents LIMIT 1');
    dbReady = true;
  } catch {
    return;
  }
  const asset = await pool.query(
    `INSERT INTO assets (ip_address, hostname, status) VALUES ($1, $2, 'active') RETURNING id`,
    // A per-run address in the benchmarking range (198.18.0.0/15): ip_address is unique.
    [`198.18.${crypto.randomInt(0, 256)}.${crypto.randomInt(1, 255)}`, `edr-ingest-${tag}`]
  );
  assetId = asset.rows[0].id;
  await EdrAgentModel.create({ agent_id: agentId, api_key_hash: crypto.randomBytes(32).toString('hex'), asset_id: assetId });
});

after(async () => {
  if (dbReady) {
    await pool.query('DELETE FROM edr_agents WHERE agent_id = $1', [agentId]);
    await pool.query('DELETE FROM assets WHERE id = $1', [assetId]); // cascades asset_vulnerabilities
    await pool.query('DELETE FROM vulnerabilities WHERE cve_id LIKE $1', [`${prefix}%`]);
  }
  await closePools();
});

function skipUnlessDb(t: TestContext): boolean {
  if (dbReady) return false;
  t.skip(SKIP);
  return true;
}

function report(n: number, extra: any[] = []) {
  const vulnerabilities = [];
  for (let i = 0; i < n; i++) {
    vulnerabilities.push({
      cve: `${prefix}${i}`,
      severity: i % 4 === 0 ? 'Critical' : 'Medium',
      package: `pkg-${i}`,
      installed_version: '1.0.0',
      fixed_version: '1.0.1',
      cvss: 7.5,
      source: 'grype',
    });
  }
  return { scan_started_at: new Date().toISOString(), vulnerabilities: [...vulnerabilities, ...extra] };
}

test('a 3,000-finding report is stored quickly, duplicates collapsed to the last report', async (t) => {
  if (skipUnlessDb(t)) return;
  // Two packages share one id (grype reports one row per package x match).
  const dup = { cve: `${prefix}0`, severity: 'Low', package: 'pkg-later', source: 'grype' };
  const started = Date.now();
  const stored = await ingestVulnerabilities(agentId, report(3000, [dup]));
  const ms = Date.now() - started;
  assert.equal(stored, 3000, 'one row per unique id');
  assert.ok(ms < 15_000, `took ${ms} ms; the agent gives up at 30 s`);

  const linked = await pool.query(
    `SELECT COUNT(*)::int AS n FROM asset_vulnerabilities av JOIN vulnerabilities v ON v.id = av.vulnerability_id
      WHERE av.asset_id = $1 AND v.cve_id LIKE $2`,
    [assetId, `${prefix}%`]
  );
  assert.equal(linked.rows[0].n, 3000);

  const zero = await pool.query(
    `SELECT v.severity, v.title, v.cvss_score::float AS cvss, av.evidence, av.status, av.risk_score::float AS risk
       FROM vulnerabilities v JOIN asset_vulnerabilities av ON av.vulnerability_id = v.id
      WHERE v.cve_id = $1 AND av.asset_id = $2`,
    [`${prefix}0`, assetId]
  );
  // The later duplicate wins, as the per-row upserts did; cvss kept (COALESCE).
  assert.equal(zero.rows[0].severity, 'low');
  assert.equal(zero.rows[0].title, `${prefix}0 — pkg-later`);
  assert.equal(zero.rows[0].cvss, 7.5);
  assert.equal(zero.rows[0].evidence, 'package=pkg-later source=grype');
  assert.equal(zero.rows[0].status, 'open');
  assert.equal(zero.rows[0].risk, 7.5, 'the risk-score trigger still runs per row');
});

test('re-sending the report updates last_detected instead of adding rows', async (t) => {
  if (skipUnlessDb(t)) return;
  const before = await pool.query(
    `SELECT MAX(last_detected) AS t, COUNT(*)::int AS n FROM asset_vulnerabilities WHERE asset_id = $1`,
    [assetId]
  );
  await new Promise((r) => setTimeout(r, 20));
  const stored = await ingestVulnerabilities(agentId, report(3000));
  assert.equal(stored, 3000);
  const after = await pool.query(
    `SELECT MAX(last_detected) AS t, COUNT(*)::int AS n FROM asset_vulnerabilities WHERE asset_id = $1`,
    [assetId]
  );
  assert.equal(after.rows[0].n, before.rows[0].n);
  assert.ok(new Date(after.rows[0].t) > new Date(before.rows[0].t));
});

test('a finding a column refuses costs only itself', async (t) => {
  if (skipUnlessDb(t)) return;
  // cvss_score is NUMERIC(3,1): 1234 overflows it and fails the batch, which
  // is then stored row by row.
  const bad = { cve: `${prefix}bad`, severity: 'High', cvss: 1234, source: 'grype' };
  const stored = await ingestVulnerabilities(agentId, report(5, [bad]));
  assert.equal(stored, 5);
  const badRow = await pool.query('SELECT 1 FROM vulnerabilities WHERE cve_id = $1', [`${prefix}bad`]);
  assert.equal(badRow.rowCount, 0);
});
