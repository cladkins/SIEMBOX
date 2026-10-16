/**
 * Query plans: the alert lookups the graph sends use migration 043's indexes.
 *
 * The SQL is captured from the real resolvers (a recording query function),
 * then EXPLAINed on a dedicated connection inside one transaction that seeds
 * 20,000 alerts and runs ANALYZE, so the planner sees realistic statistics;
 * everything is rolled back (statistics included), so other tests see nothing.
 * Skips itself without Postgres. Run with `npm test`.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import type { PoolClient } from 'pg';
import pool, { closePools } from '../../config/database';
import type { Query } from './budget';
import { alertIpMatch, alertKeyEquals } from './alertKeys';
import { entityRef, type EntityRef } from './entityKey';
import { RELATIONS } from './relations';
import type { CenterInfo, RelationDef, ResolverCtx } from './resolvers/common';
import { resolveWindow } from './window';

const SKIP = 'Postgres with the SIEMBox schema is not reachable';
let db: PoolClient | undefined;
const tag = crypto.randomBytes(3).toString('hex');

before(async () => {
  try {
    db = await pool.connect();
    await db.query('SELECT 1 FROM alerts LIMIT 1');
  } catch {
    db?.release();
    db = undefined;
    return;
  }
  await db.query('BEGIN');
  // 20,000 alerts over 30 days: 2,000 distinct source IPs, users and hosts, a
  // few EDR, sign-in and Digital Risk alerts, and 500 sign-in audit rows.
  await db.query(
    `INSERT INTO alerts (severity, title, matched_data, status, created_at, source)
     SELECT (ARRAY['low','medium','high','critical'])[1 + g % 4], 'plan ' || $1,
            jsonb_build_object('source_ip', '198.18.' || (g % 250) || '.' || (g % 8),
                               'dest_ip', '10.1.' || (g % 200) || '.' || (g % 5),
                               'client_ip', CASE WHEN g % 10 = 0 THEN '203.0.113.' || (g % 250) END,
                               'user', 'user' || (g % 2000), 'target_user', 'target' || (g % 500),
                               'host', 'Host' || (g % 2000), 'domain', 'd' || (g % 300) || '.example',
                               'user_id', (g % 50)::text, 'agent_id', md5(g::text),
                               'lookalike', 'l' || (g % 300) || '.example'),
            'new', NOW() - make_interval(mins => g * 2),
            CASE WHEN g % 50 = 0 THEN 'siembox-auth' WHEN g % 50 = 1 THEN 'edr' WHEN g % 50 = 2 THEN 'domain-monitor' END
       FROM generate_series(1, 20000) g`,
    [tag]
  );
  await db.query(
    `INSERT INTO audit_logs (action, ip_address, timestamp)
     SELECT 'auth.login.failure', ('198.18.' || (g % 250) || '.' || (g % 8))::inet, NOW() - make_interval(mins => g)
       FROM generate_series(1, 500) g`
  );
  await db.query('ANALYZE alerts');
  await db.query('ANALYZE audit_logs');
});

after(async () => {
  if (db) {
    await db.query('ROLLBACK');
    db.release();
  }
  await closePools();
});

/** The statements a relation sends for `center`, captured instead of run. */
async function captured(def: RelationDef, center: EntityRef, row: Record<string, unknown> | null = null) {
  const statements: Array<{ sql: string; params: unknown[] }> = [];
  const q: Query = async <T>(sql: string, params: unknown[] = []) => {
    statements.push({ sql, params });
    return [] as T[];
  };
  const centerInfo: CenterInfo = { exists: true, row };
  const ctx: ResolverCtx = { role: 'admin', window: resolveWindow({ window: '7d' }, Date.now()), vulnStatus: 'open', center, centerInfo };
  await def.fetch(q, ctx, { limit: 5, offset: 0 });
  assert.ok(statements.length >= 1, `${def.center} ${def.rel} sent its query`);
  return statements[0];
}

async function plannedIndexes(statement: { sql: string; params: unknown[] }): Promise<string[]> {
  const { rows } = await db!.query(`EXPLAIN (FORMAT JSON) ${statement.sql}`, statement.params);
  const names = new Set<string>();
  const walk = (node: { 'Index Name'?: string; Plans?: unknown[] }) => {
    if (node['Index Name']) names.add(node['Index Name']);
    for (const child of node.Plans ?? []) walk(child as typeof node);
  };
  walk(rows[0]['QUERY PLAN'][0].Plan);
  return [...names].sort();
}

const def = (center: string, rel: string) => RELATIONS.find((d) => d.center === center && d.rel === rel)!;

test('alerts naming an IP: a BitmapOr over the three IP indexes', async (t) => {
  if (!db) return t.skip(SKIP);
  const indexes = await plannedIndexes(await captured(def('ip', 'entity_alerts'), entityRef('ip', '198.18.7.3')));
  for (const name of ['idx_graph_alerts_md_source_ip', 'idx_graph_alerts_md_client_ip', 'idx_graph_alerts_md_dest_ip']) {
    assert.ok(indexes.includes(name), `${name} in ${indexes.join(', ')}`);
  }
});

test('alerts naming a user, host or domain; a rule, account or endpoint: their own indexes', async (t) => {
  if (!db) return t.skip(SKIP);
  const cases: Array<[string, EntityRef, string[]]> = [
    ['user', entityRef('user', 'user17'), ['idx_graph_alerts_md_user', 'idx_graph_alerts_md_target_user']],
    ['host', entityRef('host', 'host17'), ['idx_graph_alerts_md_host']],
    ['domain', entityRef('domain', 'd17.example'), ['idx_graph_alerts_md_domain', 'idx_graph_alerts_dm_lookalike']],
    ['account', entityRef('account', '7'), ['idx_graph_alerts_auth_user_id']],
    ['endpoint', entityRef('endpoint', '3f2504e0-4f89-11d3-9a0c-0305e82c3301'), ['idx_graph_alerts_edr_agent_id']],
  ];
  for (const [center, ref, expected] of cases) {
    const indexes = await plannedIndexes(await captured(def(center, 'entity_alerts'), ref));
    for (const name of expected) assert.ok(indexes.includes(name), `${center}: ${name} in ${indexes.join(', ')}`);
  }
  // A noisy rule (half the seeded alerts): its latest alerts come straight off
  // (rule_id, created_at DESC), with no sort of all of them.
  const [{ id: ruleId }] = (
    await db.query(`INSERT INTO detection_rules (name, severity, rule_yaml, rule_logic) VALUES ($1, 'low', 'x: 1', '{}') RETURNING id`, [`plan-${tag}`])
  ).rows;
  await db.query(`UPDATE alerts SET rule_id = $1 WHERE title = $2 AND id % 2 = 0`, [ruleId, `plan ${tag}`]);
  await db.query('ANALYZE alerts');
  const rule = await plannedIndexes(await captured(def('rule', 'rule_alerts'), entityRef('rule', String(ruleId))));
  assert.ok(rule.includes('idx_graph_alerts_rule_created'), rule.join(', '));
});

test("an asset's alerts: asset_id or its current IP", async (t) => {
  if (!db) return t.skip(SKIP);
  const indexes = await plannedIndexes(await captured(def('asset', 'entity_alerts'), entityRef('asset', '1'), { ip: '198.18.7.3', hostname: 'x' }));
  for (const name of ['idx_alerts_asset_id', 'idx_graph_alerts_md_source_ip', 'idx_graph_alerts_md_dest_ip']) {
    assert.ok(indexes.includes(name), `${name} in ${indexes.join(', ')}`);
  }
});

test("Threat Intel's IP view and Asset-360 use the same indexes (alertKeys.ts)", async (t) => {
  if (!db) return t.skip(SKIP);
  const threatIntel = await plannedIndexes({ sql: `SELECT id FROM alerts WHERE ${alertIpMatch('$1', { column: 'matched_data' })}`, params: ['198.18.7.3'] });
  for (const name of ['idx_graph_alerts_md_source_ip', 'idx_graph_alerts_md_client_ip', 'idx_graph_alerts_md_dest_ip']) {
    assert.ok(threatIntel.includes(name), `${name} in ${threatIntel.join(', ')}`);
  }
  const asset360 = await plannedIndexes({
    sql: `SELECT id FROM alerts WHERE asset_id = $1 OR ($2::text IS NOT NULL AND ${alertKeyEquals('source_ip', '$2', { column: 'matched_data' })})`,
    params: [1, '198.18.7.3'],
  });
  assert.ok(asset360.includes('idx_graph_alerts_md_source_ip'), asset360.join(', '));
});

test('SIEMBox sign-ins from an IP (admin): idx_graph_audit_logs_ip_time', async (t) => {
  if (!db) return t.skip(SKIP);
  const indexes = await plannedIndexes(await captured(def('ip', 'ip_signins'), entityRef('ip', '198.18.7.3')));
  assert.ok(indexes.includes('idx_graph_audit_logs_ip_time'), indexes.join(', '));
});
