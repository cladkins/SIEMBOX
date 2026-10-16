/**
 * Query plans: the alert lookups the graph, Threat Intel's IP view and
 * Asset-360 send, as they send them (ORDER BY key, created_at DESC LIMIT n),
 * use migration 043's indexes and read a bounded number of rows.
 *
 * The SQL is captured from the real resolvers (a recording query function) or
 * is the statement the route exports, then EXPLAINed on a dedicated
 * connection inside one transaction that seeds 20,000 alerts (plus 4,500
 * naming one hot IP, user and host) and runs ANALYZE, so the planner sees
 * realistic statistics; everything is rolled back (statistics included), so
 * other tests see nothing. Skips itself without Postgres. Run with `npm test`.
 *
 * Why: Postgres keeps no statistics for a partial index's expression, so it
 * took any value for 0.5% of alerts. With an OR of keys under ORDER BY
 * created_at DESC LIMIT n, that guess had it walk idx_alerts_created_at back
 * through every alert for a value no alert names (seconds at a million
 * alerts). Now each key is its own ordered scan (alertKeys.ts latestAlerts()),
 * which no estimate turns into that walk, and 043 keeps statistics on each
 * expression so a common value's scan stops at its limit. These tests check
 * the shape, the statistics, and the bound where the table is big enough to
 * show it (LIMIT 50 and 100); 24,500 rows are too few to show the walk itself.
 *
 * The last test adds the case no estimate covered: one key (an EDR host, a
 * rule, an IP, a user) holding most of the alerts, nearly all older than the
 * window. Taking them to be spread evenly over time, the planner walked
 * idx_alerts_created_at through every alert in the window to find a few. Each
 * arm is now ordered by its own key first (alertKeys.ts AlertArm), an order
 * only that key's index gives.
 *
 * Sequential scans are off in the transaction (enable_seqscan, which only
 * makes them a last resort). 24,500 alerts fit in under 1,000 pages, so reading
 * them all and sorting can cost less than an ordered scan of a common value,
 * and does when other tests have left alerts' indexes bloated (an emptied
 * table keeps its index pages): a choice the planner never makes at the sizes
 * these tests stand for, which would fail them depending on what ran before.
 * A lookup no index serves still shows as a sequential scan.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import type { PoolClient } from 'pg';
import pool, { closePools } from '../../config/database';
import { IP_ALERTS_SQL } from '../../routes/threatIntel';
import { ASSET_ALERTS_SQL } from '../assets/assetContext';
import type { Query } from './budget';
import { entityRef, type EntityRef } from './entityKey';
import { RELATIONS } from './relations';
import { ALERT_KEY_INDEXES, alertKeyEquals, alertKeyStatsName, type AlertKey } from './alertKeys';
import { countAlertsNaming } from './resolvers/alerts';
import type { CenterInfo, RelationDef, ResolverCtx } from './resolvers/common';
import { TOTAL_CAP } from './types';
import { resolveWindow } from './window';

const SKIP = 'Postgres with the SIEMBox schema is not reachable';
let db: PoolClient | undefined;
const tag = crypto.randomBytes(3).toString('hex');
/** Named by 4,500 alerts in the last 30 days (more than any LIMIT here). */
const HOT = { ip: '198.19.250.250', user: `hot-${tag}`, host: `hothost-${tag}` };
/** Named by no alert. */
const RARE_IP = '198.19.251.251';

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
  await db.query('SET LOCAL enable_seqscan = off');
  // 20,000 alerts over 30 days: 1,000 distinct source IPs, 2,000 users and hosts, a
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
    `INSERT INTO alerts (severity, title, matched_data, status, created_at)
     SELECT 'low', 'plan ' || $1, jsonb_build_object('source_ip', $2::text, 'user', $3::text, 'host', $4::text),
            'new', NOW() - make_interval(mins => g * 9)
       FROM generate_series(1, 4500) g`,
    [tag, HOT.ip, HOT.user, HOT.host]
  );
  // Sign-ins name their account, as real ones do: with user_id NULL and one
  // user, reading every row of that user was the planner's cheapest way in.
  const [{ id: userId }] = (
    await db.query(`INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, 'x', 'admin') RETURNING id`, [
      `plan-${tag}`,
      `plan-${tag}@siembox.invalid`,
    ])
  ).rows;
  await db.query(
    `INSERT INTO audit_logs (user_id, action, ip_address, timestamp)
     SELECT $1, 'auth.login.failure', ('198.18.' || (g % 250) || '.' || (g % 8))::inet, NOW() - make_interval(mins => g)
       FROM generate_series(1, 500) g`,
    [userId]
  );
  await db.query('ANALYZE users');
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

type Statement = { sql: string; params: unknown[] };

function recorder(): { q: Query; statements: Statement[] } {
  const statements: Statement[] = [];
  const q: Query = async <T>(sql: string, params: unknown[] = []) => {
    statements.push({ sql, params });
    return [] as T[];
  };
  return { q, statements };
}

function ctxFor(center: EntityRef, row: Record<string, unknown> | null, window = '7d'): ResolverCtx {
  const centerInfo: CenterInfo = { exists: true, row };
  return { role: 'admin', window: resolveWindow({ window }, Date.now()), vulnStatus: 'open', center, centerInfo };
}

/** The statement a relation sends for `center`, captured instead of run. */
async function captured(def: RelationDef, center: EntityRef, row: Record<string, unknown> | null = null, window = '7d'): Promise<Statement> {
  const { q, statements } = recorder();
  await def.fetch(q, ctxFor(center, row, window), { limit: 5, offset: 0 });
  assert.ok(statements.length >= 1, `${def.center} ${def.rel} sent its query`);
  return statements[0];
}

interface PlanNode {
  'Node Type': string;
  'Index Name'?: string;
  'Relation Name'?: string;
  'Actual Rows'?: number;
  'Actual Loops'?: number;
  'Rows Removed by Filter'?: number;
  'Rows Removed by Index Recheck'?: number;
  Plans?: PlanNode[];
}

/** Every node of a plan, with its parent's type. */
function nodes(plan: PlanNode, parent = ''): Array<PlanNode & { parent: string }> {
  return [{ ...plan, parent }, ...(plan.Plans ?? []).flatMap((child) => nodes(child, plan['Node Type']))];
}

async function plan(statement: Statement, analyze = false): Promise<Array<PlanNode & { parent: string }>> {
  const { rows } = await db!.query(`EXPLAIN (${analyze ? 'ANALYZE, ' : ''}FORMAT JSON) ${statement.sql}`, statement.params);
  return nodes(rows[0]['QUERY PLAN'][0].Plan);
}

async function plannedIndexes(statement: Statement): Promise<string[]> {
  return [...new Set((await plan(statement)).map((n) => n['Index Name']).filter((name): name is string => Boolean(name)))].sort();
}

/**
 * The shape of an "alerts naming X" plan: one scan per arm, each on its key's
 * index; never an OR of keys (a BitmapOr, which the planner can trade for a walk
 * of idx_alerts_created_at when it misjudges the value), that walk, or a
 * sequential scan of alerts.
 */
async function assertOrderedArms(label: string, statement: Statement, expected: string[]) {
  const all = await plan(statement);
  const used = all.filter((n) => n['Index Name']);
  assert.ok(!all.some((n) => n['Node Type'] === 'BitmapOr'), `${label}: no OR of keys`);
  assert.ok(!used.some((n) => n['Index Name'] === 'idx_alerts_created_at'), `${label}: no walk of idx_alerts_created_at`);
  assert.ok(!all.some((n) => n['Node Type'] === 'Seq Scan' && n['Relation Name'] === 'alerts'), `${label}: no sequential scan`);
  for (const name of expected) assert.ok(used.some((n) => n['Index Name'] === name), `${label}: ${name} in ${used.map((n) => n['Index Name']).join(', ')}`);
}

/**
 * Never the walk: idx_alerts_created_at read in its own order under a Limit,
 * stopping once enough rows pass the filter, which for a key whose alerts are
 * mostly older than the window means reading every alert in it. Each arm is
 * ordered by its key first, which that index can't give, so a scan of it can
 * only appear under a Sort (the window read whole, which the planner picks for
 * a small window).
 */
async function assertNoWalk(label: string, statement: Statement) {
  const all = await plan(statement);
  for (const n of all.filter((node) => node['Index Name'] === 'idx_alerts_created_at')) {
    assert.equal(n.parent, 'Sort', `${label}: idx_alerts_created_at only read whole and sorted, not walked (under ${n.parent})`);
  }
  assert.ok(!all.some((n) => n['Node Type'] === 'BitmapOr'), `${label}: no OR of keys`);
  assert.ok(!all.some((n) => n['Node Type'] === 'Seq Scan' && n['Relation Name'] === 'alerts'), `${label}: no sequential scan`);
}

/** Rows each scan of `alerts` read (kept, filtered out, rechecked), over all its loops. */
async function rowsRead(statement: Statement): Promise<Array<{ index: string; read: number }>> {
  return (await plan(statement, true))
    .filter((n) => n['Relation Name'] === 'alerts')
    .map((n) => ({
      index: n['Index Name'] ?? n['Node Type'],
      read: ((n['Actual Rows'] ?? 0) + (n['Rows Removed by Filter'] ?? 0) + (n['Rows Removed by Index Recheck'] ?? 0)) * (n['Actual Loops'] ?? 1),
    }));
}

/**
 * No scan of alerts reads more than `limit` rows, except the primary-key
 * lookups of what the arms found: for a common value (which the planner knows
 * from 043's statistics), each arm stops at its limit instead of reading every
 * alert that names it.
 */
async function assertBounded(label: string, statement: Statement, limit: number, arms: number) {
  for (const { index, read } of await rowsRead(statement)) {
    const bound = index === 'alerts_pkey' ? arms * limit : limit;
    assert.ok(read <= bound, `${label}: ${index} read ${read} rows (at most ${bound})`);
  }
}

const def = (center: string, rel: string) => RELATIONS.find((d) => d.center === center && d.rel === rel)!;
const IP_INDEXES = ['idx_graph_alerts_md_source_ip', 'idx_graph_alerts_md_client_ip', 'idx_graph_alerts_md_dest_ip'];

test('alerts naming an IP (7 d and the 30 d of the Threat Intel entry point): one ordered scan per key and spelling', async (t) => {
  if (!db) return t.skip(SKIP);
  for (const window of ['7d', '30d']) {
    for (const ip of ['198.18.7.3', RARE_IP, HOT.ip, '2001:db8::2']) {
      await assertOrderedArms(`ip:${ip} ${window}`, await captured(def('ip', 'entity_alerts'), entityRef('ip', ip), null, window), IP_INDEXES);
    }
  }
});

test('alerts naming a user, host or domain; a rule, account or endpoint: their own indexes, ordered', async (t) => {
  if (!db) return t.skip(SKIP);
  const cases: Array<[string, EntityRef, string[]]> = [
    ['user', entityRef('user', 'user17'), ['idx_graph_alerts_md_user', 'idx_graph_alerts_md_target_user']],
    ['host', entityRef('host', 'host17'), ['idx_graph_alerts_md_host']],
    ['domain', entityRef('domain', 'd17.example'), ['idx_graph_alerts_md_domain', 'idx_graph_alerts_dm_lookalike']],
    ['account', entityRef('account', '7'), ['idx_graph_alerts_auth_user_id']],
    ['endpoint', entityRef('endpoint', '3f2504e0-4f89-11d3-9a0c-0305e82c3301'), ['idx_graph_alerts_edr_agent_id']],
  ];
  for (const [center, ref, expected] of cases) {
    await assertOrderedArms(center, await captured(def(center, 'entity_alerts'), ref, null, '30d'), expected);
  }
  // A noisy rule (half the seeded alerts): its latest alerts come straight off
  // (rule_id, created_at DESC), with no sort of all of them.
  const [{ id: ruleId }] = (
    await db.query(`INSERT INTO detection_rules (name, severity, rule_yaml, rule_logic) VALUES ($1, 'low', 'x: 1', '{}') RETURNING id`, [`plan-${tag}`])
  ).rows;
  await db.query(`UPDATE alerts SET rule_id = $1 WHERE title = $2 AND id % 2 = 0`, [ruleId, `plan ${tag}`]);
  await db.query('ANALYZE alerts');
  const rule = await captured(def('rule', 'rule_alerts'), entityRef('rule', String(ruleId)), null, '30d');
  await assertOrderedArms('rule', rule, ['idx_graph_alerts_rule_created']);
  await assertBounded('rule', rule, TOTAL_CAP + 1, 1);
});

test("an asset's alerts: asset_id, and its current IP under each key", async (t) => {
  if (!db) return t.skip(SKIP);
  for (const window of ['7d', '30d']) {
    await assertOrderedArms(
      `asset ${window}`,
      await captured(def('asset', 'entity_alerts'), entityRef('asset', '1'), { ip: '198.18.7.3', hostname: 'x' }, window),
      ['idx_graph_alerts_asset_created', ...IP_INDEXES]
    );
  }
});

test("migration 043's statistics: the planner tells a common value from a rare one", async (t) => {
  if (!db) return t.skip(SKIP);
  // Without them it takes every value for 0.5% of alerts, so both estimates were the same.
  const estimate = async (key: AlertKey, value: string) => {
    const { rows } = await db!.query(`EXPLAIN (FORMAT JSON) SELECT 1 FROM alerts a WHERE ${alertKeyEquals(key, '$1')}`, [value]);
    return Number(rows[0]['QUERY PLAN'][0].Plan['Plan Rows']);
  };
  for (const [key, hot, rare] of [
    ['source_ip', HOT.ip, RARE_IP],
    ['user', HOT.user, `nobody-${tag}`],
    ['host', HOT.host, `nohost-${tag}`],
  ] as const) {
    const [common, uncommon] = [await estimate(key, hot), await estimate(key, rare)];
    assert.ok(common >= 20 * uncommon, `${key}: ${common} estimated for the common value, ${uncommon} for the rare one`);
  }
  for (const entry of ALERT_KEY_INDEXES) {
    const { rows } = await db.query(`SELECT null_frac FROM pg_stats_ext_exprs WHERE statistics_name = $1`, [alertKeyStatsName(entry)]);
    assert.ok(rows.length === 1 && rows[0].null_frac !== null, `${alertKeyStatsName(entry)} exists and holds data`);
  }
});

test("a common value's search hint: the same arms, and still capped at 1,000+", async (t) => {
  if (!db) return t.skip(SKIP);
  const { q, statements } = recorder();
  await countAlertsNaming(q, ctxFor(entityRef('ip', HOT.ip), null, '30d'));
  await assertOrderedArms('search hint', statements[0], IP_INDEXES);
  const [{ n }] = (await db.query(statements[0].sql, statements[0].params)).rows;
  assert.equal(Number(n), TOTAL_CAP + 1, '4,500 alerts name it');
});

test("Threat Intel's IP view and Asset-360, as they send them (LIMIT 50 and 100): the same ordered arms", async (t) => {
  if (!db) return t.skip(SKIP);
  for (const ip of [RARE_IP, HOT.ip]) {
    await assertOrderedArms(`threat intel ${ip}`, { sql: IP_ALERTS_SQL, params: [ip] }, IP_INDEXES);
    await assertBounded(`threat intel ${ip}`, { sql: IP_ALERTS_SQL, params: [ip] }, 50, 3);
    await assertOrderedArms(`asset-360 ${ip}`, { sql: ASSET_ALERTS_SQL, params: [1, ip] }, ['idx_graph_alerts_asset_created', 'idx_graph_alerts_md_source_ip']);
    await assertBounded(`asset-360 ${ip}`, { sql: ASSET_ALERTS_SQL, params: [1, ip] }, 100, 2);
  }
  const hot = (await db.query(IP_ALERTS_SQL, [HOT.ip])).rows;
  assert.equal(hot.length, 50);
  const newest = (await db.query(`SELECT max(created_at) AS at FROM alerts WHERE matched_data->>'source_ip' = $1`, [HOT.ip])).rows[0].at;
  assert.equal(hot[0].created_at.getTime(), newest.getTime(), 'the latest first');
  // An asset with no IP: the asset_id arm alone (a NULL $2 must not fail the statement).
  await db.query(ASSET_ALERTS_SQL, [1, null]);
});

test('SIEMBox sign-ins from an IP (admin): idx_graph_audit_logs_ip_time', async (t) => {
  if (!db) return t.skip(SKIP);
  const indexes = await plannedIndexes(await captured(def('ip', 'ip_signins'), entityRef('ip', '198.18.7.3')));
  assert.ok(indexes.includes('idx_graph_audit_logs_ip_time'), indexes.join(', '));
});

test('a key holding most alerts, nearly all older than the window (an EDR host after one scan): its own index, never a walk', async (t) => {
  if (!db) return t.skip(SKIP);
  // 40,000 alerts 45 days ago (62% of alerts) and 5 in the last 5 days, all
  // naming one asset, rule, IP and user: an endpoint scan that matched a YARA
  // rule on many files. ANALYZE sees each key at 62% of alerts, and takes them
  // to be spread evenly over time.
  await db.query('SAVEPOINT noisy');
  try {
    const [{ id: assetId }] = (await db.query(`INSERT INTO assets (ip_address, hostname) VALUES ('198.19.252.5', $1) RETURNING id`, [`noisy-${tag}`])).rows;
    const [{ id: ruleId }] = (
      await db.query(`INSERT INTO detection_rules (name, severity, rule_yaml, rule_logic) VALUES ($1, 'high', 'x: 1', '{}') RETURNING id`, [`noisy-${tag}`])
    ).rows;
    const noisy = { ip: '198.19.252.6', user: `scanned-${tag}` };
    await db.query(
      `INSERT INTO alerts (severity, title, matched_data, status, created_at, source, asset_id, rule_id)
       SELECT 'high', 'plan ' || $1, jsonb_build_object('source_ip', $2::text, 'user', $3::text), 'new',
              CASE WHEN g <= 5 THEN NOW() - make_interval(days => g) + interval '1 hour'
                   ELSE NOW() - interval '45 days' - make_interval(secs => g) END,
              'edr', $4, $5
         FROM generate_series(1, 40005) g`,
      [tag, noisy.ip, noisy.user, assetId, ruleId]
    );
    await db.query('ANALYZE alerts');

    const real: Query = async <T>(sql: string, params: unknown[] = []) => (await db!.query(sql, params)).rows as T[];
    const cases: Array<[string, RelationDef, EntityRef, Record<string, unknown> | null, string]> = [
      ['asset', def('asset', 'entity_alerts'), entityRef('asset', String(assetId)), { ip: '198.19.252.5', hostname: 'x' }, 'idx_graph_alerts_asset_created'],
      ['rule', def('rule', 'rule_alerts'), entityRef('rule', String(ruleId)), null, 'idx_graph_alerts_rule_created'],
      ['ip', def('ip', 'entity_alerts'), entityRef('ip', noisy.ip), null, 'idx_graph_alerts_md_source_ip'],
      ['user', def('user', 'entity_alerts'), entityRef('user', noisy.user), null, 'idx_graph_alerts_md_user'],
    ];
    for (const [label, relation, ref, row, own] of cases) {
      // Never the walk. A window as small as these 7 days (6,000 alerts) the
      // planner may read whole and sort, when that costs less than the ordered
      // scan; it knows the window's size, so that read stays small.
      for (const window of ['7d', '30d']) {
        await assertNoWalk(`${label} ${window}`, await captured(relation, ref, row, window));
        const count = await countAlertsNaming(real, ctxFor(ref, row, window));
        assert.deepEqual(count, { total: 5, capped: false }, `${label} ${window}: the 5 recent alerts`);
      }
      // 30 days (24,500 alerts): its own index, a few rows. (An EDR host like
      // this one timed out its entity_alerts, and /relation answered 503.)
      const month = await captured(relation, ref, row, '30d');
      await assertOrderedArms(`${label} 30d`, month, [own]);
      await assertBounded(`${label} 30d`, month, TOTAL_CAP + 1, 6);
    }
    // Asset-360 has no window: the asset's latest 100, off the same index.
    const asset360 = { sql: ASSET_ALERTS_SQL, params: [assetId, '198.19.252.5'] };
    await assertOrderedArms('asset-360', asset360, ['idx_graph_alerts_asset_created']);
    await assertBounded('asset-360', asset360, 100, 2);
    const latest = (await db.query(asset360.sql, asset360.params)).rows;
    assert.equal(latest.length, 100);
    assert.ok(latest[0].created_at > latest[5].created_at, 'newest first: the 5 recent alerts lead');
  } finally {
    await db.query('ROLLBACK TO SAVEPOINT noisy');
  }
});
