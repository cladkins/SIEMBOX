/**
 * ATT&CK 2/4 end to end: the real app on an ephemeral port and a real Postgres.
 *
 * - GET /api/attack/coverage: one technique per level (disabled / no_data /
 *   covered / proven) from real rules, parsed-log samples and alerts, with each
 *   rule's reason; the platform scope inferred from the parsers in use, and
 *   ?platforms= overriding it (unknown names 400);
 * - the cache: a repeat is served cached, a viewer's ?refresh=1 is ignored, an
 *   analyst's recomputes, and a rule write or an exclusion change invalidates;
 * - PUT/DELETE /api/attack/exclusions/:techniqueId: analyst+ (a viewer 403),
 *   400 for unknown, malformed and revoked IDs, excluded techniques leave the
 *   percentages;
 * - GET /api/attack/matrix and /navigator-layer shapes.
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
import app from '../app';
import pool, { closePools } from '../config/database';
import { UserModel } from '../models/User';
import { SessionModel } from '../models/Session';
import { DetectionRuleModel } from '../models/DetectionRule';
import { closeRegexScanPool } from '../services/regex/regexSafety';
import { closeRegexTestPool } from '../services/regex/boundedRegex';
import { attackDataset } from '../services/attack/attackData';

const SKIP = 'Postgres with the SIEMBox schema (migration 045) is not reachable';

type Role = 'admin' | 'analyst' | 'viewer';
let dbReady = false;
let server: Server | undefined;
let base = '';
const tag = crypto.randomBytes(6).toString('hex');
const name = `attackcov-${tag}`;
const parserName = `${name}-sshd-auth`;
const tokens: Record<Role, string> = { admin: '', analyst: '', viewer: '' };
const userIds: number[] = [];
let parserId = 0;
const ruleIds: Record<'covered' | 'nodata' | 'disabled' | 'proven', number> = { covered: 0, nodata: 0, disabled: 0, proven: 0 };

async function seedRule(suffix: string, tags: string[], enabled: boolean, conditions: unknown[]): Promise<number> {
  const rule = await DetectionRuleModel.create({
    name: `${name}-${suffix}`,
    severity: 'low',
    enabled,
    rule_yaml: `# ${name}`,
    rule_logic: { conditions, alert: { title: `${name}`, description: 'attack coverage test' } },
    tags,
  });
  return rule.id;
}

before(async () => {
  try {
    await pool.query('SELECT attack_techniques FROM alerts LIMIT 1');
    await pool.query('SELECT 1 FROM attack_technique_exclusions LIMIT 1');
    dbReady = true;
  } catch {
    return;
  }
  for (const role of ['admin', 'analyst', 'viewer'] as const) {
    const user = await UserModel.create({
      username: `${name}-${role}`,
      email: `${name}-${role}@siembox.invalid`,
      password: crypto.randomBytes(16).toString('hex'),
      role,
    });
    userIds.push(user.id);
    tokens[role] = (await SessionModel.create(user.id, 1)).token;
  }

  // A parser in use (logs in the last 7 days): its name implies Linux.
  const parser = await pool.query(
    `INSERT INTO parsers (name, enabled, priority, parser_type, pattern, field_mappings, event_type)
     VALUES ($1, false, 999, 'regex', '^x$', '{}', $2) RETURNING id`,
    [parserName, `${name}_event`]
  );
  parserId = parser.rows[0].id;
  await pool.query(
    `INSERT INTO parser_match_hourly (hour, parser_id, matches) VALUES (date_trunc('hour', NOW()), $1, 40)
     ON CONFLICT (hour, parser_id) DO UPDATE SET matches = EXCLUDED.matches`,
    [parserId]
  );
  for (const data of [
    { [`${tag}_command`]: '/usr/bin/sudo -i', user: 'alice' },
    { [`${tag}_command`]: '/usr/bin/apt update', user: 'bob' },
  ]) {
    await pool.query(
      `INSERT INTO parsed_logs (parser_id, parsed_data, timestamp, source_ip, event_type, created_at)
       VALUES ($1, $2, NOW(), '10.0.0.1', $3, NOW())`,
      [parserId, JSON.stringify(data), `${name}_event`]
    );
  }

  ruleIds.covered = await seedRule('covered', ['attack.t1548.003'], true, [
    { field: `${tag}_command`, operator: 'contains', value: 'sudo -i' },
  ]);
  ruleIds.nodata = await seedRule('nodata', ['attack.t1505.003'], true, [
    { field: `${tag}_missing`, operator: 'equals', value: 'x' },
  ]);
  ruleIds.disabled = await seedRule('disabled', ['attack.t1046'], false, [
    { field: `${tag}_command`, operator: 'exists' },
  ]);
  ruleIds.proven = await seedRule('proven', ['attack.t1021.004'], true, [
    { field: `${tag}_never`, operator: 'equals', value: 'y' },
  ]);
  await pool.query(
    `INSERT INTO alerts (rule_id, severity, title, matched_data, attack_techniques, created_at)
     VALUES ($1, 'low', $2, '{}', ARRAY['T1021.004'], NOW() - INTERVAL '2 days')`,
    [ruleIds.proven, name]
  );

  server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  await Promise.all([closeRegexScanPool(), closeRegexTestPool()]);
  if (dbReady) {
    // alerts go with their rule (ON DELETE CASCADE).
    await pool.query('DELETE FROM detection_rules WHERE name LIKE $1', [`${name}%`]);
    await pool.query(`DELETE FROM attack_technique_exclusions WHERE created_by = ANY($1)`, [userIds]);
    if (parserId) {
      await pool.query('DELETE FROM parsed_logs WHERE parser_id = $1', [parserId]);
      await pool.query('DELETE FROM parser_match_hourly WHERE parser_id = $1', [parserId]);
      await pool.query('DELETE FROM parsers WHERE id = $1', [parserId]);
    }
    await pool.query('DELETE FROM audit_logs WHERE user_id = ANY($1)', [userIds]);
    await pool.query('DELETE FROM application_errors WHERE user_id = ANY($1)', [userIds]);
    await pool.query('DELETE FROM users WHERE id = ANY($1)', [userIds]);
  }
  await closePools();
});

async function call(role: Role, method: string, url: string, body?: unknown) {
  const headers: Record<string, string> = { Authorization: `Bearer ${tokens[role]}` };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(base + url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  return {
    status: res.status,
    headers: res.headers,
    json: ((await res.json().catch(() => null)) ?? {}) as Record<string, any>,
  };
}

function skipUnlessDb(t: TestContext): boolean {
  if (dbReady) return false;
  t.skip(SKIP);
  return true;
}

function technique(body: Record<string, any>, id: string): Record<string, any> {
  const t = body.techniques.find((x: any) => x.id === id);
  assert.ok(t, `${id} is in the coverage`);
  return t;
}

function myRule(t: Record<string, any>, id: number): Record<string, any> {
  const r = t.rules.find((x: any) => x.id === id);
  assert.ok(r, `rule ${id} is listed under ${t.id}`);
  return r;
}

test('coverage: one technique per level, each rule with its reason', async (t) => {
  if (skipUnlessDb(t)) return;
  const r = await call('viewer', 'GET', '/api/attack/coverage?platforms=Linux&refresh=1');
  assert.equal(r.status, 200);
  const body = r.json;
  assert.equal(body.attack_version, attackDataset().version);
  assert.deepEqual(body.scope.platforms, ['Linux']);
  assert.equal(body.scope.source, 'query');

  const covered = technique(body, 'T1548.003');
  assert.equal(covered.level, 'covered');
  assert.match(myRule(covered, ruleIds.covered).reason, new RegExp(`from ${parserName} satisfies its conditions`));
  // ...and rolls up into its parent.
  const parent = technique(body, 'T1548');
  assert.equal(parent.level, 'covered');
  assert.ok(parent.subtechniques.covered >= 1);

  const noData = technique(body, 'T1505.003');
  assert.equal(myRule(noData, ruleIds.nodata).level, 'no_data');
  assert.match(myRule(noData, ruleIds.nodata).reason, new RegExp(`has the field \`${tag}_missing\``));

  const disabled = technique(body, 'T1046');
  assert.equal(myRule(disabled, ruleIds.disabled).level, 'disabled');

  const proven = technique(body, 'T1021.004');
  assert.equal(proven.level, 'proven');
  assert.equal(proven.proven_by, 'alert');
  assert.ok(proven.alerts_30d >= 1);
  assert.match(myRule(proven, ruleIds.proven).reason, /Raised 1 alert in the last 30 days/);

  assert.ok(body.summary.counted > 0);
  assert.equal(body.tactics.length, attackDataset().tactics.length);
  assert.ok(body.sample.logs >= 2);
});

test('coverage cache: repeat cached, a viewer refresh ignored, an analyst refresh recomputes', async (t) => {
  if (skipUnlessDb(t)) return;
  const url = '/api/attack/coverage?platforms=Linux';
  await call('analyst', 'GET', `${url}&refresh=1`);
  const again = await call('viewer', 'GET', url);
  assert.equal(again.json.cached, true);
  const viewerRefresh = await call('viewer', 'GET', `${url}&refresh=1`);
  assert.equal(viewerRefresh.status, 200);
  assert.equal(viewerRefresh.json.cached, true, "a viewer's ?refresh=1 gets the cache");
  assert.equal(viewerRefresh.json.computed_at, again.json.computed_at);
  const analystRefresh = await call('analyst', 'GET', `${url}&refresh=1`);
  assert.equal(analystRefresh.json.cached, false);
});

test('coverage cache: a rule enable/disable invalidates it', async (t) => {
  if (skipUnlessDb(t)) return;
  const url = '/api/attack/coverage?platforms=Linux';
  await call('viewer', 'GET', url);
  assert.equal((await call('viewer', 'GET', url)).json.cached, true);

  const off = await call('analyst', 'PUT', `/api/rules/${ruleIds.covered}`, { enabled: false });
  assert.equal(off.status, 200, JSON.stringify(off.json));
  const after = await call('viewer', 'GET', url);
  assert.equal(after.json.cached, false);
  assert.equal(myRule(technique(after.json, 'T1548.003'), ruleIds.covered).level, 'disabled');

  const on = await call('analyst', 'PUT', `/api/rules/${ruleIds.covered}`, { enabled: true });
  assert.equal(on.status, 200);
  const back = await call('viewer', 'GET', url);
  assert.equal(back.json.cached, false);
  assert.equal(myRule(technique(back.json, 'T1548.003'), ruleIds.covered).level, 'covered');
});

test('exclusions: analyst+ only, 400 for unknown IDs, excluded leaves the percentages, invalidates', async (t) => {
  if (skipUnlessDb(t)) return;
  const url = '/api/attack/coverage?platforms=Linux';
  const before = (await call('viewer', 'GET', url)).json;
  assert.equal(technique(before, 'T1505').excluded, false);

  const viewer = await call('viewer', 'PUT', '/api/attack/exclusions/T1505', { note: 'nope' });
  assert.equal(viewer.status, 403);
  assert.equal((await call('viewer', 'DELETE', '/api/attack/exclusions/T1505')).status, 403);

  for (const bad of ['T9999', 't1110.01', 'T1086', 'credential_access']) {
    const r = await call('analyst', 'PUT', `/api/attack/exclusions/${bad}`, { note: 'x' });
    assert.equal(r.status, 400, bad);
    assert.equal(r.json.code, 'ATTACK_UNKNOWN_TECHNIQUE', bad);
  }
  assert.equal((await call('analyst', 'PUT', '/api/attack/exclusions/T1505', { note: 42 })).status, 400);

  const put = await call('analyst', 'PUT', '/api/attack/exclusions/t1505', { note: '  no web servers  ' });
  assert.equal(put.status, 200, JSON.stringify(put.json));
  assert.equal(put.json.technique_id, 'T1505');
  assert.equal(put.json.note, 'no web servers');

  const excluded = await call('viewer', 'GET', url);
  assert.equal(excluded.json.cached, false, 'an exclusion change invalidates the cache');
  const ssc = technique(excluded.json, 'T1505');
  assert.equal(ssc.excluded, true);
  assert.equal(ssc.exclusion.note, 'no web servers');
  assert.equal(ssc.exclusion.created_by, `${name}-analyst`);
  assert.equal(technique(excluded.json, 'T1505.003').exclusion.inherited_from, 'T1505');
  assert.equal(excluded.json.summary.excluded, before.summary.excluded + 1);
  assert.equal(excluded.json.summary.counted, before.summary.counted - 1);
  assert.equal(excluded.json.summary.in_scope, before.summary.in_scope);

  const del = await call('analyst', 'DELETE', '/api/attack/exclusions/T1505');
  assert.equal(del.status, 200);
  assert.equal((await call('analyst', 'DELETE', '/api/attack/exclusions/T1505')).status, 404);
  assert.equal(technique((await call('viewer', 'GET', url)).json, 'T1505').excluded, false);
});

test('platform scope: inferred from the parsers in use, overridden by ?platforms=', async (t) => {
  if (skipUnlessDb(t)) return;
  const inferred = await call('viewer', 'GET', '/api/attack/coverage?refresh=1');
  assert.equal(inferred.status, 200);
  assert.equal(inferred.json.scope.source, 'inferred');
  assert.ok(inferred.json.scope.platforms.includes('Linux'));
  const fromParsers = inferred.json.scope.inferred.inferred_from.find(
    (e: any) => e.platform === 'Linux' && e.source === 'parsers'
  );
  assert.ok(fromParsers && fromParsers.items.includes(parserName), JSON.stringify(inferred.json.scope));
  assert.deepEqual(inferred.json.platforms, inferred.json.scope.platforms);

  const windows = await call('viewer', 'GET', '/api/attack/coverage?platforms=windows');
  assert.deepEqual(windows.json.scope.platforms, ['Windows']);
  assert.equal(windows.json.techniques.some((x: any) => x.id === 'T1548.003'), false, 'Sudo is not a Windows technique');
  assert.ok(windows.json.techniques.some((x: any) => x.id === 'T1547.001'));

  const bad = await call('viewer', 'GET', '/api/attack/coverage?platforms=Linux,Amiga');
  assert.equal(bad.status, 400);
  assert.equal(bad.json.code, 'ATTACK_BAD_PLATFORM');
});

test('matrix: tactics in order, in-scope techniques, dataset version', async (t) => {
  if (skipUnlessDb(t)) return;
  const r = await call('viewer', 'GET', '/api/attack/matrix?platforms=Linux');
  assert.equal(r.status, 200);
  assert.equal(r.json.attack_version, attackDataset().version);
  assert.deepEqual(
    r.json.tactics.map((x: any) => x.id),
    [...attackDataset().tactics].sort((a, b) => a.order - b.order).map((x) => x.id)
  );
  const ids = r.json.tactics.flatMap((x: any) => x.techniques.map((y: any) => y.id));
  assert.ok(ids.includes('T1548'));
  const inferred = await call('viewer', 'GET', '/api/attack/matrix');
  assert.equal(inferred.json.scope.source, 'inferred');
});

test('navigator layer: 4.5 enterprise layer with rule names, served as a download', async (t) => {
  if (skipUnlessDb(t)) return;
  const r = await call('viewer', 'GET', '/api/attack/navigator-layer?platforms=Linux');
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-disposition') || '', /attachment; filename="siembox-attack-coverage\.json"/);
  assert.equal(r.json.domain, 'enterprise-attack');
  assert.equal(r.json.versions.layer, '4.5');
  assert.equal(r.json.versions.attack, attackDataset().version.split('.')[0]);
  const entry = r.json.techniques.find((x: any) => x.techniqueID === 'T1021.004');
  assert.ok(entry);
  assert.equal(entry.score, 4);
  assert.match(entry.comment, new RegExp(`${name}-proven \\(proven\\)`));
});
