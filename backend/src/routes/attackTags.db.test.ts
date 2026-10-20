/**
 * ATT&CK 1/4 end to end: the real app on an ephemeral port and a real Postgres.
 *
 * - POST/PUT /api/rules refuse a bad attack.* tag with 422 ATTACK_TAG_INVALID
 *   and the validator's message (nothing saved); an edit that keeps a tag the
 *   stored rule already had is not refused;
 * - the Sigma import preview drops unknown/revoked attack tags with a warning;
 * - an alert raised by the rules engine copies the rule's technique IDs;
 * - GET /api/alerts?technique= (with sub-techniques) and ?tactic= filter;
 * - migration 045's backfill runs once (re-running it never rewrites history).
 *
 * Skips itself when Postgres isn't reachable. Every row created here is
 * removed again. Run with `npm test` (tsx --test).
 */
import { test, before, after, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import fs from 'node:fs';
import path from 'node:path';
import { once } from 'node:events';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import app from '../app';
import pool, { closePools } from '../config/database';
import { UserModel } from '../models/User';
import { SessionModel } from '../models/Session';
import { AlertModel } from '../models/Alert';
import { DetectionRuleModel } from '../models/DetectionRule';
import { RulesEngine } from '../services/rules/rulesEngine';
import { closeRegexScanPool } from '../services/regex/regexSafety';
import { closeRegexTestPool } from '../services/regex/boundedRegex';
import type { ParsedLog } from '../models/ParsedLog';

const SKIP = 'Postgres with the SIEMBox schema (migration 045) is not reachable';
const MIGRATION = fs.readFileSync(path.join(__dirname, '../../migrations/045_attack_techniques.sql'), 'utf8');

let dbReady = false;
let server: Server | undefined;
let base = '';
const tag = crypto.randomBytes(6).toString('hex');
const name = `attacktags-${tag}`;
const tokens: Record<'admin' | 'analyst', string> = { admin: '', analyst: '' };
const userIds: number[] = [];

before(async () => {
  try {
    await pool.query('SELECT attack_techniques FROM alerts LIMIT 1');
    await pool.query('SELECT 1 FROM attack_technique_exclusions LIMIT 1');
    dbReady = true;
  } catch {
    return;
  }
  for (const role of ['admin', 'analyst'] as const) {
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
  await Promise.all([closeRegexScanPool(), closeRegexTestPool()]);
  if (dbReady) {
    // alerts go with their rule (ON DELETE CASCADE).
    await pool.query('DELETE FROM detection_rules WHERE name LIKE $1', [`${name}%`]);
    await pool.query('DELETE FROM audit_logs WHERE user_id = ANY($1)', [userIds]);
    await pool.query('DELETE FROM application_errors WHERE user_id = ANY($1)', [userIds]);
    await pool.query('DELETE FROM users WHERE id = ANY($1)', [userIds]);
  }
  await closePools();
});

async function call(role: 'admin' | 'analyst', method: string, url: string, body?: unknown) {
  const headers: Record<string, string> = { Authorization: `Bearer ${tokens[role]}` };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(base + url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  return { status: res.status, json: ((await res.json().catch(() => null)) ?? {}) as Record<string, any> };
}

const RULE_YAML = [
  'conditions:',
  '  - field: event_type',
  '    operator: equals',
  `    value: ${name}`,
  'alert:',
  '  title: attack tag test',
  '  description: attack tag test',
].join('\n');

function ruleBody(suffix: string, tags: string[]) {
  return { name: `${name}-${suffix}`, severity: 'low', enabled: false, rule_yaml: RULE_YAML, tags };
}

async function seedRule(suffix: string, tags: string[], enabled = false): Promise<number> {
  const rule = await DetectionRuleModel.create({
    name: `${name}-${suffix}`,
    severity: 'low',
    enabled,
    rule_yaml: RULE_YAML,
    rule_logic: {
      conditions: [{ field: 'event_type', operator: 'equals', value: `${name}-${suffix}` }],
      alert: { title: `${name} {event_type}`, description: 'attack tag test' },
    },
    tags,
  });
  return rule.id;
}

function skipUnlessDb(t: TestContext): boolean {
  if (dbReady) return false;
  t.skip(SKIP);
  return true;
}

test('POST /api/rules: 422 ATTACK_TAG_INVALID with the validator message; nothing saved', async (t) => {
  if (skipUnlessDb(t)) return;
  for (const [suffix, tags, pattern] of [
    ['malformed', ['attack.t1110.01'], /attack\.t1110\.01: not an ATT&CK technique ID/],
    ['revoked', ['attack.t1086'], /T1086 "PowerShell" was revoked .*use attack\.t1059\.001/],
    ['tactic', ['attack.credentialaccess'], /unknown ATT&CK tactic/],
  ] as const) {
    const r = await call('analyst', 'POST', '/api/rules', ruleBody(suffix, [...tags]));
    assert.equal(r.status, 422, suffix);
    assert.equal(r.json.code, 'ATTACK_TAG_INVALID');
    assert.match(r.json.message, new RegExp(`^Rule "${name}-${suffix}" was not saved: `));
    assert.match(r.json.message, pattern);
    assert.equal(await DetectionRuleModel.findByName(`${name}-${suffix}`), null);
  }

  const ok = await call('analyst', 'POST', '/api/rules', ruleBody('ok', ['attack.t1110.001', 'attack.discovery']));
  assert.equal(ok.status, 201);
  assert.ok(ok.json.warnings.some((w: string) => /attack\.discovery: none of the rule's techniques/.test(w)));
});

test('PUT /api/rules/:id: a new bad tag is refused, a tag the rule already had is not', async (t) => {
  if (skipUnlessDb(t)) return;
  // A rule stored before validation existed, carrying a revoked tag.
  const id = await seedRule('legacy', ['ssh', 'attack.t1086']);

  const keep = await call('analyst', 'PUT', `/api/rules/${id}`, { enabled: false, tags: ['ssh', 'attack.t1086'] });
  assert.equal(keep.status, 200, JSON.stringify(keep.json));

  const add = await call('analyst', 'PUT', `/api/rules/${id}`, { tags: ['ssh', 'attack.t1086', 'attack.t9999'] });
  assert.equal(add.status, 422);
  assert.equal(add.json.code, 'ATTACK_TAG_INVALID');
  assert.match(add.json.message, /T9999 is not a technique/);
  assert.doesNotMatch(add.json.message, /T1086/);
  assert.deepEqual((await DetectionRuleModel.findById(id))!.tags, ['ssh', 'attack.t1086']);

  const fix = await call('analyst', 'PUT', `/api/rules/${id}`, { tags: ['ssh', 'attack.t1059.001'] });
  assert.equal(fix.status, 200);
});

test('Sigma preview drops unknown/revoked attack tags with a warning instead of failing', async (t) => {
  if (skipUnlessDb(t)) return;
  const sigma = [
    `title: ${name}-sigma`,
    'level: medium',
    'tags: [attack.execution, attack.t1086, attack.t1059.001]',
    'detection:',
    '  sel:',
    '    CommandLine|contains: powershell',
    '  condition: sel',
  ].join('\n');
  const r = await call('admin', 'POST', '/api/rules/import/sigma/preview', { sigma });
  assert.equal(r.status, 200);
  const [res] = r.json.results;
  assert.equal(res.ok, true);
  assert.deepEqual(res.rule.tags, ['sigma', 'imported', 'attack.execution', 'attack.t1059.001']);
  assert.ok(res.warnings.some((w: string) => /^Dropped ATT&CK tag attack\.t1086: /.test(w)));
});

test('an alert copies the rule technique IDs; ?technique= and ?tactic= filter the list', async (t) => {
  if (skipUnlessDb(t)) return;
  const ruleId = await seedRule('engine', ['ssh', 'attack.t1110.001', 'attack.T1078', 'attack.credential_access'], true);
  const engine = RulesEngine.getInstance();
  await engine.reload();
  const log = {
    id: null,
    raw_log_id: null,
    parser_id: null,
    parsed_data: { event_type: `${name}-engine` },
    timestamp: new Date(),
    source_ip: '',
    event_type: `${name}-engine`,
    created_at: new Date(),
  } as unknown as ParsedLog;
  await engine.evaluateLog(log);
  await DetectionRuleModel.update(ruleId, { enabled: false });
  await engine.reload();

  const raised = await pool.query('SELECT id, attack_techniques FROM alerts WHERE rule_id = $1', [ruleId]);
  assert.equal(raised.rowCount, 1);
  assert.deepEqual(raised.rows[0].attack_techniques, ['T1078', 'T1110.001']);

  // Two more alerts on another (untagged) rule to filter against.
  const otherRule = await seedRule('other', []);
  const discovery = await AlertModel.create({
    rule_id: otherRule,
    severity: 'low',
    title: `${name} discovery`,
    matched_data: {},
    attack_techniques: ['T1087'],
  });
  const none = await AlertModel.create({ rule_id: otherRule, severity: 'low', title: `${name} none`, matched_data: {} });
  assert.deepEqual(none.attack_techniques, []);

  const ids = async (qs: string) => {
    const r = await call('analyst', 'GET', `/api/alerts?search=${name}&limit=50&${qs}`);
    assert.equal(r.status, 200, JSON.stringify(r.json));
    return r.json.alerts.map((a: { id: number }) => a.id).sort((a: number, b: number) => a - b);
  };
  const engineAlert = raised.rows[0].id;
  assert.deepEqual(await ids('technique=T1110'), [engineAlert]); // parent matches the sub-technique
  assert.deepEqual(await ids('technique=t1110.001'), [engineAlert]);
  assert.deepEqual(await ids('technique=T1110.003'), []);
  assert.deepEqual(await ids('technique=T1087'), [discovery.id]);
  assert.deepEqual(await ids('tactic=credential_access'), [engineAlert]);
  assert.deepEqual(await ids('tactic=discovery'), [discovery.id]);
  assert.deepEqual(await ids('tactic=discovery&technique=T1110'), []);
  assert.deepEqual(await ids('technique=T1087&group=event'), [discovery.id]);

  const grouped = await call('analyst', 'GET', `/api/alerts?search=${name}&group=event&technique=T1078`);
  assert.deepEqual(grouped.json.alerts[0].attack_techniques, ['T1078', 'T1110.001']);

  assert.equal((await call('analyst', 'GET', '/api/alerts?technique=T1110.01')).status, 400);
  assert.equal((await call('analyst', 'GET', '/api/alerts?tactic=lunch')).status, 400);
});

test('migration 045 backfills existing alerts once and never rewrites them', async (t) => {
  if (skipUnlessDb(t)) return;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // As before 045 ran: no guard row; an old alert with no techniques.
    await client.query(`DELETE FROM system_settings WHERE key = 'attack_alert_techniques_backfilled'`);
    const rule = await client.query(
      `INSERT INTO detection_rules (name, severity, rule_yaml, rule_logic, tags)
       VALUES ($1, 'low', 'x', '{}'::jsonb, $2) RETURNING id`,
      [`${name}-backfill`, ['ssh', 'attack.t1110.001', 'ATTACK.T1110.001', 'attack.t1110.01', 'attack.credential_access']]
    );
    const alert = await client.query(
      `INSERT INTO alerts (rule_id, severity, title, matched_data) VALUES ($1, 'low', 'old', '{}') RETURNING id, attack_techniques`,
      [rule.rows[0].id]
    );
    assert.deepEqual(alert.rows[0].attack_techniques, []);
    const techniques = async () =>
      (await client.query('SELECT attack_techniques FROM alerts WHERE id = $1', [alert.rows[0].id])).rows[0].attack_techniques;

    await client.query(MIGRATION);
    assert.deepEqual(await techniques(), ['T1110.001']);

    // Re-tag the rule; later starts re-run the migration and change nothing.
    await client.query('UPDATE detection_rules SET tags = $2 WHERE id = $1', [rule.rows[0].id, ['attack.t1078']]);
    await client.query(MIGRATION);
    await client.query(MIGRATION);
    assert.deepEqual(await techniques(), ['T1110.001']);
    const guard = await client.query(`SELECT count(*)::int AS n FROM system_settings WHERE key = 'attack_alert_techniques_backfilled'`);
    assert.equal(guard.rows[0].n, 1);
  } finally {
    await client.query('ROLLBACK');
    client.release();
  }
});
