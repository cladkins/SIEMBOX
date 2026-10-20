/**
 * Sigma OR / NOT end to end: the real app on an ephemeral port, a real Postgres
 * and the real rules engine.
 *
 * - POST /api/rules/import/sigma turns `1 of selection_*` into one stored rule
 *   per alternative, and only the alternative a log satisfies raises an alert;
 * - `selection and not filter` is stored with `exclude` in rule_logic, the
 *   engine skips a log the filter matches, and a log WITHOUT the filter's field
 *   still alerts (Sigma semantics);
 * - the portable YAML (GET /api/rules/:id/contribute) carries `exclude` and
 *   still validates, so the rule round-trips to the catalog.
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
import { RulesEngine } from '../services/rules/rulesEngine';
import { closeRegexScanPool } from '../services/regex/regexSafety';
import { closeRegexTestPool } from '../services/regex/boundedRegex';
import type { ParsedLog } from '../models/ParsedLog';

const SKIP = 'Postgres with the SIEMBox schema is not reachable';

let dbReady = false;
let server: Server | undefined;
let base = '';
const tag = crypto.randomBytes(6).toString('hex');
const name = `sigmaornot-${tag}`;
let token = '';
let userId = 0;

before(async () => {
  try {
    await pool.query('SELECT 1 FROM detection_rules LIMIT 1');
    dbReady = true;
  } catch {
    return;
  }
  const user = await UserModel.create({
    username: `${name}-admin`,
    email: `${name}-admin@siembox.invalid`,
    password: crypto.randomBytes(16).toString('hex'),
    role: 'admin',
  });
  userId = user.id;
  token = (await SessionModel.create(user.id, 1)).token;
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
    await pool.query('DELETE FROM audit_logs WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM application_errors WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM users WHERE id = $1', [userId]);
  }
  await closePools();
});

function skipUnlessDb(t: TestContext): boolean {
  if (dbReady) return false;
  t.skip(SKIP);
  return true;
}

async function call(method: string, url: string, body?: unknown) {
  const headers: Record<string, string> = { Authorization: `Bearer ${token}` };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(base + url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  return { status: res.status, json: ((await res.json().catch(() => null)) ?? {}) as Record<string, any> };
}

function log(data: Record<string, any>): ParsedLog {
  return {
    id: null,
    raw_log_id: null,
    parser_id: null,
    parsed_data: data,
    timestamp: new Date(),
    source_ip: '',
    event_type: String(data.event_type ?? ''),
    created_at: new Date(),
  } as unknown as ParsedLog;
}

/** Enable the given rules, feed the logs through the engine, disable them again. */
async function runEngine(ruleIds: number[], logs: ParsedLog[]): Promise<void> {
  for (const id of ruleIds) await DetectionRuleModel.update(id, { enabled: true });
  const engine = RulesEngine.getInstance();
  await engine.reload();
  for (const l of logs) await engine.evaluateLog(l);
  for (const id of ruleIds) await DetectionRuleModel.update(id, { enabled: false });
  await engine.reload();
}

async function alertCount(ruleId: number): Promise<number> {
  return (await pool.query('SELECT 1 FROM alerts WHERE rule_id = $1', [ruleId])).rowCount ?? 0;
}

test('"1 of selection_*" imports one rule per alternative; only the matching one alerts', async (t) => {
  if (skipUnlessDb(t)) return;
  const sigma = [
    `title: ${name} split`,
    'level: high',
    'detection:',
    '  selection_a:',
    `    event_type: ${name}-a`,
    '  selection_b:',
    `    event_type: ${name}-b`,
    '  condition: 1 of selection_*',
  ].join('\n');
  const r = await call('POST', '/api/rules/import/sigma', { sigma });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.created, 2, JSON.stringify(r.json));
  const a = await DetectionRuleModel.findByName(`${name} split (part 1 of 2)`);
  const b = await DetectionRuleModel.findByName(`${name} split (part 2 of 2)`);
  assert.ok(a && b);
  assert.equal(a.enabled, false); // imported for review

  await runEngine([a.id, b.id], [log({ event_type: `${name}-b` })]);
  assert.equal(await alertCount(a.id), 0);
  assert.equal(await alertCount(b.id), 1);
});

test('"selection and not filter" is stored as exclude; the engine honours it like Sigma', async (t) => {
  if (skipUnlessDb(t)) return;
  const sigma = [
    `title: ${name} filtered`,
    'level: medium',
    'detection:',
    '  selection:',
    `    event_type: ${name}-sudo`,
    '  filter_admins:',
    '    user:',
    '      - alice',
    '      - bob',
    '  condition: selection and not filter_admins',
  ].join('\n');
  const r = await call('POST', '/api/rules/import/sigma', { sigma });
  assert.equal(r.json.created, 1, JSON.stringify(r.json));
  const rule = await DetectionRuleModel.findByName(`${name} filtered`);
  assert.ok(rule);
  assert.deepEqual(rule.rule_logic.exclude, [[{ field: 'user', operator: 'in', value: ['alice', 'bob'] }]]);

  // Excluded first (an alert here would show the exclusion is ignored), then a
  // log WITHOUT the filter's field, which Sigma does not filter out.
  await runEngine([rule.id], [log({ event_type: `${name}-sudo`, user: 'alice' })]);
  assert.equal(await alertCount(rule.id), 0, 'a log the filter matches must not alert');
  await runEngine([rule.id], [log({ event_type: `${name}-sudo` })]);
  assert.equal(await alertCount(rule.id), 1, 'a log without the filter field must alert');

  // The portable YAML (Contribute) keeps the exclusion and still validates, so
  // the rule round-trips to the catalog.
  const exported = await call('GET', `/api/rules/${rule.id}/contribute`);
  assert.equal(exported.status, 200, JSON.stringify(exported.json));
  assert.match(exported.json.content, /exclude:/);
  assert.equal(exported.json.valid, true, JSON.stringify(exported.json.errors));
});
