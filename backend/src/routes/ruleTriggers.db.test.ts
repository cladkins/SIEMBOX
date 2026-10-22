/**
 * Detection Rules → Triggered: GET /api/rules carries `triggers` per rule
 * (total stored alerts, last 24 h, last 7 days, newest alert time), and a rule
 * that never fired gets zeros. Real app on an ephemeral port, real Postgres.
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
import { AlertModel } from '../models/Alert';
import { DetectionRuleModel } from '../models/DetectionRule';

const SKIP = 'Postgres with the SIEMBox schema is not reachable';

let dbReady = false;
let server: Server | undefined;
let base = '';
const name = `ruletriggers-${crypto.randomBytes(6).toString('hex')}`;
let token = '';
let userId = 0;

before(async () => {
  try {
    await pool.query('SELECT 1 FROM alerts LIMIT 1');
    dbReady = true;
  } catch {
    return;
  }
  // A viewer: the counts are read-only data every role sees on the Rules page.
  const user = await UserModel.create({
    username: `${name}-viewer`,
    email: `${name}-viewer@siembox.invalid`,
    password: crypto.randomBytes(16).toString('hex'),
    role: 'viewer',
  });
  userId = user.id;
  token = (await SessionModel.create(user.id, 1)).token;
  server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  if (dbReady) {
    // alerts go with their rule (ON DELETE CASCADE).
    await pool.query('DELETE FROM detection_rules WHERE name LIKE $1', [`${name}%`]);
    await pool.query('DELETE FROM audit_logs WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM users WHERE id = $1', [userId]);
  }
  await closePools();
});

function skipUnlessDb(t: TestContext): boolean {
  if (dbReady) return false;
  t.skip(SKIP);
  return true;
}

async function seedRule(suffix: string): Promise<number> {
  const rule = await DetectionRuleModel.create({
    name: `${name}-${suffix}`,
    severity: 'low',
    enabled: false,
    rule_yaml: 'conditions: []',
    rule_logic: { conditions: [{ field: 'event_type', operator: 'equals', value: name }], alert: { title: 't', description: 'd' } },
    tags: [],
  });
  return rule.id;
}

test('GET /api/rules: triggers counts per rule, zeros for a rule that never fired', async (t) => {
  if (skipUnlessDb(t)) return;
  const busy = await seedRule('busy');
  const quiet = await seedRule('quiet');

  const created: number[] = [];
  for (let i = 0; i < 4; i++) {
    created.push((await AlertModel.create({ rule_id: busy, severity: 'low', title: `${name} ${i}`, matched_data: {} })).id);
  }
  // Ages: now, now, 3 days ago, 10 days ago.
  await pool.query(`UPDATE alerts SET created_at = NOW() - INTERVAL '3 days' WHERE id = $1`, [created[2]]);
  await pool.query(`UPDATE alerts SET created_at = NOW() - INTERVAL '10 days' WHERE id = $1`, [created[3]]);

  const res = await fetch(`${base}/api/rules`, { headers: { Authorization: `Bearer ${token}` } });
  assert.equal(res.status, 200);
  const rules = (await res.json()) as Array<Record<string, any>>;
  const byId = new Map(rules.map((r) => [r.id, r]));

  const b = byId.get(busy)!.triggers;
  assert.equal(b.total, 4);
  assert.equal(b.last_24h, 2);
  assert.equal(b.last_7d, 3);
  assert.ok(b.last_triggered_at && Date.now() - Date.parse(b.last_triggered_at) < 60_000, 'newest alert is the latest');

  assert.deepEqual(byId.get(quiet)!.triggers, { total: 0, last_24h: 0, last_7d: 0, last_triggered_at: null });
});
