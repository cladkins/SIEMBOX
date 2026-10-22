/**
 * ALR-#### alert references end to end: the real app on an ephemeral port and
 * a real Postgres.
 *
 * - every alert response (list, grouped list and its correlated members,
 *   detail, update, JSON and CSV export) carries `ref`;
 * - GET /api/alerts/:id takes the numeric id or the reference, and a
 *   malformed one is a 404;
 * - ?search=ALR-#### finds exactly that alert;
 * - the AI Analyst's alert tools take a reference and return `ref`.
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
import { findToolForRole } from '../services/ai/analystTools';
import { closeRegexScanPool } from '../services/regex/regexSafety';
import { closeRegexTestPool } from '../services/regex/boundedRegex';

const SKIP = 'Postgres with the SIEMBox schema is not reachable';

let dbReady = false;
let server: Server | undefined;
let base = '';
const tag = crypto.randomBytes(6).toString('hex');
const name = `alertrefs-${tag}`;
const userIds: number[] = [];
let token = '';
/** The seeded alerts' ids. They share a source IP, so each is "related" to the other. */
const ids: number[] = [];

before(async () => {
  try {
    await pool.query('SELECT 1 FROM alerts LIMIT 1');
    dbReady = true;
  } catch {
    return;
  }
  const user = await UserModel.create({
    username: `${name}-analyst`,
    email: `${name}@siembox.invalid`,
    password: crypto.randomBytes(16).toString('hex'),
    role: 'analyst',
  });
  userIds.push(user.id);
  token = (await SessionModel.create(user.id, 1)).token;

  for (const [severity, suffix] of [['high', 'one'], ['low', 'two']] as const) {
    const r = await pool.query(
      `INSERT INTO alerts (rule_id, parsed_log_id, severity, title, description, matched_data, status, source)
       VALUES (NULL, NULL, $1, $2, 'seeded by alertRefs.db.test', '{"source_ip":"198.51.100.7"}', 'new', 'test')
       RETURNING id`,
      [severity, `${name} ${suffix}`]
    );
    ids.push(r.rows[0].id);
  }

  server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  await Promise.all([closeRegexScanPool(), closeRegexTestPool()]);
  if (dbReady) {
    await pool.query('DELETE FROM alerts WHERE title LIKE $1', [`${name}%`]);
    await pool.query('DELETE FROM audit_logs WHERE user_id = ANY($1)', [userIds]);
    await pool.query('DELETE FROM application_errors WHERE user_id = ANY($1)', [userIds]);
    await pool.query('DELETE FROM users WHERE id = ANY($1)', [userIds]);
  }
  await closePools();
});

function ready(t: TestContext): boolean {
  if (!dbReady) t.skip(SKIP);
  return dbReady;
}

async function call(method: string, url: string, body?: unknown) {
  const headers: Record<string, string> = { Authorization: `Bearer ${token}` };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(base + url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text();
  let json: any = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* CSV */
  }
  return { status: res.status, json, text };
}

test('the list, grouped list and correlated members carry ref', async (t) => {
  if (!ready(t)) return;
  const flat = await call('GET', `/api/alerts?search=${encodeURIComponent(name)}`);
  assert.equal(flat.status, 200);
  assert.equal(flat.json.alerts.length, 2);
  for (const a of flat.json.alerts) assert.equal(a.ref, `ALR-${a.id}`);

  const grouped = await call('GET', `/api/alerts?group=event&search=${encodeURIComponent(name)}`);
  assert.equal(grouped.status, 200);
  for (const a of grouped.json.alerts) {
    assert.equal(a.ref, `ALR-${a.id}`);
    for (const c of a.correlated) assert.equal(c.ref, `ALR-${c.id}`);
  }
});

test('GET /api/alerts/:id takes the id or its reference', async (t) => {
  if (!ready(t)) return;
  const id = ids[0];
  for (const form of [String(id), `ALR-${id}`, `alr-${id}`, encodeURIComponent(`#${id}`)]) {
    const r = await call('GET', `/api/alerts/${form}`);
    assert.equal(r.status, 200, form);
    assert.equal(r.json.id, id, form);
    assert.equal(r.json.ref, `ALR-${id}`, form);
  }
});

test('a malformed reference is a 404, never a 500', async (t) => {
  if (!ready(t)) return;
  for (const form of ['ALR-0', 'ALR-abc', 'abc', 'ALR-99999999999', '0', `ALR-${ids[0]}x`, '-1']) {
    const r = await call('GET', `/api/alerts/${encodeURIComponent(form)}`);
    assert.equal(r.status, 404, form);
  }
  const triage = await call('GET', '/api/alerts/ALR-abc/triage');
  assert.equal(triage.status, 404);
});

test('PUT /api/alerts/:id takes a reference and returns ref', async (t) => {
  if (!ready(t)) return;
  const r = await call('PUT', `/api/alerts/ALR-${ids[1]}`, { status: 'investigating' });
  assert.equal(r.status, 200);
  assert.equal(r.json.id, ids[1]);
  assert.equal(r.json.ref, `ALR-${ids[1]}`);
  assert.equal(r.json.status, 'investigating');
});

test('?search=ALR-#### finds exactly that alert', async (t) => {
  if (!ready(t)) return;
  for (const q of [`ALR-${ids[1]}`, `alr-${ids[1]}`, `#${ids[1]}`]) {
    const r = await call('GET', `/api/alerts?search=${encodeURIComponent(q)}`);
    assert.equal(r.status, 200, q);
    assert.deepEqual(r.json.alerts.map((a: any) => a.id), [ids[1]], q);
    assert.equal(r.json.total, 1, q);
  }
  // A bare number still searches text (IPs, ports) but includes that alert.
  const bare = await call('GET', `/api/alerts?search=${ids[1]}&limit=500`);
  assert.ok(bare.json.alerts.some((a: any) => a.id === ids[1]));
});

test('exports carry ref', async (t) => {
  if (!ready(t)) return;
  const json = await call('GET', `/api/alerts/export?format=json&search=${encodeURIComponent(name)}`);
  assert.equal(json.status, 200);
  assert.deepEqual(json.json.map((a: any) => a.ref).sort(), ids.map((id) => `ALR-${id}`).sort());

  const csv = await call('GET', `/api/alerts/export?format=csv&search=ALR-${ids[0]}`);
  assert.equal(csv.status, 200);
  const [header, row] = csv.text.split('\r\n');
  assert.equal(header.split(',')[0], 'ref');
  assert.equal(row.split(',')[0], `ALR-${ids[0]}`);
});

test('the AI Analyst alert tools take a reference and return ref', async (t) => {
  if (!ready(t)) return;
  const ctx = { userRole: 'analyst' as const };
  const getAlert = findToolForRole('get_alert', 'analyst')!;
  const one = await getAlert.run({ id: `ALR-${ids[0]}` }, ctx);
  assert.equal(one.id, ids[0]);
  assert.equal(one.ref, `ALR-${ids[0]}`);
  assert.equal((await getAlert.run({ id: ids[0] }, ctx)).ref, `ALR-${ids[0]}`);
  assert.match((await getAlert.run({ id: 'ALR-abc' }, ctx)).error, /required/);

  // Both seeded alerts share a source IP, so each is related to the other.
  const related = await findToolForRole('get_related_alerts', 'analyst')!.run({ alertId: `ALR-${ids[0]}` }, ctx);
  const other = related.related.find((r: any) => r.id === ids[1]);
  assert.ok(other, 'the sibling alert is related');
  assert.equal(other.ref, `ALR-${ids[1]}`);

  const history = await findToolForRole('get_alert_history_stats', 'analyst')!.run({ alertId: `alr-${ids[0]}` }, ctx);
  assert.equal(history.ref, `ALR-${ids[0]}`);

  const list = await findToolForRole('list_alerts', 'analyst')!.run({ limit: 25 }, ctx);
  for (const a of list.alerts) assert.equal(a.ref, `ALR-${a.id}`);
});
