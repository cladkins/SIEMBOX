/**
 * The log relationships through /api/graph against a real Postgres: the real
 * app on an ephemeral port, fixture logs with this run's own IPs, user and
 * host, rolled up with the rollup's own statement over just their ids (so the
 * real cursor and other tests' logs are never touched), deleted in `after`.
 *
 * Covers: /neighborhood shows signed_in_as / seen_on for an IP and
 * signed_in_from for a user, with failures, successes, the NEW and
 * success-after-failures badges, and sources.logs from the rollup's state;
 * /relation searches a log relation; /evidence lists the logs behind an edge
 * (latest day by default, the pair's days for the picker), refuses a pair the
 * relation doesn't join, says expired for a day past retention and partial
 * when the day's query times out. Skips itself without Postgres.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { once } from 'node:events';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import app from '../app';
import pool, { closePools } from '../config/database';
import { UserModel } from '../models/User';
import { SessionModel } from '../models/Session';
import { graphDeps } from '../services/graph/service';
import { getEvidence } from '../services/graph/evidence';
import { entityRef } from '../services/graph/entityKey';
import { readLogEdgeState, UPSERT_SQL } from '../services/graph/logEdgeRollup';
import type { QueryClient } from '../services/shippers/snapshotCache';

const SKIP = 'Postgres with the SIEMBox schema is not reachable';
const tag = crypto.randomBytes(4).toString('hex');
const octet = (i: number) => parseInt(tag.slice(i * 2, i * 2 + 2), 16);
const IP = { actor: `198.18.${octet(0)}.${octet(1)}`, newcomer: `198.19.${octet(0)}.${octet(1)}`, sender: `10.${octet(2)}.${octet(3)}.1` };
const USER = `ev-${tag}`;
const HOST = `evhost-${tag}`;

let ready = false;
let server: Server | undefined;
let base = '';
const tokens: Record<string, string> = {};
const userIds: number[] = [];
const rawIds: number[] = [];
let parserId = 0;
let savedState: Record<string, unknown> | null = null;

async function insertLog(data: Record<string, unknown>, message: string): Promise<number> {
  const raw = await pool.query(
    `INSERT INTO raw_logs (timestamp, raw_message, source_ip, hostname, created_at) VALUES (NOW(), $1, $2, $3, NOW() - interval '1 hour') RETURNING id`,
    [message, IP.sender, HOST]
  );
  rawIds.push(raw.rows[0].id);
  const parsed = await pool.query(
    `INSERT INTO parsed_logs (raw_log_id, parser_id, parsed_data, timestamp, source_ip, event_type, created_at)
     VALUES ($1, $4, $2, NOW(), $3, 'ssh_auth', NOW() - interval '1 hour') RETURNING id`,
    [raw.rows[0].id, JSON.stringify({ observer_ip: IP.sender, ...data, message }), IP.sender, parserId]
  );
  return parsed.rows[0].id;
}

before(async () => {
  try {
    await pool.query('SELECT 1 FROM graph_log_edges_state LIMIT 1');
  } catch {
    return;
  }
  ready = true;
  // The parsed logs need a parser to count as parsed (a disabled one: it never runs).
  parserId = (
    await pool.query(
      `INSERT INTO parsers (name, parser_type, pattern, field_mappings, priority, enabled) VALUES ($1, 'regex', '^$', '{}', 999, false) RETURNING id`,
      [`graph-ev-${tag}`]
    )
  ).rows[0].id;
  for (const role of ['analyst', 'viewer']) {
    const user = await UserModel.create({ username: `graph-ev-${tag}-${role}`, email: `graph-ev-${tag}-${role}@siembox.invalid`, password: crypto.randomBytes(16).toString('hex'), role });
    userIds.push(user.id);
    tokens[role] = (await SessionModel.create(user.id, 1)).token;
  }
  const ids: number[] = [];
  for (let i = 0; i < 3; i++) ids.push(await insertLog({ source_ip: IP.actor, user: USER, auth_outcome: 'failure' }, `Failed password for ${USER} from ${IP.actor}`));
  ids.push(await insertLog({ source_ip: IP.actor, user: USER, auth_outcome: 'success' }, `Accepted password for ${USER} from ${IP.actor}`));
  ids.push(await insertLog({ source_ip: IP.newcomer, user: USER, auth_outcome: 'success' }, `Accepted password for ${USER} from ${IP.newcomer}`));
  // The rollup's own statement, over just these logs.
  const raw = await pool.query(`SELECT min(raw_log_id) AS lo, max(raw_log_id) AS hi FROM parsed_logs WHERE id = ANY($1)`, [ids]);
  await pool.query(UPSERT_SQL, [Math.min(...ids) - 1, Math.max(...ids), raw.rows[0].lo, raw.rows[0].hi, '{}']);
  // The actor signed in as the user 20 days ago too: not NEW. The newcomer is.
  await pool.query(
    `INSERT INTO graph_log_edges (day, rel, a_type, a_value, b_type, b_value, events, failures, successes, first_seen, last_seen)
     VALUES (CURRENT_DATE - 20, 'signed_in_as', 'ip', $1, 'user', $2, 1, 0, 1, NOW() - interval '20 days', NOW() - interval '20 days')`,
    [IP.actor, USER]
  );
  // The rollup covers the last 30 days and is current.
  savedState = (await pool.query(`SELECT covered_from, covered_until, caught_up FROM graph_log_edges_state WHERE id = 1`)).rows[0];
  await pool.query(`UPDATE graph_log_edges_state SET covered_from = CURRENT_DATE - 30, covered_until = NOW(), caught_up = true WHERE id = 1`);

  server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  if (ready) {
    await pool.query(`DELETE FROM graph_log_edges WHERE a_value = ANY($1) OR b_value = ANY($1)`, [[IP.actor, IP.newcomer, IP.sender, USER, HOST]]);
    await pool.query(`DELETE FROM raw_logs WHERE id = ANY($1)`, [rawIds]);
    await pool.query(`DELETE FROM parsers WHERE name = $1`, [`graph-ev-${tag}`]);
    await pool.query(`DELETE FROM users WHERE id = ANY($1)`, [userIds]);
    if (savedState) {
      await pool.query(`UPDATE graph_log_edges_state SET covered_from = $1, covered_until = $2, caught_up = $3 WHERE id = 1`, [
        savedState.covered_from,
        savedState.covered_until,
        savedState.caught_up,
      ]);
    }
  }
  await closePools();
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- the answers' shapes vary per route
type Json = any;
async function get(role: string, pathAndQuery: string): Promise<{ status: number; json: Json }> {
  const res = await fetch(base + pathAndQuery, { headers: { Authorization: `Bearer ${tokens[role]}` } });
  return { status: res.status, json: await res.json().catch(() => null) };
}
const q = encodeURIComponent;
const edge = (json: Json, rel: string, source: string, target: string) => json.edges.find((e: Json) => e.id === `${rel}|${source}|${target}`);
const group = (json: Json, rel: string) => json.groups.find((g: Json) => g.rel === rel);

test('an IP: who it signed in as, with outcomes and badges, and the device', async (t) => {
  if (!ready) return t.skip(SKIP);
  const { status, json } = await get('viewer', `/api/graph/neighborhood?entity=${q(`ip:${IP.actor}`)}&window=7d`);
  assert.equal(status, 200);
  assert.equal(group(json, 'signed_in_as').total, 1);
  const signIn = edge(json, 'signed_in_as', `ip:${IP.actor}`, `user:${USER}`);
  assert.equal(signIn?.style, 'logs');
  assert.equal(signIn.count, 4, 'only the window: the day 20 days ago is out');
  assert.equal(signIn.failures, 3);
  assert.equal(signIn.successes, 1);
  assert.equal(signIn.success_after_failures, true);
  assert.equal(signIn.new, false, 'seen before the window');
  assert.ok(edge(json, 'seen_on', `ip:${IP.actor}`, `host:${HOST}`));
  assert.equal(json.sources.logs.status, 'ok');
  assert.ok(json.sources.logs.covered_from);
});

test('a user: where it signed in from, NEW for a first-time IP', async (t) => {
  if (!ready) return t.skip(SKIP);
  const { json } = await get('analyst', `/api/graph/neighborhood?entity=${q(`user:${USER}`)}&window=7d`);
  assert.equal(group(json, 'signed_in_from').total, 2);
  assert.equal(edge(json, 'signed_in_as', `ip:${IP.newcomer}`, `user:${USER}`)?.new, true);
  assert.equal(edge(json, 'signed_in_as', `ip:${IP.actor}`, `user:${USER}`)?.new, false);
  assert.ok(edge(json, 'user_on', `user:${USER}`, `host:${HOST}`));

  const rel = await get('analyst', `/api/graph/relation?entity=${q(`user:${USER}`)}&rel=signed_in_from&q=${q(IP.newcomer)}`);
  assert.equal(rel.status, 200);
  assert.deepEqual(rel.json.items.map((i: Json) => i.node.id), [`ip:${IP.newcomer}`]);
});

test('evidence: the logs behind an edge, the pair\'s days, and refusals', async (t) => {
  if (!ready) return t.skip(SKIP);
  const path = `/api/graph/evidence?rel=signed_in_as&a=${q(`ip:${IP.actor}`)}&b=${q(`user:${USER}`)}`;
  const { status, json } = await get('viewer', path);
  assert.equal(status, 200);
  assert.equal(json.days.length, 2, 'today and 20 days ago');
  assert.equal(json.day, json.days[0]);
  assert.equal(json.logs.length, 4);
  assert.ok(json.logs.every((l: Json) => l.message.includes(USER) && l.sender_ip === IP.sender && l.hostname === HOST));
  assert.equal(json.partial, false);
  assert.equal(json.expired, false);

  assert.equal((await get('viewer', `${path}&limit=2`)).json.logs.length, 2);
  assert.equal((await get('viewer', `/api/graph/evidence?rel=signed_in_as&a=${q(`user:${USER}`)}&b=${q(`ip:${IP.actor}`)}`)).status, 400, 'a pair the relation does not join');
  assert.equal((await get('viewer', `/api/graph/evidence?rel=alert_ips&a=${q(`ip:${IP.actor}`)}&b=${q(`user:${USER}`)}`)).status, 400);
  assert.equal((await get('viewer', `${path}&day=2026-02-30`)).status, 400);

  const retention = (await readLogEdgeState(async (sql, params) => (await pool.query(sql, params)).rows)).retentionDays;
  if (retention > 0) {
    const old = await get('viewer', `${path}&day=2001-01-01`);
    assert.equal(old.json.expired, true);
    assert.deepEqual(old.json.logs, []);
  }
});

test('evidence: a day too busy to list in time is partial', async (t) => {
  if (!ready) return t.skip(SKIP);
  const acquire = async (): Promise<QueryClient> => {
    const client = await pool.connect();
    return {
      query: async (sql: string, params?: unknown[]) => {
        if (sql.includes('FROM parsed_logs pl')) throw Object.assign(new Error('canceling statement due to statement timeout'), { code: '57014' });
        return client.query(sql, params as unknown[]);
      },
      release: (err?: Error | boolean) => client.release(err),
    };
  };
  const out = await getEvidence({ ...graphDeps, acquire }, { id: userIds[0], role: 'viewer' }, {
    rel: 'signed_in_as',
    a: entityRef('ip', IP.actor),
    b: entityRef('user', USER),
    limit: 20,
  });
  assert.equal(out.partial, true);
  assert.deepEqual(out.logs, []);
  assert.equal(out.days.length, 2);
});
