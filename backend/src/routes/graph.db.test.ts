/**
 * /api/graph against a real Postgres: the real app on an ephemeral port, one
 * user and session per role (plus one that must change its password), and
 * fixtures tagged with a random id (unique IPs, hosts and users) in the real
 * tables, deleted again in `after`, so other DB tests running at the same time
 * neither see nor disturb them.
 *
 * Covers: every centre type; caps (the 6th neighbour is in the group's exact
 * total; "1,000+"); window edges and `around`; sender versus actor IPs; the
 * device and shipper (or ghost tag) a log came from; per-role answers (a
 * viewer gets no endpoint, account-detail or sign-in nodes) and that an
 * admin's cached answer never reaches a viewer; unknown entity -> 200
 * exists:false; bad input -> 400, never 401; a restricted session -> 403
 * PASSWORD_CHANGE_REQUIRED; a forced timeout (a test-only resolver running
 * pg_sleep) -> 200 with that source partial; an exhausted semaphore -> 503
 * GRAPH_BUSY with Retry-After; and migration 043 re-run on the populated
 * database changes nothing. Skips itself without Postgres. Run with `npm test`.
 */
import { test, before, after } from 'node:test';
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
import { graphDeps } from '../services/graph/service';
import { graphCache, graphSemaphore } from '../services/graph/limits';
import { RELATIONS } from '../services/graph/relations';
import type { RelationDef } from '../services/graph/resolvers/common';
import type { GraphEdge, GraphNode, NeighborhoodResponse } from '../services/graph/types';

const ROLES = ['admin', 'operator', 'analyst', 'viewer'] as const;
type Role = (typeof ROLES)[number];
const SKIP = 'Postgres with the SIEMBox schema is not reachable';

const tag = crypto.randomBytes(4).toString('hex');
const octet = (i: number) => parseInt(tag.slice(i * 2, i * 2 + 2), 16);
// Benchmark-range addresses (198.18.0.0/15) unique to this run.
const IP = {
  attacker: `198.18.${octet(0)}.${octet(1)}`,
  capped: `198.19.${octet(0)}.${octet(1)}`,
  many: `198.18.${octet(2)}.${octet(3)}`,
  windowed: `198.19.${octet(2)}.${octet(3)}`,
  sender: `10.${octet(0)}.${octet(1)}.${octet(2)}`,
  asset: `10.${octet(3)}.${octet(1)}.${octet(0)}`,
  unknown: `198.18.${octet(1)}.${octet(0)}`,
};
const HOST = `Host-${tag}`;
const USER = `root-${tag}`;
const AGENT_ID = crypto.randomUUID();
const SHIPPER_KEY = crypto.randomBytes(16).toString('hex');
const GHOST_TAG = crypto.randomBytes(4).toString('hex');

let dbReady = false;
let server: Server | undefined;
let base = '';
const tokens = {} as Record<Role | 'restricted', string>;
const userIds: number[] = [];
const ids = {
  rule: 0,
  asset: 0,
  vuln: 0,
  shipper: 0,
  raw: [] as number[],
  parsed: 0,
  ghostParsed: 0,
  alerts: {} as Record<string, number>,
  identity: 0,
  domain: 0,
  finding: 0,
};

async function insertAlert(key: string, fields: { title?: string; severity?: string; status?: string; matched: Record<string, unknown>; ago?: string; rule?: boolean; parsed?: number; asset?: number; source?: string }) {
  const r = await pool.query(
    `INSERT INTO alerts (rule_id, parsed_log_id, severity, title, matched_data, status, created_at, asset_id, source, event_id)
     VALUES ($1, $2, $3, $4, $5, $6, NOW() - $7::interval, $8, $9, $10) RETURNING id`,
    [
      fields.rule === false ? null : ids.rule,
      fields.parsed ?? null,
      fields.severity ?? 'medium',
      `${tag} ${fields.title ?? key}`,
      JSON.stringify(fields.matched),
      fields.status ?? 'new',
      fields.ago ?? '1 hour',
      fields.asset ?? null,
      fields.source ?? null,
      fields.source ? `graph-test-${tag}-${key}` : null,
    ]
  );
  ids.alerts[key] = r.rows[0].id;
  return r.rows[0].id as number;
}

before(async () => {
  try {
    for (const table of ['sessions', 'alerts', 'exposure_findings', 'edr_agents', 'audit_logs', 'log_shippers']) {
      await pool.query(`SELECT 1 FROM ${table} LIMIT 1`);
    }
    dbReady = true;
  } catch {
    return;
  }
  for (const role of ROLES) {
    const user = await UserModel.create({
      username: `graph-${tag}-${role}`,
      email: `graph-${tag}-${role}@siembox.invalid`,
      password: crypto.randomBytes(16).toString('hex'),
      role,
    });
    userIds.push(user.id);
    tokens[role] = (await SessionModel.create(user.id, 1)).token;
  }
  const restricted = await UserModel.create({
    username: `graph-${tag}-restricted`,
    email: `graph-${tag}-restricted@siembox.invalid`,
    password: crypto.randomBytes(16).toString('hex'),
    role: 'viewer',
    requirePasswordChange: 'admin',
  });
  userIds.push(restricted.id);
  tokens.restricted = (await SessionModel.create(restricted.id, 1)).token;

  ids.rule = (
    await pool.query(
      `INSERT INTO detection_rules (name, enabled, severity, rule_yaml, rule_logic) VALUES ($1, true, 'high', 'x: 1', '{}') RETURNING id`,
      [`graph-test-${tag}`]
    )
  ).rows[0].id;
  ids.asset = (
    await pool.query(`INSERT INTO assets (ip_address, hostname, criticality) VALUES ($1, $2, 'critical') RETURNING id`, [IP.asset, `asset-${tag}`])
  ).rows[0].id;
  ids.vuln = (
    await pool.query(`INSERT INTO vulnerabilities (cve_id, severity, cvss_score, title) VALUES ($1, 'critical', 9.8, 'graph test') RETURNING id`, [
      `CVE-9${tag.slice(0, 3)}-${parseInt(tag.slice(3), 16)}`.slice(0, 20),
    ])
  ).rows[0].id;
  await pool.query(`INSERT INTO asset_vulnerabilities (asset_id, vulnerability_id, status, risk_score) VALUES ($1, $2, 'open', 9.1)`, [ids.asset, ids.vuln]);
  ids.shipper = (
    await pool.query(`INSERT INTO log_shippers (name, api_key, status, ip_address, hostname) VALUES ($1, $2, 'online', $3, $4) RETURNING id`, [
      `shipper-${tag}`,
      SHIPPER_KEY,
      IP.sender,
      HOST.toLowerCase(),
    ])
  ).rows[0].id;
  await pool.query(`INSERT INTO edr_agents (agent_id, api_key_hash, asset_id, hostname, status, last_seen) VALUES ($1, 'x', $2, $3, 'online', NOW())`, [
    AGENT_ID,
    ids.asset,
    `asset-${tag}`,
  ]);

  // Two logs: one shipped by the shipper above (its md5 tag), one by a ghost.
  const md5Tag = crypto.createHash('md5').update(Buffer.from(SHIPPER_KEY, 'hex')).digest('hex').slice(0, 8);
  for (const [hostname, shipperTag] of [
    [HOST, md5Tag],
    [null, GHOST_TAG],
  ] as const) {
    const raw = await pool.query(
      `INSERT INTO raw_logs (timestamp, raw_message, source_ip, hostname, app_name, shipper_id) VALUES (NOW(), 'graph test', $1, $2, 'sshd', $3) RETURNING id`,
      [IP.sender, hostname, shipperTag]
    );
    ids.raw.push(raw.rows[0].id);
    const parsed = await pool.query(
      `INSERT INTO parsed_logs (raw_log_id, parsed_data, timestamp, source_ip, event_type) VALUES ($1, '{}', NOW(), $2, 'test') RETURNING id`,
      [raw.rows[0].id, IP.sender]
    );
    if (hostname) ids.parsed = parsed.rows[0].id;
    else ids.ghostParsed = parsed.rows[0].id;
  }

  await insertAlert('brute', {
    title: 'SSH brute force',
    severity: 'high',
    matched: { source_ip: IP.attacker, observer_ip: IP.sender, user: USER, host: HOST, count: 4118 },
    parsed: ids.parsed,
    ago: '2 hours',
  });
  await insertAlert('sameEvent', { matched: { source_ip: IP.attacker, observer_ip: IP.sender, user: '-' }, parsed: ids.parsed });
  await insertAlert('senderOnly', { matched: { source_ip: IP.sender, observer_ip: IP.sender }, parsed: ids.ghostParsed, status: 'closed' });
  await insertAlert('dest', { matched: { source_ip: IP.asset, dest_ip: IP.attacker, observer_ip: IP.sender } });
  await insertAlert('logGone', { matched: { source_ip: IP.attacker } });
  await insertAlert('edr', { rule: false, source: 'edr', asset: ids.asset, matched: { agent_id: AGENT_ID, process: 'mimikatz.exe' }, severity: 'critical' });
  await insertAlert('auth', {
    rule: false,
    source: 'siembox-auth',
    matched: { trigger: 'account-pause', source_ip: IP.attacker, username: `graph-${tag}-admin`, user_id: userIds[0] },
  });
  for (let i = 0; i < 7; i++) {
    await insertAlert(`seven${i}`, { matched: { source_ip: IP.capped }, severity: i === 6 ? 'critical' : 'low', ago: `${i + 1} hours` });
  }
  await pool.query(
    `INSERT INTO alerts (rule_id, severity, title, matched_data, status, created_at)
     SELECT $1, 'low', $2, jsonb_build_object('source_ip', $3::text), 'new', NOW() - make_interval(mins => g)
       FROM generate_series(1, 1002) g`,
    [ids.rule, `${tag} many`, IP.many]
  );
  await insertAlert('in24h', { matched: { client_ip: IP.windowed }, ago: '23 hours' });
  await insertAlert('before24h', { matched: { client_ip: IP.windowed }, ago: '25 hours' });

  await pool.query(
    `INSERT INTO audit_logs (user_id, action, ip_address, timestamp)
     SELECT $1, a, $2::inet, NOW() - INTERVAL '5 minutes' FROM unnest(ARRAY['auth.login.failure', 'auth.login.failure', 'auth.login.success']) a`,
    [userIds[0], IP.attacker]
  );

  // Digital Risk: an email identity with a finding, a watched domain with a lookalike finding and its alert.
  ids.identity = (
    await pool.query(`INSERT INTO monitored_identities (kind, value) VALUES ('email', $1) RETURNING id`, [`alice-${tag}@acme.test`])
  ).rows[0].id;
  ids.domain = (await pool.query(`INSERT INTO watched_domains (domain, scope) VALUES ($1, 'own') RETURNING id`, [`acme-${tag}.test`])).rows[0].id;
  await insertAlert('lookalike', {
    rule: false,
    source: 'domain-monitor',
    matched: { domain: `acme-${tag}.test`, lookalike: `acme-${tag}.co` },
    severity: 'high',
  });
  ids.finding = (
    await pool.query(
      `INSERT INTO exposure_findings (source, domain_id, event_type, fingerprint, title, severity, detail, alert_id)
       VALUES ('domain-monitor', $1, 'lookalike_registered', $2, 'Lookalike registered', 'high', $3, $4) RETURNING id`,
      [ids.domain, `graph-${tag}`, JSON.stringify({ lookalike: `acme-${tag}.co` }), ids.alerts.lookalike]
    )
  ).rows[0].id;
  await insertAlert('aliceLogin', { matched: { source_ip: IP.attacker, user: `Alice-${tag}@Acme.test` } });

  server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  if (dbReady) {
    await pool.query(`DELETE FROM audit_logs WHERE user_id = ANY($1)`, [userIds]);
    await pool.query(`DELETE FROM alerts WHERE title LIKE $1`, [`${tag} %`]);
    await pool.query(`DELETE FROM detection_rules WHERE id = $1`, [ids.rule]);
    await pool.query(`DELETE FROM edr_agents WHERE agent_id = $1`, [AGENT_ID]);
    await pool.query(`DELETE FROM assets WHERE id = $1`, [ids.asset]);
    await pool.query(`DELETE FROM vulnerabilities WHERE id = $1`, [ids.vuln]);
    await pool.query(`DELETE FROM log_shippers WHERE id = $1`, [ids.shipper]);
    await pool.query(`DELETE FROM raw_logs WHERE id = ANY($1)`, [ids.raw]);
    await pool.query(`DELETE FROM monitored_identities WHERE id = $1`, [ids.identity]);
    await pool.query(`DELETE FROM watched_domains WHERE id = $1`, [ids.domain]);
    await pool.query(`DELETE FROM users WHERE id = ANY($1)`, [userIds]);
  }
  await closePools();
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- the answers' shapes vary per route
type Json = any;

async function call(who: Role | 'restricted' | null, pathAndQuery: string) {
  const headers: Record<string, string> = who ? { Authorization: `Bearer ${tokens[who]}` } : {};
  const res = await fetch(base + pathAndQuery, { headers });
  const json = (await res.json().catch(() => null)) as Json;
  return { status: res.status, json, retryAfter: res.headers.get('retry-after') };
}

const nbr = async (who: Role, entity: string, extra = '') =>
  call(who, `/api/graph/neighborhood?entity=${encodeURIComponent(entity)}${extra}`) as Promise<{ status: number; json: NeighborhoodResponse; retryAfter: string | null }>;
const nodeIds = (r: NeighborhoodResponse) => r.nodes.map((n: GraphNode) => n.id);
const edge = (r: NeighborhoodResponse, rel: string, source: string, target: string) =>
  r.edges.find((e: GraphEdge) => e.rel === rel && e.source === source && e.target === target);
const group = (r: NeighborhoodResponse, rel: string) => r.groups.find((g) => g.rel === rel)!;
const alertId = (key: string) => `alert:${ids.alerts[key]}`;

test('an alert: its IPs (source and sender roles), user, host, rule, same-event alert, and the device and shipper that logged it', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  graphCache.clear();
  const { status, json } = await nbr('analyst', alertId('brute'));
  assert.equal(status, 200);
  assert.equal(json.center.exists, true);
  assert.equal(json.center.facts.severity, 'high');
  assert.ok(!('matched_data' in json.center.facts), 'never the alert matched_data');
  assert.equal(edge(json, 'alert_ips', alertId('brute'), `ip:${IP.attacker}`)?.role, 'source');
  assert.ok(edge(json, 'alert_users', alertId('brute'), `user:${USER}`));
  assert.ok(edge(json, 'alert_hosts', alertId('brute'), `host:${HOST.toLowerCase()}`), 'host named in the log, lower-cased');
  assert.ok(edge(json, 'alert_rule', alertId('brute'), `rule:${ids.rule}`));
  assert.ok(edge(json, 'alert_same_event', alertId('brute'), alertId('sameEvent')));
  const device = edge(json, 'alert_device', alertId('brute'), `host:${HOST.toLowerCase()}`);
  assert.equal(device?.style, 'logs', 'the device is the syslog header host, dashed');
  assert.ok(edge(json, 'shipped_by', `host:${HOST.toLowerCase()}`, `shipper:${ids.shipper}`), 'mapped to its shipper');
  assert.deepEqual(json.sources, { alerts: { status: 'ok' }, risk: { status: 'ok' }, logs: { status: 'ok' } });

  // The junk user '-' of the same-event alert is no node; a sender-only alert's IP is a sender.
  const same = (await nbr('analyst', alertId('sameEvent'))).json;
  assert.ok(!same.nodes.some((n) => n.type === 'user'));
  const sender = (await nbr('analyst', alertId('senderOnly'))).json;
  assert.equal(edge(sender, 'alert_ips', alertId('senderOnly'), `ip:${IP.sender}`)?.role, 'sender');
  assert.ok(sender.center.flags.includes('closed'));
  // No header host: the device is the sender IP, and an unmatched tag is a ghost shipper.
  assert.ok(edge(sender, 'alert_device', alertId('senderOnly'), `ip:${IP.sender}`));
  assert.ok(edge(sender, 'shipped_by', `ip:${IP.sender}`, `shipper_tag:${GHOST_TAG}`));
  // A rule alert whose log is gone says so.
  assert.equal(group((await nbr('analyst', alertId('logGone'))).json, 'alert_device').note, 'log_expired');
});

test('an IP: its alerts with the role it plays in each; the ip is source, dest or sender', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  graphCache.clear();
  const { json } = await nbr('analyst', `ip:${IP.attacker}`, '&limit=25');
  assert.equal(json.center.exists, true);
  assert.equal(edge(json, 'alert_ips', alertId('brute'), `ip:${IP.attacker}`)?.role, 'source');
  assert.equal(edge(json, 'alert_ips', alertId('dest'), `ip:${IP.attacker}`)?.role, 'dest');
  assert.equal(group(json, 'entity_alerts').total, 6);
  // The same fact from either side is one edge id.
  const fromAlert = (await nbr('analyst', alertId('brute'))).json;
  assert.ok(fromAlert.edges.some((e) => e.id === `alert_ips|${alertId('brute')}|ip:${IP.attacker}`));
  assert.ok(json.edges.some((e) => e.id === `alert_ips|${alertId('brute')}|ip:${IP.attacker}`));
  const sender = (await nbr('analyst', `ip:${IP.sender}`)).json;
  assert.equal(edge(sender, 'alert_ips', alertId('senderOnly'), `ip:${IP.sender}`)?.role, 'sender');
  assert.ok(sender.center.flags.includes('private'));
  assert.ok(edge(sender, 'shipper_address', `shipper:${ids.shipper}`, `ip:${IP.sender}`), 'the shipper at this address');
});

test('caps: the top 5 per relation, the rest counted exactly; over 1,000 is "1,000+"; severity first', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  graphCache.clear();
  const seven = (await nbr('viewer', `ip:${IP.capped}`)).json;
  const g = group(seven, 'entity_alerts');
  assert.deepEqual({ total: g.total, capped: g.total_capped, shown: g.shown, veryCommon: g.very_common }, { total: 7, capped: false, shown: 5, veryCommon: false });
  assert.equal(seven.nodes.filter((n) => n.type === 'alert').length, 5);
  assert.ok(nodeIds(seven).includes(alertId('seven6')), 'the critical one ranks first though it is the oldest');
  assert.equal(group((await nbr('viewer', `ip:${IP.capped}`, '&limit=6')).json, 'entity_alerts').shown, 6);

  const many = (await nbr('viewer', `ip:${IP.many}`)).json;
  const m = group(many, 'entity_alerts');
  assert.deepEqual({ total: m.total, capped: m.total_capped, shown: m.shown, veryCommon: m.very_common }, { total: 1000, capped: true, shown: 5, veryCommon: true });

  // The relation table pages through them.
  const page1 = (await call('viewer', `/api/graph/relation?entity=ip:${IP.capped}&rel=entity_alerts&limit=4`)).json;
  assert.deepEqual([page1.total, page1.items.length, page1.next_offset], [7, 4, 4]);
  const page2 = (await call('viewer', `/api/graph/relation?entity=ip:${IP.capped}&rel=entity_alerts&limit=4&offset=4`)).json;
  assert.deepEqual([page2.items.length, page2.next_offset], [3, null]);
  const ids1 = page1.items.map((i: Json) => i.node.id);
  assert.equal(new Set([...ids1, ...page2.items.map((i: Json) => i.node.id)]).size, 7);
  const oldest = (await call('viewer', `/api/graph/relation?entity=ip:${IP.capped}&rel=entity_alerts&sort=first_seen&order=asc&limit=1`)).json;
  assert.equal(oldest.items[0].node.id, alertId('seven6'));
  const searched = (await call('viewer', `/api/graph/relation?entity=ip:${IP.capped}&rel=entity_alerts&q=${encodeURIComponent('seven3')}`)).json;
  assert.deepEqual(searched.items.map((i: Json) => i.node.id), [alertId('seven3')]);
  const wild = (await call('viewer', `/api/graph/relation?entity=ip:${IP.capped}&rel=entity_alerts&q=${encodeURIComponent('%')}`)).json;
  assert.equal(wild.total, 0, 'LIKE characters in q are literal');
  const past = (await call('viewer', `/api/graph/relation?entity=ip:${IP.capped}&rel=entity_alerts&offset=40`)).json;
  assert.deepEqual([past.total, past.items.length, past.next_offset], [7, 0, null]);
});

test('windows: 24h ends at the window edge; around=T covers T - 24 h to T + 1 h', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  graphCache.clear();
  const day = (await nbr('viewer', `ip:${IP.windowed}`, '&window=24h')).json;
  assert.deepEqual(day.nodes.filter((n) => n.type === 'alert').map((n) => n.id), [alertId('in24h')]);
  const week = (await nbr('viewer', `ip:${IP.windowed}`, '&window=7d')).json;
  assert.equal(group(week, 'entity_alerts').total, 2);
  const [row] = (await pool.query(`SELECT created_at FROM alerts WHERE id = $1`, [ids.alerts.before24h])).rows;
  const t0 = new Date(row.created_at.getTime() - 30 * 60_000).toISOString();
  const around = (await nbr('viewer', `ip:${IP.windowed}`, `&around=${encodeURIComponent(t0)}`)).json;
  assert.equal(around.window.preset, 'around');
  assert.deepEqual(around.nodes.filter((n) => n.type === 'alert').map((n) => n.id), [alertId('before24h')], 'in at T + 30 min; the other is T + 2 h');
});

test('an asset: current IP, host, open vulnerabilities, shipper match, alerts by asset_id and by its IP; agent status for everyone', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  graphCache.clear();
  const admin = (await nbr('admin', `asset:${ids.asset}`)).json;
  const asset = `asset:${ids.asset}`;
  assert.ok(edge(admin, 'asset_ip', asset, `ip:${IP.asset}`));
  assert.ok(edge(admin, 'asset_host', asset, `host:asset-${tag}`));
  assert.ok(edge(admin, 'asset_vulns', asset, `vuln:${ids.vuln}`));
  assert.ok(edge(admin, 'asset_endpoint', asset, `endpoint:${AGENT_ID}`), 'admins get the endpoint');
  assert.ok(edge(admin, 'alert_asset', alertId('edr'), asset), 'the EDR alert, by asset_id (solid)');
  assert.equal(edge(admin, 'entity_alerts', alertId('dest'), asset)?.style, 'heuristic', 'an alert naming its current IP (dotted)');
  assert.deepEqual(admin.center.flags.sort(), ['critical', 'open_vulns']);
  assert.equal(admin.center.facts.agent_status, 'online');

  // Right after, a viewer: no endpoint node or relation, never the admin's cached answer.
  const viewer = await nbr('viewer', `asset:${ids.asset}`);
  assert.equal(viewer.json.cached, false);
  assert.ok(!viewer.json.nodes.some((n) => n.type === 'endpoint'));
  assert.ok(!viewer.json.groups.some((g) => g.rel === 'asset_endpoint'));
  assert.equal(viewer.json.center.facts.agent_status, 'online', 'agent status is a fact for every role');
  // The same role again is served from cache.
  assert.equal((await nbr('viewer', `asset:${ids.asset}`)).json.cached, true);
  assert.equal((await nbr('operator', `asset:${ids.asset}`)).json.cached, true, 'roles that see the same graph share it');

  const vuln = (await nbr('viewer', `vuln:${ids.vuln}`)).json;
  assert.ok(edge(vuln, 'asset_vulns', asset, `vuln:${ids.vuln}`));
  const shipper = (await nbr('viewer', `shipper:${ids.shipper}`)).json;
  assert.ok(edge(shipper, 'shipper_address', `shipper:${ids.shipper}`, `host:${HOST.toLowerCase()}`));
  assert.ok(!shipper.nodes.some((n) => Object.keys(n.facts).some((f) => /key|hash/.test(f))), 'no key or hash facts');
});

test('accounts and endpoints are admin-only; a non-admin sees the account a sign-in alert names, label only', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  graphCache.clear();
  const admin = (await nbr('admin', `ip:${IP.attacker}`, '&limit=25')).json;
  const signins = edge(admin, 'account_signins', `account:${userIds[0]}`, `ip:${IP.attacker}`);
  assert.deepEqual([signins?.count, signins?.failures, signins?.successes], [3, 2, 1]);
  assert.ok(admin.sources.accounts);

  for (const role of ['operator', 'analyst', 'viewer'] as const) {
    const r = (await nbr(role, `ip:${IP.attacker}`, '&limit=25')).json;
    assert.ok(!r.groups.some((g) => g.rel === 'ip_signins'), `${role}: no sign-in relation`);
    assert.ok(!('accounts' in r.sources), `${role}: no accounts source`);
    assert.ok(!r.edges.some((e) => e.rel === 'account_signins'));
    const auth = (await nbr(role, alertId('auth'))).json;
    const account = auth.nodes.find((n) => n.type === 'account')!;
    assert.deepEqual([account.label, account.facts, account.expandable], [`graph-${tag}-admin`, { username: `graph-${tag}-admin` }, false]);
    const edr = (await nbr(role, alertId('edr'))).json;
    assert.ok(!edr.nodes.some((n) => n.type === 'endpoint'), `${role}: no endpoint node`);
    for (const entity of [`account:${userIds[0]}`, `endpoint:${AGENT_ID}`]) {
      const refused = await nbr(role, entity);
      assert.deepEqual([refused.status, (refused.json as Json).code], [404, 'GRAPH_NOT_AVAILABLE'], `${role} ${entity}`);
    }
  }
  const auth = (await nbr('admin', alertId('auth'))).json;
  const account = auth.nodes.find((n) => n.type === 'account')!;
  assert.equal(account.facts.role, 'admin');
  assert.equal(account.expandable, true);
  const accountCenter = (await nbr('admin', `account:${userIds[0]}`)).json;
  assert.ok(edge(accountCenter, 'account_signins', `account:${userIds[0]}`, `ip:${IP.attacker}`));
  assert.ok(edge(accountCenter, 'alert_account', alertId('auth'), `account:${userIds[0]}`));
  const endpoint = (await nbr('admin', `endpoint:${AGENT_ID}`)).json;
  assert.ok(edge(endpoint, 'asset_endpoint', `asset:${ids.asset}`, `endpoint:${AGENT_ID}`));
  assert.ok(edge(endpoint, 'alert_endpoint', alertId('edr'), `endpoint:${AGENT_ID}`));
});

test('Digital Risk: a lookalike domain, its finding and alert; an email identity and the user that is that address', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  graphCache.clear();
  const lookalike = `domain:acme-${tag}.co`;
  const d = (await nbr('viewer', lookalike)).json;
  assert.ok(edge(d, 'finding_domain', `finding:${ids.finding}`, lookalike));
  assert.ok(edge(d, 'alert_domains', alertId('lookalike'), lookalike), 'the alert naming it as the lookalike');
  const f = (await nbr('viewer', `finding:${ids.finding}`)).json;
  assert.ok(edge(f, 'finding_domain', `finding:${ids.finding}`, `domain:acme-${tag}.test`));
  assert.ok(edge(f, 'alert_finding', alertId('lookalike'), `finding:${ids.finding}`));
  const watched = (await nbr('viewer', `domain:acme-${tag}.test`)).json;
  assert.equal(watched.center.facts.watched, 'own');
  const identity = (await nbr('viewer', `identity:${ids.identity}`)).json;
  const user = `user:Alice-${tag}@Acme.test`;
  assert.equal(edge(identity, 'identity_user', `identity:${ids.identity}`, user)?.style, 'heuristic', 'matched in lower case, dotted');
  const u = (await nbr('viewer', user)).json;
  assert.ok(edge(u, 'identity_user', `identity:${ids.identity}`, user));
  assert.equal(u.center.facts.is_email, true);
});

test('search: an IP and its asset; #id; a host prefix; a literal; never more than 10', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  graphCache.clear();
  const ip = (await call('viewer', `/api/graph/search?q=${IP.asset}`)).json;
  assert.deepEqual(ip.candidates.map((c: Json) => c.entity), [`ip:${IP.asset}`, `asset:${ids.asset}`]);
  assert.match(ip.candidates[0].hint, /alert/);
  const alert = (await call('viewer', `/api/graph/search?q=${encodeURIComponent(`#${ids.alerts.brute}`)}`)).json;
  assert.deepEqual(alert.candidates.map((c: Json) => c.entity), [alertId('brute')]);
  const host = (await call('viewer', `/api/graph/search?q=asset-${tag.slice(0, 6)}`)).json;
  assert.ok(host.candidates.some((c: Json) => c.entity === `asset:${ids.asset}`));
  assert.ok(host.candidates.length <= 10);
  const literal = (await call('viewer', `/api/graph/search?q=${encodeURIComponent(`user:${USER}`)}`)).json;
  assert.deepEqual(literal.candidates.map((c: Json) => c.entity), [`user:${USER}`]);
  const endpoint = (await call('viewer', `/api/graph/search?q=${encodeURIComponent(`endpoint:${AGENT_ID}`)}`)).json;
  assert.deepEqual(endpoint.candidates, [], 'a viewer gets no admin-only candidate');
  // Nor can a non-admin probe which account ids exist; an admin can look one up.
  for (const role of ['operator', 'analyst', 'viewer'] as const) {
    const probe = (await call(role, `/api/graph/search?q=${encodeURIComponent(`account:${userIds[0]}`)}`)).json;
    assert.deepEqual(probe.candidates, [], role);
  }
  const account = (await call('admin', `/api/graph/search?q=${encodeURIComponent(`account:${userIds[0]}`)}`)).json;
  assert.deepEqual(account.candidates.map((c: Json) => [c.entity, c.label]), [[`account:${userIds[0]}`, `graph-${tag}-admin`]]);
  assert.equal((await call('viewer', `/api/graph/search?q=`)).status, 400);
});

test('answers: unknown entity -> 200 exists:false; bad input -> 400 (never 401); restricted -> 403; no login -> 401', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  graphCache.clear();
  const unknown = await nbr('viewer', `ip:${IP.unknown}`);
  assert.deepEqual([unknown.status, unknown.json.center.exists, unknown.json.nodes.length], [200, false, 1]);
  const missing = await nbr('viewer', 'alert:2147483647');
  assert.deepEqual([missing.status, missing.json.center.exists], [200, false]);
  for (const bad of [
    '/api/graph/neighborhood',
    '/api/graph/neighborhood?entity=ip:999.1.1.1',
    '/api/graph/neighborhood?entity=process:1',
    '/api/graph/neighborhood?entity=ip:1.2.3.4&window=1y',
    '/api/graph/neighborhood?entity=ip:1.2.3.4&limit=26',
    '/api/graph/neighborhood?entity=ip:1.2.3.4&include=logs,nope',
    '/api/graph/neighborhood?entity[a]=1',
    '/api/graph/relation?entity=ip:1.2.3.4&rel=nope',
    '/api/graph/relation?entity=ip:1.2.3.4&rel=entity_alerts&offset=1001',
    `/api/graph/search?q=${'x'.repeat(201)}`,
  ]) {
    const r = await call('viewer', bad);
    assert.equal(r.status, 400, bad);
    assert.match(r.json.code, /^GRAPH_BAD_(ENTITY|PARAM)$/, bad);
  }
  const notHere = await call('viewer', `/api/graph/relation?entity=ip:1.2.3.4&rel=alert_ips`);
  assert.deepEqual([notHere.status, notHere.json.code], [404, 'GRAPH_NOT_AVAILABLE']);
  const restricted = await call('restricted', `/api/graph/neighborhood?entity=ip:${IP.attacker}`);
  assert.deepEqual([restricted.status, restricted.json.code], [403, 'PASSWORD_CHANGE_REQUIRED']);
  assert.equal((await call(null, `/api/graph/neighborhood?entity=ip:${IP.attacker}`)).status, 401);
  // include limits the origins that run.
  const onlyInventory = (await nbr('admin', `ip:${IP.attacker}`, '&include=inventory')).json;
  assert.deepEqual(Object.keys(onlyInventory.sources), ['inventory']);
});

/** A test-only source for IPs that sleeps past the statement timeout. */
const SLOW: RelationDef = {
  rel: 'ip_asset',
  label: 'Slow (test)',
  center: 'ip',
  neighborType: 'asset',
  origin: 'inventory',
  style: 'recorded',
  async fetch(q) {
    await q('SELECT pg_sleep(2)');
    return { items: [], total: 0, totalCapped: false };
  },
};

test('a source that times out is left out: 200, its group "timeout", its source partial, the rest intact; all out -> 503', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  graphCache.clear();
  const saved = { catalog: graphDeps.catalog, budget: graphDeps.budget };
  try {
    graphDeps.budget = { statementTimeoutMs: 300 };
    graphDeps.catalog = [...RELATIONS.filter((def) => !(def.center === 'ip' && def.rel === 'ip_asset')), SLOW];
    const started = Date.now();
    const r = await nbr('admin', `ip:${IP.attacker}`);
    assert.equal(r.status, 200);
    assert.ok(Date.now() - started < 2000, 'the slow statement was cancelled, not waited for');
    assert.equal(group(r.json, 'ip_asset').status, 'timeout');
    assert.equal(group(r.json, 'entity_alerts').status, 'ok');
    assert.ok(r.json.nodes.some((n) => n.type === 'alert'));
    assert.deepEqual(r.json.sources.inventory, { status: 'partial' });
    assert.deepEqual(r.json.sources.alerts, { status: 'ok' });
    // A partial answer isn't cached: trying again runs again.
    assert.equal((await nbr('admin', `ip:${IP.attacker}`)).json.cached, false);

    graphDeps.catalog = [SLOW];
    const all = await nbr('admin', `ip:${IP.attacker}`);
    assert.deepEqual([all.status, (all.json as Json).code, all.retryAfter], [503, 'GRAPH_BUSY', '2']);
  } finally {
    graphDeps.catalog = saved.catalog;
    graphDeps.budget = saved.budget;
  }
});

test('an exhausted semaphore: 503 GRAPH_BUSY with Retry-After after a 1 s wait', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  graphCache.clear();
  const held = await Promise.all(['a', 'b', 'c', 'd'].map((u) => graphSemaphore.acquire(`test-holder-${u}`)));
  try {
    const started = Date.now();
    const r = await nbr('viewer', `ip:${IP.capped}`);
    assert.deepEqual([r.status, (r.json as Json).code, r.retryAfter, (r.json as Json).retryAfter], [503, 'GRAPH_BUSY', '2', 2]);
    assert.ok(Date.now() - started >= 950, 'it waited about a second first');
  } finally {
    for (const release of held) release();
  }
  assert.equal((await nbr('viewer', `ip:${IP.capped}`)).status, 200, 'and works once a slot is free');
});

test('huge log values: an alert holding them is still written; spelled values find their alerts', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  graphCache.clear();
  // A btree entry over ~2.7 kB would fail the INSERT: the indexes leave such values out.
  const huge = crypto.randomBytes(3000).toString('hex');
  const id = await insertAlert('huge', { matched: { source_ip: huge, user: huge, host: huge, domain: `${huge}.example`, target_user: huge } });
  assert.ok(id > 0);
  // Values as logs write them: a trailing dot, padding, upper-case IPv6.
  const [g1, g2] = [(octet(0) | 0x100).toString(16), (octet(1) | 0x100).toString(16)]; // never 0
  const v6 = `2001:db8:0:0:0:0:${g1}:${g2}`.toUpperCase();
  await insertAlert('spelled', { matched: { domain: ` Spelled-${tag}.Example. `, host: ` HOST-${tag}-B `, source_ip: v6, user: ` padded-${tag} ` } });
  const domain = (await nbr('viewer', `domain:spelled-${tag}.example`)).json;
  assert.ok(edge(domain, 'alert_domains', alertId('spelled'), `domain:spelled-${tag}.example`), 'the domain the alert shows finds the alert');
  const host = (await nbr('viewer', `host:host-${tag}-b`)).json;
  assert.ok(edge(host, 'alert_hosts', alertId('spelled'), `host:host-${tag}-b`));
  const user = (await nbr('viewer', `user:padded-${tag}`)).json;
  assert.ok(edge(user, 'alert_users', alertId('spelled'), `user:padded-${tag}`));
  const fromAlert = (await nbr('viewer', alertId('spelled'))).json;
  const ip = fromAlert.nodes.find((n) => n.type === 'ip')!;
  assert.equal(ip.key, `2001:db8::${g1}:${g2}`);
  const back = (await nbr('viewer', ip.id)).json;
  assert.ok(edge(back, 'alert_ips', alertId('spelled'), ip.id), 'the canonical IPv6 key finds the alert that spelled it out');
  assert.equal(back.center.exists, true);
});

test('migration 043 re-runs on the populated database without changing anything', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const sql = fs.readFileSync(path.join(__dirname, '../../migrations/043_context_graph_lookups.sql'), 'utf8');
  const count = async () => Number((await pool.query(`SELECT count(*) AS n FROM alerts WHERE title LIKE $1`, [`${tag} %`])).rows[0].n);
  const before = await count();
  await pool.query(sql);
  await pool.query(sql);
  assert.equal(await count(), before);
  const { rows } = await pool.query(
    `SELECT c.relname, i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname LIKE 'idx_graph_%' ORDER BY 1`
  );
  assert.equal(rows.length, 12);
  assert.ok(rows.every((row) => row.indisvalid));
});
