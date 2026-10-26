/**
 * Context Graph application nodes against a real Postgres (the real app on an
 * ephemeral port, as graph.db.test.ts): Application Monitoring's inventory
 * (application_inventory, application_vuln_links, migration 048) seeded with
 * rows tagged with a random id, deleted again in `after`.
 *
 * Covers: an asset runs an application (by its id, its host name and a shipper
 * at its address), with versions, sources and count on a solid inventory edge;
 * a logging host and a sender IP run one; a shipper's containers; a client IP
 * uses one, marked network evidence, and that is no "runs" edge of the asset
 * at that IP; an application centre's groups and facts (the facts allow-list),
 * an unmanaged (network-only) one; app -> vuln exact (solid) and best effort
 * (dotted), from either side; the caps (an application on 500 clients is a
 * very-common group of 5, paged and searchable); search by name, vendor and
 * id (only applications in the inventory); every role sees them; an unknown
 * application is exists:false and a bad id a 400. Skips itself without
 * Postgres. Run with `npm test`.
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
import { graphCache } from '../services/graph/limits';
import type { GraphEdge, NeighborhoodResponse } from '../services/graph/types';

const ROLES = ['admin', 'operator', 'analyst', 'viewer'] as const;
type Role = (typeof ROLES)[number];
const SKIP = 'Postgres with the SIEMBox schema is not reachable';

const tag = crypto.randomBytes(4).toString('hex');
const octet = (i: number) => parseInt(tag.slice(i * 2, i * 2 + 2), 16);
// CGNAT addresses (100.64.0.0/10) unique to this run; the 500 clients in an IPv6 /64 of it.
const IP = {
  asset: `100.${64 + (octet(0) % 64)}.${octet(1)}.${octet(2)}`,
  sender: `100.${64 + (octet(1) % 64)}.${octet(2)}.${octet(3)}`,
  client: `100.${64 + (octet(2) % 64)}.${octet(3)}.${octet(0)}`,
};
const V6 = `2001:db8:${(parseInt(tag.slice(0, 4), 16) | 0x1000).toString(16)}:${(parseInt(tag.slice(4, 8), 16) | 0x1000).toString(16)}`;
const clientIp = (n: number) => `${V6}::${(n + 1).toString(16)}`;
const HOST = `apphost-${tag}`;
const ASSET_HOST = `appasset-${tag}`;
const APP = {
  web: `cg${tag}-web`,
  db: `cg${tag}-db`,
  browser: `cg${tag}-browser`,
  saas: `cg${tag}-saas`,
  orphan: `cg${tag}-orphan`,
};

let dbReady = false;
let server: Server | undefined;
let base = '';
const tokens = {} as Record<Role, string>;
const userIds: number[] = [];
const ids = { asset: 0, shipper: 0, vulnExact: 0, vulnProduct: 0 };

before(async () => {
  try {
    for (const table of ['sessions', 'application_inventory', 'application_vuln_links', 'application_signatures', 'log_shippers']) {
      await pool.query(`SELECT 1 FROM ${table} LIMIT 1`);
    }
    dbReady = true;
  } catch {
    return;
  }
  for (const role of ROLES) {
    const user = await UserModel.create({
      username: `appgraph-${tag}-${role}`,
      email: `appgraph-${tag}-${role}@siembox.invalid`,
      password: crypto.randomBytes(16).toString('hex'),
      role,
    });
    userIds.push(user.id);
    tokens[role] = (await SessionModel.create(user.id, 1)).token;
  }
  const sig = (id: string, name: string, vendor: string, category: string) =>
    pool.query(
      `INSERT INTO application_signatures (id, name, vendor, category, definition, source) VALUES ($1, $2, $3, $4, $5, 'catalog')`,
      [id, name, vendor, category, JSON.stringify({ id, name, vendor, category })]
    );
  await sig(APP.web, `Webserv ${tag}`, `Acme ${tag}`, 'web-server');
  await sig(APP.db, `Datastore ${tag}`, `Initech ${tag}`, 'database');
  await sig(APP.browser, `Browsy ${tag}`, `Globex ${tag}`, 'browser');
  await sig(APP.saas, `Cloudy ${tag}`, `Umbrella ${tag}`, 'saas');
  // A signature nothing was seen for: not a search candidate.
  await sig(APP.orphan, `Orphan ${tag}`, `Acme ${tag}`, 'web-server');

  ids.asset = (await pool.query(`INSERT INTO assets (ip_address, hostname) VALUES ($1, $2) RETURNING id`, [IP.asset, ASSET_HOST])).rows[0].id;
  ids.shipper = (
    await pool.query(`INSERT INTO log_shippers (name, api_key, status, ip_address, hostname) VALUES ($1, $2, 'online', $3, $4) RETURNING id`, [
      `appshipper-${tag}`,
      crypto.randomBytes(16).toString('hex'),
      IP.sender,
      HOST,
    ])
  ).rows[0].id;
  ids.vulnExact = (
    await pool.query(`INSERT INTO vulnerabilities (cve_id, severity, cvss_score, title) VALUES ($1, 'critical', 9.8, 'exact') RETURNING id`, [`CVE-8${tag}-1`.slice(0, 20)])
  ).rows[0].id;
  ids.vulnProduct = (
    await pool.query(`INSERT INTO vulnerabilities (cve_id, severity, cvss_score, title) VALUES ($1, 'medium', 5.0, 'best effort') RETURNING id`, [`CVE-8${tag}-2`.slice(0, 20)])
  ).rows[0].id;

  const inv = (appKey: string, locType: string, locKey: string, source: string, version: string, events: number, ago = '1 hour') =>
    pool.query(
      `INSERT INTO application_inventory (app_id, loc_type, loc_key, source, version, events, first_seen, last_seen, evidence)
       VALUES ($1, $2, $3, $4, $5, $6, NOW() - INTERVAL '3 days', NOW() - $7::interval, '{}')`,
      [appKey, locType, locKey, source, version, events, ago]
    );
  // The web server: on the asset (nmap, two versions over time; and its host
  // name's logs), on a logging host, on a sender IP, in a shipper's containers.
  await inv(APP.web, 'asset', String(ids.asset), 'service_scan', '1.24.0', 1, '2 days');
  await inv(APP.web, 'asset', String(ids.asset), 'service_scan', '1.25.3', 1);
  await inv(APP.web, 'host', ASSET_HOST, 'syslog_program', '', 40);
  await inv(APP.web, 'host', HOST, 'syslog_program', '', 7);
  await inv(APP.web, 'host', IP.sender, 'parser', '', 3);
  await inv(APP.web, 'shipper', String(ids.shipper), 'container', '1.25.3', 2);
  // The database: in the shipper's containers only.
  await inv(APP.db, 'shipper', String(ids.shipper), 'container', '16.2', 1);
  // The browser: one client at the asset's IP, one other, and 500 more.
  await inv(APP.browser, 'client', IP.asset, 'user_agent', '128.0', 12);
  await inv(APP.browser, 'client', IP.client, 'user_agent', '127.0', 5);
  await pool.query(
    `INSERT INTO application_inventory (app_id, loc_type, loc_key, source, version, events, first_seen, last_seen)
     SELECT $1, 'client', $2 || '::' || to_hex(g + 1), 'user_agent', '128.0', g, NOW() - INTERVAL '3 days', NOW() - make_interval(mins => g)
       FROM generate_series(1, 500) g`,
    [APP.browser, V6]
  );
  // A SaaS seen only in a client's DNS queries: unmanaged.
  await inv(APP.saas, 'client', IP.client, 'dns', '', 9);

  // Vulnerabilities: exact (an EDR package finding) and best effort (by product name), both on the asset.
  await pool.query(
    `INSERT INTO application_vuln_links (app_id, asset_id, vulnerability_id, match, version) VALUES ($1, $2, $3, 'package', '1.24.0'), ($1, $2, $4, 'product', '')`,
    [APP.web, ids.asset, ids.vulnExact, ids.vulnProduct]
  );

  server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  if (dbReady) {
    const apps = Object.values(APP);
    await pool.query(`DELETE FROM application_vuln_links WHERE app_id = ANY($1)`, [apps]);
    await pool.query(`DELETE FROM application_inventory WHERE app_id = ANY($1)`, [apps]);
    await pool.query(`DELETE FROM application_signatures WHERE id = ANY($1)`, [apps]);
    await pool.query(`DELETE FROM vulnerabilities WHERE id = ANY($1::int[])`, [[ids.vulnExact, ids.vulnProduct]]);
    await pool.query(`DELETE FROM assets WHERE id = $1`, [ids.asset]);
    await pool.query(`DELETE FROM log_shippers WHERE id = $1`, [ids.shipper]);
    await pool.query(`DELETE FROM users WHERE id = ANY($1)`, [userIds]);
  }
  await closePools();
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- the answers' shapes vary per route
type Json = any;

async function call(who: Role, pathAndQuery: string) {
  const res = await fetch(base + pathAndQuery, { headers: { Authorization: `Bearer ${tokens[who]}` } });
  return { status: res.status, json: (await res.json().catch(() => null)) as Json };
}
const nbr = async (who: Role, entity: string, extra = '') => {
  const r = await call(who, `/api/graph/neighborhood?entity=${encodeURIComponent(entity)}${extra}`);
  assert.equal(r.status, 200, `${entity}: ${JSON.stringify(r.json)}`);
  return r.json as NeighborhoodResponse;
};
const edge = (r: NeighborhoodResponse, rel: string, source: string, target: string) =>
  r.edges.find((e: GraphEdge) => e.rel === rel && e.source === source && e.target === target);
const group = (r: NeighborhoodResponse, rel: string) => r.groups.find((g) => g.rel === rel);
const appNode = (id: string) => `application:${id}`;

test('an asset runs its applications (by id, host name): versions, sources and count on a solid inventory edge; no network evidence', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  graphCache.clear();
  const r = await nbr('viewer', `asset:${ids.asset}`);
  const runs = group(r, 'runs_app')!;
  assert.equal(runs.neighbor_type, 'application');
  assert.equal(runs.origin, 'inventory');
  assert.equal(runs.total, 1, 'the web server; the browser at its IP is network evidence, not "runs"');
  const e = edge(r, 'runs_app', `asset:${ids.asset}`, appNode(APP.web))!;
  assert.ok(e, 'asset -> runs -> application');
  assert.equal(e.style, 'recorded');
  assert.equal(e.origin, 'inventory');
  assert.deepEqual(e.versions, ['1.24.0', '1.25.3'], 'oldest first');
  assert.deepEqual(e.sources, ['service_scan', 'syslog_program'], 'its id and its host name');
  assert.equal(e.count, 42);
  assert.ok(e.first_seen && e.last_seen);
  assert.ok(!r.nodes.some((n) => n.id === appNode(APP.browser)));
  const node = r.nodes.find((n) => n.id === appNode(APP.web))!;
  assert.equal(node.label, `Webserv ${tag}`);
});

test('a logging host, a sender IP and a shipper run applications; a client IP uses them, marked network evidence', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  graphCache.clear();
  const host = await nbr('analyst', `host:${HOST}`);
  assert.ok(edge(host, 'runs_app', `host:${HOST}`, appNode(APP.web)), 'host -> runs');
  const sender = await nbr('analyst', `ip:${IP.sender}`);
  assert.equal(group(sender, 'runs_app')?.total, 1);
  assert.ok(edge(sender, 'runs_app', `ip:${IP.sender}`, appNode(APP.web)), 'sender ip -> runs');
  assert.equal(group(sender, 'uses_app')?.total, 0);
  const shipper = await nbr('analyst', `shipper:${ids.shipper}`);
  const containers = edge(shipper, 'runs_app', `shipper:${ids.shipper}`, appNode(APP.db))!;
  assert.deepEqual([containers.sources, containers.versions], [['container'], ['16.2']]);
  assert.equal(group(shipper, 'runs_app')?.total, 2);

  const client = await nbr('viewer', `ip:${IP.client}`);
  const uses = group(client, 'uses_app')!;
  assert.equal(uses.total, 2);
  const browser = edge(client, 'uses_app', `ip:${IP.client}`, appNode(APP.browser))!;
  assert.equal(browser.network, true);
  assert.equal(browser.style, 'recorded');
  assert.deepEqual(browser.sources, ['user_agent']);
  assert.equal(edge(client, 'uses_app', `ip:${IP.client}`, appNode(APP.saas))?.network, true);
  // The asset's IP uses the browser; the asset itself does not "run" it.
  const assetIp = await nbr('viewer', `ip:${IP.asset}`);
  assert.ok(edge(assetIp, 'uses_app', `ip:${IP.asset}`, appNode(APP.browser)));
});

test("an application: its facts (the allow-list), locations by kind, vulnerabilities exact and best effort", async (t) => {
  if (!dbReady) return t.skip(SKIP);
  graphCache.clear();
  const r = await nbr('viewer', appNode(APP.web));
  assert.equal(r.center.exists, true);
  assert.equal(r.center.type, 'application');
  assert.deepEqual(r.center.facts, {
    name: `Webserv ${tag}`,
    vendor: `Acme ${tag}`,
    category: 'web-server',
    versions: '1.24.0, 1.25.3',
    locations: 5,
    open_vulns: 2,
  });
  assert.deepEqual(r.center.flags, ['open_vulns']);
  const totals = Object.fromEntries(r.groups.map((g) => [g.rel, g.total]));
  assert.deepEqual(totals, { app_assets: 1, app_hosts: 2, app_ips: 1, app_shippers: 1, app_clients: 0, app_vulns: 2 });
  // The same edge as from the asset's side: one id.
  const asset = edge(r, 'runs_app', `asset:${ids.asset}`, appNode(APP.web))!;
  assert.deepEqual(asset.sources, ['service_scan', 'syslog_program']);
  assert.ok(edge(r, 'runs_app', `host:${ASSET_HOST}`, appNode(APP.web)), 'the logging host by name, too');
  assert.ok(edge(r, 'runs_app', `ip:${IP.sender}`, appNode(APP.web)));
  assert.ok(edge(r, 'runs_app', `shipper:${ids.shipper}`, appNode(APP.web)));
  const exact = edge(r, 'app_vulns', appNode(APP.web), `vuln:${ids.vulnExact}`)!;
  assert.deepEqual([exact.match, exact.style, exact.count, exact.versions], ['exact', 'recorded', 1, ['1.24.0']]);
  const product = edge(r, 'app_vulns', appNode(APP.web), `vuln:${ids.vulnProduct}`)!;
  assert.deepEqual([product.match, product.style], ['best_effort', 'heuristic']);
  // Exact first.
  const vulnOrder = r.edges.filter((e) => e.rel === 'app_vulns').map((e) => e.match);
  assert.deepEqual(vulnOrder, ['exact', 'best_effort']);

  // From the vulnerability's side.
  const vuln = await nbr('viewer', `vuln:${ids.vulnProduct}`);
  assert.equal(group(vuln, 'vuln_apps')?.total, 1);
  assert.equal(edge(vuln, 'app_vulns', appNode(APP.web), `vuln:${ids.vulnProduct}`)?.match, 'best_effort');

  // Seen only on the network: unmanaged.
  const saas = await nbr('viewer', appNode(APP.saas));
  assert.deepEqual(saas.center.flags, ['unmanaged']);
  assert.equal(saas.center.facts.versions, null);
});

test('caps: an application on 502 clients is a very-common group of 5, paged and searchable; the answer stays small', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  graphCache.clear();
  const r = await nbr('viewer', appNode(APP.browser));
  const clients = group(r, 'app_clients')!;
  assert.deepEqual([clients.total, clients.total_capped, clients.shown, clients.very_common], [502, false, 5, true]);
  assert.ok(r.nodes.length <= 1 + 5 * r.groups.length, `${r.nodes.length} nodes`);
  assert.equal(r.edges.filter((e) => e.rel === 'uses_app').length, 5);
  // Latest seen first: the two named clients (an hour ago), then the 500 by minutes.
  const page = await call('viewer', `/api/graph/relation?entity=${encodeURIComponent(appNode(APP.browser))}&rel=app_clients&limit=50&offset=0`);
  assert.equal(page.status, 200);
  assert.equal(page.json.items.length, 50);
  assert.equal(page.json.next_offset, 50);
  assert.equal(page.json.total, 502);
  assert.equal(page.json.items[0].node.id, `ip:${clientIp(1)}`, 'one minute ago');
  const found = await call('viewer', `/api/graph/relation?entity=${encodeURIComponent(appNode(APP.browser))}&rel=app_clients&q=${encodeURIComponent(IP.client)}`);
  assert.deepEqual(found.json.items.map((i: Json) => i.node.id), [`ip:${IP.client}`]);
  assert.equal(found.json.items[0].edge.network, true);
});

test('search: applications by name, vendor and id, only those in the inventory; every role', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  graphCache.clear();
  for (const role of ROLES) {
    const byName = (await call(role, `/api/graph/search?q=${encodeURIComponent(`Webserv ${tag}`)}`)).json;
    assert.ok(byName.candidates.some((c: Json) => c.entity === appNode(APP.web) && c.type === 'application'), `${role}: by name`);
  }
  const byVendor = (await call('viewer', `/api/graph/search?q=${encodeURIComponent(`acme ${tag}`)}`)).json;
  const entities = byVendor.candidates.map((c: Json) => c.entity);
  assert.ok(entities.includes(appNode(APP.web)), 'by vendor');
  assert.ok(!entities.includes(appNode(APP.orphan)), 'not a signature nothing was seen for');
  const hint = byVendor.candidates.find((c: Json) => c.entity === appNode(APP.web)).hint;
  assert.match(hint, /^application · Acme .* · 5 locations · 2 open vulns$/);
  // Host-like (one word): the id prefix finds it too.
  const byId = (await call('viewer', `/api/graph/search?q=cg${tag}-d`)).json;
  assert.ok(byId.candidates.some((c: Json) => c.entity === appNode(APP.db)));
  // A literal, and an unknown one.
  const literal = (await call('viewer', `/api/graph/search?q=${encodeURIComponent(appNode(APP.saas))}`)).json;
  assert.deepEqual(literal.candidates.map((c: Json) => c.entity), [appNode(APP.saas)]);
});

test('every role sees and expands applications; unknown -> exists:false; a bad id -> 400', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  graphCache.clear();
  for (const role of ROLES) {
    const r = await nbr(role, appNode(APP.web));
    assert.equal(r.center.expandable, true, role);
    assert.ok(r.groups.some((g) => g.rel === 'app_vulns' && g.total === 2), role);
  }
  const unknown = await nbr('viewer', `application:cg${tag}-nope`);
  assert.equal(unknown.center.exists, false);
  assert.deepEqual(unknown.groups, []);
  for (const bad of ['application:Not An Id', 'application:-x', `application:${'a'.repeat(65)}`]) {
    assert.equal((await call('viewer', `/api/graph/neighborhood?entity=${encodeURIComponent(bad)}`)).status, 400, bad);
  }
});
