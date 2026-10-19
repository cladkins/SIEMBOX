/**
 * The Big Display's privacy canary, against a real Postgres through the real
 * app (docs/architecture/BIG-DISPLAY.md §7.8, §13 PR 3).
 *
 * - Seeds alerts whose titles, descriptions and matched_data carry personal
 *   data (a username, an email address, a title, a country name), among them
 *   a leaked-credentials and a default-password alert; an exposure finding
 *   for the email address, a lookalike domain, raw logs with a marker, and a
 *   direct sender (with a host name) that went silent. Then fetches the
 *   screen's snapshot, the admin preview and the saved-link snapshot in both
 *   privacy modes, and the signed-in board as a viewer and as an admin. None
 *   ever carries the personal data; public mode carries no address or host
 *   name either; operations mode does show the address and the host (so the
 *   seed is known to reach the panels); every panel passes the shape check.
 * - The admin preview and saved-link snapshot don't count as the link's use;
 *   a screen's fetch does (written after the response, so polled).
 * - Plan shapes: no display statement scans raw_logs or parsed_logs
 *   sequentially when an index can serve it, and the open-alerts panel uses
 *   idx_alerts_open_severity.
 *
 * Skips itself when Postgres (with migrations 041 and 042) isn't reachable.
 * What it creates is removed again (bd3-<tag>-...; 198.51.100.77 is the
 * canary sender). Its display links are live while it runs, so it holds the
 * display test lock shared throughout, as displayIndependence.db.test.ts
 * does (displayLinks.db.test.ts counts every live link under it, exclusive).
 * Run with `npm test` (tsx --test).
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';

const SKIP = 'Postgres with migrations 041 and 042 is not reachable';
const DISPLAY_TEST_LOCK = 42_042_042;
let lockClient: import('pg').PoolClient | null = null;
const tag = crypto.randomBytes(4).toString('hex');
const CANARY_IP = '198.51.100.77';
const CANARY_HOST = `canary-host-${tag}`;
/** Never in any snapshot, in any mode. */
const NEVER = ['canary-user', 'canary@example.com', 'CANARY-TITLE', 'CANARY-MSG', 'canary-lookalike.test', 'CANARY-LAND', 'CanaryBreach', 'CANARY-DESC'];

let dbReady = false;
let pool: typeof import('../config/database').default;
let closePools: () => Promise<void>;
let server: http.Server | null = null;
let port = 0;
let adminToken = '';
let viewerToken = '';
const userIds: number[] = [];
const linkIds: number[] = [];
const cleanup: Array<() => Promise<unknown>> = [];

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- assertions read whatever the API sent
type Json = Record<string, any>;

function call(method: string, path: string, opts: { token?: string; display?: string; body?: unknown } = {}): Promise<{ status: number; body: Json; text: string }> {
  const payload = opts.body === undefined ? undefined : JSON.stringify(opts.body);
  const headers: Record<string, string> = {};
  if (payload !== undefined) {
    headers['Content-Type'] = 'application/json';
    headers['Content-Length'] = String(Buffer.byteLength(payload));
  }
  if (opts.token) headers.Authorization = `Bearer ${opts.token}`;
  if (opts.display) headers['X-Display-Token'] = opts.display;
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path, headers, agent: false }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let body: Json;
        try {
          body = JSON.parse(text);
        } catch {
          body = { text };
        }
        resolve({ status: res.statusCode ?? 0, body, text });
      });
    });
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

const OPS_PANELS = [
  [{ id: 'open_alerts' }, { id: 'alert_pulse' }, { id: 'recent_alerts', min_severity: 'medium' }, { id: 'top_rules', window_hours: 24 }, { id: 'ingest' }, { id: 'sources', silent_after_minutes: 15 }],
  [{ id: 'shippers' }, { id: 'threat_map', window_days: 1 }, { id: 'top_sources' }, { id: 'digital_risk' }, { id: 'vulnerabilities' }],
];
const PUBLIC_PANELS = OPS_PANELS.map((view) => view.filter((p) => p.id !== 'top_rules' && p.id !== 'top_sources'));
const configFor = (privacy: 'operations' | 'public') => ({
  privacy,
  views: (privacy === 'public' ? PUBLIC_PANELS : OPS_PANELS).map((panels, i) => ({ title: `View ${i + 1}`, panels })),
});

before(async () => {
  const db = await import('../config/database');
  pool = db.default;
  closePools = db.closePools;
  try {
    await pool.query('SELECT 1 FROM display_links LIMIT 1');
    await pool.query('SELECT 1 FROM ingest_source_minute LIMIT 1');
    dbReady = true;
  } catch {
    return;
  }
  lockClient = await pool.connect();
  await lockClient.query('SELECT pg_advisory_lock_shared($1)', [DISPLAY_TEST_LOCK]);
  const { logger } = await import('../utils/logger');
  for (const transport of logger.transports) transport.silent = true;
  const { UserModel } = await import('../models/User');
  const { SessionModel } = await import('../models/Session');
  const password = `pw-${crypto.randomBytes(9).toString('hex')}`;
  for (const role of ['admin', 'viewer'] as const) {
    const user = await UserModel.create({ username: `bd3-${tag}-${role}`, email: `bd3-${tag}-${role}@siembox.invalid`, password, role, enabled: true, requirePasswordChange: null });
    userIds.push(user.id);
    const token = (await SessionModel.create(user.id)).token;
    if (role === 'admin') adminToken = token;
    else viewerToken = token;
  }

  const q = (sql: string, params: unknown[] = []) => pool.query(sql, params);
  const rule = await q(
    `INSERT INTO detection_rules (name, severity, rule_yaml, rule_logic, enabled) VALUES ($1, 'critical', 'x', '{}', false) RETURNING id`,
    [`bd3-${tag} Port scan`]
  );
  const ruleId = rule.rows[0].id;
  const md = { source_ip: CANARY_IP, country_code: 'DE', country_name: 'CANARY-LAND', username: 'canary-user', email: 'canary@example.com' };
  const alerts = await q(
    `INSERT INTO alerts (rule_id, severity, title, description, matched_data, status, source) VALUES
       ($1, 'critical', 'CANARY-TITLE canary-user logged in', 'CANARY-DESC canary@example.com', $2, 'new', NULL),
       (NULL, 'high', 'canary@example.com found in CanaryBreach breach', 'CANARY-DESC', '{"account":"canary@example.com","breach":"CanaryBreach"}', 'new', 'leaked-creds'),
       (NULL, 'high', 'canary-user uses SIEMBox''s default password', 'CANARY-DESC', '{"username":"canary-user"}', 'investigating', 'siembox-auth'),
       (NULL, 'medium', 'Lookalike canary-lookalike.test registered', 'CANARY-DESC', '{"domain":"canary-lookalike.test","country_name":"CANARY-LAND"}', 'new', 'domain-monitor')
     RETURNING id`,
    [ruleId, md]
  );
  const alertIds = alerts.rows.map((r) => r.id);
  const identity = await q(`INSERT INTO monitored_identities (kind, value) VALUES ('email', $1) RETURNING id`, [`canary-${tag}@example.com`]);
  const domain = await q(`INSERT INTO watched_domains (domain, scope) VALUES ($1, 'own') RETURNING id`, [`bd3-${tag}.test`]);
  const findings = await q(
    `INSERT INTO exposure_findings (source, identity_id, domain_id, event_type, fingerprint, title, severity, detail) VALUES
       ('leaked-creds', $1, NULL, 'breach', $3, 'canary@example.com in CanaryBreach', 'high',
        '{"account":"canary@example.com","breach_name":"CanaryBreach","data_classes":["Passwords"]}'),
       ('domain-monitor', NULL, $2, 'lookalike', $4, 'canary-lookalike.test', 'medium', '{"domain":"canary-lookalike.test"}')
     RETURNING id`,
    [identity.rows[0].id, domain.rows[0].id, `bd3-${tag}-breach`, `bd3-${tag}-lookalike`]
  );
  const raw = await q(
    `INSERT INTO raw_logs (timestamp, raw_message, source_ip, hostname) VALUES (NOW(), 'CANARY-MSG canary-user failed password', $1, $2) RETURNING id`,
    [CANARY_IP, CANARY_HOST]
  );
  const asset = await q(`INSERT INTO assets (ip_address, hostname) VALUES ($1, $2) RETURNING id`, [CANARY_IP, CANARY_HOST]);
  // A steady direct sender (5 logs a minute for a day) that stopped 30 minutes ago: listed first, as silent.
  await q(
    `INSERT INTO ingest_source_minute (minute, source_kind, source_key, logs, established)
     SELECT m, 'direct', $1, 5, true
       FROM generate_series(date_trunc('minute', NOW()) - INTERVAL '1440 minutes', date_trunc('minute', NOW()) - INTERVAL '30 minutes', INTERVAL '1 minute') AS m
     ON CONFLICT DO NOTHING`,
    [CANARY_IP]
  );
  cleanup.push(
    () => q('DELETE FROM alerts WHERE id = ANY($1)', [alertIds]),
    () => q('DELETE FROM detection_rules WHERE id = $1', [ruleId]),
    () => q('DELETE FROM exposure_findings WHERE id = ANY($1)', [findings.rows.map((r) => r.id)]),
    () => q('DELETE FROM monitored_identities WHERE id = $1', [identity.rows[0].id]),
    () => q('DELETE FROM watched_domains WHERE id = $1', [domain.rows[0].id]),
    () => q('DELETE FROM raw_logs WHERE id = $1', [raw.rows[0].id]),
    () => q('DELETE FROM assets WHERE id = $1', [asset.rows[0].id]),
    () => q(`DELETE FROM ingest_source_minute WHERE source_kind = 'direct' AND source_key = $1`, [CANARY_IP])
  );

  const app = (await import('../app')).default;
  const { createApiServer } = await import('../net/apiListeners');
  server = createApiServer(app);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  port = (server.address() as AddressInfo).port;
});

after(async () => {
  if (server) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server!.close(() => resolve()));
  }
  if (dbReady) {
    for (const step of cleanup.splice(0).reverse()) await step();
    await pool.query(`DELETE FROM audit_logs WHERE resource_type = 'display_link' AND resource_id = ANY($1)`, [linkIds]);
    await pool.query('DELETE FROM display_links WHERE id = ANY($1)', [linkIds]);
    await pool.query('DELETE FROM audit_logs WHERE user_id = ANY($1)', [userIds]);
    await pool.query('DELETE FROM users WHERE id = ANY($1)', [userIds]);
  }
  if (lockClient) {
    await lockClient.query('SELECT pg_advisory_unlock_shared($1)', [DISPLAY_TEST_LOCK]);
    lockClient.release();
  }
  await closePools();
});

async function createLink(privacy: 'operations' | 'public', name: string = privacy): Promise<{ id: number; token: string }> {
  const res = await call('POST', '/api/display-links', { token: adminToken, body: { name: `bd3-${tag}-${name}`, config: configFor(privacy) } });
  assert.equal(res.status, 201, JSON.stringify(res.body));
  linkIds.push(res.body.link.id);
  return { id: res.body.link.id, token: res.body.token };
}

/** Every string leaf of a value, with its path. */
function strings(value: unknown, path = '', out: Array<[string, string]> = []): Array<[string, string]> {
  if (typeof value === 'string') out.push([path, value]);
  else if (Array.isArray(value)) value.forEach((v, i) => strings(v, `${path}[${i}]`, out));
  else if (value && typeof value === 'object') for (const [k, v] of Object.entries(value)) strings(v, `${path}.${k}`, out);
  return out;
}

async function assertClean(what: string, res: { status: number; body: Json; text: string }, privacy: 'operations' | 'public') {
  assert.equal(res.status, 200, `${what}: ${res.text.slice(0, 300)}`);
  for (const marker of NEVER) assert.ok(!res.text.includes(marker), `${what}: carries ${marker}`);
  if (privacy === 'public') {
    assert.ok(!res.text.includes(CANARY_IP), `${what}: an address on a public-area display`);
    assert.ok(!res.text.includes(CANARY_HOST), `${what}: a host name on a public-area display`);
  }
  const { envelopeProblem } = await import('../services/display/redact');
  for (const [key, envelope] of Object.entries(res.body.panels as Json)) {
    assert.ok(['ok', 'not_configured', 'forbidden'].includes(envelope.state), `${what}: ${key} is ${JSON.stringify(envelope)}`);
    assert.equal(envelopeProblem(key, envelope, privacy), null, `${what}: ${key}`);
  }
  for (const [path, text] of strings(res.body.panels)) assert.ok(!text.includes('@'), `${what}: ${path} holds an @`);
}

test('no personal data on any display, in either mode; public mode shows no address or host name', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  for (const privacy of ['operations', 'public'] as const) {
    const { id, token } = await createLink(privacy);
    const screen = await call('GET', '/api/display/snapshot', { display: token });
    await assertClean(`${privacy} screen`, screen, privacy);
    await assertClean(`${privacy} preview`, await call('POST', '/api/display-links/preview', { token: adminToken, body: { config: configFor(privacy) } }), privacy);
    await assertClean(`${privacy} saved-link snapshot`, await call('GET', `/api/display-links/${id}/snapshot`, { token: adminToken }), privacy);
    const panels = screen.body.panels;
    assert.equal(panels.digital_risk.state, 'ok', 'Digital Risk is set up by the seed');
    assert.ok(panels.digital_risk.data.accounts_to_reset >= 1, 'the leaked account is counted, never named');
    assert.ok(panels['sources:15'].data.silent >= 1, 'the canary sender is silent');
    assert.ok(screen.body.attributions.includes('dbip') && screen.body.attributions.includes('hibp'));
    if (privacy === 'operations') {
      // The seed reaches the panels: what operations mode may show, it shows.
      assert.ok(panels.top_sources.data.items.some((i: Json) => i.ip === CANARY_IP && i.country_code === 'DE'), 'the alerting address');
      assert.ok(panels['sources:15'].data.rows.some((r: Json) => r.label === CANARY_HOST && r.state === 'silent'), 'the silent sender by host name');
      assert.ok(panels['recent_alerts:medium'].data.items.some((i: Json) => i.label === `bd3-${tag} Port scan`), 'the rule name');
      assert.ok(panels['recent_alerts:medium'].data.items.some((i: Json) => i.label === 'Leaked credentials'));
    } else {
      assert.deepEqual(panels['sources:15'].data.rows, []);
      assert.ok(panels['recent_alerts:medium'].data.items.every((i: Json) => i.label !== `bd3-${tag} Port scan`));
    }
  }
});

test('signed in: a viewer gets endpoints forbidden, an admin gets endpoint health; neither gets personal data', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const viewer = await call('GET', '/api/big-display/snapshot', { token: viewerToken });
  await assertClean('viewer board', viewer, 'operations');
  assert.equal(viewer.body.display.name, 'Big Display');
  assert.deepEqual(viewer.body.panels.endpoints, { state: 'forbidden' });
  const admin = await call('GET', '/api/big-display/snapshot', { token: adminToken });
  await assertClean('admin board', admin, 'operations');
  assert.notEqual(admin.body.panels.endpoints.state, 'forbidden');
  assert.equal((await call('GET', '/api/big-display/snapshot')).status, 401, 'a login is needed');
});

test('previews are not a screen: only a screen fetch records the link as used', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const { id, token } = await createLink('public', 'preview');
  const used = async () => (await pool.query('SELECT last_used_at FROM display_links WHERE id = $1', [id])).rows[0].last_used_at;
  assert.equal((await call('GET', `/api/display-links/${id}/snapshot`, { token: adminToken })).status, 200);
  assert.equal((await call('POST', '/api/display-links/preview', { token: adminToken, body: { config: configFor('public') } })).status, 200);
  assert.equal((await call('GET', `/api/display-links/${id}/snapshot`, { token: viewerToken })).status, 403, 'admins only');
  assert.equal((await call('POST', '/api/display-links/preview', { token: adminToken, body: { config: { views: [] } } })).body.code, 'DISPLAY_CONFIG_INVALID');
  assert.equal((await call('POST', '/api/display-links/preview', { token: adminToken, body: { config: configFor('public'), name: 'x' } })).body.field, 'name');
  assert.equal((await call('GET', '/api/display-links/999999999/snapshot', { token: adminToken })).status, 404);
  await new Promise((resolve) => setTimeout(resolve, 300));
  assert.equal(await used(), null, 'previews leave last_used_at alone');
  assert.equal((await pool.query('SELECT COUNT(*)::int AS n FROM display_link_clients WHERE link_id = $1', [id])).rows[0].n, 0);
  assert.equal((await call('GET', '/api/display/snapshot', { display: token })).status, 200);
  // The use is recorded after the response: poll for it (CI runners are slower).
  const deadline = Date.now() + 10_000;
  while ((await used()) === null && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 50));
  assert.notEqual(await used(), null, 'a screen fetch is a use');
});

test('plan shapes: no display statement scans raw_logs or parsed_logs, and open alerts use idx_alerts_open_severity', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const { SQL, SQL_PARAMS } = await import('../services/display/panels');
  const client = await pool.connect();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- EXPLAIN's JSON plan tree
  const nodes = (plan: any): any[] => [plan, ...((plan.Plans ?? []) as unknown[]).flatMap(nodes)];
  try {
    await client.query('BEGIN READ ONLY');
    // With sequential scans priced out, one still appears only where no index can serve.
    await client.query('SET LOCAL enable_seqscan = off');
    for (const [name, sql] of Object.entries(SQL)) {
      const params = (SQL_PARAMS as Record<string, unknown[]>)[name] ?? [];
      const explained = await client.query(`EXPLAIN (FORMAT JSON) ${sql}`, params);
      const all = nodes(explained.rows[0]['QUERY PLAN'][0].Plan);
      const scans = all.filter((n) => n['Node Type'] === 'Seq Scan' && ['raw_logs', 'parsed_logs'].includes(n['Relation Name']));
      assert.deepEqual(scans, [], `${name} scans ${scans.map((s) => s['Relation Name']).join(', ')}`);
      if (name === 'open_alerts') {
        assert.ok(all.some((n) => n['Index Name'] === 'idx_alerts_open_severity'), `open_alerts plan: ${all.map((n) => n['Node Type'] + ' ' + (n['Index Name'] ?? '')).join(' / ')}`);
      }
    }
    await client.query('COMMIT');
  } finally {
    client.release();
  }
});
