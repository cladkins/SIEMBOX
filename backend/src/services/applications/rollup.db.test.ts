/**
 * The application inventory rollup (migration 048) against a real Postgres.
 *
 * Each test runs in its own schema (app_rollup_<tag>) holding empty copies of
 * every table the rollup reads or writes (and the location view), put first
 * on the rollup's search_path; the key functions come from public. So the
 * rollup sees only these fixtures and no other DB test sees it. Dropped in
 * `after`.
 *
 * Covers: log evidence (programs on the logging host, parsers, user agents and
 * DNS queries by client) with exact counts; the parsed_logs cursor and the
 * backfill start; a crashed batch and two concurrent runners count nothing
 * twice; unmatched programs, user-agent products and images; snapshot sources
 * (nmap services, shipper containers, EDR packages and OS) and that an
 * upgraded image or package replaces its row at once (no false drift);
 * endpoint installed packages (endpoint_sbom) on the agent's asset, gone
 * with the snapshot that drops them;
 * vulnerability links, exact by package and best effort by product; the
 * retention prune and the unmatched cap; signatures stored for the page and
 * as the catalog fallback. Skips itself without Postgres.
 */
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import pool, { closePools } from '../../config/database';
import { runInventoryRollup, loadStoredSignatures, clearInventoryIndexCache, type RollupClient, DEFAULT_INVENTORY_SETTINGS, type InventorySettings } from './rollup';
import { signaturesFrom, type AppCatalog } from './appCatalog';
import { validateApplication, type AppSignature } from './appFormat';

const SKIP = 'Postgres with the SIEMBox schema is not reachable';
const schema = `app_rollup_${crypto.randomBytes(4).toString('hex')}`;
let ready = false;

const TABLES = [
  'raw_logs', 'parsed_logs', 'parsers', 'assets', 'asset_services', 'log_shippers', 'shipper_containers', 'vulnerabilities',
  'asset_vulnerabilities', 'edr_agents', 'edr_agent_packages', 'edr_agent_package_snapshots', 'application_inventory', 'application_unmatched', 'application_vuln_links',
  'application_signatures', 'application_inventory_state', 'custom_application_signatures', 'application_unmatched_ignores',
];

async function connect(): Promise<RollupClient> {
  const client = await pool.connect();
  await client.query(`SET search_path TO ${schema}, public`);
  return {
    query: (sql, params) => client.query(sql, params as unknown[]),
    release: (err) => {
      void client
        .query('RESET search_path')
        .catch(() => undefined)
        .finally(() => client.release(err));
    },
  };
}

const sig = (doc: Record<string, unknown>): AppSignature => {
  const v = validateApplication({ schema: 'siembox.app/v1', vendor: 'Test', category: 'web-server', ...doc });
  assert.ok(v.ok, v.errors.join('; '));
  return v.app!;
};
const SIGNATURES: AppSignature[] = [
  sig({ id: 'openssh', name: 'OpenSSH', category: 'remote-access', match: { syslog_program: ['sshd'], parser: ['ssh-authentication'], package: ['openssh-server'] } }),
  sig({ id: 'postfix', name: 'Postfix', category: 'mail', match: { syslog_program: ['postfix/*'] } }),
  sig({ id: 'nginx', name: 'nginx', cpe: { vendor: 'f5', product: 'nginx' }, match: { container_image: ['nginx'], parser: ['standard-nginx-access'] } }),
  sig({ id: 'postgresql', name: 'PostgreSQL', category: 'database', match: { service: { names: ['postgresql'] }, container_image: ['postgres'] } }),
  sig({ id: 'firefox', name: 'Firefox', category: 'browser', match: { user_agent: ['\\bFirefox/(\\d+(?:\\.\\d+)*)'] } }),
  sig({ id: 'zoom', name: 'Zoom', category: 'saas', match: { dns: ['zoom.us'] } }),
  sig({ id: 'ubuntu', name: 'Ubuntu', category: 'operating-system', match: { os: { family: 'linux', pretty_name: '^Ubuntu (\\d+\\.\\d+)' } } }),
  sig({ id: 'grafana', name: 'Grafana', category: 'monitoring', match: { container_image: ['grafana/grafana'] } }),
];
const CATALOG: AppCatalog = { source: 'catalog', repo: 'test/catalog', ref: 'main', apps: SIGNATURES, invalid: [], fetched_at: '2026-10-01T00:00:00.000Z', error: null };
const noGate = async () => ({ skip: new Set<string>(), refused: [] });
const settings = (over: Partial<InventorySettings> = {}): InventorySettings => ({ ...DEFAULT_INVENTORY_SETTINGS, ...over });
const run = (over: Partial<Parameters<typeof runInventoryRollup>[0]> = {}) =>
  runInventoryRollup({ connect, settings: settings(), catalog: CATALOG, gate: noGate, lag: '0 seconds', pauseRatio: 0, ...over });

let nextId = 1;
interface Log {
  app?: string | null;
  parser?: number | null;
  data?: Record<string, unknown>;
  hostname?: string | null;
  sender?: string;
  eventType?: string | null;
  ago?: string;
}
async function insertLogs(logs: Log[]): Promise<void> {
  for (const log of logs) {
    const id = nextId++;
    const sender = log.sender ?? '10.0.0.2';
    await pool.query(
      `INSERT INTO ${schema}.raw_logs (id, timestamp, raw_message, source_ip, hostname, app_name, created_at)
       VALUES ($1, NOW(), 'msg', $2, $3, $4, NOW() - $5::interval)`,
      [id, sender, log.hostname === undefined ? 'web01' : log.hostname, log.app ?? null, log.ago ?? '10 minutes']
    );
    await pool.query(
      `INSERT INTO ${schema}.parsed_logs (id, raw_log_id, parser_id, parsed_data, timestamp, source_ip, event_type, created_at)
       VALUES ($1, $1, $2, $3, NOW(), $4, $5, NOW() - $6::interval)`,
      [id, log.parser ?? null, JSON.stringify({ observer_ip: sender, source_ip: sender, ...(log.data ?? {}) }), sender, log.eventType ?? null, log.ago ?? '10 minutes']
    );
  }
}

type Row = { app_id: string; loc: string; source: string; version: string; events: number };
async function inventory(): Promise<Row[]> {
  const { rows } = await pool.query(
    `SELECT app_id, loc_type || ':' || loc_key AS loc, source, version, events::int AS events
       FROM ${schema}.application_inventory ORDER BY 1, 2, 3, 4`
  );
  return rows;
}
const find = (rows: Row[], app: string, loc: string, source: string) => rows.filter((r) => r.app_id === app && r.loc === loc && r.source === source);
const state = async () => (await pool.query(`SELECT * FROM ${schema}.application_inventory_state`)).rows[0];

before(async () => {
  try {
    await pool.query('SELECT 1 FROM application_inventory_state LIMIT 1');
  } catch {
    return;
  }
  const client = await pool.connect();
  try {
    await client.query(`CREATE SCHEMA ${schema}`);
    for (const table of TABLES) {
      await client.query(`CREATE TABLE ${schema}.${table} (LIKE public.${table} INCLUDING DEFAULTS INCLUDING CONSTRAINTS INCLUDING INDEXES)`);
    }
    await client.query('SET search_path TO public');
    const def = (await client.query(`SELECT pg_get_viewdef('public.application_location_assets'::regclass) AS def`)).rows[0].def;
    await client.query(`SET search_path TO ${schema}, public`);
    await client.query(`CREATE VIEW ${schema}.application_location_assets AS ${def}`);
    await client.query('RESET search_path');
  } finally {
    client.release();
  }
  ready = true;
});

beforeEach(async () => {
  if (!ready) return;
  await pool.query(`TRUNCATE ${TABLES.map((t) => `${schema}.${t}`).join(', ')}`);
  await pool.query(`INSERT INTO ${schema}.application_inventory_state (id) VALUES (1)`);
  await pool.query(
    `INSERT INTO ${schema}.parsers (id, name, parser_type, pattern, field_mappings) VALUES
       (1, 'ssh-authentication', 'regex', 'x', '{}'), (2, 'standard-nginx-access', 'regex', 'x', '{}'), (3, 'pihole-query', 'regex', 'x', '{}')`
  );
  clearInventoryIndexCache();
  nextId = 1;
});

after(async () => {
  if (ready) await pool.query(`DROP SCHEMA ${schema} CASCADE`);
  await closePools();
});

const FIREFOX = 'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0';
const LOGS: Log[] = [
  // sshd on web01, parsed by the SSH parser: 3 logs
  ...[1, 2, 3].map(() => ({ app: 'sshd', parser: 1, hostname: 'Web01' })),
  // postfix/smtpd on mail01 (no parser)
  { app: 'postfix/smtpd', hostname: 'mail01' },
  { app: 'postfix/qmgr', hostname: 'mail01' },
  // an unknown program twice, on two hosts
  { app: 'mystery-daemon', hostname: 'web01' },
  { app: 'mystery-daemon', hostname: null, sender: '10.0.0.9' },
  // nginx access logs carrying user agents from two clients
  { app: 'nginx', parser: 2, data: { source_ip: '203.0.113.5', user_agent: FIREFOX } },
  { app: 'nginx', parser: 2, data: { source_ip: '203.0.113.5', user_agent: FIREFOX } },
  { app: 'nginx', parser: 2, data: { source_ip: '203.0.113.6', user_agent: 'python-requests/2.31.0' } },
  // a user agent from the sender itself (fieldNormalizer's fallback): no client
  { app: 'nginx', parser: 2, data: { user_agent: FIREFOX } },
  // Pi-hole queries
  { app: 'dnsmasq', parser: 3, eventType: 'dns_query', data: { source_ip: '192.168.1.50', domain: 'us04web.zoom.us' } },
  { app: 'dnsmasq', parser: 3, eventType: 'dns_query', data: { source_ip: '192.168.1.50', domain: 'ZOOM.US.' } },
  // a domain on a non-DNS log is not a query
  { app: 'nginx', parser: 2, data: { source_ip: '203.0.113.7', domain: 'zoom.us' } },
];

test('log evidence: programs and parsers on the logging host, user agents and DNS by client', async (t) => {
  if (!ready) return t.skip(SKIP);
  await insertLogs(LOGS);
  const result = await run();
  assert.equal(result.consumed, LOGS.length);
  const rows = await inventory();
  assert.deepEqual(find(rows, 'openssh', 'host:web01', 'syslog_program').map((r) => r.events), [3], 'header host lower-cased');
  assert.deepEqual(find(rows, 'openssh', 'host:web01', 'parser').map((r) => r.events), [3]);
  assert.deepEqual(find(rows, 'postfix', 'host:mail01', 'syslog_program').map((r) => r.events), [2], 'postfix/* covers smtpd and qmgr');
  assert.deepEqual(find(rows, 'nginx', 'host:web01', 'parser').map((r) => r.events), [5]);
  assert.deepEqual(find(rows, 'firefox', 'client:203.0.113.5', 'user_agent').map((r) => [r.version, r.events]), [['121.0', 2]]);
  assert.equal(rows.filter((r) => r.app_id === 'firefox').length, 1, 'the sender-fallback user agent names no client');
  assert.deepEqual(find(rows, 'zoom', 'client:192.168.1.50', 'dns').map((r) => r.events), [2], 'domains normalized');
  assert.equal(rows.filter((r) => r.app_id === 'zoom').length, 1, 'a domain on a non-DNS log is not evidence');

  const { rows: unmatched } = await pool.query(`SELECT source, value, events::int AS events, locations FROM ${schema}.application_unmatched ORDER BY 1, 2`);
  assert.deepEqual(
    unmatched.map((u) => [u.source, u.value, u.events]),
    [
      ['parser', 'pihole-query', 2],
      ['syslog_program', 'dnsmasq', 2],
      ['syslog_program', 'mystery-daemon', 2],
      ['syslog_program', 'nginx', 5],
      ['user_agent', 'python-requests', 1],
    ]
  );
  assert.equal(unmatched.find((u) => u.value === 'mystery-daemon').locations, 2, 'two locations in one batch');
  const s = await state();
  assert.equal(Number(s.last_parsed_log_id), LOGS.length);
  assert.equal(s.caught_up, true);
  assert.equal(s.signatures_count, SIGNATURES.length);

  // A second run with nothing new changes nothing.
  await run();
  assert.deepEqual(await inventory(), rows);
});

test('a crashed batch replays without double counting, and two runners count once', async (t) => {
  if (!ready) return t.skip(SKIP);
  await insertLogs(LOGS);
  let calls = 0;
  await assert.rejects(
    run({
      batchSize: 3,
      afterBatch: () => {
        if (++calls === 2) throw new Error('simulated crash');
      },
    })
  );
  assert.equal(Number((await state()).last_parsed_log_id), 6, 'two batches committed before the crash');
  await Promise.all([run({ batchSize: 2 }), run({ batchSize: 2 })]);
  const rows = await inventory();
  assert.deepEqual(find(rows, 'openssh', 'host:web01', 'syslog_program').map((r) => r.events), [3]);
  assert.deepEqual(find(rows, 'nginx', 'host:web01', 'parser').map((r) => r.events), [5]);
  assert.deepEqual(find(rows, 'zoom', 'client:192.168.1.50', 'dns').map((r) => r.events), [2]);
  const { rows: un } = await pool.query(`SELECT events::int AS events FROM ${schema}.application_unmatched WHERE value = 'mystery-daemon'`);
  assert.equal(un[0].events, 2);
  assert.equal(Number((await state()).last_parsed_log_id), LOGS.length);
});

test('the backfill starts N days back; logs inside the lag wait', async (t) => {
  if (!ready) return t.skip(SKIP);
  await insertLogs([{ app: 'sshd', ago: '20 days' }, { app: 'sshd', ago: '2 days' }, { app: 'sshd', ago: '1 second' }]);
  await run({ settings: settings({ backfillDays: 7 }), lag: '1 minute' });
  assert.deepEqual(find(await inventory(), 'openssh', 'host:web01', 'syslog_program').map((r) => r.events), [1], 'only the 2-day-old log');
  await run({ lag: '0 seconds' });
  assert.deepEqual(find(await inventory(), 'openssh', 'host:web01', 'syslog_program').map((r) => r.events), [2]);
});

async function seedSnapshots(): Promise<void> {
  await pool.query(
    `INSERT INTO ${schema}.assets (id, ip_address, hostname) VALUES (1, '10.0.0.2', 'web01'), (2, '10.0.0.3', 'db01'), (3, '10.0.0.4', 'nas01')`
  );
  // nmap: node-nmap fills service_name only (banner is the TLS tunnel, version empty).
  await pool.query(
    `INSERT INTO ${schema}.asset_services (asset_id, port, protocol, service_name, service_version, banner, state) VALUES
       (2, 5432, 'tcp', 'postgresql', NULL, NULL, 'open'), (2, 443, 'tcp', 'https', NULL, 'ssl', 'open'), (1, 22, 'tcp', 'ssh', NULL, NULL, 'open')`
  );
  await pool.query(`INSERT INTO ${schema}.log_shippers (id, name, api_key, ip_address, hostname) VALUES (7, 'nas shipper', 'k', '10.0.0.4', 'nas01')`);
  await pool.query(
    `INSERT INTO ${schema}.shipper_containers (shipper_id, image, container_names, running) VALUES
       (7, 'nginx:1.25.3-alpine', '["proxy"]', 1), (7, 'grafana/grafana:10.2.3', '["grafana"]', 1),
       (7, 'ghcr.io/acme/widget:2.0', '["widget"]', 1), (7, 'sha256:0123456789abcdef0123', '[]', 0)`
  );
  await pool.query(`INSERT INTO ${schema}.edr_agents (agent_id, api_key_hash, asset_id, os, os_version) VALUES ($1, 'h', 1, 'linux', 'Ubuntu 22.04.4 LTS')`, [crypto.randomUUID()]);
  await pool.query(
    `INSERT INTO ${schema}.vulnerabilities (id, cve_id, severity, title) VALUES
       (1, 'CVE-2024-6387', 'high', 'CVE-2024-6387 — openssh-server'), (2, 'CVE-2023-44487', 'high', 'nginx HTTP/2 Rapid Reset'),
       (3, 'CVE-2099-0001', 'low', 'Something unrelated')`
  );
  await pool.query(
    `INSERT INTO ${schema}.asset_vulnerabilities (asset_id, vulnerability_id, status, evidence) VALUES
       (1, 1, 'open', 'package=openssh-server installed=1:8.9p1-3ubuntu0.6 fixed=1:8.9p1-3ubuntu0.10 source=grype'),
       (3, 2, 'open', 'Template: CVE-2023-44487' || chr(10) || 'Matched at: https://10.0.0.4'),
       (3, 3, 'open', 'Template: x')`
  );
}

test('snapshot sources: services, containers, EDR packages and OS; vulnerability links; replaced at once', async (t) => {
  if (!ready) return t.skip(SKIP);
  await seedSnapshots();
  await run();
  let rows = await inventory();
  assert.deepEqual(find(rows, 'postgresql', 'asset:2', 'service_scan').map((r) => r.version), [''], 'by nmap service name');
  assert.equal(rows.filter((r) => r.source === 'service_scan').length, 1, 'ssh and https name no product');
  assert.deepEqual(find(rows, 'nginx', 'shipper:7', 'container').map((r) => r.version), ['1.25.3']);
  assert.deepEqual(find(rows, 'grafana', 'shipper:7', 'container').map((r) => r.version), ['10.2.3']);
  assert.deepEqual(find(rows, 'openssh', 'asset:1', 'edr_package').map((r) => r.version), ['1:8.9p1-3ubuntu0.6']);
  assert.deepEqual(find(rows, 'ubuntu', 'asset:1', 'os').map((r) => r.version), ['22.04']);
  const { rows: un } = await pool.query(`SELECT value, sample FROM ${schema}.application_unmatched WHERE source = 'container'`);
  assert.deepEqual(un.map((u) => [u.value, u.sample]), [['ghcr.io/acme/widget', 'ghcr.io/acme/widget:2.0']], 'a bare image id is no name');

  const { rows: links } = await pool.query(`SELECT app_id, asset_id, vulnerability_id, match, version FROM ${schema}.application_vuln_links ORDER BY 1, 3`);
  assert.deepEqual(links, [
    { app_id: 'nginx', asset_id: 3, vulnerability_id: 2, match: 'product', version: '' },
    { app_id: 'openssh', asset_id: 1, vulnerability_id: 1, match: 'package', version: '1:8.9p1-3ubuntu0.6' },
  ]);

  // Upgrade: the container moves to 1.26.0, the package is patched. The old rows go now, not in 30 days.
  await pool.query(`UPDATE ${schema}.shipper_containers SET image = 'nginx:1.26.0' WHERE image LIKE 'nginx:%'`);
  await pool.query(`UPDATE ${schema}.asset_vulnerabilities SET status = 'patched' WHERE vulnerability_id = 1`);
  await run();
  rows = await inventory();
  assert.deepEqual(find(rows, 'nginx', 'shipper:7', 'container').map((r) => r.version), ['1.26.0']);
  assert.equal(find(rows, 'openssh', 'asset:1', 'edr_package').length, 0);
  const { rows: after2 } = await pool.query(`SELECT app_id FROM ${schema}.application_vuln_links ORDER BY 1`);
  assert.deepEqual(after2.map((l) => l.app_id), ['nginx']);
});

test('endpoint installed packages: endpoint_sbom on the agent\'s asset, version from the package, gone when the snapshot drops it', async (t) => {
  if (!ready) return t.skip(SKIP);
  await pool.query(`INSERT INTO ${schema}.assets (id, ip_address, hostname) VALUES (1, '10.0.0.2', 'web01'), (2, '10.0.0.3', 'db01')`);
  const agent = crypto.randomUUID();
  const unlinked = crypto.randomUUID(); // no asset yet: contributes nothing
  await pool.query(`INSERT INTO ${schema}.edr_agents (agent_id, api_key_hash, asset_id) VALUES ($1, 'h', 2), ($2, 'h', NULL)`, [agent, unlinked]);
  await pool.query(
    `INSERT INTO ${schema}.edr_agent_packages (agent_id, type, name, version) VALUES
       ($1, 'deb', 'openssh-server', '1:9.6p1-3ubuntu13.5'), ($1, 'deb', 'libc6', '2.39-0ubuntu8'), ($1, 'deb', 'Nginx', '1.24.0-2ubuntu7'),
       ($2, 'deb', 'openssh-server', '1:8.0')`,
    [agent, unlinked]
  );
  await pool.query(`INSERT INTO ${schema}.edr_agent_package_snapshots (agent_id, snapshot_hash, package_count, reported_at) VALUES ($1, 'h1', 3, NOW())`, [agent]);
  // nginx has no package matcher in these signatures: only openssh matches.
  await run();
  let rows = await inventory();
  assert.deepEqual(rows.filter((r) => r.source === 'endpoint_sbom'), [
    { app_id: 'openssh', loc: 'asset:2', source: 'endpoint_sbom', version: '1:9.6p1-3ubuntu13.5', events: 1 },
  ]);
  const { rows: ev } = await pool.query(`SELECT evidence FROM ${schema}.application_inventory WHERE source = 'endpoint_sbom'`);
  assert.deepEqual(ev[0].evidence, { package: 'openssh-server', version: '1:9.6p1-3ubuntu13.5', type: 'deb' });
  const { rows: links } = await pool.query(`SELECT * FROM ${schema}.application_vuln_links`);
  assert.equal(links.length, 0, 'an installed package is no vulnerability');

  // Upgraded: the new snapshot has the new version only; the old row goes at once.
  await pool.query(`UPDATE ${schema}.edr_agent_packages SET version = '1:9.6p1-3ubuntu13.8' WHERE agent_id = $1 AND name = 'openssh-server'`, [agent]);
  await run();
  rows = await inventory();
  assert.deepEqual(find(rows, 'openssh', 'asset:2', 'endpoint_sbom').map((r) => r.version), ['1:9.6p1-3ubuntu13.8']);

  // Removed from the host: the next snapshot no longer has it.
  await pool.query(`DELETE FROM ${schema}.edr_agent_packages WHERE agent_id = $1 AND name = 'openssh-server'`, [agent]);
  await run();
  assert.equal((await inventory()).filter((r) => r.source === 'endpoint_sbom').length, 0);
});

test('retention prunes rows not seen for N days and caps the unmatched list', async (t) => {
  if (!ready) return t.skip(SKIP);
  await pool.query(
    `INSERT INTO ${schema}.application_inventory (app_id, loc_type, loc_key, source, version, events, first_seen, last_seen) VALUES
       ('openssh', 'host', 'old01', 'syslog_program', '', 5, NOW() - interval '40 days', NOW() - interval '31 days'),
       ('openssh', 'host', 'new01', 'syslog_program', '', 5, NOW() - interval '40 days', NOW() - interval '1 day')`
  );
  await pool.query(
    `INSERT INTO ${schema}.application_unmatched (source, value, events, first_seen, last_seen)
     SELECT 'syslog_program', 'p' || g, g, NOW(), NOW() FROM generate_series(1, 510) g
     UNION ALL SELECT 'user_agent', 'Stale', 1, NOW() - interval '40 days', NOW() - interval '40 days'`
  );
  const result = await run({ forcePrune: true });
  assert.ok(result.pruned >= 1 + 1 + 10);
  const rows = await inventory();
  assert.deepEqual(rows.map((r) => r.loc), ['host:new01']);
  const { rows: un } = await pool.query(`SELECT source, count(*)::int AS n, min(events)::int AS min FROM ${schema}.application_unmatched GROUP BY 1`);
  assert.deepEqual(un, [{ source: 'syslog_program', n: 500, min: 11 }], 'the 500 most frequent kept; the stale one gone');
  // Not again within the hour.
  assert.equal((await run()).pruned, 0);
});

test('the signature set is stored for the page and as the fallback', async (t) => {
  if (!ready) return t.skip(SKIP);
  await run();
  const { rows } = await pool.query(`SELECT id, name, category, source FROM ${schema}.application_signatures ORDER BY id`);
  assert.equal(rows.length, SIGNATURES.length);
  assert.ok(rows.every((r) => r.source === 'catalog'));
  const client = await connect();
  try {
    const stored = await loadStoredSignatures((sql, params) => client.query(sql, params));
    assert.ok(stored);
    assert.equal(signaturesFrom(stored.docs, 'stored').apps.length, SIGNATURES.length, 'the stored definitions validate');
    assert.equal(stored.fetched_at, CATALOG.fetched_at);
  } finally {
    client.release();
  }
  // A smaller set replaces it; the bundled source is never offered as "stored".
  await run({ catalog: { ...CATALOG, source: 'bundled', apps: SIGNATURES.slice(0, 2) } });
  const { rows: after2 } = await pool.query(`SELECT id, source FROM ${schema}.application_signatures ORDER BY id`);
  assert.deepEqual(after2.map((r) => r.id), ['openssh', 'postfix']);
  const client2 = await connect();
  try {
    assert.equal(await loadStoredSignatures((sql, params) => client2.query(sql, params)), null);
  } finally {
    client2.release();
  }
});

test('switched off: nothing is read or written', async (t) => {
  if (!ready) return t.skip(SKIP);
  await insertLogs(LOGS);
  const result = await run({ settings: settings({ enabled: false }) });
  assert.equal(result.status, 'disabled');
  assert.equal((await inventory()).length, 0);
  assert.equal((await state()).last_parsed_log_id, null);
});

// ---------------------------------------------------------------------------
// Local signatures (migration 051): applied to evidence already rolled up.
// ---------------------------------------------------------------------------

const WIDGET = sig({
  id: 'widget', name: 'Widget', category: 'automation',
  match: { syslog_program: ['widgetd'], user_agent: ['^WidgetClient/(\\d+(?:\\.\\d+)*)'], package: ['widget-agent'], dns: ['widgetapp.io'] },
});
const unmatchedValues = async (source?: string) =>
  (await pool.query(`SELECT source, value FROM ${schema}.application_unmatched ${source ? 'WHERE source = $1' : ''} ORDER BY 1, 2`, source ? [source] : [])).rows.map(
    (r) => `${r.source}:${r.value}`
  );

test('a new local signature matches logs the cursor already passed (look back), counting each log once', async (t) => {
  if (!ready) return t.skip(SKIP);
  // (In created_at order, as ingestion writes them.)
  await insertLogs([
    ...[1, 2, 3].map(() => ({ app: 'widgetd', hostname: 'web01', ago: '2 days' })),
    { app: 'nginx', parser: 2, data: { source_ip: '203.0.113.9', user_agent: 'WidgetClient/2.4.1' }, ago: '1 day' },
    { app: 'dnsmasq', parser: 3, eventType: 'dns_query', data: { source_ip: '192.168.1.60', domain: 'api.widgetapp.io' }, ago: '5 hours' },
    ...[1, 2].map(() => ({ app: 'widgetd', hostname: 'web02', ago: '3 hours' })),
  ]);
  await run();
  assert.equal((await inventory()).filter((r) => r.app_id === 'widget').length, 0);
  assert.deepEqual(await unmatchedValues('syslog_program'), ['syslog_program:dnsmasq', 'syslog_program:nginx', 'syslog_program:widgetd']);
  assert.deepEqual(await unmatchedValues('dns'), ['dns:widgetapp.io'], 'the registrable domain of an unmatched query');
  assert.deepEqual(await unmatchedValues('user_agent'), ['user_agent:WidgetClient']);

  // The signature is saved; one more widgetd log arrives before the next run.
  await insertLogs([{ app: 'widgetd', hostname: 'web01', ago: '1 minute' }]);
  const result = await run({ local: [WIDGET] });
  assert.equal(result.localSignatures, 1);
  assert.deepEqual(result.rescan.apps, ['widget'], 'new to the set and without rows: looked back for');
  const rows = await inventory();
  assert.deepEqual(find(rows, 'widget', 'host:web01', 'syslog_program').map((r) => r.events), [4], 'the new log (main cursor) and the three old ones (look back), once each');
  assert.deepEqual(find(rows, 'widget', 'host:web02', 'syslog_program').map((r) => r.events), [2]);
  assert.deepEqual(find(rows, 'widget', 'client:203.0.113.9', 'user_agent').map((r) => [r.version, r.events]), [['2.4.1', 1]]);
  assert.deepEqual(find(rows, 'widget', 'client:192.168.1.60', 'dns').map((r) => r.events), [1]);
  assert.deepEqual(await unmatchedValues('syslog_program'), ['syslog_program:dnsmasq', 'syslog_program:nginx'], 'what the new set matches leaves the list');
  assert.deepEqual(await unmatchedValues('dns'), []);
  assert.deepEqual(await unmatchedValues('user_agent'), []);
  const s = await state();
  assert.deepEqual(s.rescan_apps, []);
  assert.deepEqual(s.rescan_pending, []);
  const { rows: stored } = await pool.query(`SELECT source FROM ${schema}.application_signatures WHERE id = 'widget'`);
  assert.deepEqual(stored.map((r) => r.source), ['local']);

  // Nothing new: nothing changes, nothing is counted again.
  await run({ local: [WIDGET] });
  assert.deepEqual(await inventory(), rows);
});

test('the look back walks the backfill window in batches, and an edit adds only new locations', async (t) => {
  if (!ready) return t.skip(SKIP);
  await insertLogs([
    { app: 'sshd-session', hostname: 'old01', ago: '9 days' },
    ...[1, 2].map(() => ({ app: 'sshd-session', hostname: 'web03', ago: '2 days' })),
    ...[1, 2, 3, 4, 5].map(() => ({ app: 'sshd', hostname: 'web01', ago: '1 day' })),
  ]);
  await run();
  assert.deepEqual(find(await inventory(), 'openssh', 'host:web01', 'syslog_program').map((r) => r.events), [5]);
  // The backfill started 7 days back: old01's log is before the window.
  assert.deepEqual(await unmatchedValues('syslog_program'), ['syslog_program:sshd-session']);

  // A local override of openssh adds sshd-session; the save queues it.
  const edited = sig({ ...SIGNATURES.find((a) => a.id === 'openssh')!, match: { ...SIGNATURES.find((a) => a.id === 'openssh')!.match, syslog_program: ['sshd', 'sshd-session'] } });
  await pool.query(`UPDATE ${schema}.application_inventory_state SET rescan_pending = '{openssh}'`);
  const r1 = await run({ local: [edited], batchSize: 2, budgetMs: 60_000 });
  assert.deepEqual(r1.rescan.apps, ['openssh']);
  assert.equal(r1.rescan.consumed, 7, 'the 7 logs of the window, in batches of two');
  const rows = await inventory();
  assert.deepEqual(find(rows, 'openssh', 'host:web01', 'syslog_program').map((r) => r.events), [5], 'a location it already had keeps its count');
  assert.deepEqual(find(rows, 'openssh', 'host:web03', 'syslog_program').map((r) => r.events), [2], 'a new location gets its history');
  assert.equal(find(rows, 'openssh', 'host:old01', 'syslog_program').length, 0, 'outside the backfill window');
  assert.deepEqual(await unmatchedValues('syslog_program'), []);
});

test('the look back resumes across runs when the budget runs out, and none runs with the backfill off', async (t) => {
  if (!ready) return t.skip(SKIP);
  await insertLogs([...Array.from({ length: 6 }, () => ({ app: 'widgetd', hostname: 'web01', ago: '1 day' }))]);
  await run();
  let clock = 0;
  // Each batch "takes" 10 ms of a 15 ms budget: one look-back batch per run.
  const timed = (over: Partial<Parameters<typeof runInventoryRollup>[0]> = {}) =>
    run({ local: [WIDGET], batchSize: 2, budgetMs: 15, now: () => (clock += 5), ...over });
  const first = await timed();
  assert.equal(first.rescan.more, true);
  for (let i = 0; i < 10 && (await state()).rescan_apps.length > 0; i++) await timed();
  assert.deepEqual(find(await inventory(), 'widget', 'host:web01', 'syslog_program').map((r) => r.events), [6]);

  // Switched off (backfill 0 days): a queued signature is dropped, not looked back for.
  await pool.query(`UPDATE ${schema}.application_inventory_state SET rescan_pending = '{widget}'`);
  const off = await run({ local: [WIDGET], settings: settings({ backfillDays: 0 }) });
  assert.deepEqual(off.rescan.apps, []);
  const s = await state();
  assert.deepEqual(s.rescan_pending, []);
  assert.deepEqual(s.rescan_apps, []);
});

test('Not identified: parsers, nmap products, installed packages (system ones flagged), EDR findings; a local signature applies to snapshots at once', async (t) => {
  if (!ready) return t.skip(SKIP);
  await pool.query(`INSERT INTO ${schema}.assets (id, ip_address, hostname) VALUES (1, '10.0.0.2', 'web01'), (2, '10.0.0.3', 'db01')`);
  await pool.query(
    `INSERT INTO ${schema}.asset_services (asset_id, port, protocol, service_name, service_version, banner, state) VALUES
       (1, 8080, 'tcp', 'http', 'Acme Server 4.2.1 (Linux)', NULL, 'open'), (2, 8080, 'tcp', 'http', 'Acme Server 4.2.0', NULL, 'open'),
       (2, 9999, 'tcp', 'tcpwrapped', NULL, NULL, 'open'), (2, 5432, 'tcp', 'postgresql', NULL, NULL, 'open')`
  );
  const a1 = crypto.randomUUID();
  const a2 = crypto.randomUUID();
  await pool.query(`INSERT INTO ${schema}.edr_agents (agent_id, api_key_hash, asset_id) VALUES ($1, 'h', 1), ($2, 'h', 2)`, [a1, a2]);
  await pool.query(
    `INSERT INTO ${schema}.edr_agent_packages (agent_id, type, name, version) VALUES
       ($1, 'deb', 'widget-agent', '3.1.0'), ($2, 'deb', 'widget-agent', '3.0.9'), ($1, 'deb', 'libc6', '2.39'), ($1, 'deb', 'openssh-server', '1:9.6p1')`,
    [a1, a2]
  );
  await pool.query(`INSERT INTO ${schema}.vulnerabilities (id, cve_id, severity, title) VALUES (1, 'CVE-2099-1000', 'high', 'acme-lib flaw')`);
  await pool.query(`INSERT INTO ${schema}.asset_vulnerabilities (asset_id, vulnerability_id, status, evidence) VALUES (2, 1, 'open', 'package=acme-lib installed=0.9 fixed=1.0 source=grype')`);
  await insertLogs([{ app: 'acme', parser: 2, hostname: 'web01' }]);
  await pool.query(`UPDATE ${schema}.parsers SET name = 'acme-access' WHERE id = 2`);
  clearInventoryIndexCache();
  await run();
  const { rows: un } = await pool.query(`SELECT source, value, events::int AS events, locations, sample_location, detail FROM ${schema}.application_unmatched WHERE source IN ('service', 'package', 'parser') ORDER BY 1, 2`);
  assert.deepEqual(un.map((u) => [u.source, u.value, u.events, u.locations]), [
    ['package', 'acme-lib', 1, 1],
    ['package', 'libc6', 1, 1],
    ['package', 'widget-agent', 2, 2],
    ['parser', 'acme-access', 1, 1],
    ['service', 'Acme Server', 2, 2],
  ]);
  assert.equal(un.find((u) => u.value === 'acme-lib').detail.vulnerable, true, 'an EDR finding is marked');
  assert.equal(un.find((u) => u.value === 'Acme Server').detail.port, 8080);

  // The widget signature: the installed packages are identified on this run, with their versions.
  const r = await run({ local: [WIDGET] });
  assert.ok(r.resolvedUnmatched >= 1);
  const rows = await inventory();
  assert.deepEqual(rows.filter((x) => x.app_id === 'widget').map((x) => [x.loc, x.source, x.version]), [
    ['asset:1', 'endpoint_sbom', '3.1.0'],
    ['asset:2', 'endpoint_sbom', '3.0.9'],
  ]);
  assert.deepEqual(await unmatchedValues('package'), ['package:acme-lib', 'package:libc6']);
});
