/**
 * Application Monitoring reads (inventory.ts) against a real Postgres: the
 * list with versions, drift, unmanaged and vulnerability counts; the filters;
 * the detail (locations resolved to assets and shippers, evidence,
 * vulnerabilities); the vulnerabilities list; the unmatched list with its
 * suggest-a-signature link. Plus the pure helpers (version order, drift and
 * unmanaged classification, the suggested signature).
 *
 * The rows use ids no real data has (app ids "zz-test-*", 198.18.0.0/15
 * addresses, CVE-2999-*) and are removed in `after`. The pure tests run
 * without a database; the DB ones skip themselves without Postgres.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { closePools, query } from '../../config/database';
import { compareVersions, getApplication, listApplications, listApplicationVulnerabilities, listUnmatched,
  listUnmatchedWithCounts, suggestedSignature, summaryFromRow } from './inventory';
import { ignoreUnmatched, unignoreUnmatched } from './customSignatures';
import { validateApplication } from './appFormat';
import * as yaml from '../../utils/yaml';

const SKIP = 'Postgres with the SIEMBox schema is not reachable';
let ready = false;
const ids: { assets: number[]; vulns: number[]; shipper: number | null } = { assets: [], vulns: [], shipper: null };

test('version order', () => {
  const sorted = ['1.10.0', '1.9.2', '1.9.10', '16', '8.9p1', '8.4p1', '2024.1.0', '2023.12.4'].sort(compareVersions);
  assert.deepEqual(sorted, ['1.9.2', '1.9.10', '1.10.0', '8.4p1', '8.9p1', '16', '2023.12.4', '2024.1.0']);
  assert.equal(compareVersions('1.2', '1.2'), 0);
  assert.ok(compareVersions('1.2', '1.2.1') < 0);
});

test('drift, unmanaged and the latest version from one list row', () => {
  const row = (versions: unknown[], sources: string[]) => summaryFromRow({ id: 'x', name: 'X', vendor: 'V', category: 'saas', sources, versions, hosts: 0, clients: 2 });
  const drift = row([{ version: '1.10.0', locations: 1, last_seen: '2026-10-01T00:00:00Z' }, { version: '1.9.2', locations: 3, last_seen: '2026-10-02T00:00:00Z' }], ['container']);
  assert.equal(drift.drift, true);
  assert.deepEqual(drift.versions.map((v) => v.version), ['1.9.2', '1.10.0'], 'oldest first');
  assert.equal(drift.latest_version, '1.10.0');
  assert.equal(drift.unmanaged, false);
  assert.equal(row([], ['dns', 'user_agent']).unmanaged, true, 'network evidence only');
  assert.equal(row([], ['dns', 'syslog_program']).unmanaged, false, 'a host of yours runs it');
  assert.equal(row([{ version: '2', locations: 4, last_seen: '2026-10-01T00:00:00Z' }], ['os']).drift, false);
});

test('the suggested signature is a valid starting point once the TODOs are filled', () => {
  for (const [source, value, sample] of [
    ['syslog_program', 'mystery-daemon', null],
    ['container', 'ghcr.io/acme/widget', 'ghcr.io/acme/widget:2.0'],
    ['user_agent', 'AcmeBot', 'AcmeBot/1.2 (+https://acme.example)'],
  ] as const) {
    const s = suggestedSignature(source, value, sample);
    assert.match(s.path, /^applications\/[a-z0-9-]+\.app\.yaml$/);
    const doc = yaml.load(s.yaml.replace(/TODO/g, 'web-server').replace("vendor: 'web-server'", "vendor: 'Acme'")) as Record<string, unknown>;
    const v = validateApplication(doc, { strict: true });
    assert.deepEqual(v.errors, [], `${source}: ${s.yaml}`);
  }
});

before(async () => {
  try {
    await query('SELECT 1 FROM application_inventory_state LIMIT 1');
  } catch {
    return;
  }
  const sig = (id: string, name: string, category: string) =>
    query(
      `INSERT INTO application_signatures (id, name, vendor, category, definition, source) VALUES ($1, $2, 'Test', $3, $4, 'catalog')
       ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name`,
      [id, name, category, JSON.stringify({ id, name, vendor: 'Test', category, description: 'test', website: null, cpe: null, supersedes: [], match: { dns: ['x.example'] }, tests: [] })]
    );
  await sig('zz-test-web', 'ZZ Test Web', 'web-server');
  await sig('zz-test-saas', 'ZZ Test SaaS', 'saas');
  const a1 = (await query(`INSERT INTO assets (ip_address, hostname) VALUES ('198.18.0.11', 'zz-web01') RETURNING id`)).rows[0].id;
  const a2 = (await query(`INSERT INTO assets (ip_address, hostname) VALUES ('198.18.0.12', 'zz-web02') RETURNING id`)).rows[0].id;
  ids.assets.push(a1, a2);
  ids.shipper = (await query(`INSERT INTO log_shippers (name, api_key, ip_address, hostname) VALUES ('zz shipper', 'zz-test-key-' || md5(random()::text), '198.18.0.12', 'zz-web02') RETURNING id`)).rows[0].id;
  const v1 = (await query(`INSERT INTO vulnerabilities (cve_id, severity, title, cvss_score) VALUES ('CVE-2999-0001', 'critical', 'ZZ web flaw', 9.8) RETURNING id`)).rows[0].id;
  ids.vulns.push(v1);
  await query(`INSERT INTO asset_vulnerabilities (asset_id, vulnerability_id, status, evidence) VALUES ($1, $2, 'open', 'package=zz-web installed=1.9.2')`, [a1, v1]);
  const ins = (app: string, type: string, key: string, source: string, version: string, events: number, ago: string, evidence: object = {}) =>
    query(
      `INSERT INTO application_inventory (app_id, loc_type, loc_key, source, version, events, first_seen, last_seen, evidence)
       VALUES ($1, $2, $3, $4, $5, $6, NOW() - interval '9 days', NOW() - $7::interval, $8)`,
      [app, type, key, source, version, events, ago, JSON.stringify(evidence)]
    );
  // zz-test-web: on zz-web01 (by host name, logs; by asset id, EDR) at 1.9.2, and in a container on the shipper at 1.10.0.
  await ins('zz-test-web', 'host', 'zz-web01', 'syslog_program', '', 40, '1 hour', { value: 'zzwebd', raw_log_id: 123 });
  await ins('zz-test-web', 'asset', String(a1), 'edr_package', '1.9.2', 1, '2 hours', { package: 'zz-web' });
  await ins('zz-test-web', 'shipper', String(ids.shipper), 'container', '1.10.0', 1, '3 hours', { image: 'zz/web:1.10.0' });
  // An old version on zz-web01's container host superseded by a newer sighting: the current version per location is the newest.
  await ins('zz-test-web', 'shipper', String(ids.shipper), 'container', '1.8.0', 1, '5 days');
  // zz-test-saas: DNS from two clients only.
  await ins('zz-test-saas', 'client', '198.18.0.50', 'dns', '', 7, '1 hour', { value: 'a.x.example' });
  await ins('zz-test-saas', 'client', '198.18.0.51', 'dns', '', 3, '1 day');
  await query(`INSERT INTO application_vuln_links (app_id, asset_id, vulnerability_id, match, version) VALUES ('zz-test-web', $1, $2, 'package', '1.9.2')`, [a1, v1]);
  await query(
    `INSERT INTO application_unmatched (source, value, events, locations, first_seen, last_seen, sample_location, sample) VALUES
       ('syslog_program', 'zz-mystery', 999999, 2, NOW(), NOW(), 'zz-web01', NULL),
       ('user_agent', 'ZZBot', 999998, 1, NOW(), NOW(), '198.18.0.50', 'ZZBot/1.0')
     ON CONFLICT DO NOTHING`
  );
  ready = true;
});

after(async () => {
  if (ready) {
    await query(`DELETE FROM application_inventory WHERE app_id LIKE 'zz-test-%'`);
    await query(`DELETE FROM application_vuln_links WHERE app_id LIKE 'zz-test-%'`);
    await query(`DELETE FROM application_signatures WHERE id LIKE 'zz-test-%'`);
    await query(`DELETE FROM application_unmatched WHERE value IN ('zz-mystery', 'ZZBot')`);
    await query(`DELETE FROM vulnerabilities WHERE id = ANY($1::int[])`, [ids.vulns]);
    await query(`DELETE FROM assets WHERE id = ANY($1::int[])`, [ids.assets]);
    if (ids.shipper) await query(`DELETE FROM log_shippers WHERE id = $1`, [ids.shipper]);
  }
  await closePools();
});

test('the list: versions per location, drift, unmanaged, vulnerabilities, filters', async (t) => {
  if (!ready) return t.skip(SKIP);
  const all = (await listApplications()).filter((a) => a.id.startsWith('zz-test-'));
  const web = all.find((a) => a.id === 'zz-test-web')!;
  assert.equal(web.hosts, 3, 'host, asset and shipper locations');
  assert.equal(web.clients, 0);
  assert.deepEqual(web.versions.map((v) => [v.version, v.locations]), [['1.9.2', 1], ['1.10.0', 1]], "1.8.0 is the shipper's older sighting, not current");
  assert.equal(web.drift, true);
  assert.equal(web.latest_version, '1.10.0');
  assert.deepEqual(web.sources, ['container', 'edr_package', 'syslog_program']);
  assert.deepEqual(web.vulnerabilities, { total: 1, exact: 1, critical: 1, high: 0 });
  const saas = all.find((a) => a.id === 'zz-test-saas')!;
  assert.equal(saas.unmanaged, true);
  assert.equal(saas.clients, 2);
  assert.equal(saas.events, 10);

  const byView = async (view: 'drift' | 'vulnerable' | 'unmanaged') => (await listApplications({ view })).filter((a) => a.id.startsWith('zz-test-')).map((a) => a.id);
  assert.deepEqual(await byView('drift'), ['zz-test-web']);
  assert.deepEqual(await byView('vulnerable'), ['zz-test-web']);
  assert.deepEqual(await byView('unmanaged'), ['zz-test-saas']);
  assert.deepEqual((await listApplications({ category: 'saas', search: 'zz test' })).map((a) => a.id), ['zz-test-saas']);
  assert.deepEqual((await listApplications({ source: 'dns', search: 'ZZ' })).map((a) => a.id), ['zz-test-saas']);
  // The host filter matches an asset's IP (the EDR row is keyed by asset id) and a shipper's host name.
  const byHost = (host: string) => listApplications({ host, search: 'zz' }).then((r) => r.map((a) => [a.id, a.hosts]));
  assert.deepEqual(await byHost('198.18.0.11'), [['zz-test-web', 2]], 'zz-web01 by name and the asset with that IP');
  assert.deepEqual(await byHost('zz-web02'), [['zz-test-web', 1]], 'the shipper on zz-web02');
  assert.deepEqual(await byHost('198.18.0.51'), [['zz-test-saas', 0]]);
});

test('the detail: locations resolved, evidence, vulnerabilities; unknown ids 404', async (t) => {
  if (!ready) return t.skip(SKIP);
  const d = (await getApplication('zz-test-web'))!;
  assert.equal(d.locations_total, 3);
  const host = d.locations.find((l) => l.loc_type === 'host')!;
  assert.equal(host.asset?.hostname, 'zz-web01', 'a logging host name resolves to its asset');
  assert.deepEqual(host.evidence[0].evidence, { value: 'zzwebd', raw_log_id: 123 });
  const ship = d.locations.find((l) => l.loc_type === 'shipper')!;
  assert.equal(ship.shipper?.name, 'zz shipper');
  assert.equal(ship.asset?.ip_address, '198.18.0.12');
  assert.equal(ship.current_version, '1.10.0');
  assert.deepEqual(ship.versions, ['1.8.0', '1.10.0']);
  assert.equal(ship.label, 'zz-web02 (shipper)');
  assert.deepEqual(d.vulnerability_list.map((v) => [v.cve_id, v.asset, v.match, v.version]), [['CVE-2999-0001', 'zz-web01', 'package', '1.9.2']]);
  assert.equal(await getApplication('zz-test-nope'), null);

  const vulns = await listApplicationVulnerabilities({ app: 'zz-test-web' });
  assert.deepEqual(vulns.map((v) => [v.app_name, v.cve_id, v.severity]), [['ZZ Test Web', 'CVE-2999-0001', 'critical']]);
});

test('the unmatched list ranks by events and links to a pre-filled catalog file', async (t) => {
  if (!ready) return t.skip(SKIP);
  const programs = await listUnmatched('syslog_program', 1);
  assert.deepEqual(programs.map((u) => u.value), ['zz-mystery']);
  const url = new URL(programs[0].suggest_url);
  assert.equal(url.hostname, 'github.com');
  assert.equal(url.searchParams.get('filename'), 'applications/zz-mystery.app.yaml');
  assert.match(url.searchParams.get('value') ?? '', /syslog_program: \[zz-mystery\]/);
  const ua = await listUnmatched('user_agent', 1);
  assert.equal(ua[0].sample, 'ZZBot/1.0');
  assert.equal(ua[0].draft.category, 'http-client', 'the draft the editor opens');
});

test('the unmatched list: new kinds, location names, system packages and ignored values hidden unless asked for', async (t) => {
  if (!ready) return t.skip(SKIP);
  await query(
    `INSERT INTO application_unmatched (source, value, events, locations, first_seen, last_seen, sample_location, sample, detail) VALUES
       ('package', 'zz-agent', 999997, 3, NOW(), NOW(), $1, 'zz-agent 1.0', '{"version": "1.0", "type": "deb"}'),
       ('package', 'libzz1', 999996, 3, NOW(), NOW(), $1, 'libzz1 1.0', '{"version": "1.0", "type": "deb"}'),
       ('service', 'ZZ Server', 999995, 1, NOW(), NOW(), $1, 'ZZ Server 2.0', '{"service_name": "http", "service_version": "ZZ Server 2.0", "port": 8080}')
     ON CONFLICT DO NOTHING`,
    [String(ids.assets[0])]
  );
  try {
    let { unmatched, counts } = await listUnmatchedWithCounts('package', 10, { search: 'zz' });
    assert.deepEqual(unmatched.map((u) => u.value), ['zz-agent'], 'a system package is hidden by default');
    assert.equal(unmatched[0].location_label, 'zz-web01', 'the asset by name');
    assert.equal(counts.package.noise, 1);
    assert.deepEqual((unmatched[0].draft.match as Record<string, unknown>).package, ['zz-agent']);
    ({ unmatched } = await listUnmatchedWithCounts('package', 10, { search: 'zz', noise: true }));
    assert.deepEqual(unmatched.map((u) => [u.value, u.noise]), [['zz-agent', false], ['libzz1', true]]);

    await ignoreUnmatched('package', 'zz-agent', 'tester');
    ({ unmatched, counts } = await listUnmatchedWithCounts('package', 10, { search: 'zz' }));
    assert.deepEqual(unmatched.map((u) => u.value), []);
    assert.equal(counts.package.ignored, 1);
    ({ unmatched } = await listUnmatchedWithCounts('package', 10, { search: 'zz', ignored: true }));
    assert.deepEqual(unmatched.map((u) => [u.value, u.ignored]), [['zz-agent', true]]);
    assert.equal(await unignoreUnmatched('package', 'zz-agent'), true);

    const svc = await listUnmatched('service', 5, { search: 'ZZ Server' });
    assert.deepEqual((svc[0].draft.match as any).service, { banner: ['^ZZ Server (\\d[\\w.~+-]*)'] });
  } finally {
    await query(`DELETE FROM application_unmatched WHERE value IN ('zz-agent', 'libzz1', 'ZZ Server')`);
    await query(`DELETE FROM application_unmatched_ignores WHERE value = 'zz-agent'`);
  }
});
