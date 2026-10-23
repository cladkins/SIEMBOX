/**
 * Content Packs v2 end to end: the real app on an ephemeral port, a real
 * Postgres and regex gate, a fake GitHub catalog (the parser, detection and
 * pack catalog caches are filled from it, so nothing leaves the machine), and
 * an in-memory SigmaHQ library (sigmaStore.setSigmaMemoryForTests; the shared
 * library tables are left alone).
 *
 * - install records the version and the item snapshot (migration 047), with
 *   the installing admin;
 * - a Sigma item while the library is not loaded is pending with the reason,
 *   and everything else installs; once the library is loaded a reinstall adds
 *   it, ENABLED; a Sigma rule already added from the library is left as it is;
 * - when the catalog's pack gains items: "What's new" lists exactly them, and
 *   install-new installs only those (an installed item is not touched), then
 *   the snapshot holds them and nothing is new;
 * - role gates: only admins install; install-new before an install is 409.
 *
 * Skips itself when Postgres isn't reachable. Every row created here is
 * removed again. Run with `npm test` (tsx --test).
 */
import { test, before, after, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { once } from 'node:events';
import * as fs from 'fs';
import * as path from 'path';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';

process.env.SIEMBOX_CATALOG_REPO = 'example/packs-test-catalog';
process.env.SIEMBOX_CATALOG_REF = 'main';

import app from '../app';
import pool, { closePools } from '../config/database';
import { UserModel } from '../models/User';
import { SessionModel } from '../models/Session';
import { DetectionRuleModel } from '../models/DetectionRule';
import { closeRegexScanPool } from '../services/regex/regexSafety';
import { closeRegexTestPool } from '../services/regex/boundedRegex';
import { fetchCatalog, clearCatalogCache, type HttpGetter } from '../services/parser/catalogService';
import { fetchDetectionCatalog, clearDetectionCache } from '../services/rules/detectionCatalog';
import { fetchPackCatalog, clearPackCache } from '../services/packs/packCatalog';
import { setSigmaMemoryForTests, clearSigmaMemory } from '../services/sigma/sigmaStore';
import { libraryRuleFromYaml, type SigmaLibraryRule } from '../services/sigma/sigmaLibrary';
import { installSigmaRule } from '../services/sigma/sigmaInstall';

const SKIP = 'Postgres with the SIEMBox schema is not reachable';
const ROLES = ['admin', 'analyst', 'viewer'] as const;
type Role = (typeof ROLES)[number];

let dbReady = false;
let server: Server | undefined;
let base = '';
const hex = crypto.randomBytes(3).toString('hex');
const prefix = `pk${hex}`;
const packId = `${prefix}-web`;
const tokens = {} as Record<Role, string>;
const userIds: number[] = [];

const uuid = () => crypto.randomUUID();
const SIGMA = { first: uuid(), second: uuid(), preAdded: uuid() };

// The fake catalog: two real catalog parsers renamed, rules named for this run.
const ROOT = path.join(__dirname, '..', '..', '..');
const parserFile = (file: string, name: string) => {
  const p = JSON.parse(fs.readFileSync(path.join(ROOT, 'catalog', 'parsers', file), 'utf8'));
  return JSON.stringify({ ...p, name });
};
const P1 = `${prefix}-traefik`;
const P2 = `${prefix}-caddy`;
const D1 = `${prefix} Admin Path Probe`;
const D2 = `${prefix} Env File Probe`;
const ruleYaml = (name: string, needle: string) => `name: ${name}
description: A request for ${needle}.
severity: medium
enabled: true
tags: [${prefix}-tag]
conditions:
  - field: path
    operator: contains
    value: '${needle}'
alert:
  title: "${name} from {client_ip}"
  description: "{client_ip} asked for {path}."
`;

function sigmaRule(id: string, title: string, needle: string): SigmaLibraryRule {
  const r = libraryRuleFromYaml(
    `rules/web/${id}.yml`,
    `title: ${title}
id: ${id}
status: test
author: Test Author
logsource:
  category: proxy
detection:
  selection:
    c-uri|contains: '${needle}'
  condition: selection
level: high
`,
    'r2099-01-01'
  );
  assert.ok('rule' in r, 'fixture Sigma rule must build');
  assert.equal(r.rule.convertible, true, r.rule.errors.join('; '));
  return r.rule;
}
const LIBRARY = [
  sigmaRule(SIGMA.first, `${prefix} Sigma First`, `/${prefix}-first`),
  sigmaRule(SIGMA.second, `${prefix} Sigma Second`, `/${prefix}-second`),
  sigmaRule(SIGMA.preAdded, `${prefix} Sigma Pre-added`, `/${prefix}-pre`),
];

const packYaml = (version: number, parsers: string[], names: string[], sigma: string[]) => `schema: siembox.pack/v1
id: ${packId}
name: ${prefix} Web
description: Test pack.
icon: Connection
version: ${version}
parsers: [${parsers.join(', ')}]
detections:
  names: [${names.map((n) => `"${n}"`).join(', ')}]
sigma:
${sigma.map((id) => `  - id: ${id}\n    title: ${LIBRARY.find((r) => r.sigma_id === id)!.title}`).join('\n')}
setup:
  - title: Ship the access log
    text: Add a **File** source.
`;

let catalogFiles: Record<string, string> = {};
const fakeGitHub: HttpGetter = async (url) => {
  if (url.startsWith('https://api.github.com/repos/example/packs-test-catalog/git/trees/main')) {
    return { status: 200, body: JSON.stringify({ tree: Object.keys(catalogFiles).map((p) => ({ path: p, type: 'blob' })) }) };
  }
  const m = url.match(/^https:\/\/raw\.githubusercontent\.com\/example\/packs-test-catalog\/main\/(.+)$/);
  const p = m ? decodeURIComponent(m[1]) : '';
  if (p in catalogFiles) return { status: 200, body: catalogFiles[p] };
  return { status: 404, body: 'not found' };
};

/** Publish a catalog state and fill every catalog cache from it. */
async function publishCatalog(files: Record<string, string>) {
  catalogFiles = files;
  clearCatalogCache();
  clearDetectionCache();
  clearPackCache();
  await fetchCatalog(true, fakeGitHub);
  await fetchDetectionCatalog(true, fakeGitHub);
  const packs = await fetchPackCatalog(true, fakeGitHub);
  assert.equal(packs.source, 'catalog', packs.error ?? '');
}

const V1 = () => ({
  'parsers/traefik.parser.json': parserFile('traefik-access.parser.json', P1),
  'parsers/caddy.parser.json': parserFile('caddy-access.parser.json', P2),
  'detections/reverse-proxy/A.yaml': ruleYaml(D1, '/admin'),
  'detections/reverse-proxy/B.yaml': ruleYaml(D2, '/.env'),
  [`packs/${packId}.pack.yaml`]: packYaml(1, [P1], [D1], [SIGMA.first, SIGMA.preAdded]),
});
// The catalog adds a parser, a detection and a Sigma rule to the pack.
const V2 = () => ({ ...V1(), [`packs/${packId}.pack.yaml`]: packYaml(2, [P1, P2], [D1, D2], [SIGMA.first, SIGMA.preAdded, SIGMA.second]) });

before(async () => {
  try {
    for (const table of ['content_pack_installs', 'detection_rules', 'parsers', 'users']) {
      await pool.query(`SELECT 1 FROM ${table} LIMIT 1`);
    }
    dbReady = true;
  } catch {
    return;
  }
  for (const role of ROLES) {
    const user = await UserModel.create({
      username: `${prefix}-${role}`,
      email: `${prefix}-${role}@siembox.invalid`,
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
    await pool.query('DELETE FROM content_pack_installs WHERE pack_id = $1', [packId]);
    await pool.query('DELETE FROM detection_rules WHERE sigma_id = ANY($1) OR name LIKE $2', [Object.values(SIGMA), `${prefix}%`]);
    await pool.query('DELETE FROM parsers WHERE name LIKE $1', [`${prefix}%`]);
    for (let i = 0; i < 30; i++) await new Promise((r) => setTimeout(r, 100)); // let fire-and-forget 403 logs land
    await pool.query('DELETE FROM application_errors WHERE user_id = ANY($1)', [userIds]);
    await pool.query('DELETE FROM audit_logs WHERE user_id = ANY($1)', [userIds]);
    await pool.query('DELETE FROM users WHERE id = ANY($1)', [userIds]);
  }
  clearSigmaMemory();
  await closePools();
});

function skipUnlessDb(t: TestContext): boolean {
  if (dbReady) return false;
  t.skip(SKIP);
  return true;
}

async function call(role: Role, method: string, url: string, body?: unknown) {
  const headers: Record<string, string> = { Authorization: `Bearer ${tokens[role]}` };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(base + url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  return { status: res.status, json: ((await res.json().catch(() => null)) ?? {}) as Record<string, any> };
}

async function packStatus(role: Role = 'viewer') {
  const r = await call(role, 'GET', '/api/packs');
  assert.equal(r.status, 200, JSON.stringify(r.json));
  const p = r.json.packs.find((x: any) => x.id === packId);
  assert.ok(p, 'the test pack is listed');
  return { overview: r.json, pack: p };
}

const record = async () => (await pool.query('SELECT * FROM content_pack_installs WHERE pack_id = $1', [packId])).rows[0];

test('Content Packs v2: install records, Sigma pending -> installed, what\'s new, install-new, role gates', async (t) => {
  if (skipUnlessDb(t)) return;
  await publishCatalog(V1());
  // The SigmaHQ library has never been loaded.
  setSigmaMemoryForTests([], null);

  // Listed from the catalog, nothing installed, no record.
  const first0 = await packStatus();
  const overview = first0.overview;
  let pack = first0.pack;
  assert.equal(overview.source.source, 'catalog');
  assert.equal(overview.sigma_library.loaded, false);
  assert.equal(pack.version, 1);
  assert.equal(pack.status, 'not_installed');
  assert.equal(pack.install, null);
  assert.equal(pack.whats_new, null);
  assert.deepEqual(pack.sigma.map((s: any) => s.state), ['pending', 'pending']);
  assert.match(pack.sigma[0].reason, /has not been loaded yet: refresh it on Detection Rules > SigmaHQ/);
  assert.equal(pack.setup[0].title, 'Ship the access log');

  // Role gates: only admins install; install-new needs an install first.
  for (const role of ['viewer', 'analyst'] as const) {
    assert.equal((await call(role, 'POST', `/api/packs/${packId}/install`)).status, 403, role);
    assert.equal((await call(role, 'POST', `/api/packs/${packId}/install-new`)).status, 403, role);
  }
  const early = await call('admin', 'POST', `/api/packs/${packId}/install-new`);
  assert.equal(early.status, 409);
  assert.equal(early.json.code, 'PACK_NOT_INSTALLED');
  assert.equal((await call('admin', 'POST', '/api/packs/no-such-pack/install')).status, 404);

  // Install while the library is not loaded: the Sigma items are pending, the rest installs.
  let r = await call('admin', 'POST', `/api/packs/${packId}/install`);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.mode, 'full');
  assert.equal(r.json.parsers.installed, 1);
  assert.equal(r.json.detections.installed, 1);
  assert.equal(r.json.sigma.installed, 0);
  assert.deepEqual(r.json.sigma.pending.map((p: any) => p.id), [SIGMA.first, SIGMA.preAdded]);
  assert.match(r.json.sigma.pending[0].reason, /not been loaded yet/);
  assert.ok(await DetectionRuleModel.findByName(D1));

  // The install record: version, who, and the item snapshot (pending Sigma items included).
  let rec = await record();
  assert.equal(rec.version, 1);
  assert.equal(rec.source, 'catalog');
  assert.equal(rec.installed_by, userIds[0]);
  assert.equal(rec.installed_by_username, `${prefix}-admin`);
  assert.deepEqual(rec.parsers, [P1]);
  assert.deepEqual(rec.detections, [D1]);
  assert.deepEqual(rec.sigma, [SIGMA.first, SIGMA.preAdded]);
  assert.deepEqual(rec.pending.map((p: any) => [p.kind, p.name]), [['sigma', SIGMA.first], ['sigma', SIGMA.preAdded]]);

  ({ pack } = await packStatus());
  assert.equal(pack.status, 'partial');
  assert.equal(pack.install.version, 1);
  assert.equal(pack.whats_new, null, 'nothing is new right after an install');

  // The library is loaded; one of the pack's rules was already added from it (disabled).
  setSigmaMemoryForTests(LIBRARY, 'r2099-01-01');
  await installSigmaRule(SIGMA.preAdded);
  ({ pack } = await packStatus());
  assert.deepEqual(pack.sigma.map((s: any) => [s.state, s.installed]), [['available', false], ['installed', true]]);

  r = await call('admin', 'POST', `/api/packs/${packId}/install`);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.sigma.installed, 1);
  assert.equal(r.json.sigma.already, 1);
  assert.deepEqual(r.json.sigma.pending, []);
  const first = await DetectionRuleModel.findBySigmaId(SIGMA.first);
  assert.equal(first.length, 1);
  assert.equal(first[0].enabled, true, 'a pack install turns its Sigma rules on, as it does its catalog detections');
  assert.equal(first[0].sigma_release, 'r2099-01-01');
  const pre = await DetectionRuleModel.findBySigmaId(SIGMA.preAdded);
  assert.equal(pre[0].enabled, false, 'a rule the user added from the library keeps its choice');
  assert.deepEqual((await record()).pending, []);
  ({ pack } = await packStatus());
  assert.equal(pack.status, 'installed');

  // The catalog adds a parser, a detection and a Sigma rule (version 2).
  await publishCatalog(V2());
  ({ pack } = await packStatus());
  assert.equal(pack.version, 2);
  assert.equal(pack.status, 'partial');
  assert.deepEqual(pack.whats_new, {
    from_version: 1,
    to_version: 2,
    version_bumped: true,
    parsers: [P2],
    detections: [D2],
    sigma: [{ id: SIGMA.second, title: `${prefix} Sigma Second` }],
    count: 3,
  });
  assert.deepEqual(pack.parsers.map((p: any) => [p.name, p.new]), [[P1, false], [P2, true]]);
  assert.deepEqual(pack.detections.map((d: any) => [d.name, d.new]), [[D1, false], [D2, true]]);
  assert.deepEqual(pack.sigma.map((s: any) => s.new), [false, false, true]);

  // An installed item the user changed: install-new must not touch it.
  await pool.query('UPDATE parsers SET description = $1 WHERE name = $2', ['edited by the user', P1]);
  await pool.query('UPDATE detection_rules SET description = $1 WHERE name = $2', ['edited by the user', D1]);

  r = await call('admin', 'POST', `/api/packs/${packId}/install-new`);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.mode, 'new');
  assert.equal(r.json.version, 2);
  assert.deepEqual([r.json.parsers.installed, r.json.parsers.updated], [1, 0]);
  assert.deepEqual([r.json.detections.installed, r.json.detections.updated], [1, 0]);
  assert.deepEqual([r.json.sigma.installed, r.json.sigma.already], [1, 0]);
  assert.equal((await pool.query('SELECT description FROM parsers WHERE name = $1', [P1])).rows[0].description, 'edited by the user');
  assert.equal((await DetectionRuleModel.findByName(D1))!.description, 'edited by the user');
  assert.ok(await DetectionRuleModel.findByName(D2));
  assert.equal((await DetectionRuleModel.findBySigmaId(SIGMA.second))[0].enabled, true);

  rec = await record();
  assert.equal(rec.version, 2);
  assert.deepEqual(rec.parsers, [P1, P2]);
  assert.deepEqual(rec.detections, [D1, D2]);
  assert.deepEqual(rec.sigma, [SIGMA.first, SIGMA.preAdded, SIGMA.second]);
  ({ pack } = await packStatus());
  assert.equal(pack.whats_new, null);
  assert.equal(pack.status, 'installed');
  assert.equal(pack.install.version, 2);

  // Nothing new: install-new installs nothing.
  r = await call('admin', 'POST', `/api/packs/${packId}/install-new`);
  assert.equal(r.status, 200);
  assert.equal(r.json.parsers.installed + r.json.detections.installed + r.json.sigma.installed, 0);
});
