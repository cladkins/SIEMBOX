/**
 * Local application signatures end to end: the real app on an ephemeral port,
 * a real Postgres, one user (and session) per role. The catalog is a stub
 * (the signature cache is primed from a fake GitHub getter before the first
 * request), so nothing leaves the machine.
 *
 * Covers the role gates (viewers read and prepare a contribution; analysts
 * check, test, save, ignore; the AI draft is admin-only and answers 409
 * without a configured provider), the save's checks (a value a catalog
 * signature claims, a failing test), a save queuing the look back, local vs
 * override and the catalog status, the contribution (the pre-filled GitHub
 * file, the warning for a catalog id), "Test" against the Not identified
 * list, ignore/unignore, and delete.
 *
 * Every user, session, signature and Not identified row it creates is
 * removed again, and the ids it queued for the look back are taken off the
 * queue. Skips itself without Postgres. Run with `npm test`.
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
import { clearAppCatalogCache, fetchAppCatalog } from '../services/applications/appCatalog';
import type { HttpGetter } from '../services/parser/catalogService';

const ROLES = ['admin', 'operator', 'analyst', 'viewer'] as const;
type Role = (typeof ROLES)[number];
const SKIP = 'Postgres with the Application Monitoring schema is not reachable';
const tag = crypto.randomBytes(4).toString('hex');
const ID = `zz-route-${tag}`;
const OVERRIDE = `zz-cat-${tag}`;

const CATALOG_FILES: Record<string, string> = {
  [`applications/${OVERRIDE}.app.yaml`]: [
    'schema: siembox.app/v1', `id: ${OVERRIDE}`, 'name: ZZ Catalog App', 'vendor: ZZ', 'category: web-server',
    'match:', `  syslog_program: [zz-cat-${tag}d]`, 'tests:', '  - source: syslog_program', `    input: zz-cat-${tag}d`, '',
  ].join('\n'),
};
const getter: HttpGetter = async (url) => {
  if (url.includes('/git/trees/')) return { status: 200, body: JSON.stringify({ tree: Object.keys(CATALOG_FILES).map((p) => ({ path: p, type: 'blob' })) }) };
  const file = Object.keys(CATALOG_FILES).find((p) => url.endsWith(p));
  return file ? { status: 200, body: CATALOG_FILES[file] } : { status: 404, body: '' };
};

const yamlFor = (id: string, extra: string[] = []) =>
  [
    'schema: siembox.app/v1', `id: ${id}`, 'name: ZZ Agent', 'vendor: ZZ', 'category: security', 'description: The ZZ endpoint agent.',
    'match:', `  package: [${id}-agent]`, ...extra, 'tests:', '  - source: package', `    input: ${id}-agent`, '',
  ].join('\n');

let server: Server | null = null;
let base = '';
let dbReady = false;
const tokens = {} as Record<Role, string>;
const userIds: number[] = [];

before(async () => {
  try {
    for (const table of ['sessions', 'custom_application_signatures', 'application_unmatched_ignores', 'application_inventory_state']) {
      await pool.query(`SELECT 1 FROM ${table} LIMIT 1`);
    }
    dbReady = true;
  } catch {
    return;
  }
  clearAppCatalogCache();
  const primed = await fetchAppCatalog({ force: true, get: getter });
  assert.equal(primed.source, 'catalog');
  for (const role of ROLES) {
    const user = await UserModel.create({ username: `appsig-${tag}-${role}`, email: `appsig-${tag}-${role}@siembox.invalid`, password: crypto.randomBytes(16).toString('hex'), role });
    userIds.push(user.id);
    tokens[role] = (await SessionModel.create(user.id, 1)).token;
  }
  await pool.query(
    `INSERT INTO application_unmatched (source, value, events, locations, first_seen, last_seen, sample_location, sample, detail)
     VALUES ('package', $1, 3, 3, NOW(), NOW(), NULL, $2, '{"version": "2.0.1", "type": "deb"}') ON CONFLICT DO NOTHING`,
    [`${ID}-agent`, `${ID}-agent 2.0.1`]
  );
  server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  if (dbReady) {
    await pool.query(`DELETE FROM custom_application_signatures WHERE id LIKE $1`, [`%-${tag}`]);
    await pool.query(`DELETE FROM application_unmatched WHERE value LIKE $1`, [`%${tag}%`]);
    await pool.query(`DELETE FROM application_unmatched_ignores WHERE value LIKE $1`, [`%${tag}%`]);
    await pool.query(`DELETE FROM application_signatures WHERE id LIKE $1`, [`%-${tag}`]);
    await pool.query(
      `UPDATE application_inventory_state SET rescan_pending = ARRAY(SELECT x FROM unnest(rescan_pending) x WHERE x NOT LIKE $1) WHERE id = 1`,
      [`%-${tag}`]
    );
    await pool.query('DELETE FROM application_errors WHERE user_id = ANY($1)', [userIds]).catch(() => undefined);
    await pool.query('DELETE FROM users WHERE id = ANY($1)', [userIds]);
  }
  clearAppCatalogCache();
  await closePools();
});

async function call(role: Role, method: string, path: string, body?: unknown) {
  const headers: Record<string, string> = { Authorization: `Bearer ${tokens[role]}` };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text();
  let json: any;
  try {
    json = JSON.parse(text);
  } catch {
    json = text;
  }
  return { status: res.status, json };
}

test('role gates: viewers read; checks, saves and ignores are analyst and up; the AI draft is admin-only', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  assert.equal((await call('viewer', 'GET', '/api/applications/signatures')).status, 200);
  assert.equal((await call('viewer', 'GET', '/api/applications/unmatched?source=package')).status, 200);
  assert.equal((await call('viewer', 'POST', '/api/applications/signatures', { yaml: yamlFor(ID) })).status, 403);
  assert.equal((await call('viewer', 'POST', '/api/applications/signatures/validate', { yaml: yamlFor(ID) })).status, 403);
  assert.equal((await call('viewer', 'POST', '/api/applications/signatures/test', { yaml: yamlFor(ID) })).status, 403);
  assert.equal((await call('viewer', 'POST', '/api/applications/unmatched/ignore', { source: 'package', value: `${ID}-agent` })).status, 403);
  assert.equal((await call('analyst', 'POST', '/api/applications/signatures/ai-draft', { items: [{ source: 'package', value: 'x' }] })).status, 403);
  const ai = await call('admin', 'POST', '/api/applications/signatures/ai-draft', { items: [{ source: 'package', value: `${ID}-agent` }] });
  const configured = (await call('admin', 'GET', '/api/applications/signatures')).json.ai_available;
  if (!configured) assert.equal(ai.status, 409, 'no provider: refused cleanly, nothing called');
  assert.equal((await call('admin', 'POST', '/api/applications/signatures/ai-draft', {})).status, 400);
});

test('validate: a good signature is ready; a claimed value and a failing test are errors', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const good = await call('analyst', 'POST', '/api/applications/signatures/validate', { yaml: yamlFor(ID) });
  assert.equal(good.status, 200);
  assert.deepEqual(good.json.errors, []);
  assert.equal(good.json.ready, true);
  assert.equal(good.json.catalog.exists, false);
  assert.match(good.json.yaml, new RegExp(`id: ${ID}`));

  const claimed = await call('analyst', 'POST', '/api/applications/signatures/validate', {
    yaml: yamlFor(ID).replace('match:\n', `match:\n  syslog_program: [zz-cat-${tag}d]\n`),
  });
  assert.ok(claimed.json.errors.some((e: string) => e.includes(`is also claimed by ${OVERRIDE}`)), claimed.json.errors.join('; '));
  const failing = await call('analyst', 'POST', '/api/applications/signatures/validate', { yaml: yamlFor(ID).replace(`    input: ${ID}-agent`, '    input: something-else') });
  assert.equal(failing.json.ok, false);
  assert.ok(failing.json.errors.some((e: string) => e.includes('does not match')));
  assert.equal((await call('analyst', 'POST', '/api/applications/signatures/validate', { yaml: 'a: [' })).status, 400);
});

test('test: what the signature would identify now (here: the Not identified package, with its version)', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const r = await call('analyst', 'POST', '/api/applications/signatures/test', { yaml: yamlFor(ID) });
  assert.equal(r.status, 200);
  const hit = r.json.result.hits.find((h: any) => h.kind === 'package');
  assert.ok(hit, JSON.stringify(r.json.result));
  assert.equal(hit.now, 'not_identified');
  assert.equal(hit.version, '2.0.1');
  assert.equal(r.json.result.resolves_unmatched, 1);
});

test('save, list, read, contribute, disable, delete; an override of a catalog id', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const created = await call('analyst', 'POST', '/api/applications/signatures', { yaml: yamlFor(ID) });
  assert.equal(created.status, 201, JSON.stringify(created.json));
  assert.equal((await call('analyst', 'POST', '/api/applications/signatures', { yaml: yamlFor(ID) })).status, 409, 'the id is taken');
  const { rows } = await pool.query(`SELECT rescan_pending FROM application_inventory_state WHERE id = 1`);
  assert.ok(rows[0].rescan_pending.includes(ID), 'queued for the look back over logs already rolled up');

  const list = await call('viewer', 'GET', '/api/applications/signatures');
  const mine = list.json.signatures.find((s: any) => s.id === ID);
  assert.deepEqual([mine.origin, mine.catalog_status, mine.enabled, mine.created_by], ['local', 'not_in_catalog', true, `appsig-${tag}-analyst`]);
  const one = await call('viewer', 'GET', `/api/applications/signatures/${ID}`);
  assert.equal(one.json.yaml, yamlFor(ID), 'the text as saved');

  const contrib = await call('viewer', 'GET', `/api/applications/signatures/${ID}/contribute`);
  assert.equal(contrib.json.ready, true, JSON.stringify(contrib.json.errors));
  assert.equal(contrib.json.path, `applications/${ID}.app.yaml`);
  const url = new URL(contrib.json.contribute_url);
  assert.equal(url.hostname, 'github.com');
  assert.equal(url.searchParams.get('filename'), `applications/${ID}.app.yaml`);
  assert.match(url.searchParams.get('value') ?? '', new RegExp(`package:\\n\\s+- ${ID}-agent`));

  // An override: same id as the catalog's, different content.
  const override = yamlFor(OVERRIDE).replace('match:\n', `match:\n  syslog_program: [zz-cat-${tag}d]\n`).replace('tests:\n', `tests:\n  - source: syslog_program\n    input: zz-cat-${tag}d\n`);
  assert.equal((await call('analyst', 'POST', '/api/applications/signatures', { yaml: override })).status, 201);
  const ov = (await call('viewer', 'GET', '/api/applications/signatures')).json.signatures.find((s: any) => s.id === OVERRIDE);
  assert.deepEqual([ov.origin, ov.catalog_status], ['override', 'differs']);
  const ovc = await call('viewer', 'GET', `/api/applications/signatures/${OVERRIDE}/contribute`);
  assert.equal(ovc.json.exists_in_catalog, true);
  assert.match(ovc.json.warnings[0], /already has/);
  const catalogOnly = await call('viewer', 'GET', `/api/applications/signatures/${OVERRIDE}`);
  assert.equal(catalogOnly.json.origin, 'override');
  assert.match(catalogOnly.json.catalog_yaml, /name: ZZ Catalog App/);

  // The id cannot change on an edit; enabled can.
  const renamed = await call('analyst', 'PUT', `/api/applications/signatures/${ID}`, { yaml: yamlFor(`${ID}-x`) });
  assert.equal(renamed.status, 422);
  const off = await call('analyst', 'PUT', `/api/applications/signatures/${ID}`, { enabled: false });
  assert.equal(off.json.signature.enabled, false);
  assert.equal((await call('viewer', 'DELETE', `/api/applications/signatures/${ID}`)).status, 403);
  assert.equal((await call('analyst', 'DELETE', `/api/applications/signatures/${ID}`)).status, 200);
  assert.equal((await call('analyst', 'DELETE', `/api/applications/signatures/${OVERRIDE}`)).status, 200);
  assert.equal((await call('viewer', 'GET', `/api/applications/signatures/${ID}`)).status, 404);
  assert.equal((await call('viewer', 'GET', `/api/applications/signatures/${OVERRIDE}`)).json.origin, 'catalog', 'the catalog signature is back');
});

test('ignore and unignore a Not identified value', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const value = `${ID}-agent`;
  assert.equal((await call('analyst', 'POST', '/api/applications/unmatched/ignore', { source: 'package', value })).status, 200);
  let list = await call('viewer', 'GET', `/api/applications/unmatched?source=package&search=${encodeURIComponent(value)}`);
  assert.deepEqual(list.json.unmatched, []);
  assert.equal(list.json.counts.package.ignored, 1);
  list = await call('viewer', 'GET', `/api/applications/unmatched?source=package&ignored=true&search=${encodeURIComponent(value)}`);
  assert.deepEqual(list.json.unmatched.map((u: any) => [u.value, u.ignored]), [[value, true]]);
  assert.equal((await call('analyst', 'POST', '/api/applications/unmatched/unignore', { source: 'package', value })).json.removed, true);
  assert.equal((await call('analyst', 'POST', '/api/applications/unmatched/ignore', { source: 'nope', value })).status, 400);
});
