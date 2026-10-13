/**
 * Viewers are read-only on parsers, detection rules, alerts and the AI Analyst,
 * end to end: the real app on an ephemeral port, a real Postgres, and one user
 * per role holding a session token (as login would issue). Each write a viewer
 * used to be able to make now answers 403 and changes nothing in the database,
 * while analyst, operator and admin keep working (alert deletion is admin-only).
 * routeInventory.test.ts proves the gate of every route without a database;
 * this file proves the refusals hold against real rows.
 *
 * Every 403 probe stays harmless even if its gate goes missing: it aims at this
 * test's own rows, or sends a body the handler rejects with 400 before doing any
 * work, or (the catalog install-all and refresh calls, which check nothing in the
 * request) reaches a catalog source pointed at a repository that does not exist.
 * The catalog browse test stands a fake GitHub in for that repository while it
 * runs, to count the tree listings (the calls that use the GitHub API quota).
 *
 * Skips itself when Postgres isn't reachable. Every row created here (users,
 * sessions, parsers, rules, alerts, audit and error-log rows) is removed again,
 * along with what an interrupted earlier run left behind.
 * Run with `npm test` (tsx --test).
 */
import { test, before, after, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import https from 'node:https';
import { EventEmitter, once } from 'node:events';
import { PassThrough } from 'node:stream';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import app from '../app';
import pool, { closePools } from '../config/database';
import { UserModel } from '../models/User';
import { SessionModel } from '../models/Session';
import { clearCatalogCache } from '../services/parser/catalogService';
import { clearDetectionCache } from '../services/rules/detectionCatalog';

const ROLES = ['admin', 'operator', 'analyst', 'viewer'] as const;
type Role = (typeof ROLES)[number];
const SKIP = 'Postgres with the SIEMBox schema is not reachable';
/** Usernames this test gives its users (contentauthz-<tag>-<role>), any tag. */
const TEST_USER_NAME = '^contentauthz-[0-9a-f]{12}-(admin|operator|analyst|viewer)$';
/** Parser, rule and alert names this test uses (contentauthz-<tag>[-suffix]), any tag. */
const TEST_ROW_NAME = '^contentauthz-[0-9a-f]{12}(-[a-z]+)?$';

// The catalog calls that check nothing in the request would install the whole
// catalog if their gate went missing; send them to a repository that cannot exist.
process.env.SIEMBOX_CATALOG_REPO = 'siembox-role-gate-test.invalid/no-such-catalog';
process.env.SIEMBOX_CATALOG_REF = 'none';

let dbReady = false;
let server: Server | undefined;
let base = '';
const tag = crypto.randomBytes(6).toString('hex');
const name = `contentauthz-${tag}`;
const tokens = {} as Record<Role, string>;
const userIds: number[] = [];
/** 403 responses so far; each one is logged to application_errors (see after()). */
let denials = 0;

before(async () => {
  try {
    for (const table of ['sessions', 'parsers', 'detection_rules', 'alerts', 'chat_sessions', 'audit_logs', 'application_errors']) {
      await pool.query(`SELECT 1 FROM ${table} LIMIT 1`);
    }
    dbReady = true;
  } catch {
    return;
  }
  for (const role of ROLES) {
    const user = await UserModel.create({
      username: `${name}-${role}`,
      email: `${name}-${role}@siembox.invalid`,
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
  if (dbReady) {
    // Leftovers of an interrupted earlier run go too, but only once they are
    // older than 10 minutes: a run going on in parallel keeps its own.
    const stale = `created_at < NOW() - INTERVAL '10 minutes'`;
    await pool.query(`DELETE FROM parsers WHERE name LIKE $1 OR (name ~ $2 AND ${stale})`, [`${name}%`, TEST_ROW_NAME]);
    await pool.query(`DELETE FROM detection_rules WHERE name LIKE $1 OR (name ~ $2 AND ${stale})`, [`${name}%`, TEST_ROW_NAME]);
    await pool.query(`DELETE FROM alerts WHERE title LIKE $1 OR (title ~ $2 AND ${stale})`, [`${name}%`, TEST_ROW_NAME]);
    // Every 403 is logged to application_errors, fire-and-forget: wait until those
    // rows have landed, then delete them and the audit rows before the users
    // (deleting a user only nulls user_id, which would leave orphan rows).
    for (let attempt = 0; attempt < 50; attempt++) {
      const logged = await pool.query('SELECT count(*)::int AS n FROM application_errors WHERE user_id = ANY($1)', [userIds]);
      if (logged.rows[0].n >= denials) break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    const leftover = await pool.query(
      `SELECT id FROM users WHERE username ~ $1 AND email LIKE '%@siembox.invalid' AND ${stale}`,
      [TEST_USER_NAME]
    );
    const doomed = [...userIds, ...leftover.rows.map((row) => row.id as number)];
    await pool.query('DELETE FROM application_errors WHERE user_id = ANY($1)', [doomed]);
    await pool.query('DELETE FROM audit_logs WHERE user_id = ANY($1)', [doomed]);
    await pool.query('DELETE FROM users WHERE id = ANY($1)', [doomed]); // sessions and chat threads cascade
  }
  await closePools();
});

/** The parts of a response body these tests read. */
interface Body {
  id?: number;
  ok?: boolean;
  matched?: boolean;
  fields?: Record<string, unknown> | null;
  parser?: { id: number };
  configured?: unknown;
  parsers?: Array<{ name: string }>;
  rules?: Array<{ name: string }>;
}

async function call(role: Role | null, method: string, path: string, body?: unknown) {
  const headers: Record<string, string> = {};
  if (role) headers.Authorization = `Bearer ${tokens[role]}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(base + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 403) denials++;
  return { status: res.status, json: (await res.json().catch(() => null)) as Body };
}

/** `roles` all get 403 from `method path`. */
async function refused(roles: readonly Role[], method: string, path: string, body?: unknown) {
  for (const role of roles) {
    assert.equal((await call(role, method, path, body)).status, 403, `${role} ${method} ${path} is refused`);
  }
}

/** `roles` all get past the gate, to the route's own 400 validation. */
async function pastTheGate(roles: readonly Role[], method: string, path: string, body?: unknown) {
  for (const role of roles) {
    assert.equal((await call(role, method, path, body)).status, 400, `${role} ${method} ${path} reaches validation`);
  }
}

/** A fingerprint of every row in `table`, to show a call changed nothing at all. */
async function fingerprint(table: 'parsers' | 'detection_rules'): Promise<string> {
  const r = await pool.query(`SELECT md5(coalesce(string_agg(t::text, '|' ORDER BY t.id), '')) AS h, count(*)::int AS n FROM ${table} t`);
  return `${r.rows[0].n}:${r.rows[0].h}`;
}

async function row(table: 'parsers' | 'detection_rules' | 'alerts', id: number) {
  return (await pool.query(`SELECT * FROM ${table} WHERE id = $1`, [id])).rows[0];
}

/** A regex parser that matches only its own sample, disabled so it never touches live logs. */
function parserBody(suffix: string) {
  return {
    name: `${name}-${suffix}`,
    description: 'role gate test',
    enabled: false,
    priority: 1000,
    parser_type: 'regex',
    pattern: `^${name} (?<message>.+)$`,
    field_mappings: { message: 'message' },
  };
}

function portableParser(suffix: string) {
  return {
    schema: 'siembox.parser/v1',
    ...parserBody(suffix),
    test_samples: [{ input: `${name} hello`, expect: { message: 'hello' } }],
  };
}

/** A disabled rule that matches only this test's own marker. */
function ruleBody(suffix: string) {
  return {
    name: `${name}-${suffix}`,
    description: 'role gate test',
    enabled: false,
    severity: 'low',
    tags: ['role-gate-test'],
    rule_yaml: [
      'conditions:',
      '  - field: message',
      '    operator: equals',
      `    value: ${name}`,
      'actions:',
      '  alert:',
      '    title: role gate test',
      '    description: role gate test',
    ].join('\n'),
  };
}

test('parsers: a viewer can no longer create, import, install, change or delete; analyst, operator and admin can', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const untouched = await fingerprint('parsers');
  await refused(['viewer'], 'POST', '/api/parsers', parserBody('viewer'));
  await refused(['viewer'], 'POST', '/api/parsers/import', { parser: portableParser('viewer') });
  await refused(['viewer'], 'POST', '/api/parsers/catalog/install', {});
  await refused(['viewer'], 'POST', '/api/parsers/catalog/install-all', {});
  await refused(['viewer'], 'POST', '/api/parsers/catalog/refresh');
  // These two run a regex the caller supplies on the event loop: analyst and up only.
  await refused(['viewer'], 'POST', '/api/parsers/validate', { parser: portableParser('viewer') });
  await refused(['viewer'], 'POST', '/api/parsers/test', { ...parserBody('viewer'), sample: `${name} hello` });
  assert.equal(await fingerprint('parsers'), untouched, 'no parser was created or changed');

  const created = await call('analyst', 'POST', '/api/parsers', parserBody('created'));
  assert.equal(created.status, 201);
  const id = created.json.id!;
  const before = await row('parsers', id);

  await refused(['viewer'], 'PUT', `/api/parsers/${id}`, { enabled: true, description: 'changed by a viewer' });
  await refused(['viewer'], 'DELETE', `/api/parsers/${id}`);
  assert.deepEqual(await row('parsers', id), before, 'the parser is unchanged');

  // Testing a saved parser on a sample stays open to every role.
  const viewerTest = await call('viewer', 'POST', `/api/parsers/${id}/test`, { sample: `${name} hello` });
  assert.equal(viewerTest.status, 200);
  assert.deepEqual(viewerTest.json.matched, true);

  const updated = await call('operator', 'PUT', `/api/parsers/${id}`, { description: 'changed by an operator' });
  assert.equal(updated.status, 200);
  assert.equal((await row('parsers', id)).description, 'changed by an operator');

  const validated = await call('analyst', 'POST', '/api/parsers/validate', { parser: portableParser('validated') });
  assert.equal(validated.status, 200);
  assert.equal(validated.json.ok, true, JSON.stringify(validated.json));
  const tested = await call('operator', 'POST', '/api/parsers/test', { ...parserBody('tested'), sample: `${name} hello` });
  assert.equal(tested.status, 200);
  assert.deepEqual(tested.json.fields?.message, 'hello');
  await pastTheGate(['analyst', 'operator', 'admin'], 'POST', '/api/parsers/catalog/install', {});

  const imported = await call('analyst', 'POST', '/api/parsers/import', { parser: portableParser('imported') });
  assert.equal(imported.status, 201, JSON.stringify(imported.json));
  assert.equal((await call('admin', 'DELETE', `/api/parsers/${imported.json.parser!.id}`)).status, 200);
  assert.equal((await call('admin', 'DELETE', `/api/parsers/${id}`)).status, 200);
  assert.equal(await row('parsers', id), undefined);
});

test('detection rules: a viewer can no longer create, install, change or delete; analyst, operator and admin can', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const untouched = await fingerprint('detection_rules');
  await refused(['viewer'], 'POST', '/api/rules', ruleBody('viewer'));
  await refused(['viewer'], 'POST', '/api/rules/catalog/install', {});
  await refused(['viewer'], 'POST', '/api/rules/catalog/install-all', {});
  await refused(['viewer'], 'POST', '/api/rules/catalog/refresh');
  assert.equal(await fingerprint('detection_rules'), untouched, 'no rule was created or changed');

  const created = await call('analyst', 'POST', '/api/rules', ruleBody('created'));
  assert.equal(created.status, 201);
  const id = created.json.id!;
  const before = await row('detection_rules', id);

  // Disabling a detection is how a viewer could have silenced alerting.
  await refused(['viewer'], 'PUT', `/api/rules/${id}`, { enabled: true });
  await refused(['viewer'], 'PUT', `/api/rules/${id}`, { description: 'changed by a viewer' });
  await refused(['viewer'], 'DELETE', `/api/rules/${id}`);
  assert.deepEqual(await row('detection_rules', id), before, 'the rule is unchanged');

  const updated = await call('operator', 'PUT', `/api/rules/${id}`, { description: 'changed by an operator' });
  assert.equal(updated.status, 200);
  assert.equal((await row('detection_rules', id)).description, 'changed by an operator');
  await pastTheGate(['analyst', 'operator', 'admin'], 'POST', '/api/rules/catalog/install', {});

  assert.equal((await call('admin', 'DELETE', `/api/rules/${id}`)).status, 200);
  assert.equal(await row('detection_rules', id), undefined);
});

/**
 * Stands in for GitHub during one test: the catalog repository (set at the top
 * of this file) holds one parser and one detection, and any other URL is a 404.
 * The tree listing answers after 300 ms, so requests sent together overlap it.
 * Returns how many tree listings were made: each one uses the GitHub API quota.
 */
function fakeCatalogRepo(t: TestContext): { trees: () => number } {
  const repo = process.env.SIEMBOX_CATALOG_REPO;
  const ref = process.env.SIEMBOX_CATALOG_REF;
  const files: Record<string, string> = {
    [`parsers/${name}-catalog.parser.json`]: JSON.stringify(portableParser('catalog')),
    [`detections/${name}-catalog.yaml`]: [`name: ${name}-catalog`, 'description: role gate test', 'severity: low', ruleBody('catalog').rule_yaml].join('\n'),
  };
  let trees = 0;
  const get = (url: string, _options: unknown, onResponse: (res: PassThrough) => void) => {
    let status = 404;
    let body = '';
    let delay = 0;
    const raw = `https://raw.githubusercontent.com/${repo}/${ref}/`;
    if (url === `https://api.github.com/repos/${repo}/git/trees/${ref}?recursive=1`) {
      trees++;
      [status, delay] = [200, 300];
      body = JSON.stringify({ tree: Object.keys(files).map((path) => ({ path, type: 'blob' })) });
    } else if (url.startsWith(raw) && files[url.slice(raw.length)] !== undefined) {
      [status, body] = [200, files[url.slice(raw.length)]];
    }
    const res = Object.assign(new PassThrough(), { statusCode: status, headers: {} });
    setTimeout(() => {
      onResponse(res);
      res.end(body);
    }, delay);
    return Object.assign(new EventEmitter(), { setTimeout: () => undefined, destroy: () => undefined });
  };
  t.mock.method(https as unknown as { get: typeof get }, 'get', get);
  return { trees: () => trees };
}

test("catalogs: a viewer's ?refresh=true is served from the cache; analyst and up refetch; reads sent together share one fetch", async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const github = fakeCatalogRepo(t);
  try {
    for (const [path, list] of [
      ['/api/parsers/catalog', 'parsers'],
      ['/api/rules/catalog', 'rules'],
    ] as const) {
      clearCatalogCache();
      clearDetectionCache();
      const start = github.trees();
      const burst = await Promise.all(Array.from({ length: 8 }, () => call('viewer', 'GET', path)));
      for (const res of burst) {
        assert.equal(res.status, 200, `viewer GET ${path}`);
        assert.deepEqual(res.json[list]?.map((e) => e.name), [`${name}-catalog`], 'the fake catalog is listed');
      }
      assert.equal(github.trees() - start, 1, `${path}: eight reads of a cold cache share one fetch`);

      const viewerRefresh = await call('viewer', 'GET', `${path}?refresh=true`);
      assert.equal(viewerRefresh.status, 200);
      assert.deepEqual(viewerRefresh.json[list]?.map((e) => e.name), [`${name}-catalog`]);
      assert.equal(github.trees() - start, 1, `${path}: a viewer's ?refresh=true is served from the cache`);

      for (const [i, role] of (['analyst', 'operator', 'admin'] as const).entries()) {
        assert.equal((await call(role, 'GET', `${path}?refresh=true`)).status, 200, `${role} GET ${path}?refresh=true`);
        assert.equal(github.trees() - start, 2 + i, `${path}: ${role}'s ?refresh=true refetches`);
      }
    }
  } finally {
    // The other tests' catalog calls must reach the nonexistent repository again.
    clearCatalogCache();
    clearDetectionCache();
  }
});

test('alerts: a viewer can no longer triage; only an admin deletes', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const inserted = await pool.query(
    `INSERT INTO alerts (severity, title, matched_data, status) VALUES ('low', $1, '{}'::jsonb, 'new') RETURNING id`,
    [`${name}-alert`]
  );
  const id = inserted.rows[0].id as number;
  const before = await row('alerts', id);

  await refused(['viewer'], 'PUT', `/api/alerts/${id}`, { status: 'closed' });
  await refused(['analyst', 'operator', 'viewer'], 'DELETE', `/api/alerts/${id}`);
  assert.deepEqual(await row('alerts', id), before, 'the alert is unchanged');

  for (const [role, status] of [['analyst', 'investigating'], ['operator', 'false_positive'], ['admin', 'closed']] as const) {
    const updated = await call(role, 'PUT', `/api/alerts/${id}`, { status });
    assert.equal(updated.status, 200, `${role} updates the alert`);
    assert.equal((await row('alerts', id)).status, status);
  }

  assert.equal((await call('admin', 'DELETE', `/api/alerts/${id}`)).status, 200);
  assert.equal(await row('alerts', id), undefined);
});

test('AI Analyst: a viewer can no longer chat or manage threads; health tells every role only whether it is configured', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  await refused(['viewer'], 'POST', '/api/ai/chat', { message: '' });
  await refused(['viewer'], 'PATCH', '/api/ai/chat/sessions/abc', { title: 'x' });
  await refused(['viewer'], 'DELETE', '/api/ai/chat/sessions/abc');
  await pastTheGate(['analyst', 'operator', 'admin'], 'POST', '/api/ai/chat', { message: '' });
  await pastTheGate(['analyst', 'operator', 'admin'], 'PATCH', '/api/ai/chat/sessions/abc', { title: 'x' });
  await pastTheGate(['analyst', 'operator', 'admin'], 'DELETE', '/api/ai/chat/sessions/abc');
  const threads = await pool.query('SELECT count(*)::int AS n FROM chat_sessions WHERE user_id = ANY($1)', [userIds]);
  assert.equal(threads.rows[0].n, 0, 'no chat thread was created');

  for (const role of ROLES) {
    const health = await call(role, 'GET', '/api/ai/chat/health');
    assert.equal(health.status, 200);
    assert.deepEqual(Object.keys(health.json), ['configured'], `${role} gets no provider, model or base URL`);
    assert.equal(typeof health.json.configured, 'boolean');
  }
});

test('reads stay open to every role', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  for (const role of ROLES) {
    for (const path of ['/api/parsers', '/api/rules', '/api/alerts?limit=1', '/api/alerts/statistics', '/api/ai/chat/sessions']) {
      assert.equal((await call(role, 'GET', path)).status, 200, `${role} GET ${path}`);
    }
  }
});

test('the refusals are recorded in audit_logs', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const r = await pool.query(
    `SELECT DISTINCT resource_type FROM audit_logs
      WHERE user_id = ANY($1) AND action = 'access.denied' AND response_status = 403`,
    [userIds]
  );
  const types = r.rows.map((x) => x.resource_type).sort();
  assert.deepEqual(types, ['ai_chat', 'alert', 'detection_rule', 'parser']);
});

test('without a login every family answers 401', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  for (const [method, path] of [
    ['POST', '/api/parsers'],
    ['POST', '/api/rules'],
    ['PUT', '/api/alerts/1'],
    ['POST', '/api/ai/chat'],
  ]) {
    assert.equal((await call(null, method, path, {})).status, 401, `${method} ${path}`);
  }
});
