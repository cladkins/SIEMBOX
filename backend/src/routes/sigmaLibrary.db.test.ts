/**
 * The SigmaHQ library end to end: the real app on an ephemeral port, a real
 * Postgres, the real regex gate, and a fake GitHub (globalThis.fetch is
 * replaced for the run, so nothing leaves the machine) serving the fixture
 * release archive (services/sigma/sigmaFixture.test.ts).
 *
 * - refresh: a viewer's call fetches nothing; an analyst's stores the release;
 * - compatibility from real parsed_logs rows (fields + logsource);
 * - add: disabled, with provenance and attribution; a name taken by another
 *   rule gets a suffix and that rule is untouched; a second add is 409; a
 *   rule with a backtracking regex is refused with nothing saved;
 * - update: "Update available" on the Rules list, enabled choice and rule ids
 *   kept, alerts stay attached, parts added when the OR grows, a removed part
 *   with alerts retired and one without deleted; "Deprecated in SigmaHQ";
 * - role gates on install, update and bulk; bulk add of the compatible rules.
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
import { DetectionRuleModel } from '../models/DetectionRule';
import { closeRegexScanPool } from '../services/regex/regexSafety';
import { closeRegexTestPool } from '../services/regex/boundedRegex';
import { clearSigmaMemory } from '../services/sigma/sigmaStore';
import { IDS, fixtureArchive } from '../services/sigma/sigmaFixture.test';

const SKIP = 'Postgres with the SIEMBox schema is not reachable';
const ROLES = ['analyst', 'viewer'] as const;
type Role = (typeof ROLES)[number];

let dbReady = false;
let server: Server | undefined;
let base = '';
const hex = crypto.randomBytes(3).toString('hex');
const prefix = `sl${hex}`;
const name = `sigmalib-${hex}`;
const tokens = {} as Record<Role, string>;
const userIds: number[] = [];
const parserIds: number[] = [];

// The fake GitHub: which release it serves, and how often it was asked.
let release = { tag: 'r2099-01-01', variant: 1 as 1 | 2 };
let githubCalls = 0;
const realFetch = globalThis.fetch;

function fakeGitHub(input: string | URL | Request, init?: RequestInit): Promise<Response> {
  const url = String(input instanceof Request ? input.url : input);
  if (!url.startsWith('https://github.com/') && !url.startsWith('https://release-assets.githubusercontent.com/')) {
    return realFetch(input, init); // the test's own calls to the app
  }
  githubCalls++;
  if (url.endsWith('/releases/latest/download/sigma_core%2B.zip')) {
    return Promise.resolve(
      new Response(null, { status: 302, headers: { location: `/SigmaHQ/sigma/releases/download/${release.tag}/sigma_core+.zip` } })
    );
  }
  if (url.includes('/releases/download/')) {
    return Promise.resolve(
      new Response(null, { status: 302, headers: { location: 'https://release-assets.githubusercontent.com/asset/1?sig=x' } })
    );
  }
  return Promise.resolve(new Response(fixtureArchive(prefix, release.variant), { status: 200 }));
}

before(async () => {
  try {
    for (const table of ['detection_rules', 'sigma_library_rules', 'sigma_library_state', 'parsed_logs', 'alerts']) {
      await pool.query(`SELECT 1 FROM ${table} LIMIT 1`);
    }
    await pool.query('SELECT sigma_id FROM detection_rules LIMIT 1');
    dbReady = true;
  } catch {
    return;
  }
  globalThis.fetch = fakeGitHub as typeof fetch;
  delete process.env.SIGMAHQ_RELEASE_ASSET;
  await pool.query('DELETE FROM sigma_library_rules');
  await pool.query('DELETE FROM sigma_library_state');
  await pool.query('DELETE FROM detection_rules WHERE sigma_id = ANY($1)', [Object.values(IDS)]);
  clearSigmaMemory();

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
  // Two parsers with recent logs: the fixture product's app (alpha, gamma) and a reverse proxy.
  for (const [parserName, rows] of [
    [`${prefix}-app`, [{ [`${prefix}_alpha`]: 'one', [`${prefix}_gamma`]: 'benign' }, { [`${prefix}_alpha`]: 'zzz' }]],
    [`${prefix}-traefik-access`, [{ user_agent: 'Mozilla/5.0', path: '/' }]],
  ] as const) {
    const p = await pool.query(
      `INSERT INTO parsers (name, enabled, priority, parser_type, pattern, field_mappings)
       VALUES ($1, false, 999, 'regex', '^x$', '{}') RETURNING id`,
      [parserName]
    );
    parserIds.push(p.rows[0].id);
    for (const data of rows) {
      await pool.query(
        `INSERT INTO parsed_logs (parser_id, parsed_data, timestamp, source_ip, event_type, created_at)
         VALUES ($1, $2, NOW(), '10.0.0.1', $3, NOW())`,
        [p.rows[0].id, JSON.stringify(data), `${prefix}_event`]
      );
    }
  }
  server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  globalThis.fetch = realFetch;
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  await Promise.all([closeRegexScanPool(), closeRegexTestPool()]);
  if (dbReady) {
    await pool.query('DELETE FROM detection_rules WHERE sigma_id = ANY($1) OR name LIKE $2', [Object.values(IDS), `${prefix}%`]);
    await pool.query('DELETE FROM parsed_logs WHERE parser_id = ANY($1)', [parserIds]);
    await pool.query('DELETE FROM parsers WHERE id = ANY($1)', [parserIds]);
    await pool.query('DELETE FROM sigma_library_rules');
    await pool.query('DELETE FROM sigma_library_state');
    for (let i = 0; i < 30; i++) {
      // 403s are logged to application_errors fire-and-forget; let them land first.
      await new Promise((r) => setTimeout(r, 100));
    }
    await pool.query('DELETE FROM application_errors WHERE user_id = ANY($1)', [userIds]);
    await pool.query('DELETE FROM audit_logs WHERE user_id = ANY($1)', [userIds]);
    await pool.query('DELETE FROM users WHERE id = ANY($1)', [userIds]);
  }
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
  const res = await realFetch(base + url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  return { status: res.status, json: ((await res.json().catch(() => null)) ?? {}) as Record<string, any> };
}

const rowsFor = (sigmaId: string) => DetectionRuleModel.findBySigmaId(sigmaId);

async function publish(tag: string, variant: 1 | 2) {
  release = { tag, variant };
  const r = await call('analyst', 'POST', '/api/sigma/library/refresh', {});
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.release_tag, tag);
}

async function libraryRow(sigmaId: string, view = 'convertible') {
  const r = await call('viewer', 'GET', `/api/sigma/library?view=${view}&q=${encodeURIComponent(sigmaId)}`);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  return r.json.rules.find((x: any) => x.sigma_id === sigmaId);
}

async function alertOn(ruleId: number) {
  await pool.query(`INSERT INTO alerts (rule_id, severity, title, matched_data) VALUES ($1, 'low', $2, '{}')`, [ruleId, `${prefix} alert`]);
}
const alertCount = async (ruleId: number) => (await pool.query('SELECT 1 FROM alerts WHERE rule_id = $1', [ruleId])).rowCount ?? 0;

test('refresh: a viewer gets the cache and nothing is fetched; an analyst stores the release', async (t) => {
  if (skipUnlessDb(t)) return;
  const v = await call('viewer', 'POST', '/api/sigma/library/refresh', { force: true });
  assert.equal(v.status, 200);
  assert.equal(v.json.refreshed, false);
  assert.equal(githubCalls, 0);
  const empty = await call('viewer', 'GET', '/api/sigma/library');
  assert.equal(empty.json.counts.rules, 0);

  await publish('r2099-01-01', 1);
  assert.equal(githubCalls, 3);
  const lib = await call('viewer', 'GET', '/api/sigma/library?view=convertible&page_size=100');
  assert.equal(lib.json.state.release_tag, 'r2099-01-01');
  assert.equal(lib.json.counts.rules, 7);
  assert.equal(lib.json.counts.convertible, 6);
  assert.equal(lib.json.source.license, 'Detection Rule License (DRL) 1.1');

  // Same release again: one request, nothing downloaded.
  await publish('r2099-01-01', 1);
  assert.equal(githubCalls, 4);
});

test('compatibility comes from the parsed logs: fields and logsource', async (t) => {
  if (skipUnlessDb(t)) return;
  const compatible = await call('viewer', 'GET', '/api/sigma/library?view=compatible&page_size=100&recheck=true');
  const ids = compatible.json.rules.map((r: any) => r.sigma_id);
  assert.ok(ids.includes(IDS.split) && ids.includes(IDS.ua) && ids.includes(IDS.not), JSON.stringify(ids));
  assert.ok(!ids.includes(IDS.windows) && !ids.includes(IDS.keyword));
  const split = compatible.json.rules.find((r: any) => r.sigma_id === IDS.split);
  assert.deepEqual(
    split.compatibility.parsers.map((p: any) => [p.parser_name, p.parts, p.matched]),
    [[`${prefix}-app`, [0], 1]]
  );
  assert.equal(split.parts, 2);
  assert.deepEqual(split.attack, { techniques: [], tactics: [] });

  const win = await libraryRow(IDS.windows);
  assert.equal(win.compatibility.compatible, false);
  assert.equal(win.compatibility.missing_field, 'image');
  const kw = await libraryRow(IDS.keyword);
  assert.ok(kw.compatibility.compatible === false);
  const lossy = await libraryRow(IDS.lossy, 'not_convertible');
  assert.equal(lossy.installable, false);
  assert.match(lossy.not_installable_reason, /not converted faithfully/);
});

test('add: viewer refused; analyst adds disabled with provenance; a taken name gets a suffix', async (t) => {
  if (skipUnlessDb(t)) return;
  const v = await call('viewer', 'POST', `/api/sigma/library/${IDS.ua}/install`);
  assert.equal(v.status, 403);
  assert.equal((await rowsFor(IDS.ua)).length, 0);

  const plain = await DetectionRuleModel.create({
    name: `${prefix} Hack Tool User Agent`,
    severity: 'low',
    rule_yaml: 'name: mine',
    rule_logic: { conditions: [{ field: 'x', operator: 'exists' }] },
  });
  const r = await call('analyst', 'POST', `/api/sigma/library/${IDS.ua}/install`);
  assert.equal(r.status, 201, JSON.stringify(r.json));
  const [row] = await rowsFor(IDS.ua);
  assert.equal(row.name, `${prefix} Hack Tool User Agent (SigmaHQ)`);
  assert.equal(row.enabled, false);
  assert.equal(row.sigma_release, 'r2099-01-01');
  assert.equal(row.sigma_part, 1);
  assert.match(row.sigma_hash ?? '', /^[0-9a-f]{64}$/);
  assert.match(row.description ?? '', /by Jane Doe, John Roe, release r2099-01-01: https:\/\/github\.com\/SigmaHQ\/sigma\/blob\//);
  assert.ok(row.tags.includes('sigmahq') && row.tags.includes('attack.t1190'));
  const untouched = await DetectionRuleModel.findById(plain.id);
  assert.equal(untouched?.rule_yaml, 'name: mine');
  assert.equal(untouched?.sigma_id, null);

  const again = await call('analyst', 'POST', `/api/sigma/library/${IDS.ua}/install`);
  assert.equal(again.status, 409);
  assert.equal(again.json.code, 'SIGMA_ALREADY_ADDED');
  assert.equal((await libraryRow(IDS.ua)).installed.rule_ids.length, 1);
});

test('add: a rule with a backtracking regex is refused, nothing saved', async (t) => {
  if (skipUnlessDb(t)) return;
  const r = await call('analyst', 'POST', `/api/sigma/library/${IDS.redos}/install`);
  assert.equal(r.status, 422, JSON.stringify(r.json));
  assert.equal(r.json.code, 'REGEX_UNSAFE');
  assert.equal((await rowsFor(IDS.redos)).length, 0);
  assert.equal((await call('analyst', 'POST', `/api/sigma/library/not-a-uuid/install`)).status, 400);
  assert.equal((await call('analyst', 'POST', `/api/sigma/library/${IDS.lossy}/install`)).status, 422);
});

test('update keeps enabled and ids, keeps alerts, follows the part count; deprecated is flagged', async (t) => {
  if (skipUnlessDb(t)) return;
  assert.equal((await call('analyst', 'POST', `/api/sigma/library/${IDS.split}/install`)).status, 201);
  assert.equal((await call('analyst', 'POST', `/api/sigma/library/${IDS.not}/install`)).status, 201);
  const [p1, p2] = await rowsFor(IDS.split);
  assert.deepEqual([p1.name, p2.name], [`${prefix} Split Rule (part 1 of 2)`, `${prefix} Split Rule (part 2 of 2)`]);
  await DetectionRuleModel.update(p1.id, { enabled: true });
  await alertOn(p1.id);

  // Nothing to update yet.
  let list = await call('viewer', 'GET', '/api/rules');
  const prov = (id: number) => list.json.find((r: any) => r.id === id)?.sigma;
  assert.equal(prov(p1.id).update_available, false);
  assert.equal(prov(p1.id).deprecated, false);
  assert.match(prov(p1.id).url, /blob\/r2099-01-01\/rules\/linux\/fixture\/split\.yml$/);

  // SigmaHQ grows the OR to three alternatives, changes the UA rule and drops the NOT rule.
  await publish('r2099-02-01', 2);
  list = await call('viewer', 'GET', '/api/rules');
  assert.equal(prov(p1.id).update_available, true);
  const [notRow] = await rowsFor(IDS.not);
  assert.equal(prov(notRow.id).deprecated, true);
  const updates = await call('viewer', 'GET', '/api/sigma/library?view=convertible&installed=updates&page_size=100');
  assert.deepEqual(updates.json.rules.map((r: any) => r.sigma_id).sort(), [IDS.ua, IDS.split].sort());
  assert.equal(updates.json.counts.updates, 2);

  assert.equal((await call('viewer', 'POST', `/api/sigma/library/${IDS.split}/update`)).status, 403);
  const up = await call('analyst', 'POST', `/api/sigma/library/${IDS.split}/update`);
  assert.equal(up.status, 200, JSON.stringify(up.json));
  const grown = await rowsFor(IDS.split);
  assert.deepEqual(grown.map((r) => r.sigma_part), [1, 2, 3]);
  assert.deepEqual(grown.slice(0, 2).map((r) => r.id), [p1.id, p2.id]); // same rows
  assert.deepEqual(grown.map((r) => r.enabled), [true, false, true]); // kept; the new part takes the rule's choice
  assert.equal(grown[2].name, `${prefix} Split Rule (part 3 of 3)`);
  assert.ok(grown.every((r) => r.sigma_release === 'r2099-02-01'));
  assert.equal(await alertCount(p1.id), 1);
  list = await call('viewer', 'GET', '/api/rules');
  assert.equal(prov(p1.id).update_available, false);

  // Shrinks back to two: the third part has an alert, so it is retired, not deleted.
  await alertOn(grown[2].id);
  await publish('r2099-03-01', 1);
  assert.equal((await call('analyst', 'POST', `/api/sigma/library/${IDS.split}/update`)).status, 200);
  assert.deepEqual((await rowsFor(IDS.split)).map((r) => r.id), [p1.id, p2.id]);
  const retired = await DetectionRuleModel.findById(grown[2].id);
  assert.ok(retired && retired.enabled === false && retired.sigma_id === null && /\(retired \d+\)$/.test(retired.name));
  assert.equal(await alertCount(grown[2].id), 1);

  // Grows and shrinks again: the new third part has no alerts, so it is removed.
  await publish('r2099-04-01', 2);
  await call('analyst', 'POST', `/api/sigma/library/${IDS.split}/update`);
  const third = (await rowsFor(IDS.split))[2];
  await publish('r2099-05-01', 1);
  const shrink = await call('analyst', 'POST', `/api/sigma/library/${IDS.split}/update`);
  assert.deepEqual(shrink.json.removed, [third.id]);
  assert.equal(await DetectionRuleModel.findById(third.id), null);

  const never = await call('analyst', 'POST', `/api/sigma/library/${IDS.windows}/update`);
  assert.equal(never.status, 404);
  assert.equal(never.json.code, 'SIGMA_NOT_ADDED');
});

test('bulk add: viewer refused; analyst adds the compatible rules, skipping added ones and reporting refusals', async (t) => {
  if (skipUnlessDb(t)) return;
  assert.equal((await call('viewer', 'POST', '/api/sigma/library/install-bulk', { all_compatible: true })).status, 403);
  assert.equal((await call('analyst', 'POST', '/api/sigma/library/install-bulk', { sigma_ids: ['x'] })).status, 400);
  const r = await call('analyst', 'POST', '/api/sigma/library/install-bulk', { sigma_ids: [IDS.ua, IDS.redos, IDS.windows] });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.deepEqual(r.json.skipped, [IDS.ua]);
  assert.equal(r.json.added, 1); // the Windows rule (compatibility is the UI's filter, not a gate)
  assert.deepEqual(r.json.failed.map((f: any) => [f.sigma_id, f.code]), [[IDS.redos, 'REGEX_UNSAFE']]);
  const all = await call('analyst', 'POST', '/api/sigma/library/install-bulk', { all_compatible: true });
  assert.equal(all.status, 200, JSON.stringify(all.json));
  assert.ok(all.json.skipped.includes(IDS.split));
  assert.ok(!all.json.skipped.includes(IDS.keyword) && all.json.added === 0);
});
