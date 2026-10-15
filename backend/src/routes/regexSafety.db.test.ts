/**
 * Regex safety end to end: the real app on an ephemeral port and a real
 * Postgres. Every write path refuses a regex recheck proves ReDoS-vulnerable
 * (422 REGEX_UNSAFE, nothing saved) and accepts an indeterminate one with a
 * warning; "try this pattern" routes run in a worker with a time budget (422
 * REGEX_TIMEOUT) while the event loop keeps answering; the startup scan flags a
 * stored unsafe parser or rule (WARN + `regex_safety` on the list) without
 * disabling it.
 *
 * Catalog and content-pack installs read a fake GitHub (the catalog repository
 * named below does not exist). Skips itself when Postgres isn't reachable.
 * Every row created here is removed again. Run with `npm test` (tsx --test).
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
import { closeRegexScanPool } from '../services/regex/regexSafety';
import { closeRegexTestPool } from '../services/regex/boundedRegex';
import { scanStoredRegexes } from '../services/regex/storedRegexScan';
import { logger } from '../utils/logger';

const ROLES = ['admin', 'analyst', 'viewer'] as const;
type Role = (typeof ROLES)[number];
const SKIP = 'Postgres with the SIEMBox schema is not reachable';
const TEST_ROW_NAME = '^regexsafety-[0-9a-f]{12}(-[a-z-]+)?$';

process.env.SIEMBOX_CATALOG_REPO = 'siembox-regex-safety-test.invalid/no-such-catalog';
process.env.SIEMBOX_CATALOG_REF = 'none';

let dbReady = false;
let server: Server | undefined;
let base = '';
const tag = crypto.randomBytes(6).toString('hex');
const name = `regexsafety-${tag}`;
const tokens = {} as Record<Role, string>;
const userIds: number[] = [];

/** The classic: exponential on 'a'.repeat(40) + '!'. Unique per run so no cached verdict hides a path. */
const EXPONENTIAL = `^(?:${tag})?(a+)+$`;
const ATTACK = 'a'.repeat(40) + '!';
const REFUSAL = 'ReDoS: regex at pattern is vulnerable (exponential) — rewrite it linear before saving';

before(async () => {
  try {
    for (const table of ['sessions', 'parsers', 'detection_rules', 'regex_safety_verdicts']) {
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
  await Promise.all([closeRegexScanPool(), closeRegexTestPool()]);
  if (dbReady) {
    const stale = `created_at < NOW() - INTERVAL '10 minutes'`;
    await pool.query(`DELETE FROM parsers WHERE name LIKE $1 OR (name ~ $2 AND ${stale})`, [`${name}%`, TEST_ROW_NAME]);
    await pool.query(`DELETE FROM detection_rules WHERE name LIKE $1 OR (name ~ $2 AND ${stale})`, [`${name}%`, TEST_ROW_NAME]);
    await pool.query('DELETE FROM audit_logs WHERE user_id = ANY($1)', [userIds]);
    await pool.query('DELETE FROM application_errors WHERE user_id = ANY($1)', [userIds]);
    await pool.query('DELETE FROM users WHERE id = ANY($1)', [userIds]);
  }
  await closePools();
});

interface Body {
  [key: string]: any;
}

async function call(role: Role | null, method: string, path: string, body?: unknown) {
  const headers: Record<string, string> = {};
  if (role) headers.Authorization = `Bearer ${tokens[role]}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const started = Date.now();
  const res = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  return { status: res.status, json: ((await res.json().catch(() => null)) ?? {}) as Body, ms: Date.now() - started };
}

async function countRows(table: 'parsers' | 'detection_rules', rowName: string): Promise<number> {
  return (await pool.query(`SELECT count(*)::int AS n FROM ${table} WHERE name = $1`, [rowName])).rows[0].n;
}

function parserBody(suffix: string, pattern: string) {
  return {
    name: `${name}-${suffix}`,
    description: 'regex safety test',
    enabled: false,
    priority: 1000,
    parser_type: 'regex',
    pattern,
    field_mappings: {},
  };
}

function portable(suffix: string, pattern: string, extra: Record<string, unknown> = {}) {
  return {
    schema: 'siembox.parser/v1',
    ...parserBody(suffix, pattern),
    test_samples: [{ input: `${name} hello`, expect: { message: `${name} hello` } }],
    ...extra,
  };
}

function ruleYaml(conditionValue: string): string {
  return [
    'conditions:',
    '  - field: message',
    '    operator: regex',
    `    value: '${conditionValue}'`,
    'alert:',
    '  title: regex safety test',
    '  description: regex safety test',
  ].join('\n');
}

/** Insert a row directly, as an install from before the gate would have left it. */
async function seedParser(suffix: string, pattern: string): Promise<number> {
  const r = await pool.query(
    `INSERT INTO parsers (name, description, enabled, priority, parser_type, pattern, field_mappings)
     VALUES ($1, 'saved before the regex gate', false, 1000, 'regex', $2, '{}') RETURNING id`,
    [`${name}-${suffix}`, pattern]
  );
  return r.rows[0].id;
}

async function seedRule(suffix: string, regex: string): Promise<number> {
  const logic = { conditions: [{ field: 'message', operator: 'regex', value: regex }], alert: { title: 't', description: 't' } };
  const r = await pool.query(
    `INSERT INTO detection_rules (name, description, enabled, severity, rule_yaml, rule_logic, tags)
     VALUES ($1, 'saved before the regex gate', false, 'low', $2, $3, '{}') RETURNING id`,
    [`${name}-${suffix}`, ruleYaml(regex), JSON.stringify(logic)]
  );
  return r.rows[0].id;
}

// ---------------------------------------------------------------------------
// Write-time refusal, path by path.
// ---------------------------------------------------------------------------

test('POST /api/parsers refuses a vulnerable pattern with 422 and saves nothing', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const res = await call('analyst', 'POST', '/api/parsers', parserBody('create', EXPONENTIAL));
  assert.equal(res.status, 422, JSON.stringify(res.json));
  assert.equal(res.json.code, 'REGEX_UNSAFE');
  assert.deepEqual(res.json.errors, [REFUSAL]);
  assert.equal(res.json.message, `Parser "${name}-create" was not saved: ${REFUSAL}`);
  assert.equal(res.json.regex_safety.vulnerable[0].source, EXPONENTIAL, 'names the regex');
  assert.equal(await countRows('parsers', `${name}-create`), 0);

  const ok = await call('analyst', 'POST', '/api/parsers', parserBody('create-ok', `^${name} (?<message>.+)$`));
  assert.equal(ok.status, 201, JSON.stringify(ok.json));
  assert.deepEqual(ok.json.warnings, []);
});

test('PUT /api/parsers/:id refuses a vulnerable derivation, but never an edit that leaves the regexes alone', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const id = (await call('analyst', 'POST', '/api/parsers', parserBody('update', `^${name} (?<message>.+)$`))).json.id;
  const refused = await call('analyst', 'PUT', `/api/parsers/${id}`, {
    derivations: [{ when: { message: { matches: `(?:${tag})?(x+x+)+y` } }, set: { flagged: true } }],
  });
  assert.equal(refused.status, 422, JSON.stringify(refused.json));
  assert.match(refused.json.errors[0], /^ReDoS: regex at derivations\[0\]\.when\.message\.matches is vulnerable \(exponential\)/);
  assert.equal((await pool.query('SELECT derivations FROM parsers WHERE id = $1', [id])).rows[0].derivations, null);

  // A parser saved before the gate: disabling it (the mitigation) is never refused.
  const seeded = await seedParser('update-seeded', EXPONENTIAL);
  const disabled = await call('analyst', 'PUT', `/api/parsers/${seeded}`, { enabled: false, description: 'off for now' });
  assert.equal(disabled.status, 200, JSON.stringify(disabled.json));
  // Touching its pattern without fixing it is refused.
  const repatterned = await call('analyst', 'PUT', `/api/parsers/${seeded}`, { pattern: `${EXPONENTIAL}|x` });
  assert.equal(repatterned.status, 422);
});

test('POST /api/parsers/import refuses a vulnerable regex even with force, and /validate refuses it fast', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const bad = portable('import', `^${name} (?<message>.+)$`, {
    derivations: [{ extract: { user: { from: 'message', pattern: `(?:${tag})?(\\w+\\s?)+$` } } }],
  });
  for (const force of [false, true]) {
    const res = await call('analyst', 'POST', '/api/parsers/import', { parser: bad, force });
    assert.equal(res.status, 422, JSON.stringify(res.json));
    assert.equal(res.json.code, 'REGEX_UNSAFE');
    assert.match(res.json.errors[0], /^ReDoS: regex at derivations\[0\]\.extract\.user is vulnerable/);
  }
  assert.equal(await countRows('parsers', `${name}-import`), 0);

  // The import preview refuses what the import would, before running a self-test.
  const preview = await call('analyst', 'POST', '/api/parsers/validate', {
    parser: portable('validate', EXPONENTIAL, { test_samples: [{ input: ATTACK, expect: { message: ATTACK } }] }),
  });
  assert.equal(preview.status, 422, JSON.stringify(preview.json));
  assert.equal(preview.json.code, 'REGEX_UNSAFE');
  assert.ok(preview.ms < 2000, `answered in ${preview.ms} ms`);
});

test('an indeterminate regex is saved with a warning', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const previous = process.env.REGEX_SAFETY_CHECK_TIMEOUT_MS;
  process.env.REGEX_SAFETY_CHECK_TIMEOUT_MS = '100'; // too short to settle this one
  t.after(() => {
    if (previous === undefined) delete process.env.REGEX_SAFETY_CHECK_TIMEOUT_MS;
    else process.env.REGEX_SAFETY_CHECK_TIMEOUT_MS = previous;
  });
  const pattern =
    `^(?:${tag})?(?<client_ip>[\\d.]+) - (?<remote_user>\\S+) \\[(?<timestamp>[^\\]]+)\\] "(?<method>\\w+) (?<request_uri>\\S+) ` +
    '(?<protocol>[^"]+)" (?<status_code>\\d{3}) (?<bytes>\\d+|-)(?: "(?<referer>[^"]*)" "(?<user_agent>[^"]*)")?$';
  const res = await call('analyst', 'POST', '/api/parsers', parserBody('indeterminate', pattern));
  assert.equal(res.status, 201, JSON.stringify(res.json));
  assert.equal(res.json.warnings.length, 1);
  assert.match(res.json.warnings[0], /^ReDoS: regex at pattern could not be proven safe \(unknown: /);
});

test('a regex that is not a string is refused on every write (the gate analyzes strings, the engines compile only strings)', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const id = (await call('analyst', 'POST', '/api/parsers', parserBody('types', `^${name} (?<payload>\\S+)$`))).json.id;
  const stored = async () => (await pool.query('SELECT pattern, derivations FROM parsers WHERE id = $1', [id])).rows[0];

  // Array-wrapped derivation regexes used to pass as "safe" and run as the regex they wrap.
  const arrayMatches = await call('analyst', 'PUT', `/api/parsers/${id}`, {
    derivations: [{ when: { payload: { matches: [`^(?:${tag})?(a+)+$`] } }, set: { t: '1' } }],
  });
  assert.equal(arrayMatches.status, 400, JSON.stringify(arrayMatches.json));
  assert.match(arrayMatches.json.message, /^Invalid derivations: derivations\[0\]\.when\.payload\.matches must be a string \(a regex\)$/);
  const arrayExtract = await call('analyst', 'PUT', `/api/parsers/${id}`, {
    derivations: [{ extract: { q: { from: 'payload', pattern: [`^(?:${tag})?(a+)+$`] } } }],
  });
  assert.equal(arrayExtract.status, 400, JSON.stringify(arrayExtract.json));
  // ...and an array pattern used to be stored as its pg array literal, {"..."}.
  const arrayPattern = await call('analyst', 'PUT', `/api/parsers/${id}`, { pattern: [`|^(?:${tag})?(c+)+$|`] });
  assert.equal(arrayPattern.status, 400, JSON.stringify(arrayPattern.json));
  assert.equal(arrayPattern.json.message, 'pattern must be a string');
  assert.deepEqual(await stored(), { pattern: `^${name} (?<payload>\\S+)$`, derivations: null });

  // Import (and so catalog install, Install all, content packs) refuses it as invalid.
  const imported = await call('analyst', 'POST', '/api/parsers/import', {
    parser: portable('types-import', `^${name} (?<payload>\\S+)$`, {
      derivations: [{ when: { payload: { matches: [`^(?:${tag})?(a|a)+$`] } }, set: { x: 'y' } }],
    }),
  });
  assert.equal(imported.status, 422, JSON.stringify(imported.json));
  assert.ok(imported.json.validation.errors.includes('derivations[0].when.payload.matches must be a string (a regex)'));
  assert.equal(await countRows('parsers', `${name}-types-import`), 0);

  // Rules: flags: [i] used to be analyzed WITHOUT "i" and run WITH it.
  const flagsYaml = [
    'conditions:',
    '  - field: payload',
    '    operator: regex',
    `    value: '^(?:${tag})?(?:q|Q)+$'`,
    '    flags: [i]',
    'alert:',
    '  title: t',
    '  description: d',
  ].join('\n');
  const rule = await call('analyst', 'POST', '/api/rules', { name: `${name}-types-rule`, severity: 'low', enabled: false, rule_yaml: flagsYaml });
  assert.equal(rule.status, 400, JSON.stringify(rule.json));
  assert.equal(rule.json.message, 'Invalid rule: conditions[0].flags must be a string (e.g. "i")');
  assert.equal(await countRows('detection_rules', `${name}-types-rule`), 0);
  // The same rule with `flags: i` is refused as the exponential regex it is.
  const asString = await call('analyst', 'POST', '/api/rules', {
    name: `${name}-types-rule`,
    severity: 'low',
    enabled: false,
    rule_yaml: flagsYaml.replace('flags: [i]', 'flags: i'),
  });
  assert.equal(asString.status, 422, JSON.stringify(asString.json));
  assert.equal(asString.json.code, 'REGEX_UNSAFE');

  const good = await call('analyst', 'POST', '/api/rules', { name: `${name}-types-rule`, severity: 'low', enabled: false, rule_yaml: ruleYaml(`^${name}`) });
  assert.equal(good.status, 201, JSON.stringify(good.json));
  const direct = await call('analyst', 'PUT', `/api/rules/${good.json.id}`, {
    rule_logic: { conditions: [{ field: 'payload', operator: 'regex', value: `^(?:${tag})?(?:q|Q)+$`, flags: ['i'] }] },
  });
  assert.equal(direct.status, 400, JSON.stringify(direct.json));
  const viaYaml = await call('analyst', 'PUT', `/api/rules/${good.json.id}`, { rule_yaml: flagsYaml });
  assert.equal(viaYaml.status, 400, JSON.stringify(viaYaml.json));
  const logic = (await pool.query('SELECT rule_logic FROM detection_rules WHERE id = $1', [good.json.id])).rows[0].rule_logic;
  assert.equal(logic.conditions[0].value, `^${name}`, 'unchanged');
});

test('a bounded repeat over overlapping alternatives is refused at write time', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  // recheck's defaults rated this "safe"; 'a'.repeat(10) + '!' stalled the API for tens of seconds.
  const res = await call('analyst', 'POST', '/api/parsers', parserBody('bounded', `^(?:${tag})?(?<x>(?:a|a|a|a|a|a|a|a){1,12})$`));
  assert.equal(res.status, 422, JSON.stringify(res.json));
  assert.equal(res.json.code, 'REGEX_UNSAFE');
  assert.equal(await countRows('parsers', `${name}-bounded`), 0);
});

test('detection rules: create, update and rule_logic sent directly are gated; enable/disable is not', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const vulnerable = `(?:${tag})?^(a|a)+$`;
  const created = await call('analyst', 'POST', '/api/rules', {
    name: `${name}-rule`,
    severity: 'low',
    enabled: false,
    rule_yaml: ruleYaml(vulnerable),
  });
  assert.equal(created.status, 422, JSON.stringify(created.json));
  assert.deepEqual(created.json.errors, ['ReDoS: regex at conditions[0].value is vulnerable (exponential) — rewrite it linear before saving']);
  assert.equal(await countRows('detection_rules', `${name}-rule`), 0);

  const good = await call('analyst', 'POST', '/api/rules', {
    name: `${name}-rule`,
    severity: 'low',
    enabled: false,
    rule_yaml: ruleYaml(`^${name}`),
  });
  assert.equal(good.status, 201, JSON.stringify(good.json));
  const id = good.json.id;
  const viaYaml = await call('analyst', 'PUT', `/api/rules/${id}`, { rule_yaml: ruleYaml(vulnerable) });
  assert.equal(viaYaml.status, 422);
  const viaLogic = await call('analyst', 'PUT', `/api/rules/${id}`, {
    rule_logic: { conditions: [{ field: 'message', operator: 'regex', value: vulnerable }] },
  });
  assert.equal(viaLogic.status, 422, 'rule_logic without YAML cannot slip past');
  const stored = (await pool.query('SELECT rule_logic FROM detection_rules WHERE id = $1', [id])).rows[0].rule_logic;
  assert.equal(stored.conditions[0].value, `^${name}`);

  const seeded = await seedRule('rule-seeded', vulnerable);
  assert.equal((await call('analyst', 'PUT', `/api/rules/${seeded}`, { enabled: false })).status, 200);
});

test('Sigma import: the preview shows the refusal inline and the import skips the rule', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const sigma = [
    `title: ${name}-sigma`,
    'level: low',
    'detection:',
    '  selection:',
    `    c-uri|re: '(?:${tag})?^(a+)+$'`,
    '  condition: selection',
  ].join('\n');
  const preview = await call('admin', 'POST', '/api/rules/import/sigma/preview', { sigma });
  assert.equal(preview.status, 200);
  assert.equal(preview.json.convertible, 0);
  assert.equal(preview.json.results[0].ok, false);
  assert.ok(
    preview.json.results[0].errors.some((e: string) => /^ReDoS: regex at conditions\[0\]\.value is vulnerable/.test(e)),
    JSON.stringify(preview.json.results[0].errors)
  );
  const imported = await call('admin', 'POST', '/api/rules/import/sigma', { sigma });
  assert.equal(imported.status, 200);
  assert.equal(imported.json.created, 0);
  assert.equal(imported.json.failed[0].code, 'REGEX_UNSAFE');
  assert.equal(await countRows('detection_rules', `${name}-sigma`), 0);
});

/** A fake GitHub holding this test's catalog; any other URL is a 404. */
function fakeCatalogRepo(t: TestContext, files: Record<string, string>) {
  const repo = process.env.SIEMBOX_CATALOG_REPO;
  const ref = process.env.SIEMBOX_CATALOG_REF;
  const get = (url: string, _options: unknown, onResponse: (res: PassThrough) => void) => {
    let status = 404;
    let body = '';
    const raw = `https://raw.githubusercontent.com/${repo}/${ref}/`;
    if (url === `https://api.github.com/repos/${repo}/git/trees/${ref}?recursive=1`) {
      status = 200;
      body = JSON.stringify({ tree: Object.keys(files).map((path) => ({ path, type: 'blob' })) });
    } else if (url.startsWith(raw) && files[url.slice(raw.length)] !== undefined) {
      [status, body] = [200, files[url.slice(raw.length)]];
    }
    const res = Object.assign(new PassThrough(), { statusCode: status, headers: {} });
    setImmediate(() => {
      onResponse(res);
      res.end(body);
    });
    return Object.assign(new EventEmitter(), { setTimeout: () => undefined, destroy: () => undefined });
  };
  t.mock.method(https as unknown as { get: typeof get }, 'get', get);
  clearCatalogCache();
  clearDetectionCache();
  t.after(() => {
    clearCatalogCache();
    clearDetectionCache();
  });
}

test('catalog installs (one and all) and content packs refuse a vulnerable catalog item and install the rest', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const safe = portable('catalog-safe', `^${name} (?<message>.+)$`);
  const unsafe = portable('catalog-unsafe', `^(?:${name} )?(a+)+$`, {
    test_samples: [{ input: 'aaa', expect: { message: 'aaa' } }],
  });
  // Content pack "media" installs the catalog parsers named plex and jellyfin:
  // plex is unsafe here (refused, nothing written) and jellyfin is absent.
  const plex = { ...portable('plex', `^(?:${tag} )?(b+)+$`), name: 'plex', test_samples: [{ input: 'bbb', expect: { message: 'bbb' } }] };
  fakeCatalogRepo(t, {
    [`parsers/${name}-safe.parser.json`]: JSON.stringify(safe),
    [`parsers/${name}-unsafe.parser.json`]: JSON.stringify(unsafe),
    'parsers/plex.parser.json': JSON.stringify(plex),
    [`detections/x/${name}-rule-safe.yaml`]: [`name: ${name}-catalog-rule-safe`, 'severity: low', ruleYaml(`^${name}`)].join('\n'),
    [`detections/x/${name}-rule-unsafe.yaml`]: [`name: ${name}-catalog-rule-unsafe`, 'severity: low', ruleYaml(`(?:${tag})?(x+x+)+y`)].join('\n'),
  });
  const plexBefore = (await pool.query(`SELECT md5(t::text) AS h FROM parsers t WHERE name = 'plex'`)).rows[0]?.h ?? null;

  const one = await call('analyst', 'POST', '/api/parsers/catalog/install', { name: `${name}-catalog-unsafe`, force: true });
  assert.equal(one.status, 422, JSON.stringify(one.json));
  assert.equal(one.json.code, 'REGEX_UNSAFE');
  assert.equal(one.json.message, `Catalog parser "${name}-catalog-unsafe" was not saved: ${REFUSAL}`);

  const all = await call('analyst', 'POST', '/api/parsers/catalog/install-all', { force: true });
  assert.equal(all.status, 200, JSON.stringify(all.json));
  const failed = Object.fromEntries(all.json.failed.map((f: any) => [f.name, f]));
  assert.equal(failed[`${name}-catalog-unsafe`].code, 'REGEX_UNSAFE');
  assert.equal(failed[`${name}-catalog-unsafe`].reason, REFUSAL);
  assert.equal(failed.plex.code, 'REGEX_UNSAFE');
  assert.equal(await countRows('parsers', `${name}-catalog-unsafe`), 0);
  assert.equal(await countRows('parsers', `${name}-catalog-safe`), 1, 'the safe item installed');

  const rules = await call('analyst', 'POST', '/api/rules/catalog/install-all');
  assert.equal(rules.status, 200, JSON.stringify(rules.json));
  assert.deepEqual(rules.json.failed.map((f: any) => [f.name, f.code]), [[`${name}-catalog-rule-unsafe`, 'REGEX_UNSAFE']]);
  assert.equal(await countRows('detection_rules', `${name}-catalog-rule-safe`), 1);
  assert.equal(await countRows('detection_rules', `${name}-catalog-rule-unsafe`), 0);
  const oneRule = await call('analyst', 'POST', '/api/rules/catalog/install', { name: `${name}-catalog-rule-unsafe` });
  assert.equal(oneRule.status, 422);

  const pack = await call('admin', 'POST', '/api/packs/media/install');
  assert.equal(pack.status, 200, JSON.stringify(pack.json));
  const packFailed = Object.fromEntries(pack.json.parsers.failed.map((f: any) => [f.name, f.reason]));
  assert.equal(packFailed.plex, 'ReDoS: regex at pattern is vulnerable (exponential) — rewrite it linear before saving');
  assert.equal(pack.json.parsers.installed + pack.json.parsers.updated, 0);
  const plexAfter = (await pool.query(`SELECT md5(t::text) AS h FROM parsers t WHERE name = 'plex'`)).rows[0]?.h ?? null;
  assert.equal(plexAfter, plexBefore, 'an existing plex parser is untouched');
});

// ---------------------------------------------------------------------------
// Bounded execution.
// ---------------------------------------------------------------------------

test("POST /api/parsers/test stops ^(a+)+$ on 'a'.repeat(40)+'!' with 422 while /health keeps answering", async (t) => {
  if (!dbReady) return t.skip(SKIP);
  // Warm the pool so the measured call is the regex, not a worker start.
  await call('analyst', 'POST', '/api/parsers/test', { ...parserBody('warm', '^x'), sample: 'x' });

  const pending = call('analyst', 'POST', '/api/parsers/test', { ...parserBody('test', EXPONENTIAL), sample: ATTACK });
  const health: number[] = [];
  for (let i = 0; i < 5; i++) {
    await new Promise((resolve) => setTimeout(resolve, 150));
    health.push((await call(null, 'GET', '/health')).ms);
  }
  const res = await pending;
  assert.equal(res.status, 422, JSON.stringify(res.json));
  assert.equal(res.json.code, 'REGEX_TIMEOUT');
  assert.match(res.json.message, /did not finish within 1000 ms/);
  assert.ok(res.ms < 2500, `answered in ${res.ms} ms`);
  assert.ok(Math.max(...health) < 250, `GET /health took ${health.join(', ')} ms during the run`);
});

test('POST /api/parsers/:id/test (any role) bounds a stored pattern that predates the gate; samples are capped', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const id = await seedParser('stored-test', EXPONENTIAL);
  const res = await call('viewer', 'POST', `/api/parsers/${id}/test`, { sample: ATTACK });
  assert.equal(res.status, 422, JSON.stringify(res.json));
  assert.equal(res.json.code, 'REGEX_TIMEOUT');
  assert.ok(res.ms < 2500, `answered in ${res.ms} ms`);

  const big = await call('viewer', 'POST', `/api/parsers/${id}/test`, { sample: 'x'.repeat(70 * 1024) });
  assert.equal(big.status, 413);
  assert.equal(big.json.code, 'SAMPLE_TOO_LARGE');
  const bigPreview = await call('analyst', 'POST', '/api/parsers/test', { ...parserBody('big', '^x'), sample: 'x'.repeat(70 * 1024) });
  assert.equal(bigPreview.status, 413);

  const invalid = await call('analyst', 'POST', '/api/parsers/test', { ...parserBody('invalid', '(unclosed'), sample: 'x' });
  assert.equal(invalid.status, 422);
  assert.equal(invalid.json.code, 'REGEX_TEST_FAILED');
  assert.match(invalid.json.message, /Invalid regular expression/);
});

// ---------------------------------------------------------------------------
// Existing data.
// ---------------------------------------------------------------------------

test('the startup scan flags a stored unsafe parser and rule (WARN, list tag) and leaves them as they are', async (t) => {
  if (!dbReady) return t.skip(SKIP);
  const parserId = await seedParser('stored-unsafe', `^(?:${tag}-stored)?(a+)+$`);
  const ruleId = await seedRule('stored-unsafe-rule', `(?:${tag}-stored)?(x+x+)+y`);
  const warn = t.mock.method(logger, 'warn');

  const result = await scanStoredRegexes();
  const flagged = result.vulnerable.map((v) => `${v.kind}:${v.name}`);
  assert.ok(flagged.includes(`parser:${name}-stored-unsafe`), flagged.join(', '));
  assert.ok(flagged.includes(`rule:${name}-stored-unsafe-rule`), flagged.join(', '));
  const lines = warn.mock.calls.map((c) => String(c.arguments[0]));
  assert.ok(
    lines.some((l) => l.includes(`Parser "${name}-stored-unsafe" (id ${parserId}, disabled) has an unsafe regex at pattern`)),
    lines.join('\n')
  );
  assert.ok(lines.some((l) => l.includes(`Detection rule "${name}-stored-unsafe-rule"`)), lines.join('\n'));

  const list = await call('viewer', 'GET', '/api/parsers');
  const row = (list.json as unknown as Body[]).find((p) => p.id === parserId)!;
  assert.equal(row.regex_safety.status, 'vulnerable');
  assert.equal(row.regex_safety.vulnerable[0].location, 'pattern');
  const rules = await call('viewer', 'GET', `/api/rules/${ruleId}`);
  assert.equal(rules.json.regex_safety.status, 'vulnerable');

  // Nothing was disabled or changed by the scan.
  const stored = (await pool.query('SELECT pattern FROM parsers WHERE id = $1', [parserId])).rows[0];
  assert.equal(stored.pattern, `^(?:${tag}-stored)?(a+)+$`);
});
