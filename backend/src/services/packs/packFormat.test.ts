/**
 * The pack format validator (packFormat.validatePack) and the validate-packs
 * script: schema, caps, references, Sigma ids, and the markdown safety rules
 * for setup guides. No database or network. Run with `npm test`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { markdownProblems, stripCode, validatePack, detectionMatchesPack, PACK_LIMITS } from './packFormat';

const SIGMA_ID = '65354b83-a2ea-4ea6-8414-3ab38be0d409';

function pack(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schema: 'siembox.pack/v1',
    id: 'web',
    name: 'Web',
    description: 'Web logs.',
    icon: 'Connection',
    version: 2,
    parsers: ['traefik-access'],
    detections: { categories: ['reverse-proxy'], tags: ['web'], names: ['PROXY-001 Path Traversal'] },
    sigma: [{ id: SIGMA_ID, title: 'Cross Site Scripting Strings' }],
    setup: [{ title: 'Ship it', text: 'Use a **File** source. See [docs](https://example.com/x).', code: 'volumes:\n  - /var/log:/var/log:ro', code_language: 'yaml' }],
    ...over,
  };
}

const errorsOf = (obj: unknown, opts = {}) => validatePack(obj, { strict: true, ...opts }).errors;

test('a well-formed pack passes and is normalized', () => {
  const v = validatePack(pack(), { strict: true });
  assert.deepEqual(v.errors, []);
  assert.equal(v.pack?.version, 2);
  assert.deepEqual(v.pack?.detections, { categories: ['reverse-proxy'], tags: ['web'], names: ['PROXY-001 Path Traversal'] });
  assert.deepEqual(v.pack?.sigma, [{ id: SIGMA_ID, title: 'Cross Site Scripting Strings' }]);
});

test('schema, id, icon and version are checked', () => {
  assert.match(errorsOf(pack({ schema: 'siembox.pack/v0' })).join(), /schema must be/);
  assert.match(errorsOf(pack({ id: 'Web Pack' })).join(), /kebab-case/);
  assert.match(errorsOf(pack({ icon: 'Skull' })).join(), /icon "Skull"/);
  for (const version of [0, -1, 1.5, '2', null]) assert.match(errorsOf(pack({ version })).join(), /version must be/, String(version));
  assert.match(errorsOf(pack(), { expectId: 'other' }).join(), /does not match the file name/);
  assert.match(errorsOf('not a mapping').join(), /YAML mapping/);
});

test('unknown keys are errors when strict and warnings otherwise', () => {
  assert.match(errorsOf(pack({ extra: 1 })).join(), /unknown key "extra"/);
  const loose = validatePack(pack({ extra: 1 }), { strict: false });
  assert.equal(loose.ok, true);
  assert.match(loose.warnings.join(), /unknown key "extra"/);
});

test('item lists: slugs, duplicates, caps, and at least one item', () => {
  assert.match(errorsOf(pack({ parsers: ['Traefik Access'] })).join(), /kebab-case name/);
  assert.match(errorsOf(pack({ parsers: ['a', 'a'] })).join(), /lists "a" twice/);
  assert.match(errorsOf(pack({ parsers: Array.from({ length: PACK_LIMITS.items + 1 }, (_, i) => `p${i}`) })).join(), /more than 200/);
  assert.match(errorsOf(pack({ parsers: [], detections: {}, sigma: [] })).join(), /at least one parser/);
});

test('Sigma ids must be lower-case UUIDs, unique, with a title (no network lookup)', () => {
  assert.match(errorsOf(pack({ sigma: [{ id: 'not-a-uuid', title: 'x' }] })).join(), /must be a SigmaHQ rule id/);
  assert.match(errorsOf(pack({ sigma: [{ id: SIGMA_ID.toUpperCase(), title: 'x' }] })).join(), /must be a SigmaHQ rule id/);
  assert.match(errorsOf(pack({ sigma: [{ id: SIGMA_ID }] })).join(), /sigma\[0\]\.title is required/);
  assert.match(errorsOf(pack({ sigma: [{ id: SIGMA_ID, title: 'a' }, { id: SIGMA_ID, title: 'b' }] })).join(), /twice/);
  assert.match(errorsOf(pack({ sigma: [SIGMA_ID] })).join(), /mapping \{ id, title \}/);
});

test('setup guide: required, step caps, total cap, code languages', () => {
  assert.match(errorsOf(pack({ setup: [] })).join(), /setup must be a list/);
  assert.match(errorsOf(pack({ setup: [{ title: 't', text: 'x'.repeat(PACK_LIMITS.stepText + 1) }] })).join(), /at most 4000/);
  const many = Array.from({ length: PACK_LIMITS.steps + 1 }, () => ({ title: 't', text: 'x' }));
  assert.match(errorsOf(pack({ setup: many })).join(), /more than 20 steps/);
  const big = Array.from({ length: 6 }, () => ({ title: 't', text: 'x'.repeat(3900) }));
  assert.match(errorsOf(pack({ setup: big })).join(), /at most 20000/);
  assert.match(errorsOf(pack({ setup: [{ title: 't', text: 'x', code: 'y', code_language: 'perl' }] })).join(), /code_language "perl"/);
});

test('references resolve against the catalog index', () => {
  const index = {
    parsers: new Set(['traefik-access']),
    detections: [{ name: 'PROXY-001 Path Traversal', path: 'detections/reverse-proxy/PROXY-001.yaml', tags: ['web'] }],
  };
  assert.deepEqual(errorsOf(pack(), { index }), []);
  const bad = errorsOf(
    pack({ parsers: ['nope'], detections: { categories: ['media'], tags: ['plex'], names: ['GONE-1'] } }),
    { index }
  );
  assert.match(bad.join('\n'), /parser "nope" is not in the catalog/);
  assert.match(bad.join('\n'), /category "media" has no detections/);
  assert.match(bad.join('\n'), /tag "plex" matches no catalog detection/);
  assert.match(bad.join('\n'), /detection "GONE-1" is not in the catalog/);
});

test('guide markdown: raw HTML, scripts, images, entities and unsafe links are refused', () => {
  const hostile = [
    '<script>alert(1)</script>',
    'Click <img src=x onerror=alert(1)>',
    '<a href="https://x">x</a>',
    '<!-- hidden -->',
    '[click](javascript:alert(1))',
    '[click]( JaVaScRiPt:alert(1))',
    '[x](data:text/html;base64,PHNjcmlwdD4=)',
    '[x][1]\n\n[1]: vbscript:msgbox',
    '![tracker](https://evil.example/pixel.png)',
    '[x](&#106;avascript:alert(1))',
    '[x](//evil.example/a)',
  ];
  for (const md of hostile) {
    assert.ok(markdownProblems(md).length > 0, `should refuse: ${md}`);
    assert.equal(validatePack(pack({ setup: [{ title: 't', text: md }] })).ok, false, md);
  }
  assert.ok(markdownProblems('').length === 0);
  assert.equal(validatePack(pack({ description: '<b>bold</b>' })).ok, false);
  assert.equal(validatePack(pack({ setup: [{ title: '<i>t</i>', text: 'x' }] })).ok, false);
});

test('guide markdown: code is literal, and ordinary text and links pass', () => {
  for (const md of [
    'Put `<siembox-host>` in the server field.',
    'Run:\n\n```\n<script>this is shown as text</script>\n```\n',
    'Compare a < b and b > c.',
    'See [the docs](https://example.com/a_(b)), [mail](mailto:a@example.com), [here](/rules) and [top](#top).',
  ]) {
    assert.deepEqual(markdownProblems(md), [], md);
  }
  // An unclosed fence is not code: its content is checked.
  assert.ok(markdownProblems('```\n<script>x</script>').length > 0);
  assert.equal(stripCode('a `b` c ``d`e`` f'), 'a  c  f');
});

test('detectionMatchesPack: categories as directory segments, tags, and exact names', () => {
  const p = { detections: { categories: ['reverse-proxy'], tags: ['media'], names: ['AUTH-001 SSH'] } };
  assert.equal(detectionMatchesPack({ path: 'detections/reverse-proxy/PROXY-003.yaml' }, p), true);
  assert.equal(detectionMatchesPack({ path: 'detections/x-reverse-proxy-y/a.yaml' }, p), false);
  assert.equal(detectionMatchesPack({ path: 'reverse-proxy.yaml' }, p), false);
  assert.equal(detectionMatchesPack({ path: 'detections/other/a.yaml', tags: ['media'] }, p), true);
  assert.equal(detectionMatchesPack({ name: 'AUTH-001 SSH', path: 'detections/authentication/a.yaml' }, p), true);
  assert.equal(detectionMatchesPack({ name: 'AUTH-002', path: 'detections/authentication/a.yaml' }, p), false);
});

// ---------------------------------------------------------------------------
// The CLI (what the catalog's CI runs).
// ---------------------------------------------------------------------------

const SCRIPT = path.join(__dirname, '..', '..', 'scripts', 'validate-packs.ts');

function runCli(args: string[]): { code: number; out: string } {
  try {
    const out = execFileSync(process.execPath, ['--import', 'tsx', SCRIPT, ...args], { encoding: 'utf8', stdio: 'pipe' });
    return { code: 0, out };
  } catch (e: any) {
    return { code: e.status ?? 1, out: `${e.stdout ?? ''}${e.stderr ?? ''}` };
  }
}

function catalogDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'packs-'));
  fs.mkdirSync(path.join(dir, 'packs'));
  fs.mkdirSync(path.join(dir, 'parsers'));
  fs.mkdirSync(path.join(dir, 'detections', 'reverse-proxy'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'parsers', 'traefik.parser.json'), JSON.stringify({ name: 'traefik-access' }));
  fs.writeFileSync(
    path.join(dir, 'detections', 'reverse-proxy', 'PROXY-001.yaml'),
    'name: PROXY-001 Path Traversal\ntags: [web]\n'
  );
  return dir;
}

const yamlPack = (id: string, extra = '') => `schema: siembox.pack/v1
id: ${id}
name: Web ${id}
description: Web logs.
icon: Connection
version: 1
parsers: [traefik-access]
detections:
  categories: [reverse-proxy]
sigma:
  - id: ${SIGMA_ID}
    title: Cross Site Scripting Strings
setup:
  - title: Ship it
    text: Use a File source.
${extra}`;

test('validate-packs: a valid catalog passes, finding parsers/ and detections/ beside packs/', () => {
  const dir = catalogDir();
  fs.writeFileSync(path.join(dir, 'packs', 'web.pack.yaml'), yamlPack('web'));
  const r = runCli([path.join(dir, 'packs')]);
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /1\/1 pack file\(s\) passed/);
  assert.match(r.out, /v1: 1 parser\(s\), detections categories reverse-proxy, 1 Sigma rule\(s\), 1 setup step\(s\)/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('validate-packs: duplicate ids, file-name mismatch, unresolved references and HTML fail', () => {
  const dir = catalogDir();
  fs.mkdirSync(path.join(dir, 'packs', 'more'));
  fs.writeFileSync(path.join(dir, 'packs', 'web.pack.yaml'), yamlPack('web'));
  // Same id in another file (named after it, in a sub-directory).
  fs.writeFileSync(path.join(dir, 'packs', 'more', 'web.pack.yaml'), yamlPack('web'));
  fs.writeFileSync(path.join(dir, 'packs', 'named.pack.yaml'), yamlPack('other'));
  fs.writeFileSync(
    path.join(dir, 'packs', 'broken.pack.yaml'),
    yamlPack('broken').replace('[traefik-access]', '[missing-parser]').replace('Use a File source.', '<script>alert(1)</script>')
  );
  const r = runCli([path.join(dir, 'packs'), '--parsers', path.join(dir, 'parsers'), '--detections', path.join(dir, 'detections')]);
  assert.equal(r.code, 1, r.out);
  assert.match(r.out, /pack id "web" is also used by/);
  assert.match(r.out, /id "other" does not match the file name "named"/);
  assert.match(r.out, /parser "missing-parser" is not in the catalog/);
  assert.match(r.out, /raw HTML is not allowed/);
  assert.match(r.out, /1\/4 pack file\(s\) passed/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('validate-packs: without catalog dirs references are not checked, and says so', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'packs-'));
  fs.writeFileSync(path.join(dir, 'web.pack.yaml'), yamlPack('web').replace('[traefik-access]', '[anything]'));
  const r = runCli([dir]);
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /parser references are not checked/);
  assert.equal(runCli([]).code, 2);
  fs.rmSync(dir, { recursive: true, force: true });
});
