/**
 * Suggested scans from the catalog, with their fallbacks (last read, bundled
 * starter set), every catalog/scans/ mirror file passing the strict
 * validator, and the bundled set's agreement with the mirror.
 * No network: the HTTP getter is a stub. Run with `npm test` (tsx --test).
 */
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'fs';
import * as path from 'path';
import * as yaml from '../../utils/yaml';
import { bundledSuggestions, clearScanCatalogCache, fetchScanCatalog } from './scanCatalog';
import { BUNDLED_SCAN_DOCS } from './bundledScans';
import { SCAN_FILE_SUFFIX, SUGGESTION_KINDS, crossCheckSuggestions, validateSuggestion } from './scanFormat';
import { scheduleFromSuggestion } from './addSuggestion';
import type { HttpGetter } from '../parser/catalogService';

const MIRROR = path.join(__dirname, '../../../../catalog/scans');

const FILES: Record<string, string> = {
  'scans/sweep.scan.yaml': [
    'schema: siembox.scan/v1', 'id: sweep', 'name: Sweep', 'kind: asset', 'category: inventory', 'description: d', 'why: w',
    'intrusive: false', 'load: light', 'schedule: { frequency: daily, time: "02:00" }', 'options: { scanType: ping }',
    'inputs: [{ field: targets }]', '',
  ].join('\n'),
  'scans/broken.scan.yaml': 'schema: siembox.scan/v1\nid: broken\n',
  'scans/wrong-name.scan.yaml': 'schema: siembox.scan/v1\nid: other\n',
};

function getter(files: Record<string, string>, opts: { fail?: boolean } = {}): HttpGetter {
  return async (url) => {
    if (opts.fail) throw new Error('getaddrinfo ENOTFOUND api.github.com');
    if (url.includes('/git/trees/')) {
      return { status: 200, body: JSON.stringify({ tree: Object.keys(files).map((p) => ({ path: p, type: 'blob' })) }) };
    }
    const file = Object.keys(files).find((p) => url.endsWith(p.split('/').map(encodeURIComponent).join('/')));
    return file ? { status: 200, body: files[file] } : { status: 404, body: '' };
  };
}

beforeEach(() => clearScanCatalogCache());

test('a catalog read: valid suggestions in use, invalid ones listed', async () => {
  const c = await fetchScanCatalog({ force: true, get: getter(FILES) });
  assert.equal(c.source, 'catalog');
  assert.deepEqual(c.suggestions.map((s) => s.id), ['sweep']);
  assert.deepEqual(c.invalid.map((i) => i.path).sort(), ['scans/broken.scan.yaml', 'scans/wrong-name.scan.yaml']);
  assert.match(c.invalid.find((i) => i.path.includes('wrong-name'))!.errors.join(), /must match the file name/);
  assert.ok(c.fetched_at);
  // Cached: a second call does not fetch.
  const again = await fetchScanCatalog({ get: getter({}, { fail: true }) });
  assert.equal(again, c);
});

test('unreachable: the last read, else the bundled set', async () => {
  let c = await fetchScanCatalog({ force: true, get: getter(FILES, { fail: true }) });
  assert.equal(c.source, 'bundled');
  assert.match(c.error ?? '', /could not be reached/);
  assert.equal(c.suggestions.length, BUNDLED_SCAN_DOCS.length);

  await fetchScanCatalog({ force: true, get: getter(FILES) });
  c = await fetchScanCatalog({ force: true, get: getter(FILES, { fail: true }) });
  assert.equal(c.source, 'cache');
  assert.deepEqual(c.suggestions.map((s) => s.id), ['sweep']);
});

test('a catalog with no scans/ yet uses the bundled set', async () => {
  const c = await fetchScanCatalog({ force: true, get: getter({ 'parsers/x.parser.json': '{}' }) });
  assert.equal(c.source, 'bundled');
  assert.match(c.error ?? '', /has no scans\//);
});

test('every catalog/scans/ mirror file passes the strict validator, covering every kind', () => {
  const files = fs.readdirSync(MIRROR).filter((f) => f.endsWith(SCAN_FILE_SUFFIX));
  assert.ok(files.length >= 20, `${files.length} suggestions`);
  const all = files.map((f) => {
    const v = validateSuggestion(yaml.load(fs.readFileSync(path.join(MIRROR, f), 'utf8')), { strict: true, expectId: f.slice(0, -SCAN_FILE_SUFFIX.length) });
    assert.equal(v.ok, true, `${f}: ${v.errors.join('; ')}`);
    assert.deepEqual(v.warnings, [], f);
    return v.suggestion!;
  });
  assert.deepEqual(crossCheckSuggestions(all), []);
  for (const kind of SUGGESTION_KINDS) assert.ok(all.some((s) => s.kind === kind), `a ${kind} suggestion`);
  // Each scheduled one becomes a schedule the Scheduled Scans rules accept.
  for (const s of all) if (s.kind !== 'endpoint_policy') assert.equal(scheduleFromSuggestion(s, 'America/Chicago').schedule.timezone, 'America/Chicago');
});

test("the bundled starter set is the catalog mirror's files, verbatim", () => {
  const list = bundledSuggestions();
  assert.equal(list.length, BUNDLED_SCAN_DOCS.length, 'every bundled suggestion validates');
  for (const doc of BUNDLED_SCAN_DOCS) {
    const id = (doc as { id: string }).id;
    const file = path.join(MIRROR, `${id}${SCAN_FILE_SUFFIX}`);
    assert.ok(fs.existsSync(file), `${id} is in catalog/scans`);
    assert.deepEqual(doc, yaml.load(fs.readFileSync(file, 'utf8')), `${id}: regenerate bundledScans.ts from the mirror`);
  }
  for (const kind of SUGGESTION_KINDS) assert.ok(list.some((s) => s.kind === kind), `the starter set has a ${kind} suggestion`);
});
