/**
 * Application signatures from the catalog, with their fallbacks (last read,
 * stored set, bundled starter set), the bundled set's agreement with the
 * catalog mirror, and the regex safety gate in front of the index.
 * No network: the HTTP getter is a stub. Run with `npm test` (tsx --test).
 */
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'fs';
import * as path from 'path';
import * as yaml from '../../utils/yaml';
import { bundledSignatures, clearAppCatalogCache, fetchAppCatalog, gateSignatureRegexes } from './appCatalog';
import { BUNDLED_APPLICATION_DOCS } from './bundledApplications';
import { crossCheckApplications, validateApplication } from './appFormat';
import { AppIndex, runAppTests } from './matchers';
import type { HttpGetter } from '../parser/catalogService';

const MIRROR = path.join(__dirname, '../../../../catalog/applications');

const FILES: Record<string, string> = {
  'applications/acme.app.yaml': [
    'schema: siembox.app/v1', 'id: acme', 'name: Acme', 'vendor: Acme', 'category: web-server',
    'match:', '  syslog_program: [acmed]', 'tests:', '  - source: syslog_program', '    input: acmed', '',
  ].join('\n'),
  'applications/broken.app.yaml': 'schema: siembox.app/v1\nid: broken\n',
  'applications/wrong-name.app.yaml': [
    'schema: siembox.app/v1', 'id: other', 'name: Other', 'vendor: X', 'category: dns', 'match:', '  dns: [other.example]', '',
  ].join('\n'),
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

beforeEach(() => clearAppCatalogCache());

test('a catalog read: valid signatures in use, invalid ones listed', async () => {
  const c = await fetchAppCatalog({ force: true, get: getter(FILES) });
  assert.equal(c.source, 'catalog');
  assert.deepEqual(c.apps.map((a) => a.id), ['acme']);
  assert.deepEqual(c.invalid.map((i) => i.path).sort(), ['applications/broken.app.yaml', 'applications/wrong-name.app.yaml']);
  assert.match(c.invalid.find((i) => i.path.includes('wrong-name'))!.errors.join(), /must match the file name/);
  assert.ok(c.fetched_at);
});

test('unreachable: the last read, else the stored set, else the bundled set', async () => {
  // Nothing read yet, nothing stored: bundled.
  let c = await fetchAppCatalog({ force: true, get: getter(FILES, { fail: true }), loadStored: async () => null });
  assert.equal(c.source, 'bundled');
  assert.match(c.error ?? '', /could not be reached/);
  assert.equal(c.apps.length, BUNDLED_APPLICATION_DOCS.length);

  // A stored set from an earlier catalog read wins over bundled.
  const stored = [{ schema: 'siembox.app/v1', id: 'stored-app', name: 'Stored', vendor: 'S', category: 'dns', match: { dns: ['stored.example'] } }];
  c = await fetchAppCatalog({ force: true, get: getter(FILES, { fail: true }), loadStored: async () => ({ docs: stored, fetched_at: '2026-10-01T00:00:00.000Z' }) });
  assert.equal(c.source, 'stored');
  assert.deepEqual(c.apps.map((a) => a.id), ['stored-app']);

  // After a good read in this process, that read wins.
  await fetchAppCatalog({ force: true, get: getter(FILES) });
  c = await fetchAppCatalog({ force: true, get: getter(FILES, { fail: true }), loadStored: async () => ({ docs: stored, fetched_at: null }) });
  assert.equal(c.source, 'cache');
  assert.deepEqual(c.apps.map((a) => a.id), ['acme']);
});

test('a catalog with no applications/ yet uses the bundled set', async () => {
  const c = await fetchAppCatalog({ force: true, get: getter({ 'parsers/x.parser.json': '{}' }) });
  assert.equal(c.source, 'bundled');
  assert.match(c.error ?? '', /has no applications\//);
});

test('the bundled starter set is the catalog mirror\'s files, verbatim, and passes its own tests', () => {
  const apps = bundledSignatures();
  assert.equal(apps.length, BUNDLED_APPLICATION_DOCS.length, 'every bundled signature validates');
  for (const doc of BUNDLED_APPLICATION_DOCS) {
    const id = (doc as { id: string }).id;
    const file = path.join(MIRROR, `${id}.app.yaml`);
    assert.ok(fs.existsSync(file), `${id} is in catalog/applications`);
    assert.deepEqual(doc, yaml.load(fs.readFileSync(file, 'utf8')), `${id}: regenerate bundledApplications.ts from the mirror`);
    assert.equal(validateApplication(doc, { strict: true, expectId: id }).ok, true);
  }
  assert.deepEqual(crossCheckApplications(apps), []);
  const index = new AppIndex(apps);
  for (const a of apps) assert.deepEqual(runAppTests(a, index), [], a.id);
});

test('the regex gate leaves refused regexes out of the index, and all of them when the checker is unavailable', async () => {
  const doc = (ua: string[]) =>
    validateApplication({ schema: 'siembox.app/v1', id: 'acme', name: 'Acme', vendor: 'A', category: 'browser', match: { user_agent: ua } }).app!;
  const app = doc(['^Acme/(\\d+)', '^Evil/(\\d+)']);
  const gate = await gateSignatureRegexes([app], async (refs) => ({
    vulnerable: refs.filter((r) => r.source.startsWith('^Evil')).map((r) => ({ location: r.location, source: r.source })),
    undecided: [],
  }));
  assert.deepEqual([...gate.skip], ['^Evil/(\\d+)']);
  assert.deepEqual(gate.refused, [{ appId: 'acme', location: 'match.user_agent[1]', source: '^Evil/(\\d+)', reason: 'ReDoS-vulnerable' }]);
  const index = new AppIndex([app], { skipRegex: gate.skip });
  assert.equal(index.matchUserAgent('Evil/1').length, 0);
  assert.equal(index.matchUserAgent('Acme/1').length, 1);

  const down = await gateSignatureRegexes([app], async () => {
    throw new Error('pool busy');
  });
  assert.equal(down.skip.size, 2);
  assert.equal(new AppIndex([app], { skipRegex: down.skip }).matchUserAgent('Acme/1').length, 0, 'nothing unchecked runs');
});
