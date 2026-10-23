/**
 * Reading packs from the catalog (packCatalog.fetchPackCatalog) with a fake
 * GitHub: catalog packs, the bundled fallback for an old catalog without
 * packs/, the last good read when the catalog becomes unreachable, the bundled
 * set when it is unreachable with nothing cached, and invalid packs left out.
 * No network. Run with `npm test` (tsx --test).
 */
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { fetchPackCatalog, clearPackCache, MAX_PACK_FILE_BYTES } from './packCatalog';
import { CONTENT_PACKS } from './contentPacks';
import type { HttpGetter } from '../parser/catalogService';

process.env.SIEMBOX_CATALOG_REPO = 'example/catalog';
process.env.SIEMBOX_CATALOG_REF = 'main';
delete process.env.SIEMBOX_CATALOG_PACKS_PATH;

const packYaml = (id: string, version = 2, extra = '') => `schema: siembox.pack/v1
id: ${id}
name: Pack ${id}
description: A pack.
icon: Box
version: ${version}
parsers: [traefik-access]
sigma:
  - id: 65354b83-a2ea-4ea6-8414-3ab38be0d409
    title: Cross Site Scripting Strings
setup:
  - title: Step
    text: Do it.
${extra}`;

function fakeGitHub(files: Record<string, string>, opts: { down?: boolean } = {}): { get: HttpGetter; calls: string[] } {
  const calls: string[] = [];
  const get: HttpGetter = async (url) => {
    calls.push(url);
    if (opts.down) throw new Error('getaddrinfo ENOTFOUND api.github.com');
    if (url.startsWith('https://api.github.com/repos/example/catalog/git/trees/main')) {
      const tree = [
        { path: 'parsers/traefik.parser.json', type: 'blob' },
        ...Object.keys(files).map((p) => ({ path: p, type: 'blob' })),
      ];
      return { status: 200, body: JSON.stringify({ tree }) };
    }
    const m = url.match(/^https:\/\/raw\.githubusercontent\.com\/example\/catalog\/main\/(.+)$/);
    const p = m ? decodeURIComponent(m[1]) : '';
    if (p in files) return { status: 200, body: files[p] };
    return { status: 404, body: 'not found' };
  };
  return { get, calls };
}

beforeEach(() => clearPackCache());

test('reads packs/<id>.pack.yaml from the catalog', async () => {
  const gh = fakeGitHub({ 'packs/web.pack.yaml': packYaml('web'), 'packs/auth.pack.yaml': packYaml('auth', 3) });
  const c = await fetchPackCatalog(true, gh.get);
  assert.equal(c.source, 'catalog');
  assert.equal(c.error, null);
  assert.deepEqual(c.packs.map((p) => [p.id, p.version]), [['auth', 3], ['web', 2]]);
  assert.equal(c.packs[0].sigma[0].id, '65354b83-a2ea-4ea6-8414-3ab38be0d409');
  assert.ok(c.fetched_at);
  // Cached: a second read does not call GitHub.
  const n = gh.calls.length;
  await fetchPackCatalog(false, gh.get);
  assert.equal(gh.calls.length, n);
});

test('an old catalog without packs/ falls back to the bundled packs', async () => {
  const gh = fakeGitHub({});
  const c = await fetchPackCatalog(true, gh.get);
  assert.equal(c.source, 'bundled');
  assert.equal(c.packs, CONTENT_PACKS);
  assert.match(c.error!, /has no packs\/ yet/);
});

test('unreachable with nothing cached: the bundled packs, and why', async () => {
  const c = await fetchPackCatalog(true, fakeGitHub({}, { down: true }).get);
  assert.equal(c.source, 'bundled');
  assert.equal(c.packs.length, 8);
  assert.match(c.error!, /could not be reached \(getaddrinfo ENOTFOUND/);
});

test('unreachable after a good read: the last good read is kept', async () => {
  await fetchPackCatalog(true, fakeGitHub({ 'packs/web.pack.yaml': packYaml('web', 5) }).get);
  const c = await fetchPackCatalog(true, fakeGitHub({}, { down: true }).get);
  assert.equal(c.source, 'cache');
  assert.deepEqual(c.packs.map((p) => [p.id, p.version]), [['web', 5]]);
  assert.match(c.error!, /could not be reached/);
});

test('an invalid or oversized pack is left out and listed; all invalid falls back', async () => {
  const gh = fakeGitHub({
    'packs/web.pack.yaml': packYaml('web'),
    'packs/bad.pack.yaml': packYaml('bad').replace('text: Do it.', 'text: <script>alert(1)</script>'),
    'packs/wrong-name.pack.yaml': packYaml('other'),
    'packs/huge.pack.yaml': packYaml('huge', 2, `# ${'x'.repeat(MAX_PACK_FILE_BYTES)}`),
    'packs/notes.md': 'not a pack',
  });
  const c = await fetchPackCatalog(true, gh.get);
  assert.equal(c.source, 'catalog');
  assert.deepEqual(c.packs.map((p) => p.id), ['web']);
  assert.deepEqual(c.invalid.map((i) => i.path).sort(), ['packs/bad.pack.yaml', 'packs/huge.pack.yaml', 'packs/wrong-name.pack.yaml']);
  assert.match(c.invalid.find((i) => i.path === 'packs/bad.pack.yaml')!.errors.join(), /raw HTML/);
  assert.match(c.error!, /3 catalog pack file\(s\) failed validation/);

  clearPackCache();
  const none = await fetchPackCatalog(true, fakeGitHub({ 'packs/bad.pack.yaml': 'id: [' }).get);
  assert.equal(none.source, 'bundled');
  assert.match(none.error!, /none of the catalog's 1 pack file\(s\) is valid/);
});

test('a newer catalog field is a warning, not a hidden pack', async () => {
  const c = await fetchPackCatalog(true, fakeGitHub({ 'packs/web.pack.yaml': packYaml('web', 2, 'maintainers: [someone]\n') }).get);
  assert.deepEqual(c.packs.map((p) => p.id), ['web']);
});

test('concurrent reads share one fetch', async () => {
  const gh = fakeGitHub({ 'packs/web.pack.yaml': packYaml('web') });
  await Promise.all([fetchPackCatalog(true, gh.get), fetchPackCatalog(true, gh.get), fetchPackCatalog(false, gh.get)]);
  assert.equal(gh.calls.filter((u) => u.includes('/git/trees/')).length, 1);
});
