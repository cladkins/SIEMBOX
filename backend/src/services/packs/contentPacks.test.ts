/**
 * The bundled fallback packs and the catalog/packs mirror: both pass the pack
 * validator, and the mirror's references resolve against this repo's mirror
 * of the catalog (catalog/parsers, rules/). No database/network. Run with
 * `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'fs';
import * as path from 'path';
import * as yaml from '../../utils/yaml';
import { CONTENT_PACKS, getBundledPack, detectionMatchesPack } from './contentPacks';
import { validatePack } from './packFormat';

const ROOT = path.join(__dirname, '..', '..', '..', '..');
const MIRROR = path.join(ROOT, 'catalog', 'packs');

test('every bundled pack passes the strict pack validator', () => {
  const ids = new Set<string>();
  for (const p of CONTENT_PACKS) {
    const v = validatePack({ schema: 'siembox.pack/v1', ...p }, { strict: true });
    assert.deepEqual(v.errors, [], `bundled pack ${p.id}`);
    assert.ok(!ids.has(p.id), `duplicate bundled pack ${p.id}`);
    ids.add(p.id);
    assert.ok(p.parsers.length > 0, `pack ${p.id} has no parsers`);
    assert.equal(p.version, 1, 'bundled packs stay at version 1 (the catalog versions start at 2 when they change)');
  }
  assert.equal(CONTENT_PACKS.length, 8);
});

test('getBundledPack resolves by id', () => {
  assert.equal(getBundledPack('auth-identity')?.name, 'Auth & Identity');
  assert.equal(getBundledPack('nope'), undefined);
});

test('the bundled packs keep the items they had before packs moved to the catalog', () => {
  // The fallback must not regress an install that cannot see catalog packs.
  assert.deepEqual(getBundledPack('reverse-proxy')!.detections.categories, ['reverse-proxy']);
  assert.deepEqual(getBundledPack('media')!.detections, { categories: [], tags: [], names: [] });
  assert.ok(getBundledPack('infrastructure')!.parsers.includes('fail2ban'));
  const media = getBundledPack('media')!;
  assert.equal(detectionMatchesPack({ path: 'detections/anything/a.yaml', tags: ['media'] }, media), false);
});

test('the catalog/packs mirror passes strict validation with resolving references', { skip: !fs.existsSync(MIRROR) }, () => {
  const parsers = new Set(
    fs
      .readdirSync(path.join(ROOT, 'catalog', 'parsers'))
      .filter((f) => f.endsWith('.parser.json'))
      .map((f) => JSON.parse(fs.readFileSync(path.join(ROOT, 'catalog', 'parsers', f), 'utf8')).name)
  );
  const detections: Array<{ name: string; path: string; tags: string[] }> = [];
  const rulesDir = path.join(ROOT, 'rules');
  for (const cat of fs.readdirSync(rulesDir, { withFileTypes: true }).filter((d) => d.isDirectory())) {
    for (const f of fs.readdirSync(path.join(rulesDir, cat.name)).filter((x) => x.endsWith('.yaml'))) {
      const r = yaml.load(fs.readFileSync(path.join(rulesDir, cat.name, f), 'utf8')) as any;
      if (r?.name) detections.push({ name: r.name, path: `detections/${cat.name}/${f}`, tags: r.tags ?? [] });
    }
  }
  const files = fs.readdirSync(MIRROR).filter((f) => f.endsWith('.pack.yaml'));
  assert.ok(files.length >= 8);
  for (const f of files) {
    const v = validatePack(yaml.load(fs.readFileSync(path.join(MIRROR, f), 'utf8')), {
      strict: true,
      index: { parsers, detections },
      expectId: f.replace(/\.pack\.yaml$/, ''),
    });
    assert.deepEqual(v.errors, [], f);
    // The catalog's pack carries every item its bundled version had.
    const bundled = getBundledPack(v.pack!.id);
    if (bundled) {
      for (const p of bundled.parsers) assert.ok(v.pack!.parsers.includes(p), `${f} dropped parser ${p}`);
      for (const c of bundled.detections.categories) assert.ok(v.pack!.detections.categories.includes(c), `${f} dropped ${c}`);
      assert.ok(v.pack!.version >= bundled.version);
      if (v.pack!.sigma.length > 0) assert.ok(v.pack!.version > bundled.version, `${f} adds Sigma rules: bump its version`);
    }
  }
});
