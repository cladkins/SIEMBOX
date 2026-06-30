/**
 * Unit tests for Content Pack manifests + the detection matcher. Run with
 * `npm test` (tsx --test). No database/network required.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CONTENT_PACKS, getContentPack, detectionMatchesPack } from './contentPacks';

test('every pack has the required fields and at least one parser', () => {
  const ids = new Set<string>();
  for (const p of CONTENT_PACKS) {
    assert.ok(p.id && !ids.has(p.id), `pack id missing or duplicated: ${p.id}`);
    ids.add(p.id);
    assert.ok(p.name && p.description && p.icon, `pack ${p.id} missing display fields`);
    assert.ok(Array.isArray(p.parsers) && p.parsers.length > 0, `pack ${p.id} has no parsers`);
    assert.ok(Array.isArray(p.setup) && p.setup.length > 0, `pack ${p.id} has no setup hints`);
  }
});

test('pack parser names are catalog-style slugs (not human-readable display names)', () => {
  // The published catalog resolves parsers by a slug `name` (e.g. ssh-authentication),
  // NOT a display name ("SSH Authentication"). Guard against referencing names that
  // can't resolve at install time.
  const slug = /^[a-z0-9][a-z0-9-]*$/;
  for (const p of CONTENT_PACKS) {
    for (const name of p.parsers) {
      assert.ok(slug.test(name), `pack "${p.id}" references non-slug parser name "${name}"`);
    }
  }
});

test('getContentPack resolves by id', () => {
  assert.equal(getContentPack('auth-identity')?.name, 'Auth & Identity');
  assert.equal(getContentPack('nope'), undefined);
});

test('detectionMatchesPack matches by category path segment', () => {
  const pack = getContentPack('reverse-proxy')!;
  assert.equal(detectionMatchesPack({ path: 'detections/reverse-proxy/PROXY-003.yaml' }, pack), true);
  assert.equal(detectionMatchesPack({ path: 'reverse-proxy/PROXY-003.yaml' }, pack), true);
  // A different category must not match.
  assert.equal(detectionMatchesPack({ path: 'detections/authentication/AUTH-002.yaml' }, pack), false);
  // Substring that isn't a path segment must not match.
  assert.equal(detectionMatchesPack({ path: 'detections/x-reverse-proxy-y/a.yaml' }, pack), false);
});

test('detectionMatchesPack matches by tag when configured', () => {
  const pack = { id: 't', name: 't', description: '', icon: '', parsers: ['x'], detectionTags: ['media'], setup: ['s'] };
  assert.equal(detectionMatchesPack({ path: 'detections/other/a.yaml', tags: ['media', 'plex'] }, pack), true);
  assert.equal(detectionMatchesPack({ path: 'detections/other/a.yaml', tags: ['network'] }, pack), false);
});

test('a pack with no detection selectors matches no detections', () => {
  const media = getContentPack('media')!;
  assert.deepEqual(media.detectionCategories, []);
  assert.equal(detectionMatchesPack({ path: 'detections/anything/a.yaml', tags: ['media'] }, media), false);
});
