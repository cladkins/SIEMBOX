/**
 * SigmaHQ archive -> library entries: unpacking caps, YAML loading, and the
 * conversion bookkeeping (parts, exclude, lossy rules, attribution).
 * DB-free. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildSigmaLibrary, isRuleFile, libraryRuleFromYaml, parseVersionTxt, sigmaAttack, sigmaRuleUrl, SIGMA_ZIP_LIMITS } from './sigmaLibrary';
import { ZipError } from '../../utils/zipReader';
import { makeZip } from '../../utils/testZip.test';
import { IDS, fixtureArchive, fixtureRules } from './sigmaFixture.test';

const RELEASE = { tag: 'r2099-01-01', asset: 'sigma_core+.zip' };
const lib = () => buildSigmaLibrary(fixtureArchive('fx'), RELEASE);
const byId = (id: string) => lib().rules.find((r) => r.sigma_id === id)!;

test('release info comes from the redirect tag and version.txt', () => {
  const { info } = lib();
  assert.deepEqual(info, { tag: 'r2099-01-01', asset: 'sigma_core+.zip', release_date: '2026-07-09', commit_hash: '552f3fee' });
  assert.deepEqual(parseVersionTxt('nonsense'), { release_date: null, commit_hash: null });
});

test('only rules*/ YAML files are rule files', () => {
  assert.equal(isRuleFile('rules/web/a.yml'), true);
  assert.equal(isRuleFile('rules-emerging-threats/2024/a.yml'), true);
  assert.equal(isRuleFile('LICENSE.Detection.Rules.md'), false);
  assert.equal(isRuleFile('tests/a.yml'), false);
  assert.equal(isRuleFile('rules/web/a.json'), false);
});

test('metadata, ATT&CK and the upstream link are kept', () => {
  const r = byId(IDS.ua);
  assert.equal(r.title, 'fx Hack Tool User Agent');
  assert.equal(r.level, 'high');
  assert.equal(r.status, 'test');
  assert.equal(r.category, 'proxy');
  assert.equal(r.author, 'Jane Doe, John Roe');
  assert.equal(r.rule_date, '2020-01-01'); // YAML dates come back as strings
  assert.equal(r.modified, '2024-05-06');
  assert.deepEqual(r.refs, ['https://example.invalid/ua']);
  assert.match(r.content_hash, /^[0-9a-f]{64}$/);
  assert.deepEqual(sigmaAttack(r), { techniques: ['T1190'], tactics: ['initial-access'] });
  assert.equal(
    sigmaRuleUrl('r2099-01-01', r.path),
    'https://github.com/SigmaHQ/sigma/blob/r2099-01-01/rules/web/proxy_generic/proxy_ua_fixture.yml'
  );
});

test('a converted part is disabled, tagged sigmahq and carries the DRL attribution', () => {
  const [part] = byId(IDS.ua).parts;
  assert.equal(part.enabled, false);
  assert.ok(part.tags!.includes('sigma') && part.tags!.includes('sigmahq') && !part.tags!.includes('imported'));
  assert.ok(part.tags!.includes('attack.t1190'));
  assert.match(part.description!, /SigmaHQ rule 0a1b2c3d-0000-4000-8000-000000000001 by Jane Doe, John Roe, release r2099-01-01/);
  assert.match(part.description!, /blob\/r2099-01-01\/rules\/web\/proxy_generic\/proxy_ua_fixture\.yml/);
  assert.match(part.description!, /Detection Rule License \(DRL\) 1\.1/);
  assert.deepEqual(part.conditions, [{ field: 'user_agent', operator: 'contains', value: 'fx-sqlmap' }]);
});

test('OR splits into parts; NOT becomes exclude', () => {
  const split = byId(IDS.split);
  assert.equal(split.convertible, true);
  assert.equal(split.parts.length, 2);
  assert.deepEqual(split.parts.map((p) => p.name), ['fx Split Rule (part 1 of 2)', 'fx Split Rule (part 2 of 2)']);
  assert.deepEqual(split.fields.sort(), ['fx_alpha', 'fx_beta']);
  const not = byId(IDS.not);
  assert.deepEqual(not.parts[0].exclude, [[{ field: 'fx_gamma', operator: 'equals', value: 'benign' }]]);
  // Variant 2 has three alternatives.
  const v2 = buildSigmaLibrary(fixtureArchive('fx', 2), RELEASE).rules.find((r) => r.sigma_id === IDS.split)!;
  assert.equal(v2.parts.length, 3);
  assert.notEqual(v2.content_hash, split.content_hash);
});

test('a rule the converter would weaken (a skipped modifier) is not convertible', () => {
  const r = byId(IDS.lossy);
  assert.equal(r.convertible, false);
  assert.deepEqual(r.parts, []);
  assert.match(r.errors.join(), /not converted faithfully: Skipped field "DestinationIp\|cidr"/);
});

test('deprecated, id-less, unreadable and code-tagged files are left out', () => {
  const ids = lib().rules.map((r) => r.sigma_id);
  assert.ok(!ids.includes(IDS.deprecated));
  assert.ok(!ids.includes('0a1b2c3d-0000-4000-8000-0000000000ff')); // !!js/function: refused by the loader
  assert.deepEqual(libraryRuleFromYaml('rules/x.yml', fixtureRules('fx')['rules/misc/code.yml'], 't'), { skip: 'unreadable' });
  assert.deepEqual(libraryRuleFromYaml('rules/x.yml', 'title: a\nid: not-a-uuid\n', 't'), { skip: 'no_id' });
  assert.deepEqual(libraryRuleFromYaml('rules/x.yml', 'a: 1\n---\nb: 2\n', 't'), { skip: 'unreadable' });
});

test('a duplicate id keeps the first file', () => {
  const rules = fixtureRules('fx');
  const archive = makeZip([
    { name: 'rules/a.yml', data: rules['rules/web/proxy_generic/proxy_ua_fixture.yml'] },
    { name: 'rules/b.yml', data: rules['rules/web/proxy_generic/proxy_ua_fixture.yml'].replace('Hack Tool', 'Other') },
  ]);
  const built = buildSigmaLibrary(archive, RELEASE);
  assert.equal(built.rules.length, 1);
  assert.equal(built.stats.skipped.duplicate_id, 1);
  assert.equal(built.rules[0].path, 'rules/a.yml');
});

test('archive caps apply (a rule file over the per-file cap refuses the archive)', () => {
  const big = makeZip([{ name: 'rules/big.yml', data: `title: x\n#${'a'.repeat(SIGMA_ZIP_LIMITS.maxEntryBytes)}\n` }]);
  assert.throws(() => buildSigmaLibrary(big, RELEASE), ZipError);
  assert.throws(() => buildSigmaLibrary(makeZip([{ name: 'README.md', data: 'x' }]), RELEASE), /no readable rules/);
});
