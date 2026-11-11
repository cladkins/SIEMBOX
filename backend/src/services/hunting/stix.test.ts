import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  huntBundle,
  indicatorStixId,
  parseStixInput,
  patternComparisons,
  SIEMBOX_IDENTITY_ID,
  stixPattern,
  StixHunt,
  stableUuid,
} from './stix';

const UUID = '6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b';

function hunt(): StixHunt {
  const created = new Date('2026-11-01T10:00:00.000Z');
  return {
    id: 7,
    stix_uuid: UUID,
    title: 'Campaign X',
    summary: 'A summary.',
    origin: 'url',
    source_url: 'https://news.example.org/x',
    status: 'completed',
    lookback_days: 14,
    match_count: 3,
    last_run_at: new Date('2026-11-02T10:00:00.000Z'),
    created_at: created,
    updated_at: new Date('2026-11-02T10:00:00.000Z'),
    indicators: [
      { stix_id: indicatorStixId(UUID, 'ipv4', '45.142.212.100'), ioc_type: 'ipv4', value: '45.142.212.100', context: 'C2', enabled: true, match_count: 3, first_seen: created, last_seen: created, created_at: created },
      { stix_id: indicatorStixId(UUID, 'url', "https://bad-host.net/a'b"), ioc_type: 'url', value: "https://bad-host.net/a'b", context: null, enabled: true, match_count: 0, first_seen: null, last_seen: null, created_at: created },
      { stix_id: indicatorStixId(UUID, 'cve', 'CVE-2024-3400'), ioc_type: 'cve', value: 'CVE-2024-3400', context: null, enabled: true, match_count: 0, first_seen: null, last_seen: null, created_at: created },
      { stix_id: indicatorStixId(UUID, 'md5', '9e107d9d372bb6826bd81d3542a419d6'), ioc_type: 'md5', value: '9e107d9d372bb6826bd81d3542a419d6', context: null, enabled: false, match_count: 0, first_seen: null, last_seen: null, created_at: created },
    ],
    hypotheses: [
      { stix_id: 'note--11111111-2222-4333-8444-555555555555', title: 'Rundll32 loads a DLL', description: 'Because.', attack_techniques: ['T1218.011'], search_terms: ['rundll32.exe'], enabled: true, match_count: 1, first_seen: created, last_seen: created, created_at: created },
    ],
  };
}

test('stableUuid is deterministic and in UUIDv4 form', () => {
  const a = stableUuid('siembox');
  assert.equal(a, stableUuid('siembox'));
  assert.match(a, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.notEqual(a, stableUuid('siembox2'));
});

test('stixPattern quotes values', () => {
  assert.equal(stixPattern('ipv4', '1.2.3.4'), "[ipv4-addr:value = '1.2.3.4']");
  assert.equal(stixPattern('domain', "o'neil.com"), "[domain-name:value = 'o\\'neil.com']");
  assert.equal(stixPattern('sha256', 'ab'), "[file:hashes.'SHA-256' = 'ab']");
  assert.equal(stixPattern('cve', 'CVE-1'), null);
});

test('huntBundle builds a STIX 2.1 bundle with report, indicators, notes and sightings', () => {
  const bundle = huntBundle(hunt(), (t) => `Name of ${t}`);
  assert.equal(bundle.type, 'bundle');
  const byType = (t: string) => bundle.objects.filter((o) => o.type === t);
  assert.equal(byType('identity')[0].id, SIEMBOX_IDENTITY_ID);
  const [report] = byType('report');
  assert.equal(report.id, `report--${UUID}`);
  assert.equal(report.name, 'Campaign X');
  assert.equal(byType('indicator').length, 2, 'the disabled md5 is not exported');
  assert.equal(byType('vulnerability').length, 1);
  assert.equal(byType('attack-pattern')[0].name, 'Name of T1218.011');
  const [note] = byType('note');
  assert.deepEqual(note.x_siembox_search_terms, ['rundll32.exe']);
  const sightings = byType('sighting');
  assert.equal(sightings.length, 2, 'the IP and the hypothesis were found');
  for (const o of bundle.objects) {
    assert.equal(o.spec_version, '2.1');
    if (o.type !== 'identity') assert.equal(o.created_by_ref, SIEMBOX_IDENTITY_ID);
  }
  const refs = report.object_refs as string[];
  for (const o of bundle.objects) if (o.type !== 'identity' && o.type !== 'report') assert.ok(refs.includes(o.id), o.id);
  // Stable IDs across exports.
  const again = huntBundle(hunt());
  assert.deepEqual(again.objects.map((o) => o.id), bundle.objects.map((o) => o.id));
});

test('patternComparisons reads simple equality patterns', () => {
  assert.deepEqual(
    patternComparisons("[ipv4-addr:value = '1.2.3.4'] OR [domain-name:value = 'o\\'neil.com']"),
    [['ipv4', '1.2.3.4'], ['domain', "o'neil.com"]]
  );
  assert.deepEqual(patternComparisons("[file:hashes.'SHA-256' = 'AB'] AND [file:hashes.MD5 = 'cd']"), [
    ['sha256', 'AB'],
    ['md5', 'cd'],
  ]);
  assert.deepEqual(patternComparisons("[process:name = 'x']"), []);
});

test('a SIEMBox bundle round-trips through parseStixInput', () => {
  const parsed = parseStixInput(huntBundle(hunt()));
  assert.equal(parsed.title, 'Campaign X');
  assert.equal(parsed.source_url, 'https://news.example.org/x');
  const values = parsed.indicators.map((i) => `${i.type}:${i.value}`).sort();
  assert.deepEqual(values, ['cve:CVE-2024-3400', 'ipv4:45.142.212.100', "url:https://bad-host.net/a'b"]);
  const ip = parsed.indicators.find((i) => i.type === 'ipv4')!;
  assert.equal(ip.stix_id, indicatorStixId(UUID, 'ipv4', '45.142.212.100'), 'the original id is kept');
  assert.equal(parsed.hypotheses.length, 1);
  assert.deepEqual(parsed.hypotheses[0].search_terms, ['rundll32.exe']);
  assert.deepEqual(parsed.hypotheses[0].attack_techniques, ['T1218.011']);
  assert.equal(parsed.hypotheses[0].description, 'Because.');
});

test('parseStixInput reads third-party bundles: observables, odd patterns, attack-patterns', () => {
  const parsed = parseStixInput({
    type: 'bundle',
    id: 'bundle--1',
    objects: [
      { type: 'grouping', id: 'grouping--1', name: 'Vendor pulse' },
      { type: 'indicator', id: 'indicator--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', pattern: "[url:value = 'https://bad.example-host.net/x']", pattern_type: 'stix' },
      { type: 'indicator', id: 'indicator--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', pattern: 'alert tcp any any', pattern_type: 'snort' },
      { type: 'domain-name', id: 'domain-name--1', value: 'bad-domain.top' },
      { type: 'file', id: 'file--1', hashes: { 'SHA-1': 'a'.repeat(39) + 'b' } },
      { type: 'attack-pattern', id: 'attack-pattern--1', external_references: [{ source_name: 'mitre-attack', external_id: 'T1190' }] },
    ],
  });
  assert.equal(parsed.title, 'Vendor pulse');
  assert.equal(parsed.stats.skipped_patterns, 1);
  assert.ok(parsed.indicators.some((i) => i.type === 'url'));
  assert.ok(parsed.indicators.some((i) => i.type === 'domain' && i.value === 'bad-domain.top'));
  assert.ok(parsed.indicators.some((i) => i.type === 'sha1'));
  assert.deepEqual(parsed.hypotheses[0].attack_techniques, ['T1190']);
});

test('parseStixInput refuses what is not a bundle', () => {
  assert.throws(() => parseStixInput('nope'), /STIX bundle/);
  assert.throws(() => parseStixInput({ objects: new Array(10_001).fill({}) }), /limit/);
});
