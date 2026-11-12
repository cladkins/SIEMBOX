import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  attributeValues,
  isMispEvent,
  isMispManifest,
  looksLikeMispFeedIndex,
  mispFeedUrls,
  parseMispEvent,
  parseMispManifest,
} from './misp';
import { documentKind } from './fetchSource';
import { parseStructured } from './huntService';

const A = (type: string, value: string, extra: Record<string, unknown> = {}) => ({
  uuid: extra.uuid ?? '5f0c1a2b-3c4d-4e5f-8a6b-7c8d9e0f1a2b'.replace(/2b$/, String(Math.floor(Math.random() * 90) + 10)),
  type,
  value,
  to_ids: true,
  category: 'Network activity',
  ...extra,
});

const EVENT = {
  Event: {
    uuid: '0b988513-9535-42f0-9ebc-5d6aec2e1c79',
    info: 'OSINT - Egregor: The New Ransomware Variant To Watch',
    date: '2026-11-10',
    Orgc: { name: 'CIRCL' },
    Tag: [
      { name: 'tlp:white' },
      { name: 'misp-galaxy:mitre-attack-pattern="Data Encrypted for Impact - T1486"' },
    ],
    Galaxy: [
      {
        type: 'mitre-attack-pattern',
        GalaxyCluster: [{ value: 'Phishing - T1566', meta: { external_id: ['T1566'] } }],
      },
    ],
    Attribute: [
      A('ip-dst', '45.142.212.100', { uuid: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', comment: 'C2' }),
      A('ip-dst|port', '185.220.101.5|443'),
      A('domain|ip', 'evil-cdn.com|91.92.93.94'),
      A('url', 'https://evil-cdn.com/payload.php'),
      A('filename|sha256', `egregor.dll|${'ab'.repeat(32)}`),
      A('vulnerability', 'CVE-2020-1472'),
      A('ip-dst', '10.0.0.5'), // private: dropped
      A('domain', 'not-for-detection.net', { to_ids: false }),
      A('domain', 'deleted-one.org', { deleted: true }),
      A('link', 'https://www.example-news.org/egregor-report', { to_ids: false }),
      A('mutex', 'Global\\\\egregor'),
    ],
    Object: [
      {
        name: 'file',
        Attribute: [A('md5', 'c'.repeat(31) + 'd'), A('filename', 'x.exe')],
      },
    ],
  },
};

test('recognises MISP events and manifests', () => {
  assert.equal(isMispEvent(EVENT), true);
  assert.equal(isMispEvent({ response: [EVENT] }), true);
  assert.equal(isMispEvent({ type: 'bundle', objects: [] }), false);
  const manifest = {
    '0b988513-9535-42f0-9ebc-5d6aec2e1c79': { info: 'Older', date: '2026-01-01', timestamp: '1700000000', Orgc: { name: 'CIRCL' } },
    '0badeefd-70f0-46e6-87f4-a6f1454661f9': { info: 'Newer', date: '2026-08-10', timestamp: '1780000000' },
  };
  assert.equal(isMispManifest(manifest), true);
  assert.equal(isMispManifest({ foo: { info: 'x' } }), false);
  assert.deepEqual(parseMispManifest(manifest).map((e) => e.info), ['Newer', 'Older']);
  assert.equal(documentKind({ contentType: 'application/json', body: JSON.stringify(EVENT) }), 'misp-event');
  assert.equal(documentKind({ contentType: 'application/json', body: JSON.stringify(manifest) }), 'misp-manifest');
});

test('mispFeedUrls finds the feed from the directory, the manifest or an event file', () => {
  const want = { base: 'https://www.circl.lu/doc/misp/feed-osint/', manifest: 'https://www.circl.lu/doc/misp/feed-osint/manifest.json' };
  assert.deepEqual(mispFeedUrls('https://www.circl.lu/doc/misp/feed-osint/'), want);
  assert.deepEqual(mispFeedUrls('https://www.circl.lu/doc/misp/feed-osint'), want);
  assert.deepEqual(mispFeedUrls('https://www.circl.lu/doc/misp/feed-osint/manifest.json'), want);
  assert.deepEqual(mispFeedUrls('https://www.circl.lu/doc/misp/feed-osint/0b988513-9535-42f0-9ebc-5d6aec2e1c79.json'), want);
  assert.equal(looksLikeMispFeedIndex('<a href="manifest.json">manifest.json</a>'), true);
  assert.equal(looksLikeMispFeedIndex('<a href="other.json">x</a>'), false);
});

test('attributeValues splits composite MISP types', () => {
  assert.deepEqual(attributeValues('ip-dst|port', '1.2.3.4|80'), [['ipv4', '1.2.3.4']]);
  assert.deepEqual(attributeValues('domain|ip', 'a.com|2001:db8::1'), [['domain', 'a.com'], ['ipv6', '2001:db8::1']]);
  assert.deepEqual(attributeValues('filename|sha1', 'x.exe|abc'), [['sha1', 'abc']]);
  assert.deepEqual(attributeValues('regkey', 'HKLM\\\\x'), []);
});

test('parseMispEvent keeps to_ids attributes, objects included, and finds techniques', () => {
  const hunt = parseMispEvent(EVENT);
  assert.equal(hunt.title, 'OSINT - Egregor: The New Ransomware Variant To Watch');
  const values = hunt.indicators.map((i) => `${i.type}:${i.value}`).sort();
  assert.deepEqual(values, [
    'cve:CVE-2020-1472',
    'domain:evil-cdn.com',
    'ipv4:185.220.101.5',
    'ipv4:45.142.212.100',
    'ipv4:91.92.93.94',
    `md5:${'c'.repeat(31)}d`,
    `sha256:${'ab'.repeat(32)}`,
    'url:https://evil-cdn.com/payload.php',
  ]);
  const ip = hunt.indicators.find((i) => i.value === '45.142.212.100')!;
  assert.equal(ip.stix_id, 'indicator--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'the MISP attribute UUID is kept');
  assert.match(ip.context!, /C2/);
  assert.match(hunt.indicators.find((i) => i.type === 'md5')!.context!, /file object/);
  assert.equal(hunt.indicators.find((i) => i.type === 'cve')!.stix_id.startsWith('vulnerability--'), true);
  assert.equal(new Set(hunt.indicators.map((i) => i.stix_id)).size, hunt.indicators.length, 'ids are unique');
  assert.deepEqual(hunt.hypotheses[0].attack_techniques, ['T1486', 'T1566']);
  assert.equal(hunt.source_url, 'https://www.example-news.org/egregor-report');
  assert.match(hunt.summary!, /CIRCL/);
  assert.match(hunt.summary!, /tlp:white/);
  assert.equal(hunt.stats.all_attributes, false);
});

test('an event with no to_ids attribute uses every huntable attribute, and says so', () => {
  const event = { Event: { uuid: 'x', info: 'No flags', Attribute: [A('domain', 'flagless-bad.net', { to_ids: false })] } };
  const hunt = parseMispEvent(event);
  assert.deepEqual(hunt.indicators.map((i) => i.value), ['flagless-bad.net']);
  assert.equal(hunt.stats.all_attributes, true);
  const { method, note } = parseStructured(event);
  assert.equal(method, 'misp');
  assert.match(note, /to_ids/);
});

test('parseStructured still reads STIX bundles', () => {
  const { method } = parseStructured({ type: 'bundle', id: 'bundle--1', objects: [{ type: 'domain-name', id: 'domain-name--1', value: 'bad-domain.top' }] });
  assert.equal(method, 'stix');
});
