/**
 * Identity facts for duplicate assets (assetIdentity.ts) and the pure parts of
 * a merge (assetMerge.ts). No database. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { identifyingMac, isUsableMac, normalizeMac, shortHostname } from './assetIdentity';
import { addIpHistory, mergedAssetFields, mergeWarnings, parseMergeIds, MAX_IP_HISTORY, type AssetRow } from './assetMerge';

test('normalizeMac accepts the common spellings and nothing else', () => {
  assert.equal(normalizeMac('AA:BB:CC:00:11:22'), 'aa:bb:cc:00:11:22');
  assert.equal(normalizeMac('aa-bb-cc-00-11-22'), 'aa:bb:cc:00:11:22');
  assert.equal(normalizeMac('aabb.cc00.1122'), 'aa:bb:cc:00:11:22');
  assert.equal(normalizeMac('aabbcc001122'), 'aa:bb:cc:00:11:22');
  for (const bad of ['', 'aa:bb:cc', 'aa:bb:cc:00:11:22:33', 'gg:bb:cc:00:11:22', 'mac aa:bb:cc:00:11:22', null, 42, undefined]) {
    assert.equal(normalizeMac(bad), null, String(bad));
  }
});

test('isUsableMac refuses zero, broadcast, multicast and locally administered (random) MACs', () => {
  assert.equal(isUsableMac('3c:22:fb:12:34:56'), true); // an Apple OUI, globally administered
  assert.equal(isUsableMac('00:00:00:00:00:00'), false);
  assert.equal(isUsableMac('ff:ff:ff:ff:ff:ff'), false);
  assert.equal(isUsableMac('01:00:5e:00:00:01'), false); // multicast
  // Private Wi-Fi / VM / container MACs set the U/L bit (x2, x6, xA, xE).
  for (const random of ['02:42:ac:11:00:02', 'a6:83:e7:01:02:03', '3e:22:fb:12:34:56', 'ce:01:02:03:04:05']) {
    assert.equal(isUsableMac(random), false, random);
  }
  assert.equal(isUsableMac(''), false);
  assert.equal(identifyingMac('3C:22:FB:12:34:56'), '3c:22:fb:12:34:56');
  assert.equal(identifyingMac('a6:83:e7:01:02:03'), null);
});

test('shortHostname: first label, lower case; IPs and generic names give null', () => {
  assert.equal(shortHostname('Chriss-MBP-383.localdomain'), 'chriss-mbp-383');
  assert.equal(shortHostname('chriss-mbp-383.local.'), 'chriss-mbp-383');
  assert.equal(shortHostname('Chriss-MBP-383.lan'), 'chriss-mbp-383');
  assert.equal(shortHostname('chriss-macbook-pro-87.tailcb24f.ts.net'), 'chriss-macbook-pro-87');
  assert.equal(shortHostname('  WEB01  '), 'web01');
  assert.equal(shortHostname('192.168.1.130'), null);
  assert.equal(shortHostname('fe80::1'), null);
  assert.equal(shortHostname('localhost.localdomain'), null);
  assert.equal(shortHostname(''), null);
  assert.equal(shortHostname(null), null);
});

test('parseMergeIds validates and de-duplicates', () => {
  assert.deepEqual(parseMergeIds('5', [7, '8', 7]), { into: 5, from: [7, 8] });
  assert.throws(() => parseMergeIds('x', [1]), /Invalid asset ID/);
  assert.throws(() => parseMergeIds(5, []), /non-empty/);
  assert.throws(() => parseMergeIds(5, 'nope'), /non-empty/);
  assert.throws(() => parseMergeIds(5, [5]), /into itself/);
  assert.throws(() => parseMergeIds(5, [1.5]), /positive integer/);
  assert.throws(() => parseMergeIds(5, [-1]), /positive integer/);
  assert.throws(() => parseMergeIds(5, Array.from({ length: 101 }, (_, i) => i + 10)), /At most 100/);
});

test('addIpHistory keeps one entry per address, widened, newest first, capped', () => {
  let h = addIpHistory(undefined, '10.0.0.1', '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z');
  h = addIpHistory(h, '10.0.0.2', '2026-01-03T00:00:00Z', '2026-01-04T00:00:00Z');
  h = addIpHistory(h, '10.0.0.1', '2025-12-01T00:00:00Z', '2026-02-01T00:00:00Z');
  assert.deepEqual(h.map((x) => x.ip), ['10.0.0.1', '10.0.0.2']);
  assert.equal(h[0].first_seen, '2025-12-01T00:00:00.000Z');
  assert.equal(h[0].last_seen, '2026-02-01T00:00:00.000Z');
  assert.deepEqual(addIpHistory('garbage', null, null, null), []);
  let many: ReturnType<typeof addIpHistory> = [];
  for (let i = 0; i < MAX_IP_HISTORY + 10; i++) many = addIpHistory(many, `10.1.0.${i}`, null, new Date(Date.UTC(2026, 0, 1, 0, i)));
  assert.equal(many.length, MAX_IP_HISTORY);
  assert.equal(many[0].ip, `10.1.0.${MAX_IP_HISTORY + 9}`);
});

function row(over: Partial<AssetRow>): AssetRow {
  return {
    id: 1, ip_address: '10.0.0.1', hostname: null, mac_address: null, os_type: null, os_version: null,
    asset_type: 'endpoint', criticality: 'medium', status: 'active', discovery_method: 'edr_agent',
    first_seen: new Date('2026-01-10T00:00:00Z'), last_seen: new Date('2026-01-20T00:00:00Z'), last_scanned: null,
    metadata: null, tags: null, ...over,
  };
}

test('mergedAssetFields: kept values win, gaps filled from the newest duplicate, dates widen, history recorded', () => {
  const into = row({ id: 33, hostname: 'kept', criticality: 'medium', tags: ['a'], metadata: { agent_id: 'x', note: 'kept' } });
  const older = row({ id: 71, ip_address: '10.0.0.71', os_type: 'old-os', criticality: 'high', first_seen: new Date('2025-06-01T00:00:00Z'),
    last_seen: new Date('2025-07-01T00:00:00Z'), tags: ['b'], metadata: { note: 'older', only_older: 1, current_ip: '1.2.3.4' } });
  const newer = row({ id: 72, ip_address: '10.0.0.72', os_type: 'new-os', mac_address: '3c:22:fb:12:34:56', last_seen: new Date('2026-03-01T00:00:00Z'),
    last_scanned: new Date('2026-02-01T00:00:00Z'), tags: ['a', 'c'] });
  const f = mergedAssetFields(into, [older, newer], 'manual', new Date('2026-04-01T00:00:00Z'));
  assert.equal(f.hostname, 'kept');
  assert.equal(f.os_type, 'new-os');
  assert.equal(f.mac_address, '3c:22:fb:12:34:56');
  assert.equal(f.criticality, 'high', 'the highest criticality of the merged rows');
  assert.equal(f.first_seen?.toISOString(), '2025-06-01T00:00:00.000Z');
  assert.equal(f.last_seen?.toISOString(), '2026-03-01T00:00:00.000Z');
  assert.equal(f.last_scanned?.toISOString(), '2026-02-01T00:00:00.000Z');
  assert.deepEqual(f.tags, ['a', 'b', 'c']);
  assert.equal(f.metadata.note, 'kept');
  assert.equal(f.metadata.only_older, 1);
  assert.equal(f.metadata.current_ip, undefined, "a duplicate's current_ip is not the kept row's");
  assert.deepEqual(f.metadata.merged_assets.map((m: any) => m.id), [71, 72]);
  assert.equal(f.metadata.merged_assets[0].mode, 'manual');
  assert.deepEqual(new Set(f.metadata.ip_history.map((h: any) => h.ip)), new Set(['10.0.0.1', '10.0.0.71', '10.0.0.72']));
});

test('mergeWarnings names other agents, different MACs and different host names', () => {
  const into = row({ id: 1, hostname: 'mbp.local', mac_address: '3c:22:fb:12:34:56' });
  const other = row({ id: 2, ip_address: '10.0.0.2', hostname: 'printer', mac_address: '00:11:22:33:44:55' });
  const w = mergeWarnings(into, [other], [{ id: 2, ip_address: '10.0.0.2', hostname: 'printer', mac_address: null, discovery_method: 'nmap', asset_type: null, open_vulnerabilities: 0, agents: ['b'] }], ['a']);
  assert.equal(w.length, 3);
  assert.match(w[0], /2 endpoint agents/);
  assert.match(w[1], /different MAC/);
  assert.match(w[2], /different host name/);
  assert.deepEqual(mergeWarnings(into, [row({ id: 3, hostname: 'MBP.localdomain' })], [], []), []);
  // The name the kept machine's agent reports counts as its own.
  assert.deepEqual(mergeWarnings(into, [row({ id: 4, hostname: 'MacBook-Pro.local' })], [], ['a'], ['macbook-pro.lan']), []);
});
