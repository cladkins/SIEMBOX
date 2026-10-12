/**
 * The SSRF address and host-name rules the RDAP client relies on: which IPv4
 * and IPv6 addresses count as public, IPv6 expansion (embedded IPv4 included),
 * internal-only host names, and resolution that refuses a host as soon as one
 * of its addresses is not public. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  UnsafeTargetError,
  hostnameRejection,
  ipv6Groups,
  isPublicAddress,
  resolvePublicAddresses,
  type LookupAllFn,
} from './netSafety';

test('addresses: only globally routable unicast is public', () => {
  const table: Array<[string, boolean]> = [
    // IPv4
    ['93.184.216.34', true],
    ['8.8.8.8', true],
    ['100.63.255.255', true], // just below CGNAT
    ['172.15.255.255', true], // just below 172.16/12
    ['0.0.0.0', false],
    ['10.0.0.1', false],
    ['100.64.0.1', false], // CGNAT
    ['127.0.0.1', false],
    ['169.254.169.254', false], // cloud metadata
    ['172.16.0.1', false],
    ['172.31.255.255', false],
    ['192.0.2.10', false],
    ['192.168.1.1', false],
    ['198.18.0.1', false],
    ['203.0.113.5', false],
    ['224.0.0.1', false],
    ['255.255.255.255', false],
    // IPv6
    ['2606:4700:4700::1111', true],
    ['2620:74:1b::1:1', true],
    ['64:ff9b::808:808', true], // NAT64 of 8.8.8.8
    ['::', false],
    ['::1', false],
    ['::ffff:8.8.8.8', false], // IPv4-mapped: never a published server address
    ['::ffff:10.0.0.1', false],
    ['64:ff9b::a00:1', false], // NAT64 of 10.0.0.1
    ['fc00::1', false],
    ['fd12:3456:789a::1', false], // ULA
    ['fe80::1', false],
    ['fe80::1%eth0', false],
    ['ff02::1', false],
    ['2001:db8::1', false], // documentation
    ['2001::1', false], // Teredo
    ['2002:c0a8:0101::1', false], // 6to4 of 192.168.1.1
    ['2002:0808:0808::1', true], // 6to4 of 8.8.8.8
    ['3fff::1', false], // documentation (RFC 9637)
    // Not addresses
    ['example.com', false],
    ['', false],
  ];
  for (const [address, expected] of table) {
    assert.equal(isPublicAddress(address), expected, address);
  }
});

test('IPv6 expansion handles compression and embedded IPv4', () => {
  assert.deepEqual(ipv6Groups('::1'), [0, 0, 0, 0, 0, 0, 0, 1]);
  assert.deepEqual(ipv6Groups('2001:db8::'), [0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]);
  assert.deepEqual(ipv6Groups('::ffff:10.0.0.1'), [0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001]);
  assert.deepEqual(ipv6Groups('1:2:3:4:5:6:7:8'), [1, 2, 3, 4, 5, 6, 7, 8]);
  assert.equal(ipv6Groups('not-an-address'), null);
  assert.equal(ipv6Groups('10.0.0.1'), null);
});

test('host names: IP literals and internal-only names are refused', () => {
  const refused = [
    '10.0.0.1',
    '[::1]',
    'localhost',
    'printer',
    'rdap.localhost',
    'nas.local',
    'metadata.google.internal',
    'router.lan',
    'box.home.arpa',
    'x.corp',
    'x.test',
    'x.invalid',
    'x.onion',
    '1.0.0.127.in-addr.arpa',
    'under_score.example.com',
    'host.123',
  ];
  for (const host of refused) assert.notEqual(hostnameRejection(host), null, host);
  for (const host of [
    'rdap.verisign.com',
    'rdap.nic.co.uk',
    'rdap.xn--ngbc5azd.example-registry.net',
  ]) {
    assert.equal(hostnameRejection(host), null, host);
  }
});

test('resolution: refused when any address is non-public, or the name does not resolve', async () => {
  const lookup =
    (addresses: string[]): LookupAllFn =>
    async () =>
      addresses.map((address) => ({ address, family: address.includes(':') ? 6 : 4 }));
  assert.deepEqual(await resolvePublicAddresses('rdap.registry.net', lookup(['8.8.8.8'])), [
    { address: '8.8.8.8', family: 4 },
  ]);
  for (const addresses of [['8.8.8.8', '10.0.0.1'], ['::1'], []]) {
    await assert.rejects(
      resolvePublicAddresses('rdap.registry.net', lookup(addresses)),
      UnsafeTargetError,
      addresses.join(',')
    );
  }
  await assert.rejects(
    resolvePublicAddresses('rdap.registry.net', async () => {
      throw Object.assign(new Error('nope'), { code: 'ENOTFOUND' });
    }),
    (err: unknown) =>
      err instanceof UnsafeTargetError &&
      err.retryable &&
      /could not resolve rdap\.registry\.net \(ENOTFOUND\)/.test(err.message)
  );
  await assert.rejects(
    resolvePublicAddresses('rdap.registry.net', lookup(['10.0.0.1'])),
    (err: unknown) => err instanceof UnsafeTargetError && !err.retryable,
    'a forbidden address is not a retry'
  );
  let asked = false;
  await assert.rejects(
    resolvePublicAddresses('metadata.internal', async () => {
      asked = true;
      return [];
    }),
    UnsafeTargetError
  );
  assert.equal(asked, false, 'an internal-only name is refused before any DNS query');
});
