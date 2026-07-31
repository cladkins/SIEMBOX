import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  toCidr,
  detectLocalInterfaces,
  vlanWarning,
  isHostNetworked,
  isValidCidr,
  isSweepableCidr,
  cidrHosts,
  resolveScope,
  LocalInterface,
} from './scope';

test('toCidr computes the network address and prefix length from a netmask', () => {
  assert.equal(toCidr('192.168.1.42', '255.255.255.0'), '192.168.1.0/24');
  assert.equal(toCidr('10.20.30.5', '255.255.0.0'), '10.20.0.0/16');
});

test('detectLocalInterfaces skips internal (loopback) and IPv6 addresses', () => {
  const fake = {
    lo: [{ address: '127.0.0.1', netmask: '255.0.0.0', family: 'IPv4', internal: true, mac: '', cidr: '127.0.0.1/8' } as any],
    eth0: [
      { address: '192.168.1.10', netmask: '255.255.255.0', family: 'IPv4', internal: false, mac: '', cidr: '192.168.1.0/24' } as any,
      { address: 'fe80::1', netmask: 'ffff:ffff:ffff:ffff::', family: 'IPv6', internal: false, mac: '', cidr: null } as any,
    ],
  };
  const result = detectLocalInterfaces(fake as any);
  assert.equal(result.length, 1);
  assert.equal(result[0].cidr, '192.168.1.0/24');
});

test('vlanWarning fires when the host is single-homed (one subnet)', () => {
  const one: LocalInterface[] = [{ name: 'eth0', address: '192.168.1.10', netmask: '255.255.255.0', cidr: '192.168.1.0/24' }];
  assert.ok(vlanWarning(one));
});

test('vlanWarning fires with zero interfaces too (container with no visible NIC)', () => {
  assert.ok(vlanWarning([]));
});

test('vlanWarning is silent once two distinct subnets are visible', () => {
  const two: LocalInterface[] = [
    { name: 'eth0', address: '192.168.1.10', netmask: '255.255.255.0', cidr: '192.168.1.0/24' },
    { name: 'eth1', address: '10.0.0.10', netmask: '255.255.255.0', cidr: '10.0.0.0/24' },
  ];
  assert.equal(vlanWarning(two), null);
});

test('isValidCidr accepts well-formed CIDRs and rejects garbage', () => {
  assert.equal(isValidCidr('192.168.1.0/24'), true);
  assert.equal(isValidCidr('10.0.0.0/8'), true);
  assert.equal(isValidCidr('192.168.1.0/33'), false);
  assert.equal(isValidCidr('999.168.1.0/24'), false);
  assert.equal(isValidCidr('not-a-cidr'), false);
  assert.equal(isValidCidr('192.168.1.0'), false); // missing prefix
});

test('isHostNetworked is true only for the exact string "true"', () => {
  assert.equal(isHostNetworked({ SIEMBOX_HOST_NETWORKING: 'true' }), true);
  assert.equal(isHostNetworked({}), false);
  assert.equal(isHostNetworked({ SIEMBOX_HOST_NETWORKING: 'false' }), false);
  assert.equal(isHostNetworked({ SIEMBOX_HOST_NETWORKING: 'yes' }), false);
});

test('resolveScope leaves detectedLanCidr null when not host-networked, even with real-looking interfaces', () => {
  const interfaces: LocalInterface[] = [
    { name: 'eth0', address: '192.168.1.10', netmask: '255.255.255.0', cidr: '192.168.1.0/24' },
  ];
  assert.equal(resolveScope([], interfaces, {}).detectedLanCidr, null);
});

test('resolveScope populates detectedLanCidr from the first interface when host-networked', () => {
  const interfaces: LocalInterface[] = [
    { name: 'eth0', address: '192.168.1.10', netmask: '255.255.255.0', cidr: '192.168.1.0/24' },
    { name: 'eth1', address: '10.0.0.10', netmask: '255.255.255.0', cidr: '10.0.0.0/24' },
  ];
  const result = resolveScope([], interfaces, { SIEMBOX_HOST_NETWORKING: 'true' });
  assert.equal(result.detectedLanCidr, '192.168.1.0/24');
});

test('resolveScope reports detectedLanCidr as null when host-networked but no interfaces are visible', () => {
  assert.equal(resolveScope([], [], { SIEMBOX_HOST_NETWORKING: 'true' }).detectedLanCidr, null);
});

test('resolveScope returns only valid manual CIDRs and reports rejects', () => {
  const interfaces: LocalInterface[] = [
    { name: 'eth0', address: '192.168.1.10', netmask: '255.255.255.0', cidr: '192.168.1.0/24' },
  ];
  const result = resolveScope(['10.0.0.0/24', 'bogus'], interfaces);
  assert.deepEqual(result.cidrs, ['10.0.0.0/24']);
  assert.deepEqual(result.rejected, ['bogus']);
  assert.ok(result.warning); // single-homed
});

test('resolveScope excludes the auto-detected interface CIDR from the returned scope', () => {
  const interfaces: LocalInterface[] = [
    { name: 'eth0', address: '192.168.1.10', netmask: '255.255.255.0', cidr: '192.168.1.0/24' },
  ];
  const result = resolveScope([], interfaces);
  assert.deepEqual(result.cidrs, []);
  assert.ok(result.warning); // still fires -- vlanWarning is independent of what's displayed as "scope"
});

test('resolveScope dedupes repeated manual CIDR entries', () => {
  const result = resolveScope(['192.168.1.0/24', '192.168.1.0/24'], []);
  assert.deepEqual(result.cidrs, ['192.168.1.0/24']);
});

test('isSweepableCidr accepts a /24 and rejects a /8 as too large to sweep', () => {
  assert.equal(isSweepableCidr('192.168.1.0/24'), true);
  assert.equal(isSweepableCidr('10.0.0.0/8'), false);
});

test('isSweepableCidr rejects malformed CIDRs the same as isValidCidr', () => {
  assert.equal(isSweepableCidr('not-a-cidr'), false);
});

test('resolveScope rejects a syntactically valid but too-large CIDR', () => {
  const result = resolveScope(['10.0.0.0/8'], []);
  assert.deepEqual(result.cidrs, []);
  assert.deepEqual(result.rejected, ['10.0.0.0/8']);
});

test('cidrHosts excludes network + broadcast for a /24', () => {
  const hosts = cidrHosts('192.168.1.0/24');
  assert.equal(hosts.length, 254);
  assert.equal(hosts[0], '192.168.1.1');
  assert.equal(hosts[hosts.length - 1], '192.168.1.254');
  assert.ok(!hosts.includes('192.168.1.0'));
  assert.ok(!hosts.includes('192.168.1.255'));
});

test('cidrHosts returns both addresses for a /31 (RFC 3021, no network/broadcast)', () => {
  assert.deepEqual(cidrHosts('10.0.0.0/31'), ['10.0.0.0', '10.0.0.1']);
});

test('cidrHosts returns just the one address for a /32', () => {
  assert.deepEqual(cidrHosts('10.0.0.5/32'), ['10.0.0.5']);
});

test('cidrHosts handles a non-zero-aligned base address by normalizing to the network', () => {
  // 192.168.1.42/24 should behave identically to 192.168.1.0/24
  assert.deepEqual(cidrHosts('192.168.1.42/24'), cidrHosts('192.168.1.0/24'));
});

test('cidrHosts on a /22 stays within the MAX_SWEEP_HOSTS bound and covers all four /24s', () => {
  const hosts = cidrHosts('10.1.0.0/22');
  assert.equal(hosts.length, 1022); // 1024 - network - broadcast
  assert.equal(hosts[0], '10.1.0.1');
  assert.equal(hosts[hosts.length - 1], '10.1.3.254');
});
