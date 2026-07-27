import { test } from 'node:test';
import assert from 'node:assert/strict';
import { toCidr, detectLocalInterfaces, vlanWarning, isValidCidr, resolveScope, LocalInterface } from './scope';

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

test('resolveScope merges detected + valid manual CIDRs and reports rejects', () => {
  const interfaces: LocalInterface[] = [
    { name: 'eth0', address: '192.168.1.10', netmask: '255.255.255.0', cidr: '192.168.1.0/24' },
  ];
  const result = resolveScope(['10.0.0.0/24', 'bogus'], interfaces);
  assert.deepEqual(result.cidrs.sort(), ['10.0.0.0/24', '192.168.1.0/24']);
  assert.deepEqual(result.rejected, ['bogus']);
  assert.ok(result.warning); // single-homed
});

test('resolveScope dedupes when a manual CIDR matches an auto-detected one', () => {
  const interfaces: LocalInterface[] = [
    { name: 'eth0', address: '192.168.1.10', netmask: '255.255.255.0', cidr: '192.168.1.0/24' },
  ];
  const result = resolveScope(['192.168.1.0/24'], interfaces);
  assert.deepEqual(result.cidrs, ['192.168.1.0/24']);
});
