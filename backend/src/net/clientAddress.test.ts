/**
 * Address normalization, the sign-in /64 key and how a request arrived.
 * Hermetic. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { Request } from 'express';
import { clientAddress, normalizeIp, parseSignInNetwork, PROXY_SOCKET_PEER, requestVia, signInNetworkKey } from './clientAddress';
import { requestLimitKey, signInLimitKey, formatWait } from './requestLimits';

/** What Express would expose for a request: req.ip, req.ips and the socket. */
function request(ip: string | undefined, peer: string | undefined, ips: string[] = []): Request {
  return { ip, ips, socket: { remoteAddress: peer } } as unknown as Request;
}

test('normalizeIp: one canonical spelling per address, null for anything else', () => {
  const cases: Array<[unknown, string | null]> = [
    ['192.0.2.1', '192.0.2.1'],
    [' 192.0.2.1 ', '192.0.2.1'],
    ['::ffff:192.0.2.1', '192.0.2.1'], // how a dual-stack listener reports IPv4 peers
    ['::FFFF:c000:201', '192.0.2.1'],
    ['2001:0DB8:0:0::1', '2001:db8::1'],
    ['fe80::1%eth0', 'fe80::1'],
    ['::1', '::1'],
    ['192.0.2.1%eth0', '192.0.2.1'],
    ['not-an-ip', null],
    ['<script>', null],
    ['192.0.2.1, 198.51.100.1', null],
    ['192.0.2.1:8080', null],
    ['[::1]', null],
    ['01.2.3.4', null],
    ['', null],
    [PROXY_SOCKET_PEER, null],
    [undefined, null],
    [42, null],
  ];
  for (const [input, expected] of cases) assert.equal(normalizeIp(input), expected, JSON.stringify(input));
});

test('signInNetworkKey: IPv4 as it is, IPv6 as its /64, unknown without an address', () => {
  assert.equal(signInNetworkKey('203.0.113.9'), '203.0.113.9');
  assert.equal(signInNetworkKey('::ffff:203.0.113.9'), '203.0.113.9');
  assert.equal(signInNetworkKey('2001:db8:1:2:3:4:5:6'), '2001:db8:1:2::/64');
  assert.equal(signInNetworkKey('2001:db8:1:2:ffff:ffff:ffff:ffff'), '2001:db8:1:2::/64');
  assert.equal(signInNetworkKey('2001:DB8:0:0:1::1'), '2001:db8::/64');
  assert.equal(signInNetworkKey('::1'), '::/64');
  assert.equal(signInNetworkKey('64:ff9b::192.0.2.1'), '64:ff9b::/64');
  assert.equal(signInNetworkKey(null), 'unknown');
  assert.equal(signInNetworkKey('junk'), 'unknown');
});

test('parseSignInNetwork: an address, an IPv6 /64 as the counters list it, or unknown', () => {
  const cases: Array<[unknown, string | null]> = [
    ['203.0.113.9', '203.0.113.9'],
    [' 203.0.113.9 ', '203.0.113.9'],
    ['2001:db8:1:2:3:4:5:6', '2001:db8:1:2::/64'],
    ['2001:db8:1:2::/64', '2001:db8:1:2::/64'],
    ['2001:DB8:1:2::77/64', '2001:db8:1:2::/64'],
    ['unknown', 'unknown'],
    ['203.0.113.9/64', null],
    ['2001:db8::/48', null],
    ['203.0.113.0/24', null],
    ['nonsense', null],
    ['', null],
    [undefined, null],
    [42, null],
  ];
  for (const [input, expected] of cases) assert.equal(parseSignInNetwork(input), expected, JSON.stringify(input));
  // Whatever status prints parses back to itself.
  assert.equal(parseSignInNetwork(signInNetworkKey('2001:db8:aa:bb::1')), signInNetworkKey('2001:db8:aa:bb::1'));
});

test('clientAddress: req.ip, normalized', () => {
  assert.equal(clientAddress(request('::ffff:192.0.2.5', '::ffff:192.0.2.5')), '192.0.2.5');
  assert.equal(clientAddress(request('203.0.113.7', PROXY_SOCKET_PEER, ['203.0.113.7'])), '203.0.113.7');
});

test('clientAddress: junk a trusted proxy forwarded falls back to that proxy, then to the TCP peer', () => {
  // Over the socket, an outer proxy 192.0.2.10 (trusted) forwarded "junk".
  assert.equal(clientAddress(request('junk', PROXY_SOCKET_PEER, ['junk', '192.0.2.10'])), '192.0.2.10');
  // A trusted TCP peer forwarded junk and nothing else.
  assert.equal(clientAddress(request('junk', '192.0.2.10', ['junk'])), '192.0.2.10');
  // The socket without any X-Forwarded-For: no address.
  assert.equal(clientAddress(request(PROXY_SOCKET_PEER, PROXY_SOCKET_PEER)), null);
  assert.equal(clientAddress(request(undefined, undefined)), null);
});

test('requestVia: proxy socket, trusted proxy or direct', () => {
  assert.equal(requestVia(request('203.0.113.7', PROXY_SOCKET_PEER, ['203.0.113.7'])), 'proxy-socket');
  assert.equal(requestVia(request('203.0.113.7', '192.0.2.10', ['203.0.113.7'])), 'trusted-proxy');
  assert.equal(requestVia(request('::ffff:192.0.2.5', '::ffff:192.0.2.5')), 'direct');
  assert.equal(requestVia(request(undefined, undefined)), 'direct');
});

test('limiter keys: the full address for request limits, the /64 for sign-in', () => {
  const v6 = request('2001:db8:1:2:3:4:5:6', '2001:db8:1:2:3:4:5:6');
  assert.equal(requestLimitKey(v6), '2001:db8:1:2:3:4:5:6');
  assert.equal(signInLimitKey(v6), '2001:db8:1:2::/64');
  assert.equal(requestLimitKey(request(PROXY_SOCKET_PEER, PROXY_SOCKET_PEER)), 'unknown');
  assert.equal(signInLimitKey(request(PROXY_SOCKET_PEER, PROXY_SOCKET_PEER)), 'unknown');
});

test('formatWait reads naturally', () => {
  assert.equal(formatWait(1), '1 second');
  assert.equal(formatWait(45), '45 seconds');
  assert.equal(formatWait(60), '1 minute');
  assert.equal(formatWait(61), '2 minutes');
  assert.equal(formatWait(900), '15 minutes');
});
