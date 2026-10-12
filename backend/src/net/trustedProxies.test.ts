/**
 * TRUSTED_PROXIES parsing, the Express trust function, Docker gateway
 * handling, name lookups through an injected resolver (answers only count when
 * Docker's DNS confirms them as containers on the backend's networks), and the
 * counter for ignored X-Forwarded-For headers. Hermetic: interfaces,
 * /proc/net/route and DNS are fixtures. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { Request } from 'express';
import { PROXY_SOCKET_PEER } from './clientAddress';
import {
  IGNORED_HEADER_GRACE_MS,
  IGNORED_HEADER_WARN_MS,
  IGNORED_PEER_TTL_MS,
  ipv6RouteGateways,
  MAX_TRACKED_PEERS,
  parseTrustedProxies,
  routeGateways,
  TrustedProxies,
  type InterfaceTable,
  type NameResolver,
  type TrustedProxiesOptions,
} from './trustedProxies';

const ROUTE_TABLE = [
  'Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT',
  'eth0\t00000000\t010012AC\t0003\t0\t0\t0\t00000000\t0\t0\t0',
  'eth0\t000012AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0',
  '',
].join('\n');
const IPV6_ROUTE_TABLE = [
  '00000000000000000000000000000000 00 00000000000000000000000000000000 00 20010db8000100000000000000000001 00000400 00000001 00000000 00000003     eth0',
  'fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0',
  '',
].join('\n');

/** A container on a bridge network: 172.18.0.2/16, gateway 172.18.0.1. */
const bridgeInterfaces = (): InterfaceTable => ({
  lo: [{ address: '127.0.0.1', family: 'IPv4', internal: true, cidr: '127.0.0.1/8' }],
  eth0: [
    { address: '172.18.0.2', family: 'IPv4', internal: false, cidr: '172.18.0.2/16' },
    { address: 'fe80::42:acff:fe12:2', family: 'IPv6', internal: false, cidr: 'fe80::42:acff:fe12:2/64' },
  ],
});

/** The Docker host's own namespace (network_mode: host). */
const hostInterfaces = (): InterfaceTable => ({
  lo: [{ address: '127.0.0.1', family: 'IPv4', internal: true, cidr: '127.0.0.1/8' }],
  eno1: [{ address: '192.168.1.10', family: 'IPv4', internal: false, cidr: '192.168.1.10/24' }],
  docker0: [{ address: '172.17.0.1', family: 'IPv4', internal: false, cidr: '172.17.0.1/16' }],
  'br-0123456789ab': [
    { address: '172.18.0.1', family: 'IPv4', internal: false, cidr: '172.18.0.1/16' },
    { address: 'fe80::1', family: 'IPv6', internal: false, cidr: 'fe80::1/64' },
  ],
  veth1234: [],
});

function dnsError(code: string): NodeJS.ErrnoException {
  return Object.assign(new Error(`query ${code}`), { code });
}

/**
 * A resolver answering from `table` (name -> v4/v6 answers or an error code);
 * unknown names are NXDOMAIN. Reverse lookups answer from `ptr` (address ->
 * names or an error code); otherwise, like Docker's DNS for the containers on
 * the bridge-network fixture, every 172.18.x.x address is
 * `c-<address>.siembox_net`, and anything else is NXDOMAIN.
 */
function fakeResolver() {
  const calls: string[] = [];
  const table: Record<string, { v4?: string[] | string; v6?: string[] | string }> = {};
  const ptr: Record<string, string[] | string> = {};
  const answer = (value: string[] | string | undefined, missing: string) => {
    if (value === undefined) return Promise.reject(dnsError(missing));
    return typeof value === 'string' ? Promise.reject(dnsError(value)) : Promise.resolve(value);
  };
  const resolver: NameResolver = {
    resolve4: (name) => {
      calls.push(`A ${name}`);
      return name in table ? answer(table[name].v4, 'ENODATA') : answer(undefined, 'ENOTFOUND');
    },
    resolve6: (name) => {
      calls.push(`AAAA ${name}`);
      return name in table ? answer(table[name].v6, 'ENODATA') : answer(undefined, 'ENOTFOUND');
    },
    reverse: (ip) => {
      calls.push(`PTR ${ip}`);
      if (ip in ptr) return answer(ptr[ip], 'ENOTFOUND');
      if (ip.startsWith('172.18.')) return Promise.resolve([`c-${ip.replace(/\./g, '-')}.siembox_net`]);
      return answer(undefined, 'ENOTFOUND');
    },
  };
  return { resolver, table, ptr, calls };
}

function captureLog() {
  const lines: Array<[string, string]> = [];
  return {
    lines,
    log: {
      info: (m: string) => lines.push(['info', m]),
      warn: (m: string) => lines.push(['warn', m]),
      error: (m: string) => lines.push(['error', m]),
    },
    of: (level: string) => lines.filter(([l]) => l === level).map(([, m]) => m),
  };
}

/** A bridge-mode container unless overridden; never touches the real system. */
function proxies(spec: string | undefined, options: Partial<TrustedProxiesOptions> = {}) {
  const log = captureLog();
  const dns = fakeResolver();
  const instance = new TrustedProxies({
    spec,
    inContainer: true,
    hostNetworking: false,
    interfaces: bridgeInterfaces,
    readFile: (path) => (path === '/proc/net/route' ? ROUTE_TABLE : path === '/proc/net/ipv6_route' ? '' : null),
    resolver: dns.resolver,
    log: log.log,
    ...options,
  });
  return { instance, log, dns };
}

function directRequest(peer: string, forwardedFor?: string, method = 'GET', url = '/api/alerts'): Request {
  return {
    method,
    originalUrl: url,
    url,
    headers: forwardedFor === undefined ? {} : { 'x-forwarded-for': forwardedFor },
    socket: { remoteAddress: peer },
  } as unknown as Request;
}

test('parse: addresses, ranges and service names; the default is frontend', () => {
  const parsed = parseTrustedProxies('frontend, 192.0.2.10 2001:DB8::7,10.10.0.0/24, 2001:db8:1::/64,traefik');
  assert.deepEqual(
    parsed.entries.map((e) => [e.kind, e.entry]),
    [
      ['name', 'frontend'],
      ['address', '192.0.2.10'],
      ['address', '2001:DB8::7'],
      ['range', '10.10.0.0/24'],
      ['range', '2001:db8:1::/64'],
      ['name', 'traefik'],
    ]
  );
  assert.deepEqual(parsed.rejected, []);
  assert.deepEqual(parsed.warnings, []);
  for (const unset of [undefined, '', '   ']) {
    const fallback = parseTrustedProxies(unset);
    assert.equal(fallback.configured, 'frontend');
    assert.deepEqual(fallback.entries.map((e) => e.entry), ['frontend']);
  }
});

test('parse: values that would trust everyone, presets, hop counts and junk are rejected; the rest applies', () => {
  const rejectedValues = [
    '*', 'true', 'TRUE', 'all', 'false', '0.0.0.0/0', '::/0', 'loopback', 'linklocal', 'uniquelocal',
    '10.0.0.0/33', '2001:db8::/129', '10.0.0.0/x', '1.2.3', '300.1.1.1', '1', '2', 'localhost', 'bad!name',
    'fe80::1%eth0/64', '0.0.0.0', '::', 'not-an-ip/24',
  ];
  const parsed = parseTrustedProxies([...rejectedValues, '192.0.2.10'].join(','));
  assert.deepEqual(parsed.rejected.map((r) => r.entry), rejectedValues);
  for (const { reason } of parsed.rejected) assert.ok(reason.length > 10, reason);
  assert.deepEqual(parsed.entries.map((e) => e.entry), ['192.0.2.10']);

  const { instance } = proxies(rejectedValues.join(','));
  assert.equal(instance.trust('1.2.3.4', 0), false, 'nothing is trusted by a rejected entry');
});

test('parse: wide ranges are accepted with a warning', () => {
  const parsed = parseTrustedProxies('10.0.0.0/16,192.168.1.0/24,2001:db8::/48,2001:db8:5::/64');
  assert.equal(parsed.entries.length, 4);
  assert.equal(parsed.warnings.length, 2);
  assert.match(parsed.warnings[0], /10\.0\.0\.0\/16 is a wide range/);
  assert.match(parsed.warnings[1], /2001:db8::\/48 is a wide range/);
});

test('none trusts only the proxy socket; combined with entries, the entries apply', () => {
  const { instance } = proxies('none');
  assert.equal(instance.trust(PROXY_SOCKET_PEER, 0), true);
  assert.equal(instance.trust('192.0.2.10', 0), false);
  assert.deepEqual(instance.describe().entries, []);

  const mixed = parseTrustedProxies('none,192.0.2.10');
  assert.deepEqual(mixed.entries.map((e) => e.entry), ['192.0.2.10']);
  assert.deepEqual(mixed.rejected.map((r) => r.entry), ['none']);
});

test('trust: the socket peer only at hop 0; listed entries at any hop; everyone else never', () => {
  const { instance } = proxies('192.0.2.10,2001:db8::7,10.10.0.0/24');
  assert.equal(instance.trust(PROXY_SOCKET_PEER, 0), true);
  assert.equal(instance.trust(PROXY_SOCKET_PEER, 1), false, 'a forged X-Forwarded-For entry');
  for (const hop of [0, 1, 3]) {
    assert.equal(instance.trust('192.0.2.10', hop), true);
    assert.equal(instance.trust('::ffff:192.0.2.10', hop), true);
    assert.equal(instance.trust('2001:DB8:0::7', hop), true);
    assert.equal(instance.trust('10.10.0.200', hop), true);
    assert.equal(instance.trust('10.10.1.1', hop), false);
    assert.equal(instance.trust('203.0.113.9', hop), false);
  }
  for (const junk of [undefined, '', 'not-an-ip', '<script>', '192.0.2.10:80', 'unix:frontend']) {
    assert.equal(instance.trust(junk, 0), false, String(junk));
  }
});

test('Docker gateway: never matched by a range (with a warning); an exact listing trusts it, with a warning', () => {
  const ranged = proxies('172.18.0.0/24');
  assert.equal(ranged.instance.trust('172.18.0.5', 0), true);
  assert.equal(ranged.instance.trust('172.18.0.1', 0), false, 'the gateway stays untrusted');
  assert.deepEqual(ranged.instance.describe().gateways, ['172.18.0.1']);
  assert.match(ranged.instance.describe().warnings.join('\n'), /contains the Docker gateway 172\.18\.0\.1/);

  const exact = proxies('172.18.0.1');
  assert.equal(exact.instance.trust('172.18.0.1', 0), true);
  assert.match(exact.instance.describe().warnings.join('\n'), /lists the Docker gateway 172\.18\.0\.1/);
});

test('gateways come from the routing tables in a container, and from docker0/br-* in the host namespace', () => {
  assert.deepEqual(routeGateways(ROUTE_TABLE), ['172.18.0.1']);
  assert.deepEqual(ipv6RouteGateways(IPV6_ROUTE_TABLE), ['2001:db8:1::1']);
  assert.deepEqual(routeGateways(null), []);

  const v6 = proxies('2001:db8:1::/64', {
    readFile: (path) => (path === '/proc/net/route' ? ROUTE_TABLE : IPV6_ROUTE_TABLE),
  });
  assert.deepEqual(v6.instance.describe().gateways, ['172.18.0.1', '2001:db8:1::1']);
  assert.equal(v6.instance.trust('2001:db8:1::1', 0), false);
  assert.equal(v6.instance.trust('2001:db8:1::2', 0), true);

  const host = proxies('172.16.0.0/12', { interfaces: hostInterfaces, readFile: () => null });
  assert.equal(host.instance.hostNetworking, true, 'docker0/br-*/veth* interfaces mean the host namespace');
  assert.deepEqual(host.instance.describe().gateways, ['172.17.0.1', '172.18.0.1']);
  assert.equal(host.instance.trust('172.18.0.3', 0), true);
  assert.equal(host.instance.trust('172.18.0.1', 0), false);

  const outside = proxies('10.0.0.0/8', { inContainer: false, interfaces: () => ({}) });
  assert.deepEqual(outside.instance.describe().gateways, [], 'no Docker, no Docker gateway');
});

test('names: only answers on the container\'s own networks count, never the gateway', async () => {
  const { instance, dns, log } = proxies('frontend');
  dns.table.frontend = { v4: ['172.18.0.3', '192.168.1.50', '172.18.0.1'] };
  await instance.start();
  instance.stop();
  assert.equal(instance.trust('172.18.0.3', 0), true);
  assert.equal(instance.trust('192.168.1.50', 0), false, 'a LAN answer is not trusted');
  assert.equal(instance.trust('172.18.0.1', 0), false, 'the gateway is not trusted');
  const [entry] = instance.describe().entries;
  assert.deepEqual(entry.addresses, ['172.18.0.3']);
  assert.deepEqual(entry.ignoredAnswers, ['192.168.1.50', '172.18.0.1']);
  assert.deepEqual(
    dns.calls.filter((call) => !call.startsWith('PTR')),
    ['A frontend', 'AAAA frontend']
  );
  assert.ok(dns.calls.includes('PTR 172.18.0.2'), "the backend's own address names its Docker network");
  assert.ok(dns.calls.includes('PTR 172.18.0.3'), 'the answer is confirmed with Docker');
  assert.ok(log.of('info').includes('TRUSTED_PROXIES: frontend -> 172.18.0.3'));
  assert.equal(log.of('warn').filter((m) => m.includes('ignored the answer')).length, 2);

  // The same ignored answers are not reported again on the next refresh.
  await instance.refresh();
  assert.equal(log.of('warn').filter((m) => m.includes('ignored the answer')).length, 2);
});

/** A container on a macvlan or ipvlan network: an address on the LAN itself, routed through the LAN's router. */
const lanInterfaces = (): InterfaceTable => ({
  lo: [{ address: '127.0.0.1', family: 'IPv4', internal: true, cidr: '127.0.0.1/8' }],
  eth0: [{ address: '192.168.1.50', family: 'IPv4', internal: false, cidr: '192.168.1.50/24' }],
});
const LAN_ROUTE_TABLE = 'Iface\tDestination\tGateway\neth0\t00000000\t0101A8C0\n'; // default via 192.168.1.1

test('names: an answer from another DNS server is not trusted, even on the backend\'s own (LAN) network', async () => {
  const { instance, dns, log } = proxies(undefined, {
    interfaces: lanInterfaces,
    readFile: (path) => (path === '/proc/net/route' ? LAN_ROUTE_TABLE : ''),
  });
  // No container is called frontend, so Docker's DNS passes the name on to the
  // LAN's DNS server, which answers with a DHCP client that calls itself
  // frontend. Its reverse lookup goes the same way and names the LAN, not one
  // of Docker's networks.
  dns.table.frontend = { v4: ['192.168.1.66'] };
  dns.ptr['192.168.1.50'] = ['siembox-backend.br0'];
  dns.ptr['192.168.1.66'] = ['frontend.lan'];
  await instance.start();
  instance.stop();
  assert.equal(instance.trust('192.168.1.66', 0), false);
  assert.equal(instance.trust('192.168.1.66', 2), false);
  const [entry] = instance.describe().entries;
  assert.deepEqual(entry.addresses, []);
  assert.deepEqual(entry.ignoredAnswers, ['192.168.1.66']);
  assert.ok(log.of('warn').some((m) => m.includes("ignored the answer 192.168.1.66 for frontend: Docker's DNS does not know it")));
  assert.ok(!log.of('info').some((m) => m.includes('frontend -> 192.168.1.66')));

  // No reverse name at all (NXDOMAIN): not trusted either.
  delete dns.ptr['192.168.1.66'];
  await instance.refresh();
  assert.equal(instance.trust('192.168.1.66', 0), false);

  // A container on that network that is called frontend is Docker's own answer: trusted.
  dns.table.frontend = { v4: ['192.168.1.67'] };
  dns.ptr['192.168.1.67'] = ['siembox-frontend.br0.'];
  await instance.refresh();
  assert.equal(instance.trust('192.168.1.67', 0), true);
  assert.ok(log.of('info').includes('TRUSTED_PROXIES: frontend -> 192.168.1.67'));
});

test('names: when Docker\'s DNS cannot be asked about an answer, only an answer it confirmed before is kept', async () => {
  const { instance, dns } = proxies('frontend');
  dns.table.frontend = { v4: ['172.18.0.3'] };
  await instance.start();
  instance.stop();
  assert.equal(instance.trust('172.18.0.3', 0), true);

  for (const ip of ['172.18.0.2', '172.18.0.3', '172.18.0.4']) dns.ptr[ip] = 'ETIMEOUT';
  dns.table.frontend = { v4: ['172.18.0.3', '172.18.0.4'] };
  await instance.refresh();
  assert.equal(instance.trust('172.18.0.3', 0), true, 'confirmed before: kept');
  assert.equal(instance.trust('172.18.0.4', 0), false, 'never confirmed: not trusted');

  // Before any confirmation, an answer that can't be checked is not trusted.
  const fresh = proxies('frontend');
  fresh.dns.table.frontend = { v4: ['172.18.0.3'] };
  fresh.dns.ptr['172.18.0.2'] = 'ETIMEOUT';
  await fresh.instance.start();
  fresh.instance.stop();
  assert.equal(fresh.instance.trust('172.18.0.3', 0), false);
});

test('IPv6 entries never match an IPv4 address, even ranges that contain ::ffff:0:0/96, and the reverse', () => {
  const { instance } = proxies('frontend,::1/64,::/80,2001:db8::/64');
  for (const hop of [0, 2]) {
    for (const ipv4 of ['198.51.100.7', '::ffff:198.51.100.7', '10.0.0.1', '0.0.0.1']) {
      assert.equal(instance.trust(ipv4, hop), false, `${ipv4} at hop ${hop}`);
    }
  }
  assert.equal(instance.trust('::1', 0), true);
  assert.equal(instance.trust('::abcd', 1), true, 'in ::/80');
  assert.equal(instance.trust('2001:db8::5', 0), true);

  const ipv4 = proxies('10.0.0.0/8,192.0.2.10');
  assert.equal(ipv4.instance.trust('10.1.2.3', 0), true);
  assert.equal(ipv4.instance.trust('::a01:203', 0), false, 'an IPv4-compatible IPv6 address is not 10.1.2.3');
  assert.equal(ipv4.instance.trust('64:ff9b::c000:20a', 0), false, 'nor is a NAT64 one');
});

test('names: NXDOMAIN clears the addresses, a timeout keeps the last good answer', async () => {
  const { instance, dns, log } = proxies('frontend');
  dns.table.frontend = { v4: ['172.18.0.3'] };
  await instance.start();
  instance.stop();
  assert.equal(instance.trust('172.18.0.3', 0), true);

  dns.table.frontend = { v4: 'ETIMEOUT', v6: 'ETIMEOUT' };
  await instance.refresh();
  assert.equal(instance.trust('172.18.0.3', 0), true, 'a timeout keeps the last answer');
  assert.equal(instance.describe().entries[0].status, 'error');

  delete dns.table.frontend; // NXDOMAIN
  await instance.refresh();
  assert.equal(instance.trust('172.18.0.3', 0), false, 'NXDOMAIN clears it');
  assert.equal(instance.describe().entries[0].status, 'not-found');
  assert.ok(log.of('info').some((m) => m.includes('frontend no longer resolves')));

  dns.table.frontend = { v4: ['172.18.0.9'] };
  await instance.refresh();
  assert.equal(instance.trust('172.18.0.9', 0), true, 'a new container address is picked up');
});

test('names are not looked up in the host namespace or outside a container', async () => {
  for (const options of [
    { hostNetworking: true },
    { interfaces: hostInterfaces },
    { inContainer: false },
  ] as Array<Partial<TrustedProxiesOptions>>) {
    const { instance, dns } = proxies('frontend', options);
    dns.table.frontend = { v4: ['172.18.0.3'] };
    await instance.start();
    await instance.refresh();
    instance.stop();
    assert.deepEqual(dns.calls, [], JSON.stringify(options));
    assert.equal(instance.trust('172.18.0.3', 0), false);
    const report = instance.describe();
    assert.equal(report.nameLookup.enabled, false);
    assert.ok(report.nameLookup.reason);
    assert.equal(report.entries[0].status, 'not-looked-up');
  }
});

test('start: waits at most about a second for a hanging lookup, and logs rejected entries and warnings', async () => {
  const { instance, log } = proxies('frontend,*,10.0.0.0/16', {
    resolver: {
      resolve4: () => new Promise<string[]>(() => {}),
      resolve6: () => new Promise<string[]>(() => {}),
      reverse: () => new Promise<string[]>(() => {}),
    },
  });
  const started = Date.now();
  await instance.start();
  instance.stop();
  const waited = Date.now() - started;
  assert.ok(waited >= 900 && waited < 3000, `waited ${waited} ms`);
  assert.deepEqual(log.of('error'), ['TRUSTED_PROXIES entry "*" ignored: it would trust every address, so any client could pick its own.']);
  assert.equal(log.of('warn').filter((m) => m.includes('wide range')).length, 1);
});

const SECOND = 1000;

test('ignored X-Forwarded-For: counted per untrusted TCP peer; a local peer warns once it has gone on for 45 s, then hourly', () => {
  let now = 1_000_000;
  const { instance, log } = proxies('192.0.2.10', { now: () => now });
  const warnings = () => log.of('warn').filter((m) => m.startsWith('Ignored X-Forwarded-For'));
  const peer = (address: string) => instance.describe().ignoredForwardedFor.peers.find((p) => p.address === address);

  instance.noteRequest(directRequest('::ffff:172.18.0.4', '203.0.113.5'));
  now += 30 * SECOND;
  instance.noteRequest(directRequest('172.18.0.4', '203.0.113.6'));
  assert.equal(warnings().length, 0, "within nginx's 30 s fallback window: not reported yet");
  assert.deepEqual(
    { ...peer('172.18.0.4'), firstSeen: undefined, lastSeen: undefined },
    { address: '172.18.0.4', kind: 'direct', requests: 2, local: true, sustained: false, firstSeen: undefined, lastSeen: undefined }
  );

  now += IGNORED_HEADER_GRACE_MS - 30 * SECOND + 1;
  instance.noteRequest(directRequest('172.18.0.4', '203.0.113.7'));
  assert.equal(warnings().length, 1);
  assert.match(warnings()[0], /^Ignored X-Forwarded-For from 172\.18\.0\.4 \(3 requests in 45 s\): it calls the API directly .*api-socket volume.*TRUSTED_PROXIES/);
  assert.equal(peer('172.18.0.4')?.sustained, true);

  // Still going: warned again an hour after the last warning, not before.
  const step = 10 * 60 * SECOND;
  for (let waited = step; waited <= IGNORED_HEADER_WARN_MS; waited += step) {
    now += step;
    instance.noteRequest(directRequest('172.18.0.4', '203.0.113.8'));
    assert.equal(warnings().length, waited < IGNORED_HEADER_WARN_MS ? 1 : 2, `after ${waited / step * 10} minutes`);
  }

  instance.noteRequest(directRequest('203.0.113.9', '1.2.3.4')); // remote: counted, never warned about
  now += 60 * SECOND;
  instance.noteRequest(directRequest('203.0.113.9', '1.2.3.4'));
  instance.noteRequest(directRequest('192.0.2.10', '1.2.3.4')); // trusted: its header is used
  instance.noteRequest(directRequest('172.18.0.5')); // no header
  instance.noteRequest(directRequest(PROXY_SOCKET_PEER, '1.2.3.4')); // the bundled nginx, one entry
  assert.equal(warnings().length, 2);
  const { peers, untracked } = instance.describe().ignoredForwardedFor;
  assert.deepEqual(
    peers.map((p) => [p.address, p.kind, p.requests, p.local, p.sustained]).sort(),
    [
      ['172.18.0.4', 'direct', 9, true, true],
      ['203.0.113.9', 'direct', 2, false, true],
    ]
  );
  assert.equal(untracked, 0);
});

test('ignored X-Forwarded-For: the fallback window after a backend restart is not reported, and a peer is forgotten after an hour', () => {
  let now = 5_000_000;
  // Host networking: the frontend container's TCP fallback can't be trusted by name.
  const { instance, log } = proxies(undefined, { now: () => now, hostNetworking: true });
  for (let i = 0; i <= 30; i++) {
    instance.noteRequest(directRequest('172.18.0.3', '192.168.1.50'));
    now += SECOND;
  }
  assert.equal(log.of('warn').filter((m) => m.startsWith('Ignored X-Forwarded-For')).length, 0);
  assert.equal(instance.describe().ignoredForwardedFor.peers[0].sustained, false);

  // A request that times out on the socket starts another fallback window, more than an hour later.
  now += IGNORED_PEER_TTL_MS;
  assert.deepEqual(instance.describe().ignoredForwardedFor.peers, [], 'forgotten after an hour');
  for (let i = 0; i <= 30; i++) {
    instance.noteRequest(directRequest('172.18.0.3', '192.168.1.50'));
    now += SECOND;
  }
  const [episode] = instance.describe().ignoredForwardedFor.peers;
  assert.equal(episode.requests, 31, 'counted afresh');
  assert.equal(episode.sustained, false);
  assert.equal(log.of('warn').filter((m) => m.startsWith('Ignored X-Forwarded-For')).length, 0);
});

test('ignored X-Forwarded-For: requests to GET /api/admin/client-address are not counted', () => {
  let now = 1_000_000;
  const { instance, log } = proxies('none', { now: () => now });
  for (const url of ['/api/admin/client-address', '/API/Admin/Client-Address/', '/api/admin/client-address?x=1']) {
    for (const method of ['GET', 'HEAD']) {
      instance.noteRequest(directRequest('192.168.1.50', '1.2.3.4', method, url));
      now += 60 * SECOND;
    }
  }
  assert.deepEqual(instance.describe().ignoredForwardedFor.peers, []);
  assert.equal(log.of('warn').length, 0);
  // Any other request from there still is.
  instance.noteRequest(directRequest('192.168.1.50', '1.2.3.4', 'POST', '/api/admin/client-address'));
  instance.noteRequest(directRequest('192.168.1.50', '1.2.3.4', 'GET', '/api/admin/jobs'));
  assert.equal(instance.describe().ignoredForwardedFor.peers[0].requests, 2);
});

test('ignored X-Forwarded-For: an untrusted proxy in front of the bundled nginx (or a trusted proxy) is counted as forwarded', () => {
  let now = 1_000_000;
  const { instance, log } = proxies('frontend,192.0.2.10', { now: () => now });
  const warnings = () => log.of('warn').filter((m) => m.startsWith('Ignored X-Forwarded-For'));

  // A reverse proxy at 192.168.1.20 in front of port 8420: nginx appends it to
  // the client it passed on.
  instance.noteRequest(directRequest(PROXY_SOCKET_PEER, '203.0.113.5, 192.168.1.20'));
  now += 50 * SECOND;
  instance.noteRequest(directRequest(PROXY_SOCKET_PEER, '203.0.113.6, 192.168.1.20'));
  assert.equal(warnings().length, 1);
  assert.match(warnings()[0], /^Ignored X-Forwarded-For from 192\.168\.1\.20 \(2 requests in 50 s\): it passes requests on to SIEMBox but is not a trusted proxy.*add it to TRUSTED_PROXIES/);

  // Behind a trusted proxy (192.0.2.10) as well, over the socket or straight over TCP.
  instance.noteRequest(directRequest(PROXY_SOCKET_PEER, '198.51.100.1, 10.9.9.9, 192.0.2.10'));
  instance.noteRequest(directRequest('192.0.2.10', '198.51.100.1, 10.9.9.9'));
  // Not counted: one entry (nginx's own client), a trusted chain down to the
  // client, and junk in place of the address.
  instance.noteRequest(directRequest(PROXY_SOCKET_PEER, '192.168.1.21'));
  instance.noteRequest(directRequest(PROXY_SOCKET_PEER, '203.0.113.7, 192.0.2.10'));
  instance.noteRequest(directRequest(PROXY_SOCKET_PEER, '203.0.113.7, not-an-ip'));
  const peers = instance.describe().ignoredForwardedFor.peers;
  assert.deepEqual(
    peers.map((p) => [p.address, p.kind, p.requests]).sort(),
    [
      ['10.9.9.9', 'forwarded', 2],
      ['192.168.1.20', 'forwarded', 2],
    ]
  );
  assert.equal(instance.untrustedForwarder('203.0.113.5, 192.168.1.20'), '192.168.1.20');
  assert.equal(instance.untrustedForwarder('203.0.113.5'), null);
  assert.equal(instance.untrustedForwarder(undefined), null);

  // The Docker gateway (a proxy on the Docker host pointed at 127.0.0.1) gets different advice.
  now += 60 * SECOND;
  instance.noteRequest(directRequest(PROXY_SOCKET_PEER, '203.0.113.5, 172.18.0.1'));
  now += 60 * SECOND;
  instance.noteRequest(directRequest(PROXY_SOCKET_PEER, '203.0.113.5, 172.18.0.1'));
  assert.match(warnings().at(-1)!, /from 172\.18\.0\.1 .*Docker network gateway.*port 8420 instead of 127\.0\.0\.1/);
});

test('ignored X-Forwarded-For: at most 100 peers, and a local peer displaces a remote one', () => {
  let now = 0;
  const { instance } = proxies('none', { now: () => ++now });
  for (let i = 0; i < MAX_TRACKED_PEERS; i++) {
    instance.noteRequest(directRequest(`203.0.${Math.floor(i / 250)}.${(i % 250) + 1}`, '1.1.1.1'));
  }
  instance.noteRequest(directRequest('198.51.100.1', '1.1.1.1')); // remote and full: not tracked
  let report = instance.describe().ignoredForwardedFor;
  assert.equal(report.peers.length, MAX_TRACKED_PEERS);
  assert.equal(report.untracked, 1);

  instance.noteRequest(directRequest('10.0.0.7', '1.1.1.1')); // local: displaces the oldest remote peer
  report = instance.describe().ignoredForwardedFor;
  assert.equal(report.peers.length, MAX_TRACKED_PEERS);
  assert.ok(report.peers.some((p) => p.address === '10.0.0.7'));
  assert.ok(!report.peers.some((p) => p.address === '203.0.0.1'), 'the least recently seen remote peer went');

  // A forgotten peer (not seen for an hour) makes room for anyone.
  now += IGNORED_PEER_TTL_MS + 1;
  instance.noteRequest(directRequest('198.51.100.2', '1.1.1.1'));
  report = instance.describe().ignoredForwardedFor;
  assert.deepEqual(report.peers.map((p) => p.address), ['198.51.100.2']);
});
