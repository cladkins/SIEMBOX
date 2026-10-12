/**
 * The startup line and the GET /api/admin/client-address report for the usual
 * deployments. Hermetic: TrustedProxies gets fixture interfaces, routes and DNS.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { Request } from 'express';
import { PROXY_SOCKET_PEER } from './clientAddress';
import { clientAddressReport, clientAddressSummary } from './diagnostics';
import { TrustedProxies, type InterfaceTable, type TrustedProxiesOptions } from './trustedProxies';

const quiet = { info: () => undefined, warn: () => undefined, error: () => undefined };
const ROUTE_TABLE = 'Iface\tDestination\tGateway\nEth0\t00000000\t010012AC\n';
const bridge = (): InterfaceTable => ({
  eth0: [{ address: '172.18.0.2', family: 'IPv4', internal: false, cidr: '172.18.0.2/16' }],
});
const SOCKET = { state: 'listening', path: '/run/siembox/api.sock' } as const;
const NO_VOLUME = { state: 'no-volume', path: '/run/siembox/api.sock', directory: '/run/siembox' } as const;
const notFound = (code: string) => Promise.reject(Object.assign(new Error(code), { code }));

async function started(spec: string | undefined, options: Partial<TrustedProxiesOptions> = {}) {
  const proxies = new TrustedProxies({
    spec,
    inContainer: true,
    hostNetworking: false,
    interfaces: bridge,
    readFile: (path) => (path === '/proc/net/route' ? ROUTE_TABLE : null),
    resolver: {
      resolve4: async (name) => (name === 'frontend' ? ['172.18.0.3'] : notFound('ENOTFOUND')),
      resolve6: async () => notFound('ENODATA'),
      // Docker's DNS names the containers on the bridge network <container>.<network>.
      reverse: async (ip) => (ip.startsWith('172.18.') ? [`c-${ip.replace(/\./g, '-')}.siembox_net`] : notFound('ENOTFOUND')),
    },
    log: quiet,
    ...options,
  });
  await proxies.start();
  proxies.stop();
  return proxies;
}

/** A request as Express sees it (`ip` and `ips` worked out by the trust function). */
function request(
  peer: string,
  ip: string,
  forwardedFor?: string,
  ips: string[] = [],
  url = '/api/admin/client-address'
): Request {
  return {
    method: 'GET',
    originalUrl: url,
    url,
    ip,
    ips,
    socket: { remoteAddress: peer },
    headers: forwardedFor === undefined ? {} : { 'x-forwarded-for': forwardedFor },
  } as unknown as Request;
}

test('startup line: default bridge deployment, old compose file, host networking, none', async () => {
  const bridged = await started(undefined);
  assert.equal(
    clientAddressSummary(8421, SOCKET, bridged),
    'Client addresses: proxy socket /run/siembox/api.sock (listening); X-Forwarded-For trusted from frontend -> 172.18.0.3; ' +
      'direct callers on :8421 use their TCP address.'
  );
  assert.match(clientAddressSummary(8421, NO_VOLUME, bridged), /no proxy socket \(\/run\/siembox missing/);

  const host = await started(undefined, { hostNetworking: true });
  assert.match(clientAddressSummary('8421', SOCKET, host), /frontend -> not looked up: host networking/);

  const none = await started('none');
  assert.match(clientAddressSummary(8421, { state: 'off' }, none), /proxy socket off .*trusted from no TCP peer/);
});

test('report: the web UI over the socket, no warnings', async () => {
  const report = clientAddressReport(
    request(PROXY_SOCKET_PEER, '192.168.1.50', '192.168.1.50', ['192.168.1.50']),
    await started(undefined),
    SOCKET
  );
  assert.deepEqual(report.you, {
    address: '192.168.1.50',
    via: 'proxy-socket',
    peer: 'proxy socket',
    forwardedFor: '192.168.1.50',
    rateLimitKey: '192.168.1.50',
    signInKey: '192.168.1.50',
  });
  assert.deepEqual(report.proxySocket, SOCKET);
  assert.deepEqual(report.gateways, ['172.18.0.1']);
  assert.deepEqual(report.warnings, []);
});

test('report: a direct call with a forged X-Forwarded-For says it was ignored, without counting the caller as a proxy', async () => {
  let now = 1_000_000;
  const proxies = await started(undefined, { now: () => now });
  // DEPLOYMENT.md's check, run twice a minute apart from the admin's workstation.
  for (let i = 0; i < 2; i++) {
    const req = request('::ffff:192.168.1.60', '::ffff:192.168.1.60', '1.2.3.4');
    proxies.noteRequest(req);
    const report = clientAddressReport(req, proxies, SOCKET);
    assert.equal(report.you.address, '192.168.1.60');
    assert.equal(report.you.via, 'direct');
    assert.equal(report.you.forwardedFor, '1.2.3.4');
    assert.deepEqual(report.warnings, [
      'This request carried X-Forwarded-For but came straight from 192.168.1.60, which is not a trusted proxy, so the header was ignored.',
    ]);
    assert.deepEqual(report.ignoredForwardedFor.peers, [], 'the workstation is not taken for a proxy to trust');
    now += 60_000;
  }
});

test('report: a local proxy whose header keeps being ignored for more than 45 s is a warning; a short burst is not', async () => {
  let now = 1_000_000;
  const proxies = await started(undefined, { now: () => now, hostNetworking: true });
  const report = () => clientAddressReport(request(PROXY_SOCKET_PEER, '192.168.1.50', '192.168.1.50', ['192.168.1.50']), proxies, SOCKET);
  // Host networking: nginx's TCP fallback for 30 s after a backend restart.
  for (let i = 0; i < 30; i++) {
    proxies.noteRequest(request('172.18.0.3', '172.18.0.3', '192.168.1.50', [], '/api/alerts'));
    now += 1000;
  }
  assert.deepEqual(report().warnings, []);
  assert.equal(report().ignoredForwardedFor.peers[0].sustained, false);

  now += 20_000;
  proxies.noteRequest(request('172.18.0.3', '172.18.0.3', '192.168.1.50', [], '/api/alerts'));
  const [warning] = report().warnings;
  assert.match(warning, /^X-Forwarded-For from 172\.18\.0\.3 has been ignored on 31 requests since .*: it calls the API directly .*update your compose file/);
});

test('report: a request through a reverse proxy SIEMBox does not trust says so, and so does the tracker', async () => {
  let now = 1_000_000;
  const proxies = await started(undefined, { now: () => now });
  // nginx appended the proxy (192.168.1.20) to the client the proxy passed on.
  const viaProxy = () =>
    request(PROXY_SOCKET_PEER, '192.168.1.20', '198.51.100.7, 192.168.1.20', ['192.168.1.20'], '/api/alerts');
  proxies.noteRequest(viaProxy());
  now += 60_000;
  proxies.noteRequest(viaProxy());
  const report = clientAddressReport(
    request(PROXY_SOCKET_PEER, '192.168.1.20', '198.51.100.7, 192.168.1.20', ['192.168.1.20']),
    proxies,
    SOCKET
  );
  assert.equal(report.you.address, '192.168.1.20');
  assert.equal(report.you.via, 'proxy-socket');
  const text = report.warnings.join('\n');
  assert.match(text, /This request reached SIEMBox through 192\.168\.1\.20, which sent X-Forwarded-For of its own/);
  assert.match(text, /X-Forwarded-For from 192\.168\.1\.20 has been ignored on 2 requests .*add it to TRUSTED_PROXIES/);
  assert.deepEqual(
    report.ignoredForwardedFor.peers.map((p) => [p.address, p.kind, p.sustained]),
    [['192.168.1.20', 'forwarded', true]]
  );

  // Listed in TRUSTED_PROXIES: the client behind it is the address, and nothing is reported.
  const trusted = await started('frontend,192.168.1.20');
  const fixed = clientAddressReport(
    request(PROXY_SOCKET_PEER, '198.51.100.7', '198.51.100.7, 192.168.1.20', ['198.51.100.7', '192.168.1.20']),
    trusted,
    SOCKET
  );
  assert.deepEqual(fixed.warnings, []);
});

test('report: host networking with an old compose file explains the shared address', async () => {
  const report = clientAddressReport(request('172.18.0.3', '172.18.0.3', '192.168.1.50'), await started(undefined, { hostNetworking: true }), NO_VOLUME);
  const text = report.warnings.join('\n');
  assert.match(text, /api-socket volume is not mounted/);
  assert.match(text, /every web UI user then shares its address/);
  assert.match(text, /frontend is not used \(host networking/);
});

test('report: an old compose file in bridge mode still works through the frontend name', async () => {
  const report = clientAddressReport(
    request('172.18.0.3', '192.168.1.50', '192.168.1.50', ['192.168.1.50']),
    await started(undefined),
    NO_VOLUME
  );
  assert.equal(report.you.via, 'trusted-proxy');
  assert.equal(report.you.address, '192.168.1.50');
  assert.match(report.warnings.join('\n'), /still work because TRUSTED_PROXIES trusts frontend \(172\.18\.0\.3\)/);
});

test('report: rejected entries, unresolved names and the gateway as a client address', async () => {
  const report = clientAddressReport(request('172.18.0.1', '172.18.0.1'), await started('frontend,traefik,*'), SOCKET);
  const text = report.warnings.join('\n');
  assert.match(text, /entry "\*" is ignored: it would trust every address/);
  assert.match(text, /entry traefik does not resolve/);
  assert.match(text, /Your address 172\.18\.0\.1 is the Docker network gateway/);
});
