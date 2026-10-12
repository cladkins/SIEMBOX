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

async function started(spec: string | undefined, options: Partial<TrustedProxiesOptions> = {}) {
  const proxies = new TrustedProxies({
    spec,
    inContainer: true,
    hostNetworking: false,
    interfaces: bridge,
    readFile: (path) => (path === '/proc/net/route' ? ROUTE_TABLE : null),
    resolver: {
      resolve4: async (name) => (name === 'frontend' ? ['172.18.0.3'] : Promise.reject(Object.assign(new Error(), { code: 'ENOTFOUND' }))),
      resolve6: async () => Promise.reject(Object.assign(new Error(), { code: 'ENODATA' })),
    },
    log: quiet,
    ...options,
  });
  await proxies.start();
  proxies.stop();
  return proxies;
}

function request(peer: string, ip: string, forwardedFor?: string, ips: string[] = []): Request {
  return {
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

test('report: a direct call with a forged X-Forwarded-For says it was ignored', async () => {
  const proxies = await started(undefined);
  const req = request('::ffff:192.168.1.60', '::ffff:192.168.1.60', '1.2.3.4');
  proxies.noteRequest(req);
  const report = clientAddressReport(req, proxies, SOCKET);
  assert.equal(report.you.address, '192.168.1.60');
  assert.equal(report.you.via, 'direct');
  assert.equal(report.you.forwardedFor, '1.2.3.4');
  assert.match(report.warnings.join('\n'), /came straight from 192\.168\.1\.60, which is not a trusted proxy/);
  assert.match(report.warnings.join('\n'), /X-Forwarded-For from 192\.168\.1\.60 has been ignored on 1 request/);
  assert.deepEqual(report.ignoredForwardedFor.peers.map((p) => p.address), ['192.168.1.60']);
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
