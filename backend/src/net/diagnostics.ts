/**
 * How the API is working out client addresses, in words: the startup log line
 * and GET /api/admin/client-address, which shows an admin what the API sees
 * for their own request and what is misconfigured.
 */
import type { Request } from 'express';
import { proxySocketState, type ProxySocketState } from './apiListeners';
import { clientAddress, normalizeIp, PROXY_SOCKET_PEER, requestVia, signInNetworkKey } from './clientAddress';
import { requestLimitKey } from './requestLimits';
import { trustedProxies, type TrustedProxies, type TrustedProxiesReport } from './trustedProxies';

/** Longest X-Forwarded-For echoed back. */
const MAX_HEADER_ECHO = 512;

type NameReport = TrustedProxiesReport['entries'][number];

function nameState(entry: NameReport, report: TrustedProxiesReport): string {
  if (entry.addresses && entry.addresses.length > 0) return entry.addresses.join(', ');
  if (!report.nameLookup.enabled) return `not looked up: ${report.nameLookup.reason}`;
  if (entry.status === 'error') return `lookup failed: ${entry.error ?? 'unknown error'}`;
  if (entry.status === 'pending') return 'not looked up yet';
  return 'no address on this network';
}

function socketSummary(socket: ProxySocketState): string {
  switch (socket.state) {
    case 'listening':
      return `proxy socket ${socket.path} (listening)`;
    case 'off':
      return 'proxy socket off (SIEMBOX_PROXY_SOCKET=off)';
    case 'no-volume':
      return `no proxy socket (${socket.directory} missing: the api-socket volume is not mounted)`;
    case 'error':
      return `proxy socket ${socket.path} failed (${socket.error})`;
    default:
      return 'proxy socket not started';
  }
}

/**
 * One line for the startup log, e.g. "Client addresses: proxy socket
 * /run/siembox/api.sock (listening); X-Forwarded-For trusted from frontend ->
 * 172.18.0.3; direct callers on :8421 use their TCP address."
 */
export function clientAddressSummary(
  port: string | number,
  socket: ProxySocketState = proxySocketState(),
  proxies: TrustedProxies = trustedProxies
): string {
  const report = proxies.describe();
  const trusted =
    report.entries.length === 0
      ? 'X-Forwarded-For trusted from no TCP peer (TRUSTED_PROXIES=none)'
      : `X-Forwarded-For trusted from ${report.entries
          .map((entry) => (entry.kind === 'name' ? `${entry.entry} -> ${nameState(entry, report)}` : entry.entry))
          .join(', ')}`;
  return `Client addresses: ${socketSummary(socket)}; ${trusted}; direct callers on :${port} use their TCP address.`;
}

/** Everything an admin needs to check their topology, for GET /api/admin/client-address. */
export function clientAddressReport(
  req: Request,
  proxies: TrustedProxies = trustedProxies,
  socket: ProxySocketState = proxySocketState()
) {
  const report = proxies.describe();
  const rawPeer = req.socket?.remoteAddress;
  const header = req.headers['x-forwarded-for'];
  const forwardedFor =
    header === undefined ? null : (Array.isArray(header) ? header.join(', ') : header).slice(0, MAX_HEADER_ECHO);
  const address = clientAddress(req);
  const via = requestVia(req);
  const peer = rawPeer === PROXY_SOCKET_PEER ? 'proxy socket' : (normalizeIp(rawPeer) ?? rawPeer ?? null);

  const warnings: string[] = [];
  if (socket.state === 'no-volume' || socket.state === 'error') {
    const frontend = report.entries.find(
      (entry) => entry.kind === 'name' && entry.entry.toLowerCase() === 'frontend' && (entry.addresses?.length ?? 0) > 0
    );
    warnings.push(
      (socket.state === 'no-volume'
        ? `The api-socket volume is not mounted (${socket.directory} does not exist), so the web UI reaches the API over TCP.`
        : `The proxy socket could not be opened (${socket.error}), so the web UI reaches the API over TCP.`) +
        (frontend
          ? ` Client addresses still work because TRUSTED_PROXIES trusts frontend (${frontend.addresses!.join(', ')}).`
          : ' Unless TRUSTED_PROXIES lists the frontend, every web UI user then shares its address.') +
        ' Update your compose file (DEPLOYMENT.md, "Updating").'
    );
  }
  for (const { entry, reason } of report.rejected) {
    warnings.push(`TRUSTED_PROXIES entry "${entry}" is ignored: ${reason}.`);
  }
  for (const entry of report.entries) {
    if (entry.kind !== 'name' || (entry.addresses?.length ?? 0) > 0) continue;
    // The default `frontend` entry is only a fallback while the socket works.
    if (entry.entry.toLowerCase() === 'frontend' && socket.state === 'listening') continue;
    if (!report.nameLookup.enabled) {
      warnings.push(`TRUSTED_PROXIES entry ${entry.entry} is not used (${report.nameLookup.reason}).`);
    } else if (entry.status === 'not-found' || entry.status === 'error') {
      warnings.push(
        `TRUSTED_PROXIES entry ${entry.entry} does not resolve to an address on this container's networks` +
          (entry.error ? ` (${entry.error})` : '') +
          '.'
      );
    }
  }
  warnings.push(...report.warnings);
  for (const ignored of report.ignoredForwardedFor.peers) {
    if (!ignored.local) continue;
    warnings.push(
      `X-Forwarded-For from ${ignored.address} has been ignored on ${ignored.requests} request(s): it is not a ` +
        'trusted proxy, so every client behind it shares that address. If it is the SIEMBox frontend, update your ' +
        'compose file (api-socket volume); if it is your own reverse proxy, add it to TRUSTED_PROXIES.'
    );
  }
  if (via === 'direct' && forwardedFor !== null) {
    warnings.push(
      `This request carried X-Forwarded-For but came straight from ${peer}, which is not a trusted proxy, so the header was ignored.`
    );
  }
  if (address && proxies.isGateway(address)) {
    warnings.push(
      `Your address ${address} is the Docker network gateway: Docker presents IPv6 and loopback clients of published ` +
        'ports this way, so they all share it. Reach SIEMBox on the host\'s IPv4 LAN address instead (DEPLOYMENT.md).'
    );
  }

  return {
    you: {
      address,
      via,
      peer,
      forwardedFor,
      rateLimitKey: requestLimitKey(req),
      signInKey: signInNetworkKey(address),
    },
    proxySocket: socket,
    trustedProxies: {
      configured: report.configured,
      entries: report.entries,
      rejected: report.rejected,
      nameLookup: report.nameLookup,
    },
    hostNetworking: report.hostNetworking,
    gateways: report.gateways,
    ownNetworks: report.ownNetworks,
    ignoredForwardedFor: report.ignoredForwardedFor,
    warnings,
  };
}
