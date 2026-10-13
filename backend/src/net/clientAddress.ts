/**
 * Who sent a request: the client address every limiter, audit row and log line
 * uses.
 *
 * Express works it out from the TCP peer and X-Forwarded-For through the trust
 * function app.ts installs (`app.set('trust proxy', ...)`, see
 * trustedProxies.ts). Only two kinds of peer may speak for someone else:
 *
 * - The bundled nginx, on the proxy socket (apiListeners.ts). Every connection
 *   accepted there has its remoteAddress stamped with PROXY_SOCKET_PEER, which
 *   is not an IP address, so no TCP client can ever claim it. It is trusted for
 *   exactly one hop: req.ip becomes the rightmost X-Forwarded-For entry, which
 *   nginx sets to the address it saw ($remote_addr).
 * - The entries of TRUSTED_PROXIES, at any hop, so outer proxies can be
 *   chained in front of nginx.
 *
 * Everyone else is their TCP peer address: a shipper, an agent or a script
 * calling :8421 directly cannot pick its address with X-Forwarded-For or
 * X-Real-IP.
 */
import net from 'node:net';
import type { Request } from 'express';

/** The remoteAddress of every connection accepted on the proxy socket. Never a valid IP. */
export const PROXY_SOCKET_PEER = 'unix:proxy-socket';

/** How a request reached the API, for diagnostics and audit details. */
export type RequestVia = 'proxy-socket' | 'trusted-proxy' | 'direct';

const MAPPED_IPV4 = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/;

/**
 * An address in one canonical form, or null when `value` is not an IP address:
 * trimmed, without an IPv6 zone ('fe80::1%eth0'), IPv4-mapped IPv6
 * ('::ffff:192.0.2.1', as a dual-stack listener reports IPv4 peers) turned into
 * plain IPv4, and other IPv6 addresses lower-cased and compressed. Two spellings
 * of one address therefore always give one limiter key.
 */
export function normalizeIp(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  let ip = value.trim();
  const zone = ip.indexOf('%');
  if (zone !== -1) ip = ip.slice(0, zone);
  const family = net.isIP(ip);
  if (family === 4) return ip;
  if (family !== 6) return null;
  try {
    // The WHATWG URL parser canonicalizes IPv6 hosts (RFC 5952 style).
    ip = new URL(`http://[${ip}]/`).hostname.slice(1, -1);
  } catch {
    ip = ip.toLowerCase();
  }
  const mapped = MAPPED_IPV4.exec(ip);
  if (mapped) {
    const high = parseInt(mapped[1], 16);
    const low = parseInt(mapped[2], 16);
    return `${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`;
  }
  return ip;
}

/**
 * The client's address, or null when there is none to give.
 *
 * Normally req.ip. That is only ever something other than an address when a
 * trusted proxy forwarded junk (an untrusted peer's X-Forwarded-For is never
 * read): then the request is put on the nearest proxy that has a valid address,
 * and on the TCP peer after that. A request on the proxy socket without any
 * X-Forwarded-For (nginx always sends one) has no address at all.
 */
export function clientAddress(req: Request): string | null {
  const ip = normalizeIp(req.ip);
  if (ip) return ip;
  const hops = req.ips ?? [];
  for (let i = 1; i < hops.length; i++) {
    const hop = normalizeIp(hops[i]);
    if (hop) return hop;
  }
  return normalizeIp(req.socket?.remoteAddress);
}

/**
 * 'proxy-socket' for the bundled nginx, 'trusted-proxy' when a TRUSTED_PROXIES
 * peer supplied the address through X-Forwarded-For, 'direct' otherwise.
 */
export function requestVia(req: Request): RequestVia {
  const peer = req.socket?.remoteAddress;
  if (peer === PROXY_SOCKET_PEER) return 'proxy-socket';
  const address = clientAddress(req);
  const peerAddress = normalizeIp(peer);
  return address !== null && peerAddress !== null && address !== peerAddress ? 'trusted-proxy' : 'direct';
}

/** The eight 16-bit groups of a valid IPv6 address. */
function ipv6Groups(ip: string): number[] {
  let text = ip;
  const dotted = /(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(text);
  if (dotted) {
    const [a, b, c, d] = dotted.slice(1).map(Number);
    text = `${text.slice(0, dotted.index)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const [head, tail] = text.split('::');
  const left = head ? head.split(':') : [];
  const right = tail === undefined ? [] : tail ? tail.split(':') : [];
  const fill = tail === undefined ? [] : new Array<string>(8 - left.length - right.length).fill('0');
  return [...left, ...fill, ...right].map((group) => parseInt(group, 16));
}

/**
 * The key sign-in limits count against: an IPv4 address as it is, an IPv6
 * address as its /64 ('2001:db8:1:2::/64'), because one IPv6 host normally has
 * the whole /64 to pick addresses from; 'unknown' when there is no address.
 * Request limiters use the full address instead (requestLimits.ts).
 */
export function signInNetworkKey(ip: string | null): string {
  const address = normalizeIp(ip);
  if (!address) return 'unknown';
  if (net.isIP(address) === 4) return address;
  const groups = ipv6Groups(address).slice(0, 4);
  const prefix = normalizeIp(`${groups.map((group) => group.toString(16)).join(':')}::`);
  return `${prefix}/64`;
}
