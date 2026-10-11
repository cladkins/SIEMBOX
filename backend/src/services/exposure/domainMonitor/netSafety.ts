/**
 * SSRF guards for outbound requests whose HOST comes from external data (the
 * RDAP server a registry publishes in IANA's bootstrap file).
 *
 * A host is acceptable only when its name is not an internal-only name and
 * EVERY address it resolves to is a public, globally routable unicast address.
 * The same check runs again inside the HTTP client's connect-time lookup
 * (http.ts), so the addresses that were vetted are exactly the ones the socket
 * connects to — a DNS answer that changes between the check and the
 * connection (rebinding) cannot slip a private address through.
 */
import dns from 'dns';
import { isIP } from 'net';

export interface ResolvedAddress {
  address: string;
  family: number;
}

/** Resolves a hostname to all of its addresses (the OS resolver by default). */
export type LookupAllFn = (hostname: string) => Promise<ResolvedAddress[]>;

export const systemLookupAll: LookupAllFn = (hostname) =>
  dns.promises.lookup(hostname, { all: true, verbatim: true });

/**
 * Raised when a target is refused; `code` lets the HTTP layer recognise it.
 * `retryable` marks a refusal only because the name could not be resolved
 * right now (a DNS hiccup), as opposed to one the rules forbid.
 */
export class UnsafeTargetError extends Error {
  readonly code = 'ERR_UNSAFE_TARGET';
  readonly retryable: boolean;

  constructor(message: string, retryable = false) {
    super(message);
    this.name = 'UnsafeTargetError';
    this.retryable = retryable;
  }
}

// ---- IPv4 ----------------------------------------------------------------------

// Everything that is not globally routable unicast (RFC 6890 and friends).
const BLOCKED_V4: ReadonlyArray<readonly [string, number]> = [
  ['0.0.0.0', 8], // "this network"
  ['10.0.0.0', 8], // private
  ['100.64.0.0', 10], // carrier-grade NAT
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local (cloud metadata lives here)
  ['172.16.0.0', 12], // private
  ['192.0.0.0', 24], // IETF protocol assignments
  ['192.0.2.0', 24], // TEST-NET-1
  ['192.88.99.0', 24], // deprecated 6to4 relay anycast
  ['192.168.0.0', 16], // private
  ['198.18.0.0', 15], // benchmarking
  ['198.51.100.0', 24], // TEST-NET-2
  ['203.0.113.0', 24], // TEST-NET-3
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved, incl. broadcast
];

function ipv4ToNumber(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    n = n * 256 + octet;
  }
  return n;
}

const BLOCKED_V4_NUMERIC = BLOCKED_V4.map(([base, bits]) => {
  const size = 2 ** (32 - bits);
  const start = ipv4ToNumber(base) as number;
  return { start, end: start + size - 1 };
});

function isPublicIPv4Number(n: number): boolean {
  return !BLOCKED_V4_NUMERIC.some(({ start, end }) => n >= start && n <= end);
}

export function isPublicIPv4(ip: string): boolean {
  const n = ipv4ToNumber(ip);
  return n !== null && isPublicIPv4Number(n);
}

// ---- IPv6 ----------------------------------------------------------------------

/** The eight 16-bit groups of an IPv6 address, or null if it isn't one. */
export function ipv6Groups(ip: string): number[] | null {
  if (ip.includes('%') || isIP(ip) !== 6) return null; // zone ids are link-local anyway
  let host: string;
  try {
    // The WHATWG URL parser canonicalises IPv6 (lowercase hex, an embedded
    // dotted IPv4 tail rewritten as two hex groups), which leaves only "::" to expand.
    host = new URL(`http://[${ip}]/`).hostname.slice(1, -1);
  } catch {
    return null;
  }
  const halves = host.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  const groups = [...head, ...Array<string>(fill).fill('0'), ...tail];
  if (groups.length !== 8) return null;
  return groups.map((g) => parseInt(g, 16));
}

const embeddedV4 = (high: number, low: number) => high * 65536 + low;

export function isPublicIPv6(ip: string): boolean {
  const g = ipv6Groups(ip);
  if (!g) return false;
  // NAT64 well-known prefix 64:ff9b::/96 (DNS64 networks): judge the IPv4 inside.
  if (g[0] === 0x64 && g[1] === 0xff9b && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0) {
    return isPublicIPv4Number(embeddedV4(g[6], g[7]));
  }
  // Only global unicast (2000::/3) is reachable on the internet. This also
  // rules out ::, ::1, IPv4-mapped/compatible, ULA fc00::/7, link-local
  // fe80::/10, multicast ff00::/8, discard 100::/64 and NAT64 local-use.
  if ((g[0] & 0xe000) !== 0x2000) return false;
  if (g[0] === 0x2001 && g[1] < 0x0200) return false; // 2001::/23 special purpose (Teredo, ORCHID, ...)
  if (g[0] === 0x2001 && g[1] === 0x0db8) return false; // documentation
  if (g[0] === 0x3fff && g[1] < 0x1000) return false; // 3fff::/20 documentation (RFC 9637)
  if (g[0] === 0x2002) return isPublicIPv4Number(embeddedV4(g[1], g[2])); // 6to4 embeds an IPv4
  return true;
}

/** True for a globally routable unicast IPv4 or IPv6 address. */
export function isPublicAddress(ip: string): boolean {
  const family = isIP(ip);
  if (family === 4) return isPublicIPv4(ip);
  if (family === 6) return isPublicIPv6(ip);
  return false;
}

// ---- Host names ------------------------------------------------------------------

// Names that only ever resolve inside a network (or nowhere): RFC 6761/6762,
// RFC 8375, ICANN's .internal, and common private-network conventions.
const INTERNAL_SUFFIXES = [
  'localhost',
  'local',
  'internal',
  'lan',
  'home',
  'home.arpa',
  'localdomain',
  'intranet',
  'corp',
  'private',
  'test',
  'invalid',
  'example',
  'onion',
  'arpa',
];

/**
 * Why a host name must not be contacted, or null when it is acceptable. IP
 * literals are refused outright: a registry publishes names, and an IP would
 * skip the name checks.
 */
export function hostnameRejection(hostname: string): string | null {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  const bare = host.replace(/^\[(.*)\]$/, '$1');
  if (!host) return 'empty host';
  if (isIP(bare) !== 0) return 'IP-address hosts are not allowed';
  if (!host.includes('.')) return 'single-label host names are not allowed';
  if (!/^[a-z0-9.-]+$/.test(host)) return 'host name has invalid characters';
  for (const suffix of INTERNAL_SUFFIXES) {
    if (host === suffix || host.endsWith(`.${suffix}`))
      return `".${suffix}" names are internal-only`;
  }
  if (/^\d+$/.test(host.split('.').pop() ?? '')) return 'numeric top-level domain';
  return null;
}

/**
 * Resolve `hostname` and return its addresses only if EVERY one is public.
 * A name that resolves to any private address is refused entirely: a server
 * with one public and one internal address is not a server we want to reach.
 */
export async function resolvePublicAddresses(
  hostname: string,
  lookup: LookupAllFn = systemLookupAll
): Promise<ResolvedAddress[]> {
  const rejection = hostnameRejection(hostname);
  if (rejection) throw new UnsafeTargetError(`refusing ${hostname}: ${rejection}`);
  let addresses: ResolvedAddress[];
  try {
    addresses = await lookup(hostname);
  } catch (err) {
    const code = (err as { code?: unknown } | null)?.code;
    throw new UnsafeTargetError(
      `could not resolve ${hostname}${typeof code === 'string' ? ` (${code})` : ''}`,
      true
    );
  }
  if (!Array.isArray(addresses) || addresses.length === 0) {
    throw new UnsafeTargetError(`${hostname} has no addresses`, true);
  }
  const blocked = addresses.find((a) => !isPublicAddress(a.address));
  if (blocked) {
    throw new UnsafeTargetError(
      `refusing ${hostname}: it resolves to a non-public address (${blocked.address})`
    );
  }
  return addresses.map((a) => ({ address: a.address, family: a.family === 6 ? 6 : 4 }));
}
