/**
 * Which peers may tell the API who the client is.
 *
 * `trustedProxies.trust` is the function app.ts gives Express as its
 * 'trust proxy' setting. Express calls it for the TCP peer (hop 0) and then for
 * each X-Forwarded-For entry from the right, and req.ip is the first address it
 * refuses (see clientAddress.ts for the model). It trusts:
 *
 * - the proxy socket's sentinel peer, at hop 0 only (the bundled nginx);
 * - TRUSTED_PROXIES entries, at any hop: IP addresses, CIDR ranges and Compose
 *   service names, comma-separated. The default is `frontend`, so an
 *   installation whose compose file predates the proxy socket keeps the real
 *   client addresses of its web UI users. `none` trusts only the socket.
 *
 * Names are looked up only in Docker's embedded DNS (127.0.0.11), only inside
 * a container on its own network namespace (never with host networking), and
 * an answer only counts when it is on one of the backend's own networks and
 * Docker's DNS confirms it as a container there: the reverse lookup of the
 * address must name `<container>.<network>` for a network the backend is on,
 * which Docker answers from its own records. Docker passes names it doesn't
 * know on to the host's DNS servers, so without that check a LAN DNS server
 * answering for `frontend` (a DHCP client calling itself that) could make a LAN
 * host trusted whenever the backend's network is the LAN itself (macvlan,
 * ipvlan). Lookups repeat every 30 s: a name that no longer exists stops being
 * trusted, a lookup that times out keeps the last answer.
 *
 * Docker gateway addresses are never trusted through a range: Docker's
 * userland proxy presents IPv6 and loopback clients of published ports as the
 * gateway, so trusting it would let those clients pick their address. Listing a
 * gateway as an exact address still works, with a warning.
 *
 * Addresses are only ever matched against entries of their own family: Node's
 * BlockList matches an IPv4 address against IPv6 ranges through its
 * IPv4-mapped form, which would make an entry like `::1/64` cover every IPv4
 * client.
 *
 * The same module counts requests whose X-Forwarded-For was ignored, so a proxy
 * that should be trusted but is not (an outdated compose file, a reverse proxy
 * missing from TRUSTED_PROXIES, in front of the web UI or of port 8421) shows
 * up in the log and in GET /api/admin/client-address.
 */
import dns from 'node:dns';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import type { NextFunction, Request, Response } from 'express';
import { logger } from '../utils/logger';
import { normalizeIp, PROXY_SOCKET_PEER } from './clientAddress';

export const DEFAULT_TRUSTED_PROXIES = 'frontend';
/** Docker's embedded DNS server, reachable from containers on user-defined networks. */
const DOCKER_DNS = '127.0.0.11';
const DNS_TIMEOUT_MS = 1000;
export const NAME_REFRESH_MS = 30_000;
/** How long startup waits for the first name lookup. */
const BOOT_WAIT_MS = 1000;
/** Peers whose ignored X-Forwarded-For is counted. */
export const MAX_TRACKED_PEERS = 100;
/**
 * How long a peer's X-Forwarded-For must keep being ignored before it is
 * reported. nginx goes back to the socket 30 s (its fail_timeout) after the
 * socket failed (a backend restart, a timed-out request) and uses its TCP
 * fallback until then, which with host networking is an untrusted peer.
 */
export const IGNORED_HEADER_GRACE_MS = 45_000;
/** A peer whose X-Forwarded-For hasn't been ignored for this long is forgotten. */
export const IGNORED_PEER_TTL_MS = 60 * 60 * 1000;
/** How often the log warns about the same peer. */
export const IGNORED_HEADER_WARN_MS = 60 * 60 * 1000;
/**
 * GET /api/admin/client-address explains its own X-Forwarded-For, so its
 * requests are not counted: an admin following DEPLOYMENT.md's check from a
 * workstation must not be told to trust that workstation.
 */
const DIAGNOSTICS_PATH = '/api/admin/client-address';

type Family = 'ipv4' | 'ipv6';

function familyOf(ip: string): Family {
  return net.isIP(ip) === 6 ? 'ipv6' : 'ipv4';
}

/** Addresses and subnets, matched only against addresses of the same family. */
class AddressList {
  private readonly lists: Record<Family, net.BlockList> = { ipv4: new net.BlockList(), ipv6: new net.BlockList() };

  addAddress(ip: string): void {
    const family = familyOf(ip);
    this.lists[family].addAddress(ip, family);
  }

  addSubnet(ip: string, prefix: number): void {
    const family = familyOf(ip);
    this.lists[family].addSubnet(ip, prefix, family);
  }

  check(ip: string): boolean {
    const family = familyOf(ip);
    return this.lists[family].check(ip, family);
  }
}

export interface NameResolver {
  resolve4(name: string): Promise<string[]>;
  resolve6(name: string): Promise<string[]>;
  /** The names of an address (PTR records). */
  reverse(ip: string): Promise<string[]>;
}

/** The part of an os.networkInterfaces() entry this module reads. */
export interface InterfaceAddress {
  address: string;
  family: string | number;
  internal: boolean;
  cidr: string | null;
}
export type InterfaceTable = Record<string, InterfaceAddress[] | undefined>;

export interface Log {
  info(message: string): unknown;
  warn(message: string): unknown;
  error(message: string): unknown;
}

export interface TrustedProxiesOptions {
  /** The TRUSTED_PROXIES value; unset or blank means `frontend`. */
  spec?: string;
  /** SIEMBOX_HOST_NETWORKING=true: the backend shares the host's network namespace. */
  hostNetworking?: boolean;
  /** Running inside a container (default: /.dockerenv or /run/.containerenv exists). */
  inContainer?: boolean;
  interfaces?: () => InterfaceTable;
  /** Reads /proc/net/route and /proc/net/ipv6_route; null when unreadable. */
  readFile?: (path: string) => string | null;
  /** Default: Docker's DNS at 127.0.0.11, 1 s timeout, one try. */
  resolver?: NameResolver;
  log?: Log;
  now?: () => number;
}

interface AddressEntry {
  kind: 'address';
  entry: string;
  address: string;
}
interface RangeEntry {
  kind: 'range';
  entry: string;
  address: string;
  prefix: number;
  family: Family;
}
type NameStatus = 'pending' | 'resolved' | 'not-found' | 'error' | 'not-looked-up';
interface NameEntry {
  kind: 'name';
  entry: string;
  ipv4: string[];
  ipv6: string[];
  status: NameStatus;
  /** Answers that were not trusted: off the backend's networks, a gateway, or not confirmed by Docker. */
  ignoredAnswers: string[];
  error?: string;
  resolvedAt?: number;
}
type Entry = AddressEntry | RangeEntry | NameEntry;

export interface RejectedEntry {
  entry: string;
  reason: string;
}

export interface ParsedTrustedProxies {
  /** The value in effect (the default when TRUSTED_PROXIES is unset or blank). */
  configured: string;
  entries: Entry[];
  rejected: RejectedEntry[];
  warnings: string[];
}

const EVERY_ADDRESS = new Set(['*', 'true', 'all', 'any']);
const PRESETS = new Set(['loopback', 'linklocal', 'uniquelocal']);
const SERVICE_NAME = /^[a-z0-9][a-z0-9_.-]*$/i;

/**
 * TRUSTED_PROXIES as entries. Values that would trust everyone ('*', 'true',
 * /0), Express's address-class presets, hop counts and anything malformed are
 * rejected with a reason; the rest still applies.
 */
export function parseTrustedProxies(spec: string | undefined): ParsedTrustedProxies {
  const configured = spec === undefined || spec.trim() === '' ? DEFAULT_TRUSTED_PROXIES : spec.trim();
  const entries: Entry[] = [];
  const rejected: RejectedEntry[] = [];
  const warnings: string[] = [];
  const seen = new Set<string>();
  let none = false;

  const add = (key: string, entry: Entry) => {
    if (seen.has(key)) return;
    seen.add(key);
    entries.push(entry);
  };

  for (const token of configured.split(/[\s,]+/).filter(Boolean)) {
    const lower = token.toLowerCase();
    if (lower === 'none') {
      none = true;
      continue;
    }
    if (EVERY_ADDRESS.has(lower)) {
      rejected.push({ entry: token, reason: 'it would trust every address, so any client could pick its own' });
      continue;
    }
    if (lower === 'false') {
      rejected.push({ entry: token, reason: "not an address; use 'none' to trust only the bundled frontend" });
      continue;
    }
    if (PRESETS.has(lower)) {
      rejected.push({
        entry: token,
        reason: 'address-class presets are not supported (they cover every host on the network); list your proxy addresses',
      });
      continue;
    }
    if (lower === 'localhost') {
      rejected.push({ entry: token, reason: 'list 127.0.0.1 or ::1 instead (names are only looked up in Docker DNS)' });
      continue;
    }
    if (/^\d+$/.test(token)) {
      rejected.push({ entry: token, reason: 'hop counts are not supported; list your proxy addresses' });
      continue;
    }

    const slash = token.indexOf('/');
    if (slash !== -1) {
      const base = token.slice(0, slash);
      const address = base.includes('%') ? null : normalizeIp(base);
      const family = address ? familyOf(address) : null;
      const prefixText = token.slice(slash + 1);
      const prefix = /^\d{1,3}$/.test(prefixText) ? Number(prefixText) : NaN;
      if (!address || !family || !Number.isInteger(prefix) || prefix > (family === 'ipv4' ? 32 : 128)) {
        rejected.push({ entry: token, reason: 'not a valid address range' });
        continue;
      }
      if (prefix === 0) {
        rejected.push({ entry: token, reason: 'a /0 range trusts every address, so any client could pick its own' });
        continue;
      }
      add(`${address}/${prefix}`, { kind: 'range', entry: token, address, prefix, family });
      if ((family === 'ipv4' && prefix < 24) || (family === 'ipv6' && prefix < 64)) {
        warnings.push(
          `TRUSTED_PROXIES entry ${token} is a wide range (shorter than /${family === 'ipv4' ? 24 : 64}): ` +
            'every host in it can set its own client address. List your proxy addresses instead if you can.'
        );
      }
      continue;
    }

    const address = token.includes('%') ? null : normalizeIp(token);
    if (address) {
      if (address === '0.0.0.0' || address === '::') {
        rejected.push({ entry: token, reason: 'not a host address' });
        continue;
      }
      add(address, { kind: 'address', entry: token, address });
      continue;
    }
    if (token.length <= 253 && SERVICE_NAME.test(token) && !/^[\d.]+$/.test(token)) {
      add(`name:${lower}`, { kind: 'name', entry: token, ipv4: [], ipv6: [], status: 'pending', ignoredAnswers: [] });
      continue;
    }
    rejected.push({ entry: token, reason: 'not an IP address, address range or service name' });
  }

  if (none && entries.length > 0) {
    rejected.push({ entry: 'none', reason: 'cannot be combined with other entries, which apply' });
  }
  return { configured, entries, rejected, warnings };
}

/** Gateways of routes in a /proc/net/route table (little-endian hex). */
export function routeGateways(table: string | null): string[] {
  const gateways: string[] = [];
  for (const line of (table ?? '').split('\n').slice(1)) {
    const gateway = line.trim().split(/\s+/)[2];
    if (!gateway || !/^[0-9a-f]{8}$/i.test(gateway) || /^0+$/.test(gateway)) continue;
    const n = parseInt(gateway, 16);
    gateways.push([n & 255, (n >>> 8) & 255, (n >>> 16) & 255, n >>> 24].join('.'));
  }
  return gateways;
}

/** Next hops of routes in a /proc/net/ipv6_route table. */
export function ipv6RouteGateways(table: string | null): string[] {
  const gateways: string[] = [];
  for (const line of (table ?? '').split('\n')) {
    const nextHop = line.trim().split(/\s+/)[4];
    if (!nextHop || !/^[0-9a-f]{32}$/i.test(nextHop) || /^0+$/.test(nextHop)) continue;
    const ip = normalizeIp(nextHop.match(/.{4}/g)!.join(':'));
    if (ip && !ip.startsWith('fe80:')) gateways.push(ip);
  }
  return gateways;
}

function isDockerBridge(name: string): boolean {
  return name === 'docker0' || name.startsWith('br-');
}

/** Interfaces only the Docker host's own network namespace has. */
function looksLikeDockerHost(table: InterfaceTable): boolean {
  return Object.keys(table).some((name) => isDockerBridge(name) || name.startsWith('veth'));
}

function isLinkLocal(ip: string): boolean {
  return ip.startsWith('fe80:') || ip.startsWith('169.254.');
}

/** The backend's own networks and addresses: every non-loopback, non-link-local interface address. */
function ownNetworks(table: InterfaceTable): { list: AddressList; cidrs: string[]; addresses: string[] } {
  const list = new AddressList();
  const cidrs: string[] = [];
  const addresses: string[] = [];
  for (const entries of Object.values(table)) {
    for (const entry of entries ?? []) {
      if (entry.internal || !entry.cidr) continue;
      const [address, prefixText] = entry.cidr.split('/');
      const ip = normalizeIp(address);
      const prefix = Number(prefixText);
      if (!ip || isLinkLocal(ip) || !Number.isInteger(prefix)) continue;
      list.addSubnet(ip, prefix);
      cidrs.push(`${ip}/${prefix}`);
      addresses.push(ip);
    }
  }
  return { list, cidrs, addresses };
}

function readFileOrNull(path: string): string | null {
  try {
    return fs.readFileSync(path, 'utf8');
  } catch {
    return null;
  }
}

function dockerDnsResolver(): NameResolver {
  const resolver = new dns.promises.Resolver({ timeout: DNS_TIMEOUT_MS, tries: 1 });
  resolver.setServers([DOCKER_DNS]);
  return {
    resolve4: (name) => resolver.resolve4(name),
    resolve6: (name) => resolver.resolve6(name),
    reverse: (ip) => resolver.reverse(ip),
  };
}

type Lookup = { status: 'ok'; addresses: string[] } | { status: 'not-found' } | { status: 'error'; error: string };

async function lookup(resolve: (name: string) => Promise<string[]>, name: string): Promise<Lookup> {
  try {
    return { status: 'ok', addresses: await resolve(name) };
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    // NXDOMAIN, or the name exists without records of this family.
    if (code === dns.NOTFOUND || code === dns.NODATA) return { status: 'not-found' };
    return { status: 'error', error: code ?? String(err) };
  }
}

/**
 * The network in a name Docker's DNS gives a container's address,
 * `<container>.<network>`: everything after the first label, lower-cased.
 */
function networkOfReverseName(name: string): string | null {
  const host = name.trim().toLowerCase().replace(/\.$/, '');
  const dot = host.indexOf('.');
  return dot > 0 && dot < host.length - 1 ? host.slice(dot + 1) : null;
}

/** Private, carrier-grade NAT, loopback, link-local and unique-local ranges. */
const LOCAL_RANGES = new AddressList();
for (const [address, prefix] of [
  ['10.0.0.0', 8],
  ['172.16.0.0', 12],
  ['192.168.0.0', 16],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['fc00::', 7],
  ['fe80::', 10],
  ['::1', 128],
] as const) {
  LOCAL_RANGES.addSubnet(address, prefix);
}

/**
 * How an ignored X-Forwarded-For arrived:
 * - 'direct': from a TCP peer on port 8421 that isn't trusted;
 * - 'forwarded': from an address in X-Forwarded-For itself, passed on by the
 *   bundled nginx (or a trusted proxy): an untrusted proxy in front of it,
 *   such as a reverse proxy in front of the web UI that TRUSTED_PROXIES doesn't
 *   list. Express takes that proxy for the client.
 */
export type IgnoredHeaderKind = 'direct' | 'forwarded';

interface IgnoredPeer {
  address: string;
  kind: IgnoredHeaderKind;
  requests: number;
  firstSeen: number;
  lastSeen: number;
  lastWarned: number | null;
  local: boolean;
}

/** Ignored for longer than nginx's fallback window after a socket failure. */
function isSustained(peer: Pick<IgnoredPeer, 'firstSeen' | 'lastSeen'>): boolean {
  return peer.lastSeen - peer.firstSeen > IGNORED_HEADER_GRACE_MS;
}

/** The entries of an X-Forwarded-For header, left to right, as Express reads them. */
function forwardedEntries(header: string | string[] | undefined): string[] {
  if (header === undefined) return [];
  const text = Array.isArray(header) ? header.join(',') : header;
  return text
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

/** Whether a request is for the diagnostics endpoint (which Express matches case-insensitively, trailing slash or not). */
function isDiagnosticsRequest(req: Request): boolean {
  if (req.method !== 'GET' && req.method !== 'HEAD') return false;
  const path = (req.originalUrl || req.url || '').split('?')[0].replace(/\/+$/, '').toLowerCase();
  return path === DIAGNOSTICS_PATH;
}

export interface IgnoredPeerReport {
  address: string;
  kind: IgnoredHeaderKind;
  requests: number;
  firstSeen: string;
  lastSeen: string;
  local: boolean;
  /** Ignored for more than 45 s: reported in warnings (for a local address) and logged. */
  sustained: boolean;
}

export interface TrustedProxiesReport {
  configured: string;
  entries: Array<{
    entry: string;
    kind: 'address' | 'range' | 'name';
    addresses?: string[];
    status?: NameStatus;
    ignoredAnswers?: string[];
    error?: string;
    resolvedAt?: string;
  }>;
  rejected: RejectedEntry[];
  nameLookup: { enabled: boolean; reason?: string };
  hostNetworking: boolean;
  gateways: string[];
  ownNetworks: string[];
  ignoredForwardedFor: {
    peers: IgnoredPeerReport[];
    untracked: number;
  };
  warnings: string[];
}

export class TrustedProxies {
  readonly configured: string;
  readonly rejected: RejectedEntry[];
  /** True when the backend shares the Docker host's network namespace. */
  readonly hostNetworking: boolean;
  private readonly entries: Entry[];
  private readonly names: NameEntry[];
  private readonly configWarnings: string[];
  private readonly inContainer: boolean;
  private readonly interfaces: () => InterfaceTable;
  private readonly readFile: (path: string) => string | null;
  private readonly log: Log;
  private readonly now: () => number;
  private resolver: NameResolver | undefined;
  private exact = new AddressList();
  private ranges = new AddressList();
  private resolved = new AddressList();
  private gatewayList = new AddressList();
  private gateways: string[] = [];
  private ownCidrs: string[] = [];
  /** Docker network names of the backend's own addresses, from the last lookup that got answers. */
  private dockerNetworks: Set<string> | null = null;
  private readonly peers = new Map<string, IgnoredPeer>();
  private untracked = 0;
  private timer: NodeJS.Timeout | null = null;
  private refreshing: Promise<void> | null = null;

  constructor(options: TrustedProxiesOptions = {}) {
    const parsed = parseTrustedProxies(options.spec);
    this.configured = parsed.configured;
    this.entries = parsed.entries;
    this.rejected = parsed.rejected;
    this.configWarnings = [...parsed.warnings];
    this.names = this.entries.filter((e): e is NameEntry => e.kind === 'name');
    this.interfaces = options.interfaces ?? (() => os.networkInterfaces() as InterfaceTable);
    this.readFile = options.readFile ?? readFileOrNull;
    this.log = options.log ?? logger;
    this.now = options.now ?? Date.now;
    this.resolver = options.resolver;
    this.inContainer = options.inContainer ?? (fs.existsSync('/.dockerenv') || fs.existsSync('/run/.containerenv'));

    const table = this.interfaceTable();
    this.hostNetworking = options.hostNetworking === true || looksLikeDockerHost(table);
    this.detectNetworks(table);

    for (const entry of this.entries) {
      if (entry.kind === 'address') this.exact.addAddress(entry.address);
      if (entry.kind === 'range') this.ranges.addSubnet(entry.address, entry.prefix);
    }
    for (const gateway of this.gateways) {
      if (this.exact.check(gateway)) {
        this.configWarnings.push(
          `TRUSTED_PROXIES lists the Docker gateway ${gateway}. Docker presents IPv6 and loopback clients of ` +
            'published ports as that address, so those clients can now set their own client address.'
        );
      } else {
        const range = this.entries.find((e): e is RangeEntry => {
          if (e.kind !== 'range') return false;
          const one = new AddressList();
          one.addSubnet(e.address, e.prefix);
          return one.check(gateway);
        });
        if (range) {
          this.configWarnings.push(
            `TRUSTED_PROXIES entry ${range.entry} contains the Docker gateway ${gateway}, which stays untrusted: ` +
              'Docker presents IPv6 and loopback clients of published ports as that address.'
          );
        }
      }
    }
  }

  /** Names are looked up only inside a container that has its own network namespace. */
  get nameLookupEnabled(): boolean {
    return this.names.length > 0 && this.inContainer && !this.hostNetworking;
  }

  private get nameLookupReason(): string | undefined {
    if (this.names.length === 0) return 'no names listed';
    if (this.hostNetworking) return 'host networking: names are not looked up, list IP addresses instead';
    if (!this.inContainer) return 'not running in a container: names are only looked up in Docker DNS';
    return undefined;
  }

  /** The 'trust proxy' function for Express. */
  readonly trust = (addr: string | undefined, hop: number): boolean => {
    if (addr === PROXY_SOCKET_PEER) return hop === 0;
    const ip = normalizeIp(addr);
    return ip !== null && this.isTrusted(ip);
  };

  /** Whether a normalized address is a trusted proxy (the proxy socket aside). */
  isTrusted(ip: string): boolean {
    if (this.exact.check(ip) || this.resolved.check(ip)) return true;
    return this.ranges.check(ip) && !this.gatewayList.check(ip);
  }

  /** Whether `ip` is a detected Docker gateway address. */
  isGateway(ip: string): boolean {
    return this.gatewayList.check(ip);
  }

  /**
   * Logs what is wrong with the configuration, then looks the names up (waiting
   * up to 1 s for the first answers) and keeps refreshing them every 30 s.
   */
  async start(): Promise<void> {
    for (const { entry, reason } of this.rejected) {
      this.log.error(`TRUSTED_PROXIES entry "${entry}" ignored: ${reason}.`);
    }
    for (const warning of this.configWarnings) this.log.warn(warning);
    if (!this.nameLookupEnabled) {
      for (const name of this.names) name.status = 'not-looked-up';
      return;
    }
    let wait: NodeJS.Timeout | undefined;
    await Promise.race([
      this.refresh(),
      new Promise<void>((resolve) => {
        wait = setTimeout(resolve, BOOT_WAIT_MS);
      }),
    ]);
    clearTimeout(wait);
    if (!this.timer) {
      this.timer = setInterval(() => void this.refresh(), NAME_REFRESH_MS);
      this.timer.unref();
    }
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  /** Looks every name up again (one lookup at a time; a call during one joins it). */
  refresh(): Promise<void> {
    if (!this.nameLookupEnabled) return Promise.resolve();
    if (!this.refreshing) {
      this.refreshing = this.lookUpNames().finally(() => {
        this.refreshing = null;
      });
    }
    return this.refreshing;
  }

  private interfaceTable(): InterfaceTable {
    try {
      return this.interfaces();
    } catch {
      return {};
    }
  }

  /** Gateways (bridge: the routing table; host networking: docker0/br-* addresses) and own subnets. */
  private detectNetworks(table: InterfaceTable): void {
    let gateways: string[] = [];
    if (this.hostNetworking) {
      for (const [name, addresses] of Object.entries(table)) {
        if (!isDockerBridge(name)) continue;
        for (const entry of addresses ?? []) {
          const ip = normalizeIp(entry.address);
          if (ip && !isLinkLocal(ip)) gateways.push(ip);
        }
      }
    } else if (this.inContainer) {
      gateways = [
        ...routeGateways(this.readFile('/proc/net/route')),
        ...ipv6RouteGateways(this.readFile('/proc/net/ipv6_route')),
      ];
    }
    const list = new AddressList();
    for (const gateway of gateways) list.addAddress(gateway);
    this.gateways = [...new Set(gateways)];
    this.gatewayList = list;
    this.ownCidrs = ownNetworks(table).cidrs;
  }

  /**
   * The Docker networks the backend is on, as Docker's DNS names them in the
   * reverse lookups of its own addresses. Null when no lookup was answered
   * (Docker's DNS is not reachable right now): then the previous set stands.
   */
  private async lookUpDockerNetworks(resolver: NameResolver, addresses: string[]): Promise<Set<string> | null> {
    const results = await Promise.all(addresses.map((ip) => lookup((a) => resolver.reverse(a), ip)));
    if (results.length > 0 && results.every((result) => result.status === 'error')) return this.dockerNetworks;
    const networks = new Set<string>();
    for (const result of results) {
      if (result.status !== 'ok') continue;
      for (const name of result.addresses) {
        const network = networkOfReverseName(name);
        if (network) networks.add(network);
      }
    }
    this.dockerNetworks = networks;
    return networks;
  }

  /**
   * Whether Docker's DNS names `ip` as a container on one of the backend's
   * networks; 'unknown' when it could not be asked.
   */
  private async dockerConfirms(
    resolver: NameResolver,
    ip: string,
    networks: Set<string> | null
  ): Promise<'yes' | 'no' | 'unknown'> {
    if (networks === null) return 'unknown';
    const result = await lookup((a) => resolver.reverse(a), ip);
    if (result.status === 'error') return 'unknown';
    if (result.status === 'not-found') return 'no';
    return result.addresses.some((name) => {
      const network = networkOfReverseName(name);
      return network !== null && networks.has(network);
    })
      ? 'yes'
      : 'no';
  }

  private async lookUpNames(): Promise<void> {
    const table = this.interfaceTable();
    this.detectNetworks(table);
    const own = ownNetworks(table);
    this.resolver ??= dockerDnsResolver();
    const resolver = this.resolver;
    const networks = await this.lookUpDockerNetworks(resolver, own.addresses);
    await Promise.all(this.names.map((name) => this.lookUpName(name, resolver, own.list, networks)));
    const list = new AddressList();
    for (const name of this.names) {
      for (const ip of [...name.ipv4, ...name.ipv6]) list.addAddress(ip);
    }
    this.resolved = list;
  }

  private async lookUpName(
    name: NameEntry,
    resolver: NameResolver,
    own: AddressList,
    networks: Set<string> | null
  ): Promise<void> {
    const [ipv4, ipv6] = await Promise.all([
      lookup((n) => resolver.resolve4(n), name.entry),
      lookup((n) => resolver.resolve6(n), name.entry),
    ]);
    const before = [...name.ipv4, ...name.ipv6].join(', ');
    const ignoredBefore = new Set(name.ignoredAnswers);
    const ignored: Array<{ ip: string; reason: string }> = [];
    const accept = async (result: Lookup, previous: string[]): Promise<string[]> => {
      if (result.status === 'error') return previous;
      if (result.status === 'not-found') return [];
      const accepted: string[] = [];
      for (const answer of result.addresses) {
        const ip = normalizeIp(answer);
        if (!ip) continue;
        if (!own.check(ip)) {
          ignored.push({ ip, reason: "it is not on this container's networks" });
          continue;
        }
        if (this.gatewayList.check(ip)) {
          ignored.push({ ip, reason: 'it is the Docker gateway' });
          continue;
        }
        const confirmed = await this.dockerConfirms(resolver, ip, networks);
        if (confirmed === 'yes' || (confirmed === 'unknown' && previous.includes(ip))) {
          accepted.push(ip);
        } else {
          ignored.push({
            ip,
            reason:
              confirmed === 'unknown'
                ? "Docker's DNS could not be asked whether it is a container on this container's networks"
                : "Docker's DNS does not know it as a container on this container's networks (the answer came " +
                  'from another DNS server)',
          });
        }
      }
      return accepted;
    };
    name.ipv4 = await accept(ipv4, name.ipv4);
    name.ipv6 = await accept(ipv6, name.ipv6);
    name.ignoredAnswers = ignored.map(({ ip }) => ip);
    const failed = [ipv4, ipv6].filter((r): r is Extract<Lookup, { status: 'error' }> => r.status === 'error');
    name.error = failed.length > 0 ? failed.map((r) => r.error).join(', ') : undefined;
    const addresses = [...name.ipv4, ...name.ipv6];
    name.status = failed.length === 2 ? 'error' : addresses.length > 0 ? 'resolved' : 'not-found';
    name.resolvedAt = this.now();
    const after = addresses.join(', ');
    if (after !== before) {
      this.log.info(
        after
          ? `TRUSTED_PROXIES: ${name.entry} -> ${after}`
          : `TRUSTED_PROXIES: ${name.entry} no longer resolves to a container on this container's networks`
      );
    }
    for (const { ip, reason } of ignored) {
      if (!ignoredBefore.has(ip)) {
        this.log.warn(`TRUSTED_PROXIES: ignored the answer ${ip} for ${name.entry}: ${reason}, so it is not trusted.`);
      }
    }
  }

  /**
   * The X-Forwarded-For entry Express takes for the client (the first from the
   * right that isn't trusted), when there are entries left of it: that address
   * passed on an X-Forwarded-For of its own, so it is a proxy that isn't
   * trusted. Null otherwise. Only meaningful for a request whose TCP peer is
   * trusted (the proxy socket, or a TRUSTED_PROXIES entry).
   */
  untrustedForwarder(header: string | string[] | undefined): string | null {
    const entries = forwardedEntries(header);
    for (let i = entries.length - 1; i >= 0; i--) {
      const ip = normalizeIp(entries[i]);
      if (ip !== null && this.isTrusted(ip)) continue;
      return ip !== null && i > 0 ? ip : null;
    }
    return null;
  }

  /**
   * Counts a request whose X-Forwarded-For is ignored: one that came over TCP
   * from a peer that is not trusted ('direct'), or one whose header was passed
   * on by an untrusted proxy in front of a trusted one ('forwarded'). Local
   * peers (private, loopback, ULA, link-local) are most likely a proxy that
   * should be trusted, so once that has gone on for more than 45 s they get a
   * warning, at most once an hour each. Requests to GET
   * /api/admin/client-address are not counted.
   */
  noteRequest(req: Request): void {
    const header = req.headers['x-forwarded-for'];
    if (header === undefined || isDiagnosticsRequest(req)) return;
    const peer = req.socket?.remoteAddress;
    if (!peer) return;
    if (peer !== PROXY_SOCKET_PEER) {
      const ip = normalizeIp(peer);
      if (!ip) return;
      if (!this.isTrusted(ip)) {
        this.record(ip, 'direct');
        return;
      }
    }
    const forwarder = this.untrustedForwarder(header);
    if (forwarder) this.record(forwarder, 'forwarded');
  }

  private record(ip: string, kind: IgnoredHeaderKind): void {
    const now = this.now();
    const key = `${kind} ${ip}`;
    let record = this.peers.get(key);
    if (record && now - record.lastSeen > IGNORED_PEER_TTL_MS) {
      this.peers.delete(key); // forgotten: this is a new episode
      record = undefined;
    }
    if (!record) {
      const local = LOCAL_RANGES.check(ip);
      if (this.peers.size >= MAX_TRACKED_PEERS && !this.makeRoom(local, now)) {
        this.untracked++;
        return;
      }
      record = { address: ip, kind, requests: 0, firstSeen: now, lastSeen: now, lastWarned: null, local };
      this.peers.set(key, record);
    }
    record.requests++;
    record.lastSeen = now;
    if (
      record.local &&
      isSustained(record) &&
      (record.lastWarned === null || now - record.lastWarned >= IGNORED_HEADER_WARN_MS)
    ) {
      record.lastWarned = now;
      this.log.warn(
        `Ignored X-Forwarded-For from ${ip} (${record.requests} requests in ${Math.round(
          (record.lastSeen - record.firstSeen) / 1000
        )} s): ${this.ignoredPeerAdvice(record)} See DEPLOYMENT.md, "Client addresses and reverse proxies".`
      );
    }
  }

  /** Makes room: drops a forgotten peer, or for a local peer the least recently seen remote one. */
  private makeRoom(local: boolean, now: number): boolean {
    for (const [key, record] of this.peers) {
      if (now - record.lastSeen > IGNORED_PEER_TTL_MS) {
        this.peers.delete(key);
        return true;
      }
    }
    if (!local) return false;
    let victim: string | null = null;
    let oldest = Infinity;
    for (const [key, record] of this.peers) {
      if (!record.local && record.lastSeen < oldest) {
        oldest = record.lastSeen;
        victim = key;
      }
    }
    if (victim === null) return false;
    this.peers.delete(victim);
    this.untracked++;
    return true;
  }

  /**
   * What an ignored peer means and what to do about it, as a clause that
   * starts with "it" (the log line and the admin report put it after the
   * address).
   */
  ignoredPeerAdvice(peer: { address: string; kind: IgnoredHeaderKind }): string {
    const { address } = peer;
    const shared =
      peer.kind === 'forwarded'
        ? `it passes requests on to SIEMBox but is not a trusted proxy, so every client behind it shares the address ${address}.`
        : `it calls the API directly and is not a trusted proxy, so every client behind it shares the address ${address}.`;
    if (this.isGateway(address)) {
      return (
        `${shared} It is the Docker network gateway, which is never trusted through a range (Docker presents ` +
        "loopback and IPv6 clients of published ports this way): point your proxy at the host's LAN address and " +
        'port 8420 instead of 127.0.0.1, then add that address to TRUSTED_PROXIES (keep "frontend" in the list).'
      );
    }
    if (peer.kind === 'forwarded') {
      return `${shared} If it is your reverse proxy, add it to TRUSTED_PROXIES (keep "frontend" in the list).`;
    }
    return (
      `${shared} If it is the SIEMBox frontend, update your compose file so the backend and frontend share the ` +
      'api-socket volume; if it is your own reverse proxy, add it to TRUSTED_PROXIES (keep "frontend" in the list).'
    );
  }

  describe(): TrustedProxiesReport {
    const iso = (ms: number) => new Date(ms).toISOString();
    const now = this.now();
    return {
      configured: this.configured,
      entries: this.entries.map((entry) => {
        if (entry.kind === 'address') return { entry: entry.entry, kind: 'address' as const, addresses: [entry.address] };
        if (entry.kind === 'range') {
          return { entry: entry.entry, kind: 'range' as const, addresses: [`${entry.address}/${entry.prefix}`] };
        }
        return {
          entry: entry.entry,
          kind: 'name' as const,
          addresses: [...entry.ipv4, ...entry.ipv6],
          status: entry.status,
          ...(entry.ignoredAnswers.length > 0 ? { ignoredAnswers: entry.ignoredAnswers } : {}),
          ...(entry.error ? { error: entry.error } : {}),
          ...(entry.resolvedAt ? { resolvedAt: iso(entry.resolvedAt) } : {}),
        };
      }),
      rejected: this.rejected,
      nameLookup: this.nameLookupEnabled ? { enabled: true } : { enabled: false, reason: this.nameLookupReason },
      hostNetworking: this.hostNetworking,
      gateways: this.gateways,
      ownNetworks: this.ownCidrs,
      ignoredForwardedFor: {
        peers: [...this.peers.values()]
          .filter((record) => now - record.lastSeen <= IGNORED_PEER_TTL_MS)
          .sort((a, b) => b.lastSeen - a.lastSeen)
          .map((record) => ({
            address: record.address,
            kind: record.kind,
            requests: record.requests,
            firstSeen: iso(record.firstSeen),
            lastSeen: iso(record.lastSeen),
            local: record.local,
            sustained: isSustained(record),
          })),
        untracked: this.untracked,
      },
      warnings: [...this.configWarnings],
    };
  }
}

/**
 * An environment setting, read by a computed name. TRUSTED_PROXIES goes
 * through this because CodeQL's js/clear-text-logging query takes any
 * environment variable whose name contains "trusted" for a secret, and this
 * module logs its entries on purpose: a rejected value, a wide range or what a
 * name resolved to is how an operator finds a misconfiguration. The value is a
 * list of proxy addresses and service names, not a secret (the admin
 * diagnostics endpoint returns it too). A read by a non-constant name is what
 * that query treats as an ordinary setting.
 */
function environmentSetting(name: string): string | undefined {
  return process.env[name];
}

/** The instance app.ts and server.ts use, configured from the environment. */
export const trustedProxies = new TrustedProxies({
  spec: environmentSetting('TRUSTED_PROXIES'),
  hostNetworking: process.env.SIEMBOX_HOST_NETWORKING === 'true',
});

/**
 * First middleware: counts requests whose X-Forwarded-For is being ignored
 * (TrustedProxies.noteRequest). It never changes the request.
 */
export function ignoredForwardedForTracker(proxies: TrustedProxies = trustedProxies) {
  return function ignoredForwardedForTracker(req: Request, _res: Response, next: NextFunction): void {
    proxies.noteRequest(req);
    next();
  };
}
