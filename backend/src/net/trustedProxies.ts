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
 * a container on a bridge network (never with host networking), and only
 * answers on the backend's own networks count, so a LAN DNS server that answers
 * for `frontend` can never make some LAN host trusted. Lookups repeat every
 * 30 s: a name that no longer exists stops being trusted, a lookup that times
 * out keeps the last answer.
 *
 * Docker gateway addresses are never trusted through a range: Docker's
 * userland proxy presents IPv6 and loopback clients of published ports as the
 * gateway, so trusting it would let those clients pick their address. Listing a
 * gateway as an exact address still works, with a warning.
 *
 * The same module counts direct requests whose X-Forwarded-For was ignored, so
 * a proxy that should be trusted but is not (an outdated compose file, a reverse
 * proxy missing from TRUSTED_PROXIES) shows up in the log and in
 * GET /api/admin/client-address.
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
export const IGNORED_HEADER_WARN_MS = 60 * 60 * 1000;

type Family = 'ipv4' | 'ipv6';

function familyOf(ip: string): Family {
  return net.isIP(ip) === 6 ? 'ipv6' : 'ipv4';
}

export interface NameResolver {
  resolve4(name: string): Promise<string[]>;
  resolve6(name: string): Promise<string[]>;
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
  /** Answers that were not on the backend's own networks (or were a gateway). */
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

/** The backend's own networks: every non-loopback, non-link-local interface subnet. */
function ownNetworks(table: InterfaceTable): { list: net.BlockList; cidrs: string[] } {
  const list = new net.BlockList();
  const cidrs: string[] = [];
  for (const addresses of Object.values(table)) {
    for (const entry of addresses ?? []) {
      if (entry.internal || !entry.cidr) continue;
      const [address, prefixText] = entry.cidr.split('/');
      const ip = normalizeIp(address);
      const prefix = Number(prefixText);
      if (!ip || isLinkLocal(ip) || !Number.isInteger(prefix)) continue;
      list.addSubnet(ip, prefix, familyOf(ip));
      cidrs.push(`${ip}/${prefix}`);
    }
  }
  return { list, cidrs };
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

/** Private, carrier-grade NAT, loopback, link-local and unique-local ranges. */
const LOCAL_RANGES = new net.BlockList();
for (const [address, prefix] of [
  ['10.0.0.0', 8],
  ['172.16.0.0', 12],
  ['192.168.0.0', 16],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
] as const) {
  LOCAL_RANGES.addSubnet(address, prefix, 'ipv4');
}
for (const [address, prefix] of [
  ['fc00::', 7],
  ['fe80::', 10],
  ['::1', 128],
] as const) {
  LOCAL_RANGES.addSubnet(address, prefix, 'ipv6');
}

interface IgnoredPeer {
  requests: number;
  firstSeen: number;
  lastSeen: number;
  lastWarned: number | null;
  local: boolean;
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
    peers: Array<{ address: string; requests: number; firstSeen: string; lastSeen: string; local: boolean }>;
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
  private exact = new net.BlockList();
  private ranges = new net.BlockList();
  private resolved = new net.BlockList();
  private gatewayList = new net.BlockList();
  private gateways: string[] = [];
  private ownCidrs: string[] = [];
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
      if (entry.kind === 'address') this.exact.addAddress(entry.address, familyOf(entry.address));
      if (entry.kind === 'range') this.ranges.addSubnet(entry.address, entry.prefix, entry.family);
    }
    for (const gateway of this.gateways) {
      const family = familyOf(gateway);
      if (this.exact.check(gateway, family)) {
        this.configWarnings.push(
          `TRUSTED_PROXIES lists the Docker gateway ${gateway}. Docker presents IPv6 and loopback clients of ` +
            'published ports as that address, so those clients can now set their own client address.'
        );
      } else {
        const range = this.entries.find((e): e is RangeEntry => {
          if (e.kind !== 'range' || e.family !== family) return false;
          const one = new net.BlockList();
          one.addSubnet(e.address, e.prefix, e.family);
          return one.check(gateway, family);
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
    const family = familyOf(ip);
    if (this.exact.check(ip, family) || this.resolved.check(ip, family)) return true;
    return this.ranges.check(ip, family) && !this.gatewayList.check(ip, family);
  }

  /** Whether `ip` is a detected Docker gateway address. */
  isGateway(ip: string): boolean {
    return this.gatewayList.check(ip, familyOf(ip));
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
    const list = new net.BlockList();
    for (const gateway of gateways) list.addAddress(gateway, familyOf(gateway));
    this.gateways = [...new Set(gateways)];
    this.gatewayList = list;
    this.ownCidrs = ownNetworks(table).cidrs;
  }

  private async lookUpNames(): Promise<void> {
    const table = this.interfaceTable();
    this.detectNetworks(table);
    const own = ownNetworks(table).list;
    this.resolver ??= dockerDnsResolver();
    const resolver = this.resolver;
    await Promise.all(
      this.names.map(async (name) => {
        const [ipv4, ipv6] = await Promise.all([
          lookup((n) => resolver.resolve4(n), name.entry),
          lookup((n) => resolver.resolve6(n), name.entry),
        ]);
        const before = [...name.ipv4, ...name.ipv6].join(', ');
        const ignoredBefore = new Set(name.ignoredAnswers);
        const ignored: string[] = [];
        const accept = (result: Lookup, previous: string[]): string[] => {
          if (result.status === 'error') return previous;
          if (result.status === 'not-found') return [];
          const accepted: string[] = [];
          for (const answer of result.addresses) {
            const ip = normalizeIp(answer);
            if (!ip) continue;
            const family = familyOf(ip);
            if (own.check(ip, family) && !this.gatewayList.check(ip, family)) accepted.push(ip);
            else ignored.push(ip);
          }
          return accepted;
        };
        name.ipv4 = accept(ipv4, name.ipv4);
        name.ipv6 = accept(ipv6, name.ipv6);
        name.ignoredAnswers = ignored;
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
              : `TRUSTED_PROXIES: ${name.entry} no longer resolves to an address on this container's networks`
          );
        }
        for (const ip of ignored) {
          if (!ignoredBefore.has(ip)) {
            this.log.warn(
              `TRUSTED_PROXIES: ignored the answer ${ip} for ${name.entry}: it is not on this container's networks ` +
                '(or it is the Docker gateway), so it is not trusted.'
            );
          }
        }
      })
    );
    const list = new net.BlockList();
    for (const name of this.names) {
      for (const ip of [...name.ipv4, ...name.ipv6]) list.addAddress(ip, familyOf(ip));
    }
    this.resolved = list;
  }

  /**
   * Counts a request whose X-Forwarded-For is ignored: one that came over TCP
   * from a peer that is not trusted. Local peers (private, loopback, ULA,
   * link-local) are most likely a proxy that should be trusted, so they get a
   * warning, at most once an hour each.
   */
  noteRequest(req: Request): void {
    if (req.headers['x-forwarded-for'] === undefined) return;
    const peer = req.socket?.remoteAddress;
    if (!peer || peer === PROXY_SOCKET_PEER) return;
    const ip = normalizeIp(peer);
    if (!ip || this.isTrusted(ip)) return;
    const now = this.now();
    let record = this.peers.get(ip);
    if (!record) {
      const local = LOCAL_RANGES.check(ip, familyOf(ip));
      if (this.peers.size >= MAX_TRACKED_PEERS && !(local && this.evictRemotePeer())) {
        this.untracked++;
        return;
      }
      record = { requests: 0, firstSeen: now, lastSeen: now, lastWarned: null, local };
      this.peers.set(ip, record);
    }
    record.requests++;
    record.lastSeen = now;
    if (record.local && (record.lastWarned === null || now - record.lastWarned >= IGNORED_HEADER_WARN_MS)) {
      record.lastWarned = now;
      this.log.warn(
        `Ignored X-Forwarded-For from ${ip} (${record.requests} request${record.requests === 1 ? '' : 's'} so far): ` +
          `it is not a trusted proxy, so every client behind it shares the address ${ip}. ` +
          'If it is the SIEMBox frontend, update your compose file so the backend and frontend share the api-socket volume; ' +
          'if it is your own reverse proxy, add it to TRUSTED_PROXIES (keep "frontend" in the list). ' +
          'See DEPLOYMENT.md, "Client addresses and reverse proxies".'
      );
    }
  }

  /** Makes room for a local peer by dropping the least recently seen remote one. */
  private evictRemotePeer(): boolean {
    let victim: string | null = null;
    let oldest = Infinity;
    for (const [ip, record] of this.peers) {
      if (!record.local && record.lastSeen < oldest) {
        oldest = record.lastSeen;
        victim = ip;
      }
    }
    if (victim === null) return false;
    this.peers.delete(victim);
    this.untracked++;
    return true;
  }

  describe(): TrustedProxiesReport {
    const iso = (ms: number) => new Date(ms).toISOString();
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
        peers: [...this.peers.entries()]
          .sort((a, b) => b[1].lastSeen - a[1].lastSeen)
          .map(([address, r]) => ({
            address,
            requests: r.requests,
            firstSeen: iso(r.firstSeen),
            lastSeen: iso(r.lastSeen),
            local: r.local,
          })),
        untracked: this.untracked,
      },
      warnings: [...this.configWarnings],
    };
  }
}

/** The instance app.ts and server.ts use, configured from the environment. */
export const trustedProxies = new TrustedProxies({
  spec: process.env.TRUSTED_PROXIES,
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
