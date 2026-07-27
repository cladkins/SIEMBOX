// Module 2, passive phase: zero packets to targets. ARP table read, mDNS listen,
// SSDP listen, DHCP lease parse, LLDP capture when available.
//
// Parsing logic is split out as pure functions so it's unit-testable against
// fixture text; the live network/exec calls around them are thin wrappers that
// this sandboxed environment cannot itself exercise against real hardware.
import * as dgram from 'dgram';
import * as fs from 'fs';
import { exec } from 'child_process';
import { promisify } from 'util';
import { logger } from '../../utils/logger';

const execAsync = promisify(exec);

export interface ArpEntry {
  ip: string;
  mac: string;
}

/** Parse Linux's /proc/net/arp. Skips incomplete entries (flags 0x0 -- no reply yet). */
export function parseProcNetArp(content: string): ArpEntry[] {
  const lines = content.trim().split('\n').slice(1); // drop header row
  const entries: ArpEntry[] = [];
  for (const line of lines) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 4) continue;
    const [ip, , flags, mac] = cols;
    if (flags === '0x0' || mac === '00:00:00:00:00:00') continue;
    entries.push({ ip, mac: mac.toLowerCase() });
  }
  return entries;
}

/** Parse `arp -a` output (Linux/macOS/BSD variants all include "(ip) at mac"). */
export function parseArpCommandOutput(content: string): ArpEntry[] {
  const entries: ArpEntry[] = [];
  const pattern = /\(([\d.]+)\)\s+at\s+([0-9a-fA-F:]{11,17})/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(content))) {
    entries.push({ ip: match[1], mac: match[2].toLowerCase() });
  }
  return entries;
}

/** Read the local ARP cache. Zero packets sent -- just reads the kernel's existing table. */
export async function readArpTable(): Promise<ArpEntry[]> {
  try {
    const content = await fs.promises.readFile('/proc/net/arp', 'utf8');
    return parseProcNetArp(content);
  } catch {
    // Not Linux, or /proc unavailable in this container -- fall back to the arp binary.
  }
  try {
    const { stdout } = await execAsync('arp -a');
    return parseArpCommandOutput(stdout);
  } catch (err: any) {
    logger.warn(`[logDiscovery] ARP table read failed: ${err?.message || err}`);
    return [];
  }
}

export interface DhcpLease {
  ip: string;
  mac: string;
  hostname?: string;
}

const DNSMASQ_LEASE_PATHS = ['/var/lib/misc/dnsmasq.leases', '/var/db/dnsmasq.leases'];
const ISC_DHCPD_LEASE_PATHS = ['/var/lib/dhcp/dhcpd.leases', '/var/db/dhcpd.leases'];

/** dnsmasq lease line: "<expiry-epoch> <mac> <ip> <hostname> <client-id>". */
export function parseDnsmasqLeases(content: string): DhcpLease[] {
  const leases: DhcpLease[] = [];
  for (const line of content.trim().split('\n')) {
    if (!line.trim()) continue;
    const cols = line.trim().split(/\s+/);
    if (cols.length < 4) continue;
    const [, mac, ip, hostname] = cols;
    if (!/^[0-9a-fA-F:]{17}$/.test(mac)) continue;
    leases.push({ ip, mac: mac.toLowerCase(), hostname: hostname === '*' ? undefined : hostname });
  }
  return leases;
}

/** isc-dhcp-server lease blocks: "lease <ip> { ... hardware ethernet <mac>; ... client-hostname \"<name>\"; ... }". Later blocks win on repeat IPs (the file is append-only history). */
export function parseIscDhcpdLeases(content: string): DhcpLease[] {
  const byIp = new Map<string, DhcpLease>();
  const blockPattern = /lease\s+([\d.]+)\s*\{([^}]*)\}/g;
  let match: RegExpExecArray | null;
  while ((match = blockPattern.exec(content))) {
    const [, ip, body] = match;
    const mac = /hardware ethernet\s+([0-9a-fA-F:]{17});/.exec(body)?.[1];
    const hostname = /client-hostname\s+"([^"]*)";/.exec(body)?.[1];
    if (mac) byIp.set(ip, { ip, mac: mac.toLowerCase(), hostname });
  }
  return Array.from(byIp.values());
}

/** Parse whichever DHCP lease file is reachable, if any. Returns [] rather than throwing when none is. */
export async function readDhcpLeases(): Promise<DhcpLease[]> {
  for (const path of DNSMASQ_LEASE_PATHS) {
    try {
      return parseDnsmasqLeases(await fs.promises.readFile(path, 'utf8'));
    } catch {
      /* try next */
    }
  }
  for (const path of ISC_DHCPD_LEASE_PATHS) {
    try {
      return parseIscDhcpdLeases(await fs.promises.readFile(path, 'utf8'));
    } catch {
      /* try next */
    }
  }
  return [];
}

// --- mDNS -------------------------------------------------------------------

const MDNS_MULTICAST_ADDR = '224.0.0.251';
const MDNS_PORT = 5353;

/** Encode a minimal single-question DNS/mDNS query for `${name}` (PTR, class IN). */
export function buildMdnsQuery(name: string): Buffer {
  const header = Buffer.alloc(12); // id=0, flags=0 (standard query), qdcount=1, an/ns/arcount=0
  header.writeUInt16BE(1, 4);

  const labels = name.replace(/\.$/, '').split('.');
  const qnameParts = labels.map((label) => Buffer.concat([Buffer.from([label.length]), Buffer.from(label, 'ascii')]));
  const qname = Buffer.concat([...qnameParts, Buffer.from([0])]);

  const qtypeQclass = Buffer.alloc(4);
  qtypeQclass.writeUInt16BE(12, 0); // PTR
  qtypeQclass.writeUInt16BE(1, 2); // IN

  return Buffer.concat([header, qname, qtypeQclass]);
}

/** True when a DNS/mDNS message's QR bit marks it as a response rather than a query. */
export function isDnsResponse(buf: Buffer): boolean {
  if (buf.length < 4) return false;
  return (buf.readUInt16BE(2) & 0x8000) !== 0;
}

export interface MdnsResponder {
  ip: string;
  service: string;
}

/**
 * Query each declared mDNS service in turn and record which hosts answered
 * within the listen window. Best-effort: a host that replies just outside the
 * window for one service, or on a network that blocks multicast, is missed --
 * that's why discovery also has the active phase.
 */
export async function queryMdnsServices(services: string[], opts: { listenMs?: number } = {}): Promise<MdnsResponder[]> {
  const listenMs = opts.listenMs ?? 800;
  const responders: MdnsResponder[] = [];

  for (const service of services) {
    const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    try {
      await new Promise<void>((resolve) => {
        socket.on('message', (msg, rinfo) => {
          if (isDnsResponse(msg)) responders.push({ ip: rinfo.address, service });
        });
        socket.on('error', (err) => {
          logger.warn(`[logDiscovery] mDNS query for ${service} failed: ${err.message}`);
          resolve();
        });
        socket.bind(0, () => {
          socket.send(buildMdnsQuery(`${service}.local`), MDNS_PORT, MDNS_MULTICAST_ADDR);
          setTimeout(resolve, listenMs);
        });
      });
    } finally {
      socket.close();
    }
  }

  return responders;
}

// --- SSDP --------------------------------------------------------------------

const SSDP_MULTICAST_ADDR = '239.255.255.250';
const SSDP_PORT = 1900;

export function buildSsdpSearchRequest(searchTarget = 'ssdp:all', mxSeconds = 2): string {
  return [
    'M-SEARCH * HTTP/1.1',
    `HOST: ${SSDP_MULTICAST_ADDR}:${SSDP_PORT}`,
    'MAN: "ssdp:discover"',
    `MX: ${mxSeconds}`,
    `ST: ${searchTarget}`,
    '',
    '',
  ].join('\r\n');
}

/** SSDP responses are plain HTTP-style header text over UDP. */
export function parseSsdpResponse(raw: string): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const line of raw.split('\r\n').slice(1)) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    if (key) headers[key] = value;
  }
  return headers;
}

export interface SsdpResponder {
  ip: string;
  st?: string;
  server?: string;
}

export async function discoverSsdp(opts: { listenMs?: number; searchTarget?: string } = {}): Promise<SsdpResponder[]> {
  const listenMs = opts.listenMs ?? 2000;
  const responders: SsdpResponder[] = [];
  const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });

  try {
    await new Promise<void>((resolve) => {
      socket.on('message', (msg, rinfo) => {
        const headers = parseSsdpResponse(msg.toString('utf8'));
        responders.push({ ip: rinfo.address, st: headers.st, server: headers.server });
      });
      socket.on('error', (err) => {
        logger.warn(`[logDiscovery] SSDP discovery failed: ${err.message}`);
        resolve();
      });
      socket.bind(0, () => {
        socket.setBroadcast(true);
        socket.send(Buffer.from(buildSsdpSearchRequest(opts.searchTarget)), SSDP_PORT, SSDP_MULTICAST_ADDR);
        setTimeout(resolve, listenMs);
      });
    });
  } finally {
    socket.close();
  }

  return responders;
}

// --- LLDP ---------------------------------------------------------------------

/**
 * LLDP requires raw 802.1AB frame capture (a privileged raw socket / pcap
 * binding), which isn't available to a plain Node process without native
 * dependencies. Same "degrade gracefully" pattern as the endpoint agent's
 * optional tools: skip cleanly and let the rest of discovery keep running.
 */
export async function captureLldp(): Promise<ArpEntry[]> {
  logger.info('[logDiscovery] LLDP capture skipped: requires raw packet access not available in this deployment.');
  return [];
}
