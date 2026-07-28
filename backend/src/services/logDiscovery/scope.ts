// Module 1: scope. Detects the SIEMBOX host's local subnet(s), warns when the
// host is single-homed (the most common homelab discovery gap -- see
// CLAUDE.md/spec), and accepts a manual CIDR list for multi-VLAN setups.
import * as os from 'os';

export interface LocalInterface {
  name: string;
  address: string;
  netmask: string;
  cidr: string;
}

function netmaskToPrefixLength(netmask: string): number {
  return netmask
    .split('.')
    .reduce((bits, octet) => bits + ((parseInt(octet, 10).toString(2).match(/1/g) || []).length), 0);
}

function networkAddress(address: string, netmask: string): string {
  const addrOctets = address.split('.').map(Number);
  const maskOctets = netmask.split('.').map(Number);
  return addrOctets.map((o, i) => o & maskOctets[i]).join('.');
}

export function toCidr(address: string, netmask: string): string {
  return `${networkAddress(address, netmask)}/${netmaskToPrefixLength(netmask)}`;
}

/**
 * Every non-internal IPv4 interface on the SIEMBOX host, as a CIDR. In a
 * container this reflects whatever network the container itself was attached
 * to -- typically just one subnet, which is exactly the gap this module warns about.
 */
export function detectLocalInterfaces(interfaces: NodeJS.Dict<os.NetworkInterfaceInfo[]> = os.networkInterfaces()): LocalInterface[] {
  const result: LocalInterface[] = [];
  for (const [name, addrs] of Object.entries(interfaces)) {
    for (const addr of addrs || []) {
      if (addr.family === 'IPv4' && !addr.internal) {
        result.push({
          name,
          address: addr.address,
          netmask: addr.netmask,
          cidr: (addr as any).cidr || toCidr(addr.address, addr.netmask),
        });
      }
    }
  }
  return result;
}

/** Non-null only when the host looks single-homed and other gear likely lives on a different VLAN. */
export function vlanWarning(interfaces: LocalInterface[]): string | null {
  const uniqueSubnets = new Set(interfaces.map((i) => i.cidr));
  if (uniqueSubnets.size <= 1) {
    return 'SIEMBOX only sees its own subnet by default. If your homelab spans more than one VLAN or subnet, add their CIDRs manually or this scan will miss them.';
  }
  return null;
}

const CIDR_PATTERN = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d|[12]\d|3[0-2])$/;

export function isValidCidr(cidr: string): boolean {
  const match = CIDR_PATTERN.exec(cidr.trim());
  if (!match) return false;
  return match.slice(1, 5).every((octet) => Number(octet) <= 255);
}

/** Roughly a /22 -- big enough for "another VLAN", small enough that a manual CIDR sweep stays bounded, never a de facto full-range scan. */
export const MAX_SWEEP_HOSTS = 1024;

function cidrSize(cidr: string): number {
  const prefix = parseInt(cidr.split('/')[1], 10);
  return Math.pow(2, 32 - prefix);
}

/** Syntactically valid AND small enough to actively sweep host-by-host. */
export function isSweepableCidr(cidr: string): boolean {
  return isValidCidr(cidr) && cidrSize(cidr.trim()) <= MAX_SWEEP_HOSTS;
}

function ipToInt(ip: string): number {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + Number(octet), 0) >>> 0;
}

function intToIp(n: number): string {
  return [24, 16, 8, 0].map((shift) => (n >>> shift) & 0xff).join('.');
}

/**
 * Every usable host address in a CIDR (network + broadcast excluded, except
 * for /31 and /32 where there's no such concept -- RFC 3021 / a single host).
 * Only meaningful for CIDRs that pass isSweepableCidr; larger ranges are
 * rejected before this is ever called.
 */
export function cidrHosts(cidr: string): string[] {
  const [base, prefixStr] = cidr.trim().split('/');
  const prefix = parseInt(prefixStr, 10);
  const hostBits = 32 - prefix;
  const size = Math.pow(2, hostBits);
  const networkInt = hostBits === 0 ? ipToInt(base) : ((ipToInt(base) >>> hostBits) << hostBits) >>> 0;

  const start = prefix >= 31 ? 0 : 1;
  const end = prefix >= 31 ? size - 1 : size - 2;

  const hosts: string[] = [];
  for (let i = start; i <= end; i++) {
    hosts.push(intToIp((networkInt + i) >>> 0));
  }
  return hosts;
}

export interface ScopeResult {
  cidrs: string[];
  warning: string | null;
  rejected: string[]; // manually-entered CIDRs that failed validation (malformed, or larger than MAX_SWEEP_HOSTS)
}

/**
 * Resolve the full scan scope: valid, sweepably-sized manually-entered CIDRs,
 * deduped. Invalid or too-large entries are reported back rather than
 * silently dropped, so the UI can flag the problem.
 *
 * Deliberately excludes the auto-detected local interface CIDR from `cidrs`.
 * It's still used for the VLAN warning below, but surfacing it as a "scope"
 * is misleading -- in the common Docker Compose deployment it's just the
 * container's own bridge network (e.g. 172.20.0.0/16), not the user's LAN.
 * Manual CIDRs are what actually get swept by active discovery (see
 * activeDiscovery.ts's sweepCidr) to find real LAN hosts passive discovery's
 * ARP/mDNS/SSDP techniques can't see from inside the container's own bridge.
 */
export function resolveScope(manualCidrs: string[] = [], interfaces: LocalInterface[] = detectLocalInterfaces()): ScopeResult {
  const rejected = manualCidrs.filter((c) => !isSweepableCidr(c));
  const cidrs = Array.from(new Set(manualCidrs.filter((c) => isSweepableCidr(c))));

  return { cidrs, warning: vlanWarning(interfaces), rejected };
}
