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

export interface ScopeResult {
  cidrs: string[];
  warning: string | null;
  rejected: string[]; // manually-entered CIDRs that failed validation
}

/**
 * Resolve the full scan scope: auto-detected local CIDRs plus any valid
 * manually-entered ones, deduped. Invalid manual entries are reported back
 * rather than silently dropped, so the UI can flag the typo.
 */
export function resolveScope(manualCidrs: string[] = [], interfaces: LocalInterface[] = detectLocalInterfaces()): ScopeResult {
  const rejected = manualCidrs.filter((c) => !isValidCidr(c));
  const validManual = manualCidrs.filter((c) => isValidCidr(c));
  const auto = interfaces.map((i) => i.cidr);
  const cidrs = Array.from(new Set([...auto, ...validManual]));

  return { cidrs, warning: vlanWarning(interfaces), rejected };
}
