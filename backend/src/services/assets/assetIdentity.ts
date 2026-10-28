/**
 * Identity facts for telling whether two asset rows are the same machine.
 * Pure: no database. Used by the endpoint-asset stickiness and automatic
 * merge (services/assets/assetMerge.ts, services/edr/edrService.ts) and by the
 * "Possible duplicates" hints on the asset detail.
 *
 * MAC addresses are stored as text (assets.mac_address VARCHAR(17)) in
 * whatever form the source sent: nmap reports "AA:BB:CC:DD:EE:FF", the
 * endpoint agent Go's net.HardwareAddr form "aa:bb:cc:dd:ee:ff". Compare them
 * through normalizeMac only.
 */
import { isIP } from 'net';

/** "aa:bb:cc:dd:ee:ff" for a 48-bit MAC in any common spelling, else null. */
export function normalizeMac(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const hex = value.trim().toLowerCase().replace(/[^0-9a-f]/g, '');
  // Only separators may be dropped: "aa:bb:cc:dd:ee:ff", "aa-bb-...", "aabb.ccdd.eeff", "aabbccddeeff".
  if (hex.length !== 12 || !/^[0-9a-f:.\-\s]+$/i.test(value.trim())) return null;
  return hex.match(/../g)!.join(':');
}

/**
 * A MAC that identifies one piece of hardware, so two rows sharing it are the
 * same machine: a well-formed, globally administered unicast address. Refused:
 * all zeros, broadcast, multicast (I/G bit), and locally administered ones
 * (U/L bit), which covers macOS/iOS/Android/Windows private ("random") Wi-Fi
 * addresses, VM and container bridges, and most VPN adapters, all of which
 * can repeat across machines or change per network.
 */
export function isUsableMac(value: unknown): boolean {
  const mac = normalizeMac(value);
  if (!mac) return false;
  if (mac === '00:00:00:00:00:00' || mac === 'ff:ff:ff:ff:ff:ff') return false;
  const first = parseInt(mac.slice(0, 2), 16);
  if (first & 0x01) return false; // multicast
  if (first & 0x02) return false; // locally administered (random/private)
  return true;
}

/** normalizeMac, but only for a usable (hardware-identifying) MAC. */
export function identifyingMac(value: unknown): string | null {
  return isUsableMac(value) ? normalizeMac(value) : null;
}

/**
 * The short host name, for "possible duplicate" hints only (never for an
 * automatic merge): lower case, no trailing dot, just the first DNS label, so
 * "Chriss-MBP-383.localdomain", "chriss-mbp-383.local" and
 * "chriss-mbp-383.tailcb24f.ts.net" all become "chriss-mbp-383". Null for an
 * empty name, an IP address, or a placeholder name too generic to suggest a
 * match ("localhost").
 */
export function shortHostname(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const name = value.trim().toLowerCase().replace(/\.+$/, '');
  if (!name || isIP(name)) return null;
  const first = name.split('.')[0];
  if (!first || GENERIC_HOSTNAMES.has(first)) return null;
  return first;
}

const GENERIC_HOSTNAMES = new Set(['localhost', 'unknown', 'host', 'computer', 'none', 'null', '(none)']);
