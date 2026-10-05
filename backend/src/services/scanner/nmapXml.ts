/**
 * Parse raw nmap XML (`nmap -oX -`) into the same host-object shape the
 * in-process scanner feeds to NmapScanner.processScanResults.
 *
 * Why this exists: when a scan is dispatched to a log shipper (see migration
 * 032), the shipper runs nmap out on the LAN and posts its raw XML back. The
 * backend parses it here and ingests it through the exact same code path as a
 * locally-run scan, so a shipper-run scan and a backend-run scan of the same
 * target produce identical assets and services.
 *
 * This deliberately mirrors node-nmap's own convertRawJsonToScanResults
 * (node_modules/node-nmap/index.js) field-for-field -- same xml2js options,
 * same host shape {hostname, ip, mac, vendor, openPorts, osNmap}, same
 * open-ports-only filter, even the same quirk where a port's `product` is read
 * from the service's `tunnel` attribute. Matching it exactly is the point: the
 * two scan paths must not diverge. If node-nmap's mapping is ever corrected,
 * correct it here in the same change.
 */
import { parseStringPromise } from 'xml2js';

export interface NmapPort {
  port?: number;
  protocol?: string;
  service?: string;
  tunnel?: string;
  method?: string;
  product?: string;
}

export interface NmapHost {
  hostname: string | null;
  ip: string | null;
  mac: string | null;
  vendor?: string;
  openPorts: NmapPort[] | null;
  osNmap: string | null;
}

/** Shape xml2js produces from nmap XML (only the bits we read). */
interface RawNmap {
  nmaprun?: {
    host?: RawHost[];
  };
}
interface RawAttr {
  $: Record<string, string>;
}
interface RawHost {
  hostnames?: Array<{ hostname?: RawAttr[] } | string>;
  address: RawAttr[];
  ports?: Array<{ port?: RawPort[] }>;
  os?: Array<{ osmatch?: RawAttr[] }>;
}
interface RawPort {
  $: { portid: string; protocol: string };
  state: RawAttr[];
  service: RawAttr[];
}

/**
 * Parse an nmap XML document into host objects. Returns [] for XML with no
 * hosts (a scan that found nothing). Rejects only on malformed XML.
 */
export async function parseNmapXml(xml: string): Promise<NmapHost[]> {
  const raw = (await parseStringPromise(xml)) as RawNmap;
  const hosts = raw?.nmaprun?.host;
  if (!Array.isArray(hosts)) return [];

  return hosts.map((host): NmapHost => {
    const newHost: NmapHost = { hostname: null, ip: null, mac: null, openPorts: null, osNmap: null };

    // Hostname -- node-nmap guards against the "\r\n"/"\n" whitespace-only
    // entries xml2js can leave in place of an empty <hostnames/> element.
    const firstHostname = host.hostnames?.[0];
    if (
      firstHostname &&
      firstHostname !== '\r\n' &&
      firstHostname !== '\n' &&
      typeof firstHostname === 'object' &&
      firstHostname.hostname?.[0]?.$?.name
    ) {
      newHost.hostname = firstHostname.hostname[0].$.name;
    }

    // Addresses: ipv4 -> ip, mac -> mac (+ vendor).
    for (const address of host.address ?? []) {
      const type = address.$.addrtype;
      if (type === 'ipv4') {
        newHost.ip = address.$.addr;
      } else if (type === 'mac') {
        newHost.mac = address.$.addr;
        if (address.$.vendor) newHost.vendor = address.$.vendor;
      }
    }

    // Ports: open ones only.
    const portList = host.ports?.[0]?.port;
    if (Array.isArray(portList)) {
      newHost.openPorts = portList
        .filter((p) => p.state?.[0]?.$?.state === 'open')
        .map((portItem): NmapPort => {
          const svc = portItem.service?.[0]?.$ ?? {};
          const port = parseInt(portItem.$.portid, 10);
          const out: NmapPort = {};
          if (port) out.port = port;
          if (portItem.$.protocol) out.protocol = portItem.$.protocol;
          if (svc.name) out.service = svc.name;
          if (svc.tunnel) out.tunnel = svc.tunnel;
          if (svc.method) out.method = svc.method;
          // Mirrors node-nmap: `product` is taken from the service's `tunnel`
          // attribute (its quirk -- kept identical so both scan paths agree).
          if (svc.tunnel) out.product = svc.tunnel;
          return out;
        });
    }

    // OS match (best guess).
    const osName = host.os?.[0]?.osmatch?.[0]?.$?.name;
    if (osName) newHost.osNmap = osName;

    return newHost;
  });
}
