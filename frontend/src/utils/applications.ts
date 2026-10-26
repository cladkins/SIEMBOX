/**
 * Pure helpers for the Application Monitoring page (views/ApplicationMonitoring.vue):
 * labels for evidence sources and locations, version order and drift, deep
 * links to the pages the inventory points at. No Vue, no network: unit-tested
 * in applications.test.ts.
 */

export type InventorySource =
  | 'syslog_program'
  | 'parser'
  | 'service_scan'
  | 'container'
  | 'edr_package'
  | 'endpoint_sbom'
  | 'os'
  | 'user_agent'
  | 'dns';

export interface VersionCount {
  version: string;
  locations: number;
  last_seen: string;
}

export interface ApplicationRow {
  id: string;
  name: string;
  vendor: string;
  category: string;
  sources: InventorySource[];
  hosts: number;
  clients: number;
  versions: VersionCount[];
  latest_version: string | null;
  drift: boolean;
  unmanaged: boolean;
  vulnerabilities: { total: number; exact: number; critical: number; high: number };
  events: number;
  first_seen: string | null;
  last_seen: string | null;
}

export const SOURCE_LABELS: Record<InventorySource, { label: string; hint: string }> = {
  syslog_program: { label: 'Log program', hint: 'The program name in its syslog lines' },
  parser: { label: 'Parser', hint: 'A catalog parser for it matched the logs' },
  service_scan: { label: 'Service scan', hint: 'An nmap service on an asset' },
  container: { label: 'Container', hint: "A log shipper reported the image on its host" },
  edr_package: { label: 'Vulnerable package', hint: "The endpoint agent's vulnerability scan found the package with an open finding" },
  endpoint_sbom: { label: 'Installed package', hint: "The package is in the endpoint agent's list of installed software" },
  os: { label: 'Endpoint OS', hint: 'The operating system an endpoint agent reports' },
  user_agent: { label: 'User agent', hint: 'A client sent it as its user agent (web and proxy logs)' },
  dns: { label: 'DNS', hint: 'A client looked up its domains (DNS logs)' },
};

export const SOURCE_ORDER: InventorySource[] = ['syslog_program', 'parser', 'service_scan', 'container', 'edr_package', 'endpoint_sbom', 'os', 'user_agent', 'dns'];

export function sourceLabel(source: string): string {
  return SOURCE_LABELS[source as InventorySource]?.label ?? source;
}

/** The evidence sources that only show the network using it (not a host of yours running it). */
export const NETWORK_SOURCES: InventorySource[] = ['user_agent', 'dns'];

export function isNetworkOnly(sources: string[]): boolean {
  return sources.length > 0 && sources.every((s) => (NETWORK_SOURCES as string[]).includes(s));
}

/** Version order: numeric runs as numbers ("1.10" > "1.9", "8.9p1" > "8.4p1"). Same as the backend's compareVersions. */
export function compareVersions(a: string, b: string): number {
  const pa = a.split(/[^0-9A-Za-z]+/).filter(Boolean);
  const pb = b.split(/[^0-9A-Za-z]+/).filter(Boolean);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i];
    const y = pb[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const nx = /^\d+$/.test(x);
    const ny = /^\d+$/.test(y);
    if (nx && ny) {
      const d = Number(x) - Number(y);
      if (d !== 0) return d < 0 ? -1 : 1;
    } else if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

export function sortVersions<T extends { version: string }>(versions: T[]): T[] {
  return [...versions].sort((a, b) => compareVersions(a.version, b.version));
}

/** Is this version behind the newest one seen? (Highlighted as drift.) */
export function isBehind(version: string, latest: string | null): boolean {
  return latest !== null && compareVersions(version, latest) < 0;
}

/** Locations not on the newest version, for the drift view. */
export function locationsBehind(app: Pick<ApplicationRow, 'versions' | 'latest_version'>): number {
  return app.versions.filter((v) => isBehind(v.version, app.latest_version)).reduce((n, v) => n + v.locations, 0);
}

/** Drift view order: most locations behind first, then the most versions, then name. */
export function driftOrder(apps: ApplicationRow[]): ApplicationRow[] {
  return apps
    .filter((a) => a.drift)
    .sort((a, b) => locationsBehind(b) - locationsBehind(a) || b.versions.length - a.versions.length || a.name.localeCompare(b.name));
}

/** "3 hosts, 12 clients" / "1 host" / "—". */
export function whereLabel(app: Pick<ApplicationRow, 'hosts' | 'clients'>): string {
  const parts: string[] = [];
  if (app.hosts) parts.push(`${app.hosts} ${app.hosts === 1 ? 'host' : 'hosts'}`);
  if (app.clients) parts.push(`${app.clients} ${app.clients === 1 ? 'client' : 'clients'}`);
  return parts.length ? parts.join(', ') : '—';
}

export const LOCATION_TYPE_LABELS: Record<string, string> = {
  host: 'Logging host',
  asset: 'Asset',
  shipper: 'Container host',
  client: 'Network client',
};

/** "10 categories" style humanizing of a category slug: "reverse-proxy" -> "Reverse proxy". */
export function categoryLabel(category: string): string {
  const special: Record<string, string> = { saas: 'SaaS', dns: 'DNS', vpn: 'VPN', 'http-client': 'HTTP client', 'os-component': 'OS component' };
  if (special[category]) return special[category];
  const s = category.replace(/-/g, ' ');
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** Logs page filtered to the evidence: a raw log's program, or a client/host IP. */
export function logsLink(evidence: { value?: unknown } | null | undefined, source: string, locKey: string): { path: string; query: Record<string, string> } | null {
  const value = typeof evidence?.value === 'string' ? evidence.value : '';
  if (source === 'syslog_program' && value) return { path: '/logs', query: { app_name: value, tab: 'raw', range: '7d' } };
  if ((source === 'user_agent' || source === 'dns') && /^[0-9a-f.:]+$/i.test(locKey)) return { path: '/logs', query: { source_ip: locKey, tab: 'parsed', range: '7d' } };
  if (source === 'parser' && /^[0-9a-f.:]+$/i.test(locKey)) return { path: '/logs', query: { source_ip: locKey, tab: 'parsed', range: '7d' } };
  return null;
}

/** Vulnerability Management filtered to one CVE. */
export function vulnerabilityLink(cveId: string): { path: string; query: Record<string, string> } {
  return { path: '/vulnerability-management', query: { search: cveId } };
}

/** Days since an ISO time, for "last seen 3 d ago". */
export function ageLabel(iso: string | null, now: number = Date.now()): string {
  if (!iso) return '—';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '—';
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 90) return 'just now';
  if (s < 90 * 60) return `${Math.round(s / 60)} min ago`;
  if (s < 36 * 3600) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}

/** Where the signatures come from, in words, for the page's status line. */
export function signatureSourceText(source: string | null, count: number): string {
  switch (source) {
    case 'catalog':
      return `${count} signatures from the catalog`;
    case 'cache':
      return `${count} signatures from the last catalog read (the catalog is unreachable)`;
    case 'stored':
      return `${count} signatures stored from an earlier catalog read (the catalog is unreachable)`;
    case 'bundled':
      return `${count} built-in starter signatures (the catalog has none or is unreachable)`;
    default:
      return 'signatures not loaded yet';
  }
}

/** Client-side filter of the list by the page's text box (the server filters too; this keeps typing instant). */
export function matchesSearch(app: Pick<ApplicationRow, 'name' | 'vendor' | 'id' | 'category'>, text: string): boolean {
  const q = text.trim().toLowerCase();
  if (!q) return true;
  return [app.name, app.vendor, app.id, app.category].some((v) => v.toLowerCase().includes(q));
}
