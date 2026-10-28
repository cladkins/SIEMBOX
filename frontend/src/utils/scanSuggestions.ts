/**
 * Suggested scans (catalog scans/<id>.scan.yaml, GET /api/scan-suggestions):
 * labels, filtering and the human summaries the "Suggested scans" browser
 * shows. The backend validates and creates; nothing here decides what a
 * suggestion may contain (backend/src/services/scanSuggestions/scanFormat.ts).
 */
import { describeSchedule, type CalendarSchedule } from './scheduleTiming.ts';
import { describeSpec, type ScanSpec } from './scanPolicies.ts';

export type SuggestionKind = 'asset' | 'vulnerability' | 'container' | 'log_discovery' | 'endpoint_policy';

export interface SuggestionInput {
  field: string;
  required: boolean;
  label: string | null;
  hint: string | null;
}

export interface ScanSuggestion {
  id: string;
  name: string;
  kind: SuggestionKind;
  category: string;
  tags: string[];
  description: string;
  why: string;
  intrusive: boolean;
  intrusive_note: string | null;
  load: 'light' | 'moderate' | 'heavy';
  schedule: Omit<CalendarSchedule, 'timezone'> | null;
  options: Record<string, any>;
  inputs: SuggestionInput[];
}

export interface ScanSuggestionCatalog {
  source: 'catalog' | 'cache' | 'bundled';
  repo: string;
  ref: string;
  suggestions: ScanSuggestion[];
  invalid: Array<{ path: string; errors: string[] }>;
  fetched_at: string | null;
  error: string | null;
}

export const KIND_LABELS: Record<SuggestionKind, string> = {
  asset: 'Asset discovery (Nmap)',
  vulnerability: 'Vulnerability (Nuclei)',
  container: 'Container image (Trivy)',
  log_discovery: 'Log discovery',
  endpoint_policy: 'Endpoint scan policy',
};

export const KIND_SHORT: Record<SuggestionKind, string> = {
  asset: 'Asset',
  vulnerability: 'Vulnerability',
  container: 'Container',
  log_discovery: 'Log discovery',
  endpoint_policy: 'Endpoint policy',
};

export const CATEGORY_LABELS: Record<string, string> = {
  inventory: 'Inventory',
  services: 'Services',
  cves: 'CVEs',
  exposure: 'Exposure',
  misconfiguration: 'Misconfiguration',
  credentials: 'Default credentials',
  tls: 'TLS',
  dns: 'DNS',
  containers: 'Containers',
  'log-sources': 'Log sources',
  endpoints: 'Endpoints',
};

export const INPUT_LABELS: Record<string, string> = {
  targets: 'Targets (IPs or CIDRs)',
  target: 'Target (host, IP or CIDR)',
  image_ref: 'Image reference',
  cidrs: 'Subnets',
  shipper: 'Log shipper to run from',
  endpoints: 'Endpoints to assign',
};

export function categoryLabel(c: string): string {
  return CATEGORY_LABELS[c] ?? c;
}

export interface SuggestionFilter {
  kind?: SuggestionKind | '';
  category?: string;
  query?: string;
  /** Only these kinds (e.g. the Endpoints page shows endpoint policies only). */
  kinds?: SuggestionKind[] | null;
}

/** The suggestions matching the filters, in the order given. */
export function filterSuggestions(list: ScanSuggestion[], f: SuggestionFilter): ScanSuggestion[] {
  const q = (f.query ?? '').trim().toLowerCase();
  return list.filter((s) => {
    if (f.kinds && f.kinds.length > 0 && !f.kinds.includes(s.kind)) return false;
    if (f.kind && s.kind !== f.kind) return false;
    if (f.category && s.category !== f.category) return false;
    if (!q) return true;
    return [s.name, s.description, s.why, s.category, ...s.tags].some((t) => t.toLowerCase().includes(q));
  });
}

/** The categories present in a list, in first-seen order. */
export function categoriesOf(list: ScanSuggestion[]): string[] {
  return [...new Set(list.map((s) => s.category))];
}

/** "Daily at 02:30 (America/Chicago)": the schedule in the zone it will be added in. */
export function describeSuggestionSchedule(s: ScanSuggestion, timezone: string): string {
  if (!s.schedule) return 'Each scan type has its own timing';
  return describeSchedule({ schedule: { ...s.schedule, timezone } as CalendarSchedule });
}

const SCAN_TYPE_TEXT: Record<string, string> = {
  ping: 'Ping sweep (-sn, no ports)',
  port: 'TCP connect scan, ports 1-1000',
  service: 'Service and version detection, ports 1-1000',
  os: 'OS and version detection (needs raw-socket privileges)',
};

const MODE_TEXT: Record<string, string> = {
  passive: 'Passive: listens only, no packets to hosts',
  active: 'Active: probes hosts on fingerprinted ports and paths',
  full: 'Full: passive, then active',
};

const POLICY_TYPES: Array<[string, string]> = [
  ['vuln', 'Vulnerabilities'],
  ['yara', 'YARA'],
  ['packages', 'Packages'],
  ['inventory', 'System inventory'],
];

/** The options as lines a person can read ("Templates: tags kev; excluding intrusive, dos, fuzz"). */
export function describeOptions(s: ScanSuggestion, timezone: string): string[] {
  const o = s.options ?? {};
  if (s.kind === 'asset') return [SCAN_TYPE_TEXT[o.scanType] ?? String(o.scanType)];
  if (s.kind === 'log_discovery') return [MODE_TEXT[o.mode] ?? String(o.mode)];
  if (s.kind === 'container') return [o.all_images ? 'Every discovered image (SIEMBox host and log shipper hosts)' : 'One image you name'];
  if (s.kind === 'vulnerability') {
    const sel = o.templateSelection ?? {};
    const lines: string[] = [];
    if (sel.all) lines.push('Templates: all');
    if (sel.cves) lines.push('Templates: CVEs');
    if (sel.tags?.length) lines.push(`Templates tagged: ${sel.tags.join(', ')}`);
    if (sel.templates?.length) lines.push(`Templates: ${sel.templates.join(', ')}`);
    if (sel.severities?.length) lines.push(`Severities: ${sel.severities.join(', ')}`);
    if (sel.excludeTags?.length) lines.push(`Excluding tags: ${sel.excludeTags.join(', ')}`);
    if (o.rateLimit) lines.push(`Rate limit: ${o.rateLimit} requests/second`);
    if (o.timeout) lines.push(`Timeout: ${Math.round(o.timeout / 60000)} minutes`);
    return lines;
  }
  const scans = o.scans ?? {};
  return POLICY_TYPES.map(([key, label]) => {
    const entry = scans[key] as Partial<ScanSpec> | undefined;
    if (!entry) return `${label}: -`;
    const spec: ScanSpec = {
      enabled: entry.enabled ?? false,
      schedule: entry.schedule ? ({ ...entry.schedule, timezone } as ScanSpec['schedule']) : null,
      interval_minutes: entry.interval_minutes ?? null,
      window: entry.window ? { ...entry.window, timezone } : null,
    } as ScanSpec;
    return `${label}: ${describeSpec(spec)}`;
  });
}

/** What the person fills in after adding: "Targets (IPs or CIDRs); optional: Log shipper to run from". */
export function describeInputs(s: ScanSuggestion): string {
  const required = s.inputs.filter((i) => i.required).map((i) => i.label || INPUT_LABELS[i.field] || i.field);
  const optional = s.inputs.filter((i) => !i.required).map((i) => i.label || INPUT_LABELS[i.field] || i.field);
  if (required.length === 0 && optional.length === 0) return 'Nothing: enable it as it is';
  return [required.join(', '), optional.length ? `optional: ${optional.join(', ')}` : ''].filter(Boolean).join('; ');
}

export function loadTag(load: ScanSuggestion['load']): 'success' | 'warning' | 'danger' {
  return load === 'light' ? 'success' : load === 'moderate' ? 'warning' : 'danger';
}

/** Missing inputs on a schedule row, as the list's badge text ("Needs targets"). */
export function missingInputsText(missing: string[] | undefined | null): string {
  if (!missing || missing.length === 0) return '';
  const names = missing.map((m) => (m === 'image_ref' ? 'an image' : m === 'target' ? 'a target' : m));
  return `Needs ${names.join(', ')}`;
}
