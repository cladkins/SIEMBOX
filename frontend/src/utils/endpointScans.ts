/**
 * Endpoint scan history and on-demand scans (Endpoints page): labels, status
 * tags, the one-line summary per scan type, and the role check for requesting
 * scans. Pure, so it is unit-tested (endpointScans.test.ts).
 * Server side: backend/src/services/edr/edrScans.ts.
 */

export type ScanType = 'vuln' | 'yara' | 'packages' | 'inventory';
export type ScanStatus = 'pending' | 'running' | 'succeeded' | 'failed' | 'cancelled' | 'expired';

export interface ScanRow {
  id: string;
  scan_type: ScanType;
  trigger: 'schedule' | 'startup' | 'console';
  requested_by_username?: string | null;
  requested_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  duration_ms?: number | null;
  status: ScanStatus;
  summary?: Record<string, number | boolean | string> | null;
  error?: string | null;
}

export const SCAN_TYPES: { value: ScanType; label: string }[] = [
  { value: 'vuln', label: 'Vulnerability scan (grype)' },
  { value: 'yara', label: 'YARA file scan' },
  { value: 'packages', label: 'Package inventory' },
  { value: 'inventory', label: 'System inventory' },
];

/** Endpoints one "Scan selected" may name (BULK_SCAN_MAX_AGENTS on the server). */
export const BULK_SCAN_MAX = 200;

/** First agent release that runs on-demand scans (MIN_ADHOC_AGENT_VERSION on the server). */
export const MIN_ADHOC_AGENT_VERSION = '0.0.20';

const SHORT: Record<ScanType, string> = {
  vuln: 'Vulnerabilities',
  yara: 'YARA',
  packages: 'Packages',
  inventory: 'Inventory',
};

export function scanTypeLabel(t: string): string {
  return SHORT[t as ScanType] ?? t;
}

export function triggerLabel(t: string): string {
  if (t === 'console') return 'on demand';
  if (t === 'schedule') return 'scheduled';
  return t;
}

/** Element Plus tag type for a status. */
export function scanStatusTag(status: string): 'success' | 'danger' | 'warning' | 'info' | 'primary' {
  switch (status) {
    case 'succeeded':
      return 'success';
    case 'failed':
      return 'danger';
    case 'expired':
      return 'warning';
    case 'running':
      return 'primary';
    default:
      return 'info';
  }
}

export function isActive(status: string): boolean {
  return status === 'pending' || status === 'running';
}

/** Whether any row is still pending or running (the history keeps refreshing while so). */
export function hasActiveScans(rows: Pick<ScanRow, 'status'>[]): boolean {
  return rows.some((r) => isActive(r.status));
}

/** Status text: a pending request on an offline agent says so. */
export function scanStatusText(row: Pick<ScanRow, 'status'>, agentOnline: boolean): string {
  if (row.status === 'pending' && !agentOnline) return 'queued — agent offline';
  if (row.status === 'pending') return 'queued';
  return row.status;
}

export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms) || ms < 0) return '—';
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

const n = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const plural = (count: number, one: string, many = `${one}s`) => `${count.toLocaleString()} ${count === 1 ? one : many}`;

/** One line for the history table's Summary column, by scan type. Empty when there is nothing to say. */
export function summarizeScan(row: Pick<ScanRow, 'scan_type' | 'summary'>): string {
  const s = row.summary ?? {};
  const parts: string[] = [];
  switch (row.scan_type) {
    case 'vuln': {
      const total = n(s.findings);
      if (total !== null) parts.push(plural(total, 'finding'));
      const fresh = n(s.new);
      if (fresh !== null) parts.push(`${fresh.toLocaleString()} new`);
      const resolved = n(s.resolved);
      if (resolved !== null) parts.push(`${resolved.toLocaleString()} no longer reported`);
      break;
    }
    case 'packages': {
      const total = n(s.packages);
      if (total !== null) parts.push(plural(total, 'package'));
      const added = n(s.added);
      const removed = n(s.removed);
      if (added !== null) parts.push(`+${added.toLocaleString()}`);
      if (removed !== null) parts.push(`−${removed.toLocaleString()}`);
      const unchanged = n(s.unchanged);
      if (unchanged !== null) parts.push(`${unchanged.toLocaleString()} unchanged`);
      break;
    }
    case 'yara': {
      const hits = n(s.hits);
      if (hits !== null) parts.push(plural(hits, 'hit'));
      const fresh = n(s.new_hits);
      if (fresh !== null && fresh !== hits) parts.push(`${fresh.toLocaleString()} new`);
      if (s.full === true) parts.push('full scan');
      else if (s.full === false) parts.push('changed files only');
      break;
    }
    case 'inventory': {
      if (s.changed === true) parts.push('changed');
      else if (s.changed === false) parts.push('no change');
      const sw = n(s.software);
      if (sw !== null) parts.push(plural(sw, 'program'));
      break;
    }
  }
  return parts.join(' · ');
}

/** Requesting scans: analysts and up. Viewers read the history only. */
export function canRequestScans(role: string | null | undefined): boolean {
  return role === 'admin' || role === 'operator' || role === 'analyst';
}

/** Whether the agent runs on-demand scans (it reports the capability in its heartbeat). */
export function supportsAdhocScans(agent: { capabilities?: string[] | null } | null | undefined): boolean {
  return Array.isArray(agent?.capabilities) && agent.capabilities.includes('adhoc_scans');
}
