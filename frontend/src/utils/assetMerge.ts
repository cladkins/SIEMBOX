/**
 * Asset Inventory's "Merge into…" dialog and "Possible duplicates" hints:
 * which asset to keep by default, what the confirmation lists, and the
 * labels. The backend decides what a merge moves and does it
 * (POST /api/assets/:id/merge, backend/src/services/assets/assetMerge.ts).
 */

export interface MergeableAsset {
  id: number;
  ip_address: string;
  hostname?: string | null;
  last_seen?: string | null;
  discovery_method?: string | null;
  agent_count?: number;
}

export interface MergeCounts {
  vulnerabilities: number;
  vulnerabilities_combined: number;
  services: number;
  alerts: number;
  agents: number;
  application_locations: number;
  application_vuln_links: number;
}

export interface MergedAssetSummary {
  id: number;
  ip_address: string;
  hostname: string | null;
  mac_address: string | null;
  discovery_method: string | null;
  asset_type: string | null;
  open_vulnerabilities: number;
  agents: string[];
}

export interface MergeResult {
  into: { id: number; ip_address: string; hostname: string | null };
  merged: MergedAssetSummary[];
  moved: MergeCounts;
  dry_run: boolean;
  warnings: string[];
}

export type DuplicateReason = 'same_mac' | 'same_hostname' | 'same_agent';

export interface DuplicateHint {
  id: number;
  ip_address: string;
  hostname: string | null;
  mac_address: string | null;
  discovery_method: string | null;
  asset_type: string | null;
  last_seen: string | null;
  open_vulnerabilities: number;
  agents: number;
  reasons: DuplicateReason[];
}

/** Who may merge: the asset write roles (routes/assets.ts requireAssetWrite). */
export function canMergeAssets(role: string | undefined | null): boolean {
  return role === 'admin' || role === 'operator' || role === 'analyst';
}

/**
 * The asset to keep when none was chosen: one an endpoint agent reports on
 * (its asset stays the agent's), else the most recently seen, else the lowest id.
 */
export function defaultKeepId(assets: MergeableAsset[]): number | null {
  if (assets.length === 0) return null;
  const seen = (a: MergeableAsset) => (a.last_seen ? new Date(a.last_seen).getTime() || 0 : 0);
  const sorted = [...assets].sort(
    (a, b) => Number((b.agent_count ?? 0) > 0) - Number((a.agent_count ?? 0) > 0) || seen(b) - seen(a) || a.id - b.id
  );
  return sorted[0].id;
}

/** The ids merged into `keepId` (every selected one but it). */
export function mergeFromIds(assets: MergeableAsset[], keepId: number | null): number[] {
  return assets.filter((a) => a.id !== keepId).map((a) => a.id);
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** The confirmation's "what moves" lines, zero counts left out. */
export function mergeMoveLines(moved: MergeCounts): string[] {
  const lines: string[] = [];
  if (moved.vulnerabilities) {
    const combined = moved.vulnerabilities_combined
      ? ` (${plural(moved.vulnerabilities_combined, 'vulnerability', 'vulnerabilities')} found on more than one of them become one finding)`
      : '';
    lines.push(`${plural(moved.vulnerabilities, 'vulnerability finding')}${combined}`);
  }
  if (moved.services) lines.push(plural(moved.services, 'service'));
  if (moved.alerts) lines.push(plural(moved.alerts, 'alert'));
  if (moved.agents) lines.push(plural(moved.agents, 'endpoint agent'));
  if (moved.application_locations) lines.push(plural(moved.application_locations, 'Application Monitoring entry', 'Application Monitoring entries'));
  return lines;
}

/** "192.168.1.130 (chriss-mbp.local)". */
export function assetLabel(a: { ip_address: string; hostname?: string | null }): string {
  return a.hostname ? `${a.ip_address} (${a.hostname})` : a.ip_address;
}

const REASON_LABELS: Record<DuplicateReason, string> = {
  same_mac: 'Same MAC address',
  same_hostname: 'Same host name',
  same_agent: 'Recorded this endpoint agent',
};

export function duplicateReasonLabel(reason: string): string {
  return REASON_LABELS[reason as DuplicateReason] ?? reason;
}
