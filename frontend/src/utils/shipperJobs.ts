/**
 * Display helpers for scans dispatched to log shippers (the Shippers page's
 * job list, and the scan pages' 'expired' status) and for the scan dialogs'
 * public-target confirmation. The backend rules these mirror:
 * backend/src/services/scanner/shipperJobs.ts (expiry, cancel roles) and
 * publicTargetGuard.ts (allow_public_targets).
 */
import { findPublicTargets, type PublicTargetReport } from './targetSafety.ts';

export type ShipperJobKind = 'nmap' | 'nuclei' | 'discovery';
export type ScanOriginPage = 'assets' | 'vulnerability_scanning' | 'log_discovery' | 'scheduled_scans';

export interface ScanOrigin {
  page: ScanOriginPage;
  scheduledScanId?: number;
  scheduledScanName?: string;
}

/** One job as GET /api/shippers/:id/jobs returns it. */
export interface ShipperJob {
  kind: ShipperJobKind;
  scanId: number;
  shipperId: number;
  status: 'queued' | 'running' | 'expired';
  targets: string[];
  scanType: string | null;
  createdBy: number | null;
  createdByUsername: string | null;
  createdAt: string;
  claimedAt: string | null;
  ageSeconds: number;
  expiresAt: string | null;
  origin: ScanOrigin | null;
  description: string | null;
  errorMessage: string | null;
  publicTargetsConfirmed: boolean;
}

export function jobKindLabel(kind: ShipperJobKind): string {
  switch (kind) {
    case 'nmap':
      return 'Asset scan (nmap)';
    case 'nuclei':
      return 'Vulnerability scan (nuclei)';
    case 'discovery':
      return 'Log discovery sweep';
  }
}

export function jobOriginLabel(origin: ScanOrigin | null): string {
  if (!origin) return 'Unknown';
  switch (origin.page) {
    case 'assets':
      return 'Assets page';
    case 'vulnerability_scanning':
      return 'Vulnerability Scanning page';
    case 'log_discovery':
      return 'Log Discovery page';
    case 'scheduled_scans':
      return origin.scheduledScanName ? `Scheduled scan "${origin.scheduledScanName}"` : 'Scheduled scan';
    default:
      return 'Unknown';
  }
}

/** "45s", "12m", "3h 5m", "2d 4h". */
export function formatAge(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return m % 60 ? `${h}h ${m % 60}m` : `${h}h`;
  const d = Math.floor(h / 24);
  return h % 24 ? `${d}d ${h % 24}h` : `${d}d`;
}

const ROLE_RANK: Record<string, number> = { viewer: 0, analyst: 1, operator: 2, admin: 3 };

/** Lowest role that may cancel each kind (backend SHIPPER_JOB_CANCEL_ROLE). */
export const JOB_CANCEL_ROLE: Record<ShipperJobKind, 'analyst' | 'operator'> = {
  nmap: 'analyst',
  nuclei: 'operator',
  discovery: 'operator',
};

export function canCancelJob(role: string | undefined, kind: ShipperJobKind): boolean {
  if (!role || !(role in ROLE_RANK)) return false;
  return ROLE_RANK[role] >= ROLE_RANK[JOB_CANCEL_ROLE[kind]];
}

/** The Shippers list's job badge: "2 queued", "1 running", "2 queued · 1 running". */
export function jobBadgeText(queued: number | null | undefined, running: number | null | undefined): string {
  const parts: string[] = [];
  if (queued) parts.push(`${queued} queued`);
  if (running) parts.push(`${running} running`);
  return parts.join(' · ');
}

/** Queued or running: still waiting on, or out on, the shipper. */
export function isActiveJob(job: Pick<ShipperJob, 'status'>): boolean {
  return job.status === 'queued' || job.status === 'running';
}

/** Element Plus tag type for a scan status, 'expired' and 'cancelled' included. */
export function scanStatusTagType(status: string): '' | 'success' | 'warning' | 'info' | 'danger' {
  switch (status) {
    case 'completed':
      return 'success';
    case 'running':
      return 'warning';
    case 'queued':
      return 'info';
    case 'failed':
      return 'danger';
    case 'expired':
      return 'danger';
    case 'cancelled':
      return 'info';
    default:
      return '';
  }
}

/** Status text: an expired scan never ran, which the bare word doesn't say. */
export function scanStatusLabel(status: string): string {
  return status === 'expired' ? 'expired (never ran)' : status;
}

/**
 * Whether a scan form may be submitted: false while it names public targets
 * the user hasn't confirmed. `allowPublicTargets` is what to send.
 */
export function publicTargetGate(
  targets: readonly string[],
  confirmed: boolean
): { report: PublicTargetReport; blocked: boolean; allowPublicTargets: boolean } {
  const report = findPublicTargets(targets);
  const hasPublic = report.publicTargets.length > 0;
  return { report, blocked: hasPublic && !confirmed, allowPublicTargets: hasPublic && confirmed };
}

/** Replace one whole target in free-text input (lines, commas or spaces), keeping the separators. */
export function replaceTargetToken(input: string, from: string, to: string): string {
  return input
    .split(/([\s,]+)/)
    .map((part) => (part === from ? to : part))
    .join('');
}
