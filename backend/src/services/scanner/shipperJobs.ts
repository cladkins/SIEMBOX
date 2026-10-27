/**
 * Scan jobs dispatched to log shippers: expiry, listing and cancel.
 *
 * A scan with "Run from" a shipper is created 'queued' and waits for that
 * shipper to claim it on its next job-pull (GET /api/shippers/scan-jobs/:api_key).
 * Three tables of work end up there: asset scans (nmap) and vulnerability scans
 * (nuclei) in vulnerability_scans, and log-discovery sweeps in discovery_scans.
 *
 * Expiry. A queued job nobody claims within the expiry window (system_settings
 * shipper_job_expiry_hours, default 24, admin-editable under Settings > Asset
 * Discovery) becomes 'expired' and is never run. Without this a one-off scan
 * queued for a shipper that was offline ran whenever the shipper came back,
 * days later, long after anyone remembered asking for it. Enforced twice: the
 * shipper-job-expiry sweep (jobs/shipperJobExpiry.ts) marks stale rows
 * expired, and every claim query refuses a row older than the window, so a
 * shipper polling between sweeps still can't receive old work.
 *
 * Only unclaimed ('queued') jobs expire. A job the shipper already claimed is
 * 'running' on the shipper and finishes or fails there.
 */
import pool from '../../config/database';
import { logger } from '../../utils/logger';

export const SHIPPER_JOB_EXPIRY_SETTING_KEY = 'shipper_job_expiry_hours';
export const DEFAULT_SHIPPER_JOB_EXPIRY_HOURS = 24;
export const MIN_SHIPPER_JOB_EXPIRY_HOURS = 1;
/** 30 days. */
export const MAX_SHIPPER_JOB_EXPIRY_HOURS = 720;
/** How long an expired job stays on the Shippers page's job list. */
const RECENTLY_EXPIRED_DAYS = 7;

/** The page (or schedule) a scan was started from, stored as scan_options.origin. */
export type ScanOriginPage = 'assets' | 'vulnerability_scanning' | 'log_discovery' | 'scheduled_scans';

export interface ScanOrigin {
  page: ScanOriginPage;
  scheduledScanId?: number;
  scheduledScanName?: string;
}

export type ShipperJobKind = 'nmap' | 'nuclei' | 'discovery';

export interface ShipperJob {
  kind: ShipperJobKind;
  scanId: number;
  shipperId: number;
  status: 'queued' | 'running' | 'expired';
  targets: string[];
  /** nmap scan type (ping/port/service/os), or the discovery mode; null for nuclei. */
  scanType: string | null;
  createdBy: number | null;
  createdByUsername: string | null;
  createdAt: string;
  claimedAt: string | null;
  ageSeconds: number;
  /** Queued only: when the job expires if the shipper still hasn't claimed it. */
  expiresAt: string | null;
  origin: ScanOrigin | null;
  description: string | null;
  /** Expired only: the reason recorded on the scan. */
  errorMessage: string | null;
  publicTargetsConfirmed: boolean;
}

export interface ShipperJobCounts {
  queued: number;
  running: number;
}

/** A valid expiry window in whole hours, or null. */
export function parseExpiryHours(value: unknown): number | null {
  const n = typeof value === 'number' ? value : typeof value === 'string' && /^\s*\d+\s*$/.test(value) ? Number(value) : NaN;
  if (!Number.isInteger(n) || n < MIN_SHIPPER_JOB_EXPIRY_HOURS || n > MAX_SHIPPER_JOB_EXPIRY_HOURS) return null;
  return n;
}

/** The expiry window in hours. The default when unset, invalid or unreadable: a broken setting must never stop expiry. */
export async function getShipperJobExpiryHours(): Promise<number> {
  try {
    const result = await pool.query('SELECT value FROM system_settings WHERE key = $1', [SHIPPER_JOB_EXPIRY_SETTING_KEY]);
    return parseExpiryHours(result.rows[0]?.value) ?? DEFAULT_SHIPPER_JOB_EXPIRY_HOURS;
  } catch {
    return DEFAULT_SHIPPER_JOB_EXPIRY_HOURS;
  }
}

/** Save the expiry window (already validated with parseExpiryHours). */
export async function setShipperJobExpiryHours(hours: number, userId: number | null): Promise<void> {
  // system_settings has two historical shapes (001 and 004); key and value are
  // in both, updated_by only in 001's.
  await pool.query(
    `INSERT INTO system_settings (key, value) VALUES ($1, $2)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
    [SHIPPER_JOB_EXPIRY_SETTING_KEY, String(hours)]
  );
  await pool
    .query('UPDATE system_settings SET updated_by = $2 WHERE key = $1', [SHIPPER_JOB_EXPIRY_SETTING_KEY, userId])
    .catch(() => {});
}

export function expiryMessage(hours: number): string {
  return (
    `Expired without running: the assigned log shipper did not pick this job up within ${hours} h ` +
    '(offline or not polling). Queued shipper jobs are never run late; start the scan again if it is still wanted.'
  );
}

export interface ExpiryResult {
  hours: number;
  /** vulnerability_scans rows (asset and vulnerability scans) marked expired. */
  scans: number[];
  /** discovery_scans rows marked expired. */
  discoveryScans: number[];
}

/**
 * Mark every queued shipper job older than the window 'expired' (optionally
 * just one shipper's). Idempotent: an expired row is no longer 'queued'.
 */
export async function expireStaleShipperJobs(opts: { shipperId?: number; maxAgeHours?: number } = {}): Promise<ExpiryResult> {
  const hours = opts.maxAgeHours ?? (await getShipperJobExpiryHours());
  const message = expiryMessage(hours);
  const shipperId = opts.shipperId ?? null;
  const scans = await pool.query(
    `UPDATE vulnerability_scans
        SET status = 'expired', completed_at = NOW(), updated_at = NOW(), error_message = $1
      WHERE assigned_shipper_id IS NOT NULL
        AND status = 'queued'
        AND created_at <= NOW() - make_interval(hours => $2::int)
        AND ($3::int IS NULL OR assigned_shipper_id = $3::int)
      RETURNING id, scan_type, assigned_shipper_id`,
    [message, hours, shipperId]
  );
  const discovery = await pool.query(
    `UPDATE discovery_scans
        SET status = 'expired', completed_at = NOW(), error_message = $1
      WHERE assigned_shipper_id IS NOT NULL
        AND status = 'queued'
        AND created_at <= NOW() - make_interval(hours => $2::int)
        AND ($3::int IS NULL OR assigned_shipper_id = $3::int)
      RETURNING id, assigned_shipper_id`,
    [message, hours, shipperId]
  );
  for (const row of scans.rows) {
    logger.warn(`[ShipperJobs] ${row.scan_type} scan ${row.id} for shipper ${row.assigned_shipper_id} expired unclaimed after ${hours} h`);
  }
  for (const row of discovery.rows) {
    logger.warn(`[ShipperJobs] discovery scan ${row.id} for shipper ${row.assigned_shipper_id} expired unclaimed after ${hours} h`);
  }
  return {
    hours,
    scans: scans.rows.map((r) => r.id as number),
    discoveryScans: discovery.rows.map((r) => r.id as number),
  };
}

function parseOptions(raw: unknown): Record<string, any> {
  if (!raw) return {};
  if (typeof raw === 'string') {
    try {
      return JSON.parse(raw);
    } catch {
      return {};
    }
  }
  return typeof raw === 'object' ? (raw as Record<string, any>) : {};
}

/** scan_options.origin, or what an older row's own fields say about where it came from. */
function originOf(opts: Record<string, any>): ScanOrigin | null {
  const o = opts.origin;
  if (o && typeof o === 'object' && typeof o.page === 'string') {
    const origin: ScanOrigin = { page: o.page as ScanOriginPage };
    if (Number.isInteger(o.scheduledScanId)) origin.scheduledScanId = o.scheduledScanId;
    if (typeof o.scheduledScanName === 'string') origin.scheduledScanName = o.scheduledScanName;
    return origin;
  }
  // Rows from before scan_options.origin: a schedule's runs carry "Scheduled: <name>".
  const description = typeof opts.description === 'string' ? opts.description : '';
  if (description.startsWith('Scheduled: ')) {
    return { page: 'scheduled_scans', scheduledScanName: description.slice('Scheduled: '.length) };
  }
  return null;
}

/** Queued or running, or expired within the last RECENTLY_EXPIRED_DAYS, for the table aliased `t`. */
function jobStatusFilter(t: string): string {
  return `(${t}.status IN ('queued', 'running')
        OR (${t}.status = 'expired' AND ${t}.completed_at > NOW() - make_interval(days => ${RECENTLY_EXPIRED_DAYS})))`;
}

/**
 * The jobs dispatched to a shipper (or every shipper) that are queued or
 * running, plus the ones that expired in the last week, oldest first.
 */
export async function listShipperJobs(shipperId?: number): Promise<ShipperJob[]> {
  const hours = await getShipperJobExpiryHours();
  const sid = shipperId ?? null;
  const scans = await pool.query(
    `SELECT vs.id, vs.scan_type, vs.status, vs.target, vs.scan_options, vs.assigned_shipper_id,
            vs.initiated_by, u.username, vs.created_at, vs.claimed_at, vs.error_message,
            EXTRACT(EPOCH FROM (NOW() - vs.created_at))::int AS age_seconds,
            vs.created_at + make_interval(hours => $2::int) AS expires_at
       FROM vulnerability_scans vs
       LEFT JOIN users u ON u.id = vs.initiated_by
      WHERE vs.assigned_shipper_id IS NOT NULL
        AND vs.scan_type IN ('asset_discovery', 'vulnerability')
        AND ${jobStatusFilter('vs')}
        AND ($1::int IS NULL OR vs.assigned_shipper_id = $1::int)`,
    [sid, hours]
  );
  const discovery = await pool.query(
    `SELECT ds.id, ds.mode, ds.status, ds.cidrs, ds.scan_options, ds.assigned_shipper_id,
            ds.created_by, u.username, ds.created_at, ds.claimed_at, ds.error_message,
            EXTRACT(EPOCH FROM (NOW() - ds.created_at))::int AS age_seconds,
            ds.created_at + make_interval(hours => $2::int) AS expires_at
       FROM discovery_scans ds
       LEFT JOIN users u ON u.id = ds.created_by
      WHERE ds.assigned_shipper_id IS NOT NULL
        AND ${jobStatusFilter('ds')}
        AND ($1::int IS NULL OR ds.assigned_shipper_id = $1::int)`,
    [sid, hours]
  );

  const iso = (v: unknown): string | null => (v ? new Date(v as string).toISOString() : null);
  const jobs: ShipperJob[] = [];
  for (const row of scans.rows) {
    const kind: ShipperJobKind = row.scan_type === 'vulnerability' ? 'nuclei' : 'nmap';
    const opts = parseOptions(row.scan_options);
    const targets =
      kind === 'nmap'
        ? Array.isArray(opts.targets)
          ? opts.targets.map(String)
          : String(row.target || '').split(/,\s*/).filter(Boolean)
        : [String(opts.target ?? row.target ?? '')].filter(Boolean);
    jobs.push({
      kind,
      scanId: row.id,
      shipperId: row.assigned_shipper_id,
      status: row.status,
      targets,
      scanType: kind === 'nmap' ? (opts.scanType ?? null) : null,
      createdBy: row.initiated_by ?? null,
      createdByUsername: row.username ?? null,
      createdAt: iso(row.created_at) as string,
      claimedAt: iso(row.claimed_at),
      ageSeconds: row.age_seconds,
      expiresAt: row.status === 'queued' ? iso(row.expires_at) : null,
      origin: originOf(opts) ?? { page: kind === 'nmap' ? 'assets' : 'vulnerability_scanning' },
      description: typeof opts.description === 'string' && opts.description ? opts.description : null,
      errorMessage: row.status === 'expired' ? row.error_message ?? null : null,
      publicTargetsConfirmed: Boolean(opts.publicTargetsConfirmation),
    });
  }
  for (const row of discovery.rows) {
    const opts = parseOptions(row.scan_options);
    const cidrs = Array.isArray(row.cidrs) ? row.cidrs : parseOptions(row.cidrs);
    jobs.push({
      kind: 'discovery',
      scanId: row.id,
      shipperId: row.assigned_shipper_id,
      status: row.status,
      targets: Array.isArray(cidrs) ? cidrs.map(String) : [],
      scanType: row.mode ?? null,
      createdBy: row.created_by ?? null,
      createdByUsername: row.username ?? null,
      createdAt: iso(row.created_at) as string,
      claimedAt: iso(row.claimed_at),
      ageSeconds: row.age_seconds,
      expiresAt: row.status === 'queued' ? iso(row.expires_at) : null,
      origin: originOf(opts) ?? { page: 'log_discovery' },
      description: null,
      errorMessage: row.status === 'expired' ? row.error_message ?? null : null,
      publicTargetsConfirmed: Boolean(opts.publicTargetsConfirmation),
    });
  }
  return jobs.sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.scanId - b.scanId);
}

/** Queued and running job counts per shipper id (shippers with none are left out). */
export async function countShipperJobs(): Promise<Record<number, ShipperJobCounts>> {
  const result = await pool.query(
    `SELECT assigned_shipper_id AS id, status, COUNT(*)::int AS n FROM vulnerability_scans
      WHERE assigned_shipper_id IS NOT NULL AND status IN ('queued', 'running')
        AND scan_type IN ('asset_discovery', 'vulnerability')
      GROUP BY assigned_shipper_id, status
     UNION ALL
     SELECT assigned_shipper_id AS id, status, COUNT(*)::int AS n FROM discovery_scans
      WHERE assigned_shipper_id IS NOT NULL AND status IN ('queued', 'running')
      GROUP BY assigned_shipper_id, status`
  );
  const counts: Record<number, ShipperJobCounts> = {};
  for (const row of result.rows) {
    const c = (counts[row.id] ??= { queued: 0, running: 0 });
    if (row.status === 'queued') c.queued += row.n;
    else c.running += row.n;
  }
  return counts;
}

export function isShipperJobKind(value: unknown): value is ShipperJobKind {
  return value === 'nmap' || value === 'nuclei' || value === 'discovery';
}

export type CancelOutcome =
  | { found: false }
  | { found: true; cancelled: boolean; status: string; previousStatus: string };

/**
 * Cancel one of a shipper's queued or running jobs. A queued job is never
 * handed out afterwards; a running one is already on the shipper, which can't
 * be interrupted from here, so the results it posts later are ignored (see the
 * /scan-results and /discovery-results handlers). Asset and vulnerability
 * scans become 'cancelled'; a discovery scan becomes 'failed' with the reason,
 * as the Log Discovery page's own cancel does.
 */
export async function cancelShipperJob(
  shipperId: number,
  kind: ShipperJobKind,
  scanId: number,
  username: string | null
): Promise<CancelOutcome> {
  const who = username ? ` by ${username}` : '';
  if (kind === 'discovery') {
    const row = (
      await pool.query('SELECT status FROM discovery_scans WHERE id = $1 AND assigned_shipper_id = $2', [scanId, shipperId])
    ).rows[0];
    if (!row) return { found: false };
    const reason =
      row.status === 'queued'
        ? `Cancelled${who} from the Shippers page before the shipper claimed it`
        : `Cancelled${who} from the Shippers page while the shipper was running it; its results will be ignored`;
    const result = await pool.query(
      `UPDATE discovery_scans SET status = 'failed', completed_at = NOW(), error_message = $3
        WHERE id = $1 AND assigned_shipper_id = $2 AND status IN ('queued', 'running')
        RETURNING status`,
      [scanId, shipperId, reason]
    );
    const cancelled = (result.rowCount ?? 0) > 0;
    return { found: true, cancelled, status: cancelled ? 'failed' : row.status, previousStatus: row.status };
  }

  const scanType = kind === 'nmap' ? 'asset_discovery' : 'vulnerability';
  const row = (
    await pool.query('SELECT status FROM vulnerability_scans WHERE id = $1 AND assigned_shipper_id = $2 AND scan_type = $3', [
      scanId,
      shipperId,
      scanType,
    ])
  ).rows[0];
  if (!row) return { found: false };
  const reason =
    row.status === 'queued'
      ? `Cancelled${who} from the Shippers page before the shipper claimed it`
      : `Cancelled${who} from the Shippers page while the shipper was running it; its results will be ignored`;
  const result = await pool.query(
    `UPDATE vulnerability_scans
        SET status = 'cancelled', completed_at = NOW(), updated_at = NOW(), error_message = $4
      WHERE id = $1 AND assigned_shipper_id = $2 AND scan_type = $3 AND status IN ('queued', 'running')
      RETURNING status`,
    [scanId, shipperId, scanType, reason]
  );
  const cancelled = (result.rowCount ?? 0) > 0;
  return { found: true, cancelled, status: cancelled ? 'cancelled' : row.status, previousStatus: row.status };
}

/**
 * The still-queued run a schedule left for a shipper, if any: the schedule's
 * last_scan_id, when that scan is queued for the same shipper. The scheduler
 * skips queuing another run while one waits, so an offline shipper doesn't
 * collect a pile of identical jobs to run back to back when it returns.
 */
export async function pendingScheduledRun(lastScanId: number | null, shipperId: number | null): Promise<number | null> {
  if (lastScanId == null || shipperId == null) return null;
  const result = await pool.query(
    `SELECT id FROM vulnerability_scans WHERE id = $1 AND assigned_shipper_id = $2 AND status = 'queued'`,
    [lastScanId, shipperId]
  );
  return result.rows[0]?.id ?? null;
}
