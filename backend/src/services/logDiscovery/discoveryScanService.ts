// Orchestrates one scan run: scope -> passive discovery -> (active discovery) ->
// matcher -> upsert into discovery_sources. Mirrors NmapScanner's shape (create a
// job row, run async, update the job row on completion/failure) but the actual
// discovery work is this feature's own (ARP/mDNS/SSDP/DHCP + scoped port/HTTP/TLS
// probing), since nothing like it existed before this feature.
import { logger } from '../../utils/logger';
import { ErrorLogService } from '../errors/errorLogService';
import { query } from '../../config/database';
import { DiscoveryScanModel, DiscoveryScanMode } from '../../models/DiscoveryScan';
import { DiscoverySourceModel, DiscoverySource } from '../../models/DiscoverySource';
import { loadFingerprintLibrary, getFingerprintById } from './fingerprintLoader';
import { resolveScope } from './scope';
import { selectPortsToScan, selectHttpProbes } from './activeDiscovery';
import { gatherSignals } from './probePipeline';
import { matchHost } from './matcher';
import { rankSources, RankableItem } from './ranker';
import { renderOnboardInstructions, SiemboxSyslogSettings } from './onboarder';
import { DiscoveredSignals, LogAccessMethod, ProbePlan, RankedResult, RuntimeSource } from './types';

// ---------------------------------------------------------------------------
// Cancellation + watchdog. The worker is an in-memory promise chained off a job
// row, so without these a scan could stay 'running' forever (cancel had no
// path in, and nothing bounded a wedged run). Cancellation is cooperative:
// requestCancel() flags the id and the worker checks the flag at phase
// boundaries and during the upsert loop — every probe inside a phase is
// individually timeout-bounded, so boundaries are reached promptly.
// ---------------------------------------------------------------------------

/** Hard cap on a single scan run. Sweeps are bounded (≤1024 hosts/CIDR, sub-second
 * port timeouts), so a legitimate run finishes well inside this. */
export const SCAN_WATCHDOG_MS = 30 * 60 * 1000;

const cancelRequested = new Set<number>();
const activeScanIds = new Set<number>();

export class ScanCancelledError extends Error {
  constructor(scanId: number) {
    super(`Discovery scan ${scanId} cancelled`);
    this.name = 'ScanCancelledError';
  }
}

/**
 * Flag a scan for cooperative cancellation. Returns true if this process has
 * an in-memory worker to interrupt — false means the row is an orphan from a
 * previous process and only the DB status needs fixing.
 */
export function requestCancel(scanId: number): boolean {
  const known = activeScanIds.has(scanId);
  cancelRequested.add(scanId);
  return known;
}

function throwIfCancelled(scanId: number): void {
  if (cancelRequested.has(scanId)) throw new ScanCancelledError(scanId);
}

async function executeScan(scanId: number, mode: DiscoveryScanMode, cidrs: string[]): Promise<void> {
  const library = loadFingerprintLibrary();
  // Same plan-driven pipeline a shipper runs (see probePipeline.ts), just
  // in-process here with the backend logger and cooperative cancellation.
  const signals = await gatherSignals({
    mode,
    cidrs,
    plan: buildProbePlan(library),
    log: (level, message) =>
      level === 'warn' ? logger.warn(`[logDiscovery] ${message}`) : logger.info(`[logDiscovery] ${message}`),
    checkCancel: () => throwIfCancelled(scanId),
  });
  await ingestSignals(scanId, signals, library);
}

/**
 * Match a batch of observed host signals against the fingerprint library, upsert
 * each into discovery_sources, and complete the scan. Shared by the in-process
 * path (executeScan above) and the shipper path (ingestShipperDiscovery below),
 * so a shipper-run discovery scan produces the same discovery_sources rows as a
 * backend-run one. The fingerprint library lives only here -- the shipper just
 * returns raw signals.
 */
export async function ingestSignals(
  scanId: number,
  signalsList: DiscoveredSignals[],
  library = loadFingerprintLibrary()
): Promise<void> {
  let hostsMatched = 0;
  for (const signals of signalsList) {
    throwIfCancelled(scanId);
    const best = matchHost(signals, library)[0] || null;
    await DiscoverySourceModel.upsert({
      ip_address: signals.ip,
      mac_address: signals.mac || null,
      hostname: signals.hostname || null,
      open_ports: signals.open_ports,
      matched_fingerprint_id: best?.fingerprint.id ?? null,
      confidence: best?.confidence ?? 0,
      is_guess: best?.is_guess ?? true,
      security_value: best?.fingerprint.security_value ?? null,
      evidence: {
        discovery_methods: signals.discovery_methods,
        matched_signals: best?.matched_signals ?? [],
        http_responses: signals.http_responses.map((r) => ({ port: r.port, path: r.path, status: r.status })),
        tls_subjects: signals.tls_subjects,
        mdns_services: signals.mdns_services,
        ssdp_services: signals.ssdp_services,
      },
      last_scan_id: scanId,
    });
    if (best) hostsMatched++;
  }

  await DiscoveryScanModel.complete(scanId, { hosts_seen: signalsList.length, hosts_matched: hostsMatched });
}

/**
 * Extract the portable probe targets (ports, HTTP paths, mDNS services) from the
 * fingerprint library. Sent to a shipper in its discovery job so it runs the
 * same probing without needing the fingerprint files.
 */
export function buildProbePlan(library = loadFingerprintLibrary()): ProbePlan {
  const mdnsServices = Array.from(new Set(library.flatMap((fp) => fp.signals.mdns.map((s) => s.service))));
  return { ports: selectPortsToScan(library), httpPaths: selectHttpProbes(library), mdnsServices };
}

export interface RunScanOptions {
  mode: DiscoveryScanMode;
  manualCidrs?: string[];
  createdBy?: number | null;
  /**
   * Dispatch to a log shipper instead of running on the backend. When set, the
   * scan is created 'queued' and left for that shipper to claim and run the full
   * passive+active probe out on the LAN (migration 033). null/undefined runs it
   * in-process, exactly as before.
   */
  assignedShipperId?: number | null;
}

export interface RunScanResult {
  scanId: number;
  cidrs: string[];
  vlanWarning: string | null;
  rejectedCidrs: string[];
}

/** Kick off a scan asynchronously (like NmapScanner.scan) and return immediately with its job id. */
export async function runScan(opts: RunScanOptions): Promise<RunScanResult> {
  const scope = resolveScope(opts.manualCidrs || []);

  // Dispatched to a shipper: create 'queued' and return. The shipper claims it
  // via the job-pull and runs the probe out on the LAN; no in-process worker or
  // watchdog here (the shipper owns the run), exactly like the nmap/nuclei path.
  if (opts.assignedShipperId != null) {
    const scan = await DiscoveryScanModel.createAssigned(opts.mode, scope.cidrs, opts.createdBy ?? null, opts.assignedShipperId);
    logger.info(`[logDiscovery] scan ${scan.id} queued for shipper ${opts.assignedShipperId}`);
    return { scanId: scan.id, cidrs: scope.cidrs, vlanWarning: scope.warning, rejectedCidrs: scope.rejected };
  }

  const scan = await DiscoveryScanModel.create(opts.mode, scope.cidrs, opts.createdBy ?? null);

  activeScanIds.add(scan.id);
  // Watchdog: if the run wedges past the hard cap, flag it cancelled (the
  // worker bails at its next checkpoint) and fail the row. The model's
  // only-from-'running' guard keeps a late complete() from resurrecting it.
  const watchdog = setTimeout(() => {
    requestCancel(scan.id);
    DiscoveryScanModel.fail(scan.id, `Timed out after ${Math.round(SCAN_WATCHDOG_MS / 60000)} minutes (watchdog)`).catch(
      (err) => logger.error(`[logDiscovery] watchdog failed to mark scan ${scan.id}:`, err)
    );
  }, SCAN_WATCHDOG_MS);
  watchdog.unref?.();

  executeScan(scan.id, opts.mode, scope.cidrs)
    .catch(async (err: any) => {
      if (err instanceof ScanCancelledError) {
        // Row was already failed by the cancel endpoint / watchdog; the guarded
        // fail() below is a no-op in that case. Deliberately NOT reported to the
        // dashboard's error log: a cancel (or a watchdog timeout, which cancels)
        // is an intended outcome, not a fault to investigate.
        logger.info(`[logDiscovery] scan ${scan.id} stopped: ${err.message}`);
      } else {
        logger.error(`[logDiscovery] scan ${scan.id} failed:`, err);
        ErrorLogService.logBackgroundError('log-discovery', err, {
          dedupeKey: `scan-${scan.id}`,
          scanId: scan.id,
          mode: opts.mode,
        });
      }
      await DiscoveryScanModel.fail(scan.id, err?.message || 'Scan execution failed').catch(() => {});
    })
    .finally(() => {
      clearTimeout(watchdog);
      activeScanIds.delete(scan.id);
      cancelRequested.delete(scan.id);
    });

  return { scanId: scan.id, cidrs: scope.cidrs, vlanWarning: scope.warning, rejectedCidrs: scope.rejected };
}

/**
 * A discovery job handed to a log shipper by the job-pull. Carries the probe
 * plan (so the shipper needs no fingerprint files) and the CIDRs to sweep.
 */
export interface ShipperDiscoveryJob {
  scanId: number;
  kind: 'discovery';
  mode: DiscoveryScanMode;
  cidrs: string[];
  probePlan: ProbePlan;
}

/** Atomically claim a shipper's queued discovery scans and turn them into jobs. */
export async function claimDiscoveryJobsForShipper(shipperId: number): Promise<ShipperDiscoveryJob[]> {
  const claimed = await DiscoveryScanModel.claimForShipper(shipperId);
  if (claimed.length === 0) return [];
  const probePlan = buildProbePlan();
  return claimed.map((s) => ({
    scanId: s.id,
    kind: 'discovery',
    mode: s.mode,
    cidrs: Array.isArray(s.cidrs) ? s.cidrs : [],
    probePlan,
  }));
}

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/**
 * Coerce the raw JSON a shipper posts into safe DiscoveredSignals: every array
 * defaulted, non-IPv4 hosts dropped (discovery is IPv4, and ip_address is INET
 * so a bad value would fail the upsert). Defensive -- the shipper is trusted to
 * run our agent, but a malformed payload must not break ingestion.
 */
export function normalizeDiscoveredSignals(raw: unknown): DiscoveredSignals[] {
  if (!Array.isArray(raw)) return [];
  const out: DiscoveredSignals[] = [];
  for (const h of raw) {
    if (!h || typeof h !== 'object') continue;
    const ip = String((h as any).ip ?? '');
    const m = IPV4_RE.exec(ip);
    if (!m || m.slice(1).some((o) => Number(o) > 255)) continue;
    out.push({
      ip,
      mac: (h as any).mac ? String((h as any).mac) : undefined,
      hostname: (h as any).hostname ? String((h as any).hostname) : undefined,
      open_ports: Array.isArray((h as any).open_ports) ? (h as any).open_ports.filter((n: any) => Number.isInteger(n)) : [],
      http_responses: Array.isArray((h as any).http_responses) ? (h as any).http_responses : [],
      tls_subjects: Array.isArray((h as any).tls_subjects) ? (h as any).tls_subjects : [],
      banners: Array.isArray((h as any).banners) ? (h as any).banners : [],
      mdns_services: Array.isArray((h as any).mdns_services) ? (h as any).mdns_services.map(String) : [],
      ssdp_services: Array.isArray((h as any).ssdp_services) ? (h as any).ssdp_services : [],
      discovery_methods: Array.isArray((h as any).discovery_methods) ? (h as any).discovery_methods.map(String) : [],
    });
  }
  return out;
}

/**
 * Ingest the signals a shipper posted back for a dispatched discovery scan.
 * Normalizes, then runs the SAME matcher/upsert/complete path as an in-process
 * scan. Marks the scan failed and rethrows on error so the caller can respond.
 */
export async function ingestShipperDiscovery(scanId: number, rawSignals: unknown): Promise<void> {
  try {
    const signals = normalizeDiscoveredSignals(rawSignals);
    logger.info(`[logDiscovery] scan ${scanId} ingesting ${signals.length} host(s) from shipper`);
    await ingestSignals(scanId, signals);
  } catch (err: any) {
    await DiscoveryScanModel.fail(scanId, err?.message || 'Failed to ingest discovery results').catch(() => {});
    throw err;
  }
}

/** Mark a shipper-dispatched discovery scan failed (shipper couldn't run it). */
export async function failDiscoveryScan(scanId: number, message: string): Promise<void> {
  await DiscoveryScanModel.fail(scanId, message || 'Shipper reported discovery scan failure').catch(() => {});
}

function toRuntimeSource(row: DiscoverySource): RuntimeSource {
  return {
    id: row.id,
    ip: row.ip_address,
    mac: row.mac_address,
    hostname: row.hostname,
    open_ports: row.open_ports || [],
    matched_fingerprint_id: row.matched_fingerprint_id,
    confidence: row.confidence,
    is_guess: row.is_guess,
    security_value: row.security_value,
    status: row.status,
    selected_log_access: row.selected_log_access,
    evidence: row.evidence,
  };
}

/** Module 4 (ranker) applied to whatever module 3 (matcher) has recorded so far. */
export async function getRankedSources(): Promise<RankedResult> {
  const rows = await DiscoverySourceModel.findAll();
  const items: RankableItem[] = rows.map((row) => ({
    source: {
      ...toRuntimeSource(row),
      poller: {
        configured: row.poller_configured,
        enabled: row.poller_enabled ?? false,
        last_status: (row.poller_last_status as 'ok' | 'error' | null) ?? null,
        last_polled_at: row.poller_last_polled_at,
        last_error: row.poller_last_error,
      },
    },
    fingerprint: row.matched_fingerprint_id ? getFingerprintById(row.matched_fingerprint_id) || null : null,
  }));
  return rankSources(items);
}

/** Same settings key shippers.ts reads, so onboarding instructions always point at wherever the syslog listener actually is. */
export async function getSiemboxSyslogSettings(): Promise<SiemboxSyslogSettings> {
  try {
    const result = await query(`SELECT key, value FROM system_settings WHERE key IN ('syslog_host', 'syslog_port')`);
    const settings: SiemboxSyslogSettings = { host: '', port: 514 };
    for (const row of result.rows) {
      if (row.key === 'syslog_host') settings.host = row.value;
      if (row.key === 'syslog_port') settings.port = parseInt(row.value, 10);
    }
    return settings;
  } catch {
    return { host: '', port: 514 };
  }
}

export interface OnboardPreview {
  instructions: string;
  log_access: LogAccessMethod;
}

/**
 * Manual-mode onboarding preview: never writes anything, just renders the
 * copy-paste block for a confirmed source's matched fingerprint. `methodIndex`
 * lets the user pick a different entry from log_access (easiest-first order).
 */
export async function buildOnboardPreview(sourceId: number, methodIndex = 0): Promise<OnboardPreview> {
  const row = await DiscoverySourceModel.findById(sourceId);
  if (!row) throw new Error('Discovery source not found');
  if (!row.matched_fingerprint_id) throw new Error('This source has no matched fingerprint to onboard from');

  const fingerprint = getFingerprintById(row.matched_fingerprint_id);
  if (!fingerprint) throw new Error(`Fingerprint "${row.matched_fingerprint_id}" is no longer in the library`);

  const logAccess = fingerprint.log_access[methodIndex] || fingerprint.log_access[0];
  const siembox = await getSiemboxSyslogSettings();
  const instructions = renderOnboardInstructions(fingerprint, toRuntimeSource(row), logAccess, siembox);

  return { instructions, log_access: logAccess };
}
