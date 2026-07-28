// Orchestrates one scan run: scope -> passive discovery -> (active discovery) ->
// matcher -> upsert into discovery_sources. Mirrors NmapScanner's shape (create a
// job row, run async, update the job row on completion/failure) but the actual
// discovery work is this feature's own (ARP/mDNS/SSDP/DHCP + scoped port/HTTP/TLS
// probing), since nothing like it existed before this feature.
import { logger } from '../../utils/logger';
import { query } from '../../config/database';
import { DiscoveryScanModel, DiscoveryScanMode } from '../../models/DiscoveryScan';
import { DiscoverySourceModel, DiscoverySource } from '../../models/DiscoverySource';
import { loadFingerprintLibrary, getFingerprintById } from './fingerprintLoader';
import { resolveScope } from './scope';
import { readArpTable, readDhcpLeases, queryMdnsServices, discoverSsdp, captureLldp } from './passiveDiscovery';
import { probeHost, sweepCidr } from './activeDiscovery';
import { matchHost } from './matcher';
import { rankSources, RankableItem } from './ranker';
import { renderOnboardInstructions, SiemboxSyslogSettings } from './onboarder';
import { DiscoveredSignals, LogAccessMethod, RankedResult, RuntimeSource } from './types';

interface Candidate {
  ip: string;
  mac?: string;
  hostname?: string;
  mdns_services: string[];
  ssdp_services: Array<{ st?: string; server?: string }>;
  discovery_methods: Set<string>;
}

function ensureCandidate(candidates: Map<string, Candidate>, ip: string): Candidate {
  let c = candidates.get(ip);
  if (!c) {
    c = { ip, mdns_services: [], ssdp_services: [], discovery_methods: new Set() };
    candidates.set(ip, c);
  }
  return c;
}

async function runPassivePhase(): Promise<Map<string, Candidate>> {
  const candidates = new Map<string, Candidate>();
  const ensure = (ip: string): Candidate => ensureCandidate(candidates, ip);

  const [arp, leases] = await Promise.all([readArpTable(), readDhcpLeases()]);
  for (const entry of arp) {
    const c = ensure(entry.ip);
    c.mac = entry.mac;
    c.discovery_methods.add('arp');
  }
  for (const lease of leases) {
    const c = ensure(lease.ip);
    c.mac = c.mac || lease.mac;
    c.hostname = c.hostname || lease.hostname;
    c.discovery_methods.add('dhcp_lease');
  }

  const library = loadFingerprintLibrary();
  const mdnsServices = Array.from(new Set(library.flatMap((fp) => fp.signals.mdns.map((s) => s.service))));
  if (mdnsServices.length > 0) {
    const responders = await queryMdnsServices(mdnsServices).catch((err) => {
      logger.warn(`[logDiscovery] mDNS phase failed: ${err?.message || err}`);
      return [];
    });
    for (const r of responders) {
      const c = ensure(r.ip);
      if (!c.mdns_services.includes(r.service)) c.mdns_services.push(r.service);
      c.discovery_methods.add('mdns');
    }
  }

  const ssdpResponders = await discoverSsdp().catch((err) => {
    logger.warn(`[logDiscovery] SSDP phase failed: ${err?.message || err}`);
    return [];
  });
  for (const r of ssdpResponders) {
    const c = ensure(r.ip);
    c.ssdp_services.push({ st: r.st, server: r.server });
    c.discovery_methods.add('ssdp');
  }

  await captureLldp(); // no-op today; documented in passiveDiscovery.ts

  return candidates;
}

/**
 * Sweeps every manually-approved CIDR (scope.ts already bounds each to
 * MAX_SWEEP_HOSTS) for live hosts and folds them into `candidates` as new
 * entries, so runActivePhase probes them the same as passively-discovered
 * ones. This is what actually makes a manually-entered subnet find real LAN
 * hosts -- passive discovery's ARP/mDNS/SSDP only ever see the container's
 * own bridge network.
 */
async function runCidrSweep(cidrs: string[], candidates: Map<string, Candidate>): Promise<void> {
  if (cidrs.length === 0) return;

  const results = await Promise.all(
    cidrs.map((cidr) =>
      sweepCidr(cidr).catch((err: any) => {
        logger.warn(`[logDiscovery] CIDR sweep of ${cidr} failed: ${err?.message || err}`);
        return [] as string[];
      })
    )
  );

  for (const ips of results) {
    for (const ip of ips) {
      ensureCandidate(candidates, ip).discovery_methods.add('active_sweep');
    }
  }
}

async function runActivePhase(candidates: Map<string, Candidate>, signalsByIp: Map<string, DiscoveredSignals>): Promise<void> {
  const ips = Array.from(candidates.keys());
  const concurrency = 4;
  let next = 0;

  async function worker() {
    while (next < ips.length) {
      const ip = ips[next++];
      try {
        const active = await probeHost(ip, loadFingerprintLibrary());
        const existing = signalsByIp.get(ip);
        if (!existing) continue;
        existing.open_ports = active.open_ports;
        existing.http_responses = active.http_responses;
        existing.tls_subjects = active.tls_subjects;
        existing.banners = active.banners;
        existing.discovery_methods = Array.from(new Set([...existing.discovery_methods, ...active.discovery_methods]));
      } catch (err: any) {
        logger.warn(`[logDiscovery] active probe of ${ip} failed: ${err?.message || err}`);
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, ips.length) }, worker));
}

async function executeScan(scanId: number, mode: DiscoveryScanMode, cidrs: string[]): Promise<void> {
  const library = loadFingerprintLibrary();
  const candidates = await runPassivePhase();

  if (mode === 'active' || mode === 'full') {
    await runCidrSweep(cidrs, candidates);
  }

  const signalsByIp = new Map<string, DiscoveredSignals>();
  for (const [ip, c] of candidates) {
    signalsByIp.set(ip, {
      ip,
      mac: c.mac,
      hostname: c.hostname,
      open_ports: [],
      http_responses: [],
      tls_subjects: [],
      banners: [],
      mdns_services: c.mdns_services,
      ssdp_services: c.ssdp_services,
      discovery_methods: Array.from(c.discovery_methods),
    });
  }

  if (mode === 'active' || mode === 'full') {
    await runActivePhase(candidates, signalsByIp);
  }

  let hostsMatched = 0;
  for (const [ip, signals] of signalsByIp) {
    const best = matchHost(signals, library)[0] || null;
    await DiscoverySourceModel.upsert({
      ip_address: ip,
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

  await DiscoveryScanModel.complete(scanId, { hosts_seen: signalsByIp.size, hosts_matched: hostsMatched });
}

export interface RunScanOptions {
  mode: DiscoveryScanMode;
  manualCidrs?: string[];
  createdBy?: number | null;
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
  const scan = await DiscoveryScanModel.create(opts.mode, scope.cidrs, opts.createdBy ?? null);

  executeScan(scan.id, opts.mode, scope.cidrs).catch(async (err: any) => {
    logger.error(`[logDiscovery] scan ${scan.id} failed:`, err);
    await DiscoveryScanModel.fail(scan.id, err?.message || 'Scan execution failed');
  });

  return { scanId: scan.id, cidrs: scope.cidrs, vlanWarning: scope.warning, rejectedCidrs: scope.rejected };
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
    source: toRuntimeSource(row),
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
