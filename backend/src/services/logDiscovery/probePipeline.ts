// The plan-driven probe pipeline: passive discovery -> (CIDR sweep) -> active
// probe -> a list of observed per-host signals. This is the orchestration that
// used to live inside discoveryScanService.executeScan, lifted out so the EXACT
// same pipeline runs two ways:
//   - in-process on the backend (discoveryScanService builds the plan from the
//     fingerprint library and passes its winston logger), and
//   - bundled into the log shipper's discovery agent (handed the plan in its
//     job, logging to the console).
//
// It is deliberately dependency-light -- only the probe primitives
// (passiveDiscovery / activeDiscovery, pure Node stdlib) and types -- so it
// bundles into a standalone agent with no backend/DB/winston/js-yaml pulled in.
// The fingerprint library stays on the backend; this pipeline only PRODUCES raw
// signals, and the backend matches them.
import { DiscoveredSignals, ProbePlan } from './types';
import { readArpTable, readDhcpLeases, queryMdnsServices, discoverSsdp, captureLldp } from './passiveDiscovery';
import { sweepCidr, probeHostWithPlan } from './activeDiscovery';

/** Injected logger so this module never imports the backend's winston logger. */
export type ProbeLogger = (level: 'info' | 'warn', message: string) => void;
const noLog: ProbeLogger = () => {};

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

/** Passive phase: ARP + DHCP leases + mDNS (for the planned services) + SSDP. Zero packets to targets beyond the multicast queries. */
async function runPassivePhase(mdnsServices: string[], log: ProbeLogger): Promise<Map<string, Candidate>> {
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

  if (mdnsServices.length > 0) {
    const responders = await queryMdnsServices(mdnsServices).catch((err) => {
      log('warn', `mDNS phase failed: ${err?.message || err}`);
      return [];
    });
    for (const r of responders) {
      const c = ensure(r.ip);
      if (!c.mdns_services.includes(r.service)) c.mdns_services.push(r.service);
      c.discovery_methods.add('mdns');
    }
  }

  const ssdpResponders = await discoverSsdp().catch((err) => {
    log('warn', `SSDP phase failed: ${err?.message || err}`);
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

/** Sweep each approved CIDR for live hosts and fold them into candidates. */
async function runCidrSweep(cidrs: string[], candidates: Map<string, Candidate>, log: ProbeLogger): Promise<void> {
  if (cidrs.length === 0) return;
  const results = await Promise.all(
    cidrs.map((cidr) =>
      sweepCidr(cidr).catch((err: any) => {
        log('warn', `CIDR sweep of ${cidr} failed: ${err?.message || err}`);
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

/** Active phase: probe every candidate for the planned ports/HTTP paths (+ TLS/banners). */
async function runActivePhase(
  candidates: Map<string, Candidate>,
  signalsByIp: Map<string, DiscoveredSignals>,
  plan: ProbePlan,
  log: ProbeLogger
): Promise<void> {
  const ips = Array.from(candidates.keys());
  const concurrency = 4;
  let next = 0;

  async function worker() {
    while (next < ips.length) {
      const ip = ips[next++];
      try {
        const active = await probeHostWithPlan(ip, { ports: plan.ports, httpPaths: plan.httpPaths });
        const existing = signalsByIp.get(ip);
        if (!existing) continue;
        existing.open_ports = active.open_ports;
        existing.http_responses = active.http_responses;
        existing.tls_subjects = active.tls_subjects;
        existing.banners = active.banners;
        existing.discovery_methods = Array.from(new Set([...existing.discovery_methods, ...active.discovery_methods]));
      } catch (err: any) {
        log('warn', `active probe of ${ip} failed: ${err?.message || err}`);
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, ips.length) }, worker));
}

export interface GatherSignalsOptions {
  mode: 'passive' | 'active' | 'full';
  cidrs: string[];
  plan: ProbePlan;
  log?: ProbeLogger;
  /** Called at phase boundaries so a caller can abort a cancelled/timed-out run (it should throw). */
  checkCancel?: () => void;
}

/**
 * Run the full probe pipeline for one scan and return the observed signals, one
 * entry per discovered host. Pure: no DB, no fingerprint matching -- the caller
 * ingests/matches the result.
 */
export async function gatherSignals(opts: GatherSignalsOptions): Promise<DiscoveredSignals[]> {
  const log = opts.log ?? noLog;
  const active = opts.mode === 'active' || opts.mode === 'full';

  const candidates = await runPassivePhase(opts.plan.mdnsServices, log);
  opts.checkCancel?.();

  if (active) {
    await runCidrSweep(opts.cidrs, candidates, log);
    opts.checkCancel?.();
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

  if (active) {
    await runActivePhase(candidates, signalsByIp, opts.plan, log);
    opts.checkCancel?.();
  }

  return Array.from(signalsByIp.values());
}
