/**
 * "Test" in the signature editor: what a signature would identify in the
 * evidence SIEMBox holds now, before it is saved. Read-only, bounded, and
 * off the log tables (raw_logs / parsed_logs are never scanned):
 *
 *   - the Not identified list (every kind, ignored values too);
 *   - the log values other signatures already identify (the inventory's
 *     evidence: program, parser, user agent, domain);
 *   - the snapshot sources as the rollup reads them: nmap services, shipper
 *     containers, endpoint OS, and of the installed packages and EDR findings
 *     the names the signature lists.
 *
 * The caller gates the signature's regexes (services/regex) before this runs
 * them; inputs are truncated to MAX_MATCH_INPUT as the rollup's are.
 */
import { query } from '../../config/database';
import type { AppSignature } from './appFormat';
import { AppIndex, MAX_MATCH_INPUT, type AppMatch } from './matchers';
import { unmatchedResolves } from './rollup';

export const TEST_MATCH_LIMIT = 200;
const SNAPSHOT_READ = 20_000;
const INVENTORY_VALUES_READ = 5_000;

export interface EvidenceHit {
  kind: string;
  value: string;
  version: string | null;
  location: string | null;
  location_label: string | null;
  /** Where it is now: in the Not identified list, or identified as other applications. */
  now: 'not_identified' | 'identified' | 'snapshot';
  identified_as: string[];
}

export interface EvidenceTestResult {
  hits: EvidenceHit[];
  /** Hits per kind (all of them, not only the listed ones). */
  counts: Record<string, number>;
  total: number;
  locations: number;
  versions: string[];
  /** The hits that would leave the Not identified list. */
  resolves_unmatched: number;
  truncated: boolean;
}

/** Collects hits; pure. */
export class HitCollector {
  readonly hits: EvidenceHit[] = [];
  readonly counts: Record<string, number> = {};
  private locs = new Set<string>();
  private versions = new Set<string>();
  total = 0;
  resolves = 0;
  add(h: EvidenceHit): void {
    this.total++;
    this.counts[h.kind] = (this.counts[h.kind] ?? 0) + 1;
    if (h.location) this.locs.add(`${h.kind}\u0000${h.location}`);
    if (h.version) this.versions.add(h.version);
    if (h.now === 'not_identified') this.resolves++;
    if (this.hits.length < TEST_MATCH_LIMIT) this.hits.push(h);
  }
  result(): EvidenceTestResult {
    return {
      hits: this.hits,
      counts: this.counts,
      total: this.total,
      locations: this.locs.size,
      versions: [...this.versions].sort(),
      resolves_unmatched: this.resolves,
      truncated: this.total > this.hits.length,
    };
  }
}

const mine = (matches: AppMatch[], id: string) => matches.find((m) => m.appId === id);

/**
 * Run `app` over the evidence. `others` is the rest of the set in use (to
 * show what a value is identified as now, and so that supersedes applies);
 * `skipRegex` the regexes the safety gate refused (left out, as the rollup
 * leaves them out).
 */
export async function testSignatureAgainstEvidence(app: AppSignature, others: AppSignature[], skipRegex: Set<string> = new Set()): Promise<EvidenceTestResult> {
  const full = new AppIndex([...others.filter((a) => a.id !== app.id), app], { skipRegex });
  const only = new AppIndex([app], { skipRegex });
  const hits = new HitCollector();
  const id = app.id;

  // 1. The Not identified list.
  const unmatched = await query(
    `SELECT u.source, u.value, u.sample, u.detail, u.sample_location,
            CASE WHEN u.source IN ('package', 'service') THEN COALESCE(a.hostname, host(a.ip_address))
                 WHEN u.source = 'container' THEN COALESCE(ls.hostname, ls.name) END AS label
       FROM application_unmatched u
       LEFT JOIN assets a ON u.source IN ('package', 'service') AND a.id::text = u.sample_location
       LEFT JOIN log_shippers ls ON u.source = 'container' AND ls.id::text = u.sample_location
      ORDER BY u.events DESC LIMIT $1`,
    [SNAPSHOT_READ]
  );
  for (const r of unmatched.rows) {
    if (!unmatchedResolves(only, r)) continue;
    const version = versionFor(only, r);
    hits.add({ kind: r.source, value: r.sample || r.value, version, location: r.sample_location, location_label: r.label ?? r.sample_location, now: 'not_identified', identified_as: [] });
  }

  // 2. Log values other signatures identify now.
  const identified = await query(
    `SELECT source, value, max(loc_key) AS loc, array_agg(DISTINCT app_id) AS apps
       FROM (SELECT source, evidence->>'value' AS value, loc_key, app_id FROM application_inventory
              WHERE source IN ('syslog_program', 'parser', 'user_agent', 'dns') AND app_id <> $1 AND evidence ? 'value'
              ORDER BY last_seen DESC LIMIT $2) i
      GROUP BY source, value`,
    [id, INVENTORY_VALUES_READ]
  );
  for (const r of identified.rows) {
    const v = String(r.value ?? '').slice(0, MAX_MATCH_INPUT);
    if (!v) continue;
    const m =
      r.source === 'syslog_program' ? only.matchProgram(v)
      : r.source === 'parser' ? only.matchParser(v)
      : r.source === 'user_agent' ? only.matchUserAgent(v)
      : only.matchDomain(v);
    const hit = mine(m, id);
    if (!hit) continue;
    hits.add({ kind: r.source, value: v, version: hit.version, location: r.loc, location_label: r.loc, now: 'identified', identified_as: r.apps ?? [] });
  }

  // 3. Snapshots.
  const services = await query(
    `SELECT s.asset_id, s.port, s.protocol, s.service_name, s.service_version, s.banner, COALESCE(a.hostname, host(a.ip_address)) AS label
       FROM asset_services s LEFT JOIN assets a ON a.id = s.asset_id
      WHERE s.asset_id IS NOT NULL AND COALESCE(s.state, 'open') = 'open' ORDER BY s.id LIMIT $1`,
    [SNAPSHOT_READ]
  );
  for (const s of services.rows) {
    const input = { name: s.service_name, version: s.service_version, banner: s.banner };
    const hit = mine(only.matchService(input), id);
    if (!hit) continue;
    const now = full.matchService(input).filter((m) => m.appId !== id).map((m) => m.appId);
    hits.add({
      kind: 'service',
      value: `${s.port}/${s.protocol} ${[s.service_name, s.service_version].filter(Boolean).join(' ')}`.trim(),
      version: hit.version, location: String(s.asset_id), location_label: s.label, now: now.length ? 'identified' : 'snapshot', identified_as: now,
    });
  }
  const containers = await query(
    `SELECT c.shipper_id, c.image, COALESCE(ls.hostname, ls.name) AS label FROM shipper_containers c LEFT JOIN log_shippers ls ON ls.id = c.shipper_id ORDER BY c.id LIMIT $1`,
    [SNAPSHOT_READ]
  );
  for (const c of containers.rows) {
    const hit = mine(only.matchImage(c.image), id);
    if (!hit) continue;
    const now = full.matchImage(c.image).filter((m) => m.appId !== id).map((m) => m.appId);
    hits.add({ kind: 'container', value: c.image, version: hit.version, location: String(c.shipper_id), location_label: c.label, now: now.length ? 'identified' : 'snapshot', identified_as: now });
  }
  if (app.match.package.length) {
    const pkgs = await query(
      `SELECT a.asset_id, p.name, p.version, p.type, COALESCE(x.hostname, host(x.ip_address)) AS label
         FROM edr_agent_packages p JOIN edr_agents a ON a.agent_id = p.agent_id LEFT JOIN assets x ON x.id = a.asset_id
        WHERE a.asset_id IS NOT NULL AND lower(p.name) = ANY($1::text[]) LIMIT $2`,
      [app.match.package, SNAPSHOT_READ]
    );
    for (const p of pkgs.rows) {
      const hit = mine(only.matchPackage(p.name, p.version), id);
      if (!hit) continue;
      const now = full.matchPackage(p.name, p.version).filter((m) => m.appId !== id).map((m) => m.appId);
      hits.add({ kind: 'package', value: `${p.name} ${p.version}${p.type ? ` (${p.type})` : ''}`, version: hit.version, location: String(p.asset_id), location_label: p.label, now: now.length ? 'identified' : 'snapshot', identified_as: now });
    }
  }
  if (app.match.os) {
    const agents = await query(
      `SELECT e.asset_id, e.os, e.os_version, COALESCE(a.hostname, host(a.ip_address)) AS label FROM edr_agents e LEFT JOIN assets a ON a.id = e.asset_id
        WHERE e.asset_id IS NOT NULL LIMIT $1`,
      [SNAPSHOT_READ]
    );
    for (const a of agents.rows) {
      const hit = mine(only.matchOs(a.os, a.os_version), id);
      if (!hit) continue;
      const now = full.matchOs(a.os, a.os_version).filter((m) => m.appId !== id).map((m) => m.appId);
      hits.add({ kind: 'os', value: `${a.os ?? ''} ${a.os_version ?? ''}`.trim(), version: hit.version, location: String(a.asset_id), location_label: a.label, now: now.length ? 'identified' : 'snapshot', identified_as: now });
    }
  }
  return hits.result();
}

/** The version a signature reads from a Not identified value, if any. */
function versionFor(index: AppIndex, r: { source: string; value: string; sample?: string | null; detail?: Record<string, any> | null }): string | null {
  const d = r.detail ?? {};
  const m =
    r.source === 'container' ? index.matchImage(r.sample || r.value)
    : r.source === 'user_agent' ? index.matchUserAgent(r.sample || r.value)
    : r.source === 'service' ? index.matchService({ name: d.service_name ?? r.value, version: d.service_version ?? null, banner: d.banner ?? null })
    : r.source === 'package' ? index.matchPackage(r.value, d.version ?? null)
    : [];
  return m[0]?.version ?? null;
}
