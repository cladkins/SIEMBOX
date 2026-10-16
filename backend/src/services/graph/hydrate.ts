/**
 * Node facts, loaded for every node of a type at once (one `= ANY($1)` lookup
 * per type, each in its own budget step), after the relations have said which
 * nodes there are. Explicit column lists only; never a key, hash or secret
 * (visibility.test.ts checks this file and everything under services/graph).
 *
 * A record node whose row is gone (a rule deleted since, an asset removed) is
 * reported missing and dropped with its edges. A type whose lookup timed out
 * keeps its nodes with the label their key gives, and marks the answer partial.
 * IP facts need no database except the local threat-feed names: GeoIP is an
 * in-process lookup, and nothing calls an external service.
 */
import net from 'net';
import { domainToUnicode } from 'url';
import type { BudgetContext, Query } from './budget';
import type { EntityRef } from './entityKey';
import { iso } from './resolvers/common';
import { sanitizeFact, sanitizeLabel } from './labels';
import { canSeeAccountDetails, canSeeType } from './visibility';
import { geoipService } from '../geoip/geoipService';
import { OFFLINE_THRESHOLD_MINUTES } from '../../models/EdrAgent';
import type { FactValue, GraphNode, NodeFlag, NodeType, Role } from './types';

const PRIVATE_RANGES = new net.BlockList();
for (const [address, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.168.0.0', 16],
] as const) {
  PRIVATE_RANGES.addSubnet(address, prefix, 'ipv4');
}
for (const [address, prefix] of [
  ['::1', 128],
  ['fc00::', 7],
  ['fe80::', 10],
] as const) {
  PRIVATE_RANGES.addSubnet(address, prefix, 'ipv6');
}

/** RFC 1918, loopback, link-local, CGNAT, ULA. */
export function isPrivateIp(ip: string): boolean {
  const family = net.isIP(ip);
  if (family === 0) return false;
  return PRIVATE_RANGES.check(ip, family === 4 ? 'ipv4' : 'ipv6');
}

export interface HydrateResult {
  nodes: Map<string, GraphNode>;
  /** Record nodes whose row no longer exists. */
  missing: Set<string>;
  /** A lookup timed out or failed: some nodes lack their facts. */
  partial: boolean;
}

type Row = Record<string, unknown>;

const text = (value: unknown): string | null => (value === null || value === undefined ? null : sanitizeFact(value));
const num = (value: unknown): number | null => {
  if (value === null || value === undefined || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
};
const bool = (value: unknown): boolean | null => (typeof value === 'boolean' ? value : null);
const when = (value: unknown): string | null => iso(value) ?? null;

function baseNode(ref: EntityRef, label: string, facts: Record<string, FactValue> = {}, flags: NodeFlag[] = []): GraphNode {
  return { id: ref.id, type: ref.type, key: ref.key, label: sanitizeLabel(label) || ref.key, facts, flags, expandable: true };
}

interface TypeLoader {
  sql: string;
  /** The id column's value as the node key. */
  key: (row: Row) => string;
  /** pg array type of the ids. */
  cast: string;
  build: (ref: EntityRef, row: Row, role: Role) => GraphNode;
}

const LOADERS: Partial<Record<NodeType, TypeLoader>> = {
  alert: {
    sql: `SELECT a.id, a.title, a.severity, a.status, a.source, a.rule_id, a.created_at, t.verdict, t.risk_score
            FROM alerts a LEFT JOIN alert_triage t ON t.alert_id = a.id
           WHERE a.id = ANY($1::int[])`,
    key: (row) => String(row.id),
    cast: 'int',
    build: (ref, row) =>
      baseNode(
        ref,
        `#${ref.key} ${String(row.title ?? '')}`,
        {
          title: text(row.title),
          severity: text(row.severity),
          status: text(row.status),
          source: text(row.source),
          rule_id: num(row.rule_id),
          created_at: when(row.created_at),
          verdict: text(row.verdict),
          risk_score: num(row.risk_score),
        },
        row.status === 'closed' || row.status === 'false_positive' ? ['closed'] : []
      ),
  },
  rule: {
    sql: `SELECT r.id, r.name, r.severity, r.enabled FROM detection_rules r WHERE r.id = ANY($1::int[])`,
    key: (row) => String(row.id),
    cast: 'int',
    build: (ref, row) => baseNode(ref, String(row.name ?? `Rule #${ref.key}`), { name: text(row.name), severity: text(row.severity), enabled: bool(row.enabled) }),
  },
  asset: {
    sql: `SELECT a.id, a.hostname, host(a.ip_address) AS ip, a.asset_type, a.criticality, a.status, a.last_seen,
                 (SELECT count(*) FROM asset_vulnerabilities av WHERE av.asset_id = a.id AND av.status = 'open') AS open_vulns,
                 ag.agent_status, ag.agent_version, ag.agent_last_seen
            FROM assets a
            LEFT JOIN LATERAL (
              SELECT CASE WHEN e.last_seen IS NOT NULL AND e.last_seen > NOW() - ($2::int * INTERVAL '1 minute')
                          THEN 'online' ELSE 'offline' END AS agent_status,
                     e.agent_version, e.last_seen AS agent_last_seen
                FROM edr_agents e WHERE e.asset_id = a.id
               ORDER BY e.last_seen DESC NULLS LAST LIMIT 1
            ) ag ON true
           WHERE a.id = ANY($1::int[])`,
    key: (row) => String(row.id),
    cast: 'int',
    build: (ref, row) => {
      const openVulns = num(row.open_vulns) ?? 0;
      const flags: NodeFlag[] = [];
      if (row.criticality === 'critical') flags.push('critical');
      if (openVulns > 0) flags.push('open_vulns');
      return baseNode(
        ref,
        String(row.hostname || row.ip || `Asset #${ref.key}`),
        {
          hostname: text(row.hostname),
          ip: text(row.ip),
          asset_type: text(row.asset_type),
          criticality: text(row.criticality),
          status: text(row.status),
          last_seen: when(row.last_seen),
          open_vulns: openVulns,
          agent_status: text(row.agent_status),
          agent_version: text(row.agent_version),
          agent_last_seen: when(row.agent_last_seen),
        },
        flags
      );
    },
  },
  vuln: {
    sql: `SELECT v.id, v.cve_id, v.severity, v.cvss_score, v.title FROM vulnerabilities v WHERE v.id = ANY($1::int[])`,
    key: (row) => String(row.id),
    cast: 'int',
    build: (ref, row) =>
      baseNode(ref, String(row.cve_id ?? `Vulnerability #${ref.key}`), {
        cve_id: text(row.cve_id),
        severity: text(row.severity),
        cvss: num(row.cvss_score),
        title: text(row.title),
      }),
  },
  finding: {
    sql: `SELECT f.id, f.title, f.source, f.event_type, f.severity, f.first_seen, f.last_seen, f.resolved_at
            FROM exposure_findings f WHERE f.id = ANY($1::bigint[])`,
    key: (row) => String(row.id),
    cast: 'bigint',
    build: (ref, row) =>
      baseNode(ref, String(row.title || `Finding #${ref.key}`), {
        title: text(row.title),
        source: text(row.source),
        event_type: text(row.event_type),
        severity: text(row.severity),
        first_seen: when(row.first_seen),
        last_seen: when(row.last_seen),
        resolved: row.resolved_at !== null && row.resolved_at !== undefined,
      }),
  },
  identity: {
    sql: `SELECT i.id, i.kind, i.value FROM monitored_identities i WHERE i.id = ANY($1::int[])`,
    key: (row) => String(row.id),
    cast: 'int',
    build: (ref, row) => baseNode(ref, String(row.value ?? `Identity #${ref.key}`), { kind: text(row.kind), value: text(row.value) }),
  },
  shipper: {
    sql: `SELECT s.id, s.name, s.status, s.hostname, s.ip_address, s.version, s.last_seen
            FROM log_shippers s WHERE s.id = ANY($1::int[])`,
    key: (row) => String(row.id),
    cast: 'int',
    build: (ref, row) =>
      baseNode(ref, String(row.name ?? `Shipper #${ref.key}`), {
        name: text(row.name),
        status: text(row.status),
        hostname: text(row.hostname),
        ip_address: text(row.ip_address),
        version: text(row.version),
        last_seen: when(row.last_seen),
      }),
  },
  endpoint: {
    sql: `SELECT e.agent_id::text AS agent_id, e.hostname, e.os, e.agent_version, e.status, e.last_seen
            FROM edr_agents e WHERE e.agent_id = ANY($1::uuid[])`,
    key: (row) => String(row.agent_id).toLowerCase(),
    cast: 'uuid',
    build: (ref, row) =>
      baseNode(ref, String(row.hostname || ref.key), {
        hostname: text(row.hostname),
        os: text(row.os),
        agent_version: text(row.agent_version),
        status: text(row.status),
        last_seen: when(row.last_seen),
      }),
  },
  account: {
    sql: `SELECT u.id, u.username, u.role, u.enabled, u.mfa_enabled, u.last_login FROM users u WHERE u.id = ANY($1::int[])`,
    key: (row) => String(row.id),
    cast: 'int',
    build: (ref, row) =>
      baseNode(ref, String(row.username ?? `Account #${ref.key}`), {
        username: text(row.username),
        role: text(row.role),
        enabled: bool(row.enabled),
        mfa_enabled: bool(row.mfa_enabled),
        last_login: when(row.last_login),
      }),
  },
};

/** A node from its key alone: value types, and record types whose lookup didn't run. */
function keyNode(ref: EntityRef, hint: string | undefined): GraphNode {
  switch (ref.type) {
    case 'user':
      return baseNode(ref, ref.key, { is_email: ref.key.includes('@') });
    case 'domain': {
      const unicode = ref.key.includes('xn--') ? domainToUnicode(ref.key) : '';
      return baseNode(ref, ref.key, { watched: null, unicode: unicode && unicode !== ref.key ? sanitizeFact(unicode) : null });
    }
    case 'ip': {
      const geo = geoipService.lookup(ref.key);
      const isPrivate = isPrivateIp(ref.key);
      const flags: NodeFlag[] = [];
      if (isPrivate) flags.push('private');
      if (geo && geoipService.isForeign(geo.country_code)) flags.push('foreign');
      return baseNode(ref, ref.key, {
        country: geo ? sanitizeFact(geo.country_name) : null,
        country_code: geo ? sanitizeFact(geo.country_code) : null,
        private: isPrivate,
        threat_feeds: null,
      }, flags);
    }
    case 'shipper_tag':
      return baseNode(ref, `Unknown shipper ${ref.key}`, { tag: ref.key });
    case 'account':
      return baseNode(ref, hint ?? `Account #${ref.key}`, { username: hint ?? null });
    case 'alert':
      return baseNode(ref, `Alert #${ref.key}`);
    case 'host':
      return baseNode(ref, ref.key);
    default:
      return baseNode(ref, hint ?? `${ref.type} #${ref.key}`);
  }
}

async function loadType(q: Query, type: NodeType, keys: string[]): Promise<Row[]> {
  const loader = LOADERS[type]!;
  const params: unknown[] = [loader.cast === 'int' || loader.cast === 'bigint' ? keys.map(Number) : keys];
  if (type === 'asset') params.push(OFFLINE_THRESHOLD_MINUTES);
  return q<Row>(loader.sql, params);
}

/**
 * Nodes for `refs` (deduplicated), with facts. Each lookup is a budget step.
 * Types the role can't see are skipped (filterGraph() drops them anyway).
 */
export async function hydrate(budget: BudgetContext, role: Role, refs: EntityRef[], hints: Map<string, string>): Promise<HydrateResult> {
  const byType = new Map<NodeType, Map<string, EntityRef>>();
  for (const ref of refs) {
    if (!canSeeType(role, ref.type)) continue;
    if (!byType.has(ref.type)) byType.set(ref.type, new Map());
    byType.get(ref.type)!.set(ref.key, ref);
  }
  const nodes = new Map<string, GraphNode>();
  const missing = new Set<string>();
  let partial = false;

  for (const [type, keyed] of byType) {
    for (const ref of keyed.values()) nodes.set(ref.id, keyNode(ref, hints.get(ref.id)));
    const loader = LOADERS[type];
    // A non-admin's account node is the username its alert showed, no lookup.
    if (!loader || (type === 'account' && !canSeeAccountDetails(role))) continue;
    const keys = [...keyed.keys()];
    const result = await budget.step(`facts:${type}`, (q) => loadType(q, type, keys));
    if (result.status !== 'ok') {
      partial = true;
      continue;
    }
    const found = new Set<string>();
    for (const row of result.value) {
      const key = loader.key(row);
      const ref = keyed.get(key);
      if (!ref) continue;
      found.add(key);
      nodes.set(ref.id, loader.build(ref, row, role));
    }
    for (const ref of keyed.values()) if (!found.has(ref.key)) missing.add(ref.id);
  }

  // IPs: the local threat-feed names (bulk, enabled feeds only).
  const ips = [...(byType.get('ip')?.keys() ?? [])];
  if (ips.length > 0) {
    const feeds = await budget.step('facts:threat_feeds', (q) =>
      q<{ indicator: string; feeds: string[] }>(
        `SELECT i.indicator, array_agg(DISTINCT f.name ORDER BY f.name) AS feeds
           FROM threat_indicators i JOIN threat_feeds f ON f.id = i.feed_id
          WHERE i.indicator = ANY($1::text[]) AND f.enabled
          GROUP BY i.indicator`,
        [ips]
      )
    );
    if (feeds.status === 'ok') {
      const named = new Map(feeds.value.map((row) => [row.indicator, row.feeds]));
      for (const ip of ips) {
        const node = nodes.get(`ip:${ip}`);
        if (!node) continue;
        const list = named.get(ip) ?? [];
        node.facts.threat_feeds = list.length > 0 ? sanitizeFact(list.join(', ')) : null;
        if (list.length > 0) node.flags.push('threat_feed');
      }
    } else {
      partial = true;
    }
  }

  // Domains: whether a watched domain (own or brand).
  const domains = [...(byType.get('domain')?.keys() ?? [])];
  if (domains.length > 0) {
    const watched = await budget.step('facts:watched_domains', (q) =>
      q<{ domain: string; scope: string }>(`SELECT wd.domain, wd.scope FROM watched_domains wd WHERE wd.domain = ANY($1::text[])`, [domains])
    );
    if (watched.status === 'ok') {
      for (const row of watched.value) {
        const node = nodes.get(`domain:${row.domain}`);
        if (node) node.facts.watched = sanitizeFact(row.scope);
      }
    } else {
      partial = true;
    }
  }

  return { nodes, missing, partial };
}
