/**
 * Relations of Application Monitoring's inventory (application_inventory and
 * application_vuln_links, migration 048). Current state, like the inventory
 * page (rows drop out with its retention), so not windowed; solid edges, from
 * the inventory, never the dashed edges of what a log said.
 *
 *   runs_app      a location runs an application (location -> application),
 *                 with the versions, evidence sources and event count on the edge:
 *                   asset    any inventory location SIEMBox knows as the asset
 *                            (application_location_assets: its id, its IP, its
 *                            host name, a shipper at its address)
 *                   host     a logging host by name (syslog header host name)
 *                   ip       a logging host known only by its sender IP
 *                   shipper  a log shipper's host (its containers)
 *                 Network evidence (user agents, DNS queries) is not "runs".
 *   uses_app      a client IP seen using an application on the network (user
 *                 agent, DNS query): ip -> application, marked network
 *   app_vulns     an application has an open vulnerability (application ->
 *                 vuln): match 'exact' for an EDR finding on one of its
 *                 packages (solid), 'best_effort' for a finding on a host
 *                 where it runs whose title names the product (dotted)
 *
 * From an application centre the same edges are reached as app_assets,
 * app_hosts, app_ips, app_shippers, app_clients and app_vulns; a vuln centre
 * reaches its applications as vuln_apps. Every list goes through pagedSql():
 * counted over at most TOTAL_CAP + 1 neighbours and cut to the page, so an
 * application on 500 clients is a "500 clients, very common" group with a
 * page of them, not 500 nodes.
 *
 * Every lookup is an index probe: application_inventory by its primary key
 * (app_id, loc_type, ...) or idx_application_inventory_location (loc_type,
 * loc_key); application_vuln_links by its primary key (app_id, ...) or
 * idx_application_vuln_links_vuln (graphPlans.db.test.ts).
 */
import type { Query } from '../budget';
import { canonicalHost, canonicalIp, entityRef, type EntityRef } from '../entityKey';
import { sanitizeFact } from '../labels';
import type { GraphEdge, RelId } from '../types';
import { NETWORK_SOURCES } from '../../applications/rollup';
import { compareVersions } from '../../applications/inventory';
import { dir, edgeSpec, EMPTY_PAGE, LABEL_FILTER, pagedSql, type CenterInfo, type NeighborItem, type PageRequest, type RelationDef, type ResolverCtx } from './common';

/** Versions an edge carries at most (the newest). */
export const EDGE_VERSIONS = 5;

/** The evidence sources that only say an application was seen on the network. */
export const NETWORK_ONLY: readonly string[] = NETWORK_SOURCES;

export async function loadApplicationCenter(q: Query, ref: EntityRef): Promise<CenterInfo> {
  const [row] = await q(`SELECT s.id, s.name FROM application_signatures s WHERE s.id = $1`, [ref.key]);
  return { exists: Boolean(row), row: row ?? null };
}

type InvRow = Record<string, unknown> & {
  id: string | number;
  events: string | number | null;
  first_seen: unknown;
  last_seen: unknown;
  sources: string[] | null;
  versions: string[] | null;
};

/** The edge facts of an aggregated inventory row: versions (oldest first, the newest EDGE_VERSIONS), sources, count. Pure. */
export function inventoryEdgeFacts(row: Pick<InvRow, 'events' | 'first_seen' | 'last_seen' | 'sources' | 'versions'>, network: boolean): Partial<GraphEdge> {
  const versions = [...new Set((row.versions ?? []).filter((v) => typeof v === 'string' && v !== '').map((v) => sanitizeFact(v)))]
    .sort(compareVersions)
    .slice(-EDGE_VERSIONS);
  const out: Partial<GraphEdge> = {
    count: Number(row.events ?? 0),
    versions,
    sources: [...new Set(row.sources ?? [])].sort(),
  };
  const first = row.first_seen instanceof Date ? row.first_seen.toISOString() : typeof row.first_seen === 'string' ? new Date(row.first_seen).toISOString() : undefined;
  const last = row.last_seen instanceof Date ? row.last_seen.toISOString() : typeof row.last_seen === 'string' ? new Date(row.last_seen).toISOString() : undefined;
  if (first) out.first_seen = first;
  if (last) out.last_seen = last;
  if (network) out.network = true;
  return out;
}

/** The aggregate columns every inventory list selects (over application_inventory i). */
const AGG = `sum(i.events) AS events, min(i.first_seen) AS first_seen, max(i.last_seen) AS last_seen,
             array_agg(DISTINCT i.source) AS sources,
             array_agg(DISTINCT i.version) FILTER (WHERE i.version <> '') AS versions`;

/** Page order over the capped rows: latest seen first (or by count / first seen). */
function invOrder(page: PageRequest): string {
  const d = dir(page);
  if (page.sort === 'count') return `events ${d} NULLS LAST, id ${d}`;
  if (page.sort === 'first_seen') return `first_seen ${d}, id ${d}`;
  return `last_seen ${d}, id ${d}`;
}

/**
 * The applications of one location kind: `where` (on i) picks the location's
 * inventory rows; only applications of the stored signature set, as the
 * inventory page lists them. Edges point from the centre (the location).
 */
async function appsAt(q: Query, ctx: ResolverCtx, page: PageRequest, where: string, params: unknown[], rel: 'runs_app' | 'uses_app') {
  const result = await pagedSql<InvRow>(
    q,
    `SELECT i.app_id AS id, ${AGG}
       FROM application_inventory i JOIN application_signatures s ON s.id = i.app_id
      WHERE ${where} ${LABEL_FILTER}
      GROUP BY i.app_id
      ORDER BY max(i.last_seen) DESC, i.app_id DESC`,
    params,
    invOrder(page),
    page,
    `s.name || ' ' || s.vendor`
  );
  return {
    items: result.rows.map((row): NeighborItem => {
      const app = entityRef('application', String(row.id));
      return { ref: app, edge: edgeSpec(rel, ctx.center, app, 'inventory', 'recorded', inventoryEdgeFacts(row, rel === 'uses_app')) };
    }),
    total: result.total,
    totalCapped: result.totalCapped,
  };
}

/** An application's locations of one kind (`where` on i, $1 the app id), as `type` neighbours keyed by loc_key. */
async function locationsOf(
  q: Query,
  ctx: ResolverCtx,
  page: PageRequest,
  opts: { where: string; params: unknown[]; label: string; join?: string; key: (locKey: string) => EntityRef | null; rel: 'runs_app' | 'uses_app' }
) {
  const result = await pagedSql<InvRow>(
    q,
    `SELECT i.loc_key AS id, ${AGG}
       FROM application_inventory i ${opts.join ?? ''}
      WHERE i.app_id = $1 AND ${opts.where} ${LABEL_FILTER}
      GROUP BY i.loc_key
      ORDER BY max(i.last_seen) DESC, i.loc_key DESC`,
    [ctx.center.key, ...opts.params],
    invOrder(page),
    page,
    opts.label
  );
  const items: NeighborItem[] = [];
  for (const row of result.rows) {
    const ref = opts.key(String(row.id));
    if (!ref) continue;
    items.push({ ref, edge: edgeSpec(opts.rel, ref, ctx.center, 'inventory', 'recorded', inventoryEdgeFacts(row, opts.rel === 'uses_app')) });
  }
  return { items, total: result.total, totalCapped: result.totalCapped };
}

type VulnRow = Record<string, unknown> & { id: string | number; assets: string | number; exact: boolean; versions: string[] | null };

/** An app_vulns edge from `app` to `vuln`: exact (an EDR package finding) is solid, best effort dotted. */
function vulnEdge(app: EntityRef, vuln: EntityRef, row: VulnRow) {
  const versions = [...new Set((row.versions ?? []).filter(Boolean).map((v) => sanitizeFact(v)))].sort(compareVersions).slice(-EDGE_VERSIONS);
  return edgeSpec('app_vulns', app, vuln, 'inventory', row.exact ? 'recorded' : 'heuristic', {
    match: row.exact ? 'exact' : 'best_effort',
    count: Number(row.assets ?? 0),
    ...(versions.length ? { versions } : {}),
  });
}

const VULN_PAGE_ORDER = (page: PageRequest) => `exact ${dir(page)}, cvss ${dir(page)} NULLS LAST, id ${dir(page)}`;

/** The relation a location centre reaches its applications by (one per centre type). */
function runsApp(center: 'asset' | 'host' | 'ip' | 'shipper', label: string, fetch: RelationDef['fetch']): RelationDef {
  return { rel: 'runs_app', label, center, neighborType: 'application', origin: 'inventory', style: 'recorded', fetch };
}

/** The application's locations: (rel id, label, neighbour type). */
function appRel(rel: RelId, label: string, neighborType: RelationDef['neighborType'], fetch: RelationDef['fetch'], style: RelationDef['style'] = 'recorded'): RelationDef {
  return { rel, label, center: 'application', neighborType, origin: 'inventory', style, fetch };
}

export const APPLICATION_RELATIONS: RelationDef[] = [
  runsApp('asset', 'Applications', async (q, ctx, page) => {
    if (!ctx.centerInfo.exists) return EMPTY_PAGE;
    // Every inventory location that is this asset (the view Application
    // Monitoring resolves locations with), then their rows.
    return appsAt(
      q,
      ctx,
      page,
      `(i.app_id, i.loc_type, i.loc_key) IN (SELECT la.app_id, la.loc_type, la.loc_key FROM application_location_assets la WHERE la.asset_id = $1)
        AND i.source <> ALL($2::text[])`,
      [Number(ctx.center.key), NETWORK_ONLY],
      'runs_app'
    );
  }),
  runsApp('host', 'Applications', (q, ctx, page) =>
    appsAt(q, ctx, page, `i.loc_type = 'host' AND i.loc_key = $1 AND i.source <> ALL($2::text[])`, [ctx.center.key, NETWORK_ONLY], 'runs_app')
  ),
  runsApp('ip', 'Applications (logging host)', (q, ctx, page) =>
    appsAt(q, ctx, page, `i.loc_type = 'host' AND i.loc_key = $1 AND i.source <> ALL($2::text[])`, [ctx.center.key, NETWORK_ONLY], 'runs_app')
  ),
  {
    rel: 'uses_app',
    label: 'Applications used (seen on the network)',
    center: 'ip',
    neighborType: 'application',
    origin: 'inventory',
    style: 'recorded',
    fetch: (q, ctx, page) => appsAt(q, ctx, page, `i.loc_type = 'client' AND i.loc_key = $1`, [ctx.center.key], 'uses_app'),
  },
  runsApp('shipper', 'Applications (containers)', (q, ctx, page) => {
    if (!ctx.centerInfo.exists) return Promise.resolve(EMPTY_PAGE);
    return appsAt(q, ctx, page, `i.loc_type = 'shipper' AND i.loc_key = $1`, [ctx.center.key], 'runs_app');
  }),

  appRel('app_assets', 'Assets running it', 'asset', async (q, ctx, page) => {
    if (!ctx.centerInfo.exists) return EMPTY_PAGE;
    const result = await pagedSql<InvRow>(
      q,
      `SELECT a.id, ${AGG}
         FROM (SELECT DISTINCT la.asset_id, la.loc_type, la.loc_key FROM application_location_assets la
                WHERE la.app_id = $1 AND la.source <> ALL($2::text[])) la
         JOIN assets a ON a.id = la.asset_id
         JOIN application_inventory i ON i.app_id = $1 AND i.loc_type = la.loc_type AND i.loc_key = la.loc_key AND i.source <> ALL($2::text[])
        WHERE TRUE ${LABEL_FILTER}
        GROUP BY a.id
        ORDER BY max(i.last_seen) DESC, a.id DESC`,
      [ctx.center.key, NETWORK_ONLY],
      invOrder(page),
      page,
      'COALESCE(a.hostname, host(a.ip_address))'
    );
    return {
      items: result.rows.map((row) => {
        const asset = entityRef('asset', String(row.id));
        return { ref: asset, edge: edgeSpec('runs_app', asset, ctx.center, 'inventory', 'recorded', inventoryEdgeFacts(row, false)) };
      }),
      total: result.total,
      totalCapped: result.totalCapped,
    };
  }),
  // Logging hosts by name, and those known only by their sender IP: the
  // device itself, whether or not it is also an asset.
  appRel('app_hosts', 'Logging hosts running it', 'host', async (q, ctx, page) => {
    if (!ctx.centerInfo.exists) return EMPTY_PAGE;
    return locationsOf(q, ctx, page, {
      where: `i.loc_type = 'host' AND graph_ip(i.loc_key) IS NULL AND i.source <> ALL($2::text[])`,
      params: [NETWORK_ONLY],
      label: 'i.loc_key',
      key: (k) => (canonicalHost(k) ? entityRef('host', canonicalHost(k)!) : null),
      rel: 'runs_app',
    });
  }),
  appRel('app_ips', 'Logging IPs running it', 'ip', async (q, ctx, page) => {
    if (!ctx.centerInfo.exists) return EMPTY_PAGE;
    return locationsOf(q, ctx, page, {
      where: `i.loc_type = 'host' AND graph_ip(i.loc_key) IS NOT NULL AND i.source <> ALL($2::text[])`,
      params: [NETWORK_ONLY],
      label: 'i.loc_key',
      key: (k) => (canonicalIp(k) ? entityRef('ip', canonicalIp(k)!) : null),
      rel: 'runs_app',
    });
  }),
  appRel('app_shippers', 'Container hosts (log shippers)', 'shipper', async (q, ctx, page) => {
    if (!ctx.centerInfo.exists) return EMPTY_PAGE;
    return locationsOf(q, ctx, page, {
      where: `i.loc_type = 'shipper'`,
      params: [],
      join: `JOIN log_shippers ls ON ls.id::text = i.loc_key`,
      label: 'ls.name',
      key: (k) => (/^[1-9][0-9]{0,9}$/.test(k) ? entityRef('shipper', k) : null),
      rel: 'runs_app',
    });
  }),
  appRel('app_clients', 'Clients using it (seen on the network)', 'ip', async (q, ctx, page) => {
    if (!ctx.centerInfo.exists) return EMPTY_PAGE;
    return locationsOf(q, ctx, page, {
      where: `i.loc_type = 'client'`,
      params: [],
      label: 'i.loc_key',
      key: (k) => (canonicalIp(k) ? entityRef('ip', canonicalIp(k)!) : null),
      rel: 'uses_app',
    });
  }),
  appRel('app_vulns', 'Open vulnerabilities', 'vuln', async (q, ctx, page) => {
    if (!ctx.centerInfo.exists) return EMPTY_PAGE;
    const result = await pagedSql<VulnRow>(
      q,
      `SELECT v.id, v.cvss_score AS cvss, count(DISTINCT l.asset_id) AS assets, bool_or(l.match = 'package') AS exact,
              array_agg(DISTINCT l.version) FILTER (WHERE l.version <> '') AS versions
         FROM application_vuln_links l JOIN vulnerabilities v ON v.id = l.vulnerability_id
        WHERE l.app_id = $1 ${LABEL_FILTER}
        GROUP BY v.id, v.cvss_score
        ORDER BY bool_or(l.match = 'package') DESC, v.cvss_score DESC NULLS LAST, v.id DESC`,
      [ctx.center.key],
      VULN_PAGE_ORDER(page),
      page,
      `v.cve_id || ' ' || COALESCE(v.title, '')`
    );
    return {
      items: result.rows.map((row) => {
        const vuln = entityRef('vuln', String(row.id));
        return { ref: vuln, edge: vulnEdge(ctx.center, vuln, row) };
      }),
      total: result.total,
      totalCapped: result.totalCapped,
    };
  }),
  {
    rel: 'vuln_apps',
    label: 'Applications',
    center: 'vuln',
    neighborType: 'application',
    origin: 'inventory',
    style: 'recorded',
    async fetch(q, ctx, page) {
      if (!ctx.centerInfo.exists) return EMPTY_PAGE;
      const result = await pagedSql<VulnRow>(
        q,
        `SELECT l.app_id AS id, count(DISTINCT l.asset_id) AS assets, bool_or(l.match = 'package') AS exact,
                array_agg(DISTINCT l.version) FILTER (WHERE l.version <> '') AS versions
           FROM application_vuln_links l JOIN application_signatures s ON s.id = l.app_id
          WHERE l.vulnerability_id = $1 ${LABEL_FILTER}
          GROUP BY l.app_id
          ORDER BY bool_or(l.match = 'package') DESC, count(DISTINCT l.asset_id) DESC, l.app_id DESC`,
        [Number(ctx.center.key)],
        `exact ${dir(page)}, assets ${dir(page)}, id ${dir(page)}`,
        page,
        `s.name || ' ' || s.vendor`
      );
      return {
        items: result.rows.map((row) => {
          const app = entityRef('application', String(row.id));
          return { ref: app, edge: vulnEdge(app, ctx.center, row) };
        }),
        total: result.total,
        totalCapped: result.totalCapped,
      };
    },
  },
];
