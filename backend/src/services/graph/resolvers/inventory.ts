/**
 * Relations from the asset inventory and vulnerability management. Current
 * state, so not windowed:
 *
 *   asset_ip / ip_asset         assets.ip_address ("current IP": the IP an
 *                               asset had at an event's time is not recorded)
 *   asset_host / host_assets    lower(assets.hostname)
 *   asset_vulns / vuln_assets   asset_vulnerabilities, open only unless
 *                               vuln_status=all, ranked by risk score
 *
 * The edges point from the asset, whichever side was expanded.
 */
import net from 'net';
import type { Query } from '../budget';
import { canonicalIp, entityRef, type EntityRef } from '../entityKey';
import { dir, edgeSpec, EMPTY_PAGE, LABEL_FILTER, pageInMemory, pagedSql, type CenterInfo, type PageRequest, type RelationDef, type ResolverCtx } from './common';
import { logHost } from './alerts';

export async function loadAssetCenter(q: Query, ref: EntityRef): Promise<CenterInfo> {
  const [row] = await q(`SELECT a.id, host(a.ip_address) AS ip, a.hostname FROM assets a WHERE a.id = $1`, [Number(ref.key)]);
  return { exists: Boolean(row), row: row ?? null };
}

export async function loadVulnCenter(q: Query, ref: EntityRef): Promise<CenterInfo> {
  const [row] = await q(`SELECT v.id FROM vulnerabilities v WHERE v.id = $1`, [Number(ref.key)]);
  return { exists: Boolean(row), row: row ?? null };
}

/** Assets matching `where` (on `a`), as a page of asset items with `edge` from each to the centre. */
async function assetPage(
  q: Query,
  ctx: ResolverCtx,
  page: PageRequest,
  where: string,
  params: unknown[],
  rel: 'asset_ip' | 'asset_host'
) {
  const result = await pagedSql(
    q,
    `SELECT a.id, a.last_seen FROM assets a WHERE ${where} ${LABEL_FILTER} ORDER BY a.last_seen DESC NULLS LAST, a.id DESC`,
    params,
    `last_seen ${dir(page)} NULLS LAST, id ${dir(page)}`,
    page,
    'COALESCE(a.hostname, host(a.ip_address))'
  );
  return {
    items: result.rows.map((row) => {
      const asset = entityRef('asset', String(row.id));
      return { ref: asset, edge: edgeSpec(rel, asset, ctx.center, 'inventory', 'recorded') };
    }),
    total: result.total,
    totalCapped: result.totalCapped,
  };
}

const VULN_ORDER = (page: PageRequest) =>
  page.sort === 'first_seen' || page.sort === 'last_seen'
    ? `${page.sort === 'first_seen' ? 'first_detected' : 'last_detected'} ${dir(page)} NULLS LAST, id ${dir(page)}`
    : `is_open ${dir(page)}, risk_score ${dir(page)} NULLS LAST, id ${dir(page)}`;

export const INVENTORY_RELATIONS: RelationDef[] = [
  {
    rel: 'asset_ip',
    label: 'Current IP',
    center: 'asset',
    neighborType: 'ip',
    origin: 'inventory',
    style: 'recorded',
    async fetch(_q, ctx, page) {
      const ip = ctx.centerInfo.exists ? canonicalIp(ctx.centerInfo.row?.ip) : null;
      if (!ip) return EMPTY_PAGE;
      const ref = entityRef('ip', ip);
      return pageInMemory([{ ref, edge: edgeSpec('asset_ip', ctx.center, ref, 'inventory', 'recorded') }], page);
    },
  },
  {
    rel: 'ip_asset',
    label: 'Asset with this IP',
    center: 'ip',
    neighborType: 'asset',
    origin: 'inventory',
    style: 'recorded',
    // net.isIP guards the ::inet cast (entityKey.ts already canonicalized it).
    fetch: (q, ctx, page) =>
      net.isIP(ctx.center.key) ? assetPage(q, ctx, page, 'a.ip_address = $1::inet', [ctx.center.key], 'asset_ip') : Promise.resolve(EMPTY_PAGE),
  },
  {
    rel: 'asset_host',
    label: 'Host name',
    center: 'asset',
    neighborType: 'host',
    origin: 'inventory',
    style: 'recorded',
    async fetch(_q, ctx, page) {
      const host = ctx.centerInfo.exists ? logHost(ctx.centerInfo.row?.hostname) : null;
      if (!host) return EMPTY_PAGE;
      const ref = entityRef('host', host);
      return pageInMemory([{ ref, edge: edgeSpec('asset_host', ctx.center, ref, 'inventory', 'recorded') }], page);
    },
  },
  {
    rel: 'host_assets',
    label: 'Assets with this host name',
    center: 'host',
    neighborType: 'asset',
    origin: 'inventory',
    style: 'recorded',
    fetch: (q, ctx, page) => assetPage(q, ctx, page, 'lower(a.hostname) = $1', [ctx.center.key], 'asset_host'),
  },
  {
    rel: 'asset_vulns',
    label: 'Vulnerabilities',
    center: 'asset',
    neighborType: 'vuln',
    origin: 'inventory',
    style: 'recorded',
    async fetch(q, ctx, page) {
      if (!ctx.centerInfo.exists) return EMPTY_PAGE;
      const result = await pagedSql(
        q,
        `SELECT v.id, av.risk_score, av.status = 'open' AS is_open, av.first_detected, av.last_detected
           FROM asset_vulnerabilities av JOIN vulnerabilities v ON v.id = av.vulnerability_id
          WHERE av.asset_id = $1 AND ($2 = 'all' OR av.status = 'open') ${LABEL_FILTER}
          ORDER BY (av.status = 'open') DESC, av.risk_score DESC NULLS LAST, v.id DESC`,
        [Number(ctx.center.key), ctx.vulnStatus],
        VULN_ORDER(page),
        page,
        `v.cve_id || ' ' || COALESCE(v.title, '')`
      );
      return {
        items: result.rows.map((row) => {
          const vuln = entityRef('vuln', String(row.id));
          return { ref: vuln, edge: edgeSpec('asset_vulns', ctx.center, vuln, 'inventory', 'recorded') };
        }),
        total: result.total,
        totalCapped: result.totalCapped,
      };
    },
  },
  {
    rel: 'vuln_assets',
    label: 'Affected assets',
    center: 'vuln',
    neighborType: 'asset',
    origin: 'inventory',
    style: 'recorded',
    async fetch(q, ctx, page) {
      if (!ctx.centerInfo.exists) return EMPTY_PAGE;
      const result = await pagedSql(
        q,
        `SELECT a.id, av.risk_score, av.status = 'open' AS is_open, av.first_detected, av.last_detected
           FROM asset_vulnerabilities av JOIN assets a ON a.id = av.asset_id
          WHERE av.vulnerability_id = $1 AND ($2 = 'all' OR av.status = 'open') ${LABEL_FILTER}
          ORDER BY (av.status = 'open') DESC, av.risk_score DESC NULLS LAST, a.id DESC`,
        [Number(ctx.center.key), ctx.vulnStatus],
        VULN_ORDER(page),
        page,
        'COALESCE(a.hostname, host(a.ip_address))'
      );
      return {
        items: result.rows.map((row) => {
          const asset = entityRef('asset', String(row.id));
          return { ref: asset, edge: edgeSpec('asset_vulns', asset, ctx.center, 'inventory', 'recorded') };
        }),
        total: result.total,
        totalCapped: result.totalCapped,
      };
    },
  },
];
