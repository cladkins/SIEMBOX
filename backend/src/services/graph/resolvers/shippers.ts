/**
 * Relations of log shippers (current state, not windowed):
 *
 *   shipper_address / ip_shipper / host_shipper
 *       the address and host name a shipper reported (log_shippers.ip_address,
 *       hostname), solid
 *   asset_shipper / shipper_assets
 *       a shipper matched to an asset by host name or IP, as Asset-360 does
 *       (services/assets/assetContext.ts): a heuristic match, dotted
 *
 * A shipper_tag centre (a raw_logs.shipper_id no shipper matches: a ghost
 * shipper) exists while a retained raw log carries it. The devices behind it
 * come with the log relationships of PR 3 (shipped_devices).
 */
import net from 'net';
import type { Query } from '../budget';
import { canonicalIp, entityRef, type EntityRef } from '../entityKey';
import { dir, edgeSpec, EMPTY_PAGE, LABEL_FILTER, pageInMemory, pagedSql, type CenterInfo, type NeighborItem, type PageRequest, type RelationDef, type ResolverCtx } from './common';
import { ipForms, logHost } from './alerts';

export async function loadShipperCenter(q: Query, ref: EntityRef): Promise<CenterInfo> {
  const [row] = await q(`SELECT s.id, s.ip_address, s.hostname FROM log_shippers s WHERE s.id = $1`, [Number(ref.key)]);
  return { exists: Boolean(row), row: row ?? null };
}

/** Whether a retained raw log carries the tag (one probe of idx_raw_logs_shipper_id). */
export async function loadShipperTagCenter(q: Query, ref: EntityRef): Promise<CenterInfo> {
  const [row] = await q<{ seen: boolean }>(`SELECT EXISTS (SELECT 1 FROM raw_logs WHERE shipper_id = $1) AS seen`, [ref.key]);
  return { exists: row?.seen === true, row: null };
}

async function shipperPage(q: Query, ctx: ResolverCtx, page: PageRequest, where: string, params: unknown[], heuristic: boolean) {
  const result = await pagedSql(
    q,
    `SELECT s.id, s.last_seen FROM log_shippers s WHERE (${where}) ${LABEL_FILTER} ORDER BY s.last_seen DESC NULLS LAST, s.id DESC`,
    params,
    `last_seen ${dir(page)} NULLS LAST, id ${dir(page)}`,
    page,
    's.name'
  );
  return {
    items: result.rows.map((row): NeighborItem => {
      const shipper = entityRef('shipper', String(row.id));
      return heuristic
        ? { ref: shipper, edge: edgeSpec('asset_shipper', ctx.center, shipper, 'inventory', 'heuristic') }
        : { ref: shipper, edge: edgeSpec('shipper_address', shipper, ctx.center, 'inventory', 'recorded') };
    }),
    total: result.total,
    totalCapped: result.totalCapped,
  };
}

export const SHIPPER_RELATIONS: RelationDef[] = [
  {
    rel: 'shipper_address',
    label: 'Address',
    center: 'shipper',
    neighborType: 'ip',
    origin: 'inventory',
    style: 'recorded',
    async fetch(_q, ctx, page) {
      const row = ctx.centerInfo.exists ? ctx.centerInfo.row : null;
      if (!row) return EMPTY_PAGE;
      const items: NeighborItem[] = [];
      const ip = canonicalIp(row.ip_address);
      if (ip) {
        const ref = entityRef('ip', ip);
        items.push({ ref, edge: edgeSpec('shipper_address', ctx.center, ref, 'inventory', 'recorded') });
      }
      const host = logHost(row.hostname);
      if (host) {
        const ref = entityRef('host', host);
        items.push({ ref, edge: edgeSpec('shipper_address', ctx.center, ref, 'inventory', 'recorded') });
      }
      return pageInMemory(items, page);
    },
  },
  {
    rel: 'ip_shipper',
    label: 'Shippers at this IP',
    center: 'ip',
    neighborType: 'shipper',
    origin: 'inventory',
    style: 'recorded',
    fetch: (q, ctx, page) => shipperPage(q, ctx, page, 's.ip_address = ANY($1::text[])', [ipForms(ctx.center.key)], false),
  },
  {
    rel: 'host_shipper',
    label: 'Shippers on this host',
    center: 'host',
    neighborType: 'shipper',
    origin: 'inventory',
    style: 'recorded',
    fetch: (q, ctx, page) => shipperPage(q, ctx, page, 'lower(s.hostname) = $1', [ctx.center.key], false),
  },
  {
    rel: 'asset_shipper',
    label: 'Log shipper (matched by host name or IP)',
    center: 'asset',
    neighborType: 'shipper',
    origin: 'inventory',
    style: 'heuristic',
    async fetch(q, ctx, page) {
      const row = ctx.centerInfo.exists ? ctx.centerInfo.row : null;
      if (!row) return EMPTY_PAGE;
      const host = typeof row.hostname === 'string' && row.hostname.trim() ? row.hostname.trim().toLowerCase() : null;
      const ip = canonicalIp(row.ip);
      return shipperPage(
        q,
        ctx,
        page,
        `(($1::text IS NOT NULL AND lower(s.hostname) = $1) OR s.ip_address = ANY($2::text[]))`,
        [host, ip ? ipForms(ip) : []],
        true
      );
    },
  },
  {
    rel: 'shipper_assets',
    label: 'Assets (matched by host name or IP)',
    center: 'shipper',
    neighborType: 'asset',
    origin: 'inventory',
    style: 'heuristic',
    async fetch(q, ctx, page) {
      const row = ctx.centerInfo.exists ? ctx.centerInfo.row : null;
      if (!row) return EMPTY_PAGE;
      const host = typeof row.hostname === 'string' && row.hostname.trim() ? row.hostname.trim().toLowerCase() : null;
      // The ::inet cast only ever sees a valid address.
      const ip = typeof row.ip_address === 'string' && net.isIP(row.ip_address.trim()) ? row.ip_address.trim() : null;
      const result = await pagedSql(
        q,
        `SELECT a.id, a.last_seen
           FROM assets a
          WHERE (($1::text IS NOT NULL AND lower(a.hostname) = $1) OR ($2::text IS NOT NULL AND a.ip_address = $2::inet)) ${LABEL_FILTER}
          ORDER BY a.last_seen DESC NULLS LAST, a.id DESC`,
        [host, ip],
        `last_seen ${dir(page)} NULLS LAST, id ${dir(page)}`,
        page,
        'COALESCE(a.hostname, host(a.ip_address))'
      );
      return {
        items: result.rows.map((r) => {
          const asset = entityRef('asset', String(r.id));
          return { ref: asset, edge: edgeSpec('asset_shipper', asset, ctx.center, 'inventory', 'heuristic') };
        }),
        total: result.total,
        totalCapped: result.totalCapped,
      };
    },
  },
];
