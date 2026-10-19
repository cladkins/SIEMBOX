/**
 * Relations seen in logs: read from the daily rollup graph_log_edges
 * (migration 044, services/graph/logEdgeRollup.ts). All dashed ("seen in
 * logs": a claim a log made). Edges carry the canonical a -> b relation, so a
 * pair reached from either side is one edge.
 *
 *   a -> b (rel)                 b side (group rel)   built from
 *   ip -> user (signed_in_as)    signed_in_from       parsed, actor != observer, user
 *   ip -> device (seen_on)       actors_seen          parsed, actor != observer
 *   user -> device (user_on)     users_seen           parsed, user
 *   ip -> ip (connected_to)      connected_from       parsed, actor != observer, dest != actor
 *   ip -> domain (queried)       queried_by           parsed, actor != observer, domain
 *   host -> ip (sent_by)         sent_hosts           every log with a header host
 *   device -> shipper (shipped_by) shipped_devices    every log with a shipper tag
 *
 * A device is a host (the syslog header host) or, when the log named none, the
 * sender's ip. For an asset centre the device side uses both its host name and
 * its current IP; the edge goes to that device, which comes with the asset's
 * own host/ip edge. A shipper tag is mapped to its shipper at read time; an
 * unmatched one is a ghost shipper_tag node.
 *
 * Counts are per whole ingest day: a day is in the window when its edges were
 * seen in it (last_seen >= from, first_seen < to). Each direction reads at
 * most READ_CAP rows (newest days first); hitting it marks the total capped.
 */
import type { Query } from '../budget';
import { canonicalIp, entityRef, type EntityRef } from '../entityKey';
import { shipperTags } from '../shipperTags';
import { TOTAL_CAP, type GraphEdge, type NodeType, type RelId } from '../types';
import { dayRange } from '../window';
import type { LogEdgeRel } from '../logEdgeRollup';
import { logHost } from './alerts';
import {
  containsPattern,
  edgeSpec,
  EMPTY_PAGE,
  iso,
  pageInMemory,
  type NeighborItem,
  type PageRequest,
  type RelationDef,
  type RelationPage,
  type ResolverCtx,
} from './common';

export const READ_CAP = 20_000;
/** The relations whose edges show failed and successful sign-ins. */
const OUTCOME_RELS: ReadonlySet<string> = new Set(['signed_in_as', 'seen_on', 'user_on']);

type Side = 'a' | 'b';
interface Key {
  type: NodeType;
  value: string;
}

interface Row {
  n_type: NodeType;
  n_value: string;
  c_type: NodeType;
  c_value: string;
  events: string;
  failures: string;
  successes: string;
  first_seen: Date;
  last_seen: Date;
  graph_total: string;
  read_rows: string;
}

/** The window's ingest days, one day wider each side (the database's clock may not be UTC); first/last_seen bound it exactly. */
export function logDays(ctx: Pick<ResolverCtx, 'window'>): { first: string; last: string } {
  const day = 86_400_000;
  return dayRange({ fromMs: ctx.window.fromMs - day, toMs: ctx.window.toMs + day });
}

const ORDER: Record<string, string> = {
  count: 'events',
  last_seen: 'last_seen',
  first_seen: 'first_seen',
};

/**
 * One relation of the centre: rows of `rel` with the centre on `side`, from
 * each of `keys`, summed per neighbour over the window's days.
 */
async function readEdges(
  q: Query,
  ctx: ResolverCtx,
  rel: LogEdgeRel,
  side: Side,
  keys: Key[],
  page: PageRequest,
  options: { neighborTypes?: NodeType[]; all?: boolean } = {}
): Promise<{ rows: Row[]; total: number; totalCapped: boolean }> {
  if (keys.length === 0) return { rows: [], total: 0, totalCapped: false };
  const other: Side = side === 'a' ? 'b' : 'a';
  const days = logDays(ctx);
  const params: unknown[] = [rel, days.first, days.last, ctx.window.from, ctx.window.to];
  const bind = (value: unknown) => {
    params.push(value);
    return `$${params.length}`;
  };
  const typeFilter = options.neighborTypes ? `AND ${other}_type = ANY(${bind(options.neighborTypes)}::text[])` : '';
  // One ordered index scan per key: the PK (a side) or idx_graph_log_edges_b (b side).
  const arms = keys.map(
    (key) => `(SELECT ${other}_type AS n_type, ${other}_value AS n_value, ${side}_type AS c_type, ${side}_value AS c_value,
                      events, failures, successes, first_seen, last_seen
                 FROM graph_log_edges
                WHERE ${side}_type = ${bind(key.type)} AND ${side}_value = ${bind(key.value)}
                  AND day BETWEEN $2::date AND $3::date AND rel = $1 ${typeFilter}
                  AND last_seen >= $4::timestamptz AND first_seen < $5::timestamptz
                ORDER BY day DESC LIMIT ${READ_CAP})`
  );
  const search = page.q && !options.all ? `WHERE n_value ILIKE ${bind(containsPattern(page.q))} ESCAPE '\\'` : '';
  const order = `${ORDER[page.sort ?? 'count']} ${page.order === 'asc' ? 'ASC' : 'DESC'}, last_seen DESC, n_value`;
  const limit = options.all ? TOTAL_CAP + 1 : page.limit;
  const offset = options.all ? 0 : page.offset;
  const rows = await q<Row>(
    `WITH e AS MATERIALIZED (${arms.join(' UNION ALL ')}),
          agg AS (
            SELECT n_type, n_value,
                   (array_agg(c_type ORDER BY events DESC))[1] AS c_type,
                   (array_agg(c_value ORDER BY events DESC))[1] AS c_value,
                   sum(events) AS events, sum(failures) AS failures, sum(successes) AS successes,
                   min(first_seen) AS first_seen, max(last_seen) AS last_seen
              FROM e ${search} GROUP BY n_type, n_value
          )
     SELECT n_type, n_value, c_type, c_value, events, failures, successes, first_seen, last_seen,
            count(*) OVER () AS graph_total, (SELECT count(*) FROM e) AS read_rows
       FROM agg ORDER BY ${order} LIMIT ${bind(limit)} OFFSET ${bind(offset)}`,
    params
  );
  if (rows.length === 0) {
    if (offset === 0) return { rows, total: 0, totalCapped: false };
    const [counts] = await q<{ total: string; read_rows: string }>(
      `WITH e AS MATERIALIZED (${arms.join(' UNION ALL ')})
       SELECT (SELECT count(*) FROM (SELECT 1 FROM e ${search} GROUP BY n_type, n_value) g) AS total, (SELECT count(*) FROM e) AS read_rows`,
      params.slice(0, -2)
    );
    const total = Number(counts?.total ?? 0);
    return { rows, total: Math.min(total, TOTAL_CAP), totalCapped: total > TOTAL_CAP || Number(counts?.read_rows ?? 0) >= READ_CAP };
  }
  const total = Number(rows[0].graph_total);
  return { rows, total: Math.min(total, TOTAL_CAP), totalCapped: total > TOTAL_CAP || Number(rows[0].read_rows) >= READ_CAP * keys.length };
}

function edgeExtras(rel: LogEdgeRel, row: Row): Partial<GraphEdge> {
  const out: Partial<GraphEdge> = { count: Number(row.events), first_seen: iso(row.first_seen), last_seen: iso(row.last_seen) };
  if (OUTCOME_RELS.has(rel)) {
    out.failures = Number(row.failures);
    out.successes = Number(row.successes);
  }
  if (rel === 'signed_in_as') out.success_after_failures = out.failures! > 0 && out.successes! > 0;
  return out;
}

/**
 * The NEW badge on signed_in_as: pairs whose first day in the rollup is in the
 * window. Only said when the rollup covers days before the window
 * (covered_from), else every pair would look new. Bounded; a timeout leaves
 * the badge off (the caller's step catches nothing here: it is best effort).
 */
async function markNew(q: Query, ctx: ResolverCtx, side: Side, center: Key, items: NeighborItem[]): Promise<void> {
  const signIns = items.filter((item) => item.edge.rel === 'signed_in_as');
  const coveredFrom = ctx.logs?.coveredFrom;
  // It must hold days before the window's first: else nothing could be "seen before".
  if (signIns.length === 0 || !coveredFrom || coveredFrom >= ctx.window.from.slice(0, 10)) return;
  const other: Side = side === 'a' ? 'b' : 'a';
  const values = signIns.map((item) => item.ref.key);
  try {
    await q(`SAVEPOINT graph_new_badge`);
    const rows = await q<{ v: string; first_ever: Date }>(
      `SELECT v, min(first_seen) AS first_ever
         FROM (SELECT ${other}_value AS v, first_seen FROM graph_log_edges
                WHERE ${side}_type = $1 AND ${side}_value = $2 AND rel = 'signed_in_as'
                ORDER BY day LIMIT ${READ_CAP}) s
        WHERE v = ANY($3::text[])
        GROUP BY v`,
      [center.type, center.value, values]
    );
    await q(`RELEASE SAVEPOINT graph_new_badge`);
    const first = new Map(rows.map((row) => [row.v, iso(row.first_ever)]));
    for (const item of signIns) {
      const at = first.get(item.ref.key);
      item.edge.new = Boolean(at && at >= ctx.window.from);
    }
  } catch {
    await q(`ROLLBACK TO SAVEPOINT graph_new_badge`).catch(() => undefined);
  }
}

const refOf = (type: NodeType, value: string): EntityRef => entityRef(type, value);

/** A relation of value centres (ip, host, user, domain, shipper_tag). */
function valueRelation(def: {
  rel: RelId;
  label: string;
  center: NodeType;
  neighborType: NodeType;
  edgeRel: LogEdgeRel;
  side: Side;
  neighborTypes?: NodeType[];
}): RelationDef {
  return {
    rel: def.rel,
    label: def.label,
    center: def.center,
    neighborType: def.neighborType,
    origin: 'logs',
    style: 'logs',
    rollup: true,
    async fetch(q, ctx, page) {
      if (ctx.logs && !ctx.logs.enabled) return EMPTY_PAGE;
      const key: Key = { type: ctx.center.type, value: ctx.center.key };
      if (def.edgeRel === 'shipped_by' && def.side === 'a') return shippersOf(q, ctx, page, [key], ctx.center);
      const result = await readEdges(q, ctx, def.edgeRel, def.side, [key], page, { neighborTypes: def.neighborTypes });
      const items = result.rows.map((row): NeighborItem => {
        const ref = refOf(row.n_type, row.n_value);
        const [source, target] = def.side === 'a' ? [ctx.center, ref] : [ref, ctx.center];
        return { ref, edge: edgeSpec(def.edgeRel, source, target, 'logs', 'logs', edgeExtras(def.edgeRel, row)) };
      });
      if (def.edgeRel === 'signed_in_as') await markNew(q, ctx, def.side, key, items);
      return withNeighborType({ items, total: result.total, totalCapped: result.totalCapped });
    },
  };
}

/** A device group holds hosts, ips or both: say which when it is one. */
function withNeighborType(page: RelationPage): RelationPage {
  const types = new Set(page.items.map((item) => item.ref.type));
  return types.size === 1 ? { ...page, neighborType: [...types][0] } : page;
}

/** The shippers a device's logs came through: few, so paged (and searched by shipper name) in memory. */
async function shippersOf(q: Query, ctx: ResolverCtx, page: PageRequest, keys: Key[], device: EntityRef): Promise<RelationPage> {
  const result = await readEdges(q, ctx, 'shipped_by', 'a', keys, page, { all: true });
  const known = await shipperTags.lookup(q, result.rows.map((row) => row.n_value));
  const merged = new Map<string, NeighborItem>();
  for (const row of result.rows) {
    const id = known.get(row.n_value);
    const ref = id !== undefined ? entityRef('shipper', String(id)) : entityRef('shipper_tag', row.n_value);
    const extras = edgeExtras('shipped_by', row);
    const prev = merged.get(ref.id);
    if (prev) {
      // A shipper's md5 and sha256 tags: one neighbour.
      prev.edge.count = (prev.edge.count ?? 0) + (extras.count ?? 0);
      continue;
    }
    merged.set(ref.id, { ref, edge: edgeSpec('shipped_by', device, ref, 'logs', 'logs', extras) });
  }
  const paged = pageInMemory([...merged.values()], page);
  return { ...paged, total: Math.min(paged.total, TOTAL_CAP), totalCapped: paged.totalCapped || result.totalCapped };
}

/** The devices behind a shipper (its tags) or a ghost tag. */
const shippedDevices = (center: 'shipper' | 'shipper_tag'): RelationDef => ({
  rel: 'shipped_devices',
  label: 'Devices it shipped logs for',
  center,
  neighborType: 'host',
  origin: 'logs',
  style: 'logs',
  rollup: true,
  async fetch(q, ctx, page) {
    if (ctx.logs && !ctx.logs.enabled) return EMPTY_PAGE;
    if (center === 'shipper' && !ctx.centerInfo.exists) return EMPTY_PAGE;
    const tags = center === 'shipper' ? await shipperTags.tagsOf(q, Number(ctx.center.key)) : [ctx.center.key];
    const result = await readEdges(q, ctx, 'shipped_by', 'b', tags.map((value) => ({ type: 'shipper_tag', value })), page);
    const items = result.rows.map((row): NeighborItem => {
      const ref = refOf(row.n_type, row.n_value);
      return { ref, edge: edgeSpec('shipped_by', ref, ctx.center, 'logs', 'logs', edgeExtras('shipped_by', row)) };
    });
    return withNeighborType({ items, total: result.total, totalCapped: result.totalCapped });
  },
});

/** An asset's devices: its host name and its current IP. */
function assetDevices(ctx: ResolverCtx): Array<{ key: Key; ref: EntityRef; rel: RelId }> {
  const row = ctx.centerInfo.exists ? ctx.centerInfo.row : null;
  if (!row) return [];
  const out: Array<{ key: Key; ref: EntityRef; rel: RelId }> = [];
  const host = logHost(row.hostname);
  if (host) out.push({ key: { type: 'host', value: host }, ref: entityRef('host', host), rel: 'asset_host' });
  const ip = canonicalIp(row.ip);
  if (ip) out.push({ key: { type: 'ip', value: ip }, ref: entityRef('ip', ip), rel: 'asset_ip' });
  return out;
}

/** actors_seen / users_seen for an asset: the edge goes to the device, which comes with the asset's own edge to it. */
const assetRelation = (rel: 'actors_seen' | 'users_seen', label: string, neighborType: NodeType, edgeRel: LogEdgeRel): RelationDef => ({
  rel,
  label,
  center: 'asset',
  neighborType,
  origin: 'logs',
  style: 'logs',
  rollup: true,
  async fetch(q, ctx, page) {
    if (ctx.logs && !ctx.logs.enabled) return EMPTY_PAGE;
    const devices = assetDevices(ctx);
    const result = await readEdges(q, ctx, edgeRel, 'b', devices.map((d) => d.key), page);
    const items = result.rows.map((row): NeighborItem => {
      const device = devices.find((d) => d.key.type === row.c_type && d.key.value === row.c_value) ?? devices[0];
      const ref = refOf(row.n_type, row.n_value);
      return {
        ref,
        edge: edgeSpec(edgeRel, ref, device.ref, 'logs', 'logs', edgeExtras(edgeRel, row)),
        extra: [{ ref: device.ref, edge: edgeSpec(device.rel, ctx.center, device.ref, 'inventory', 'recorded') }],
      };
    });
    return { items, total: result.total, totalCapped: result.totalCapped };
  },
});

const DEVICE_TYPES: NodeType[] = ['host', 'ip'];

export const LOG_EDGE_RELATIONS: RelationDef[] = [
  // ip as the actor
  valueRelation({ rel: 'signed_in_as', label: 'Signed in as (seen in logs)', center: 'ip', neighborType: 'user', edgeRel: 'signed_in_as', side: 'a' }),
  valueRelation({ rel: 'seen_on', label: 'Seen on devices', center: 'ip', neighborType: 'host', edgeRel: 'seen_on', side: 'a' }),
  valueRelation({ rel: 'connected_to', label: 'Connected to', center: 'ip', neighborType: 'ip', edgeRel: 'connected_to', side: 'a' }),
  valueRelation({ rel: 'queried', label: 'Domains queried', center: 'ip', neighborType: 'domain', edgeRel: 'queried', side: 'a' }),
  // ip as the device, destination or sender
  valueRelation({ rel: 'actors_seen', label: 'Client IPs seen on it', center: 'ip', neighborType: 'ip', edgeRel: 'seen_on', side: 'b' }),
  valueRelation({ rel: 'users_seen', label: 'Users seen on it', center: 'ip', neighborType: 'user', edgeRel: 'user_on', side: 'b' }),
  valueRelation({ rel: 'connected_from', label: 'Connections from', center: 'ip', neighborType: 'ip', edgeRel: 'connected_to', side: 'b' }),
  valueRelation({ rel: 'sent_hosts', label: 'Host names it sent logs as', center: 'ip', neighborType: 'host', edgeRel: 'sent_by', side: 'b' }),
  valueRelation({ rel: 'shipped_by', label: 'Shipped by', center: 'ip', neighborType: 'shipper', edgeRel: 'shipped_by', side: 'a' }),
  // host as the device
  valueRelation({ rel: 'actors_seen', label: 'Client IPs seen on it', center: 'host', neighborType: 'ip', edgeRel: 'seen_on', side: 'b' }),
  valueRelation({ rel: 'users_seen', label: 'Users seen on it', center: 'host', neighborType: 'user', edgeRel: 'user_on', side: 'b' }),
  valueRelation({ rel: 'sent_by', label: 'Sent from', center: 'host', neighborType: 'ip', edgeRel: 'sent_by', side: 'a' }),
  valueRelation({ rel: 'shipped_by', label: 'Shipped by', center: 'host', neighborType: 'shipper', edgeRel: 'shipped_by', side: 'a' }),
  // user
  valueRelation({ rel: 'signed_in_from', label: 'Signed in from (seen in logs)', center: 'user', neighborType: 'ip', edgeRel: 'signed_in_as', side: 'b' }),
  valueRelation({ rel: 'user_on', label: 'Seen on devices', center: 'user', neighborType: 'host', edgeRel: 'user_on', side: 'a', neighborTypes: DEVICE_TYPES }),
  // domain
  valueRelation({ rel: 'queried_by', label: 'Queried by', center: 'domain', neighborType: 'ip', edgeRel: 'queried', side: 'b' }),
  // shippers
  shippedDevices('shipper'),
  shippedDevices('shipper_tag'),
  // asset (its host name and current IP)
  assetRelation('actors_seen', 'Client IPs seen on it', 'ip', 'seen_on'),
  assetRelation('users_seen', 'Users seen on it', 'user', 'user_on'),
];
