/**
 * Relations recorded on alerts.
 *
 * From an alert (read off its row: matched_data keeps a copy of the fields the
 * rule matched, and only these keys are read, never the whole object):
 *   alert_ips      source_ip, client_ip (when different), dest_ip. role: dest;
 *                  else sender when it equals observer_ip (the log's sender,
 *                  which fieldNormalizer fills in when the parser extracted no
 *                  IP); else source
 *   alert_users    user, target_user (junk dropped)
 *   alert_hosts    lower(host): "host named in the log"
 *   alert_domains  domain, lookalike (Digital Risk alerts)
 *   alert_rule     rule_id;  alert_asset  asset_id (EDR)
 *   alert_account  siembox-auth user_id (labelled with the alert's username)
 *   alert_endpoint EDR agent_id (admin)
 *   alert_same_event  alerts on the same parsed log
 *   alert_device   the device that logged it (the syslog header host, else
 *                  the sender IP) and that device's shipper or ghost tag, while
 *                  the log is retained (dashed: seen in logs)
 *
 * To alerts (entity_alerts, rule_alerts): the latest TOTAL_CAP + 1 alerts in
 * the window naming the centre, ranked by severity then recency, each lookup
 * on a migration 043 index (idx_graph_alerts_*, through alertKeys.ts).
 */
import type { Query } from '../budget';
import { canonicalDomain, canonicalHost, canonicalId, canonicalIp, canonicalShipperTag, canonicalUser, canonicalUuid, entityRef, JUNK_USERS, type EntityRef } from '../entityKey';
import { alertIpMatch, alertKeyEquals } from '../alertKeys';
import { shipperTags } from '../shipperTags';
import { TOTAL_CAP, type NodeType } from '../types';
import {
  dir,
  edgeSpec,
  EMPTY_PAGE,
  pageInMemory,
  pagedSql,
  type CenterInfo,
  LABEL_FILTER,
  type EdgeSpec,
  type NeighborItem,
  type PageRequest,
  type RelationDef,
  type RelationPage,
  type ResolverCtx,
} from './common';

/** The alert columns and matched_data keys the alert relations read. */
export const ALERT_CENTER_SQL = `
  SELECT a.id, a.rule_id, a.asset_id, a.parsed_log_id, a.source,
         a.matched_data->>'source_ip'   AS md_source_ip,
         a.matched_data->>'client_ip'   AS md_client_ip,
         a.matched_data->>'dest_ip'     AS md_dest_ip,
         a.matched_data->>'observer_ip' AS md_observer_ip,
         a.matched_data->>'user'        AS md_user,
         a.matched_data->>'target_user' AS md_target_user,
         a.matched_data->>'host'        AS md_host,
         a.matched_data->>'domain'      AS md_domain,
         a.matched_data->>'lookalike'   AS md_lookalike,
         a.matched_data->>'user_id'     AS md_user_id,
         a.matched_data->>'username'    AS md_username,
         a.matched_data->>'agent_id'    AS md_agent_id
    FROM alerts a
   WHERE a.id = $1`;

export async function loadAlertCenter(q: Query, ref: EntityRef): Promise<CenterInfo> {
  const [row] = await q(ALERT_CENTER_SQL, [Number(ref.key)]);
  return { exists: Boolean(row), row: row ?? null };
}

const str = (value: unknown) => (typeof value === 'string' ? value : value === null || value === undefined ? null : String(value));

/** A host value from a log or an alert: a valid host, and not one of the "nobody" words. */
export function logHost(value: unknown): string | null {
  const host = canonicalHost(value);
  return host && !JUNK_USERS.has(host) ? host : null;
}

type Row = Record<string, unknown>;

export function alertIpItems(alert: EntityRef, row: Row): NeighborItem[] {
  const observer = canonicalIp(row.md_observer_ip);
  const dest = canonicalIp(row.md_dest_ip);
  const seen = new Map<string, NeighborItem>();
  for (const value of [row.md_source_ip, row.md_client_ip, row.md_dest_ip]) {
    const ip = canonicalIp(value);
    if (!ip || seen.has(ip)) continue;
    const role = ip === dest ? 'dest' : ip === observer ? 'sender' : 'source';
    const ref = entityRef('ip', ip);
    seen.set(ip, { ref, edge: edgeSpec('alert_ips', alert, ref, 'alerts', 'recorded', { role }) });
  }
  return [...seen.values()];
}

function valueItems(
  alert: EntityRef,
  values: unknown[],
  type: NodeType,
  canonical: (value: unknown) => string | null,
  rel: EdgeSpec['rel']
): NeighborItem[] {
  const keys = [...new Set(values.map(canonical).filter((key): key is string => key !== null))];
  return keys.map((key) => {
    const ref = entityRef(type, key);
    return { ref, edge: edgeSpec(rel, alert, ref, 'alerts', 'recorded') };
  });
}

function single(alert: EntityRef, ref: EntityRef | null, rel: EdgeSpec['rel'], origin: EdgeSpec['origin'] = 'alerts', labelHint?: string): NeighborItem[] {
  if (!ref) return [];
  return [{ ref, edge: edgeSpec(rel, alert, ref, origin, 'recorded'), ...(labelHint ? { labelHint } : {}) }];
}

const rowOf = (ctx: ResolverCtx): Row | null => (ctx.centerInfo.exists ? ctx.centerInfo.row : null);

/** A relation read off the alert's own row. */
function fromRow(
  rel: RelationDef['rel'],
  label: string,
  neighborType: NodeType,
  items: (alert: EntityRef, row: Row) => NeighborItem[],
  extra: Partial<RelationDef> = {}
): RelationDef {
  return {
    rel,
    label,
    center: 'alert',
    neighborType,
    origin: 'alerts',
    style: 'recorded',
    ...extra,
    async fetch(_q, ctx, page) {
      const row = rowOf(ctx);
      return row ? pageInMemory(items(ctx.center, row), page) : EMPTY_PAGE;
    },
  };
}

const SEVERITY_RANK = `CASE a.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END`;

/** The ranking of an alert page: severity then recency, unless the caller sorts by time. */
function alertOrder(page: PageRequest): string {
  if (page.sort === 'last_seen' || page.sort === 'first_seen') {
    const d = dir(page);
    return `created_at ${d}, id ${d}`;
  }
  return page.order === 'asc' ? `sev_rank ASC, created_at ASC, id ASC` : `sev_rank DESC, created_at DESC, id DESC`;
}

interface AlertMatch {
  pred: string;
  roleExpr?: string;
  byAssetExpr?: string;
  edge: (alert: EntityRef, row: Row) => EdgeSpec;
}

/** An IPv6 address's eight groups, from its canonical (compressed) form. */
function ipv6Groups(ip: string): string[] {
  const [head, tail] = ip.split('::');
  const left = head ? head.split(':') : [];
  const right = tail === undefined ? [] : tail ? tail.split(':') : [];
  const zeros = tail === undefined ? [] : Array<string>(8 - left.length - right.length).fill('0');
  return [...left, ...zeros, ...right];
}

/**
 * The spellings an IP is looked up by: alerts keep the text the log had.
 * IPv4 as is and as ::ffff:a.b.c.d; IPv6 compressed (RFC 5952), uncompressed,
 * and zero-padded, each in lower and upper case.
 */
export function ipForms(ip: string): string[] {
  if (!ip.includes(':')) return [ip, `::ffff:${ip}`];
  const groups = ipv6Groups(ip);
  const spellings = [ip, groups.join(':'), groups.map((g) => g.padStart(4, '0')).join(':')];
  return [...new Set(spellings.flatMap((form) => [form, form.toUpperCase()]))];
}

const ipPredicate = (p: string) => alertIpMatch(p, { any: true });
const ipRole = (p: string) =>
  `CASE WHEN ${alertKeyEquals('dest_ip', p, { any: true })} THEN 'dest' WHEN a.matched_data->>'observer_ip' = ANY(${p}::text[]) THEN 'sender' ELSE 'source' END`;

/** The alerts naming the centre, as an SQL predicate on `a` with its params bound through `bind`. */
function alertMatch(ctx: ResolverCtx, bind: (value: unknown) => string): AlertMatch | null {
  const center = ctx.center;
  const toCenter = (rel: EdgeSpec['rel']) => (alert: EntityRef) => edgeSpec(rel, alert, center, 'alerts', 'recorded');
  switch (center.type) {
    case 'ip': {
      const p = bind(ipForms(center.key));
      return {
        pred: ipPredicate(p),
        roleExpr: ipRole(p),
        edge: (alert, row) =>
          edgeSpec('alert_ips', alert, center, 'alerts', 'recorded', { role: (str(row.ip_role) ?? 'source') as 'source' }),
      };
    }
    case 'user': {
      const p = bind(center.key);
      return { pred: `(${alertKeyEquals('user', p)} OR ${alertKeyEquals('target_user', p)})`, edge: toCenter('alert_users') };
    }
    case 'host':
      return { pred: alertKeyEquals('host', bind(center.key)), edge: toCenter('alert_hosts') };
    case 'domain': {
      const p = bind(center.key);
      return {
        pred: `(${alertKeyEquals('domain', p)} OR (a.source = 'domain-monitor' AND ${alertKeyEquals('lookalike', p)}))`,
        edge: toCenter('alert_domains'),
      };
    }
    case 'asset': {
      const id = bind(Number(center.key));
      const ip = canonicalIp(ctx.centerInfo.row?.ip);
      const byAsset = `(a.asset_id = ${id})`;
      return {
        // The asset's current IP: the alerts that name it, which may predate it being this asset's.
        pred: ip ? `(a.asset_id = ${id} OR ${ipPredicate(bind(ipForms(ip)))})` : byAsset,
        byAssetExpr: byAsset,
        edge: (alert, row) =>
          row.by_asset === true
            ? edgeSpec('alert_asset', alert, center, 'alerts', 'recorded')
            : edgeSpec('entity_alerts', alert, center, 'alerts', 'heuristic'),
      };
    }
    case 'account':
      return { pred: `(a.source = 'siembox-auth' AND ${alertKeyEquals('user_id', bind(center.key))})`, edge: toCenter('alert_account') };
    case 'endpoint':
      return { pred: `(a.source = 'edr' AND ${alertKeyEquals('agent_id', bind(center.key))})`, edge: toCenter('alert_endpoint') };
    case 'rule':
      return { pred: `a.rule_id = ${bind(Number(center.key))}`, edge: toCenter('alert_rule') };
    default:
      return null;
  }
}

/** The alerts in the window naming the centre: a page of them, ranked. */
export async function alertsNaming(q: Query, ctx: ResolverCtx, page: PageRequest): Promise<RelationPage> {
  if (!ctx.centerInfo.exists) return EMPTY_PAGE;
  const params: unknown[] = [];
  const bind = (value: unknown) => {
    params.push(value);
    return `$${params.length}`;
  };
  const match = alertMatch(ctx, bind);
  if (!match) return EMPTY_PAGE;
  const inner = `
    SELECT a.id, a.severity, a.created_at,
           ${match.roleExpr ?? 'NULL::text'} AS ip_role,
           ${match.byAssetExpr ?? 'NULL::boolean'} AS by_asset,
           ${SEVERITY_RANK} AS sev_rank
      FROM alerts a
     WHERE ${match.pred}
       AND a.created_at >= ${bind(ctx.window.from)}::timestamptz
       AND a.created_at < ${bind(ctx.window.to)}::timestamptz
       ${LABEL_FILTER}
     ORDER BY a.created_at DESC`;
  const result = await pagedSql(q, inner, params, alertOrder(page), page, 'a.title');
  return {
    items: result.rows.map((row) => {
      const ref = entityRef('alert', String(row.id));
      return { ref, edge: match.edge(ref, row) };
    }),
    total: result.total,
    totalCapped: result.totalCapped,
  };
}

/**
 * How many alerts in the window name the centre, counted over at most
 * TOTAL_CAP + 1 rows (search hints). null when the centre type names none.
 */
export async function countAlertsNaming(q: Query, ctx: ResolverCtx): Promise<{ total: number; capped: boolean } | null> {
  const params: unknown[] = [];
  const bind = (value: unknown) => {
    params.push(value);
    return `$${params.length}`;
  };
  const match = alertMatch(ctx, bind);
  if (!match) return null;
  const [row] = await q<{ n: string }>(
    `SELECT count(*) AS n FROM (
       SELECT 1 FROM alerts a
        WHERE ${match.pred}
          AND a.created_at >= ${bind(ctx.window.from)}::timestamptz AND a.created_at < ${bind(ctx.window.to)}::timestamptz
        LIMIT ${TOTAL_CAP + 1}) s`,
    params
  );
  const n = Number(row?.n ?? 0);
  return { total: Math.min(n, TOTAL_CAP), capped: n > TOTAL_CAP };
}

const ALERT_NAMED_BY: NodeType[] =['ip', 'user', 'host', 'domain', 'asset', 'account', 'endpoint'];

function entityAlerts(center: NodeType): RelationDef {
  return {
    rel: 'entity_alerts',
    label: 'Alerts',
    center,
    neighborType: 'alert',
    origin: 'alerts',
    style: 'recorded',
    fetch: (q, ctx, page) => alertsNaming(q, ctx, page),
  };
}

export const ALERT_RELATIONS: RelationDef[] = [
  fromRow('alert_ips', 'IPs', 'ip', (alert, row) => alertIpItems(alert, row)),
  fromRow('alert_users', 'Users', 'user', (alert, row) => valueItems(alert, [row.md_user, row.md_target_user], 'user', canonicalUser, 'alert_users')),
  fromRow('alert_hosts', 'Hosts named in the log', 'host', (alert, row) => valueItems(alert, [row.md_host], 'host', logHost, 'alert_hosts')),
  fromRow('alert_domains', 'Domains', 'domain', (alert, row) =>
    valueItems(alert, [row.md_domain, row.md_lookalike], 'domain', canonicalDomain, 'alert_domains')
  ),
  fromRow('alert_rule', 'Rule', 'rule', (alert, row) => {
    const id = canonicalId(row.rule_id);
    return single(alert, id ? entityRef('rule', id) : null, 'alert_rule');
  }),
  fromRow('alert_asset', 'Asset', 'asset', (alert, row) => {
    const id = canonicalId(row.asset_id);
    return single(alert, id ? entityRef('asset', id) : null, 'alert_asset');
  }),
  {
    rel: 'alert_finding',
    label: 'Digital Risk findings',
    center: 'alert',
    neighborType: 'finding',
    origin: 'risk',
    style: 'recorded',
    async fetch(q, ctx, page) {
      if (!ctx.centerInfo.exists) return EMPTY_PAGE;
      const result = await pagedSql(
        q,
        `SELECT f.id, f.last_seen FROM exposure_findings f WHERE f.alert_id = $1 ${LABEL_FILTER} ORDER BY f.last_seen DESC, f.id DESC`,
        [Number(ctx.center.key)],
        `last_seen ${dir(page)}, id ${dir(page)}`,
        page,
        'f.title'
      );
      return {
        items: result.rows.map((row) => {
          const ref = entityRef('finding', String(row.id));
          return { ref, edge: edgeSpec('alert_finding', ctx.center, ref, 'risk', 'recorded') };
        }),
        total: result.total,
        totalCapped: result.totalCapped,
      };
    },
  },
  {
    rel: 'alert_same_event',
    label: 'Alerts on the same event',
    center: 'alert',
    neighborType: 'alert',
    origin: 'alerts',
    style: 'recorded',
    async fetch(q, ctx, page) {
      const parsedLogId = canonicalId(rowOf(ctx)?.parsed_log_id);
      if (!parsedLogId) return EMPTY_PAGE;
      const result = await pagedSql(
        q,
        `SELECT a.id, a.created_at FROM alerts a
          WHERE a.parsed_log_id = $1 AND a.id <> $2 ${LABEL_FILTER} ORDER BY a.created_at DESC, a.id DESC`,
        [Number(parsedLogId), Number(ctx.center.key)],
        `created_at ${dir(page)}, id ${dir(page)}`,
        page,
        'a.title'
      );
      return {
        items: result.rows.map((row) => {
          const ref = entityRef('alert', String(row.id));
          // One edge per pair, from the older alert (lower id) to the newer.
          const [a, b] = Number(ref.key) < Number(ctx.center.key) ? [ref, ctx.center] : [ctx.center, ref];
          return { ref, edge: edgeSpec('alert_same_event', a, b, 'alerts', 'recorded') };
        }),
        total: result.total,
        totalCapped: result.totalCapped,
      };
    },
  },
  fromRow('alert_account', 'SIEMBox account', 'account', (alert, row) => {
    if (row.source !== 'siembox-auth') return [];
    const id = canonicalId(row.md_user_id);
    const username = canonicalUser(row.md_username);
    return single(alert, id ? entityRef('account', id) : null, 'alert_account', 'alerts', username ?? undefined);
  }),
  fromRow('alert_endpoint', 'Endpoint agent', 'endpoint', (alert, row) => {
    if (row.source !== 'edr') return [];
    const id = canonicalUuid(row.md_agent_id);
    return single(alert, id ? entityRef('endpoint', id) : null, 'alert_endpoint');
  }),
  {
    rel: 'alert_device',
    label: 'Logged by',
    center: 'alert',
    neighborType: 'host',
    origin: 'logs',
    style: 'logs',
    async fetch(q, ctx, page) {
      const row = rowOf(ctx);
      if (!row) return EMPTY_PAGE;
      const parsedLogId = canonicalId(row.parsed_log_id);
      // Rule alerts name their last log; EDR, sign-in and Digital Risk alerts have none.
      if (!parsedLogId) {
        return row.rule_id === null || row.rule_id === undefined ? EMPTY_PAGE : { ...EMPTY_PAGE, note: 'log_expired' };
      }
      const [log] = await q<{ hostname: string | null; source_ip: string | null; shipper_id: string | null }>(
        `SELECT rl.hostname, rl.source_ip, rl.shipper_id
           FROM parsed_logs pl JOIN raw_logs rl ON rl.id = pl.raw_log_id
          WHERE pl.id = $1`,
        [Number(parsedLogId)]
      );
      if (!log) return { ...EMPTY_PAGE, note: 'log_expired' };
      const host = logHost(log.hostname);
      const sender = canonicalIp(log.source_ip);
      const device = host ? entityRef('host', host) : sender ? entityRef('ip', sender) : null;
      if (!device) return EMPTY_PAGE;
      const item: NeighborItem = { ref: device, edge: edgeSpec('alert_device', ctx.center, device, 'logs', 'logs'), extra: [] };
      const tag = canonicalShipperTag(log.shipper_id);
      if (tag) {
        const known = await shipperTags.lookup(q, [tag]);
        const id = known.get(tag);
        const shipper = id !== undefined ? entityRef('shipper', String(id)) : entityRef('shipper_tag', tag);
        item.extra!.push({ ref: shipper, edge: edgeSpec('shipped_by', device, shipper, 'logs', 'logs') });
      }
      return pageInMemory([item], page);
    },
  },
  {
    rel: 'rule_alerts',
    label: 'Alerts',
    center: 'rule',
    neighborType: 'alert',
    origin: 'alerts',
    style: 'recorded',
    fetch: (q, ctx, page) => alertsNaming(q, ctx, page),
  },
  ...ALERT_NAMED_BY.map(entityAlerts),
];
