/**
 * Digital Risk relations (exposure_findings, monitored_identities,
 * watched_domains; tables of hundreds to thousands of rows). Findings count
 * when open, or resolved and last seen in the window.
 *
 *   finding_identity / identity_findings  exposure_findings.identity_id
 *   finding_domain / domain_findings      the watched domain (domain_id) and
 *                                         the lookalike a finding names (detail.lookalike)
 *   alert_finding (from a finding)        exposure_findings.alert_id: the alert it raised
 *   identity_user                         an email identity and the users that
 *                                         are that address, compared in lower
 *                                         case (alerts' user and target_user):
 *                                         a heuristic match, dotted
 *   identity_domain                       an email-domain identity and that domain
 */
import type { Query } from '../budget';
import { canonicalDomain, canonicalId, canonicalUser, entityRef, type EntityRef } from '../entityKey';
import { alertKeyExpr } from '../alertKeys';
import { dir, edgeSpec, EMPTY_PAGE, LABEL_FILTER, pageInMemory, pagedSql, type CenterInfo, type NeighborItem, type PageRequest, type RelationDef, type ResolverCtx } from './common';

export async function loadFindingCenter(q: Query, ref: EntityRef): Promise<CenterInfo> {
  const [row] = await q(
    `SELECT f.id, f.identity_id, f.domain_id, f.alert_id, wd.domain AS watched_domain, f.detail->>'lookalike' AS lookalike
       FROM exposure_findings f LEFT JOIN watched_domains wd ON wd.id = f.domain_id
      WHERE f.id = $1`,
    [Number(ref.key)]
  );
  return { exists: Boolean(row), row: row ?? null };
}

export async function loadIdentityCenter(q: Query, ref: EntityRef): Promise<CenterInfo> {
  const [row] = await q(`SELECT i.id, i.kind, i.value FROM monitored_identities i WHERE i.id = $1`, [Number(ref.key)]);
  return { exists: Boolean(row), row: row ?? null };
}

/** Findings matching `where` on `f` (params from $4 on), open or last seen in the window. */
async function findingPage(q: Query, ctx: ResolverCtx, page: PageRequest, where: string, params: unknown[]) {
  const result = await pagedSql(
    q,
    `SELECT f.id, f.first_seen, f.last_seen
       FROM exposure_findings f
      WHERE (${where})
        AND (f.resolved_at IS NULL OR (f.last_seen >= $1::timestamptz AND f.last_seen < $2::timestamptz))
        ${LABEL_FILTER}
      ORDER BY f.last_seen DESC, f.id DESC`,
    [ctx.window.from, ctx.window.to, ...params],
    page.sort === 'first_seen' ? `first_seen ${dir(page)}, id ${dir(page)}` : `last_seen ${dir(page)}, id ${dir(page)}`,
    page,
    'COALESCE(f.title, f.event_type)'
  );
  return { result, refs: result.rows.map((row) => entityRef('finding', String(row.id))) };
}

const rowOf = (ctx: ResolverCtx) => (ctx.centerInfo.exists ? ctx.centerInfo.row : null);

export const RISK_RELATIONS: RelationDef[] = [
  {
    rel: 'finding_identity',
    label: 'Monitored identity',
    center: 'finding',
    neighborType: 'identity',
    origin: 'risk',
    style: 'recorded',
    async fetch(_q, ctx, page) {
      const id = canonicalId(rowOf(ctx)?.identity_id);
      if (!id) return EMPTY_PAGE;
      const ref = entityRef('identity', id);
      return pageInMemory([{ ref, edge: edgeSpec('finding_identity', ctx.center, ref, 'risk', 'recorded') }], page);
    },
  },
  {
    rel: 'identity_findings',
    label: 'Findings',
    center: 'identity',
    neighborType: 'finding',
    origin: 'risk',
    style: 'recorded',
    async fetch(q, ctx, page) {
      if (!ctx.centerInfo.exists) return EMPTY_PAGE;
      const { result, refs } = await findingPage(q, ctx, page, 'f.identity_id = $3', [Number(ctx.center.key)]);
      return {
        items: refs.map((ref) => ({ ref, edge: edgeSpec('finding_identity', ref, ctx.center, 'risk', 'recorded') })),
        total: result.total,
        totalCapped: result.totalCapped,
      };
    },
  },
  {
    rel: 'finding_domain',
    label: 'Domains',
    center: 'finding',
    neighborType: 'domain',
    origin: 'risk',
    style: 'recorded',
    async fetch(_q, ctx, page) {
      const row = rowOf(ctx);
      if (!row) return EMPTY_PAGE;
      const keys = [...new Set([row.watched_domain, row.lookalike].map(canonicalDomain).filter((d): d is string => d !== null))];
      return pageInMemory(
        keys.map((key) => {
          const ref = entityRef('domain', key);
          return { ref, edge: edgeSpec('finding_domain', ctx.center, ref, 'risk', 'recorded') };
        }),
        page
      );
    },
  },
  {
    rel: 'domain_findings',
    label: 'Digital Risk findings',
    center: 'domain',
    neighborType: 'finding',
    origin: 'risk',
    style: 'recorded',
    async fetch(q, ctx, page) {
      const { result, refs } = await findingPage(
        q,
        ctx,
        page,
        `f.domain_id = (SELECT wd.id FROM watched_domains wd WHERE wd.domain = $3) OR f.detail->>'lookalike' = $3`,
        [ctx.center.key]
      );
      return {
        items: refs.map((ref) => ({ ref, edge: edgeSpec('finding_domain', ref, ctx.center, 'risk', 'recorded') })),
        total: result.total,
        totalCapped: result.totalCapped,
      };
    },
  },
  {
    rel: 'alert_finding',
    label: 'Alert',
    center: 'finding',
    neighborType: 'alert',
    origin: 'risk',
    style: 'recorded',
    async fetch(_q, ctx, page) {
      const id = canonicalId(rowOf(ctx)?.alert_id);
      if (!id) return EMPTY_PAGE;
      const ref = entityRef('alert', id);
      return pageInMemory([{ ref, edge: edgeSpec('alert_finding', ref, ctx.center, 'risk', 'recorded') }], page);
    },
  },
  {
    rel: 'identity_user',
    label: 'Users with this address',
    center: 'identity',
    neighborType: 'user',
    origin: 'risk',
    style: 'heuristic',
    async fetch(q, ctx, page) {
      const row = rowOf(ctx);
      if (!row || row.kind !== 'email' || typeof row.value !== 'string') return EMPTY_PAGE;
      // Alerts in the window (idx_alerts_created_at), compared in lower case:
      // identity values are stored lower-case, log users keep their case.
      const result = await pagedSql(
        q,
        `SELECT x.u AS label, count(*) AS n, min(a.created_at) AS first_seen, max(a.created_at) AS last_seen
           FROM alerts a
           CROSS JOIN LATERAL (VALUES (${alertKeyExpr('user', 'a.matched_data')}), (${alertKeyExpr('target_user', 'a.matched_data')})) AS x(u)
          WHERE a.created_at >= $2::timestamptz AND a.created_at < $3::timestamptz
            AND (lower(${alertKeyExpr('user', 'a.matched_data')}) = $1 OR lower(${alertKeyExpr('target_user', 'a.matched_data')}) = $1)
            AND lower(x.u) = $1
            ${LABEL_FILTER}
          GROUP BY x.u
          ORDER BY max(a.created_at) DESC`,
        [row.value, ctx.window.from, ctx.window.to],
        page.sort === 'count' ? `n ${dir(page)}, label` : `last_seen ${dir(page)}, label`,
        page,
        'x.u'
      );
      const items: NeighborItem[] = [];
      for (const r of result.rows) {
        const user = canonicalUser(r.label);
        if (!user) continue;
        const ref = entityRef('user', user);
        items.push({ ref, edge: edgeSpec('identity_user', ctx.center, ref, 'risk', 'heuristic') });
      }
      return { items, total: result.total, totalCapped: result.totalCapped };
    },
  },
  {
    rel: 'identity_user',
    label: 'Monitored identity',
    center: 'user',
    neighborType: 'identity',
    origin: 'risk',
    style: 'heuristic',
    async fetch(q, ctx, page) {
      if (!ctx.center.key.includes('@')) return EMPTY_PAGE;
      const result = await pagedSql(
        q,
        `SELECT i.id FROM monitored_identities i WHERE i.kind = 'email' AND i.value = lower($1) ${LABEL_FILTER} ORDER BY i.id`,
        [ctx.center.key],
        'id',
        page,
        'i.value'
      );
      return {
        items: result.rows.map((r) => {
          const ref = entityRef('identity', String(r.id));
          return { ref, edge: edgeSpec('identity_user', ref, ctx.center, 'risk', 'heuristic') };
        }),
        total: result.total,
        totalCapped: result.totalCapped,
      };
    },
  },
  {
    rel: 'identity_domain',
    label: 'Domain',
    center: 'identity',
    neighborType: 'domain',
    origin: 'risk',
    style: 'recorded',
    async fetch(_q, ctx, page) {
      const row = rowOf(ctx);
      if (!row || row.kind !== 'email_domain') return EMPTY_PAGE;
      const domain = canonicalDomain(row.value);
      if (!domain) return EMPTY_PAGE;
      const ref = entityRef('domain', domain);
      return pageInMemory([{ ref, edge: edgeSpec('identity_domain', ctx.center, ref, 'risk', 'recorded') }], page);
    },
  },
  {
    rel: 'identity_domain',
    label: 'Monitored email domain',
    center: 'domain',
    neighborType: 'identity',
    origin: 'risk',
    style: 'recorded',
    async fetch(q, ctx, page) {
      const result = await pagedSql(
        q,
        `SELECT i.id FROM monitored_identities i WHERE i.kind = 'email_domain' AND i.value = $1 ${LABEL_FILTER} ORDER BY i.id`,
        [ctx.center.key],
        'id',
        page,
        'i.value'
      );
      return {
        items: result.rows.map((r) => {
          const ref = entityRef('identity', String(r.id));
          return { ref, edge: edgeSpec('identity_domain', ref, ctx.center, 'risk', 'recorded') };
        }),
        total: result.total,
        totalCapped: result.totalCapped,
      };
    },
  },
];
