/**
 * SIEMBox accounts (admin only, as GET /api/users/:id and the admin dashboard's
 * activity view are): the sign-ins recorded in audit_logs (auth.login.success,
 * auth.login.failure, auth.login.paused), windowed, with success and failure
 * counts per pair.
 *
 *   account_signins  an account and the IPs it signed in (or tried to) from
 *   ip_signins       an IP and the accounts it signed in (or tried to) as,
 *                    on idx_graph_audit_logs_ip_time
 *
 * A failed sign-in to a username that doesn't exist names no account (only a
 * hash of the username is kept, by design), so it isn't here.
 */
import net from 'net';
import type { Query } from '../budget';
import { canonicalIp, entityRef, type EntityRef } from '../entityKey';
import { dir, edgeSpec, EMPTY_PAGE, iso, LABEL_FILTER, pagedSql, type CenterInfo, type PageRequest, type RelationDef } from './common';

const ADMIN = ['admin'] as const;

export async function loadAccountCenter(q: Query, ref: EntityRef): Promise<CenterInfo> {
  const [row] = await q(`SELECT u.id FROM users u WHERE u.id = $1`, [Number(ref.key)]);
  return { exists: Boolean(row), row: row ?? null };
}

const signinOrder = (page: PageRequest) =>
  page.sort === 'count'
    ? `events ${dir(page)}, last_seen DESC`
    : page.sort === 'first_seen'
      ? `first_seen ${dir(page)}`
      : `last_seen ${dir(page)}`;

const counts = (row: Record<string, unknown>) => ({
  count: Number(row.events),
  successes: Number(row.successes),
  failures: Number(row.failures),
  first_seen: iso(row.first_seen),
  last_seen: iso(row.last_seen),
});

export const ACCOUNT_RELATIONS: RelationDef[] = [
  {
    rel: 'account_signins',
    label: 'Sign-in IPs',
    center: 'account',
    neighborType: 'ip',
    origin: 'accounts',
    style: 'recorded',
    roles: ADMIN,
    async fetch(q, ctx, page) {
      if (!ctx.centerInfo.exists) return EMPTY_PAGE;
      const result = await pagedSql(
        q,
        `SELECT host(l.ip_address) AS label, count(*) AS events,
                count(*) FILTER (WHERE l.action = 'auth.login.success') AS successes,
                count(*) FILTER (WHERE l.action <> 'auth.login.success') AS failures,
                min(l.timestamp) AS first_seen, max(l.timestamp) AS last_seen
           FROM audit_logs l
          WHERE l.user_id = $1 AND l.action LIKE 'auth.login.%' AND l.ip_address IS NOT NULL
            AND l.timestamp >= $2::timestamptz AND l.timestamp < $3::timestamptz
            ${LABEL_FILTER}
          GROUP BY l.ip_address
          ORDER BY max(l.timestamp) DESC`,
        [Number(ctx.center.key), ctx.window.from, ctx.window.to],
        signinOrder(page),
        page,
        'host(l.ip_address)'
      );
      const items = [];
      for (const row of result.rows) {
        const ip = canonicalIp(row.label);
        if (!ip) continue;
        const ref = entityRef('ip', ip);
        items.push({ ref, edge: edgeSpec('account_signins', ctx.center, ref, 'accounts', 'recorded', counts(row)) });
      }
      return { items, total: result.total, totalCapped: result.totalCapped };
    },
  },
  {
    rel: 'ip_signins',
    label: 'SIEMBox sign-ins',
    center: 'ip',
    neighborType: 'account',
    origin: 'accounts',
    style: 'recorded',
    roles: ADMIN,
    async fetch(q, ctx, page) {
      // net.isIP guards the ::inet cast.
      if (!net.isIP(ctx.center.key)) return EMPTY_PAGE;
      const result = await pagedSql(
        q,
        `SELECT l.user_id AS id, u.username AS label, count(*) AS events,
                count(*) FILTER (WHERE l.action = 'auth.login.success') AS successes,
                count(*) FILTER (WHERE l.action <> 'auth.login.success') AS failures,
                min(l.timestamp) AS first_seen, max(l.timestamp) AS last_seen
           FROM audit_logs l JOIN users u ON u.id = l.user_id
          WHERE l.ip_address = $1::inet AND l.action LIKE 'auth.login.%'
            AND l.timestamp >= $2::timestamptz AND l.timestamp < $3::timestamptz
            ${LABEL_FILTER}
          GROUP BY l.user_id, u.username
          ORDER BY max(l.timestamp) DESC`,
        [ctx.center.key, ctx.window.from, ctx.window.to],
        signinOrder(page),
        page,
        'u.username'
      );
      return {
        items: result.rows.map((row) => {
          const ref = entityRef('account', String(row.id));
          return { ref, edge: edgeSpec('account_signins', ref, ctx.center, 'accounts', 'recorded', counts(row)) };
        }),
        total: result.total,
        totalCapped: result.totalCapped,
      };
    },
  },
];
