/**
 * Endpoint (EDR) agents: analysts, operators and admins, as the Endpoints page
 * and GET /api/edr/agents/:id are. Every role still sees an asset's agent
 * status as facts on the asset node (hydrate.ts), the same as Asset-360 shows it.
 *
 *   asset_endpoint  edr_agents.asset_id, from either side
 *   endpoint_vulns  the open findings on the endpoint's asset
 *
 * The alerts an agent raised are entity_alerts (alerts.ts).
 */
import type { Query } from '../budget';
import { canonicalId, entityRef, type EntityRef } from '../entityKey';
import { dir, edgeSpec, EMPTY_PAGE, LABEL_FILTER, pageInMemory, pagedSql, type CenterInfo, type RelationDef } from './common';
import { vulnsOfAssets } from './inventory';

export async function loadEndpointCenter(q: Query, ref: EntityRef): Promise<CenterInfo> {
  const [row] = await q(`SELECT e.agent_id, e.asset_id FROM edr_agents e WHERE e.agent_id = $1::uuid`, [ref.key]);
  return { exists: Boolean(row), row: row ?? null };
}

export const ENDPOINT_RELATIONS: RelationDef[] = [
  {
    rel: 'asset_endpoint',
    label: 'Endpoint agent',
    center: 'asset',
    neighborType: 'endpoint',
    origin: 'inventory',
    style: 'recorded',
    async fetch(q, ctx, page) {
      if (!ctx.centerInfo.exists) return EMPTY_PAGE;
      const result = await pagedSql(
        q,
        `SELECT e.agent_id::text AS id, e.last_seen
           FROM edr_agents e WHERE e.asset_id = $1 ${LABEL_FILTER} ORDER BY e.last_seen DESC NULLS LAST`,
        [Number(ctx.center.key)],
        `last_seen ${dir(page)} NULLS LAST, id`,
        page,
        'COALESCE(e.hostname, e.agent_id::text)'
      );
      return {
        items: result.rows.map((row) => {
          const ref = entityRef('endpoint', String(row.id).toLowerCase());
          return { ref, edge: edgeSpec('asset_endpoint', ctx.center, ref, 'inventory', 'recorded') };
        }),
        total: result.total,
        totalCapped: result.totalCapped,
      };
    },
  },
  {
    rel: 'asset_endpoint',
    label: 'Asset',
    center: 'endpoint',
    neighborType: 'asset',
    origin: 'inventory',
    style: 'recorded',
    async fetch(_q, ctx, page) {
      const id = ctx.centerInfo.exists ? canonicalId(ctx.centerInfo.row?.asset_id) : null;
      if (!id) return EMPTY_PAGE;
      const ref = entityRef('asset', id);
      return pageInMemory([{ ref, edge: edgeSpec('asset_endpoint', ref, ctx.center, 'inventory', 'recorded') }], page);
    },
  },
  {
    rel: 'endpoint_vulns',
    label: 'Vulnerabilities',
    center: 'endpoint',
    neighborType: 'vuln',
    origin: 'inventory',
    style: 'recorded',
    fetch(q, ctx, page) {
      const id = ctx.centerInfo.exists ? canonicalId(ctx.centerInfo.row?.asset_id) : null;
      return id ? vulnsOfAssets(q, ctx, page, 'a.id = $1', [Number(id)], 'endpoint_vulns') : Promise.resolve(EMPTY_PAGE);
    },
  },
];
