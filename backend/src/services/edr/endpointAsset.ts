/**
 * Which asset an endpoint agent reports on: a sticky link.
 *
 * Assets are keyed by IP (assets.ip_address is unique), and a laptop's IP
 * changes with every network, VPN and hotspot. Re-resolving the agent's asset
 * from its current IP on every report (as ingest used to) made one machine
 * into one asset per address it ever had, each keeping the findings stored
 * while the agent pointed at it. Now:
 *
 *   - An enrolled agent stays on its asset (edr_agents.asset_id).
 *   - When an inventory reports a new IP:
 *       nobody holds it            -> the agent's asset takes the IP;
 *       a duplicate of this agent  -> merged into the agent's asset (strong
 *         holds it                    evidence only, see findAutoMergeCandidates),
 *                                     then the asset takes the IP;
 *       another device holds it    -> the agent's asset keeps its IP and records
 *         (another agent's asset, an  the new one in metadata.current_ip (and
 *         nmap-found host, ...)       metadata.ip_history); nothing is stolen.
 *   - An agent with no asset yet (just enrolled, or its asset was deleted)
 *     reuses an asset that clearly is its machine (one recording its agent id,
 *     or with its hardware MAC, and no agent of its own), else the asset at its
 *     IP (so an endpoint still correlates with the nmap/log asset of that
 *     address), else a new one.
 *
 * Every report also folds in this agent's strong duplicates (an automatic,
 * audited merge), and runEndpointAssetBackfill() does the same once per
 * start for every agent, which cleans up rows the old behaviour left behind.
 * Weaker evidence (same host name) is only offered as a hint on the asset
 * page (services/assets/assetMerge.ts findDuplicateHints), for a manual merge.
 */
import type { PoolClient } from 'pg';
import pool from '../../config/database';
import { logger } from '../../utils/logger';
import { identifyingMac } from '../assets/assetIdentity';
import { addIpHistory, mergeAssets } from '../assets/assetMerge';

export interface EndpointFacts {
  ip: string | null;
  hostname?: string | null;
  mac?: string | null;
  os?: string | null;
  os_version?: string | null;
  /** Merged into assets.metadata (the agent's own keys). */
  metadata?: Record<string, unknown>;
}

export type IpOutcome = 'unchanged' | 'moved' | 'moved_after_merge' | 'held_by_other' | 'none';

export interface EndpointLink {
  assetId: number | null;
  /** How the asset was found: kept (the agent's own), reused, by_ip, created. */
  link: 'kept' | 'reused' | 'by_ip' | 'created' | 'none';
  ip: IpOutcome;
  /** Assets folded in by the automatic merge. */
  merged: number[];
}

interface Candidate {
  id: number;
  reason: 'agent_id' | 'mac';
}

/**
 * Assets that are certainly this agent's own duplicates: no agent of their own
 * attached, and either
 *   (a) metadata.agent_id is this agent (only an agent's own inventory writes
 *       it), and the asset's MAC, if it has a hardware one, is one of this
 *       agent's (so an nmap-found host now at an address the agent once used
 *       is not taken), or
 *   (b) created by an endpoint agent (discovery_method 'edr_agent') with the
 *       same hardware MAC as this agent (assetIdentity.isUsableMac: random,
 *       locally administered and zero MACs never count).
 * Never on host name alone, and never an nmap/log/manual asset on MAC alone.
 */
export async function findAutoMergeCandidates(
  c: PoolClient | typeof pool,
  agentId: string,
  assetId: number,
  agentMacs: Array<string | null | undefined>
): Promise<Candidate[]> {
  const macs = [...new Set(agentMacs.map(identifyingMac).filter((m): m is string => !!m))];
  const r = await c.query(
    `SELECT a.id, a.discovery_method, a.mac_address, a.metadata->>'agent_id' AS meta_agent
       FROM assets a
      WHERE a.id <> $2
        AND NOT EXISTS (SELECT 1 FROM edr_agents e WHERE e.asset_id = a.id)
        AND (a.metadata->>'agent_id' = $1
             OR (a.discovery_method = 'edr_agent' AND cardinality($3::text[]) > 0
                 AND regexp_replace(lower(coalesce(a.mac_address, '')), '[^0-9a-f]', '', 'g')
                     = ANY(SELECT replace(m, ':', '') FROM unnest($3::text[]) m)))
      ORDER BY a.id`,
    [agentId, assetId, macs]
  );
  const out: Candidate[] = [];
  for (const row of r.rows) {
    const mac = identifyingMac(row.mac_address);
    if (row.meta_agent === agentId && (row.discovery_method === 'edr_agent' || !mac || macs.includes(mac))) {
      out.push({ id: row.id, reason: 'agent_id' });
    } else if (row.discovery_method === 'edr_agent' && mac && macs.includes(mac)) {
      out.push({ id: row.id, reason: 'mac' });
    }
  }
  return out;
}

/** Fold this agent's strong duplicates into its asset (audited). Returns the merged ids. */
async function autoMerge(c: PoolClient, agentId: string, assetId: number, agentMacs: Array<string | null | undefined>, trigger: string): Promise<number[]> {
  const candidates = await findAutoMergeCandidates(c, agentId, assetId, agentMacs);
  if (!candidates.length) return [];
  const reasons = [...new Set(candidates.map((x) => x.reason))].join('+');
  await mergeAssets(assetId, candidates.map((x) => x.id), {
    mode: 'auto',
    reason: reasons,
    client: c,
    details: { agent_id: agentId, trigger, rules: candidates },
  });
  return candidates.map((x) => x.id);
}

/** An asset that clearly is this agent's machine and has no agent of its own (for an agent with no asset). */
async function findReusableAsset(c: PoolClient, agentId: string, mac: string | null): Promise<{ id: number; reason: string } | null> {
  const r = await c.query(
    `SELECT a.id, (a.metadata->>'agent_id' = $1) AS by_agent
       FROM assets a
      WHERE NOT EXISTS (SELECT 1 FROM edr_agents e WHERE e.asset_id = a.id)
        AND (a.metadata->>'agent_id' = $1
             OR ($2::text IS NOT NULL AND regexp_replace(lower(coalesce(a.mac_address, '')), '[^0-9a-f]', '', 'g') = replace($2::text, ':', '')))
      ORDER BY (a.metadata->>'agent_id' = $1) DESC, a.last_seen DESC NULLS LAST, a.id
      LIMIT 1`,
    [agentId, mac]
  );
  return r.rows[0] ? { id: r.rows[0].id, reason: r.rows[0].by_agent ? 'agent_id' : 'mac' } : null;
}

/**
 * Resolve (and update) the asset an agent reports on from a report's facts,
 * per the file comment. One transaction, holding the agent row's lock so two
 * reports from one agent cannot race. Returns the asset id (null when the
 * agent has no asset and the report carried no usable IP).
 */
export async function linkEndpointAsset(agentId: string, facts: EndpointFacts, trigger = 'inventory'): Promise<EndpointLink> {
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const agentRow = await c.query('SELECT asset_id FROM edr_agents WHERE agent_id = $1 FOR UPDATE', [agentId]);
    if (!agentRow.rows.length) {
      await c.query('ROLLBACK');
      return { assetId: null, link: 'none', ip: 'none', merged: [] };
    }
    const mac = identifyingMac(facts.mac);
    let assetId: number | null = agentRow.rows[0].asset_id;
    let link: EndpointLink['link'] = 'kept';
    if (assetId !== null) {
      const exists = await c.query('SELECT 1 FROM assets WHERE id = $1 FOR UPDATE', [assetId]);
      if (!exists.rows.length) assetId = null;
    }
    if (assetId === null) {
      const reusable = await findReusableAsset(c, agentId, mac);
      if (reusable) {
        assetId = reusable.id;
        link = 'reused';
      } else if (facts.ip) {
        const holder = await c.query('SELECT id FROM assets WHERE ip_address = $1::inet FOR UPDATE', [facts.ip]);
        if (holder.rows.length) {
          // As before: an endpoint correlates with the existing asset at its address.
          assetId = holder.rows[0].id;
          link = 'by_ip';
          const others = await c.query('SELECT agent_id FROM edr_agents WHERE asset_id = $1 AND agent_id <> $2', [assetId, agentId]);
          if (others.rows.length) {
            logger.warn('[EDR] agent linked to an asset another agent already reports on', { agentId, assetId, ip: facts.ip });
          }
        } else {
          const created = await c.query(
            `INSERT INTO assets (ip_address, asset_type, criticality, status, discovery_method, first_seen, last_seen, metadata)
             VALUES ($1::inet, 'endpoint', 'medium', 'active', 'edr_agent', NOW(), NOW(), '{}'::jsonb) RETURNING id`,
            [facts.ip]
          );
          assetId = created.rows[0].id;
          link = 'created';
        }
      } else {
        await c.query('COMMIT');
        return { assetId: null, link: 'none', ip: 'none', merged: [] };
      }
      await c.query('UPDATE edr_agents SET asset_id = $2 WHERE agent_id = $1', [agentId, assetId]);
    }
    const id = assetId as number;

    const current = (await c.query('SELECT host(ip_address) AS ip, mac_address FROM assets WHERE id = $1', [id])).rows[0];
    const merged = await autoMerge(c, agentId, id, [facts.mac, current.mac_address], trigger);

    let ipOutcome: IpOutcome = facts.ip ? 'unchanged' : 'none';
    let takeIp = false;
    if (facts.ip && facts.ip !== current.ip) {
      const holder = await c.query('SELECT id FROM assets WHERE ip_address = $1::inet AND id <> $2', [facts.ip, id]);
      if (!holder.rows.length) {
        takeIp = true;
        ipOutcome = merged.length ? 'moved_after_merge' : 'moved';
      } else {
        ipOutcome = 'held_by_other';
      }
    }

    const asset = (await c.query('SELECT host(ip_address) AS ip, first_seen, metadata FROM assets WHERE id = $1', [id])).rows[0];
    const meta: Record<string, any> = { ...(asset.metadata ?? {}), ...(facts.metadata ?? {}) };
    if (facts.ip) {
      meta.ip_history = addIpHistory(asset.metadata?.ip_history, facts.ip, new Date(), new Date());
      if (ipOutcome === 'held_by_other') {
        meta.current_ip = facts.ip;
        meta.current_ip_at = new Date().toISOString();
      } else {
        delete meta.current_ip;
        delete meta.current_ip_at;
      }
    }
    await c.query(
      `UPDATE assets SET
         ip_address = CASE WHEN $2::boolean THEN $3::inet ELSE ip_address END,
         hostname = COALESCE($4, hostname),
         mac_address = COALESCE($5, mac_address),
         os_type = COALESCE($6, os_type),
         os_version = COALESCE($7, os_version),
         asset_type = 'endpoint',
         status = 'active',
         last_seen = NOW(),
         metadata = $8::jsonb,
         updated_at = NOW()
       WHERE id = $1`,
      [id, takeIp, facts.ip, facts.hostname || null, facts.mac || null, facts.os || null, facts.os_version || null, JSON.stringify(meta)]
    );
    if (facts.ip) await c.query('UPDATE edr_agents SET ip = $2 WHERE agent_id = $1', [agentId, facts.ip]);
    await c.query('COMMIT');
    if (ipOutcome === 'held_by_other') {
      logger.info('[EDR] endpoint reported an address another asset holds; kept its own asset', { agentId, assetId: id, ip: facts.ip });
    }
    return { assetId: id, link, ip: ipOutcome, merged };
  } catch (error) {
    await c.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    c.release();
  }
}

export interface BackfillResult {
  agents: number;
  merges: Array<{ agent_id: string; into: number; from: number[] }>;
}

/**
 * Fold every agent's strong duplicates into its asset (the rows the old
 * re-link-by-IP left behind). Idempotent: a second run finds nothing to do.
 * Each merge is audited (asset.merge, mode auto, trigger backfill). Runs in
 * the background at startup (server.ts); never throws.
 */
export async function runEndpointAssetBackfill(onlyAgents?: string[]): Promise<BackfillResult> {
  const result: BackfillResult = { agents: 0, merges: [] };
  let agents: Array<{ agent_id: string }>;
  try {
    // onlyAgents: tests limit the run to their own agents.
    agents = (await pool.query(
      `SELECT agent_id::text FROM edr_agents WHERE asset_id IS NOT NULL AND ($1::uuid[] IS NULL OR agent_id = ANY($1::uuid[]))
        ORDER BY created_at, agent_id`,
      [onlyAgents ?? null]
    )).rows;
  } catch (error) {
    logger.warn('[EDR] endpoint asset backfill could not list agents', { error: error instanceof Error ? error.message : String(error) });
    return result;
  }
  for (const { agent_id } of agents) {
    result.agents++;
    const c = await pool.connect();
    try {
      await c.query('BEGIN');
      const row = await c.query(
        `SELECT e.asset_id, a.mac_address FROM edr_agents e JOIN assets a ON a.id = e.asset_id WHERE e.agent_id = $1 FOR UPDATE OF e`,
        [agent_id]
      );
      if (row.rows.length) {
        const merged = await autoMerge(c, agent_id, row.rows[0].asset_id, [row.rows[0].mac_address], 'backfill');
        if (merged.length) result.merges.push({ agent_id, into: row.rows[0].asset_id, from: merged });
      }
      await c.query('COMMIT');
    } catch (error) {
      await c.query('ROLLBACK').catch(() => undefined);
      logger.warn('[EDR] endpoint asset backfill failed for an agent', { agentId: agent_id, error: error instanceof Error ? error.message : String(error) });
    } finally {
      c.release();
    }
  }
  const total = result.merges.reduce((n, m) => n + m.from.length, 0);
  if (total) logger.info(`[EDR] endpoint asset backfill: merged ${total} duplicate asset(s) for ${result.merges.length} agent(s)`);
  else logger.info(`[EDR] endpoint asset backfill: no duplicate endpoint assets (${result.agents} agent(s) checked)`);
  return result;
}
