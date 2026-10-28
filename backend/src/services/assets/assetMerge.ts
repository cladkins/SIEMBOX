/**
 * Merging duplicate asset rows into one.
 *
 * Assets are keyed by IP (assets.ip_address is unique), so one machine that
 * moved between networks could end up as several rows. mergeAssets() folds
 * the `from` rows into the `into` row and deletes them, in one transaction,
 * moving everything that points at an asset:
 *
 *   asset_vulnerabilities  one row per (asset, vulnerability): rows for the
 *                          same vulnerability become one, with the earliest
 *                          first_detected, the latest last_detected, open if
 *                          any of them was open (else the kept row's status),
 *                          the newest evidence and every distinct note. The
 *                          risk score is recomputed by trg_risk_score from the
 *                          kept asset's criticality, which is raised to the
 *                          highest of the merged rows first, so it is the
 *                          highest of theirs.
 *   asset_services         one row per (port, protocol): the most recently
 *                          seen, discovered_at the earliest
 *   alerts.asset_id        re-pointed
 *   edr_agents.asset_id    re-pointed
 *   application_inventory  loc_type 'asset' locations re-keyed (Application
 *                          Monitoring's per-asset rows), duplicates collapsed
 *   application_vuln_links re-pointed (rebuilt by the next rollup anyway)
 *   the asset row          kept row's values win; missing hostname/MAC/OS are
 *                          filled from the merged rows; tags are unioned;
 *                          metadata keys the kept row lacks are copied;
 *                          first_seen/last_seen/last_scanned widen; the merged
 *                          rows are listed in metadata.merged_assets and their
 *                          addresses in metadata.ip_history.
 *
 * Those are every foreign key to assets(id) (alerts, application_vuln_links,
 * asset_services, asset_vulnerabilities, edr_agents) plus the one table that
 * names an asset id as text (application_inventory). assetMerge.db.test.ts
 * fails when a new foreign key to assets appears that this file does not list.
 *
 * Every merge writes one audit_logs row (action 'asset.merge') in the same
 * transaction, with the full mapping and per-table counts.
 */
import type { PoolClient } from 'pg';
import pool from '../../config/database';
import { ApiError } from '../../middleware/errorHandler';
import { logger } from '../../utils/logger';
import { identifyingMac, normalizeMac, shortHostname } from './assetIdentity';
import { toInet } from '../audit/auditService';

/** Foreign keys to assets(id) that mergeAssets moves (table.column). */
export const MERGED_FOREIGN_KEYS = [
  'alerts.asset_id',
  'application_vuln_links.asset_id',
  'asset_services.asset_id',
  'asset_vulnerabilities.asset_id',
  'edr_agents.asset_id',
] as const;

/** Most rows one merge folds in. */
export const MAX_MERGE_SOURCES = 100;
const MAX_MERGED_HISTORY = 200;
export const MAX_IP_HISTORY = 50;

const CRITICALITY_RANK: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };

export interface AssetRow {
  id: number;
  ip_address: string;
  hostname: string | null;
  mac_address: string | null;
  os_type: string | null;
  os_version: string | null;
  asset_type: string | null;
  criticality: string | null;
  status: string | null;
  discovery_method: string | null;
  first_seen: Date | null;
  last_seen: Date | null;
  last_scanned: Date | null;
  metadata: Record<string, any> | null;
  tags: string[] | null;
}

export interface IpHistoryEntry {
  ip: string;
  first_seen: string | null;
  last_seen: string | null;
}

export interface MergeCounts {
  vulnerabilities: number;
  vulnerabilities_combined: number;
  services: number;
  alerts: number;
  agents: number;
  application_locations: number;
  application_vuln_links: number;
}

export interface MergedAssetSummary {
  id: number;
  ip_address: string;
  hostname: string | null;
  mac_address: string | null;
  discovery_method: string | null;
  asset_type: string | null;
  open_vulnerabilities: number;
  agents: string[];
}

export interface MergeResult {
  into: { id: number; ip_address: string; hostname: string | null };
  merged: MergedAssetSummary[];
  moved: MergeCounts;
  dry_run: boolean;
  warnings: string[];
}

export interface MergeOptions {
  /** 'manual' from the API; 'auto' from endpoint stickiness and the backfill. */
  mode: 'manual' | 'auto';
  /** Why (auto merges name the rule: 'agent_id' or 'mac'). */
  reason?: string;
  userId?: number | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  /** Count what would move, change nothing. */
  dryRun?: boolean;
  /** Run inside the caller's transaction (the caller commits). */
  client?: PoolClient;
  /** Extra audit details (the agent an auto merge was for). */
  details?: Record<string, unknown>;
}

/** Parse and check a merge request's ids. Pure; throws ApiError(400). */
export function parseMergeIds(into: unknown, from: unknown): { into: number; from: number[] } {
  const intoId = Number(into);
  if (!Number.isInteger(intoId) || intoId <= 0) throw new ApiError(400, 'Invalid asset ID');
  if (!Array.isArray(from) || from.length === 0) throw new ApiError(400, '`from` must be a non-empty array of asset ids');
  const ids: number[] = [];
  for (const raw of from) {
    const id = typeof raw === 'string' && /^\d+$/.test(raw) ? Number(raw) : raw;
    if (typeof id !== 'number' || !Number.isInteger(id) || id <= 0) throw new ApiError(400, '`from` must hold positive integer asset ids');
    if (id === intoId) throw new ApiError(400, 'An asset cannot be merged into itself');
    if (!ids.includes(id)) ids.push(id);
  }
  if (ids.length > MAX_MERGE_SOURCES) throw new ApiError(400, `At most ${MAX_MERGE_SOURCES} assets can be merged at once`);
  return { into: intoId, from: ids };
}

function iso(d: Date | string | null | undefined): string | null {
  if (!d) return null;
  const t = new Date(d);
  return isNaN(t.getTime()) ? null : t.toISOString();
}

function minDate(...ds: Array<Date | null | undefined>): Date | null {
  const valid = ds.filter((d): d is Date => !!d && !isNaN(new Date(d).getTime())).map((d) => new Date(d));
  return valid.length ? new Date(Math.min(...valid.map((d) => d.getTime()))) : null;
}

function maxDate(...ds: Array<Date | null | undefined>): Date | null {
  const valid = ds.filter((d): d is Date => !!d && !isNaN(new Date(d).getTime())).map((d) => new Date(d));
  return valid.length ? new Date(Math.max(...valid.map((d) => d.getTime()))) : null;
}

/**
 * Add an address to an ip_history list (newest last_seen first, one entry per
 * address, capped). Pure.
 */
export function addIpHistory(
  history: unknown,
  ip: string | null | undefined,
  firstSeen: Date | string | null,
  lastSeen: Date | string | null
): IpHistoryEntry[] {
  const list: IpHistoryEntry[] = Array.isArray(history)
    ? history.filter((h): h is IpHistoryEntry => !!h && typeof h === 'object' && typeof (h as any).ip === 'string')
        .map((h) => ({ ip: h.ip, first_seen: h.first_seen ?? null, last_seen: h.last_seen ?? null }))
    : [];
  if (ip) {
    const found = list.find((h) => h.ip === ip);
    const f = iso(firstSeen);
    const l = iso(lastSeen);
    if (found) {
      if (f && (!found.first_seen || f < found.first_seen)) found.first_seen = f;
      if (l && (!found.last_seen || l > found.last_seen)) found.last_seen = l;
    } else {
      list.push({ ip, first_seen: f, last_seen: l });
    }
  }
  list.sort((a, b) => (b.last_seen ?? '').localeCompare(a.last_seen ?? ''));
  return list.slice(0, MAX_IP_HISTORY);
}

/** The kept row's values after folding `sources` in. Pure. */
export function mergedAssetFields(into: AssetRow, sources: AssetRow[], mode: string, at: Date) {
  // Newest first, so a missing field is filled from the most recently seen duplicate.
  const bySeen = [...sources].sort((a, b) => (maxDate(b.last_seen)?.getTime() ?? 0) - (maxDate(a.last_seen)?.getTime() ?? 0));
  const fill = <K extends keyof AssetRow>(k: K): AssetRow[K] => {
    if (into[k] !== null && into[k] !== undefined && into[k] !== '') return into[k];
    for (const s of bySeen) if (s[k] !== null && s[k] !== undefined && s[k] !== '') return s[k];
    return into[k];
  };
  let criticality = into.criticality;
  for (const s of sources) {
    if ((CRITICALITY_RANK[s.criticality ?? ''] ?? 0) > (CRITICALITY_RANK[criticality ?? ''] ?? 0)) criticality = s.criticality;
  }
  const tags = [...new Set([...(into.tags ?? []), ...sources.flatMap((s) => s.tags ?? [])])];

  const meta: Record<string, any> = {};
  // Oldest duplicate first, then newer ones, then the kept row: the kept row wins.
  for (const s of [...bySeen].reverse()) Object.assign(meta, s.metadata ?? {});
  Object.assign(meta, into.metadata ?? {});
  let ipHistory = addIpHistory(into.metadata?.ip_history, into.ip_address, into.first_seen, into.last_seen);
  const mergedHistory: any[] = Array.isArray(into.metadata?.merged_assets) ? [...into.metadata!.merged_assets] : [];
  for (const s of sources) {
    for (const h of Array.isArray(s.metadata?.ip_history) ? s.metadata!.ip_history : []) {
      ipHistory = addIpHistory(ipHistory, h?.ip, h?.first_seen ?? null, h?.last_seen ?? null);
    }
    ipHistory = addIpHistory(ipHistory, s.ip_address, s.first_seen, s.last_seen);
    if (Array.isArray(s.metadata?.merged_assets)) mergedHistory.push(...s.metadata!.merged_assets);
    mergedHistory.push({
      id: s.id,
      ip_address: s.ip_address,
      hostname: s.hostname,
      mac_address: s.mac_address,
      discovery_method: s.discovery_method,
      first_seen: iso(s.first_seen),
      last_seen: iso(s.last_seen),
      merged_at: at.toISOString(),
      mode,
    });
  }
  meta.ip_history = ipHistory;
  meta.merged_assets = mergedHistory.slice(-MAX_MERGED_HISTORY);
  // A current_ip a duplicate recorded is about that row, not the kept one.
  if (!into.metadata || !('current_ip' in into.metadata)) delete meta.current_ip;

  return {
    hostname: fill('hostname'),
    mac_address: fill('mac_address'),
    os_type: fill('os_type'),
    os_version: fill('os_version'),
    criticality: criticality ?? 'medium',
    first_seen: minDate(into.first_seen, ...sources.map((s) => s.first_seen)),
    last_seen: maxDate(into.last_seen, ...sources.map((s) => s.last_seen)),
    last_scanned: maxDate(into.last_scanned, ...sources.map((s) => s.last_scanned)),
    tags: tags.length ? tags : into.tags,
    metadata: meta,
  };
}

const ASSET_COLUMNS = `id, host(ip_address) AS ip_address, hostname, mac_address, os_type, os_version, asset_type,
  criticality, status, discovery_method, first_seen, last_seen, last_scanned, metadata, tags`;

async function countMoves(c: PoolClient, into: number, from: number[]): Promise<{ counts: MergeCounts; perAsset: Map<number, { open: number; agents: string[] }> }> {
  const fromText = from.map(String);
  const r = await c.query(
    `SELECT
       (SELECT COUNT(*)::int FROM asset_vulnerabilities WHERE asset_id = ANY($2::int[])) AS vulnerabilities,
       (SELECT COUNT(*)::int FROM (
          SELECT vulnerability_id FROM asset_vulnerabilities
           WHERE asset_id = ANY($2::int[]) OR asset_id = $1
           GROUP BY vulnerability_id
          HAVING COUNT(*) > 1 AND bool_or(asset_id = ANY($2::int[]))) d) AS vulnerabilities_combined,
       (SELECT COUNT(*)::int FROM asset_services WHERE asset_id = ANY($2::int[])) AS services,
       (SELECT COUNT(*)::int FROM alerts WHERE asset_id = ANY($2::int[])) AS alerts,
       (SELECT COUNT(*)::int FROM edr_agents WHERE asset_id = ANY($2::int[])) AS agents,
       (SELECT COUNT(*)::int FROM application_inventory WHERE loc_type = 'asset' AND loc_key = ANY($3::text[])) AS application_locations,
       (SELECT COUNT(*)::int FROM application_vuln_links WHERE asset_id = ANY($2::int[])) AS application_vuln_links`,
    [into, from, fromText]
  );
  const per = await c.query(
    `SELECT a.id,
            (SELECT COUNT(*)::int FROM asset_vulnerabilities av WHERE av.asset_id = a.id AND av.status = 'open') AS open,
            COALESCE((SELECT array_agg(e.agent_id::text ORDER BY e.agent_id) FROM edr_agents e WHERE e.asset_id = a.id), '{}') AS agents
       FROM assets a WHERE a.id = ANY($1::int[])`,
    [from]
  );
  return {
    counts: r.rows[0],
    perAsset: new Map(per.rows.map((p: any) => [p.id, { open: p.open, agents: p.agents }])),
  };
}

/**
 * Fold `fromIds` into `intoId` and delete them (see the file comment). With
 * dryRun, returns what would move and changes nothing. Throws ApiError 400
 * (bad ids) or 404 (an asset that does not exist).
 */
export async function mergeAssets(intoId: number, fromIds: number[], opts: MergeOptions): Promise<MergeResult> {
  const { into: target, from } = parseMergeIds(intoId, fromIds);
  const own = !opts.client;
  const c = opts.client ?? (await pool.connect());
  try {
    if (own) await c.query('BEGIN');
    else await c.query('SAVEPOINT asset_merge');
    const all = [target, ...from];
    const locked = await c.query(`SELECT ${ASSET_COLUMNS} FROM assets WHERE id = ANY($1::int[]) ORDER BY id FOR UPDATE`, [all]);
    const rows = new Map<number, AssetRow>(locked.rows.map((r: AssetRow) => [r.id, r]));
    const missing = all.filter((id) => !rows.has(id));
    if (missing.length) throw new ApiError(404, `Asset not found: ${missing.join(', ')}`);
    const into = rows.get(target)!;
    const sources = from.map((id) => rows.get(id)!);

    const { counts, perAsset } = await countMoves(c, target, from);
    const merged: MergedAssetSummary[] = sources.map((s) => ({
      id: s.id,
      ip_address: s.ip_address,
      hostname: s.hostname,
      mac_address: s.mac_address,
      discovery_method: s.discovery_method,
      asset_type: s.asset_type,
      open_vulnerabilities: perAsset.get(s.id)?.open ?? 0,
      agents: perAsset.get(s.id)?.agents ?? [],
    }));
    const intoAgents = await agentsOn(c, target);
    const warnings = mergeWarnings(into, sources, merged, intoAgents.map((x) => x.agent_id), intoAgents.map((x) => x.hostname));
    const result: MergeResult = {
      into: { id: into.id, ip_address: into.ip_address, hostname: into.hostname },
      merged,
      moved: counts,
      dry_run: !!opts.dryRun,
      warnings,
    };
    if (opts.dryRun) {
      if (own) await c.query('ROLLBACK');
      else await c.query('ROLLBACK TO SAVEPOINT asset_merge');
      return result;
    }

    const at = new Date();
    const fields = mergedAssetFields(into, sources, opts.mode, at);
    // The kept row first: trg_risk_score reads its criticality for the moved findings.
    await c.query(
      `UPDATE assets SET hostname = $2, mac_address = $3, os_type = $4, os_version = $5, criticality = $6,
              first_seen = $7, last_seen = $8, last_scanned = $9, tags = $10, metadata = $11, updated_at = NOW()
        WHERE id = $1`,
      [target, fields.hostname, fields.mac_address, fields.os_type, fields.os_version, fields.criticality,
       fields.first_seen, fields.last_seen, fields.last_scanned, fields.tags, JSON.stringify(fields.metadata)]
    );
    if (fields.criticality !== into.criticality) {
      // A higher criticality raises the kept row's own findings' risk too (the trigger recomputes).
      await c.query('UPDATE asset_vulnerabilities SET updated_at = updated_at WHERE asset_id = $1', [target]);
    }

    await moveVulnerabilities(c, target, from);
    await moveServices(c, target, from);
    await c.query('UPDATE alerts SET asset_id = $1 WHERE asset_id = ANY($2::int[])', [target, from]);
    await c.query('UPDATE edr_agents SET asset_id = $1 WHERE asset_id = ANY($2::int[])', [target, from]);
    await moveApplicationInventory(c, target, from);
    await c.query('DELETE FROM assets WHERE id = ANY($1::int[])', [from]);

    await c.query(
      `INSERT INTO audit_logs (user_id, action, resource_type, resource_id, ip_address, user_agent, response_status, details)
       VALUES ($1, 'asset.merge', 'asset', $2, $3, $4, 200, $5)`,
      [
        opts.userId ?? null,
        target,
        toInet(opts.ipAddress),
        opts.userAgent ? opts.userAgent.slice(0, 256) : null,
        JSON.stringify({
          mode: opts.mode,
          ...(opts.reason ? { reason: opts.reason } : {}),
          into: result.into,
          merged,
          moved: counts,
          ...(warnings.length ? { warnings } : {}),
          ...(opts.details ?? {}),
        }),
      ]
    );
    if (own) await c.query('COMMIT');
    else await c.query('RELEASE SAVEPOINT asset_merge');
    logger.info(
      `[assets] merged ${from.join(', ')} into ${target} (${opts.mode}${opts.reason ? `: ${opts.reason}` : ''}); ` +
        `vulns=${counts.vulnerabilities} (combined ${counts.vulnerabilities_combined}) services=${counts.services} ` +
        `alerts=${counts.alerts} agents=${counts.agents} app_locations=${counts.application_locations}`
    );
    return result;
  } catch (error) {
    if (own) await c.query('ROLLBACK').catch(() => undefined);
    else await c.query('ROLLBACK TO SAVEPOINT asset_merge').catch(() => undefined);
    throw error;
  } finally {
    if (own) c.release();
  }
}

async function agentsOn(c: PoolClient, assetId: number): Promise<Array<{ agent_id: string; hostname: string | null }>> {
  const r = await c.query('SELECT agent_id::text, hostname FROM edr_agents WHERE asset_id = $1 ORDER BY agent_id', [assetId]);
  return r.rows;
}

/**
 * What a reviewer should know before confirming. `intoNames`: other names the
 * kept machine goes by (its endpoint agent's host name). Pure.
 */
export function mergeWarnings(
  into: AssetRow,
  sources: AssetRow[],
  merged: MergedAssetSummary[],
  intoAgents: string[],
  intoNames: Array<string | null> = []
): string[] {
  const w: string[] = [];
  const agents = new Set([...intoAgents, ...merged.flatMap((m) => m.agents)]);
  if (agents.size > 1) {
    w.push(`${agents.size} endpoint agents will report on the kept asset; remove the ones no longer installed on the Endpoints page.`);
  }
  // Hardware MACs only: random (private Wi-Fi, VM) ones differ on one machine anyway.
  const intoMac = identifyingMac(into.mac_address);
  for (const s of sources) {
    const mac = identifyingMac(s.mac_address);
    if (intoMac && mac && mac !== intoMac) w.push(`Asset ${s.id} (${s.ip_address}) has a different MAC address (${s.mac_address}).`);
  }
  const known = new Set([into.hostname, ...intoNames].map(shortHostname).filter((n): n is string => !!n));
  for (const s of sources) {
    const name = shortHostname(s.hostname);
    if (known.size && name && !known.has(name) && !(intoMac && identifyingMac(s.mac_address) === intoMac)) {
      w.push(`Asset ${s.id} (${s.ip_address}) has a different host name (${s.hostname}).`);
    }
  }
  return w;
}

async function moveVulnerabilities(c: PoolClient, target: number, from: number[]): Promise<void> {
  await c.query('DROP TABLE IF EXISTS pg_temp.asset_merge_av');
  // One row per vulnerability any merged asset has: which row survives (the
  // kept asset's own, else the most recently detected) and the combined values.
  await c.query(
    `CREATE TEMP TABLE asset_merge_av ON COMMIT DROP AS
     SELECT vulnerability_id,
            (array_agg(id ORDER BY (asset_id = $1) DESC, last_detected DESC NULLS LAST, id))[1] AS keep_id,
            MIN(first_detected) AS first_detected,
            MAX(last_detected) AS last_detected,
            bool_or(status = 'open') AS any_open,
            (array_agg(evidence ORDER BY last_detected DESC NULLS LAST, id) FILTER (WHERE evidence IS NOT NULL))[1] AS evidence,
            string_agg(DISTINCT notes, E'\\n') FILTER (WHERE notes IS NOT NULL AND notes <> '') AS notes
       FROM asset_vulnerabilities
      WHERE (asset_id = $1 OR asset_id = ANY($2::int[]))
        AND vulnerability_id IN (SELECT vulnerability_id FROM asset_vulnerabilities WHERE asset_id = ANY($2::int[]))
      GROUP BY vulnerability_id`,
    [target, from]
  );
  await c.query(
    `DELETE FROM asset_vulnerabilities av USING asset_merge_av m
      WHERE av.vulnerability_id = m.vulnerability_id AND (av.asset_id = $1 OR av.asset_id = ANY($2::int[])) AND av.id <> m.keep_id`,
    [target, from]
  );
  await c.query(
    `UPDATE asset_vulnerabilities av
        SET asset_id = $1,
            first_detected = m.first_detected,
            last_detected = m.last_detected,
            status = CASE WHEN m.any_open THEN 'open' ELSE av.status END,
            patched_at = CASE WHEN m.any_open THEN NULL ELSE av.patched_at END,
            patched_by = CASE WHEN m.any_open THEN NULL ELSE av.patched_by END,
            evidence = COALESCE(m.evidence, av.evidence),
            notes = m.notes,
            updated_at = NOW()
       FROM asset_merge_av m
      WHERE av.id = m.keep_id`,
    [target]
  );
  await c.query('DROP TABLE IF EXISTS pg_temp.asset_merge_av');
}

async function moveServices(c: PoolClient, target: number, from: number[]): Promise<void> {
  await c.query('DROP TABLE IF EXISTS pg_temp.asset_merge_svc');
  await c.query(
    `CREATE TEMP TABLE asset_merge_svc ON COMMIT DROP AS
     SELECT port, protocol,
            (array_agg(id ORDER BY last_seen DESC NULLS LAST, (asset_id = $1) DESC, id))[1] AS keep_id,
            MIN(discovered_at) AS discovered_at
       FROM asset_services
      WHERE (asset_id = $1 OR asset_id = ANY($2::int[]))
        AND (port, protocol) IN (SELECT port, protocol FROM asset_services WHERE asset_id = ANY($2::int[]))
      GROUP BY port, protocol`,
    [target, from]
  );
  await c.query(
    `DELETE FROM asset_services s USING asset_merge_svc m
      WHERE s.port = m.port AND s.protocol = m.protocol AND (s.asset_id = $1 OR s.asset_id = ANY($2::int[])) AND s.id <> m.keep_id`,
    [target, from]
  );
  await c.query(
    `UPDATE asset_services s SET asset_id = $1, discovered_at = m.discovered_at
       FROM asset_merge_svc m WHERE s.id = m.keep_id`,
    [target]
  );
  await c.query('DROP TABLE IF EXISTS pg_temp.asset_merge_svc');
}

async function moveApplicationInventory(c: PoolClient, target: number, from: number[]): Promise<void> {
  const fromText = from.map(String);
  // Per-asset rows are snapshot sources (events = what the snapshot holds), so
  // duplicates keep the larger count rather than adding up.
  await c.query(
    `INSERT INTO application_inventory (app_id, loc_type, loc_key, source, version, events, first_seen, last_seen, evidence)
     SELECT app_id, 'asset', $1::text, source, version, MAX(events), MIN(first_seen), MAX(last_seen),
            (array_agg(evidence ORDER BY last_seen DESC))[1]
       FROM application_inventory
      WHERE loc_type = 'asset' AND loc_key = ANY($2::text[])
      GROUP BY app_id, source, version
     ON CONFLICT (app_id, loc_type, loc_key, source, version) DO UPDATE SET
       events = GREATEST(application_inventory.events, EXCLUDED.events),
       first_seen = LEAST(application_inventory.first_seen, EXCLUDED.first_seen),
       last_seen = GREATEST(application_inventory.last_seen, EXCLUDED.last_seen),
       evidence = CASE WHEN EXCLUDED.last_seen > application_inventory.last_seen THEN EXCLUDED.evidence ELSE application_inventory.evidence END`,
    [String(target), fromText]
  );
  await c.query(`DELETE FROM application_inventory WHERE loc_type = 'asset' AND loc_key = ANY($1::text[])`, [fromText]);
  await c.query(
    `INSERT INTO application_vuln_links (app_id, asset_id, vulnerability_id, match, version)
     SELECT DISTINCT ON (app_id, vulnerability_id) app_id, $1, vulnerability_id, match, version
       FROM application_vuln_links WHERE asset_id = ANY($2::int[])
      ORDER BY app_id, vulnerability_id, (match = 'package') DESC
     ON CONFLICT (app_id, asset_id, vulnerability_id) DO NOTHING`,
    [target, from]
  );
  // The merged assets' own links go with their rows (ON DELETE CASCADE).
}

// ---- Possible duplicates (hints only) ---------------------------------------

export interface DuplicateHint {
  id: number;
  ip_address: string;
  hostname: string | null;
  mac_address: string | null;
  discovery_method: string | null;
  asset_type: string | null;
  last_seen: Date | null;
  open_vulnerabilities: number;
  agents: number;
  /** same_mac, same_hostname, same_agent (metadata.agent_id names this asset's agent). */
  reasons: string[];
}

/**
 * Other assets that may be the same machine as `assetId`: the same MAC
 * address (any MAC: a hint, so random ones count too), the same short host
 * name (assetIdentity.shortHostname) as the asset or as the name its endpoint
 * agent reports, or one that recorded this asset's agent. Hints only: nothing
 * is merged.
 */
export async function findDuplicateHints(assetId: number, limit = 50): Promise<DuplicateHint[] | null> {
  const self = await pool.query(`SELECT ${ASSET_COLUMNS} FROM assets WHERE id = $1`, [assetId]);
  if (!self.rows.length) return null;
  const a: AssetRow = self.rows[0];
  const mac = normalizeMac(a.mac_address);
  const agentRows = (await pool.query('SELECT agent_id::text, hostname FROM edr_agents WHERE asset_id = $1', [assetId])).rows;
  const agents: string[] = agentRows.map((r: any) => r.agent_id);
  // The asset's own name and the name its endpoint agent reports (nmap's
  // reverse-DNS name and the machine's own can differ: MBP vs MacBook-Pro).
  const names = [...new Set([a.hostname, ...agentRows.map((r: any) => r.hostname)].map(shortHostname).filter((n): n is string => !!n))];
  if (!mac && names.length === 0 && agents.length === 0) return [];
  // Normalized in SQL the same way as normalizeMac/shortHostname (hex digits only; first label, lower case).
  const r = await pool.query(
    `SELECT a.id, host(a.ip_address) AS ip_address, a.hostname, a.mac_address, a.discovery_method, a.asset_type, a.last_seen,
            (SELECT COUNT(*)::int FROM asset_vulnerabilities av WHERE av.asset_id = a.id AND av.status = 'open') AS open_vulnerabilities,
            (SELECT COUNT(*)::int FROM edr_agents e WHERE e.asset_id = a.id) AS agents,
            ($2::text IS NOT NULL AND regexp_replace(lower(coalesce(a.mac_address, '')), '[^0-9a-f]', '', 'g') = replace($2::text, ':', '')) AS same_mac,
            (a.metadata->>'agent_id' = ANY($4::text[])) AS same_agent
       FROM assets a
      WHERE a.id <> $1
        AND (($2::text IS NOT NULL AND regexp_replace(lower(coalesce(a.mac_address, '')), '[^0-9a-f]', '', 'g') = replace($2::text, ':', ''))
             OR (a.hostname IS NOT NULL AND split_part(rtrim(lower(btrim(a.hostname)), '.'), '.', 1) = ANY($3::text[]))
             OR (a.metadata->>'agent_id' = ANY($4::text[])))
      ORDER BY a.last_seen DESC NULLS LAST, a.id
      LIMIT $5`,
    [assetId, mac, names, agents, limit]
  );
  return r.rows
    .map((row: any) => {
      const name = shortHostname(row.hostname);
      return {
        id: row.id,
        ip_address: row.ip_address,
        hostname: row.hostname,
        mac_address: row.mac_address,
        discovery_method: row.discovery_method,
        asset_type: row.asset_type,
        last_seen: row.last_seen,
        open_vulnerabilities: row.open_vulnerabilities,
        agents: row.agents,
        reasons: [
          ...(row.same_mac ? ['same_mac'] : []),
          // The SQL first label can match an IP-like or generic name shortHostname refuses.
          ...(name && names.includes(name) ? ['same_hostname'] : []),
          ...(row.same_agent ? ['same_agent'] : []),
        ],
      };
    })
    .filter((h: DuplicateHint) => h.reasons.length > 0);
}
