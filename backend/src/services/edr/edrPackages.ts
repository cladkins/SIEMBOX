/**
 * Endpoint software inventory (migration 049): the full list of packages an
 * endpoint agent finds installed on its host, from POST /api/edr/packages.
 * Application Monitoring's rollup reads it as the `endpoint_sbom` source.
 *
 * Every report is a full snapshot. Rows are upserted in batches (UNNEST, as
 * storeEdrVulnBatch does: a host has 3,000-10,000 packages and the agent gives
 * up after 30 s), stamped with one clock reading taken under the agent's
 * snapshot-row lock, and the agent's rows with an older stamp, absent from
 * this report, are deleted. All in one transaction, so a reader sees the old
 * snapshot or the new one, never half of each.
 *
 * The snapshot hash (the agent's, else one computed here) lets an unchanged
 * report skip the writes: the agent may even send the hash alone, and is told
 * whether the server already has that snapshot.
 */
import crypto from 'crypto';
import pool from '../../config/database';
import { logger } from '../../utils/logger';
import { ApiError } from '../../middleware/errorHandler';
import { EdrAgentModel } from '../../models/EdrAgent';
import { attachScanSummary } from './edrScans';

/** Field limits; longer values are clipped. */
export const MAX_NAME = 256;
export const MAX_VERSION = 128;
export const MAX_TYPE = 32;
export const MAX_HASH = 128;
/** Packages one report may hold; the rest are dropped (and logged). */
export const MAX_PACKAGES = 50_000;
/** Rows per upsert statement. */
export const PACKAGE_BATCH = 2_000;
/** Inside the agent's 30 s request timeout. */
const STATEMENT_TIMEOUT_MS = 25_000;

export interface PackageRow {
  type: string;
  name: string;
  version: string;
}

// eslint-disable-next-line no-control-regex -- stripping control characters is the point (Postgres TEXT refuses NUL)
const CONTROL = /[\u0000-\u001f\u007f]/g;

function clean(value: unknown, max: number): string {
  if (value === null || value === undefined) return '';
  if (typeof value !== 'string' && typeof value !== 'number') return '';
  return String(value).replace(CONTROL, '').trim().slice(0, max);
}

/** An ecosystem name: lower case letters, digits, '-', '_' and '.'; anything else becomes ''. */
function cleanType(value: unknown): string {
  const t = clean(value, MAX_TYPE).toLowerCase();
  return /^[a-z0-9][a-z0-9._-]*$/.test(t) ? t : '';
}

/**
 * The report's packages, cleaned and de-duplicated on (type, name, version)
 * (dpkg lists a multi-arch package once per architecture). Entries without a
 * name are skipped. Pure.
 */
export function normalizePackages(items: unknown[]): { rows: PackageRow[]; skipped: number; truncated: number } {
  const seen = new Map<string, PackageRow>();
  let skipped = 0;
  for (const item of items) {
    if (!item || typeof item !== 'object') {
      skipped++;
      continue;
    }
    const p = item as Record<string, unknown>;
    const name = clean(p.name, MAX_NAME);
    if (!name) {
      skipped++;
      continue;
    }
    const row = { type: cleanType(p.type ?? p.source), name, version: clean(p.version, MAX_VERSION) };
    seen.set(`${row.type}\u0000${row.name}\u0000${row.version}`, row);
  }
  let rows = [...seen.values()];
  let truncated = 0;
  if (rows.length > MAX_PACKAGES) {
    truncated = rows.length - MAX_PACKAGES;
    rows = rows.slice(0, MAX_PACKAGES);
  }
  return { rows, skipped, truncated };
}

/** A hash of the snapshot, independent of order, for agents that send none. Pure. */
export function computeSnapshotHash(rows: PackageRow[]): string {
  const lines = rows.map((r) => `${r.type}\u0000${r.name}\u0000${r.version}`).sort();
  return `sha256:${crypto.createHash('sha256').update(lines.join('\n')).digest('hex')}`;
}

function cleanHash(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const h = value.trim();
  if (!h) return null;
  if (h.length > MAX_HASH || !/^[A-Za-z0-9:_+/=.-]+$/.test(h)) throw new ApiError(400, 'snapshot_hash is malformed');
  return h;
}

function parseTimestamp(value: unknown): Date | null {
  if (!value) return null;
  const d = new Date(String(value));
  return isNaN(d.getTime()) ? null : d;
}

export interface PackageIngestResult {
  /** True when the snapshot was stored or the server already had it. */
  accepted: boolean;
  /** The server already had this snapshot; nothing was written. */
  unchanged: boolean;
  /** A hash-only report the server does not have: send the full list. */
  snapshot_required: boolean;
  package_count: number;
  stored: number;
  /** Packages the previous snapshot did not hold. */
  added: number;
  removed: number;
  skipped: number;
  truncated: number;
}

/**
 * Store one agent's package report. Body: { snapshot_hash?, collected_at?,
 * force?, scan_id?, packages?: [{ name, version, type }] }. Without
 * `packages` it is a hash-only check. `force` stores the list even when the
 * hash is unchanged. With scan_id (the agent's scan history row), the counts
 * go into that row's summary.
 */
export async function ingestPackages(agentId: string, input: unknown): Promise<PackageIngestResult> {
  const body = (input && typeof input === 'object' ? input : {}) as Record<string, unknown>;
  const hasList = Array.isArray(body.packages);
  const agentHash = cleanHash(body.snapshot_hash);
  if (!hasList && !agentHash) throw new ApiError(400, 'packages must be an array (or send snapshot_hash alone)');
  if (body.packages !== undefined && !hasList) throw new ApiError(400, 'packages must be an array');
  const force = body.force === true;
  const collectedAt = parseTimestamp(body.collected_at);
  const normalized = hasList ? normalizePackages(body.packages as unknown[]) : { rows: [], skipped: 0, truncated: 0 };
  const hash = agentHash ?? computeSnapshotHash(normalized.rows);

  await EdrAgentModel.touch(agentId);
  const started = Date.now();
  const result: PackageIngestResult = {
    accepted: false, unchanged: false, snapshot_required: false, package_count: 0, stored: 0, added: 0, removed: 0,
    skipped: normalized.skipped, truncated: normalized.truncated,
  };

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query("SELECT set_config('statement_timeout', $1, true)", [String(STATEMENT_TIMEOUT_MS)]);
    await client.query(`INSERT INTO edr_agent_package_snapshots (agent_id) VALUES ($1) ON CONFLICT (agent_id) DO NOTHING`, [agentId]);
    // Serializes two reports from one agent; the clock is read after the lock.
    const { rows: meta } = await client.query(
      `SELECT snapshot_hash, package_count, clock_timestamp() AS stamp FROM edr_agent_package_snapshots WHERE agent_id = $1 FOR UPDATE`,
      [agentId]
    );
    const stamp: Date = meta[0].stamp;

    if (!force && meta[0].snapshot_hash && meta[0].snapshot_hash === hash) {
      await client.query(
        `UPDATE edr_agent_package_snapshots SET reported_at = $2, collected_at = COALESCE($3, collected_at) WHERE agent_id = $1`,
        [agentId, stamp, collectedAt]
      );
      await client.query('COMMIT');
      const count = Number(meta[0].package_count);
      await attachScanSummary(agentId, body.scan_id, 'packages', { packages: count, added: 0, removed: 0, unchanged: count });
      return { ...result, accepted: true, unchanged: true, package_count: count };
    }
    if (!hasList) {
      await client.query('ROLLBACK');
      return { ...result, snapshot_required: true, package_count: Number(meta[0].package_count) };
    }

    const rows = normalized.rows;
    let added = 0;
    for (let i = 0; i < rows.length; i += PACKAGE_BATCH) {
      const batch = rows.slice(i, i + PACKAGE_BATCH);
      // xmax = 0 marks a row this statement inserted (not one it updated).
      const up = await client.query(
        `WITH up AS (
           INSERT INTO edr_agent_packages AS p (agent_id, type, name, version, first_seen, last_seen)
           SELECT $1, t.type, t.name, t.version, $5, $5 FROM UNNEST($2::text[], $3::text[], $4::text[]) AS t(type, name, version)
           ON CONFLICT (agent_id, type, name, version) DO UPDATE SET last_seen = EXCLUDED.last_seen
           RETURNING (xmax = 0) AS inserted)
         SELECT COUNT(*) FILTER (WHERE inserted)::int AS added FROM up`,
        [agentId, batch.map((r) => r.type), batch.map((r) => r.name), batch.map((r) => r.version), stamp]
      );
      added += up.rows[0].added;
    }
    const removed = await client.query(`DELETE FROM edr_agent_packages WHERE agent_id = $1 AND last_seen < $2`, [agentId, stamp]);
    await client.query(
      `UPDATE edr_agent_package_snapshots
          SET snapshot_hash = $2, package_count = $3, collected_at = $4, stored_at = $5, reported_at = $5
        WHERE agent_id = $1`,
      [agentId, hash, rows.length, collectedAt, stamp]
    );
    await client.query('COMMIT');
    Object.assign(result, {
      accepted: true, package_count: rows.length, stored: rows.length, added, removed: removed.rowCount ?? 0,
    });
    await attachScanSummary(agentId, body.scan_id, 'packages', {
      packages: rows.length, added, removed: result.removed, unchanged: rows.length - added,
    });
    logger.info(
      `[EDR] package snapshot agent=${agentId} packages=${rows.length} removed=${result.removed} ` +
        `skipped=${result.skipped} truncated=${result.truncated} ms=${Date.now() - started}`
    );
    return result;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

/** An agent's packages for the Endpoints page: optional name filter, in name order. */
export async function listAgentPackages(agentId: string, opts: { q?: string; limit?: number; offset?: number } = {}) {
  const limit = Math.min(Math.max(opts.limit ?? 200, 1), 1000);
  const offset = Math.max(opts.offset ?? 0, 0);
  const params: unknown[] = [agentId];
  let where = 'agent_id = $1';
  const q = (opts.q ?? '').trim().slice(0, 100);
  if (q) {
    params.push(`%${q.toLowerCase().replace(/[\\%_]/g, '\\$&')}%`);
    where += ` AND lower(name) LIKE $${params.length}`;
  }
  const total = await pool.query(`SELECT COUNT(*)::int AS n FROM edr_agent_packages WHERE ${where}`, params);
  const rows = await pool.query(
    `SELECT type, name, version, first_seen, last_seen FROM edr_agent_packages WHERE ${where}
      ORDER BY lower(name), name, version LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
    [...params, limit, offset]
  );
  const meta = await pool.query(
    `SELECT package_count, collected_at, stored_at, reported_at FROM edr_agent_package_snapshots WHERE agent_id = $1`,
    [agentId]
  );
  return { total: total.rows[0].n, packages: rows.rows, snapshot: meta.rows[0] ?? null };
}
