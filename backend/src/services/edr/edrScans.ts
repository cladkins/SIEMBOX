/**
 * Endpoint scan history and on-demand ("ad hoc") scans (migration 050).
 *
 * Every scan an endpoint agent runs gets a row in edr_agent_scans:
 *  - console requests (an analyst's "Scan now") are created here as
 *    `pending`, served to the agent in its heartbeat response
 *    (`scan_requests`) and moved on by the agent's reports;
 *  - the agent's own scheduled and startup runs are created by its first
 *    report (POST /api/edr/scans without a scan_id).
 * The agent reports a run's start (`running`) and its end (`succeeded` or
 * `failed`, with a summary). Where the server receives the scan's data
 * (vulnerabilities, packages, inventory) and the payload names the scan_id, it
 * computes the summary itself; those keys win over the agent's.
 *
 * One outstanding (pending or running) console request per agent and type: a
 * second request returns the first. A pending request the agent never picks up
 * expires after PENDING_EXPIRY_HOURS; a run never reported finished expires
 * after RUNNING_EXPIRY_HOURS. History is pruned to EDR_SCAN_HISTORY_DAYS and
 * the newest EDR_SCAN_HISTORY_PER_TYPE rows per agent and type.
 */
import pool, { query } from '../../config/database';
import { ApiError } from '../../middleware/errorHandler';
import { logger } from '../../utils/logger';
import { isUuid } from './agentUpdate';

export const SCAN_TYPES = ['vuln', 'yara', 'packages', 'inventory'] as const;
export type ScanType = (typeof SCAN_TYPES)[number];
export const SCAN_TRIGGERS = ['schedule', 'startup', 'console'] as const;
export type ScanTrigger = (typeof SCAN_TRIGGERS)[number];
export const SCAN_STATUSES = ['pending', 'running', 'succeeded', 'failed', 'cancelled', 'expired'] as const;
export type ScanStatus = (typeof SCAN_STATUSES)[number];
/** Statuses an agent may report. */
export const REPORTABLE_SCAN_STATUSES = ['running', 'succeeded', 'failed'] as const;

/** Heartbeat capability of an agent that runs console scan requests. */
export const ADHOC_SCAN_CAPABILITY = 'adhoc_scans';
/** First agent release with ADHOC_SCAN_CAPABILITY (shown to users of older agents). */
export const MIN_ADHOC_AGENT_VERSION = '0.0.20';

/** A console request the agent has not picked up by then is `expired`. */
export const PENDING_EXPIRY_HOURS = 24;
/** A run the agent has not reported finished by then is `expired`. */
export const RUNNING_EXPIRY_HOURS = 12;
/** History older than this is pruned (outstanding rows never are). */
export const EDR_SCAN_HISTORY_DAYS = 90;
/** Newest rows kept per agent and scan type. */
export const EDR_SCAN_HISTORY_PER_TYPE = 200;
/** Agents one bulk request may name. */
export const BULK_SCAN_MAX_AGENTS = 200;

export const MAX_SCAN_ERROR_LENGTH = 500;
const MAX_SUMMARY_KEYS = 20;
const MAX_SUMMARY_STRING = 200;
const MAX_CAPABILITIES = 16;

export interface ScanRequest {
  scan_id: string;
  scan_type: ScanType;
  requested_at: Date;
}

// ---- Validation (pure) ---------------------------------------------------------

function isOneOf<T extends string>(list: readonly T[], v: unknown): v is T {
  return typeof v === 'string' && (list as readonly string[]).includes(v);
}

/** The `types` of a scan request: a non-empty list of known types, de-duplicated. Throws 400. */
export function parseScanTypes(raw: unknown): ScanType[] {
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new ApiError(400, `types must be a non-empty array of: ${SCAN_TYPES.join(', ')}`);
  }
  const out: ScanType[] = [];
  for (const t of raw) {
    if (!isOneOf(SCAN_TYPES, t)) throw new ApiError(400, `unknown scan type "${String(t).slice(0, 32)}"`);
    if (!out.includes(t)) out.push(t);
  }
  return out;
}

/**
 * An agent-supplied summary: a flat object of up to MAX_SUMMARY_KEYS
 * snake_case keys with number, boolean or short string values. Anything else
 * is dropped. Null for no usable summary.
 */
export function sanitizeSummary(raw: unknown): Record<string, number | boolean | string> | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const out: Record<string, number | boolean | string> = {};
  let n = 0;
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (n >= MAX_SUMMARY_KEYS) break;
    if (!/^[a-z][a-z0-9_]{0,31}$/.test(k)) continue;
    if (typeof v === 'number' && Number.isFinite(v)) out[k] = v;
    else if (typeof v === 'boolean') out[k] = v;
    else if (typeof v === 'string') out[k] = v.slice(0, MAX_SUMMARY_STRING);
    else continue;
    n++;
  }
  return n > 0 ? out : null;
}

/** The heartbeat `capabilities` list, or undefined (keep the stored one) when absent or malformed. */
export function parseCapabilities(raw: unknown): string[] | undefined {
  if (!Array.isArray(raw)) return undefined;
  const out: string[] = [];
  for (const c of raw) {
    if (typeof c !== 'string' || !/^[a-z][a-z0-9_]{0,31}$/.test(c)) continue;
    if (!out.includes(c)) out.push(c);
    if (out.length >= MAX_CAPABILITIES) break;
  }
  return out;
}

/** Whether an agent row says it runs console scan requests. */
export function supportsAdhocScans(agent: { capabilities?: string[] | null } | null | undefined): boolean {
  return Array.isArray(agent?.capabilities) && agent!.capabilities!.includes(ADHOC_SCAN_CAPABILITY);
}

function parseTimestamp(value: unknown): Date | null {
  if (!value) return null;
  const d = new Date(String(value));
  return isNaN(d.getTime()) ? null : d;
}

function cleanError(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const e = value.trim();
  return e ? e.slice(0, MAX_SCAN_ERROR_LENGTH) : null;
}

// ---- Expiry and retention ------------------------------------------------------------

/**
 * Expire pending requests never picked up and runs never reported finished,
 * for one agent or (no argument) all of them. Returns how many rows changed.
 */
export async function expireStaleScans(agentId?: string): Promise<number> {
  const result = await query(
    `UPDATE edr_agent_scans
        SET status = 'expired',
            error = CASE WHEN status = 'pending'
                         THEN 'The agent did not pick up the request within ' || $2::int || ' hours'
                         ELSE 'The agent did not report the scan finished within ' || $3::int || ' hours' END,
            completed_at = COALESCE(completed_at, NOW()),
            updated_at = NOW()
      WHERE status IN ('pending', 'running')
        AND ($1::uuid IS NULL OR agent_id = $1::uuid)
        AND ((status = 'pending' AND requested_at < NOW() - make_interval(hours => $2::int))
          OR (status = 'running' AND COALESCE(started_at, requested_at) < NOW() - make_interval(hours => $3::int)))`,
    [agentId ?? null, PENDING_EXPIRY_HOURS, RUNNING_EXPIRY_HOURS]
  );
  return result.rowCount ?? 0;
}

/** Delete history past EDR_SCAN_HISTORY_DAYS or beyond the newest EDR_SCAN_HISTORY_PER_TYPE per agent and type. */
export async function pruneScanHistory(): Promise<number> {
  const result = await query(
    `DELETE FROM edr_agent_scans s
      USING (
        SELECT id, ROW_NUMBER() OVER (PARTITION BY agent_id, scan_type ORDER BY requested_at DESC, id) AS rn, requested_at
          FROM edr_agent_scans
         WHERE status NOT IN ('pending', 'running')
      ) r
      WHERE s.id = r.id
        AND (r.rn > $1 OR r.requested_at < NOW() - make_interval(days => $2::int))`,
    [EDR_SCAN_HISTORY_PER_TYPE, EDR_SCAN_HISTORY_DAYS]
  );
  return result.rowCount ?? 0;
}

/** Fleet-wide expiry + retention; run by the edr-agent-release job. */
export async function runScanHousekeeping(): Promise<{ expired: number; pruned: number }> {
  const expired = await expireStaleScans();
  const pruned = await pruneScanHistory();
  return { expired, pruned };
}

// ---- Console requests ---------------------------------------------------------------

const ROW_COLUMNS = `s.id, s.agent_id, s.scan_type, s.trigger, s.requested_by, u.username AS requested_by_username,
  s.requested_at, s.started_at, s.completed_at, s.status, s.summary, s.error,
  CASE WHEN s.started_at IS NOT NULL AND s.completed_at IS NOT NULL
       THEN GREATEST(0, (EXTRACT(EPOCH FROM (s.completed_at - s.started_at)) * 1000)::bigint) END AS duration_ms`;

async function selectScans(where: string, params: unknown[]): Promise<any[]> {
  const result = await query(
    `SELECT ${ROW_COLUMNS} FROM edr_agent_scans s LEFT JOIN users u ON u.id = s.requested_by WHERE ${where}`,
    params
  );
  return result.rows.map(normalizeRow);
}

function normalizeRow(r: any) {
  return { ...r, duration_ms: r.duration_ms === null || r.duration_ms === undefined ? null : Number(r.duration_ms) };
}

async function assertAgent(agentId: string): Promise<void> {
  if (!isUuid(agentId)) throw new ApiError(404, 'Agent not found');
  const r = await query('SELECT 1 FROM edr_agents WHERE agent_id = $1', [agentId]);
  if (r.rows.length === 0) throw new ApiError(404, 'Agent not found');
}

/**
 * "Scan now" on one agent: one console request per type. A type with a request
 * already outstanding returns that one (created: false). Offline agents are
 * fine: the request waits for the next heartbeat (or expires).
 */
export async function requestScans(
  agentId: string,
  types: ScanType[],
  userId: number | null
): Promise<{ scans: Array<Record<string, unknown> & { created: boolean }>; created: number }> {
  await assertAgent(agentId);
  await expireStaleScans(agentId);
  const scans: Array<Record<string, unknown> & { created: boolean }> = [];
  let created = 0;
  for (const type of types) {
    // Insert-or-find, twice: the outstanding row can finish between the two statements.
    for (let attempt = 0; attempt < 2; attempt++) {
      const ins = await query(
        `INSERT INTO edr_agent_scans (agent_id, scan_type, trigger, requested_by, status)
         VALUES ($1, $2, 'console', $3, 'pending')
         ON CONFLICT (agent_id, scan_type) WHERE trigger = 'console' AND status IN ('pending', 'running') DO NOTHING
         RETURNING id`,
        [agentId, type, userId]
      );
      const id = ins.rows[0]?.id;
      const rows = id
        ? await selectScans('s.id = $1', [id])
        : await selectScans(
            `s.agent_id = $1 AND s.scan_type = $2 AND s.trigger = 'console' AND s.status IN ('pending', 'running')`,
            [agentId, type]
          );
      if (rows[0]) {
        scans.push({ ...rows[0], created: !!id });
        if (id) created++;
        break;
      }
    }
  }
  return { scans, created };
}

/**
 * "Scan selected": console requests for up to BULK_SCAN_MAX_AGENTS agents.
 * Agents with a request already outstanding for a type keep it.
 */
export async function requestScansBulk(
  rawAgentIds: unknown,
  types: ScanType[],
  userId: number | null
): Promise<{ agents: number; created: number; already_outstanding: number; missing: string[] }> {
  if (!Array.isArray(rawAgentIds) || rawAgentIds.length === 0) {
    throw new ApiError(400, 'agent_ids must be a non-empty array');
  }
  const ids = [...new Set(rawAgentIds.map((v) => (typeof v === 'string' ? v.toLowerCase() : '')))];
  if (ids.length > BULK_SCAN_MAX_AGENTS) {
    throw new ApiError(400, `At most ${BULK_SCAN_MAX_AGENTS} endpoints per request`);
  }
  if (ids.some((id) => !isUuid(id))) throw new ApiError(400, 'agent_ids must be endpoint ids');
  await expireStaleScans();
  const found = await query('SELECT agent_id FROM edr_agents WHERE agent_id = ANY($1::uuid[])', [ids]);
  const present = new Set<string>(found.rows.map((r: { agent_id: string }) => r.agent_id));
  const missing = ids.filter((id) => !present.has(id));
  if (present.size === 0) return { agents: 0, created: 0, already_outstanding: 0, missing };
  const ins = await query(
    `INSERT INTO edr_agent_scans (agent_id, scan_type, trigger, requested_by, status)
     SELECT a.id, t.type, 'console', $3, 'pending'
       FROM unnest($1::uuid[]) AS a(id) CROSS JOIN unnest($2::text[]) AS t(type)
     ON CONFLICT (agent_id, scan_type) WHERE trigger = 'console' AND status IN ('pending', 'running') DO NOTHING`,
    [[...present], types, userId]
  );
  const created = ins.rowCount ?? 0;
  return { agents: present.size, created, already_outstanding: present.size * types.length - created, missing };
}

/** Cancel a pending console request. 404 unknown, 409 when it is no longer pending. */
export async function cancelScan(agentId: string, scanId: string) {
  if (!isUuid(agentId) || !isUuid(scanId)) throw new ApiError(404, 'Scan not found');
  await expireStaleScans(agentId);
  const upd = await query(
    `UPDATE edr_agent_scans
        SET status = 'cancelled', completed_at = NOW(), updated_at = NOW()
      WHERE id = $1 AND agent_id = $2 AND status = 'pending'
      RETURNING id`,
    [scanId, agentId]
  );
  const rows = await selectScans('s.id = $1 AND s.agent_id = $2', [scanId, agentId]);
  if (!rows[0]) throw new ApiError(404, 'Scan not found');
  if ((upd.rowCount ?? 0) === 0) {
    throw new ApiError(409, `Only a pending request can be cancelled; this one is ${rows[0].status}`);
  }
  return rows[0];
}

/** An agent's scan history, newest first, with optional type/status filters. */
export async function listScans(
  agentId: string,
  opts: { type?: string; status?: string; limit?: number; offset?: number } = {}
) {
  await assertAgent(agentId);
  await expireStaleScans(agentId);
  const limit = Math.min(Math.max(opts.limit ?? 50, 1), 200);
  const offset = Math.max(opts.offset ?? 0, 0);
  const params: unknown[] = [agentId];
  let where = 's.agent_id = $1';
  if (opts.type !== undefined) {
    if (!isOneOf(SCAN_TYPES, opts.type)) throw new ApiError(400, 'unknown scan type');
    params.push(opts.type);
    where += ` AND s.scan_type = $${params.length}`;
  }
  if (opts.status !== undefined) {
    if (!isOneOf(SCAN_STATUSES, opts.status)) throw new ApiError(400, 'unknown scan status');
    params.push(opts.status);
    where += ` AND s.status = $${params.length}`;
  }
  const total = await query(`SELECT COUNT(*)::int AS n FROM edr_agent_scans s WHERE ${where}`, params);
  const scans = await selectScans(
    `${where} ORDER BY s.requested_at DESC, s.id LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
    [...params, limit, offset]
  );
  const outstanding = await query(
    `SELECT COUNT(*)::int AS n FROM edr_agent_scans WHERE agent_id = $1 AND status IN ('pending', 'running')`,
    [agentId]
  );
  const agent = await query('SELECT capabilities, agent_version FROM edr_agents WHERE agent_id = $1', [agentId]);
  return {
    total: total.rows[0].n,
    outstanding: outstanding.rows[0].n,
    supports_adhoc: supportsAdhocScans(agent.rows[0]),
    min_agent_version: MIN_ADHOC_AGENT_VERSION,
    scans,
  };
}

// ---- Agent side -------------------------------------------------------------------------

/** Pending console requests for the heartbeat response, oldest first (after expiring stale ones). */
export async function pendingScanRequests(agentId: string): Promise<ScanRequest[]> {
  await expireStaleScans(agentId);
  const result = await query(
    `SELECT id AS scan_id, scan_type, requested_at FROM edr_agent_scans
      WHERE agent_id = $1 AND status = 'pending' ORDER BY requested_at, id`,
    [agentId]
  );
  return result.rows;
}

export interface ScanReportResult {
  scan_id: string;
  status: ScanStatus;
  /** False when the report changed nothing (the run was cancelled, expired or already finished). */
  accepted: boolean;
}

/**
 * POST /api/edr/scans: the agent reports a run's start or end.
 *  - With scan_id (a console request, or a scheduled run it reported starting):
 *    `running` moves a pending row on; `succeeded`/`failed` finish a pending,
 *    running or expired row. A cancelled request is answered accepted=false,
 *    status 'cancelled', and the agent skips it; so is an expired one reported
 *    `running`.
 *  - Without scan_id: a scheduled or startup run; a new row is created in the
 *    reported status and its id returned for the finishing report.
 */
export async function reportScan(agentId: string, input: unknown): Promise<ScanReportResult> {
  const body = (input && typeof input === 'object' && !Array.isArray(input) ? input : {}) as Record<string, unknown>;
  if (!isOneOf(SCAN_TYPES, body.scan_type)) throw new ApiError(400, `scan_type must be one of: ${SCAN_TYPES.join(', ')}`);
  if (!isOneOf(REPORTABLE_SCAN_STATUSES, body.status)) {
    throw new ApiError(400, `status must be one of: ${REPORTABLE_SCAN_STATUSES.join(', ')}`);
  }
  const scanType = body.scan_type;
  const status = body.status;
  const finished = status !== 'running';
  const startedAt = parseTimestamp(body.started_at);
  const completedAt = finished ? parseTimestamp(body.completed_at) : null;
  const summary = sanitizeSummary(body.summary);
  const error = status === 'failed' ? cleanError(body.error) : null;
  const rawId = body.scan_id;

  if (rawId === undefined || rawId === null || rawId === '') {
    const trigger = body.trigger === undefined ? 'schedule' : body.trigger;
    if (!isOneOf(SCAN_TRIGGERS, trigger) || trigger === 'console') {
      throw new ApiError(400, 'trigger must be schedule or startup (a console run reports its scan_id)');
    }
    const ins = await query(
      `INSERT INTO edr_agent_scans (agent_id, scan_type, trigger, requested_at, started_at, completed_at, status, summary, error)
       VALUES ($1, $2, $3, COALESCE($4::timestamptz, NOW()), COALESCE($4::timestamptz, NOW()),
               CASE WHEN $8::boolean THEN COALESCE($5::timestamptz, NOW()) END, $6, $7::jsonb, $9)
       RETURNING id, status`,
      [agentId, scanType, trigger, startedAt, completedAt, status, summary ? JSON.stringify(summary) : null, finished, error]
    );
    return { scan_id: ins.rows[0].id, status: ins.rows[0].status, accepted: true };
  }

  if (!isUuid(rawId)) throw new ApiError(400, 'scan_id must be a UUID');
  const scanId = (rawId as string).toLowerCase();
  const current = await query('SELECT scan_type, status FROM edr_agent_scans WHERE id = $1 AND agent_id = $2', [scanId, agentId]);
  if (current.rows.length === 0) throw new ApiError(404, 'Scan not found');
  if (current.rows[0].scan_type !== scanType) throw new ApiError(400, 'scan_type does not match the scan');

  const upd = finished
    ? await query(
        `UPDATE edr_agent_scans
            SET status = $3,
                started_at = COALESCE(started_at, $4::timestamptz, requested_at),
                completed_at = COALESCE($5::timestamptz, NOW()),
                summary = CASE WHEN $6::jsonb IS NULL THEN summary ELSE $6::jsonb || COALESCE(summary, '{}'::jsonb) END,
                error = $7,
                updated_at = NOW()
          WHERE id = $1 AND agent_id = $2 AND status IN ('pending', 'running', 'expired')
          RETURNING status`,
        [scanId, agentId, status, startedAt, completedAt, summary ? JSON.stringify(summary) : null, error]
      )
    : await query(
        `UPDATE edr_agent_scans
            SET status = 'running', started_at = COALESCE($3::timestamptz, NOW()), updated_at = NOW()
          WHERE id = $1 AND agent_id = $2 AND status = 'pending'
          RETURNING status`,
        [scanId, agentId, startedAt]
      );
  if ((upd.rowCount ?? 0) > 0) return { scan_id: scanId, status: upd.rows[0].status, accepted: true };
  const now = await query('SELECT status FROM edr_agent_scans WHERE id = $1', [scanId]);
  const st = (now.rows[0]?.status ?? current.rows[0].status) as ScanStatus;
  // A repeated `running` report for a run already running is fine (accepted, nothing to change).
  return { scan_id: scanId, status: st, accepted: !finished && st === 'running' };
}

/**
 * Merge a summary the server computed from an ingest into the agent's scan
 * row (its keys win). Best-effort: an absent, malformed or foreign scan_id is
 * ignored, and a failure is logged, never thrown, so an ingest never fails
 * over its history row.
 */
export async function attachScanSummary(
  agentId: string,
  rawScanId: unknown,
  scanType: ScanType,
  summary: Record<string, number | boolean | string>
): Promise<void> {
  if (!isUuid(rawScanId)) return;
  try {
    await pool.query(
      `UPDATE edr_agent_scans
          SET summary = COALESCE(summary, '{}'::jsonb) || $4::jsonb, updated_at = NOW()
        WHERE id = $1 AND agent_id = $2 AND scan_type = $3 AND status <> 'cancelled'`,
      [(rawScanId as string).toLowerCase(), agentId, scanType, JSON.stringify(summary)]
    );
  } catch (err) {
    logger.warn('[EDR] scan summary update failed', {
      agentId,
      scanType,
      error: err instanceof Error ? err.message : String(err),
    });
  }
}
