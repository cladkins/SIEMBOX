/**
 * Endpoint scan policies (migration 054): which scans each endpoint agent runs
 * and when, set on the server.
 *
 * A policy holds one entry per scan type (vuln, yara, packages, inventory):
 *
 *   { enabled, schedule | interval_minutes, window }
 *
 * - `schedule` is the calendar timing of Scheduled Scans (utils/scheduleTiming:
 *   hourly / daily / weekly / monthly in a time zone); without one the scan
 *   runs every `interval_minutes` after it last ran.
 * - `window` ({start, end, timezone}, HH:MM, may wrap past midnight) limits
 *   when a due scan may start: one that comes due outside it waits for it.
 *
 * Exactly one policy is the default; an endpoint follows its named policy
 * (edr_agents.scan_policy_id) or the default, and may override single scan
 * types (edr_agents.scan_policy_overrides). That is its effective policy.
 *
 * Delivery: the server decides when a scan is due and issues it as a scan
 * request (edr_agent_scans, trigger 'policy') in the agent's heartbeat
 * response, the path console "Scan now" requests take. The agent config's
 * `scan_policy` tells the agent the server schedules its scans, so it stops
 * running its own intervals. Due times are checked on each heartbeat, so an
 * offline endpoint gets nothing queued; when it reconnects, a scan that came
 * due meanwhile runs once (missed runs are not replayed), subject to the
 * window. Only agents reporting POLICY_SCAN_CAPABILITY follow policies; older
 * ones keep their own intervals.
 *
 * Per endpoint and type, edr_agent_policy_runs keeps the next due time, the
 * last issue time and the entry they were computed for (spec_key); when the
 * effective entry changes, the next due time is recomputed (planPolicyRun).
 */
import pool, { query } from '../../config/database';
import { ApiError } from '../../middleware/errorHandler';
import {
  computeNextRun,
  normalizeCalendarSchedule,
  wallClockAt,
  isValidTimeZone,
  parseTime,
  type CalendarSchedule,
} from '../../utils/scheduleTiming';
import { isUuid } from './agentUpdate';
import { SCAN_TYPES, expireStaleScans, type ScanType } from './edrScans';

/** Heartbeat capability of an agent whose scans the server schedules. */
export const POLICY_SCAN_CAPABILITY = 'policy_scans';
/** First agent release with POLICY_SCAN_CAPABILITY (shown to users of older agents). */
export const MIN_POLICY_AGENT_VERSION = '0.0.22';

/** Fixed-interval bounds, minutes. */
export const MIN_POLICY_INTERVAL_MINUTES = 15;
export const MAX_POLICY_INTERVAL_MINUTES = 30 * 24 * 60;
export const MAX_POLICY_NAME = 100;
export const MAX_POLICY_DESCRIPTION = 500;
/** Endpoints one bulk assignment may name. */
export const BULK_ASSIGN_MAX_AGENTS = 500;

/** What an agent without POLICY_SCAN_CAPABILITY runs on its own (its built-in defaults). */
export const LOCAL_AGENT_INTERVALS = {
  inventory_seconds: 3600,
  vuln_seconds: 86400,
  packages_seconds: 6 * 3600,
  yara: 'changed files every minute; a full pass at startup and after a rule update',
};

export interface ScanWindow {
  /** HH:MM, local to `timezone`. */
  start: string;
  /** HH:MM; earlier than start = the window runs past midnight. */
  end: string;
  timezone: string;
}

export interface ScanSpec {
  enabled: boolean;
  /** Calendar timing, or null for a fixed interval. */
  schedule: CalendarSchedule | null;
  /** Minutes between runs (schedule null), else null. */
  interval_minutes: number | null;
  window: ScanWindow | null;
}

export type PolicyScans = Record<ScanType, ScanSpec>;
export type PolicyOverrides = Partial<Record<ScanType, ScanSpec>>;

export interface ScanPolicy {
  id: number;
  name: string;
  description: string | null;
  is_default: boolean;
  scans: PolicyScans;
  created_at?: Date;
  updated_at?: Date;
}

/** The default policy's starting entries (and the fallback if its row is missing). */
export const BUILTIN_DEFAULT_SCANS: PolicyScans = {
  vuln: { enabled: true, schedule: null, interval_minutes: 1440, window: null },
  yara: { enabled: true, schedule: null, interval_minutes: 1440, window: null },
  packages: { enabled: true, schedule: null, interval_minutes: 360, window: null },
  inventory: { enabled: true, schedule: null, interval_minutes: 60, window: null },
};

// ---- Validation (pure) ---------------------------------------------------------

const TIME = /^([01]\d|2[0-3]):([0-5]\d)$/;

function isObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

function isScanType(v: unknown): v is ScanType {
  return typeof v === 'string' && (SCAN_TYPES as readonly string[]).includes(v);
}

/**
 * One scan type's entry, normalized (fixed key order, so equal entries
 * serialize equally). Throws an Error naming the problem; `label` prefixes it.
 */
export function normalizeScanSpec(input: unknown, label = 'scan'): ScanSpec {
  if (!isObject(input)) throw new Error(`${label} must be an object`);
  if (typeof input.enabled !== 'boolean') throw new Error(`${label}.enabled must be a boolean`);
  const hasSchedule = input.schedule !== undefined && input.schedule !== null;
  const hasInterval = input.interval_minutes !== undefined && input.interval_minutes !== null;
  if (hasSchedule && hasInterval) {
    throw new Error(`${label}: send either schedule (calendar timing) or interval_minutes (fixed interval), not both`);
  }
  let schedule: CalendarSchedule | null = null;
  let interval: number | null = null;
  if (hasSchedule) {
    try {
      schedule = normalizeCalendarSchedule(input.schedule);
    } catch (err) {
      throw new Error(`${label}.${err instanceof Error ? err.message : 'schedule is invalid'}`, { cause: err });
    }
  } else {
    const v = input.interval_minutes;
    if (!Number.isInteger(v) || (v as number) < MIN_POLICY_INTERVAL_MINUTES || (v as number) > MAX_POLICY_INTERVAL_MINUTES) {
      throw new Error(
        `${label}.interval_minutes must be an integer from ${MIN_POLICY_INTERVAL_MINUTES} to ${MAX_POLICY_INTERVAL_MINUTES} (or send a calendar schedule)`
      );
    }
    interval = v as number;
  }
  let window: ScanWindow | null = null;
  if (input.window !== undefined && input.window !== null) {
    const w = input.window;
    if (!isObject(w)) throw new Error(`${label}.window must be an object or null`);
    if (typeof w.start !== 'string' || !TIME.test(w.start)) throw new Error(`${label}.window.start must be HH:MM (24-hour)`);
    if (typeof w.end !== 'string' || !TIME.test(w.end)) throw new Error(`${label}.window.end must be HH:MM (24-hour)`);
    if (w.start === w.end) throw new Error(`${label}.window: start and end must differ (send window: null for any time)`);
    if (!isValidTimeZone(w.timezone)) throw new Error(`${label}.window.timezone must be an IANA time zone name, e.g. UTC`);
    window = { start: w.start, end: w.end, timezone: w.timezone };
  }
  return { enabled: input.enabled, schedule, interval_minutes: interval, window };
}

/** A policy's `scans`: an entry for every scan type, nothing else. */
export function normalizePolicyScans(input: unknown): PolicyScans {
  if (!isObject(input)) throw new Error(`scans must be an object with an entry for each of: ${SCAN_TYPES.join(', ')}`);
  for (const k of Object.keys(input)) {
    if (!isScanType(k)) throw new Error(`scans: unknown scan type "${k.slice(0, 32)}"`);
  }
  const out = {} as PolicyScans;
  for (const t of SCAN_TYPES) {
    if (input[t] === undefined) throw new Error(`scans.${t} is required`);
    out[t] = normalizeScanSpec(input[t], `scans.${t}`);
  }
  return out;
}

/** An endpoint's overrides: entries for some scan types (null entries drop out), or null for none. */
export function normalizeOverrides(input: unknown): PolicyOverrides | null {
  if (input === null || input === undefined) return null;
  if (!isObject(input)) throw new Error('overrides must be an object of scan type -> entry, or null');
  const out: PolicyOverrides = {};
  for (const [k, v] of Object.entries(input)) {
    if (!isScanType(k)) throw new Error(`overrides: unknown scan type "${k.slice(0, 32)}"`);
    if (v === null) continue;
    out[k] = normalizeScanSpec(v, `overrides.${k}`);
  }
  // Fixed key order, as normalizePolicyScans.
  const ordered: PolicyOverrides = {};
  for (const t of SCAN_TYPES) if (out[t]) ordered[t] = out[t];
  return Object.keys(ordered).length > 0 ? ordered : null;
}

/** A stored entry, re-normalized; one that no longer validates counts as disabled. */
function storedSpec(raw: unknown): ScanSpec {
  try {
    return normalizeScanSpec(raw);
  } catch {
    return { enabled: false, schedule: null, interval_minutes: 1440, window: null };
  }
}

function storedScans(raw: unknown): PolicyScans {
  const src = isObject(raw) ? raw : {};
  const out = {} as PolicyScans;
  for (const t of SCAN_TYPES) out[t] = src[t] === undefined ? { ...BUILTIN_DEFAULT_SCANS[t], enabled: false } : storedSpec(src[t]);
  return out;
}

function storedOverrides(raw: unknown): PolicyOverrides {
  const out: PolicyOverrides = {};
  if (!isObject(raw)) return out;
  for (const t of SCAN_TYPES) if (raw[t] !== undefined && raw[t] !== null) out[t] = storedSpec(raw[t]);
  return out;
}

function toApiError(err: unknown): never {
  if (err instanceof ApiError) throw err;
  throw new ApiError(400, err instanceof Error ? err.message : 'Invalid scan policy');
}

// ---- Timing (pure) -----------------------------------------------------------------

/** Identity of an entry for edr_agent_policy_runs.spec_key. */
export function specKey(spec: ScanSpec): string {
  return JSON.stringify(normalizeScanSpec(spec));
}

function minutesOf(hhmm: string): number {
  const { hour, minute } = parseTime(hhmm);
  return hour * 60 + minute;
}

/** Whether instant `ms` falls inside the window (start inclusive, end exclusive). */
export function inWindow(ms: number, window: ScanWindow): boolean {
  const w = wallClockAt(ms, window.timezone);
  const m = w.hour * 60 + w.minute;
  const start = minutesOf(window.start);
  const end = minutesOf(window.end);
  return start < end ? m >= start && m < end : m >= start || m < end;
}

/** The first instant at or after `ms` inside the window (`ms` itself without one). */
export function applyWindow(ms: number, window: ScanWindow | null): number {
  if (!window || inWindow(ms, window)) return ms;
  return computeNextRun({ frequency: 'daily', time: window.start, timezone: window.timezone }, new Date(ms)).getTime();
}

/** When an entry is next due after a run at `afterMs`. */
export function nextAfter(spec: ScanSpec, afterMs: number): number {
  if (spec.schedule) return computeNextRun(spec.schedule, new Date(afterMs)).getTime();
  return afterMs + (spec.interval_minutes ?? 1440) * 60_000;
}

export interface PolicyRunState {
  spec_key: string;
  next_due_at: Date | null;
  last_issued_at: Date | null;
}

export interface PolicyRunPlan extends PolicyRunState {
  /** Issue a run now. */
  issue: boolean;
  /** Why a due run is not issued now. */
  waiting: 'window' | 'outstanding' | null;
  /** The state differs from the stored one (write it). */
  changed: boolean;
}

/**
 * What a heartbeat at `now` does for one scan type, from its effective entry,
 * its stored state, and whether a policy run of it is still outstanding:
 *
 * - disabled: nothing is due;
 * - no state yet (an endpoint new to policies): due now, its baseline run;
 * - the entry changed (or was re-enabled): a calendar entry is next due at its
 *   next occurrence; an interval one `interval_minutes` after the last run
 *   (now if that has passed, or it never ran);
 * - due: issued if the window allows, the next due time computed from now (so
 *   runs missed while the endpoint was offline collapse into this one); a due
 *   run outside the window waits for it; a due run while the previous one is
 *   still outstanding is skipped (next due computed from now).
 */
export function planPolicyRun(
  spec: ScanSpec,
  state: PolicyRunState | null,
  now: Date,
  outstanding: boolean
): PolicyRunPlan {
  const nowMs = now.getTime();
  const key = specKey(spec);
  const lastIssued = state?.last_issued_at ?? null;
  const same = (next: Date | null, last: Date | null) =>
    !!state &&
    state.spec_key === key &&
    (state.next_due_at?.getTime() ?? null) === (next?.getTime() ?? null) &&
    (state.last_issued_at?.getTime() ?? null) === (last?.getTime() ?? null);

  if (!spec.enabled) {
    return { spec_key: key, next_due_at: null, last_issued_at: lastIssued, issue: false, waiting: null, changed: !same(null, lastIssued) };
  }

  let due: number;
  if (!state) {
    due = nowMs;
  } else if (state.spec_key !== key || !state.next_due_at) {
    if (spec.schedule) due = computeNextRun(spec.schedule, now).getTime();
    else due = lastIssued ? Math.max(nowMs, nextAfter(spec, lastIssued.getTime())) : nowMs;
  } else {
    due = state.next_due_at.getTime();
  }

  const result = (next: number, last: Date | null, issue: boolean, waiting: PolicyRunPlan['waiting']): PolicyRunPlan => {
    const nextDate = new Date(next);
    return { spec_key: key, next_due_at: nextDate, last_issued_at: last, issue, waiting, changed: !same(nextDate, last) };
  };

  if (due > nowMs) return result(due, lastIssued, false, null);
  if (spec.window && !inWindow(nowMs, spec.window)) return result(due, lastIssued, false, 'window');
  if (outstanding) return result(nextAfter(spec, nowMs), lastIssued, false, 'outstanding');
  return result(nextAfter(spec, nowMs), now, true, null);
}

/**
 * The next `count` run times from a plan: its next due time (now, when it
 * issues), each moved into the window, each later one after the run before.
 */
export function projectRuns(spec: ScanSpec, plan: PolicyRunPlan, now: Date, count: number): Date[] {
  if (!spec.enabled) return [];
  const runs: Date[] = [];
  let t = plan.issue ? now.getTime() : plan.next_due_at ? Math.max(plan.next_due_at.getTime(), now.getTime()) : now.getTime();
  for (let i = 0; i < count; i++) {
    const at = applyWindow(t, spec.window);
    runs.push(new Date(at));
    t = nextAfter(spec, at);
  }
  return runs;
}

/** The next runs of an entry saved now on an endpoint that already has a baseline (the editor's preview). */
export function previewRuns(spec: ScanSpec, now: Date, count: number): Date[] {
  const first = spec.schedule ? computeNextRun(spec.schedule, now).getTime() : nextAfter(spec, now.getTime());
  const plan: PolicyRunPlan = {
    spec_key: '', next_due_at: new Date(first), last_issued_at: null, issue: false, waiting: null, changed: false,
  };
  return projectRuns(spec, plan, now, count);
}

/** Whether an agent row says the server schedules its scans. */
export function supportsPolicyScans(agent: { capabilities?: string[] | null } | null | undefined): boolean {
  return Array.isArray(agent?.capabilities) && agent!.capabilities!.includes(POLICY_SCAN_CAPABILITY);
}

export interface EffectiveScan {
  scan_type: ScanType;
  source: 'policy' | 'override';
  spec: ScanSpec;
}

/** The effective entry per scan type: the endpoint's override, else its policy's. */
export function resolveEffective(policyScans: PolicyScans, overrides: PolicyOverrides | null): EffectiveScan[] {
  return SCAN_TYPES.map((t) => {
    const o = overrides?.[t];
    return o ? { scan_type: t, source: 'override' as const, spec: o } : { scan_type: t, source: 'policy' as const, spec: policyScans[t] };
  });
}

// ---- Policies (DB) -----------------------------------------------------------------

interface PolicyRow {
  id: number;
  name: string;
  description: string | null;
  is_default: boolean;
  scans: unknown;
  created_at: Date;
  updated_at: Date;
  endpoint_count?: number | string;
}

/** A request body: whatever JSON the client sent. */
type Body = Record<string, unknown> | null | undefined;

function rowToPolicy(r: PolicyRow): ScanPolicy & { endpoint_count?: number } {
  return {
    id: r.id,
    name: r.name,
    description: r.description,
    is_default: r.is_default,
    scans: storedScans(r.scans),
    created_at: r.created_at,
    updated_at: r.updated_at,
    ...(r.endpoint_count !== undefined ? { endpoint_count: Number(r.endpoint_count) } : {}),
  };
}

function parsePolicyId(raw: unknown): number {
  const n = typeof raw === 'number' ? raw : typeof raw === 'string' && /^\d{1,9}$/.test(raw) ? Number(raw) : NaN;
  if (!Number.isInteger(n) || n <= 0) throw new ApiError(404, 'Scan policy not found');
  return n;
}

/** All policies, the default first, with how many endpoints follow each. */
export async function listPolicies() {
  const result = await query(
    `SELECT p.*,
            (SELECT COUNT(*)::int FROM edr_agents a
              WHERE a.scan_policy_id = p.id OR (p.is_default AND a.scan_policy_id IS NULL)) AS endpoint_count
       FROM edr_scan_policies p
      ORDER BY p.is_default DESC, LOWER(p.name)`
  );
  return result.rows.map(rowToPolicy);
}

export async function getPolicy(rawId: unknown): Promise<ScanPolicy> {
  const id = parsePolicyId(rawId);
  const r = await query('SELECT * FROM edr_scan_policies WHERE id = $1', [id]);
  if (!r.rows[0]) throw new ApiError(404, 'Scan policy not found');
  return rowToPolicy(r.rows[0]);
}

function parseName(raw: unknown): string {
  if (typeof raw !== 'string' || !raw.trim()) throw new ApiError(400, 'name is required');
  const name = raw.trim();
  if (name.length > MAX_POLICY_NAME) throw new ApiError(400, `name must be at most ${MAX_POLICY_NAME} characters`);
  return name;
}

function parseDescription(raw: unknown): string | null {
  if (raw === undefined || raw === null) return null;
  if (typeof raw !== 'string') throw new ApiError(400, 'description must be a string');
  const d = raw.trim();
  if (d.length > MAX_POLICY_DESCRIPTION) throw new ApiError(400, `description must be at most ${MAX_POLICY_DESCRIPTION} characters`);
  return d || null;
}

function isUniqueViolation(err: unknown): boolean {
  return (err as { code?: string })?.code === '23505';
}

/** Raise config_version for endpoints so they re-pull config (their scan_policy changed). */
async function bumpConfig(where: string, params: unknown[]): Promise<void> {
  await query(`UPDATE edr_agents SET config_version = COALESCE(config_version, 1) + 1 WHERE ${where}`, params);
}

export async function createPolicy(body: Body, userId: number | null): Promise<ScanPolicy> {
  const name = parseName(body?.name);
  const description = parseDescription(body?.description);
  let scans: PolicyScans;
  try {
    scans = normalizePolicyScans(body?.scans);
  } catch (err) {
    toApiError(err);
  }
  try {
    const r = await query(
      `INSERT INTO edr_scan_policies (name, description, is_default, scans, created_by, updated_by)
       VALUES ($1, $2, FALSE, $3::jsonb, $4, $4) RETURNING *`,
      [name, description, JSON.stringify(scans), userId]
    );
    return rowToPolicy(r.rows[0]);
  } catch (err) {
    if (isUniqueViolation(err)) throw new ApiError(409, `A scan policy named "${name}" already exists`);
    throw err;
  }
}

/** Edit a policy's name, description and/or scans (each optional). */
export async function updatePolicy(rawId: unknown, body: Body, userId: number | null): Promise<ScanPolicy> {
  const current = await getPolicy(rawId);
  const name = body?.name === undefined ? current.name : parseName(body.name);
  const description = body?.description === undefined ? current.description : parseDescription(body.description);
  let scans = current.scans;
  if (body?.scans !== undefined) {
    try {
      scans = normalizePolicyScans(body.scans);
    } catch (err) {
      toApiError(err);
    }
  }
  try {
    const r = await query(
      `UPDATE edr_scan_policies
          SET name = $2, description = $3, scans = $4::jsonb, updated_by = $5, updated_at = NOW()
        WHERE id = $1 RETURNING *`,
      [current.id, name, description, JSON.stringify(scans), userId]
    );
    if (current.is_default) await bumpConfig('scan_policy_id IS NULL', []);
    else await bumpConfig('scan_policy_id = $1', [current.id]);
    return rowToPolicy(r.rows[0]);
  } catch (err) {
    if (isUniqueViolation(err)) throw new ApiError(409, `A scan policy named "${name}" already exists`);
    throw err;
  }
}

/** Delete a named policy; its endpoints fall back to the default. The default cannot be deleted. */
export async function deletePolicy(rawId: unknown): Promise<{ deleted: ScanPolicy; endpoints: number }> {
  const current = await getPolicy(rawId);
  if (current.is_default) throw new ApiError(400, 'The default scan policy cannot be deleted');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const moved = await client.query(
      `UPDATE edr_agents SET scan_policy_id = NULL, config_version = COALESCE(config_version, 1) + 1
        WHERE scan_policy_id = $1`,
      [current.id]
    );
    await client.query('DELETE FROM edr_scan_policies WHERE id = $1', [current.id]);
    await client.query('COMMIT');
    return { deleted: current, endpoints: moved.rowCount ?? 0 };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/** A request's policy_id: a named policy's id, or null (or the default's id) for the default. */
async function resolveAssignment(raw: unknown): Promise<{ id: number | null; policy: ScanPolicy | null }> {
  if (raw === null) return { id: null, policy: null };
  const policy = await getPolicy(raw).catch((err) => {
    if (err instanceof ApiError && err.statusCode === 404) throw new ApiError(400, 'policy_id must name an existing scan policy, or be null for the default');
    throw err;
  });
  return policy.is_default ? { id: null, policy } : { id: policy.id, policy };
}

/** Assign a policy (null = the default) to up to BULK_ASSIGN_MAX_AGENTS endpoints. */
export async function assignPolicyBulk(rawAgentIds: unknown, rawPolicyId: unknown) {
  if (!Array.isArray(rawAgentIds) || rawAgentIds.length === 0) throw new ApiError(400, 'agent_ids must be a non-empty array');
  const ids = [...new Set(rawAgentIds.map((v) => (typeof v === 'string' ? v.toLowerCase() : '')))];
  if (ids.length > BULK_ASSIGN_MAX_AGENTS) throw new ApiError(400, `At most ${BULK_ASSIGN_MAX_AGENTS} endpoints per request`);
  if (ids.some((id) => !isUuid(id))) throw new ApiError(400, 'agent_ids must be endpoint ids');
  if (rawPolicyId === undefined) throw new ApiError(400, 'policy_id is required (null for the default policy)');
  const { id } = await resolveAssignment(rawPolicyId);
  const upd = await query(
    `UPDATE edr_agents
        SET scan_policy_id = $2,
            config_version = COALESCE(config_version, 1) + CASE WHEN scan_policy_id IS DISTINCT FROM $2 THEN 1 ELSE 0 END
      WHERE agent_id = ANY($1::uuid[])
      RETURNING agent_id`,
    [ids, id]
  );
  const found = new Set<string>(upd.rows.map((r: { agent_id: string }) => r.agent_id));
  return { agents: found.size, policy_id: id, missing: ids.filter((x) => !found.has(x)) };
}

// ---- One endpoint ------------------------------------------------------------------

interface AgentPolicyContext {
  agent_id: string;
  capabilities: string[] | null;
  agent_version: string | null;
  scan_policy_id: number | null;
  overrides: PolicyOverrides;
  policy: { id: number | null; name: string; is_default: boolean; scans: PolicyScans };
}

async function loadContext(agentId: string): Promise<AgentPolicyContext | null> {
  if (!isUuid(agentId)) return null;
  const r = await query(
    `SELECT a.agent_id, a.capabilities, a.agent_version, a.scan_policy_id, a.scan_policy_overrides,
            p.id AS p_id, p.name AS p_name, p.is_default AS p_default, p.scans AS p_scans
       FROM edr_agents a
       LEFT JOIN edr_scan_policies p
         ON p.id = COALESCE(a.scan_policy_id, (SELECT id FROM edr_scan_policies WHERE is_default LIMIT 1))
      WHERE a.agent_id = $1`,
    [agentId]
  );
  const row = r.rows[0];
  if (!row) return null;
  return {
    agent_id: row.agent_id,
    capabilities: row.capabilities,
    agent_version: row.agent_version,
    scan_policy_id: row.scan_policy_id,
    overrides: storedOverrides(row.scan_policy_overrides),
    policy: row.p_id
      ? { id: row.p_id, name: row.p_name, is_default: row.p_default, scans: storedScans(row.p_scans) }
      : { id: null, name: 'Default', is_default: true, scans: BUILTIN_DEFAULT_SCANS },
  };
}

async function loadStates(agentId: string): Promise<Map<string, PolicyRunState>> {
  const r = await query(
    'SELECT scan_type, spec_key, next_due_at, last_issued_at FROM edr_agent_policy_runs WHERE agent_id = $1',
    [agentId]
  );
  return new Map(
    r.rows.map((s: PolicyRunState & { scan_type: string }) => [
      s.scan_type,
      { spec_key: s.spec_key, next_due_at: s.next_due_at, last_issued_at: s.last_issued_at },
    ])
  );
}

async function loadOutstanding(agentId: string): Promise<Set<string>> {
  const r = await query(
    `SELECT scan_type FROM edr_agent_scans
      WHERE agent_id = $1 AND trigger = 'policy' AND status IN ('pending', 'running')`,
    [agentId]
  );
  return new Set(r.rows.map((x: { scan_type: string }) => x.scan_type));
}

async function saveState(agentId: string, type: ScanType, plan: PolicyRunPlan): Promise<void> {
  await query(
    `INSERT INTO edr_agent_policy_runs (agent_id, scan_type, spec_key, next_due_at, last_issued_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, NOW())
     ON CONFLICT (agent_id, scan_type) DO UPDATE
        SET spec_key = EXCLUDED.spec_key, next_due_at = EXCLUDED.next_due_at,
            last_issued_at = EXCLUDED.last_issued_at, updated_at = NOW()`,
    [agentId, type, plan.spec_key, plan.next_due_at, plan.last_issued_at]
  );
}

/**
 * Heartbeat: issue the policy scans due for this agent now (pending
 * edr_agent_scans rows, trigger 'policy', served in this same response).
 * Agents without POLICY_SCAN_CAPABILITY get none. Returns how many were issued.
 */
export async function issueDuePolicyScans(agentId: string, now: Date = new Date()): Promise<number> {
  const ctx = await loadContext(agentId);
  if (!ctx || !supportsPolicyScans(ctx)) return 0;
  await expireStaleScans(agentId);
  const [states, outstanding] = await Promise.all([loadStates(agentId), loadOutstanding(agentId)]);
  let issued = 0;
  for (const eff of resolveEffective(ctx.policy.scans, ctx.overrides)) {
    const state = states.get(eff.scan_type) ?? null;
    let plan = planPolicyRun(eff.spec, state, now, outstanding.has(eff.scan_type));
    if (plan.issue) {
      const ins = await query(
        `INSERT INTO edr_agent_scans (agent_id, scan_type, trigger, status, requested_at, policy_id, policy_name, policy_source)
         VALUES ($1, $2, 'policy', 'pending', $3, $4, $5, $6)
         ON CONFLICT (agent_id, scan_type) WHERE trigger = 'policy' AND status IN ('pending', 'running') DO NOTHING
         RETURNING id`,
        [agentId, eff.scan_type, now, ctx.policy.id, ctx.policy.name, eff.source]
      );
      if (ins.rows[0]) issued++;
      else plan = planPolicyRun(eff.spec, state, now, true); // a concurrent heartbeat issued it
    }
    if (plan.changed) await saveState(agentId, eff.scan_type, plan);
  }
  return issued;
}

/** The agent config's `scan_policy`: the server schedules this agent's scans; which types run at all. */
export async function agentConfigScanPolicy(agentId: string) {
  const ctx = await loadContext(agentId);
  const scans = ctx ? resolveEffective(ctx.policy.scans, ctx.overrides) : resolveEffective(BUILTIN_DEFAULT_SCANS, null);
  return {
    managed: true,
    policy: ctx?.policy.name ?? 'Default',
    scans: Object.fromEntries(scans.map((s) => [s.scan_type, { enabled: s.spec.enabled }])),
  };
}

/** The Endpoints details pane: an endpoint's policy, overrides, effective entries and next runs. */
export async function getAgentScanPolicy(agentId: string, now: Date = new Date()) {
  const ctx = await loadContext(agentId);
  if (!ctx) throw new ApiError(404, 'Agent not found');
  const managed = supportsPolicyScans(ctx);
  const [states, outstanding] = await Promise.all([loadStates(agentId), loadOutstanding(agentId)]);
  const last = await query(
    `SELECT DISTINCT ON (scan_type) scan_type, status, requested_at, completed_at
       FROM edr_agent_scans WHERE agent_id = $1 AND trigger = 'policy'
      ORDER BY scan_type, requested_at DESC`,
    [agentId]
  );
  type LastRun = { scan_type: string; status: string; requested_at: Date; completed_at: Date | null };
  const lastByType = new Map<string, LastRun>(last.rows.map((r: LastRun) => [r.scan_type, r]));
  const scans = resolveEffective(ctx.policy.scans, ctx.overrides).map((eff) => {
    const state = states.get(eff.scan_type) ?? null;
    const plan = planPolicyRun(eff.spec, state, now, outstanding.has(eff.scan_type));
    const runs = projectRuns(eff.spec, plan, now, 3);
    const lr = lastByType.get(eff.scan_type);
    return {
      scan_type: eff.scan_type,
      source: eff.source,
      spec: eff.spec,
      next_runs: runs.map((d) => d.toISOString()),
      waiting: plan.waiting,
      outstanding: outstanding.has(eff.scan_type),
      last_issued_at: plan.last_issued_at ? plan.last_issued_at.toISOString() : null,
      last_run: lr ? { status: lr.status, requested_at: lr.requested_at, completed_at: lr.completed_at } : null,
    };
  });
  return {
    agent_id: ctx.agent_id,
    managed,
    min_agent_version: MIN_POLICY_AGENT_VERSION,
    agent_version: ctx.agent_version,
    policy: { id: ctx.policy.id, name: ctx.policy.name, is_default: ctx.policy.is_default },
    assigned_policy_id: ctx.scan_policy_id,
    overrides: ctx.overrides,
    scans,
    local_intervals: managed ? null : LOCAL_AGENT_INTERVALS,
  };
}

/**
 * Set an endpoint's policy (`policy_id`, null = default) and/or its overrides
 * (`overrides`: the full map, replacing the previous one; null or {} clears).
 */
export async function setAgentScanPolicy(agentId: string, body: Body) {
  const ctx = await loadContext(agentId);
  if (!ctx) throw new ApiError(404, 'Agent not found');
  const hasPolicy = body && Object.prototype.hasOwnProperty.call(body, 'policy_id');
  const hasOverrides = body && Object.prototype.hasOwnProperty.call(body, 'overrides');
  if (!hasPolicy && !hasOverrides) throw new ApiError(400, 'Send policy_id and/or overrides');
  let policyId = ctx.scan_policy_id;
  if (hasPolicy) policyId = (await resolveAssignment(body.policy_id)).id;
  let overrides: PolicyOverrides | null = Object.keys(ctx.overrides).length ? ctx.overrides : null;
  if (hasOverrides) {
    try {
      overrides = normalizeOverrides(body.overrides);
    } catch (err) {
      toApiError(err);
    }
  }
  await query(
    `UPDATE edr_agents
        SET scan_policy_id = $2, scan_policy_overrides = $3::jsonb,
            config_version = COALESCE(config_version, 1) + 1
      WHERE agent_id = $1`,
    [agentId, policyId, overrides ? JSON.stringify(overrides) : null]
  );
  return getAgentScanPolicy(agentId);
}
