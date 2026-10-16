/**
 * Endpoint-agent update orchestration: the GitHub release check, the fleet-wide
 * settings (system_settings `edr_agent_*` keys) and requesting/cancelling
 * per-agent updates. Decision logic lives in agentUpdate.ts (pure, tested);
 * this file only does the I/O.
 *
 * The server never serves the binary: it names a target version and a fresh
 * request_id, bumps the agent's config_version, and the agent downloads the
 * release from GitHub itself. Setting or clearing a request always bumps
 * config_version so the next heartbeat makes the agent re-pull its config.
 */
import crypto from 'crypto';
import { query } from '../../config/database';
import { logger } from '../../utils/logger';
import { ApiError } from '../../middleware/errorHandler';
import {
  AGENT_RELEASE_REPO,
  checkUpdateEligibility,
  isUuid,
  parseLatestRelease,
  selectAgentsToUpdate,
  type AgentUpdateRow,
} from './agentUpdate';

const RELEASE_URL = `https://api.github.com/repos/${AGENT_RELEASE_REPO}/releases/latest`;
const FETCH_TIMEOUT_MS = 15_000;

const KEY_AUTO = 'edr_agent_auto_update';
const KEY_LATEST = 'edr_agent_latest_version';
const KEY_CHECKED = 'edr_agent_latest_checked_at';
const KEY_ERROR = 'edr_agent_latest_error';

export interface AgentUpdateStatus {
  latest_version: string | null;
  checked_at: string | null;
  error: string | null;
  auto_update: boolean;
}

async function readSettings(): Promise<Map<string, string>> {
  const result = await query('SELECT key, value FROM system_settings WHERE key = ANY($1::text[])', [
    [KEY_AUTO, KEY_LATEST, KEY_CHECKED, KEY_ERROR],
  ]);
  return new Map(result.rows.map((r: { key: string; value: string }) => [r.key, r.value]));
}

async function writeSettings(entries: Record<string, string>): Promise<void> {
  const keys = Object.keys(entries);
  await query(
    `INSERT INTO system_settings (key, value, updated_at)
     SELECT k, v, NOW() FROM unnest($1::text[], $2::text[]) AS t(k, v)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
    [keys, keys.map((k) => entries[k])]
  );
}

/** Fleet-wide update state for the Endpoints page. */
export async function getAgentUpdateStatus(): Promise<AgentUpdateStatus> {
  const s = await readSettings();
  return {
    latest_version: s.get(KEY_LATEST) || null,
    checked_at: s.get(KEY_CHECKED) || null,
    error: s.get(KEY_ERROR) || null,
    auto_update: s.get(KEY_AUTO) === 'true',
  };
}

// ---- Release check -------------------------------------------------------------

let checkInFlight: Promise<AgentUpdateStatus> | null = null;

async function fetchLatestRelease(): Promise<unknown> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const headers: Record<string, string> = {
      'User-Agent': 'SIEMBox-EDR',
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    };
    // Same optional token the parser catalog uses; only raises the rate limit.
    const token = process.env.GITHUB_TOKEN;
    if (token) headers.Authorization = `Bearer ${token}`;
    const res = await fetch(RELEASE_URL, { headers, signal: controller.signal, redirect: 'follow' });
    if (!res.ok) {
      throw new Error(`GitHub returned HTTP ${res.status}${res.status === 403 ? ' (rate limited? set GITHUB_TOKEN)' : ''}`);
    }
    return await res.json();
  } catch (err) {
    if (err instanceof Error && err.name === 'AbortError') {
      throw new Error(`GitHub request timed out after ${FETCH_TIMEOUT_MS / 1000}s`, { cause: err });
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Ask GitHub for the latest agent release and store the result. Never throws on
 * network or parse problems: they are stored as edr_agent_latest_error (the last
 * good latest version is kept) and returned in the status. When auto-update is
 * on, a newly accepted version is immediately targeted. Concurrent calls share
 * one request.
 */
export function checkForAgentRelease(): Promise<AgentUpdateStatus> {
  if (!checkInFlight) {
    checkInFlight = runReleaseCheck().finally(() => {
      checkInFlight = null;
    });
  }
  return checkInFlight;
}

async function runReleaseCheck(): Promise<AgentUpdateStatus> {
  const checkedAt = new Date().toISOString();
  let error = '';
  let version: string | null = null;
  try {
    const parsed = parseLatestRelease(await fetchLatestRelease());
    if (parsed.ok) version = parsed.version;
    else error = parsed.error;
  } catch (err) {
    error = (err instanceof Error ? err.message : String(err)).slice(0, 500);
  }
  const entries: Record<string, string> = { [KEY_CHECKED]: checkedAt, [KEY_ERROR]: error };
  if (version) entries[KEY_LATEST] = version;
  await writeSettings(entries);
  if (error) logger.warn(`[EDR] agent release check failed: ${error}`);

  const status = await getAgentUpdateStatus();
  if (version && status.auto_update) {
    try {
      const n = await requestUpdatesForOutdated('auto');
      if (n > 0) logger.info(`[EDR] auto-update requested for ${n} agent(s) -> v${version}`);
    } catch (err) {
      logger.warn('[EDR] auto-update targeting failed:', err instanceof Error ? err.message : err);
    }
  }
  return status;
}

/** Turn auto-update on/off. Turning it on immediately targets the stored latest version. */
export async function setAutoUpdate(enabled: boolean): Promise<{ status: AgentUpdateStatus; requested: number }> {
  await writeSettings({ [KEY_AUTO]: enabled ? 'true' : 'false' });
  const requested = enabled ? await requestUpdatesForOutdated('auto') : 0;
  return { status: await getAgentUpdateStatus(), requested };
}

// ---- Requests ----------------------------------------------------------------------

/** Request `target` for one agent. Caller has already checked eligibility. */
async function setRequest(agentId: string, target: string): Promise<boolean> {
  const result = await query(
    `UPDATE edr_agents
        SET update_request_id = $2::uuid,
            update_target_version = $3,
            update_state = 'pending',
            update_error = NULL,
            update_requested_at = NOW(),
            update_updated_at = NOW(),
            config_version = COALESCE(config_version, 1) + 1
      WHERE agent_id = $1`,
    [agentId, crypto.randomUUID(), target]
  );
  return (result.rowCount ?? 0) > 0;
}

/** Admin "Update" on one agent. 409 when no latest version is known or the agent is not behind it. */
export async function requestAgentUpdate(agentId: string): Promise<{ target_version: string }> {
  if (!isUuid(agentId)) throw new ApiError(404, 'Agent not found');
  const { latest_version } = await getAgentUpdateStatus();
  if (!latest_version) throw new ApiError(409, 'No update target is known yet; run a release check first');
  const agent = await query('SELECT agent_version FROM edr_agents WHERE agent_id = $1', [agentId]);
  if (agent.rows.length === 0) throw new ApiError(404, 'Agent not found');
  const verdict = checkUpdateEligibility(agent.rows[0].agent_version, latest_version, 'manual');
  if (!verdict.eligible) {
    throw new ApiError(409, `Agent is already at or above v${latest_version}`);
  }
  await setRequest(agentId, latest_version);
  return { target_version: latest_version };
}

/** Admin "Cancel": drop an outstanding request. 404 unknown agent, 409 nothing to cancel. */
export async function cancelAgentUpdate(agentId: string): Promise<void> {
  if (!isUuid(agentId)) throw new ApiError(404, 'Agent not found');
  const result = await query(
    `UPDATE edr_agents
        SET update_request_id = NULL,
            update_target_version = NULL,
            update_state = NULL,
            update_error = NULL,
            update_updated_at = NOW(),
            config_version = COALESCE(config_version, 1) + 1
      WHERE agent_id = $1 AND update_request_id IS NOT NULL`,
    [agentId]
  );
  if ((result.rowCount ?? 0) > 0) return;
  const exists = await query('SELECT 1 FROM edr_agents WHERE agent_id = $1', [agentId]);
  if (exists.rows.length === 0) throw new ApiError(404, 'Agent not found');
  throw new ApiError(409, 'No update request to cancel');
}

/**
 * Request the stored latest version for every outdated semver agent (see
 * selectAgentsToUpdate for what 'auto' and 'manual-bulk' skip). Returns how many
 * agents were targeted. No-op when no latest version is known.
 */
export async function requestUpdatesForOutdated(mode: 'auto' | 'manual-bulk'): Promise<number> {
  const { latest_version } = await getAgentUpdateStatus();
  if (!latest_version) return 0;
  const rows = await query(
    `SELECT agent_id, agent_version, update_request_id, update_target_version, update_state FROM edr_agents`
  );
  const ids = selectAgentsToUpdate(rows.rows as AgentUpdateRow[], latest_version, mode);
  if (ids.length === 0) return 0;
  const requestIds = ids.map(() => crypto.randomUUID());
  const result = await query(
    `UPDATE edr_agents a
        SET update_request_id = t.request_id,
            update_target_version = $3,
            update_state = 'pending',
            update_error = NULL,
            update_requested_at = NOW(),
            update_updated_at = NOW(),
            config_version = COALESCE(a.config_version, 1) + 1
       FROM unnest($1::uuid[], $2::uuid[]) AS t(agent_id, request_id)
      WHERE a.agent_id = t.agent_id`,
    [ids, requestIds, latest_version]
  );
  return result.rowCount ?? 0;
}
