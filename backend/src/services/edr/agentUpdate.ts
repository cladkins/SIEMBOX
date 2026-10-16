/**
 * Pure helpers for console-triggered endpoint-agent updates: version
 * comparison, update eligibility, the heartbeat `update` field validator, the
 * AgentConfig `agent_update` shape and GitHub release parsing. No database or
 * network access, so everything here is unit-testable (agentUpdate.test.ts).
 *
 * Wire contract: the server names a target version and a fresh request_id; the
 * agent downloads the release from GitHub itself. Only plain X.Y.Z is a valid
 * target; an agent whose own version is not X.Y.Z is a "dev build" (manual
 * update allowed, auto-update skips it). Downgrades and same-version updates
 * are never requested.
 */

/** GitHub repository the agent is released from (hardcoded on the agent too). */
export const AGENT_RELEASE_REPO = 'cladkins/siembox-endpoint';

/** Release asset that must exist for a release to be an update target. */
export const CHECKSUM_ASSET_NAME = 'SHA256SUMS';

export const UPDATE_STATES = ['pending', 'downloading', 'installing', 'succeeded', 'failed'] as const;
export type UpdateState = (typeof UPDATE_STATES)[number];

/** States an agent may report in a heartbeat (`pending` is server-only). */
export const REPORTABLE_STATES = ['downloading', 'installing', 'succeeded', 'failed'] as const;
export type ReportableState = (typeof REPORTABLE_STATES)[number];

export const MAX_REQUEST_ID_LENGTH = 64;
export const MAX_UPDATE_ERROR_LENGTH = 500;
export const MAX_VERSION_LENGTH = 64;

const SEMVER_RE = /^\d+\.\d+\.\d+$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Whether `value` is a UUID (agent ids and request ids), so a malformed path id is a 404, not a SQL cast error. */
export function isUuid(value: unknown): boolean {
  return typeof value === 'string' && UUID_RE.test(value);
}

export type Semver = [number, number, number];

/** Parse a plain X.Y.Z version, or null for anything else (dev builds, prereleases, a `v` prefix). */
export function parseSemver(version: unknown): Semver | null {
  if (typeof version !== 'string' || !SEMVER_RE.test(version)) return null;
  const parts = version.split('.').map(Number);
  if (!parts.every((n) => Number.isSafeInteger(n))) return null;
  return [parts[0], parts[1], parts[2]];
}

export function isSemver(version: unknown): boolean {
  return parseSemver(version) !== null;
}

/** An agent version that is not X.Y.Z (including an unknown version) is a dev build. */
export function isDevBuild(agentVersion: unknown): boolean {
  return !isSemver(agentVersion);
}

/** Numeric X, Y, Z compare: negative if a < b, 0 if equal, positive if a > b. Null if either is not semver. */
export function compareSemver(a: string, b: string): number | null {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (!pa || !pb) return null;
  for (let i = 0; i < 3; i++) {
    if (pa[i] !== pb[i]) return pa[i] < pb[i] ? -1 : 1;
  }
  return 0;
}

export type UpdateEligibility =
  | { eligible: true; devBuild: boolean }
  | { eligible: false; reason: 'invalid_target' | 'up_to_date' };

/**
 * Whether `target` may be requested for an agent running `agentVersion`.
 * Manual requests (the default) are allowed for dev builds; `auto` requests
 * only for agents on a semver version strictly lower than the target.
 */
export function checkUpdateEligibility(
  agentVersion: string | null | undefined,
  target: string | null | undefined,
  mode: 'manual' | 'auto' = 'manual'
): UpdateEligibility {
  if (!parseSemver(target)) return { eligible: false, reason: 'invalid_target' };
  if (!isSemver(agentVersion)) {
    return mode === 'manual' ? { eligible: true, devBuild: true } : { eligible: false, reason: 'up_to_date' };
  }
  const cmp = compareSemver(agentVersion as string, target as string);
  return cmp !== null && cmp < 0 ? { eligible: true, devBuild: false } : { eligible: false, reason: 'up_to_date' };
}

/** The slice of an edr_agents row that targeting looks at. */
export interface AgentUpdateRow {
  agent_id: string;
  agent_version: string | null;
  update_request_id: string | null;
  update_target_version: string | null;
  update_state: string | null;
}

/**
 * Agents that should get a fresh request for `target`.
 *  - `auto`: semver agents lower than target with no request (any state,
 *    including failed) already outstanding for that version, so a failing
 *    agent is not retried every release check. Manual Update retries it.
 *  - `manual-bulk` ("Update all outdated"): the same, but dev builds are
 *    skipped as well (it is a fleet action, not a targeted one) and a failed
 *    request is retried; only an in-flight one is left alone.
 */
export function selectAgentsToUpdate(
  agents: AgentUpdateRow[],
  target: string,
  mode: 'auto' | 'manual-bulk'
): string[] {
  return agents
    .filter((a) => {
      if (!isSemver(a.agent_version)) return false; // dev builds: manual per-agent only
      if (!checkUpdateEligibility(a.agent_version, target, 'auto').eligible) return false;
      const sameTarget = a.update_request_id !== null && a.update_target_version === target;
      if (!sameTarget) return true;
      // An outstanding request for this version is left alone, except that
      // "Update all outdated" retries a failed one.
      return mode === 'manual-bulk' && a.update_state === 'failed';
    })
    .map((a) => a.agent_id);
}

// ---- Heartbeat `update` field ----------------------------------------------------

export interface HeartbeatUpdate {
  request_id: string;
  state: ReportableState;
  /** Truncated to MAX_UPDATE_ERROR_LENGTH; null unless state is `failed`. */
  error: string | null;
  /** The target version the agent reports, when it sent a valid one. */
  version: string | null;
}

/**
 * Validate the optional heartbeat `update` object. Returns null for an absent
 * or malformed one, which the route then ignores (the heartbeat itself still
 * succeeds: liveness must not depend on a bad optional field).
 */
export function parseHeartbeatUpdate(raw: unknown): HeartbeatUpdate | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const { request_id, state, error, version } = raw as Record<string, unknown>;
  if (typeof request_id !== 'string' || request_id.length === 0 || request_id.length > MAX_REQUEST_ID_LENGTH) return null;
  if (!UUID_RE.test(request_id)) return null; // request ids are server-issued UUIDs
  if (typeof state !== 'string' || !(REPORTABLE_STATES as readonly string[]).includes(state)) return null;
  if (error !== undefined && error !== null && typeof error !== 'string') return null;
  if (version !== undefined && version !== null && typeof version !== 'string') return null;
  const errText = state === 'failed' && typeof error === 'string' && error.length > 0
    ? error.slice(0, MAX_UPDATE_ERROR_LENGTH)
    : null;
  return {
    request_id: request_id.toLowerCase(),
    state: state as ReportableState,
    error: errText,
    version: typeof version === 'string' && isSemver(version) ? version : null,
  };
}

/** A usable agent_version string from a heartbeat, or undefined (keep the stored one). */
export function sanitizeAgentVersion(raw: unknown): string | undefined {
  if (typeof raw !== 'string') return undefined;
  const v = raw.trim();
  return v.length > 0 && v.length <= MAX_VERSION_LENGTH ? v : undefined;
}

// ---- AgentConfig.agent_update ------------------------------------------------------

export interface AgentUpdateConfig {
  version: string;
  request_id: string;
}

/** `agent_update` for AgentConfig: the outstanding request, or null. */
export function buildAgentUpdateConfig(
  agent: { update_request_id?: string | null; update_target_version?: string | null } | null | undefined
): AgentUpdateConfig | null {
  if (!agent?.update_request_id || !agent.update_target_version) return null;
  return { version: agent.update_target_version, request_id: agent.update_request_id };
}

// ---- GitHub release ------------------------------------------------------------------

export type ReleaseParse =
  | { ok: true; version: string }
  | { ok: false; error: string };

/**
 * Accept a GitHub "latest release" payload as an update target only when its
 * tag is vX.Y.Z (no prerelease) and it carries a SHA256SUMS asset: releases
 * published before the checksum pipeline cannot be verified by the agent.
 */
export function parseLatestRelease(payload: unknown): ReleaseParse {
  if (!payload || typeof payload !== 'object') return { ok: false, error: 'unexpected response from GitHub' };
  const rel = payload as { tag_name?: unknown; draft?: unknown; prerelease?: unknown; assets?: unknown };
  if (rel.draft === true || rel.prerelease === true) return { ok: false, error: 'latest release is a draft or prerelease' };
  const tag = typeof rel.tag_name === 'string' ? rel.tag_name : '';
  const m = /^v(\d+\.\d+\.\d+)$/.exec(tag);
  if (!m || !isSemver(m[1])) return { ok: false, error: `latest release tag "${tag.slice(0, 64)}" is not vX.Y.Z` };
  const assets = Array.isArray(rel.assets) ? rel.assets : [];
  const hasSums = assets.some((a) => !!a && typeof a === 'object' && (a as { name?: unknown }).name === CHECKSUM_ASSET_NAME);
  if (!hasSums) return { ok: false, error: `release ${tag} has no ${CHECKSUM_ASSET_NAME} asset; agents cannot verify it` };
  return { ok: true, version: m[1] };
}
