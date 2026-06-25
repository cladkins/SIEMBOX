/**
 * EDR server-side ingest.
 *
 * Turns agent payloads into rows in SIEMBox's EXISTING tables:
 *   enroll/inventory -> assets (asset_type='endpoint', upserted by IP so an
 *                       endpoint correlates with any existing log/Nuclei asset)
 *   vulnerabilities  -> vulnerabilities + asset_vulnerabilities (idempotent upsert)
 *   events(detection)-> alerts (source='edr', linked to the endpoint asset,
 *                       deduped on the agent's stable event id)
 * The only EDR-specific state is the agent identity (models/EdrAgent).
 */
import crypto from 'crypto';
import { isIP } from 'net';
import { query } from '../../config/database';
import { logger } from '../../utils/logger';
import { ApiError } from '../../middleware/errorHandler';
import { AssetRepository } from '../assets/assetRepository';
import { VulnerabilityRepository } from '../vulnerabilities/vulnerabilityRepository';
import {
  AssetType,
  AssetStatus,
  DiscoveryMethod,
} from '../../models/Asset';
import { VulnerabilitySeverity, VulnerabilityStatus } from '../../models/Vulnerability';
import {
  EdrAgentModel,
  EdrEnrollmentTokenModel,
  sha256hex,
  generateSecret,
} from '../../models/EdrAgent';
import { getCurrentYaraVersion } from './yaraService';

/**
 * Desired agent behaviour.
 *
 * `config_version` is COMPOSITE: the agent's own row version plus the current
 * server-wide YARA bundle version. Publishing a new YARA bundle (a higher yara
 * version) therefore raises config_version for every agent, so the agent re-pulls
 * its config and then downloads the new rules — no agent rows need touching. The
 * agent treats config_version as an opaque monotonic counter, so this is safe.
 *
 * `yara_rules_version` is the version the agent compares against; 0 means "use the
 * embedded baseline only" (no server bundle published yet).
 */
export function buildAgentConfig(baseConfigVersion: number, yaraRulesVersion = 0) {
  return {
    config_version: baseConfigVersion + yaraRulesVersion,
    yara_rules_version: yaraRulesVersion,
    heartbeat_interval_seconds: 60,
    config_poll_interval_seconds: 300,
    inventory_interval_seconds: 3600,
    vuln_scan_interval_seconds: 86400,
    enabled_modules: ['inventory', 'vuln', 'detect'],
    rule_set_version: 1,
    // Server-pushed Sigma rules. Empty for now; wire to /api/rules (endpoint/Sigma) later.
    rules: [] as string[],
  };
}

const SEVERITY: Record<string, VulnerabilitySeverity> = {
  critical: VulnerabilitySeverity.CRITICAL,
  high: VulnerabilitySeverity.HIGH,
  medium: VulnerabilitySeverity.MEDIUM,
  low: VulnerabilitySeverity.LOW,
  info: VulnerabilitySeverity.INFO,
};
const ALERT_SEVERITIES = new Set(['low', 'medium', 'high', 'critical']);

/** Prefer the agent's reported (LAN) IP; fall back to the connecting IP. */
function pickIp(bodyIp?: string, connIp?: string): string | null {
  if (bodyIp && isIP(bodyIp)) return bodyIp;
  const stripped = (connIp || '').replace(/^::ffff:/, '');
  if (stripped && isIP(stripped)) return stripped;
  return null;
}

/** Upsert the endpoint asset (by IP) and return its id, or null if no usable IP. */
async function upsertEndpointAsset(facts: {
  ip: string | null;
  hostname?: string | null;
  mac?: string | null;
  os?: string | null;
  os_version?: string | null;
  metadata?: Record<string, unknown>;
}): Promise<number | null> {
  if (!facts.ip) return null;
  const asset = await AssetRepository.create({
    ip_address: facts.ip,
    hostname: facts.hostname || null,
    mac_address: facts.mac || null,
    os_type: facts.os || null,
    os_version: facts.os_version || null,
    asset_type: AssetType.ENDPOINT,
    discovery_method: DiscoveryMethod.EDR_AGENT,
    status: AssetStatus.ACTIVE,
    metadata: facts.metadata as any,
  });
  return asset.id;
}

// ---- Enrollment -------------------------------------------------------------

export interface EnrollInput {
  enrollment_token?: string;
  hostname?: string;
  os?: string;
  os_version?: string;
  arch?: string;
  agent_version?: string;
  ip?: string;
}

export async function enrollAgent(input: EnrollInput, connIp?: string) {
  if (!input?.enrollment_token) {
    throw new ApiError(401, 'enrollment_token is required');
  }
  // Atomically consume the single-use token (exists, unused, unexpired).
  const token = await EdrEnrollmentTokenModel.consume(sha256hex(input.enrollment_token));
  if (!token) {
    throw new ApiError(401, 'Invalid, expired, or already-used enrollment token');
  }

  const ip = pickIp(input.ip, connIp);
  const assetId = await upsertEndpointAsset({
    ip,
    hostname: input.hostname,
    os: input.os,
    os_version: input.os_version,
    metadata: { agent: true },
  });

  const agentId = crypto.randomUUID();
  const apiKey = generateSecret(); // 64-char hex, returned exactly once
  await EdrAgentModel.create({
    agent_id: agentId,
    api_key_hash: sha256hex(apiKey),
    asset_id: assetId,
    hostname: input.hostname,
    os: input.os,
    os_version: input.os_version,
    arch: input.arch,
    agent_version: input.agent_version,
    ip,
  });

  logger.info('EDR agent enrolled', { agentId, assetId, hostname: input.hostname });
  // New agents default to config_version 1; include the current YARA version so a
  // freshly-enrolled agent downloads the current bundle on its first config poll.
  const yaraVersion = await getCurrentYaraVersion();
  return { agent_id: agentId, agent_api_key: apiKey, config: buildAgentConfig(1, yaraVersion) };
}

// ---- Inventory --------------------------------------------------------------

export async function ingestInventory(agentId: string, inventory: any): Promise<number | null> {
  const agent = await EdrAgentModel.findById(agentId);
  const ip = pickIp(inventory?.ip, agent?.ip ?? undefined);
  // Cap software so a huge package list can't bloat the asset row.
  const software = Array.isArray(inventory?.software) ? inventory.software : [];
  const assetId = await upsertEndpointAsset({
    ip,
    hostname: inventory?.hostname,
    mac: inventory?.mac,
    os: inventory?.os,
    os_version: inventory?.os_version,
    metadata: {
      agent: true,
      agent_id: agentId,
      agent_version: inventory?.agent_version,
      software_count: software.length,
      software: software.slice(0, 2000),
      inventory_collected_at: inventory?.collected_at,
    },
  });

  // Keep the agent linked to whatever asset its IP resolved to.
  if (assetId && agent && agent.asset_id !== assetId) {
    await query('UPDATE edr_agents SET asset_id = $2 WHERE agent_id = $1', [agentId, assetId]);
  }
  await EdrAgentModel.touch(agentId);
  return assetId;
}

// ---- Vulnerabilities --------------------------------------------------------

export async function ingestVulnerabilities(agentId: string, payload: any): Promise<number> {
  const agent = await EdrAgentModel.findById(agentId);
  await EdrAgentModel.touch(agentId);
  if (!agent?.asset_id) return 0; // no asset to attach findings to yet

  const items = Array.isArray(payload?.vulnerabilities) ? payload.vulnerabilities : [];
  let stored = 0;
  for (const v of items) {
    const cve = (v?.cve ?? '').toString().trim();
    if (!cve) continue;
    const severity = SEVERITY[(v?.severity ?? '').toString().toLowerCase()] ?? VulnerabilitySeverity.MEDIUM;
    try {
      const vuln = await VulnerabilityRepository.upsertVulnerability({
        cve_id: cve.slice(0, 64),
        severity,
        title: v?.package ? `${cve} — ${v.package}` : cve,
        description: v?.description ?? null,
        cvss_score: typeof v?.cvss === 'number' ? v.cvss : null,
        metadata: {
          source: v?.source || 'edr',
          package: v?.package,
          installed_version: v?.installed_version,
          fixed_version: v?.fixed_version,
        } as any,
      });
      await VulnerabilityRepository.createAssetVulnerability({
        asset_id: agent.asset_id,
        vulnerability_id: vuln.id,
        status: VulnerabilityStatus.OPEN,
        evidence: [
          v?.package && `package=${v.package}`,
          v?.installed_version && `installed=${v.installed_version}`,
          v?.fixed_version && `fixed=${v.fixed_version}`,
          `source=${v?.source || 'edr'}`,
        ].filter(Boolean).join(' '),
      });
      stored++;
    } catch (e) {
      logger.warn('EDR vuln upsert failed', { agentId, cve, error: e instanceof Error ? e.message : String(e) });
    }
  }
  return stored;
}

// ---- Events (detections -> alerts) -----------------------------------------

export async function ingestEvents(agentId: string, events: any[]): Promise<number> {
  const agent = await EdrAgentModel.findById(agentId);
  const assetId = agent?.asset_id ?? null;
  await EdrAgentModel.touch(agentId);

  let created = 0;
  for (const e of Array.isArray(events) ? events : []) {
    if (!e || e.type !== 'detection') continue; // telemetry ignored for now
    const eventId = (e.id ?? '').toString().trim();
    if (!eventId) continue;

    const severity = ALERT_SEVERITIES.has((e.severity ?? '').toString()) ? e.severity : 'medium';
    const matched = {
      ...(e.fields && typeof e.fields === 'object' ? e.fields : {}),
      rule_id: e.rule_id ?? null,
      rule_name: e.rule_name ?? null,
      source: e.source ?? null,
      agent_id: agentId,
      event_timestamp: e.timestamp ?? null,
    };
    const title = (e.title || e.rule_name || 'Endpoint detection').toString().slice(0, 255);
    const description = e.rule_name
      ? `${e.rule_name}${e.source ? ` (${e.source})` : ''}`
      : (e.source ?? null);

    try {
      // Dedupe agent replays via the partial unique index on event_id.
      const res = await query(
        `INSERT INTO alerts
           (rule_id, parsed_log_id, severity, title, description, matched_data, status, asset_id, source, event_id)
         VALUES (NULL, NULL, $1, $2, $3, $4, 'new', $5, 'edr', $6)
         ON CONFLICT (event_id) WHERE event_id IS NOT NULL DO NOTHING
         RETURNING id`,
        [severity, title, description, JSON.stringify(matched), assetId, eventId]
      );
      if ((res.rowCount ?? 0) > 0) created++;
    } catch (e2) {
      logger.warn('EDR event->alert insert failed', { agentId, eventId, error: e2 instanceof Error ? e2.message : String(e2) });
    }
  }
  return created;
}

// ---- Enrollment-token management (admin UI) --------------------------------

export async function createEnrollmentToken(opts: { label?: string; createdBy?: number; expiresInHours?: number }) {
  const token = generateSecret();
  const expires_at = opts.expiresInHours && opts.expiresInHours > 0
    ? new Date(Date.now() + opts.expiresInHours * 3600_000)
    : null;
  await EdrEnrollmentTokenModel.create({
    token_hash: sha256hex(token),
    label: opts.label ?? null,
    created_by: opts.createdBy ?? null,
    expires_at,
  });
  // Plaintext returned exactly once.
  return { token, label: opts.label ?? null, expires_at };
}
