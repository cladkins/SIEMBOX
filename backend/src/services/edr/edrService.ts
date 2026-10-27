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
import pool, { query } from '../../config/database';
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
  HEARTBEAT_INTERVAL_SECONDS,
  CONFIG_POLL_INTERVAL_SECONDS,
  INVENTORY_INTERVAL_SECONDS,
  VULN_SCAN_INTERVAL_SECONDS,
} from '../../models/EdrAgent';
import { getCurrentYaraVersion } from './yaraService';
import type { AgentUpdateConfig } from './agentUpdate';
import { attachScanSummary } from './edrScans';
import { agentConfigScanPolicy } from './scanPolicies';

export type AgentScanPolicyConfig = Awaited<ReturnType<typeof agentConfigScanPolicy>>;
import { NotificationService } from '../notifications/notificationService';
import { maybeTriageAlert } from '../ai/triageService';

/** Parse an RFC3339/ISO timestamp, or null if missing/invalid. */
function parseTimestamp(value: unknown): Date | null {
  if (!value) return null;
  const d = new Date(String(value));
  return isNaN(d.getTime()) ? null : d;
}

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
 *
 * `scan_policy` (when given) says the server schedules this agent's scans
 * (services/edr/scanPolicies.ts): an agent that understands it stops running
 * its own intervals and runs the policy scans the heartbeat issues; `scans`
 * names which types its effective policy enables. Older agents ignore it and
 * keep the interval fields below.
 */
export function buildAgentConfig(
  baseConfigVersion: number,
  yaraRulesVersion = 0,
  agentUpdate: AgentUpdateConfig | null = null,
  scanPolicy: AgentScanPolicyConfig | null = null
) {
  return {
    config_version: baseConfigVersion + yaraRulesVersion,
    yara_rules_version: yaraRulesVersion,
    heartbeat_interval_seconds: HEARTBEAT_INTERVAL_SECONDS,
    config_poll_interval_seconds: CONFIG_POLL_INTERVAL_SECONDS,
    inventory_interval_seconds: INVENTORY_INTERVAL_SECONDS,
    vuln_scan_interval_seconds: VULN_SCAN_INTERVAL_SECONDS,
    enabled_modules: ['inventory', 'vuln', 'detect'],
    rule_set_version: 1,
    // Server-pushed Sigma rules. Empty for now; wire to /api/rules (endpoint/Sigma) later.
    rules: [] as string[],
    // Outstanding self-update request ({version, request_id}), or null. The
    // agent attempts a given request_id at most once.
    agent_update: agentUpdate,
    ...(scanPolicy ? { scan_policy: scanPolicy } : {}),
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
  return {
    agent_id: agentId,
    agent_api_key: apiKey,
    config: buildAgentConfig(1, yaraVersion, null, await agentConfigScanPolicy(agentId)),
  };
}

// ---- Inventory --------------------------------------------------------------

/**
 * A hash of a host inventory without its collection time, independent of key
 * and software order, so an unchanged host hashes the same every hour. Pure.
 */
export function inventoryHash(inventory: any): string {
  const canonical = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(canonical);
    if (v && typeof v === 'object') {
      return Object.fromEntries(
        Object.keys(v as Record<string, unknown>).sort().map((k) => [k, canonical((v as Record<string, unknown>)[k])])
      );
    }
    return v;
  };
  const facts: Record<string, unknown> = { ...(inventory && typeof inventory === 'object' ? inventory : {}) };
  const software = facts.software;
  delete facts.software;
  delete facts.collected_at;
  const sw = Array.isArray(software) ? software.map((x) => JSON.stringify(canonical(x))).sort() : [];
  return crypto.createHash('sha256').update(JSON.stringify([canonical(facts), sw])).digest('hex');
}

export async function ingestInventory(agentId: string, inventory: any, scanId?: unknown): Promise<number | null> {
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

  // Scan history: did anything change since the previous report?
  const hash = inventoryHash(inventory);
  const prev = await query(
    `UPDATE edr_agents a SET inventory_hash = $2 FROM (SELECT inventory_hash FROM edr_agents WHERE agent_id = $1) old
      WHERE a.agent_id = $1 RETURNING old.inventory_hash AS previous`,
    [agentId, hash]
  );
  await attachScanSummary(agentId, scanId, 'inventory', {
    changed: prev.rows[0]?.previous !== hash,
    software: software.length,
  });
  return assetId;
}

// ---- Vulnerabilities --------------------------------------------------------

export async function ingestVulnerabilities(agentId: string, payload: any): Promise<number> {
  const agent = await EdrAgentModel.findById(agentId);
  await EdrAgentModel.touch(agentId);

  // Record the agent-reported scan window (independent of whether findings attach
  // to an asset) so the UI can show the real last scan + derive the next one.
  const startedAt = parseTimestamp(payload?.scan_started_at);
  const completedAt = parseTimestamp(payload?.scan_completed_at);
  if (startedAt || completedAt) await EdrAgentModel.recordScan(agentId, startedAt, completedAt);

  if (!agent?.asset_id) return 0; // no asset to attach findings to yet

  const items = Array.isArray(payload?.vulnerabilities) ? payload.vulnerabilities : [];
  // Track the breakdown so the agent's grype count (one row per package×match)
  // can be reconciled with what we store (unique vuln-id per host). Logged below.
  const seen = new Set<string>();
  let duplicate = 0;
  let skippedNoId = 0;
  // One row per identifier: a single INSERT ... ON CONFLICT cannot touch a row
  // twice. Merged as the per-item upserts applied them in turn: a later report
  // wins, except that its missing cvss/description keep an earlier one's
  // (those columns update with COALESCE).
  const rows = new Map<string, EdrVulnRow>();
  for (const v of items) {
    // Primary field is `cve`; fall back to a generic advisory id (GHSA/ELSA/…)
    // if the agent sends one, so non-CVE findings aren't silently dropped.
    const ident = (v?.cve ?? v?.id ?? v?.vulnerability_id ?? '').toString().trim();
    if (!ident) { skippedNoId++; continue; }
    if (seen.has(ident)) duplicate++; else seen.add(ident);
    const key = ident.slice(0, 64);
    const row = edrVulnRow(key, ident, v);
    const earlier = rows.get(key);
    if (earlier) {
      row.cvss_score ??= earlier.cvss_score;
      row.description ??= earlier.description;
    }
    rows.set(key, row);
  }

  const all = [...rows.values()];
  // History summary, counted before the report is stored: how many of its
  // findings the endpoint did not have yet, and how many of the previous
  // report's open findings it no longer holds.
  const before = await countVulnChanges(agent.asset_id, agent.last_vuln_ingest_at ?? null, all.map((r) => r.cve_id));

  let stored = 0;
  for (let i = 0; i < all.length; i += EDR_VULN_BATCH) {
    stored += await storeEdrVulnBatch(agentId, agent.asset_id, all.slice(i, i + EDR_VULN_BATCH));
  }
  await query('UPDATE edr_agents SET last_vuln_ingest_at = $2 WHERE agent_id = $1', [agentId, before.startedAt]);
  await attachScanSummary(agentId, payload?.scan_id, 'vuln', {
    findings: all.length,
    new: Math.max(0, all.length - before.alreadyOpen),
    resolved: before.resolved,
    stored,
  });
  // received = grype's count; unique = what the host shows as "Open vulns".
  // received - unique = duplicate_id (same id, multiple packages) + skipped_no_id.
  logger.info(
    `[EDR] vuln ingest agent=${agentId} received=${items.length} unique=${seen.size} ` +
    `duplicate_id=${duplicate} skipped_no_id=${skippedNoId}`
  );
  return stored;
}

/**
 * Before storing a vulnerability report: how many of its identifiers the asset
 * already has linked, and how many findings of the previous report (open,
 * last_detected at or after that report started being stored) it no longer
 * holds. The store does not close those: an endpoint finding stays open until
 * someone marks it, so `resolved` means "no longer reported by the scan".
 * `startedAt` is read before the writes, so this report's rows are all at or
 * after it.
 */
async function countVulnChanges(
  assetId: number,
  previous: Date | null,
  identifiers: string[]
): Promise<{ alreadyOpen: number; resolved: number; startedAt: Date }> {
  const result = await query(
    `SELECT NOW() AS started_at,
            (SELECT COUNT(*)::int FROM asset_vulnerabilities av JOIN vulnerabilities v ON v.id = av.vulnerability_id
              WHERE av.asset_id = $1 AND v.cve_id = ANY($2::varchar[])) AS already,
            CASE WHEN $3::timestamptz IS NULL THEN 0 ELSE
              (SELECT COUNT(*)::int FROM asset_vulnerabilities av JOIN vulnerabilities v ON v.id = av.vulnerability_id
                WHERE av.asset_id = $1 AND av.status = 'open' AND av.last_detected >= $3::timestamptz
                  AND NOT (v.cve_id = ANY($2::varchar[]))) END AS resolved`,
    [assetId, identifiers, previous]
  );
  const r = result.rows[0];
  return { alreadyOpen: r.already, resolved: r.resolved, startedAt: r.started_at };
}

/**
 * Rows per statement when storing an agent's vulnerability report. A host can
 * report thousands of findings; one upsert per finding (plus the risk-score
 * trigger's lookups) took longer than the agent's 30 s request timeout, so the
 * agent gave up and re-sent the whole report while the server was still
 * working through the last one. Two statements per batch instead.
 */
const EDR_VULN_BATCH = 500;

interface EdrVulnRow {
  cve_id: string;
  severity: string;
  title: string;
  description: string | null;
  cvss_score: number | null;
  metadata: Record<string, unknown>;
  evidence: string;
}

function edrVulnRow(key: string, ident: string, v: any): EdrVulnRow {
  const severity = SEVERITY[(v?.severity ?? '').toString().toLowerCase()] ?? VulnerabilitySeverity.MEDIUM;
  return {
    cve_id: key,
    severity,
    title: (v?.package ? `${ident} — ${v.package}` : ident).slice(0, 500),
    description: v?.description ?? null,
    cvss_score: typeof v?.cvss === 'number' ? v.cvss : null,
    metadata: {
      source: v?.source || 'edr',
      package: v?.package,
      installed_version: v?.installed_version,
      fixed_version: v?.fixed_version,
    },
    evidence: [
      v?.package && `package=${v.package}`,
      v?.installed_version && `installed=${v.installed_version}`,
      v?.fixed_version && `fixed=${v.fixed_version}`,
      `source=${v?.source || 'edr'}`,
    ].filter(Boolean).join(' '),
  };
}

/**
 * Upsert one batch of findings and link them to the asset, with the same
 * column semantics as VulnerabilityRepository.upsertVulnerability +
 * createAssetVulnerability, in one transaction. If the batch fails (a value
 * a column refuses, say), it is retried row by row so one bad finding costs
 * only itself, as before. Returns the findings stored.
 */
async function storeEdrVulnBatch(agentId: string, assetId: number, batch: EdrVulnRow[]): Promise<number> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const upserted = await client.query(
      `INSERT INTO vulnerabilities (cve_id, severity, title, description, cvss_score, metadata)
       SELECT * FROM UNNEST($1::varchar[], $2::varchar[], $3::varchar[], $4::text[], $5::numeric[], $6::jsonb[])
       ON CONFLICT (cve_id) DO UPDATE SET
         cvss_score = COALESCE(EXCLUDED.cvss_score, vulnerabilities.cvss_score),
         severity = EXCLUDED.severity,
         title = EXCLUDED.title,
         description = COALESCE(EXCLUDED.description, vulnerabilities.description),
         last_modified_date = EXCLUDED.last_modified_date,
         metadata = COALESCE(EXCLUDED.metadata, vulnerabilities.metadata),
         updated_at = NOW()
       RETURNING id, cve_id`,
      [
        batch.map((r) => r.cve_id),
        batch.map((r) => r.severity),
        batch.map((r) => r.title),
        batch.map((r) => r.description),
        batch.map((r) => r.cvss_score),
        batch.map((r) => JSON.stringify(r.metadata)),
      ]
    );
    const idOf = new Map<string, number>(upserted.rows.map((r: any) => [r.cve_id, r.id]));
    const linked = batch.filter((r) => idOf.has(r.cve_id));
    await client.query(
      `INSERT INTO asset_vulnerabilities (asset_id, vulnerability_id, status, evidence, first_detected, last_detected)
       SELECT $1, t.vulnerability_id, $2, t.evidence, NOW(), NOW()
         FROM UNNEST($3::int[], $4::text[]) AS t(vulnerability_id, evidence)
       ON CONFLICT (asset_id, vulnerability_id) DO UPDATE SET
         last_detected = NOW(),
         evidence = COALESCE(EXCLUDED.evidence, asset_vulnerabilities.evidence),
         updated_at = NOW()`,
      [assetId, VulnerabilityStatus.OPEN, linked.map((r) => idOf.get(r.cve_id)), linked.map((r) => r.evidence)]
    );
    await client.query('COMMIT');
    return linked.length;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    logger.warn('EDR vuln batch failed; storing its findings one by one', {
      agentId,
      size: batch.length,
      error: error instanceof Error ? error.message : String(error),
    });
    let stored = 0;
    for (const r of batch) {
      try {
        const vuln = await VulnerabilityRepository.upsertVulnerability({
          cve_id: r.cve_id,
          severity: r.severity as any,
          title: r.title,
          description: r.description,
          cvss_score: r.cvss_score,
          metadata: r.metadata as any,
        });
        await VulnerabilityRepository.createAssetVulnerability({
          asset_id: assetId,
          vulnerability_id: vuln.id,
          status: VulnerabilityStatus.OPEN,
          evidence: r.evidence,
        });
        stored++;
      } catch (e) {
        logger.warn('EDR vuln upsert failed', { agentId, ident: r.cve_id, error: e instanceof Error ? e.message : String(e) });
      }
    }
    return stored;
  } finally {
    client.release();
  }
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
      if ((res.rowCount ?? 0) > 0) {
        created++;
        // Notify like rule-based alerts do. notifyAlert respects the per-event
        // enabled + min-severity preferences, so endpoint detections no longer
        // silently skip Email/Slack/ntfy.
        void NotificationService.notifyAlert({
          id: res.rows[0].id,
          severity,
          ruleName: (e.rule_name || e.source || 'Endpoint').toString(),
          title,
          description: description || undefined,
        });
        // Same fire-and-forget triage hook as rulesEngine.createAlert.
        maybeTriageAlert({ id: res.rows[0].id, severity, source: 'edr' });
      }
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
