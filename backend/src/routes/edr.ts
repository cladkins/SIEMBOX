/**
 * EDR API — agent-facing ingest (custom agent auth) + admin-facing management
 * (JWT + admin). Mounted at /api/edr WITHOUT the global `authenticate` so the
 * unauthenticated enroll endpoint and the agent-token endpoints can coexist with
 * the admin UI endpoints. Wire format: docs/EDR_API.md in cladkins/SIEMBOX-EDR.
 */
import { Router, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import { ApiError } from '../middleware/errorHandler';
import { authenticate, authorize } from '../middleware/auth';
import { authenticateAgent, requireAgentMatchesParam } from '../middleware/edrAgentAuth';
import { query } from '../config/database';
import { EdrAgentModel, EdrEnrollmentTokenModel } from '../models/EdrAgent';
import { VulnerabilityRepository } from '../services/vulnerabilities/vulnerabilityRepository';
import {
  enrollAgent,
  ingestInventory,
  ingestEvents,
  ingestVulnerabilities,
  buildAgentConfig,
  createEnrollmentToken,
} from '../services/edr/edrService';
import { ingestPackages, listAgentPackages } from '../services/edr/edrPackages';
import {
  getCurrentYaraVersion,
  getCurrentYaraBundle,
  getYaraStatus,
} from '../services/edr/yaraService';
import { refreshYaraForge } from '../services/edr/yaraForgeService';
import { buildAgentUpdateConfig, parseHeartbeatUpdate, sanitizeAgentVersion } from '../services/edr/agentUpdate';
import {
  getAgentUpdateStatus,
  checkForAgentRelease,
  setAutoUpdate,
  requestAgentUpdate,
  cancelAgentUpdate,
  requestUpdatesForOutdated,
} from '../services/edr/agentUpdateService';
import {
  parseCapabilities,
  parseScanTypes,
  pendingScanRequests,
  reportScan,
  requestScans,
  requestScansBulk,
  cancelScan,
  listScans,
} from '../services/edr/edrScans';
import { AuditService } from '../services/audit/auditService';
import { rateLimitedHandler, requestLimitKey } from '../net/requestLimits';

const router = Router();

// The general limiter (app.ts) exempts the agent-key routes below when they
// carry X-Agent-ID, so without this an invalid or unauthenticated request would
// reach authenticateAgent's DB lookup with no throttle at all. This
// per-address limiter runs in FRONT of agent auth to bound that (and the work
// it triggers). The ceiling is high on purpose: many endpoint agents
// legitimately share one NAT egress address — raise EDR_AGENT_RATE_MAX for
// large fleets behind a single public IP.
const edrAgentLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: Number(process.env.EDR_AGENT_RATE_MAX) || 30000, // requests per address per window
  keyGenerator: requestLimitKey,
  standardHeaders: 'draft-6',
  legacyHeaders: false,
  handler: rateLimitedHandler('Too many agent requests from your address.'),
});

// ---- Agent-facing endpoints -------------------------------------------------

// Enrollment — unauthenticated; the body carries a one-time enrollment token.
// Counted by the general limiter (app.ts) whatever headers it carries.
// The Endpoints page: analysts and operators read agents and their findings
// (and request scans, SCAN_WRITERS below). Enrollment, tokens, YARA rules,
// agent updates and removal stay admin-only.
const ENDPOINT_READERS = ['admin', 'operator', 'analyst'] as const;

router.post('/agents/enroll', async (req: Request, res: Response) => {
  const result = await enrollAgent(req.body ?? {}, req.ip);
  res.status(200).json(result);
});

// Heartbeat — agent auth; :id must match the authenticated agent. The returned
// config_version is composite (agent row + current YARA version) so a new YARA
// bundle makes it rise and the agent re-pulls config. See buildAgentConfig.
router.post('/agents/:id/heartbeat', edrAgentLimiter, authenticateAgent, requireAgentMatchesParam, async (req: Request, res: Response) => {
  const { status, agent_version, update, capabilities } = req.body ?? {};
  // `update` is the agent's self-update progress, `capabilities` what it can do.
  // A malformed one is dropped, not rejected: liveness must not depend on an
  // optional field.
  const base = await EdrAgentModel.heartbeat(
    req.params.id as string,
    status,
    sanitizeAgentVersion(agent_version),
    parseHeartbeatUpdate(update),
    parseCapabilities(capabilities)
  );
  const yaraVersion = await getCurrentYaraVersion();
  // Console scan requests waiting for this agent (older agents ignore the field).
  const scanRequests = await pendingScanRequests(req.params.id as string);
  res.status(200).json({
    config_version: (base ?? req.edrAgent!.config_version) + yaraVersion,
    scan_requests: scanRequests,
  });
});

// Config pull — agent auth.
router.get('/agents/:id/config', edrAgentLimiter, authenticateAgent, requireAgentMatchesParam, async (req: Request, res: Response) => {
  const yaraVersion = await getCurrentYaraVersion();
  res.status(200).json(buildAgentConfig(req.edrAgent!.config_version, yaraVersion, buildAgentUpdateConfig(req.edrAgent)));
});

// YARA rule pull — agent auth. Returns the curated bundle (highest version) as
// raw text/plain. Empty body is valid; the agent appends its embedded baseline.
// The agent only calls this when yara_rules_version increased, so it's low-traffic.
router.get('/agents/:id/yara', edrAgentLimiter, authenticateAgent, requireAgentMatchesParam, async (_req: Request, res: Response) => {
  const bundle = await getCurrentYaraBundle();
  res.status(200).type('text/plain').send(bundle?.rules ?? '');
});

/** Body `agent_id` must match the authenticated agent (defense in depth). */
function assertBodyAgent(req: Request) {
  const bodyId = (req.body?.agent_id ?? '').toString();
  if (bodyId && bodyId !== req.edrAgent!.agent_id) {
    throw new ApiError(403, 'agent_id does not match authenticated agent');
  }
}

// Inventory — agent auth; upsert the endpoint asset.
router.post('/inventory', edrAgentLimiter, authenticateAgent, async (req: Request, res: Response) => {
  assertBodyAgent(req);
  await ingestInventory(req.edrAgent!.agent_id, req.body?.inventory ?? {}, req.body?.scan_id);
  res.status(202).json({ accepted: true });
});

// Events — agent auth; detections -> alerts (deduped on event id).
router.post('/events', edrAgentLimiter, authenticateAgent, async (req: Request, res: Response) => {
  assertBodyAgent(req);
  const created = await ingestEvents(req.edrAgent!.agent_id, req.body?.events ?? []);
  res.status(202).json({ accepted: true, alerts_created: created });
});

// Vulnerabilities — agent auth; upsert into the existing vuln tables.
router.post('/vulnerabilities', edrAgentLimiter, authenticateAgent, async (req: Request, res: Response) => {
  assertBodyAgent(req);
  const stored = await ingestVulnerabilities(req.edrAgent!.agent_id, req.body ?? {});
  res.status(202).json({ accepted: true, stored });
});

// Installed packages — agent auth; a full snapshot of the host's software
// (replaces the agent's previous one). An unchanged snapshot_hash skips the
// writes; a hash-only body asks whether the server has that snapshot.
router.post('/packages', edrAgentLimiter, authenticateAgent, async (req: Request, res: Response) => {
  assertBodyAgent(req);
  const result = await ingestPackages(req.edrAgent!.agent_id, req.body ?? {});
  res.status(200).json(result);
});

// Scan history — agent auth; the agent reports a scan's start and end (console
// requests by scan_id; its own scheduled runs without one, which creates the row).
router.post('/scans', edrAgentLimiter, authenticateAgent, async (req: Request, res: Response) => {
  assertBodyAgent(req);
  res.status(200).json(await reportScan(req.edrAgent!.agent_id, req.body ?? {}));
});

// ---- Admin-facing endpoints (UI) -------------------------------------------

// List endpoints with live status + open-vuln / recent-detection counts.
router.get('/agents', authenticate, authorize(...ENDPOINT_READERS), async (_req: Request, res: Response) => {
  const agents = await EdrAgentModel.listWithStats();
  res.json({ agents });
});

// Generate an enrollment token (plaintext shown exactly once).
router.post('/tokens', authenticate, authorize('admin'), async (req: Request, res: Response) => {
  const { label, expires_in_hours } = req.body ?? {};
  const result = await createEnrollmentToken({
    label: typeof label === 'string' ? label.slice(0, 200) : undefined,
    createdBy: req.user!.id,
    expiresInHours: typeof expires_in_hours === 'number' ? expires_in_hours : undefined,
  });
  res.status(201).json(result);
});

// List issued tokens (hash + status — never the plaintext secret).
router.get('/tokens', authenticate, authorize('admin'), async (_req: Request, res: Response) => {
  const tokens = await EdrEnrollmentTokenModel.listAll();
  res.json({ tokens });
});

// Revoke (delete) an enrollment token by its hash. Revoking an active token
// stops it being used to enroll; on a used/expired token it just clears the row.
router.delete('/tokens/:hash', authenticate, authorize('admin'), async (req: Request, res: Response) => {
  const ok = await EdrEnrollmentTokenModel.delete(req.params.hash as string);
  if (!ok) throw new ApiError(404, 'Token not found');
  res.json({ deleted: true });
});

// Current served YARA bundle metadata (version/sha/source/size) — never the rules
// body. Useful for the UI and for verifying a publish landed.
router.get('/yara', authenticate, authorize('admin'), async (_req: Request, res: Response) => {
  res.json(await getYaraStatus());
});

// Pull the latest YARA-Forge bundle on demand (works regardless of the daily-job
// toggle). Returns the new version, or 200 with updated=false if it was unchanged.
router.post('/yara/refresh', authenticate, authorize('admin'), async (_req: Request, res: Response) => {
  const version = await refreshYaraForge();
  res.json({ updated: version !== null, version: version ?? (await getCurrentYaraVersion()) });
});

// ---- Agent updates (admin) --------------------------------------------------
// Static paths (/agents/update-outdated) are declared before /agents/:id.

/** Audit an admin write; AuditService.log never throws. */
async function auditEdr(req: Request, action: string, details: Record<string, unknown>) {
  await AuditService.log({
    userId: req.user!.id,
    action,
    resourceType: 'edr_agent',
    ipAddress: req.ip ?? null,
    userAgent: req.get('user-agent') ?? null,
    responseStatus: 200,
    details,
  });
}

// Latest known release, last check, and the auto-update switch.
router.get('/agent-updates', authenticate, authorize('admin'), async (_req: Request, res: Response) => {
  res.json(await getAgentUpdateStatus());
});

// Run the GitHub release check now (failures come back in `error`, not as a 5xx).
router.post('/agent-updates/check', authenticate, authorize('admin'), async (req: Request, res: Response) => {
  const status = await checkForAgentRelease();
  await auditEdr(req, 'edr.agent_update.check', { latest_version: status.latest_version, error: status.error });
  res.json(status);
});

// Fleet-wide auto-update. Turning it on immediately targets outdated agents.
router.put('/agent-updates/settings', authenticate, authorize('admin'), async (req: Request, res: Response) => {
  const { auto_update } = req.body ?? {};
  if (typeof auto_update !== 'boolean') throw new ApiError(400, 'auto_update must be a boolean');
  const { status, requested } = await setAutoUpdate(auto_update);
  await auditEdr(req, 'edr.agent_update.auto_update', { auto_update, requested });
  res.json(status);
});

// Request an update for every outdated (semver) agent.
router.post('/agents/update-outdated', authenticate, authorize('admin'), async (req: Request, res: Response) => {
  const requested = await requestUpdatesForOutdated('manual-bulk');
  await auditEdr(req, 'edr.agent_update.request_all', { requested });
  res.json({ requested });
});

// ---- On-demand scans (analyst and up; history readable by every role) -------
// Static path (/agents/scans/bulk) declared before /agents/:id.

const SCAN_WRITERS = ['admin', 'operator', 'analyst'] as const;

// "Scan selected": request scans on up to BULK_SCAN_MAX_AGENTS endpoints.
router.post('/agents/scans/bulk', authenticate, authorize(...SCAN_WRITERS), async (req: Request, res: Response) => {
  const types = parseScanTypes(req.body?.types);
  const result = await requestScansBulk(req.body?.agent_ids, types, req.user!.id);
  await auditEdr(req, 'edr.scan.request_bulk', { types, ...result });
  res.json(result);
});

// "Scan now" on one endpoint. A type already outstanding returns that request.
router.post('/agents/:id/scans', authenticate, authorize(...SCAN_WRITERS), async (req: Request, res: Response) => {
  const agentId = req.params.id as string;
  const types = parseScanTypes(req.body?.types);
  const result = await requestScans(agentId, types, req.user!.id);
  await auditEdr(req, 'edr.scan.request', {
    agent_id: agentId,
    types,
    created: result.created,
    scan_ids: result.scans.map((s) => s.id),
  });
  res.json(result);
});

// Cancel a pending request (409 once the agent has started it).
router.post('/agents/:id/scans/:scanId/cancel', authenticate, authorize(...SCAN_WRITERS), async (req: Request, res: Response) => {
  const agentId = req.params.id as string;
  const scan = await cancelScan(agentId, req.params.scanId as string);
  await auditEdr(req, 'edr.scan.cancel', { agent_id: agentId, scan_id: scan.id, scan_type: scan.scan_type });
  res.json({ scan });
});

// An endpoint's scan history (scheduled and on-demand), newest first.
router.get('/agents/:id/scans', authenticate, async (req: Request, res: Response) => {
  const num = (v: unknown) => (typeof v === 'string' && /^\d+$/.test(v) ? parseInt(v, 10) : undefined);
  const str = (v: unknown) => (typeof v === 'string' && v !== '' ? v : undefined);
  res.json(await listScans(req.params.id as string, {
    type: str(req.query.type),
    status: str(req.query.status),
    limit: num(req.query.limit),
    offset: num(req.query.offset),
  }));
});

// Request an update to the latest version for one agent.
router.post('/agents/:id/update', authenticate, authorize('admin'), async (req: Request, res: Response) => {
  const agentId = req.params.id as string;
  const { target_version } = await requestAgentUpdate(agentId);
  await auditEdr(req, 'edr.agent_update.request', { agent_id: agentId, target_version });
  res.json({ requested: true, target_version });
});

// Cancel an outstanding update request.
router.delete('/agents/:id/update', authenticate, authorize('admin'), async (req: Request, res: Response) => {
  const agentId = req.params.id as string;
  await cancelAgentUpdate(agentId);
  await auditEdr(req, 'edr.agent_update.cancel', { agent_id: agentId });
  res.json({ cancelled: true });
});

// Endpoint detail.
router.get('/agents/:id', authenticate, authorize(...ENDPOINT_READERS), async (req: Request, res: Response) => {
  const agent = await EdrAgentModel.findById(req.params.id as string);
  if (!agent) throw new ApiError(404, 'Agent not found');
  const safe: any = { ...agent };
  delete safe.api_key_hash; // never expose the agent's auth secret
  res.json({ agent: safe });
});

// Endpoint's vulnerabilities (reuses the existing asset-vuln store).
router.get('/agents/:id/vulnerabilities', authenticate, authorize(...ENDPOINT_READERS), async (req: Request, res: Response) => {
  const agent = await EdrAgentModel.findById(req.params.id as string);
  if (!agent) throw new ApiError(404, 'Agent not found');
  const vulns = agent.asset_id ? await VulnerabilityRepository.getAssetVulnerabilities(agent.asset_id) : [];
  res.json({ vulnerabilities: vulns });
});

// Endpoint's installed packages (the agent's newest snapshot), filtered by name.
router.get('/agents/:id/packages', authenticate, authorize(...ENDPOINT_READERS), async (req: Request, res: Response) => {
  const agent = await EdrAgentModel.findById(req.params.id as string);
  if (!agent) throw new ApiError(404, 'Agent not found');
  const num = (v: unknown) => (typeof v === 'string' && /^\d+$/.test(v) ? parseInt(v, 10) : undefined);
  res.json(await listAgentPackages(agent.agent_id, {
    q: typeof req.query.q === 'string' ? req.query.q : undefined,
    limit: num(req.query.limit),
    offset: num(req.query.offset),
  }));
});

// Endpoint's detections (alerts) — reuses the existing alerts table.
router.get('/agents/:id/detections', authenticate, authorize(...ENDPOINT_READERS), async (req: Request, res: Response) => {
  const agent = await EdrAgentModel.findById(req.params.id as string);
  if (!agent) throw new ApiError(404, 'Agent not found');
  if (!agent.asset_id) { res.json({ alerts: [] }); return; }
  const limit = Math.min(parseInt((req.query.limit as string) || '100', 10) || 100, 500);
  const result = await query(
    `SELECT id, severity, title, description, matched_data, status, event_id, created_at
       FROM alerts
      WHERE asset_id = $1 AND source = 'edr'
      ORDER BY created_at DESC
      LIMIT $2`,
    [agent.asset_id, limit]
  );
  res.json({ alerts: result.rows });
});

// Deregister an endpoint (does not delete its asset/alerts/vulns).
router.delete('/agents/:id', authenticate, authorize('admin'), async (req: Request, res: Response) => {
  const ok = await EdrAgentModel.delete(req.params.id as string);
  if (!ok) throw new ApiError(404, 'Agent not found');
  res.json({ deleted: true });
});

export default router;
