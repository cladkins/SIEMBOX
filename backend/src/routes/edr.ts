/**
 * EDR API — agent-facing ingest (custom agent auth) + admin-facing management
 * (JWT + admin). Mounted at /api/edr WITHOUT the global `authenticate` so the
 * unauthenticated enroll endpoint and the agent-token endpoints can coexist with
 * the admin UI endpoints. Wire format: docs/EDR_API.md in cladkins/SIEMBOX-EDR.
 */
import { Router, Request, Response } from 'express';
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
import {
  getCurrentYaraVersion,
  getCurrentYaraBundle,
  getYaraStatus,
} from '../services/edr/yaraService';
import { refreshYaraForge } from '../services/edr/yaraForgeService';

const router = Router();

// ---- Agent-facing endpoints -------------------------------------------------

// Enrollment — unauthenticated; the body carries a one-time enrollment token.
router.post('/agents/enroll', async (req: Request, res: Response) => {
  const result = await enrollAgent(req.body ?? {}, req.ip);
  res.status(200).json(result);
});

// Heartbeat — agent auth; :id must match the authenticated agent. The returned
// config_version is composite (agent row + current YARA version) so a new YARA
// bundle makes it rise and the agent re-pulls config. See buildAgentConfig.
router.post('/agents/:id/heartbeat', authenticateAgent, requireAgentMatchesParam, async (req: Request, res: Response) => {
  const { status, agent_version } = req.body ?? {};
  const base = await EdrAgentModel.heartbeat(req.params.id, status, agent_version);
  const yaraVersion = await getCurrentYaraVersion();
  res.status(200).json({ config_version: (base ?? req.edrAgent!.config_version) + yaraVersion });
});

// Config pull — agent auth.
router.get('/agents/:id/config', authenticateAgent, requireAgentMatchesParam, async (req: Request, res: Response) => {
  const yaraVersion = await getCurrentYaraVersion();
  res.status(200).json(buildAgentConfig(req.edrAgent!.config_version, yaraVersion));
});

// YARA rule pull — agent auth. Returns the curated bundle (highest version) as
// raw text/plain. Empty body is valid; the agent appends its embedded baseline.
// The agent only calls this when yara_rules_version increased, so it's low-traffic.
router.get('/agents/:id/yara', authenticateAgent, requireAgentMatchesParam, async (_req: Request, res: Response) => {
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
router.post('/inventory', authenticateAgent, async (req: Request, res: Response) => {
  assertBodyAgent(req);
  await ingestInventory(req.edrAgent!.agent_id, req.body?.inventory ?? {});
  res.status(202).json({ accepted: true });
});

// Events — agent auth; detections -> alerts (deduped on event id).
router.post('/events', authenticateAgent, async (req: Request, res: Response) => {
  assertBodyAgent(req);
  const created = await ingestEvents(req.edrAgent!.agent_id, req.body?.events ?? []);
  res.status(202).json({ accepted: true, alerts_created: created });
});

// Vulnerabilities — agent auth; upsert into the existing vuln tables.
router.post('/vulnerabilities', authenticateAgent, async (req: Request, res: Response) => {
  assertBodyAgent(req);
  const stored = await ingestVulnerabilities(req.edrAgent!.agent_id, req.body ?? {});
  res.status(202).json({ accepted: true, stored });
});

// ---- Admin-facing endpoints (UI) -------------------------------------------

// List endpoints with live status + open-vuln / recent-detection counts.
router.get('/agents', authenticate, authorize('admin'), async (_req: Request, res: Response) => {
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
  const ok = await EdrEnrollmentTokenModel.delete(req.params.hash);
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

// Endpoint detail.
router.get('/agents/:id', authenticate, authorize('admin'), async (req: Request, res: Response) => {
  const agent = await EdrAgentModel.findById(req.params.id);
  if (!agent) throw new ApiError(404, 'Agent not found');
  const { api_key_hash, ...safe } = agent as any;
  res.json({ agent: safe });
});

// Endpoint's vulnerabilities (reuses the existing asset-vuln store).
router.get('/agents/:id/vulnerabilities', authenticate, authorize('admin'), async (req: Request, res: Response) => {
  const agent = await EdrAgentModel.findById(req.params.id);
  if (!agent) throw new ApiError(404, 'Agent not found');
  const vulns = agent.asset_id ? await VulnerabilityRepository.getAssetVulnerabilities(agent.asset_id) : [];
  res.json({ vulnerabilities: vulns });
});

// Endpoint's detections (alerts) — reuses the existing alerts table.
router.get('/agents/:id/detections', authenticate, authorize('admin'), async (req: Request, res: Response) => {
  const agent = await EdrAgentModel.findById(req.params.id);
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
  const ok = await EdrAgentModel.delete(req.params.id);
  if (!ok) throw new ApiError(404, 'Agent not found');
  res.json({ deleted: true });
});

export default router;
