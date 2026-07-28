import { Router, Request, Response } from 'express';
import { ApiError } from '../middleware/errorHandler';
import { DiscoveryScanModel } from '../models/DiscoveryScan';
import { DiscoverySourceModel } from '../models/DiscoverySource';
import { resolveScope, detectLocalInterfaces } from '../services/logDiscovery/scope';
import { runScan, requestCancel, getRankedSources, buildOnboardPreview } from '../services/logDiscovery/discoveryScanService';
import { loadFingerprintLibrary } from '../services/logDiscovery/fingerprintLoader';

const router = Router();

function parseSourceId(req: Request): number {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) throw new ApiError(400, 'Invalid source id');
  return id;
}

// GET /scope - preview of auto-detected CIDRs + the single-VLAN warning, plus a
// dry-run merge if the caller wants to preview manual CIDRs before scanning.
router.get('/scope', (req: Request, res: Response) => {
  const manualCidrs = typeof req.query.manual_cidrs === 'string' && req.query.manual_cidrs.length > 0
    ? req.query.manual_cidrs.split(',').map((c) => c.trim())
    : [];
  const scope = resolveScope(manualCidrs, detectLocalInterfaces());
  res.json({
    cidrs: scope.cidrs,
    vlan_warning: scope.warning,
    rejected_cidrs: scope.rejected,
  });
});

// GET /fingerprints - the loaded fingerprint library (read-only, for the UI to explain matches)
router.get('/fingerprints', (_req: Request, res: Response) => {
  res.json(loadFingerprintLibrary());
});

// POST /scans - trigger a scan (mode: passive | active | full). Runs asynchronously; returns the job id.
router.post('/scans', async (req: Request, res: Response) => {
  const { mode = 'full', manual_cidrs } = req.body || {};
  if (!['passive', 'active', 'full'].includes(mode)) {
    throw new ApiError(400, "mode must be 'passive', 'active', or 'full'");
  }
  if (manual_cidrs !== undefined && !Array.isArray(manual_cidrs)) {
    throw new ApiError(400, 'manual_cidrs must be an array of CIDR strings');
  }

  const result = await runScan({ mode, manualCidrs: manual_cidrs, createdBy: req.user?.id ?? null });
  res.status(202).json({
    scan_id: result.scanId,
    cidrs: result.cidrs,
    vlan_warning: result.vlanWarning,
    rejected_cidrs: result.rejectedCidrs,
  });
});

// GET /scans - recent scan jobs
router.get('/scans', async (_req: Request, res: Response) => {
  res.json(await DiscoveryScanModel.findAll());
});

// GET /scans/:id - one scan job's status
router.get('/scans/:id', async (req: Request, res: Response) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) throw new ApiError(400, 'Invalid scan id');
  const scan = await DiscoveryScanModel.findById(id);
  if (!scan) throw new ApiError(404, 'Scan not found');
  res.json(scan);
});

// POST /scans/:id/cancel - stop a running scan. Also the remedy for a scan row
// orphaned 'running' by a previous process (no in-memory worker): the status
// still flips to failed, it just has nothing to interrupt.
router.post('/scans/:id/cancel', async (req: Request, res: Response) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) throw new ApiError(400, 'Invalid scan id');
  const scan = await DiscoveryScanModel.findById(id);
  if (!scan) throw new ApiError(404, 'Scan not found');
  if (scan.status !== 'running') {
    res.json({ cancelled: false, scan });
    return;
  }

  const hadWorker = requestCancel(id);
  await DiscoveryScanModel.fail(id, hadWorker ? 'Cancelled by user' : 'Cancelled by user (orphaned run — no active worker)');
  res.json({ cancelled: true, scan: await DiscoveryScanModel.findById(id) });
});

// GET /sources - ranked discovery results: { top, advanced }
router.get('/sources', async (_req: Request, res: Response) => {
  res.json(await getRankedSources());
});

// POST /sources/:id/confirm - user confirms a candidate is what the matcher thinks it is
router.post('/sources/:id/confirm', async (req: Request, res: Response) => {
  const id = parseSourceId(req);
  const updated = await DiscoverySourceModel.setStatus(id, 'confirmed');
  if (!updated) throw new ApiError(404, 'Discovery source not found');
  res.json(updated);
});

// POST /sources/:id/ignore - dismiss a candidate; it will not resurface in the ranked list
router.post('/sources/:id/ignore', async (req: Request, res: Response) => {
  const id = parseSourceId(req);
  const updated = await DiscoverySourceModel.setStatus(id, 'ignored');
  if (!updated) throw new ApiError(404, 'Discovery source not found');
  res.json(updated);
});

// POST /sources/:id/onboard/preview - render the copy-paste onboarding block. Read-only; does not change status.
router.post('/sources/:id/onboard/preview', async (req: Request, res: Response) => {
  const id = parseSourceId(req);
  const methodIndex = Number.isInteger(req.body?.method_index) ? req.body.method_index : 0;
  try {
    const preview = await buildOnboardPreview(id, methodIndex);
    res.json(preview);
  } catch (err: any) {
    throw new ApiError(404, err?.message || 'Unable to build onboarding preview');
  }
});

// POST /sources/:id/onboard/confirm - manual mode only: record the chosen log_access method and
// mark the source onboarded. Requires an explicit confirm:true -- never onboard without it.
router.post('/sources/:id/onboard/confirm', async (req: Request, res: Response) => {
  const id = parseSourceId(req);
  if (req.body?.confirm !== true) {
    throw new ApiError(400, 'Set confirm:true to acknowledge you have applied the onboarding instructions');
  }
  const methodIndex = Number.isInteger(req.body?.method_index) ? req.body.method_index : 0;

  let preview;
  try {
    preview = await buildOnboardPreview(id, methodIndex);
  } catch (err: any) {
    throw new ApiError(404, err?.message || 'Unable to onboard this source');
  }

  await DiscoverySourceModel.setSelectedLogAccess(id, preview.log_access);
  const updated = await DiscoverySourceModel.setStatus(id, 'onboarded');
  res.json({ source: updated, instructions: preview.instructions });
});

export default router;
