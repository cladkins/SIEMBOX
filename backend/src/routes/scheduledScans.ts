import { Router, Request, Response } from 'express';
import { ScheduledScanModel, ScheduledScanType } from '../models/ScheduledScan';
import { ApiError } from '../middleware/errorHandler';
import { pendingRunFor, triggerScheduledScan } from '../jobs/scheduledScans';
import { LogShipperModel } from '../models/LogShipper';
import { requireScanPermission, UserRole } from '../middleware/scanPermissions';
import { auditPublicTargetConfirmation, enforcePublicTargets } from '../services/scanner/publicTargetGuard';
import { findPublicTargets } from '../services/scanner/targetSafety';
import type { PublicTargetConfirmation } from '../services/scanner/publicTargetGuard';

// app.ts mounts this router behind `authenticate`. Listing is open to any role;
// creating, changing, deleting or running a schedule (which dispatches a scan,
// possibly to a shipper) requires admin or operator, the roles that can open the
// Scheduled Scans page. Denials are written to audit_logs.
//
// Public targets: creating a schedule, or saving one's scan_options, with a
// target in public address space needs allow_public_targets: true (a 400 names
// the targets otherwise; services/scanner/publicTargetGuard.ts). The
// confirmation is stored as scan_options.publicTargetsConfirmation. A schedule
// saved before this check keeps running as it is; the list reports its public
// targets (public_targets) so the page can badge it.
const router = Router();
const requireScheduleWrite = requireScanPermission(UserRole.Operator, 'scheduled_scan');

function validateScanOptions(scanType: ScheduledScanType, opts: any): void {
  if (!opts || typeof opts !== 'object' || Array.isArray(opts)) {
    throw new ApiError(400, 'scan_options must be an object');
  }
  if (scanType === 'asset') {
    if (!Array.isArray(opts.targets) || opts.targets.length === 0) {
      throw new ApiError(400, 'Asset scans require scan_options.targets (a non-empty array of IPs/CIDRs)');
    }
  } else if (scanType === 'container') {
    if (!opts.image_ref || typeof opts.image_ref !== 'string') {
      throw new ApiError(400, 'Container scans require scan_options.image_ref (an image reference)');
    }
  } else {
    if (!opts.target || typeof opts.target !== 'string') {
      throw new ApiError(400, 'Vulnerability scans require scan_options.target (a host/IP string)');
    }
  }

  // Optional shipper dispatch (asset/vuln only -- container scans are Trivy, no
  // LAN scan). Shape check here; existence is verified in assertShipperExists.
  if (scanType !== 'container' && opts.assignedShipperId !== undefined && opts.assignedShipperId !== null) {
    if (!Number.isInteger(opts.assignedShipperId) || opts.assignedShipperId <= 0) {
      throw new ApiError(400, 'scan_options.assignedShipperId must be a positive integer');
    }
  }
}

// Verify a chosen shipper exists at config time, so a bad id is a clean 400 now
// rather than a schedule that errors (or silently falls back) when it fires.
async function assertShipperExists(scanType: ScheduledScanType, opts: any): Promise<void> {
  if (scanType === 'container') return;
  const id = opts?.assignedShipperId;
  if (id === undefined || id === null) return;
  const shipper = await LogShipperModel.findById(id);
  if (!shipper) {
    throw new ApiError(400, `No log shipper with id ${id}`);
  }
}

/** The targets a schedule's scan_options name (none for a container scan). */
function scheduleTargets(scanType: ScheduledScanType, opts: any): string[] {
  if (scanType === 'container' || !opts) return [];
  if (scanType === 'asset') return Array.isArray(opts.targets) ? opts.targets.map(String) : [];
  return opts.target ? [String(opts.target)] : [];
}

/** scan_options as stored: the client's options with this save's confirmation, or none. */
function withConfirmation(opts: any, confirmation: PublicTargetConfirmation | null): Record<string, any> {
  // A confirmation is the server's record of this save, never the client's.
  const rest: Record<string, any> = { ...(opts || {}) };
  delete rest.publicTargetsConfirmation;
  return confirmation ? { ...rest, publicTargetsConfirmation: confirmation } : rest;
}

function validateInterval(value: any): void {
  if (!Number.isInteger(value) || value < 5) {
    throw new ApiError(400, 'interval_minutes must be an integer of at least 5');
  }
}

// GET / - list all schedules
router.get('/', async (_req: Request, res: Response) => {
  const scans = await ScheduledScanModel.findAll();
  res.json(
    scans.map((s) => ({
      ...s,
      public_targets: findPublicTargets(scheduleTargets(s.scan_type, s.scan_options)).publicTargets.map((t) => t.target),
    }))
  );
});

// POST / - create a schedule
router.post('/', requireScheduleWrite, async (req: Request, res: Response) => {
  const { name, scan_type, scan_options, interval_minutes, enabled } = req.body;

  if (!name || typeof name !== 'string') {
    throw new ApiError(400, 'name is required');
  }
  if (scan_type !== 'asset' && scan_type !== 'vulnerability' && scan_type !== 'container') {
    throw new ApiError(400, "scan_type must be 'asset', 'vulnerability', or 'container'");
  }
  validateInterval(interval_minutes);
  validateScanOptions(scan_type, scan_options);
  await assertShipperExists(scan_type, scan_options);
  const targets = scheduleTargets(scan_type, scan_options);
  const publicCheck = enforcePublicTargets(targets, req, res);
  if (!publicCheck) return;

  const created = await ScheduledScanModel.create({
    name,
    scan_type,
    scan_options: withConfirmation(scan_options, publicCheck.confirmation),
    interval_minutes,
    enabled: enabled !== false,
    created_by: (req as any).user?.id ?? null,
  });
  await auditPublicTargetConfirmation(req, publicCheck.confirmation, { type: 'scheduled_scan', id: created.id, targets });
  res.status(201).json(created);
});

// PUT /:id - update a schedule
router.put('/:id', requireScheduleWrite, async (req: Request, res: Response) => {
  const id = parseInt(req.params.id as string, 10);
  if (isNaN(id)) {
    throw new ApiError(400, 'Invalid id');
  }

  const existing = await ScheduledScanModel.findById(id);
  if (!existing) {
    throw new ApiError(404, 'Scheduled scan not found');
  }

  const { name, scan_type, scan_options, interval_minutes, enabled } = req.body;

  if (scan_type !== undefined && scan_type !== 'asset' && scan_type !== 'vulnerability' && scan_type !== 'container') {
    throw new ApiError(400, "scan_type must be 'asset', 'vulnerability', or 'container'");
  }
  if (interval_minutes !== undefined) {
    validateInterval(interval_minutes);
  }
  let storedOptions: Record<string, any> | undefined;
  let confirmation: PublicTargetConfirmation | null = null;
  let targets: string[] = [];
  if (scan_options !== undefined) {
    const effectiveType = (scan_type as ScheduledScanType) || existing.scan_type;
    validateScanOptions(effectiveType, scan_options);
    await assertShipperExists(effectiveType, scan_options);
    // Saving the options (the edit dialog) is a new decision about the
    // targets, so public ones need confirming again, even if the schedule
    // already had them. Toggling enabled or renaming alone doesn't.
    targets = scheduleTargets(effectiveType, scan_options);
    const publicCheck = enforcePublicTargets(targets, req, res);
    if (!publicCheck) return;
    confirmation = publicCheck.confirmation;
    storedOptions = withConfirmation(scan_options, confirmation);
  }

  await ScheduledScanModel.update(id, { name, scan_type, scan_options: storedOptions, interval_minutes, enabled });
  await auditPublicTargetConfirmation(req, confirmation, { type: 'scheduled_scan', id, targets });

  // Re-anchor the next run when the cadence changes or the schedule is re-enabled.
  if (interval_minutes !== undefined || enabled === true) {
    await ScheduledScanModel.resetNextRun(id);
  }

  res.json(await ScheduledScanModel.findById(id));
});

// DELETE /:id - remove a schedule
router.delete('/:id', requireScheduleWrite, async (req: Request, res: Response) => {
  const id = parseInt(req.params.id as string, 10);
  if (isNaN(id)) {
    throw new ApiError(400, 'Invalid id');
  }
  const ok = await ScheduledScanModel.delete(id);
  if (!ok) {
    throw new ApiError(404, 'Scheduled scan not found');
  }
  res.json({ message: 'Scheduled scan deleted' });
});

// POST /:id/run - trigger a schedule immediately
router.post('/:id/run', requireScheduleWrite, async (req: Request, res: Response) => {
  const id = parseInt(req.params.id as string, 10);
  if (isNaN(id)) {
    throw new ApiError(400, 'Invalid id');
  }
  const schedule = await ScheduledScanModel.findById(id);
  if (!schedule) {
    throw new ApiError(404, 'Scheduled scan not found');
  }
  // A run still waiting for its shipper isn't queued a second time.
  const pending = await pendingRunFor(schedule);
  if (pending !== null) {
    res.status(409).json({
      error: `The previous run (scan ${pending}) is still queued for its log shipper; not queuing another until the shipper picks it up or it expires.`,
      message: `The previous run (scan ${pending}) is still queued for its log shipper; not queuing another until the shipper picks it up or it expires.`,
      scanId: pending,
    });
    return;
  }
  const scanId = await triggerScheduledScan(schedule);
  await ScheduledScanModel.markRun(id, scanId);
  res.status(202).json({ message: 'Scan triggered', scanId });
});

export default router;
