import { Router, Request, Response } from 'express';
import { ScheduledScanModel, ScheduledScanType } from '../models/ScheduledScan';
import { ApiError } from '../middleware/errorHandler';
import { triggerScheduledScan } from '../jobs/scheduledScans';
import { LogShipperModel } from '../models/LogShipper';

const router = Router();

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

function validateInterval(value: any): void {
  if (!Number.isInteger(value) || value < 5) {
    throw new ApiError(400, 'interval_minutes must be an integer of at least 5');
  }
}

// GET / - list all schedules
router.get('/', async (_req: Request, res: Response) => {
  const scans = await ScheduledScanModel.findAll();
  res.json(scans);
});

// POST / - create a schedule
router.post('/', async (req: Request, res: Response) => {
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

  const created = await ScheduledScanModel.create({
    name,
    scan_type,
    scan_options,
    interval_minutes,
    enabled: enabled !== false,
    created_by: (req as any).user?.id ?? null,
  });
  res.status(201).json(created);
});

// PUT /:id - update a schedule
router.put('/:id', async (req: Request, res: Response) => {
  const id = parseInt(req.params.id, 10);
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
  if (scan_options !== undefined) {
    const effectiveType = (scan_type as ScheduledScanType) || existing.scan_type;
    validateScanOptions(effectiveType, scan_options);
    await assertShipperExists(effectiveType, scan_options);
  }

  await ScheduledScanModel.update(id, { name, scan_type, scan_options, interval_minutes, enabled });

  // Re-anchor the next run when the cadence changes or the schedule is re-enabled.
  if (interval_minutes !== undefined || enabled === true) {
    await ScheduledScanModel.resetNextRun(id);
  }

  res.json(await ScheduledScanModel.findById(id));
});

// DELETE /:id - remove a schedule
router.delete('/:id', async (req: Request, res: Response) => {
  const id = parseInt(req.params.id, 10);
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
router.post('/:id/run', async (req: Request, res: Response) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) {
    throw new ApiError(400, 'Invalid id');
  }
  const schedule = await ScheduledScanModel.findById(id);
  if (!schedule) {
    throw new ApiError(404, 'Scheduled scan not found');
  }
  const scanId = await triggerScheduledScan(schedule);
  await ScheduledScanModel.markRun(id, scanId);
  res.status(202).json({ message: 'Scan triggered', scanId });
});

export default router;
