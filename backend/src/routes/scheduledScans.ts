import { Router, Request, Response } from 'express';
import { ScheduledScanModel, ScheduledScanType } from '../models/ScheduledScan';
import { ApiError } from '../middleware/errorHandler';
import { triggerScheduledScan } from '../jobs/scheduledScans';

const router = Router();

function validateScanOptions(scanType: ScheduledScanType, opts: any): void {
  if (!opts || typeof opts !== 'object' || Array.isArray(opts)) {
    throw new ApiError(400, 'scan_options must be an object');
  }
  if (scanType === 'asset') {
    if (!Array.isArray(opts.targets) || opts.targets.length === 0) {
      throw new ApiError(400, 'Asset scans require scan_options.targets (a non-empty array of IPs/CIDRs)');
    }
  } else {
    if (!opts.target || typeof opts.target !== 'string') {
      throw new ApiError(400, 'Vulnerability scans require scan_options.target (a host/IP string)');
    }
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
  if (scan_type !== 'asset' && scan_type !== 'vulnerability') {
    throw new ApiError(400, "scan_type must be 'asset' or 'vulnerability'");
  }
  validateInterval(interval_minutes);
  validateScanOptions(scan_type, scan_options);

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

  if (scan_type !== undefined && scan_type !== 'asset' && scan_type !== 'vulnerability') {
    throw new ApiError(400, "scan_type must be 'asset' or 'vulnerability'");
  }
  if (interval_minutes !== undefined) {
    validateInterval(interval_minutes);
  }
  if (scan_options !== undefined) {
    validateScanOptions((scan_type as ScheduledScanType) || existing.scan_type, scan_options);
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
