import { Router, Request, Response } from 'express';
import { ScheduledScanModel, ScheduledScanType } from '../models/ScheduledScan';
import { ApiError } from '../middleware/errorHandler';
import { discoverySweep, pendingRunFor, triggerScheduledScan } from '../jobs/scheduledScans';
import { LogShipperModel } from '../models/LogShipper';
import { requireScanPermission, UserRole } from '../middleware/scanPermissions';
import { auditPublicTargetConfirmation, enforcePublicTargets } from '../services/scanner/publicTargetGuard';
import { findPublicTargets } from '../services/scanner/targetSafety';
import type { PublicTargetConfirmation } from '../services/scanner/publicTargetGuard';
import { nextRuns, normalizeCalendarSchedule, type CalendarSchedule } from '../utils/scheduleTiming';
import {
  SCHEDULED_SCAN_TYPES,
  isScheduledScanKind,
  missingInputMessage,
  missingScanInputs,
  scanOptionsShapeError,
  scheduleTargets,
} from '../services/scanner/scheduleOptions';
import { isSweepableCidr } from '../services/logDiscovery/scope';

// app.ts mounts this router behind `authenticate`. Listing is open to any role;
// creating, changing, deleting or running a schedule (which dispatches a scan,
// possibly to a shipper) requires admin or operator, the roles that can open the
// Scheduled Scans page. Denials are written to audit_logs.
//
// Scan types: asset (Nmap), vulnerability (Nuclei), container (Trivy) and
// log_discovery (a Log Discovery sweep). What scan_options each takes:
// services/scanner/scheduleOptions.ts.
//
// Incomplete schedules: a schedule added from a suggested scan
// (routes/scanSuggestions.ts) is saved disabled, without its targets. It
// cannot be enabled or run until they are filled in (a 400 names what is
// missing); saving its options from the edit dialog needs them complete.
//
// Public targets: creating a schedule, or saving one's scan_options, with a
// target in public address space needs allow_public_targets: true (a 400 names
// the targets otherwise; services/scanner/publicTargetGuard.ts). The
// confirmation is stored as scan_options.publicTargetsConfirmation. A schedule
// saved before this check keeps running as it is; the list reports its public
// targets (public_targets) so the page can badge it.
//
// Timing: a schedule either runs every interval_minutes (the original mode) or
// on a calendar `schedule` (hourly / daily / weekly / monthly wall-clock times
// in an IANA time zone; utils/scheduleTiming.ts). A request sends one of the
// two; next_run_at is recomputed whenever the timing changes or the schedule
// is re-enabled, and after every run.
const router = Router();
const requireScheduleWrite = requireScanPermission(UserRole.Operator, 'scheduled_scan');

/** A 400 for scan_options that are malformed or still missing their targets. */
function validateScanOptions(scanType: ScheduledScanType, opts: any): void {
  const shape = scanOptionsShapeError(scanType, opts);
  if (shape) throw new ApiError(400, shape);
  if (missingScanInputs(scanType, opts).length > 0) throw new ApiError(400, missingInputMessage(scanType));
  if (scanType === 'log_discovery' && Array.isArray(opts.manual_cidrs)) {
    const bad = opts.manual_cidrs.filter((c: string) => !isSweepableCidr(c));
    if (bad.length > 0) throw new ApiError(400, `scan_options.manual_cidrs: not a sweepable CIDR: ${bad.slice(0, 5).join(', ')}`);
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

/**
 * The addresses a save's public-target check covers: the targets the options
 * name; for a log discovery schedule without its own CIDRs, the saved Log
 * Discovery scope each run sweeps (as POST /api/log-discovery/scans checks).
 */
async function targetsToCheck(scanType: ScheduledScanType, opts: any): Promise<string[]> {
  return scanType === 'log_discovery' ? discoverySweep(opts) : scheduleTargets(scanType, opts);
}

/** A 400 when the schedule cannot be enabled or run yet: an input is still to be filled in. */
function assertComplete(schedule: { scan_type: ScheduledScanType; scan_options: any }, action: string): void {
  const missing = missingScanInputs(schedule.scan_type, schedule.scan_options);
  if (missing.length > 0) {
    throw new ApiError(400, `Fill in ${missing.join(', ')} (Edit) before ${action} this schedule`);
  }
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
    throw new ApiError(400, 'interval_minutes must be an integer of at least 5 (or send a calendar schedule instead)');
  }
}

function parseSchedule(value: unknown): CalendarSchedule {
  try {
    return normalizeCalendarSchedule(value);
  } catch (error) {
    throw new ApiError(400, error instanceof Error ? error.message : 'Invalid schedule');
  }
}

const present = (v: unknown) => v !== undefined && v !== null;

/**
 * The timing a create or a full preview names: a calendar schedule, or a fixed
 * interval. Exactly one must be sent.
 */
function parseTiming(body: { schedule?: unknown; interval_minutes?: unknown } | undefined): { schedule: CalendarSchedule | null; interval_minutes: number | null } {
  if (present(body?.schedule)) {
    if (present(body?.interval_minutes)) {
      throw new ApiError(400, 'Send either schedule (calendar timing) or interval_minutes (fixed interval), not both');
    }
    return { schedule: parseSchedule(body.schedule), interval_minutes: null };
  }
  validateInterval(body?.interval_minutes);
  return { schedule: null, interval_minutes: body!.interval_minutes as number };
}

// GET / - list all schedules
router.get('/', async (_req: Request, res: Response) => {
  const scans = await ScheduledScanModel.findAll();
  res.json(
    scans.map((s) => ({
      ...s,
      public_targets: findPublicTargets(scheduleTargets(s.scan_type, s.scan_options)).publicTargets.map((t) => t.target),
      missing_inputs: missingScanInputs(s.scan_type, s.scan_options),
    }))
  );
});

// POST /preview - the next runs a timing would produce (the form's live preview).
// Writes nothing; gated like the writes because only the edit dialog uses it.
router.post('/preview', requireScheduleWrite, async (req: Request, res: Response) => {
  const timing = parseTiming(req.body);
  const count = req.body?.count ?? 3;
  if (!Number.isInteger(count) || count < 1 || count > 10) {
    throw new ApiError(400, 'count must be an integer from 1 to 10');
  }
  const now = new Date();
  const runs = timing.schedule
    ? nextRuns(timing.schedule, now, count)
    : Array.from({ length: count }, (_, i) => new Date(now.getTime() + (i + 1) * timing.interval_minutes! * 60_000));
  res.json({ ...timing, next_runs: runs.map((d) => d.toISOString()) });
});

// POST / - create a schedule
router.post('/', requireScheduleWrite, async (req: Request, res: Response) => {
  const { name, scan_type, scan_options, enabled } = req.body;

  if (!name || typeof name !== 'string') {
    throw new ApiError(400, 'name is required');
  }
  if (!isScheduledScanKind(scan_type)) {
    throw new ApiError(400, `scan_type must be one of: ${SCHEDULED_SCAN_TYPES.join(', ')}`);
  }
  const timing = parseTiming(req.body);
  validateScanOptions(scan_type, scan_options);
  await assertShipperExists(scan_type, scan_options);
  const targets = await targetsToCheck(scan_type, scan_options);
  const publicCheck = enforcePublicTargets(targets, req, res);
  if (!publicCheck) return;

  const created = await ScheduledScanModel.create({
    name,
    scan_type,
    scan_options: withConfirmation(scan_options, publicCheck.confirmation),
    interval_minutes: timing.interval_minutes,
    schedule: timing.schedule,
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

  const { name, scan_type, scan_options, enabled } = req.body;

  if (scan_type !== undefined && !isScheduledScanKind(scan_type)) {
    throw new ApiError(400, `scan_type must be one of: ${SCHEDULED_SCAN_TYPES.join(', ')}`);
  }

  // Timing, if this save changes it. A calendar `schedule` replaces any
  // interval; `interval_minutes` (with schedule absent or null) switches to, or
  // stays in, the fixed-interval mode; `schedule: null` alone switches back to
  // the schedule's stored interval, if it has one.
  let timing: { schedule: CalendarSchedule | null; interval_minutes: number | null } | undefined;
  if (present(req.body.schedule)) {
    timing = parseTiming(req.body);
  } else if (present(req.body.interval_minutes)) {
    validateInterval(req.body.interval_minutes);
    timing = { schedule: null, interval_minutes: req.body.interval_minutes };
  } else if (req.body.schedule === null) {
    if (existing.interval_minutes == null) {
      throw new ApiError(400, 'This schedule has no interval to return to: send interval_minutes along with schedule: null');
    }
    timing = { schedule: null, interval_minutes: existing.interval_minutes };
  } else if (req.body.interval_minutes === null) {
    throw new ApiError(400, 'interval_minutes must be an integer of at least 5 (or send a calendar schedule instead)');
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
    targets = await targetsToCheck(effectiveType, scan_options);
    const publicCheck = enforcePublicTargets(targets, req, res);
    if (!publicCheck) return;
    confirmation = publicCheck.confirmation;
    storedOptions = withConfirmation(scan_options, confirmation);
  }

  // Enabling needs the targets in place (a suggestion is added without them).
  const effectiveEnabled = enabled === undefined ? existing.enabled : enabled === true;
  if (effectiveEnabled) {
    assertComplete(
      { scan_type: (scan_type as ScheduledScanType) || existing.scan_type, scan_options: scan_options ?? existing.scan_options },
      enabled === true && !existing.enabled ? 'enabling' : 'saving'
    );
  }

  await ScheduledScanModel.update(id, {
    name,
    scan_type,
    scan_options: storedOptions,
    interval_minutes: timing?.interval_minutes,
    schedule: timing?.schedule,
    enabled,
  });
  await auditPublicTargetConfirmation(req, confirmation, { type: 'scheduled_scan', id, targets });

  // Re-anchor the next run when the timing changes or the schedule is re-enabled.
  if (timing !== undefined || enabled === true) {
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
  assertComplete(schedule, 'running');
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
