import net from 'net';
import { Router, Request, Response } from 'express';
import { ApiError } from '../middleware/errorHandler';
import { authorize } from '../middleware/auth';
import { DiscoveryScanModel } from '../models/DiscoveryScan';
import { DiscoverySourceModel, DiscoverySourceManualInput } from '../models/DiscoverySource';
import { LogShipperModel } from '../models/LogShipper';
import { DiscoverySourcePollerModel } from '../models/DiscoverySourcePoller';
import { resolveScope, detectLocalInterfaces, isValidCidr, isSweepableCidr } from '../services/logDiscovery/scope';
import {
  runScan,
  requestCancel,
  getRankedSources,
  buildOnboardPreview,
  getPersistedScopeCidrs,
  savePersistedScopeCidrs,
} from '../services/logDiscovery/discoveryScanService';
import { loadFingerprintLibrary, getFingerprintById } from '../services/logDiscovery/fingerprintLoader';
import { listPollableFingerprintIds } from '../services/logDiscovery/apiPoll/registry';
import { pollOneSource } from '../services/logDiscovery/apiPoll/poller';

const router = Router();

function parseSourceId(req: Request): number {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) throw new ApiError(400, 'Invalid source id');
  return id;
}

export type ManualSourceValidation =
  | { ok: true; value: DiscoverySourceManualInput }
  | { ok: false; status: number; message: string };

/**
 * Validate + normalize the body of POST /sources/manual. Pure (no DB), so it's
 * unit-testable on its own. Rejects a DNS name for ip_address up front — INET is
 * NOT NULL and casting a hostname would surface as a 500, not a clean 400. The
 * fingerprint checks mirror POST /sources/:id/poller/credential exactly: the id
 * must have a real poll adapter AND an api_pull log_access entry.
 */
export function validateManualSourceInput(body: unknown): ManualSourceValidation {
  const b = (body ?? {}) as Record<string, unknown>;

  const ipRaw = typeof b.ip_address === 'string' ? b.ip_address.trim() : '';
  if (!ipRaw || net.isIP(ipRaw) === 0) {
    return { ok: false, status: 400, message: 'ip_address must be a literal IPv4 or IPv6 address (not a DNS name)' };
  }

  const pollable = listPollableFingerprintIds();
  const fingerprintId = typeof b.fingerprint_id === 'string' ? b.fingerprint_id : '';
  if (!fingerprintId || !pollable.includes(fingerprintId)) {
    return { ok: false, status: 400, message: `fingerprint_id must be a pollable device type (one of: ${pollable.join(', ')})` };
  }
  const fingerprint = getFingerprintById(fingerprintId);
  if (!fingerprint) {
    return { ok: false, status: 404, message: `Fingerprint "${fingerprintId}" is no longer in the library` };
  }
  const logAccess = fingerprint.log_access.find((la) => la.method === 'api_pull');
  if (!logAccess) {
    return { ok: false, status: 400, message: `${fingerprint.name} has no api_pull log access method` };
  }

  // port: an explicit 1-65535 integer, else the fingerprint's api_pull target_port.
  let target_port: number;
  if (b.port === undefined || b.port === null) {
    target_port = typeof logAccess.target_port === 'number' ? logAccess.target_port : NaN;
    if (!Number.isInteger(target_port) || target_port < 1 || target_port > 65535) {
      return { ok: false, status: 400, message: 'port is required (this fingerprint declares no default api_pull target_port)' };
    }
  } else if (typeof b.port === 'number' && Number.isInteger(b.port) && b.port >= 1 && b.port <= 65535) {
    target_port = b.port;
  } else {
    return { ok: false, status: 400, message: 'port must be an integer between 1 and 65535' };
  }

  // tls: explicit boolean, else default true for authentik (https:9443) / false elsewhere.
  let tls: boolean;
  if (b.tls === undefined || b.tls === null) {
    tls = fingerprintId === 'authentik';
  } else if (typeof b.tls === 'boolean') {
    tls = b.tls;
  } else {
    return { ok: false, status: 400, message: 'tls must be a boolean' };
  }

  const hostname = typeof b.hostname === 'string' && b.hostname.trim().length > 0 ? b.hostname.trim() : null;

  return {
    ok: true,
    value: {
      ip_address: ipRaw,
      hostname,
      fingerprint_id: fingerprintId,
      target_port,
      tls,
      security_value: fingerprint.security_value ?? null,
    },
  };
}

// GET /scope - preview of the scan scope + the single-VLAN warning. Shows the
// persisted standing scope by default, unioned with any ad-hoc manual CIDRs the
// caller wants to preview before scanning (e.g. while editing the subnet list).
router.get('/scope', async (req: Request, res: Response) => {
  const adHocCidrs = typeof req.query.manual_cidrs === 'string' && req.query.manual_cidrs.length > 0
    ? req.query.manual_cidrs.split(',').map((c) => c.trim())
    : [];
  const persisted = await getPersistedScopeCidrs();
  const scope = resolveScope([...persisted, ...adHocCidrs], detectLocalInterfaces());
  res.json({
    cidrs: scope.cidrs,
    vlan_warning: scope.warning,
    rejected_cidrs: scope.rejected,
    detected_lan_cidr: scope.detectedLanCidr,
  });
});

// GET /scope/cidrs - the persisted standing scan-scope CIDRs (server-side,
// shared across admins/devices). This is what the page loads on mount so an
// added subnet survives leaving the page.
router.get('/scope/cidrs', async (_req: Request, res: Response) => {
  res.json({ cidrs: await getPersistedScopeCidrs() });
});

// PUT /scope/cidrs - replace the persisted standing scan scope. Each CIDR is
// validated (well-formed AND /22-or-smaller so the sweep stays bounded);
// accepted ones are upserted, rejected ones are reported back rather than
// silently dropped. Admin-gated like the other mutating log-discovery routes.
router.put('/scope/cidrs', authorize('admin'), async (req: Request, res: Response) => {
  const { cidrs } = req.body || {};
  if (!Array.isArray(cidrs) || !cidrs.every((c) => typeof c === 'string')) {
    throw new ApiError(400, 'cidrs must be an array of CIDR strings');
  }
  const trimmed = cidrs.map((c) => c.trim()).filter(Boolean);
  const accepted = Array.from(new Set(trimmed.filter((c) => isValidCidr(c) && isSweepableCidr(c))));
  const rejected = trimmed.filter((c) => !(isValidCidr(c) && isSweepableCidr(c)));
  await savePersistedScopeCidrs(accepted);
  res.json({ cidrs: accepted, rejected });
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

  // Optional: run this discovery scan from a log shipper out on the LAN (the
  // backend can't probe the LAN from inside Docker). When set, the shipper must
  // exist -- otherwise the scan would queue forever with no one to claim it.
  const rawShipperId = req.body?.assignedShipperId ?? req.body?.assigned_shipper_id;
  let assignedShipperId: number | undefined;
  if (rawShipperId !== undefined && rawShipperId !== null && rawShipperId !== '') {
    assignedShipperId = Number(rawShipperId);
    if (!Number.isInteger(assignedShipperId) || assignedShipperId <= 0) {
      throw new ApiError(400, 'assignedShipperId must be a positive integer');
    }
    const shipper = await LogShipperModel.findById(assignedShipperId);
    if (!shipper) {
      throw new ApiError(400, `No log shipper with id ${assignedShipperId}`);
    }
  }

  const result = await runScan({ mode, manualCidrs: manual_cidrs, createdBy: req.user?.id ?? null, assignedShipperId });
  res.status(202).json({
    scan_id: result.scanId,
    cidrs: result.cidrs,
    vlan_warning: result.vlanWarning,
    rejected_cidrs: result.rejectedCidrs,
    assigned_shipper_id: assignedShipperId ?? null,
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

// POST /scans/:id/cancel - stop a running scan. Also the remedy for two stuck
// states: a scan row orphaned 'running' by a previous process (no in-memory
// worker), and a shipper-dispatched scan stuck 'queued' because its shipper
// never came back to claim it. In every case the status flips to failed; there
// may just be nothing to interrupt.
router.post('/scans/:id/cancel', async (req: Request, res: Response) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) throw new ApiError(400, 'Invalid scan id');
  const scan = await DiscoveryScanModel.findById(id);
  if (!scan) throw new ApiError(404, 'Scan not found');
  if (scan.status !== 'running' && scan.status !== 'queued') {
    res.json({ cancelled: false, scan });
    return;
  }

  // Only a 'running' scan can have a worker in this process to interrupt; a
  // 'queued' one has never started, so skip the cancel flag (and its cleanup).
  const hadWorker = scan.status === 'running' ? requestCancel(id) : false;
  const reason =
    scan.status === 'queued'
      ? 'Cancelled by user before the shipper claimed it'
      : hadWorker
        ? 'Cancelled by user'
        : 'Cancelled by user (orphaned run — no active worker)';
  const cancelled = await DiscoveryScanModel.cancel(id, reason);
  res.json({ cancelled, scan: await DiscoveryScanModel.findById(id) });
});

// GET /sources - ranked discovery results: { top, advanced }
router.get('/sources', async (_req: Request, res: Response) => {
  res.json(await getRankedSources());
});

// POST /sources/manual - admin manually adds an api_pull source for a device they
// already know about (device type + IP + port + scheme), without waiting for a scan
// to discover and fingerprint it. Creates a scan-less, 'confirmed' discovery_sources
// row (its port/scheme stored in evidence); the credential + polling are then saved
// through the SAME existing poller routes the Onboard dialog uses. Admin-gated like
// the other mutating log-discovery routes. Defined before the "/sources/:id/*"
// routes so "manual" is never parsed as an id.
router.post('/sources/manual', authorize('admin'), async (req: Request, res: Response) => {
  const parsed = validateManualSourceInput(req.body);
  if (!parsed.ok) throw new ApiError(parsed.status, parsed.message);
  const source = await DiscoverySourceModel.upsertManual(parsed.value);
  res.status(201).json(source);
});

// DELETE /sources/:id - delete a MANUALLY added source (the poller row cascades via
// its ON DELETE CASCADE FK). Scoped to manual rows on purpose: a scan-discovered
// source is removed by re-scanning or ignoring it, not deleted here, so this won't
// let an admin wipe scan history. 404 if missing, 403 if it isn't a manual row.
router.delete('/sources/:id', authorize('admin'), async (req: Request, res: Response) => {
  const id = parseSourceId(req);
  const source = await DiscoverySourceModel.findById(id);
  if (!source) throw new ApiError(404, 'Discovery source not found');
  if ((source.evidence as Record<string, unknown> | null)?.manual !== true) {
    throw new ApiError(403, 'Only manually added sources can be deleted here');
  }
  await DiscoverySourceModel.deleteById(id);
  res.json({ deleted: true });
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

// GET /poller/supported-fingerprints - which fingerprint ids have a real poll
// adapter, so the frontend doesn't have to hardcode that list.
router.get('/poller/supported-fingerprints', (_req: Request, res: Response) => {
  res.json(listPollableFingerprintIds());
});

// GET /sources/:id/poller - poller status for a source (never includes the
// credential itself; { configured: false } when none has been saved).
router.get('/sources/:id/poller', async (req: Request, res: Response) => {
  const id = parseSourceId(req);
  const row = await DiscoverySourcePollerModel.findById(id);
  res.json(row ? DiscoverySourcePollerModel.toPublic(row) : { configured: false });
});

// POST /sources/:id/poller/credential - save (or replace) the token/credential
// for this source's api_pull method and start polling it. Admin-gated, same as
// shippers.ts's HTTP-push-key routes and threatFeeds.ts's reputation-provider
// routes -- the two existing "user pastes a secret" precedents in this codebase.
router.post('/sources/:id/poller/credential', authorize('admin'), async (req: Request, res: Response) => {
  const id = parseSourceId(req);
  const { username, secret } = req.body || {};
  if (typeof secret !== 'string' || secret.trim().length === 0) {
    throw new ApiError(400, 'secret is required');
  }

  const source = await DiscoverySourceModel.findById(id);
  if (!source) throw new ApiError(404, 'Discovery source not found');
  if (!source.matched_fingerprint_id) throw new ApiError(400, 'This source has no matched fingerprint to poll');

  const fingerprint = getFingerprintById(source.matched_fingerprint_id);
  if (!fingerprint) throw new ApiError(404, `Fingerprint "${source.matched_fingerprint_id}" is no longer in the library`);

  // Resolve the api_pull entry explicitly rather than log_access[0] -- most
  // fingerprints list a file/syslog method first.
  const logAccess = fingerprint.log_access.find((la) => la.method === 'api_pull');
  if (!logAccess) throw new ApiError(400, `${fingerprint.name} has no api_pull log access method`);

  const row = await DiscoverySourcePollerModel.upsertCredential(id, {
    fingerprintId: fingerprint.id,
    method: logAccess.method,
    username: typeof username === 'string' && username.length > 0 ? username : null,
    secret,
  });

  // Matches the outcome of the manual onboard/confirm flow, so a source
  // doesn't sit in two different "half-done" states depending on which path
  // (manual copy-paste vs. saving a poll credential) was used.
  await DiscoverySourceModel.setSelectedLogAccess(id, logAccess);
  await DiscoverySourceModel.setStatus(id, 'onboarded');

  res.json(DiscoverySourcePollerModel.toPublic(row));
});

// DELETE /sources/:id/poller/credential - full revoke: stops polling and
// forgets the credential, interval, and cursor (not just the secret).
router.delete('/sources/:id/poller/credential', authorize('admin'), async (req: Request, res: Response) => {
  const id = parseSourceId(req);
  const cleared = await DiscoverySourcePollerModel.clear(id);
  res.json({ cleared });
});

// PATCH /sources/:id/poller - toggle enabled and/or change the poll interval.
router.patch('/sources/:id/poller', authorize('admin'), async (req: Request, res: Response) => {
  const id = parseSourceId(req);
  const { enabled, poll_interval_minutes } = req.body || {};

  let row = await DiscoverySourcePollerModel.findById(id);
  if (!row) throw new ApiError(404, 'No poller configured for this source — save a credential first');

  if (typeof enabled === 'boolean') {
    row = await DiscoverySourcePollerModel.setEnabled(id, enabled);
  }
  if (poll_interval_minutes !== undefined) {
    if (typeof poll_interval_minutes !== 'number' || !Number.isFinite(poll_interval_minutes)) {
      throw new ApiError(400, 'poll_interval_minutes must be a number');
    }
    row = await DiscoverySourcePollerModel.setInterval(id, poll_interval_minutes);
  }

  res.json(DiscoverySourcePollerModel.toPublic(row!));
});

// POST /sources/:id/poller/run-now - poll immediately instead of waiting for
// the next scheduled cycle, for UI feedback right after saving a credential.
router.post('/sources/:id/poller/run-now', authorize('admin'), async (req: Request, res: Response) => {
  const id = parseSourceId(req);
  const row = await DiscoverySourcePollerModel.findById(id);
  if (!row) throw new ApiError(404, 'No poller configured for this source — save a credential first');
  const result = await pollOneSource(row);
  res.json(result);
});

export default router;
