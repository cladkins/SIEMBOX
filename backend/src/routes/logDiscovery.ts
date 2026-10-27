import net from 'net';
import { Router, Request, Response } from 'express';
import { ApiError } from '../middleware/errorHandler';
import { authorize, requireOperator } from '../middleware/auth';
import { requireScanPermission, UserRole } from '../middleware/scanPermissions';
import { DiscoveryScanModel } from '../models/DiscoveryScan';
import {
  DiscoverySource,
  DiscoverySourceModel,
  DiscoverySourceManualInput,
  ReplacementCredential,
  UNIQUE_VIOLATION,
} from '../models/DiscoverySource';
import { CredentialEncryption } from '../services/credentials/credentialEncryption';
import { LogShipperModel } from '../models/LogShipper';
import { DiscoverySourcePoller, DiscoverySourcePollerModel } from '../models/DiscoverySourcePoller';
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
import { auditPublicTargetConfirmation, enforcePublicTargets } from '../services/scanner/publicTargetGuard';
import { LogAccessMethod } from '../services/logDiscovery/types';
import { listPollableFingerprintIds } from '../services/logDiscovery/apiPoll/registry';
import { pollOneSource } from '../services/logDiscovery/apiPoll/poller';
import {
  describePollTarget,
  isManualSource,
  readTargetOverrides,
  resolveApiPull,
  validateEndpointPath,
} from '../services/logDiscovery/apiPoll/pollTarget';

// Access: app.ts mounts this router behind `authenticate`; the UI's Log
// Discovery page is limited to admins and operators. Reads are open to any role.
// Starting or cancelling a scan (which may dispatch it to a shipper) and
// triaging a discovered source (confirm, ignore, mark onboarded) require admin or
// operator; scan denials are written to audit_logs. Changing the scan scope,
// manual sources, poll targets and poll credentials stays admin-only
// (authorize('admin')).
const router = Router();
const requireDiscoveryScan = requireScanPermission(UserRole.Operator, 'discovery_scan');

function parseSourceId(req: Request): number {
  const id = parseInt(req.params.id as string, 10);
  if (!Number.isInteger(id)) throw new ApiError(400, 'Invalid source id');
  return id;
}

const IP_ADDRESS_MESSAGE = 'ip_address must be a literal IPv4 or IPv6 address (not a DNS name)';
const EXPECTED_IP_ADDRESS_MESSAGE =
  "expected_ip_address must be a literal IPv4 or IPv6 address: the source's address as you loaded it";

export const SOURCE_CHANGED_MESSAGE =
  'This source changed while it was being edited (its address, its connection settings or its saved token): nothing was saved. Reload it and try again.';

export const TOKEN_ADDRESS_CHANGED_MESSAGE =
  'The source is no longer at the address this token was entered for (its address was changed in the meantime): the token was not saved. Reload the source, check its address and enter the token again.';

/**
 * A manual source's address, shared by POST /sources/manual and PATCH
 * /sources/:id so both validate it the same way: a literal IPv4/IPv6 address,
 * trimmed. A DNS name is rejected up front — INET is NOT NULL and casting a
 * hostname would surface as a 500, not a clean 400 — and so is an IPv6 zone
 * index ("fe80::1%eth0"), which net.isIP accepts but INET does not. Null when
 * invalid.
 */
function parseLiteralIp(raw: unknown): string | null {
  const ip = typeof raw === 'string' ? raw.trim() : '';
  if (!ip || net.isIP(ip) === 0 || ip.includes('%')) return null;
  return ip;
}

/** Compare two literal addresses, ignoring how an IPv6 address is written. */
function sameAddress(a: string, b: string): boolean {
  const canonical = (ip: string) => {
    if (!net.isIPv6(ip)) return ip;
    try {
      return new URL(`http://[${ip}]`).hostname.slice(1, -1);
    } catch {
      return ip.toLowerCase();
    }
  };
  return canonical(a) === canonical(b);
}

/**
 * An optional expected_ip_address (the source's address as the client loaded
 * it, so a change made from a stale view is refused): undefined when absent,
 * null when malformed.
 */
function parseExpectedAddress(raw: unknown): string | null | undefined {
  if (raw === undefined || raw === null) return undefined;
  return parseLiteralIp(raw);
}

function isPort(v: unknown): v is number {
  return typeof v === 'number' && Number.isInteger(v) && v >= 1 && v <= 65535;
}

/**
 * A manual source's port and scheme when none is given: the fingerprint's
 * api_pull target_port (null when it declares none), and https for authentik
 * (served on 9443/TLS) only.
 */
function manualSourceDefaults(fingerprintId: string, logAccess: LogAccessMethod): { port: number | null; tls: boolean } {
  return { port: isPort(logAccess.target_port) ? logAccess.target_port : null, tls: fingerprintId === 'authentik' };
}

export type ManualSourceValidation =
  | { ok: true; value: DiscoverySourceManualInput }
  | { ok: false; status: number; message: string };

/**
 * Validate + normalize the body of POST /sources/manual. Pure (no DB), so it's
 * unit-testable on its own. The address must be a literal IP (parseLiteralIp).
 * The fingerprint checks mirror POST /sources/:id/poller/credential exactly: the
 * id must have a real poll adapter AND an api_pull log_access entry.
 */
export function validateManualSourceInput(body: unknown): ManualSourceValidation {
  const b = (body ?? {}) as Record<string, unknown>;

  const ipRaw = parseLiteralIp(b.ip_address);
  if (!ipRaw) {
    return { ok: false, status: 400, message: IP_ADDRESS_MESSAGE };
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

  const defaults = manualSourceDefaults(fingerprintId, logAccess);

  // port: an explicit 1-65535 integer, else the fingerprint's api_pull target_port.
  let target_port: number;
  if (b.port === undefined || b.port === null) {
    if (defaults.port === null) {
      return { ok: false, status: 400, message: 'port is required (this fingerprint declares no default api_pull target_port)' };
    }
    target_port = defaults.port;
  } else if (isPort(b.port)) {
    target_port = b.port;
  } else {
    return { ok: false, status: 400, message: 'port must be an integer between 1 and 65535' };
  }

  // tls: explicit boolean, else default true for authentik (https:9443) / false elsewhere.
  let tls: boolean;
  if (b.tls === undefined || b.tls === null) {
    tls = defaults.tls;
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

/**
 * A validated PATCH /sources/:id body. Absent fields stay as they are; null
 * returns a setting to its default (the fingerprint's endpoint, the adapter's
 * port/scheme, or for a manual source the same defaults POST /sources/manual
 * uses).
 */
export interface SourceTargetUpdate {
  /** Only ever set for a manual source, and only when it differs from the current address. */
  ip_address?: string;
  port?: number | null;
  tls?: boolean | null;
  endpoint?: string | null;
}

export type SourceTargetValidation =
  | { ok: true; value: SourceTargetUpdate }
  | { ok: false; status: number; message: string };

const TARGET_FIELDS = ['ip_address', 'port', 'tls', 'endpoint'] as const;

/**
 * Validate + normalize the body of PATCH /sources/:id. Pure (no DB). `manual`
 * and `currentIp` describe the source being edited: only a manually added
 * source's address can change (403 otherwise — a scan-discovered source is
 * always polled at the address the scan found), and a new address is validated
 * exactly like POST /sources/manual's. Sending the current address back is
 * accepted for any source and changes nothing. An expected_ip_address that is
 * not the current address means the client edited a view of the source from
 * before it moved: 409.
 */
export function validateSourceTargetUpdate(
  body: unknown,
  ctx: { manual: boolean; currentIp: string }
): SourceTargetValidation {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { ok: false, status: 400, message: 'Send a JSON object with ip_address, port, tls and/or endpoint' };
  }
  const b = body as Record<string, unknown>;
  if (!TARGET_FIELDS.some((field) => b[field] !== undefined)) {
    return {
      ok: false,
      status: 400,
      message: 'Nothing to change: send port, tls, endpoint and/or (for a manually added source) ip_address',
    };
  }

  const expected = parseExpectedAddress(b.expected_ip_address);
  if (expected === null) return { ok: false, status: 400, message: EXPECTED_IP_ADDRESS_MESSAGE };
  if (expected !== undefined && !sameAddress(expected, ctx.currentIp)) {
    return { ok: false, status: 409, message: SOURCE_CHANGED_MESSAGE };
  }

  const value: SourceTargetUpdate = {};

  if (b.ip_address !== undefined) {
    const ip = parseLiteralIp(b.ip_address);
    if (!ip) return { ok: false, status: 400, message: IP_ADDRESS_MESSAGE };
    if (!sameAddress(ip, ctx.currentIp)) {
      if (!ctx.manual) {
        return {
          ok: false,
          status: 403,
          message: "A scan-discovered source's address can't be changed (it is polled where the scan found it); only a manually added source's address can be edited",
        };
      }
      value.ip_address = ip;
    }
  }

  if (b.port !== undefined) {
    if (b.port !== null && !isPort(b.port)) {
      return { ok: false, status: 400, message: 'port must be an integer between 1 and 65535, or null for the default' };
    }
    value.port = b.port;
  }

  if (b.tls !== undefined) {
    if (b.tls !== null && typeof b.tls !== 'boolean') {
      return { ok: false, status: 400, message: 'tls must be a boolean, or null for the default' };
    }
    value.tls = b.tls;
  }

  if (b.endpoint !== undefined) {
    const endpoint = validateEndpointPath(b.endpoint);
    if (!endpoint.ok) return { ok: false, status: 400, message: endpoint.message };
    value.endpoint = endpoint.value;
  }

  return { ok: true, value };
}

export const ADDRESS_NEEDS_TOKEN_MESSAGE =
  "Changing the address of a source with a saved token needs the token again: send credential.secret with the new ip_address (a saved token is never sent to a new address)";

const MAX_SECRET_LENGTH = 4096;
/** discovery_source_pollers.credential_username is VARCHAR(255) (migration 030). */
export const MAX_USERNAME_LENGTH = 255;

export type ReplacementCredentialInput = { secret: string; username: string | null };

/**
 * PATCH /sources/:id's optional `credential` ({secret, username?}). undefined
 * when absent; {error} when present but malformed. The secret is kept as
 * typed (only checked for being non-blank), like POST .../poller/credential.
 */
export function parseReplacementCredential(value: unknown): ReplacementCredentialInput | { error: string } | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'object' || Array.isArray(value)) {
    return { error: 'credential must be an object: {"secret": "...", "username": "..."}' };
  }
  const c = value as Record<string, unknown>;
  if (typeof c.secret !== 'string' || c.secret.trim().length === 0) {
    return { error: 'credential.secret must be a non-empty string' };
  }
  if (c.secret.length > MAX_SECRET_LENGTH) return { error: `credential.secret must be at most ${MAX_SECRET_LENGTH} characters` };
  let username: string | null = null;
  if (c.username !== undefined && c.username !== null && c.username !== '') {
    if (typeof c.username !== 'string') return { error: 'credential.username must be a string' };
    if (c.username.length > MAX_USERNAME_LENGTH) {
      return { error: `credential.username must be at most ${MAX_USERNAME_LENGTH} characters` };
    }
    username = c.username;
  }
  return { secret: c.secret, username };
}

/** The response of PATCH /sources/:id: the source row, its poller status and its poll target. Never a credential. */
function sourceTargetResponse(source: DiscoverySource, poller: DiscoverySourcePoller | null, fingerprintId: string | null) {
  return {
    source,
    poller: poller ? DiscoverySourcePollerModel.toPublic(poller) : { configured: false },
    target: describePollTarget(source, fingerprintId, poller?.poll_cursor ?? null),
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
// CIDRs in public address space are refused (400, naming them) unless the body
// carries allow_public_targets: true.
router.post('/scans', requireDiscoveryScan, async (req: Request, res: Response) => {
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

  // The CIDRs this run will sweep: the request's list, or the saved scan
  // scope. Public address space is refused unless the request confirms it
  // (allow_public_targets: true): see services/scanner/publicTargetGuard.ts.
  const manualCidrs: string[] = manual_cidrs !== undefined ? manual_cidrs : await getPersistedScopeCidrs();
  const sweep = resolveScope(manualCidrs, []).cidrs;
  const publicCheck = enforcePublicTargets(sweep, req, res);
  if (!publicCheck) return;

  const result = await runScan({
    mode,
    manualCidrs,
    createdBy: req.user?.id ?? null,
    assignedShipperId,
    scanOptions: {
      origin: { page: 'log_discovery' },
      ...(publicCheck.confirmation ? { publicTargetsConfirmation: publicCheck.confirmation } : {}),
    },
  });
  await auditPublicTargetConfirmation(req, publicCheck.confirmation, { type: 'discovery_scan', id: result.scanId, targets: sweep });
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
  const id = parseInt(req.params.id as string, 10);
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
router.post('/scans/:id/cancel', requireDiscoveryScan, async (req: Request, res: Response) => {
  const id = parseInt(req.params.id as string, 10);
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

// PATCH /sources/:id - change how an API-polled source is reached: port, HTTPS
// on/off, the endpoint path, and for a manually added source its address.
// Admin-only, like the other poller writes. A manual source's target is updated
// where POST /sources/manual stored it (address + evidence); a scan-discovered
// source's goes to poll_overrides, which re-scans never touch, and its address
// never changes. A new endpoint or address clears the poll cursor (the next poll
// starts fresh); port/scheme changes keep it. The schedule and status are never
// touched, the saved credential only by a move that brings a new one (below),
// and the response never includes the credential. An expected_ip_address (the
// address the client loaded; the Edit dialog always sends it) that the source no
// longer has is a 409. The update only applies if the source still has the
// address and the settings read here, which the change was merged with (and, for
// a move without a token, still has no saved token): an edit that overlaps
// another one, or a move that overlaps a token save, is refused with 409
// instead of undoing the other or mixing the two.
router.patch('/sources/:id', authorize('admin'), async (req: Request, res: Response) => {
  const id = parseSourceId(req);
  const source = await DiscoverySourceModel.findById(id);
  if (!source) throw new ApiError(404, 'Discovery source not found');

  // The fingerprint that is polled: the poller row's (what pollOneSource uses),
  // else the matched one for a source with no credential saved yet.
  const poller = await DiscoverySourcePollerModel.findById(id);
  const fingerprintId = poller?.fingerprint_id ?? source.matched_fingerprint_id;
  const apiPull = resolveApiPull(fingerprintId);
  if (!fingerprintId || !apiPull) throw new ApiError(400, 'This source has no API pull method to configure');

  const manual = isManualSource(source);
  const parsed = validateSourceTargetUpdate(req.body, { manual, currentIp: source.ip_address });
  if (!parsed.ok) throw new ApiError(parsed.status, parsed.message);
  const change = parsed.value;

  // A saved token must never follow a manual source to a new address (an admin
  // session, or a stolen one, could otherwise redirect it to any host): an
  // address change on a source with a saved token needs the token again, and
  // the swap happens in the same statement as the move.
  const addressChanged = change.ip_address !== undefined;
  const replacementInput = parseReplacementCredential((req.body as Record<string, unknown>).credential);
  if (replacementInput && 'error' in replacementInput) throw new ApiError(400, replacementInput.error);
  if (replacementInput && !addressChanged) {
    throw new ApiError(
      400,
      'credential is only accepted with an address change; replace the token with POST /api/log-discovery/sources/:id/poller/credential'
    );
  }
  if (replacementInput && !poller) {
    throw new ApiError(400, 'This source has no saved token yet; save one with POST /api/log-discovery/sources/:id/poller/credential');
  }
  if (addressChanged && poller && !replacementInput) throw new ApiError(400, ADDRESS_NEEDS_TOKEN_MESSAGE);

  let replacement: ReplacementCredential | null = null;
  if (replacementInput) {
    let enc: { encrypted: string; iv: string; authTag: string };
    try {
      enc = CredentialEncryption.encrypt(replacementInput.secret);
    } catch (err) {
      // The encryption error names the CREDENTIAL_ENCRYPTION_KEY problem; it never contains the secret.
      throw new ApiError(500, `The token could not be encrypted, so nothing was changed: ${(err as Error).message}`);
    }
    replacement = { ...enc, username: replacementInput.username };
  }

  const current = readTargetOverrides(source);
  const endpoint = change.endpoint !== undefined ? change.endpoint : current.endpoint ?? null;
  const resetCursor = addressChanged || endpoint !== (current.endpoint ?? null);

  let updated: DiscoverySource | null;
  try {
    if (manual) {
      // A manual source always has a port and scheme; null means the same
      // defaults POST /sources/manual applies.
      const defaults = manualSourceDefaults(fingerprintId, apiPull.logAccess);
      const port = change.port === undefined ? current.port ?? defaults.port : change.port ?? defaults.port;
      if (port === null) {
        throw new ApiError(400, 'port is required (this fingerprint declares no default api_pull target_port)');
      }
      updated = await DiscoverySourceModel.updateManualTarget(
        id,
        {
          ip_address: change.ip_address ?? source.ip_address,
          target_port: port,
          tls: change.tls === undefined ? current.tls ?? defaults.tls : change.tls ?? defaults.tls,
          endpoint,
        },
        resetCursor,
        replacement,
        // What was checked and merged with above. Another edit that commits in
        // between (a move, another setting, a token saved before a move without
        // one) makes this a no-op: the 409 below.
        { ip_address: source.ip_address, evidence: source.evidence, noSavedToken: addressChanged && !replacement }
      );
    } else {
      const next: Record<string, unknown> = {};
      const port = change.port === undefined ? current.port : change.port ?? undefined;
      const tls = change.tls === undefined ? current.tls : change.tls ?? undefined;
      if (port !== undefined) next.port = port;
      if (tls !== undefined) next.tls = tls;
      if (endpoint !== null) next.endpoint = endpoint;
      // Only while the source still has the overrides merged with here.
      updated = await DiscoverySourceModel.setPollOverrides(
        id,
        Object.keys(next).length > 0 ? next : null,
        resetCursor,
        source.poll_overrides
      );
    }
    if (!updated && (await DiscoverySourceModel.findById(id))) throw new ApiError(409, SOURCE_CHANGED_MESSAGE);
  } catch (err) {
    if ((err as { code?: unknown } | null)?.code === UNIQUE_VIOLATION) {
      throw new ApiError(409, `Another discovery source already has the address ${change.ip_address}`);
    }
    throw err;
  }
  if (!updated) throw new ApiError(404, 'Discovery source not found');

  res.json(sourceTargetResponse(updated, await DiscoverySourcePollerModel.findById(id), fingerprintId));
});

// POST /sources/:id/confirm - user confirms a candidate is what the matcher thinks it is
router.post('/sources/:id/confirm', requireOperator, async (req: Request, res: Response) => {
  const id = parseSourceId(req);
  const updated = await DiscoverySourceModel.setStatus(id, 'confirmed');
  if (!updated) throw new ApiError(404, 'Discovery source not found');
  res.json(updated);
});

// POST /sources/:id/ignore - dismiss a candidate; it will not resurface in the ranked list
router.post('/sources/:id/ignore', requireOperator, async (req: Request, res: Response) => {
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
router.post('/sources/:id/onboard/confirm', requireOperator, async (req: Request, res: Response) => {
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
// credential itself; { configured: false } when none has been saved), plus its
// poll target (address, port, scheme, endpoint, the URL being polled), or
// target: null when the source has no API pull method.
router.get('/sources/:id/poller', async (req: Request, res: Response) => {
  const id = parseSourceId(req);
  const row = await DiscoverySourcePollerModel.findById(id);
  const source = await DiscoverySourceModel.findById(id);
  const target = source
    ? describePollTarget(source, row?.fingerprint_id ?? source.matched_fingerprint_id, row?.poll_cursor ?? null)
    : null;
  res.json({ ...(row ? DiscoverySourcePollerModel.toPublic(row) : { configured: false }), target });
});

// POST /sources/:id/poller/credential - save (or replace) the token/credential
// for this source's api_pull method and start polling it. Admin-gated, same as
// shippers.ts's HTTP-push-key routes and threatFeeds.ts's reputation-provider
// routes -- the two existing "user pastes a secret" precedents in this codebase.
// With expected_ip_address (the address the token was entered for; the UI
// always sends it), the token is only saved while the source still has that
// address, else 409: a manual source's address can change, and a token typed
// for one address must never reach another.
router.post('/sources/:id/poller/credential', authorize('admin'), async (req: Request, res: Response) => {
  const id = parseSourceId(req);
  const { username, secret, expected_ip_address } = req.body || {};
  if (typeof secret !== 'string' || secret.trim().length === 0) {
    throw new ApiError(400, 'secret is required');
  }
  if (typeof username === 'string' && username.length > MAX_USERNAME_LENGTH) {
    throw new ApiError(400, `username must be at most ${MAX_USERNAME_LENGTH} characters`);
  }
  const expectedIp = parseExpectedAddress(expected_ip_address);
  if (expectedIp === null) throw new ApiError(400, EXPECTED_IP_ADDRESS_MESSAGE);

  const source = await DiscoverySourceModel.findById(id);
  if (!source) throw new ApiError(404, 'Discovery source not found');
  if (expectedIp !== undefined && !sameAddress(expectedIp, source.ip_address)) {
    throw new ApiError(409, TOKEN_ADDRESS_CHANGED_MESSAGE);
  }
  if (!source.matched_fingerprint_id) throw new ApiError(400, 'This source has no matched fingerprint to poll');

  const fingerprint = getFingerprintById(source.matched_fingerprint_id);
  if (!fingerprint) throw new ApiError(404, `Fingerprint "${source.matched_fingerprint_id}" is no longer in the library`);

  // Resolve the api_pull entry explicitly rather than log_access[0] -- most
  // fingerprints list a file/syslog method first.
  const logAccess = fingerprint.log_access.find((la) => la.method === 'api_pull');
  if (!logAccess) throw new ApiError(400, `${fingerprint.name} has no api_pull log access method`);

  // The address is checked again where the token is written, while the source
  // row is locked: a move that commits after the check above makes it a 409.
  const row = await DiscoverySourcePollerModel.upsertCredential(id, {
    fingerprintId: fingerprint.id,
    method: logAccess.method,
    username: typeof username === 'string' && username.length > 0 ? username : null,
    secret,
    expectedIpAddress: expectedIp ?? null,
  });
  if (!row) {
    if (await DiscoverySourceModel.findById(id)) throw new ApiError(409, TOKEN_ADDRESS_CHANGED_MESSAGE);
    throw new ApiError(404, 'Discovery source not found');
  }

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
// pollOneSource reads the credential and the address together itself.
router.post('/sources/:id/poller/run-now', authorize('admin'), async (req: Request, res: Response) => {
  const id = parseSourceId(req);
  const result = await pollOneSource(id);
  if (!result) throw new ApiError(404, 'No poller configured for this source — save a credential first');
  res.json(result);
});

export default router;
