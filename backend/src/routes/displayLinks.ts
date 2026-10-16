/**
 * Settings > Display links: admins create, configure, pause, rotate and revoke
 * the read-only links wall screens use (docs/architecture/BIG-DISPLAY.md §4.5,
 * §7.5). Mounted behind authenticate and requireAdmin in app.ts, with a 32 kB
 * body cap.
 *
 * A link's secret appears in exactly two responses, create and rotate, and
 * never again: list and get return its 4-character hint, never the secret or
 * its hash. Every change writes an audit row (resourceType display_link)
 * naming the link and the changed fields, with old and new values for
 * enabled, privacy, expires_at and allowed_cidrs; the secret and its hash are
 * never in one.
 *
 * Errors are { status: 'error', statusCode, code, message } plus `field` for
 * a 400: DISPLAY_CONFIG_INVALID (the board layout) or DISPLAY_LINK_BAD_REQUEST
 * (the link's own fields); 409 DISPLAY_LINK_LIMIT, DISPLAY_LINK_NAME_TAKEN or
 * DISPLAY_LINK_REVOKED; 404 DISPLAY_LINK_NOT_FOUND.
 */
import { Router, type NextFunction, type Request, type Response } from 'express';
import { DisplayLinkError, DisplayLinkModel, type DisplayLinkRow } from '../models/DisplayLink';
import { LIMITS, parseCreateLink, parseDisplayConfig, parseUpdateLink, type Invalid } from '../services/display/config';
import { displayPath } from '../services/display/token';
import { forgetLinkActivity } from '../middleware/displayAuth';
import { AuditService } from '../services/audit/auditService';
import { clientAddress, requestVia } from '../net/clientAddress';

const router = Router();

/** Secrets are in some of these responses; none may be cached. */
router.use(function noStore(_req: Request, res: Response, next: NextFunction) {
  res.set('Cache-Control', 'no-store');
  next();
});

export type DisplayLinkAuditAction =
  | 'display_link.created'
  | 'display_link.updated'
  | 'display_link.paused'
  | 'display_link.resumed'
  | 'display_link.rotated'
  | 'display_link.revoked'
  /** Written by middleware/displayAuth.ts: a new address used the link. */
  | 'display_link.client_first_seen'
  /** Written by middleware/displayAuth.ts: the secret was used from outside allowed_cidrs. */
  | 'display_link.refused_network';

function sendError(res: Response, status: number, code: string, message: string, extra: Record<string, unknown> = {}): void {
  res.status(status).json({ status: 'error', statusCode: status, code, message, ...extra });
}

function sendInvalid(res: Response, invalid: Invalid): void {
  sendError(res, 400, invalid.code, invalid.message, { field: invalid.field });
}

/** A model refusal (404 or 409) answered with its code; anything else goes on to the error handler. */
function answerModelError(res: Response, error: unknown): void {
  if (error instanceof DisplayLinkError) return sendError(res, error.status, error.code, error.message);
  throw error;
}

/** The :id of the path, or null (answered 404, as an id that doesn't exist is). */
function linkId(req: Request): number | null {
  const raw = req.params.id as string;
  return /^[1-9]\d{0,8}$/.test(raw) ? Number(raw) : null;
}

const notFound = (res: Response) => sendError(res, 404, 'DISPLAY_LINK_NOT_FOUND', 'Display link not found');

async function audit(
  req: Request,
  action: DisplayLinkAuditAction,
  linkId: number,
  status: number,
  details: Record<string, unknown>,
  requestBody?: unknown
): Promise<void> {
  await AuditService.log({
    userId: req.user!.id,
    action,
    resourceType: 'display_link',
    resourceId: linkId,
    ipAddress: clientAddress(req),
    userAgent: req.get('User-Agent') ?? null,
    requestBody,
    responseStatus: status,
    details: { via: requestVia(req), ...details },
  });
}

const iso = (date: Date | null) => (date ? new Date(date).toISOString() : null);
const privacyOf = (row: DisplayLinkRow) => {
  const parsed = parseDisplayConfig(row.config);
  return parsed.ok ? parsed.value.privacy : null;
};

/** The fields a change touched, and old and new values for the ones the audit trail keeps. */
function describeChange(before: DisplayLinkRow, after: DisplayLinkRow) {
  const changed: string[] = [];
  const values: Record<string, { from: unknown; to: unknown }> = {};
  if (before.name !== after.name) {
    changed.push('name');
    values.name_change = { from: before.name, to: after.name };
  }
  if (before.config_version !== after.config_version) changed.push('config');
  const tracked: Array<[string, unknown, unknown]> = [
    ['enabled', before.enabled, after.enabled],
    ['privacy', privacyOf(before), privacyOf(after)],
    ['expires_at', iso(before.expires_at), iso(after.expires_at)],
    ['allowed_cidrs', before.allowed_cidrs, after.allowed_cidrs],
  ];
  for (const [field, from, to] of tracked) {
    if (JSON.stringify(from) === JSON.stringify(to)) continue;
    if (field !== 'privacy') changed.push(field);
    values[field] = { from, to };
  }
  return { changed, values };
}

// GET /api/display-links[?include_revoked=true]
router.get('/', async (req: Request, res: Response) => {
  const links = await DisplayLinkModel.list({ includeRevoked: req.query.include_revoked === 'true' });
  res.json({ links, limit: LIMITS.liveLinks });
});

// POST /api/display-links: { name, config, expires_at?, allowed_cidrs? } -> 201 { link, token, path }
router.post('/', async (req: Request, res: Response) => {
  const input = parseCreateLink(req.body, new Date());
  if (!input.ok) return sendInvalid(res, input);
  let created;
  try {
    created = await DisplayLinkModel.create({ ...input.value, userId: req.user!.id });
  } catch (error) {
    return answerModelError(res, error);
  }
  const { link, token } = created;
  await audit(
    req,
    'display_link.created',
    link.id,
    201,
    {
      name: link.name,
      privacy: link.privacy,
      views: link.view_count,
      panel_keys: link.panel_keys,
      expires_at: iso(link.expires_at),
      allowed_cidrs: link.allowed_cidrs,
    },
    req.body
  );
  res.status(201).json({ link, token, path: displayPath(token) });
});

// GET /api/display-links/:id
router.get('/:id', async (req: Request, res: Response) => {
  const id = linkId(req);
  const link = id === null ? null : await DisplayLinkModel.findById(id);
  if (!link) return notFound(res);
  res.json({ link });
});

// PUT /api/display-links/:id: any of { name, config, enabled, expires_at, allowed_cidrs }
router.put('/:id', async (req: Request, res: Response) => {
  const id = linkId(req);
  if (id === null) return notFound(res);
  const patch = parseUpdateLink(req.body, new Date());
  if (!patch.ok) return sendInvalid(res, patch);
  let change;
  try {
    change = await DisplayLinkModel.update(id, patch.value, req.user!.id);
  } catch (error) {
    return answerModelError(res, error);
  }
  const { changed, values } = describeChange(change.before, change.after);
  const onlyEnabled = changed.length === 1 && changed[0] === 'enabled';
  const action: DisplayLinkAuditAction = onlyEnabled
    ? change.after.enabled
      ? 'display_link.resumed'
      : 'display_link.paused'
    : 'display_link.updated';
  await audit(req, action, id, 200, { name: change.after.name, changed, ...values }, req.body);
  res.json({ link: await DisplayLinkModel.findById(id) });
});

// DELETE /api/display-links/:id: revoke (the row stays for the audit trail)
router.delete('/:id', async (req: Request, res: Response) => {
  const id = linkId(req);
  if (id === null) return notFound(res);
  let row;
  try {
    row = await DisplayLinkModel.revoke(id, req.user!.id);
  } catch (error) {
    return answerModelError(res, error);
  }
  forgetLinkActivity(id);
  await audit(req, 'display_link.revoked', id, 200, { name: row.name });
  res.json({ revoked: true });
});

// POST /api/display-links/:id/rotate -> { link, token, path }: the old secret stops at once
router.post('/:id/rotate', async (req: Request, res: Response) => {
  const id = linkId(req);
  if (id === null) return notFound(res);
  let token: string;
  try {
    token = await DisplayLinkModel.rotate(id, req.user!.id);
  } catch (error) {
    return answerModelError(res, error);
  }
  forgetLinkActivity(id);
  const link = await DisplayLinkModel.findById(id);
  await audit(req, 'display_link.rotated', id, 200, { name: link?.name ?? null });
  res.json({ link, token, path: displayPath(token) });
});

export default router;
