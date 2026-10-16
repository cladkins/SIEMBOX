/**
 * A wall screen's credential: its display link secret in X-Display-Token
 * (docs/architecture/BIG-DISPLAY.md §4.3).
 *
 * A display token is never a login, and a login is never a display token:
 * authenticate (middleware/auth.ts) never reads X-Display-Token, and this
 * never reads Authorization. routeInventory.test.ts proves both directions.
 *
 * Every request re-reads the link (one unique-index lookup), so pause, rotate
 * and revoke act on the screen's next refresh; nothing about authorization is
 * cached. Refusals are answered here, not thrown: no "API Error" line, no
 * application_errors row and no audit row, so a forgotten TV polling with a
 * revoked link fills nothing. They are counted in memory and summed up in one
 * log line every 5 minutes instead. The one refusal that is audited, once per
 * link and address per hour, is a valid secret used from outside its allowed
 * networks: that is a leak signal.
 */
import type { NextFunction, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import { DisplayLinkModel, type DisplayLinkAuth } from '../models/DisplayLink';
import { hashDisplayToken, isDisplayToken } from '../services/display/token';
import { TOUCH_INTERVAL_SECONDS } from '../services/display/linkStatus';
import { AuditService } from '../services/audit/auditService';
import { clientAddress, requestVia } from '../net/clientAddress';
import { rateLimitedHandler, requestLimitKey } from '../net/requestLimits';
import { logger } from '../utils/logger';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace -- augmenting @types/express's global Express.Request requires namespace declaration merging
  namespace Express {
    interface Request {
      /** The display link a request authenticated with (authenticateDisplay). */
      displayLink?: DisplayLinkAuth;
    }
  }
}

export const DISPLAY_TOKEN_HEADER = 'X-Display-Token';

export type DisplayRefusal =
  | 'DISPLAY_TOKEN_REQUIRED'
  | 'DISPLAY_LINK_INVALID'
  | 'DISPLAY_LINK_REVOKED'
  | 'DISPLAY_LINK_EXPIRED'
  | 'DISPLAY_LINK_PAUSED'
  | 'DISPLAY_NETWORK_NOT_ALLOWED'
  | 'DISPLAY_UNAVAILABLE';

/** Status and wording of each refusal; the screen acts on the code (§5.8). */
export const DISPLAY_REFUSALS: Readonly<Record<DisplayRefusal, { status: number; message: string }>> = {
  DISPLAY_TOKEN_REQUIRED: { status: 401, message: 'This page needs a display link. Ask an administrator for one.' },
  DISPLAY_LINK_INVALID: {
    status: 401,
    message: "This display link isn't valid any more (it may have been replaced). Ask an administrator for the new one.",
  },
  DISPLAY_LINK_REVOKED: { status: 401, message: 'This display link was revoked.' },
  DISPLAY_LINK_EXPIRED: { status: 401, message: 'This display link has expired.' },
  DISPLAY_LINK_PAUSED: { status: 403, message: 'Paused by an administrator.' },
  DISPLAY_NETWORK_NOT_ALLOWED: { status: 403, message: "This screen's network isn't allowed to use this link." },
  DISPLAY_UNAVAILABLE: { status: 503, message: 'SIEMBox is temporarily unavailable. The screen will try again.' },
};

// --- Refusal counts --------------------------------------------------------------

const SUMMARY_INTERVAL_MS = 5 * 60 * 1000;
const refusals = { window: {} as Partial<Record<DisplayRefusal, number>>, sinceStart: 0 };
let summaryTimer: NodeJS.Timeout | null = null;

function summarize(): void {
  const counts = refusals.window;
  const total = Object.values(counts).reduce((sum, n) => sum + (n ?? 0), 0);
  if (total === 0) return;
  logger.warn('Display link requests refused', { minutes: SUMMARY_INTERVAL_MS / 60_000, refused: total, byCode: counts });
  refusals.window = {};
}

function countRefusal(code: DisplayRefusal): void {
  refusals.sinceStart++;
  refusals.window[code] = (refusals.window[code] ?? 0) + 1;
  if (!summaryTimer) {
    summaryTimer = setInterval(summarize, SUMMARY_INTERVAL_MS);
    summaryTimer.unref();
  }
}

/** Refusals since the process started, by code in the current 5-minute window. */
export function displayRefusalStats(): { sinceStart: number; window: Partial<Record<DisplayRefusal, number>> } {
  return { sinceStart: refusals.sinceStart, window: { ...refusals.window } };
}

/** Write the summary now and stop its timer (shutdown, tests). */
export function stopDisplayRefusalSummary(): void {
  summarize();
  if (summaryTimer) clearInterval(summaryTimer);
  summaryTimer = null;
}

/** Answer a refusal in the standard error envelope, uncached, with its code. */
function refuse(res: Response, code: DisplayRefusal, extra: Record<string, unknown> = {}): void {
  countRefusal(code);
  const { status, message } = DISPLAY_REFUSALS[code];
  res.set('Cache-Control', 'no-store');
  if (status === 503) res.set('Retry-After', '5');
  res.status(status).json({ status: 'error', statusCode: status, code, message, ...extra });
}

// --- Use and leak signals ----------------------------------------------------------

/** In-memory maps hold at most this many keys; a full map is cleared (like notFoundHandler's). */
const MAX_TRACKED = 5000;
const HOUR_MS = 60 * 60 * 1000;
/** At most this many display_link.client_first_seen rows per link per hour. */
export const FIRST_SEEN_AUDITS_PER_HOUR = 10;

/** `${linkId}|${address}` -> when its use was last written. */
const lastTouch = new Map<string, number>();
/** linkId -> first-seen audit rows written in the current hour. */
const firstSeenAudits = new Map<number, { since: number; count: number }>();
/** `${linkId}|${address}` -> when a refused_network row was last written. */
const refusedNetworkAudits = new Map<string, number>();

function remember<K, V>(map: Map<K, V>, key: K, value: V): void {
  if (!map.has(key) && map.size >= MAX_TRACKED) map.clear();
  map.set(key, value);
}

function mayAuditFirstSeen(linkId: number, now: number): boolean {
  const entry = firstSeenAudits.get(linkId);
  if (!entry || now - entry.since >= HOUR_MS) {
    remember(firstSeenAudits, linkId, { since: now, count: 1 });
    return true;
  }
  if (entry.count >= FIRST_SEEN_AUDITS_PER_HOUR) return false;
  entry.count++;
  return true;
}

/**
 * Record a screen's use, at most once a minute per (link, address), without
 * holding up the response. An address new to the link trims the link's
 * devices to the 20 most recently seen and writes display_link.client_first_seen
 * (at most 10 per link per hour). Informational only: it never refuses.
 * `tokenHash` is the secret this request authenticated with: the write is
 * dropped if a rotate or revoke committed in the meantime.
 */
export function touchUsed(link: DisplayLinkAuth, req: Request, tokenHash: string): void {
  const ip = clientAddress(req);
  const key = `${link.id}|${ip ?? '-'}`;
  const now = Date.now();
  const last = lastTouch.get(key);
  if (last !== undefined && now - last < TOUCH_INTERVAL_SECONDS * 1000) return;
  remember(lastTouch, key, now);
  const userAgent = req.get('User-Agent') ?? null;
  const work = ip ? DisplayLinkModel.touch(link.id, tokenHash, ip, userAgent)
    : DisplayLinkModel.touchLastUsed(link.id, tokenHash).then(() => false);
  void work
    .then(async (firstTime) => {
      if (!firstTime || !ip) return;
      await DisplayLinkModel.trimClients(link.id);
      if (!mayAuditFirstSeen(link.id, now)) return;
      await AuditService.log({
        userId: null,
        action: 'display_link.client_first_seen',
        resourceType: 'display_link',
        resourceId: link.id,
        ipAddress: ip,
        userAgent,
        responseStatus: 200,
        details: { name: link.name, via: requestVia(req) },
      });
    })
    .catch((error: unknown) => {
      logger.warn('Display link use not recorded', { linkId: link.id, error: error instanceof Error ? error.message : String(error) });
    });
}

/** A valid secret used from outside its networks: audited once per (link, address) per hour. */
export function noteRefusedNetwork(link: DisplayLinkAuth, req: Request): void {
  const ip = clientAddress(req);
  const key = `${link.id}|${ip ?? '-'}`;
  const now = Date.now();
  const last = refusedNetworkAudits.get(key);
  if (last !== undefined && now - last < HOUR_MS) return;
  remember(refusedNetworkAudits, key, now);
  void AuditService.log({
    userId: null,
    action: 'display_link.refused_network',
    resourceType: 'display_link',
    resourceId: link.id,
    ipAddress: ip,
    userAgent: req.get('User-Agent') ?? null,
    responseStatus: DISPLAY_REFUSALS.DISPLAY_NETWORK_NOT_ALLOWED.status,
    details: { name: link.name, via: requestVia(req) },
  });
}

/** Forget a link's write throttle (after a rotation, the next use is the new secret's first). */
export function forgetLinkActivity(linkId: number): void {
  const prefix = `${linkId}|`;
  for (const key of lastTouch.keys()) if (key.startsWith(prefix)) lastTouch.delete(key);
}

/** Clear every in-memory map and count (tests). */
export function resetDisplayAuthState(): void {
  lastTouch.clear();
  firstSeenAudits.clear();
  refusedNetworkAudits.clear();
  refusals.window = {};
  refusals.sinceStart = 0;
}

// --- The gate ------------------------------------------------------------------

/**
 * The display link of X-Display-Token, or a refusal, in this order:
 * no header (401 DISPLAY_TOKEN_REQUIRED); malformed or unknown (401
 * DISPLAY_LINK_INVALID, the same answer for both, and a malformed one is
 * never hashed or looked up); the database failing (503 DISPLAY_UNAVAILABLE,
 * never "invalid"); revoked (401); expired (401, with expires_at); paused
 * (403); outside allowed_cidrs (403).
 */
export async function authenticateDisplay(req: Request, res: Response, next: NextFunction): Promise<void> {
  const token = req.get(DISPLAY_TOKEN_HEADER); // Authorization is never read here
  if (!token) return refuse(res, 'DISPLAY_TOKEN_REQUIRED');
  if (!isDisplayToken(token)) return refuse(res, 'DISPLAY_LINK_INVALID');
  const tokenHash = hashDisplayToken(token);
  let link: DisplayLinkAuth | null;
  try {
    link = await DisplayLinkModel.findForAuth(tokenHash, clientAddress(req));
  } catch {
    return refuse(res, 'DISPLAY_UNAVAILABLE'); // database down is not "invalid link"
  }
  if (!link) return refuse(res, 'DISPLAY_LINK_INVALID');
  if (link.revoked_at) return refuse(res, 'DISPLAY_LINK_REVOKED');
  if (link.expires_at && new Date(link.expires_at).getTime() <= Date.now()) {
    return refuse(res, 'DISPLAY_LINK_EXPIRED', { expires_at: new Date(link.expires_at).toISOString() });
  }
  if (!link.enabled) return refuse(res, 'DISPLAY_LINK_PAUSED');
  if (link.address_allowed !== true) {
    noteRefusedNetwork(link, req);
    return refuse(res, 'DISPLAY_NETWORK_NOT_ALLOWED');
  }
  req.displayLink = link;
  touchUsed(link, req, tokenHash);
  next();
}

/**
 * Failed display lookups: 30 per 15 minutes per client address, then 429
 * (RATE_LIMITED, with Retry-After). Only 401s count, so a working screen, a
 * paused one and a database outage never use it up. It sits in front of
 * authenticateDisplay, so guessing costs no database work after 30 misses.
 * Display requests also count towards the general /api limit.
 */
export const displayTokenLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  keyGenerator: requestLimitKey,
  standardHeaders: 'draft-6',
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  requestWasSuccessful: (_req: Request, res: Response) => res.statusCode !== 401,
  handler: rateLimitedHandler('Too many display link attempts from your address.'),
});
