/**
 * Audit rows and log lines for sign-in and account events, and the in-memory
 * count of attempts refused while a key was paused.
 *
 * Every row records the client address (net/clientAddress.ts) and, in
 * details.via, how the request arrived (proxy-socket, trusted-proxy or
 * direct). A username that doesn't exist is never stored as typed (it could be
 * a password typed into the wrong field): user_id is NULL and
 * details.usernameHash holds 16 hex characters of its hash.
 *
 * Refused attempts (a 429 while paused) are not audited one by one, which
 * would let a flood of requests flood the table: each pause start writes one
 * auth.login.paused row, and refusals are counted here and summed up in one
 * log line every 5 minutes.
 */
import type { Request } from 'express';
import { AuditService } from '../audit/auditService';
import { logger } from '../../utils/logger';
import { clientAddress, requestVia, signInNetworkKey, type RequestVia } from '../../net/clientAddress';
import type { PauseReason, SignInScope } from './signInPolicy';

export interface AuthRequestContext {
  /** The client address, or null. */
  ip: string | null;
  /** Its sign-in network: the IPv4 address, the IPv6 /64, or 'unknown'. */
  network: string;
  via: RequestVia;
  userAgent: string | null;
}

export function authContext(req: Request): AuthRequestContext {
  const ip = clientAddress(req);
  return {
    ip,
    network: signInNetworkKey(ip),
    via: requestVia(req),
    userAgent: req.get('User-Agent')?.slice(0, 256) ?? null,
  };
}

export type AuthAuditAction =
  | 'auth.login.success'
  | 'auth.login.failure'
  | 'auth.login.paused'
  | 'auth.logout'
  | 'auth.mfa.enabled'
  | 'auth.mfa.disabled'
  | 'auth.mfa.disable_failed'
  | 'auth.mfa.recovery_used'
  | 'auth.password.changed'
  | 'auth.password.change_failed'
  /** An account is now required to change its password, outside a reset: found on the default password. */
  | 'auth.password.change_required'
  | 'auth.browser.revoked'
  | 'auth.unlock'
  | 'user.created'
  | 'user.updated'
  | 'user.deleted'
  | 'user.password_reset';

/**
 * Write one audit row. `ctx` is the request's (or null for the CLI, which
 * records details.by = 'cli'). Never throws: AuditService.log reports its own
 * failures.
 */
export async function auditAuth(
  action: AuthAuditAction,
  ctx: AuthRequestContext | null,
  entry: { userId: number | null; status: number; targetUserId?: number | null; details?: Record<string, unknown> }
): Promise<void> {
  const target = entry.targetUserId ?? (entry.userId ?? undefined);
  await AuditService.log({
    userId: entry.userId,
    action,
    resourceType: target !== undefined && target !== null ? 'user' : undefined,
    resourceId: target ?? undefined,
    ipAddress: ctx?.ip ?? null,
    userAgent: ctx?.userAgent ?? null,
    responseStatus: entry.status,
    details: { ...(ctx ? { via: ctx.via } : {}), ...(entry.details ?? {}) },
  });
}

// --- Refusals ----------------------------------------------------------------

const SUMMARY_INTERVAL_MS = 5 * 60 * 1000;
const MAX_TRACKED_KEYS = 2000;

const refused = {
  sinceStart: 0,
  byReason: {} as Partial<Record<PauseReason, number>>,
  byKey: new Map<string, number>(),
  /** Since the last summary line. */
  window: 0,
  windowByReason: {} as Partial<Record<PauseReason, number>>,
};
let summaryTimer: NodeJS.Timeout | null = null;

function summarize(): void {
  if (refused.window === 0) return;
  logger.warn('Sign-in attempts refused while paused', {
    minutes: SUMMARY_INTERVAL_MS / 60_000,
    refused: refused.window,
    byReason: refused.windowByReason,
  });
  refused.window = 0;
  refused.windowByReason = {};
}

/** Count one attempt refused because `key` is paused. */
export function noteRefusal(key: string, reason: PauseReason): void {
  refused.sinceStart++;
  refused.window++;
  refused.byReason[reason] = (refused.byReason[reason] ?? 0) + 1;
  refused.windowByReason[reason] = (refused.windowByReason[reason] ?? 0) + 1;
  if (!refused.byKey.has(key) && refused.byKey.size >= MAX_TRACKED_KEYS) {
    const oldest = refused.byKey.keys().next().value;
    if (oldest !== undefined) refused.byKey.delete(oldest);
  }
  refused.byKey.set(key, (refused.byKey.get(key) ?? 0) + 1);
  if (!summaryTimer) {
    summaryTimer = setInterval(summarize, SUMMARY_INTERVAL_MS);
    summaryTimer.unref();
  }
}

/** Refusals since the process started (the admin page). */
export function refusalStats(): { sinceStart: number; byReason: Partial<Record<PauseReason, number>> } {
  return { sinceStart: refused.sinceStart, byReason: { ...refused.byReason } };
}

/** Refusals of one key since the process started. */
export function refusalsForKey(key: string): number {
  return refused.byKey.get(key) ?? 0;
}

/** Flush the summary now and stop its timer (shutdown, tests). */
export function stopRefusalSummary(): void {
  summarize();
  if (summaryTimer) clearInterval(summaryTimer);
  summaryTimer = null;
}

// --- Log lines ---------------------------------------------------------------

/** 'Login failed' for a sign-in; the other checks name themselves ('Password change failed', ...). */
export function logLoginFailure(fields: {
  userId: number | null;
  usernameHash?: string;
  ctx: AuthRequestContext;
  reason: string;
  message?: string;
}): void {
  logger.warn(fields.message ?? 'Login failed', {
    userId: fields.userId,
    ...(fields.usernameHash ? { usernameHash: fields.usernameHash } : {}),
    ip: fields.ctx.ip,
    via: fields.ctx.via,
    reason: fields.reason,
  });
}

export function logPauseStarted(fields: {
  scope: SignInScope;
  seconds: number;
  failures: number;
  userId: number | null;
  ctx: AuthRequestContext;
}): void {
  logger.warn('Sign-in paused', {
    scope: fields.scope,
    seconds: fields.seconds,
    failures: fields.failures,
    userId: fields.userId,
    ip: fields.ctx.ip,
    network: fields.ctx.network,
    via: fields.ctx.via,
  });
}
