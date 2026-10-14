/**
 * What sign-in and the other credential checks share (routes/auth.ts,
 * routes/users.ts, scripts/auth-admin.ts): the password check with its dummy
 * hash, what happens after a check failed (audit, log, pauses, alerts,
 * forgetting a browser), and revoking an account's sessions, browsers and
 * counters.
 */
import crypto from 'node:crypto';
import bcrypt from 'bcrypt';
import type { User } from '../../models/User';
import { SessionModel } from '../../models/Session';
import { LoginThrottleModel, type Charge, type Reservation } from '../../models/LoginThrottle';
import { logger } from '../../utils/logger';
import { formatWait } from '../../net/requestLimits';
import {
  BROWSER_REVOKE_FAILURES,
  auditUsernameHash,
  longestPause,
  signInSettings,
  usernameHash,
  type PauseReason,
} from './signInPolicy';
import { auditAuth, logLoginFailure, logPauseStarted, type AuthAuditAction, type AuthRequestContext } from './authEvents';
import { noteCheckedFailure, raiseAuthAlert } from './authAlerts';
import { revokeBrowser, revokeBrowsersForUser, type RecognizedBrowser } from './recognizedBrowsers';

let dummyHash: Promise<string> | null = null;

/**
 * A cost-10 bcrypt hash of random bytes, made once per process: what an
 * unknown username's password is checked against, so it takes as long as a
 * real account's. Warmed at startup (server.ts).
 */
export function getDummyHash(): Promise<string> {
  dummyHash ??= bcrypt.hash(crypto.randomBytes(32).toString('hex'), 10);
  return dummyHash;
}

/** Exactly one bcrypt compare, whether or not the account exists. */
export async function checkPassword(password: string, user: User | null): Promise<boolean> {
  const hash = user?.password_hash ?? (await getDummyHash());
  const ok = await bcrypt.compare(password, hash);
  return ok && user !== null;
}

/** Which check failed: the audit action and the answer depend on it. */
export type CheckStage = 'password' | 'mfa' | 'password_change' | 'mfa_disable';

export type FailureReason = 'unknown_user' | 'bad_password' | 'mfa_invalid' | 'mfa_replay' | 'mfa_unavailable';

const STAGE_ACTION: Record<CheckStage, AuthAuditAction> = {
  password: 'auth.login.failure',
  mfa: 'auth.login.failure',
  password_change: 'auth.password.change_failed',
  mfa_disable: 'auth.mfa.disable_failed',
};

const STAGE_LOG: Record<CheckStage, string> = {
  password: 'Login failed',
  mfa: 'Login failed',
  password_change: 'Password change failed',
  mfa_disable: 'MFA disable failed',
};

/** Status of a failed check's answer when it didn't start a pause. */
const STAGE_STATUS: Record<CheckStage, number> = { password: 401, mfa: 401, password_change: 400, mfa_disable: 400 };

export interface StartedPause {
  reason: PauseReason;
  seconds: number;
}

function startedPauses(reservation: Reservation): Charge[] {
  return reservation.outcome === 'charged' ? reservation.charges.filter((charge) => charge.pauseStarted) : [];
}

function holdingCharges(reservation: Reservation): Charge[] {
  return reservation.outcome === 'charged' ? reservation.charges.filter((charge) => charge.heldSeconds > 0) : [];
}

/**
 * After a password or code was checked and was wrong (the reservation's
 * charges stand): the audit row and log line, one auth.login.paused row and
 * log line per pause this attempt started, the alerts for those, forgetting a
 * recognized browser at 20 consecutive failures, and the spike counter.
 * Returns the pause to report when the keys now hold this attempt's username
 * back (one it started, or the network pause it was let through, whose start
 * was audited already): the answer is then a 429 with the longest wait.
 */
export async function recordFailedCheck(params: {
  ctx: AuthRequestContext;
  reservation: Reservation;
  stage: CheckStage;
  reason: FailureReason;
  /** The account, when it exists. */
  user: User | null;
  /** As typed (only its hash is ever stored). */
  username: string;
  browser: RecognizedBrowser | null;
}): Promise<StartedPause | null> {
  const { ctx, reservation, stage, reason, user, username, browser } = params;
  const settings = signInSettings();
  const usernameKeyHash = user ? undefined : auditUsernameHash(username);
  const pauses = startedPauses(reservation);
  const reported = longestPause(holdingCharges(reservation).map((charge) => ({ ...charge, remainingMs: charge.heldSeconds * 1000 })));

  void noteCheckedFailure();
  logLoginFailure({ userId: user?.id ?? null, usernameHash: usernameKeyHash, ctx, reason, message: STAGE_LOG[stage] });
  await auditAuth(STAGE_ACTION[stage], ctx, {
    userId: user?.id ?? null,
    status: reported ? 429 : STAGE_STATUS[stage],
    details: {
      reason,
      ...(stage === 'mfa' ? { stage: 'mfa' } : {}),
      recognizedBrowser: browser !== null,
      ...(usernameKeyHash ? { usernameHash: usernameKeyHash } : {}),
    },
  });

  for (const charge of pauses) {
    const scopeUser = charge.scope === 'ip' ? null : (user?.id ?? null);
    logPauseStarted({ scope: charge.scope, seconds: charge.pauseSeconds, failures: charge.after.failures, userId: scopeUser, ctx });
    await auditAuth('auth.login.paused', ctx, {
      userId: scopeUser,
      status: 429,
      details: {
        scope: charge.scope,
        seconds: charge.pauseSeconds,
        failures: charge.after.failures,
        pauses: charge.after.pauses,
        ...(charge.network ? { network: charge.network } : {}),
        ...(usernameKeyHash && (charge.scope === 'aip' || charge.scope === 'acct') ? { usernameHash: usernameKeyHash } : {}),
      },
    });
    const wait = formatWait(charge.pauseSeconds);
    const matched = {
      trigger: '',
      scope: charge.scope,
      failures: charge.after.failures,
      pauses: charge.after.pauses,
      pause_seconds: charge.pauseSeconds,
      network: charge.network,
      source_ip: ctx.ip,
      via: ctx.via,
      ...(user ? { username: user.username, user_id: user.id } : {}),
    };
    if (charge.scope === 'ip') {
      void raiseAuthAlert({
        trigger: 'network-pause',
        severity: 'medium',
        key: charge.key,
        streakStartedAt: charge.streakStartedAt,
        title: `Sign-in paused for network ${charge.network ?? 'unknown'}`,
        description:
          `${charge.after.failures} failed sign-ins from ${charge.network ?? 'an unknown address'} for any username. ` +
          `While it is paused (${wait}), new browsers on that network can't sign in to a username that failed from ` +
          'there in the last 15 minutes (others still get their password checked); browsers that signed in before ' +
          'are not affected.',
        matched: { ...matched, trigger: 'network-pause' },
      });
    } else if (charge.scope === 'acct' && user) {
      void raiseAuthAlert({
        trigger: 'account-pause',
        severity: user.role === 'admin' ? 'critical' : 'high',
        key: charge.key,
        streakStartedAt: charge.streakStartedAt,
        title: `Sign-in paused for account ${user.username}`,
        description:
          `${charge.after.failures} failed sign-ins for ${user.username} from new browsers, across all networks. ` +
          `Sign-in to it from new browsers is paused for ${wait}; browsers that signed in before are not affected. ` +
          'Unlock it on the Users page once you know who it was.',
        matched: { ...matched, trigger: 'account-pause' },
      });
    } else if (charge.scope === 'mfa' && user) {
      void raiseAuthAlert({
        trigger: 'mfa-pause',
        severity: 'critical',
        key: charge.key,
        streakStartedAt: charge.streakStartedAt,
        title: `Wrong MFA codes for ${user.username} after a correct password`,
        description:
          `${charge.after.failures} wrong MFA codes for ${user.username}. Each followed a correct password, so the ` +
          `password may be known to someone else: change it. MFA codes for the account are paused for ${wait}.`,
        matched: { ...matched, trigger: 'mfa-pause' },
      });
    }
  }

  if (browser && reservation.outcome === 'charged') {
    const browserCharge = reservation.charges.find((charge) => charge.scope === 'br');
    if (browserCharge && browserCharge.after.failures >= BROWSER_REVOKE_FAILURES) {
      try {
        if (await revokeBrowser(browser.id)) {
          logger.warn('Recognized browser forgotten after too many failures', {
            userId: browser.userId,
            failures: browserCharge.after.failures,
            ip: ctx.ip,
          });
          await auditAuth('auth.browser.revoked', ctx, {
            userId: browser.userId,
            status: reported ? 429 : STAGE_STATUS[stage],
            details: { reason: 'failures', failures: browserCharge.after.failures },
          });
          void raiseAuthAlert({
            trigger: 'browser-revoked',
            severity: 'high',
            key: browserCharge.key,
            streakStartedAt: browserCharge.streakStartedAt,
            title: `Recognized browser of ${user?.username ?? `user ${browser.userId}`} forgotten after ${browserCharge.after.failures} failures`,
            description:
              `A browser that had signed in before failed ${browserCharge.after.failures} times in a row, so SIEMBox no ` +
              'longer recognizes it. If that was not its owner, its token may have been copied.',
            matched: {
              trigger: 'browser-revoked',
              user_id: browser.userId,
              failures: browserCharge.after.failures,
              source_ip: ctx.ip,
              via: ctx.via,
            },
          });
        }
      } catch (error) {
        logger.error('Could not forget a recognized browser', {
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
  }

  if (!reported || !settings.protection) return null;
  return { reason: settings.scopes[reported.scope].reason, seconds: reported.heldSeconds };
}

/**
 * After a password change or reset: sign the account out everywhere, forget
 * its browsers and clear its counters.
 */
export async function revokeAccountAccess(user: Pick<User, 'id' | 'username'>): Promise<{
  sessions: number;
  browsers: number;
  counters: number;
}> {
  const sessions = await SessionModel.deleteAllForUser(user.id);
  const browsers = await revokeBrowsersForUser(user.id);
  const counters = await LoginThrottleModel.clearByUser(user.id, usernameHash(user.username));
  return { sessions, browsers, counters };
}
