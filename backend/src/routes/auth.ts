/**
 * Sign-in and the caller's own account.
 *
 * POST /login checks a password (and, for MFA users, a code) under sign-in
 * protection (services/auth/signInPolicy.ts, models/LoginThrottle.ts), in this
 * order:
 *
 *  1. Validate the body, without touching the database (400).
 *  2. Look the user up. This always runs.
 *  3. Look up the browser token, if one was sent, with the same query whether
 *     or not the user exists.
 *  4. Pick the keys: a recognized browser counts against its own key only;
 *     any other against the account from this network, the network and the
 *     account from every network.
 *  5. Reserve them: charge one failure to each, or refuse with a 429 if one is
 *     paused (no bcrypt, no audit row; refusals are counted in memory).
 *  6. One bcrypt compare, against a dummy hash when the user doesn't exist.
 *  7. Wrong password or no such user: the charges stand. 401, or 429 when this
 *     attempt started a pause. The same answer, and the same work, whether or
 *     not the account exists or is disabled.
 *  8. Right password: refund the charges. A disabled account gets 403 now,
 *     and only now. An account whose password is the shipped default
 *     ("changeme") is required to change it (services/auth/passwordChange.ts),
 *     which restricts its other sessions at once too.
 *  9. MFA: the code is charged to the MFA key (or the browser's) the same way,
 *     and refunded when it is right.
 * 10. Success: create the session, only while the password is still the one
 *     checked (a change or reset that landed meanwhile answers 401, as a
 *     wrong password would), reset the keys that reset, issue or touch the
 *     browser token. An account that must change its password gets a
 *     session too, with passwordChangeRequired: true; that session can only
 *     read /me, change the password or sign out (middleware/auth.ts).
 *
 * Each outcome is answered here, in the standard error envelope, rather than
 * thrown to errorHandler: no "API Error" line or application_errors row for
 * 401, 403 or 429. A 5xx (the database failing) never counts as a failure: the
 * charges of an attempt that couldn't be checked are refunded.
 */
import { Router, Request, Response, NextFunction } from 'express';
import { UserModel, type User } from '../models/User';
import { SessionModel } from '../models/Session';
import { LoginThrottleModel, type Reservation } from '../models/LoginThrottle';
import { ApiError } from '../middleware/errorHandler';
import { authenticate, authenticateAllowingPasswordChange, requireAdmin } from '../middleware/auth';
import { logger } from '../utils/logger';
import * as MfaService from '../services/auth/mfaService';
import {
  MAX_PASSWORD_LENGTH,
  browserKey,
  mfaKey,
  parseCode,
  parseLoginBody,
  passwordChangeKey,
  passwordKeys,
  pausedBody,
  signInSettings,
  usernameHash,
  type PauseCause,
  type PauseReason,
  type ThrottleKeySpec,
} from '../services/auth/signInPolicy';
import { auditAuth, authContext, noteRefusal } from '../services/auth/authEvents';
import { raiseAuthAlert } from '../services/auth/authAlerts';
import { isShippedDefaultPassword, newPasswordProblem } from '../services/auth/passwordChange';
import { raiseDefaultPasswordAlert } from '../services/auth/defaultPasswordAlerts';
import { checkPassword, recordFailedCheck, revokeAccountAccess } from '../services/auth/signInService';
import {
  findRecognizedBrowser,
  issueOrTouchBrowser,
  type RecognizedBrowser,
} from '../services/auth/recognizedBrowsers';

const router = Router();

/** Nothing under /api/auth may be cached: tokens, profiles and errors alike. */
router.use(function noStore(_req: Request, res: Response, next: NextFunction) {
  res.set('Cache-Control', 'no-store');
  next();
});

function sendError(res: Response, status: number, message: string, extra: Record<string, unknown> = {}): void {
  res.status(status).json({ status: 'error', statusCode: status, message, ...extra });
}

/** A SIGNIN_PAUSED 429 with Retry-After. */
function sendPaused(
  res: Response,
  reason: PauseReason,
  retryAfter: number,
  opts: { cause?: PauseCause; mfaRequired?: boolean } = {}
): void {
  res.setHeader('Retry-After', String(retryAfter));
  res.status(429).json(pausedBody(reason, retryAfter, opts));
}

/** Refuse an attempt whose reservation found a paused key, counting it in memory. */
function refusePaused(res: Response, reservation: Extract<Reservation, { outcome: 'paused' }>, mfaRequired = false): void {
  const reason = signInSettings().scopes[reservation.scope].reason;
  noteRefusal(reservation.key, reason);
  sendPaused(res, reason, reservation.retryAfter, { mfaRequired });
}

/**
 * Run a check whose reservation was charged; if it throws (the database), the
 * charges are refunded before the error goes on to the 500: an attempt that
 * couldn't be checked is not a failure.
 */
async function checked<T>(reservation: Reservation, check: () => Promise<T>): Promise<T> {
  try {
    return await check();
  } catch (error) {
    await LoginThrottleModel.refund(reservation);
    throw error;
  }
}

// Login
router.post('/login', async (req: Request, res: Response) => {
  // 1. Validate, with no database access.
  const input = parseLoginBody(req.body);
  if (!input) {
    sendError(res, 400, 'Username and password are required');
    return;
  }
  const ctx = authContext(req);

  try {
    // 2-3. The user, and the browser if its token is valid for that username.
    const user = await UserModel.findByUsername(input.username);
    const browser = input.browserToken ? await findRecognizedBrowser(input.browserToken, input.username) : null;

    // 4-5. Charge the keys, or refuse while one is paused.
    const keys: ThrottleKeySpec[] = browser
      ? [browserKey(browser.id, browser.userId)]
      : passwordKeys(usernameHash(input.username), ctx.network, user?.id ?? null);
    const reservation = await LoginThrottleModel.reserve(keys, ctx.userAgent);
    if (reservation.outcome === 'paused') {
      refusePaused(res, reservation);
      return;
    }

    // 6. One bcrypt compare, account or not.
    const passwordOk = await checked(reservation, () => checkPassword(input.password, user));

    // 7. Wrong password or no such account: the same answer either way.
    if (!passwordOk || !user) {
      const pause = await recordFailedCheck({
        ctx,
        reservation,
        stage: 'password',
        reason: user ? 'bad_password' : 'unknown_user',
        user,
        username: input.username,
        browser,
      });
      if (pause) sendPaused(res, pause.reason, pause.seconds, { cause: 'password' });
      else sendError(res, 401, 'Invalid username or password');
      return;
    }

    // 8. The password is right.
    await LoginThrottleModel.refund(reservation);
    if (!user.enabled) {
      logger.warn('Login failed', { userId: user.id, ip: ctx.ip, via: ctx.via, reason: 'disabled' });
      await auditAuth('auth.login.failure', ctx, {
        userId: user.id,
        status: 403,
        details: { reason: 'disabled', recognizedBrowser: browser !== null },
      });
      sendError(res, 403, 'Account is disabled');
      return;
    }
    // Still on the shipped default: anyone could look it up, whatever happens
    // at the code step, so flag it before MFA. Only the boolean leaves here.
    // Compare-and-set on the hash just checked: a password changed since this
    // sign-in read the account is never flagged (and gets no session, step 10).
    if (!user.must_change_password && isShippedDefaultPassword(input.password)) {
      const since = await UserModel.requirePasswordChange(user.id, 'default', { ifHash: user.password_hash });
      if (since) {
        user.must_change_password = true;
        user.must_change_password_reason = 'default';
        user.must_change_password_since = since;
        logger.warn('Account found on the default password; it must choose a new one', {
          userId: user.id,
          ip: ctx.ip,
          via: ctx.via,
        });
        await auditAuth('auth.password.change_required', ctx, {
          userId: user.id,
          status: 200,
          details: { by: 'sign-in', reason: 'default' },
        });
        void raiseDefaultPasswordAlert(user, since, ctx);
      }
    }

    // 9. MFA, only for users who enrolled.
    let mfaMethod: 'totp' | 'recovery' | null = null;
    if (user.mfa_enabled) {
      const codeKey = browser ? browserKey(browser.id, browser.userId) : mfaKey(user.id);
      const codeReason = signInSettings().scopes[codeKey.scope].reason;
      if (!input.code) {
        // Not a failure: it only follows a correct password.
        const remainingMs = await LoginThrottleModel.remainingPauseMs(codeKey.key);
        if (remainingMs > 0) {
          const retryAfter = Math.max(1, Math.ceil(remainingMs / 1000));
          noteRefusal(codeKey.key, codeReason);
          sendPaused(res, codeReason, retryAfter, { mfaRequired: true });
        } else {
          sendError(res, 401, 'MFA code required', { mfaRequired: true });
        }
        return;
      }
      const codeReservation = await LoginThrottleModel.reserve([codeKey], ctx.userAgent);
      if (codeReservation.outcome === 'paused') {
        refusePaused(res, codeReservation, true);
        return;
      }
      const result = await checked(codeReservation, () => MfaService.verifyCode(user, input.code!));
      if (!result.ok) {
        const pause = await recordFailedCheck({
          ctx,
          reservation: codeReservation,
          stage: 'mfa',
          reason: result.reason === 'replay' ? 'mfa_replay' : result.reason === 'unavailable' ? 'mfa_unavailable' : 'mfa_invalid',
          user,
          username: input.username,
          browser,
        });
        if (pause) sendPaused(res, pause.reason, pause.seconds, { cause: 'code', mfaRequired: true });
        else sendError(res, 401, 'Invalid MFA code', { mfaRequired: true });
        return;
      }
      // The code is right: take its charge back before the reset, so the
      // "signed in after N failed attempts" count is only the failures.
      await LoginThrottleModel.refund(codeReservation);
      mfaMethod = result.method;
      if (result.method === 'recovery') {
        await auditAuth('auth.mfa.recovery_used', ctx, { userId: user.id, status: 200 });
      }
    }

    // 10. Success.
    await completeSignIn(res, { user, browser, token: input.browserToken, mfaMethod, ctx, reservation });
  } catch (error) {
    logger.error('Login could not be completed', { error: error instanceof Error ? error.message : String(error) });
    throw new ApiError(500, 'Login failed');
  }
});

/** Step 10: reset, the browser token, the session, the audit row and log line, and the success alerts. */
async function completeSignIn(
  res: Response,
  params: {
    user: User;
    browser: RecognizedBrowser | null;
    token?: string;
    mfaMethod: 'totp' | 'recovery' | null;
    ctx: ReturnType<typeof authContext>;
    reservation: Reservation;
  }
): Promise<void> {
  const { user, browser, ctx, reservation } = params;
  // The session (24 hours) comes first, and only while the password is still
  // the one this sign-in checked. A change or reset that landed since (a
  // bcrypt compare and, with MFA, a code ago) already signed every session
  // out; a session created now would outlive the password it was earned with,
  // and no longer be restricted by a requirement that change lifted.
  const session = await SessionModel.createIfPasswordHash(user.id, user.password_hash, 24);
  if (!session) {
    logger.info('Login failed', { userId: user.id, ip: ctx.ip, via: ctx.via, reason: 'password_changed' });
    await auditAuth('auth.login.failure', ctx, {
      userId: user.id,
      status: 401,
      details: { reason: 'password_changed', recognizedBrowser: browser !== null },
    });
    sendError(res, 401, 'Invalid username or password');
    return;
  }
  const resetKeys = browser
    ? [browserKey(browser.id, browser.userId).key]
    : [passwordKeys(usernameHash(user.username), ctx.network, user.id)[0].key, mfaKey(user.id).key];
  const before = await LoginThrottleModel.reset(resetKeys);
  const browserToken = await issueOrTouchBrowser({
    userId: user.id,
    browser,
    token: params.token,
    ip: ctx.ip,
    userAgent: ctx.userAgent,
    passwordHash: user.password_hash,
  });

  await UserModel.updateLastLogin(user.id);
  // Why this session is restricted (middleware/auth.ts), when it is.
  const restricted = user.must_change_password === true;
  const changeReason = restricted ? { passwordChangeRequired: user.must_change_password_reason ?? null } : {};

  logger.info('User logged in', {
    username: user.username,
    userId: user.id,
    ip: ctx.ip,
    via: ctx.via,
    browser: browser ? 'recognized' : 'new',
    ...changeReason,
  });
  await auditAuth('auth.login.success', ctx, {
    userId: user.id,
    status: 200,
    details: {
      recognizedBrowser: browser !== null,
      mfa: params.mfaMethod !== null,
      method: params.mfaMethod ?? 'password',
      ...changeReason,
    },
  });

  // Alerts: a new browser got in while the account was under attack, or after
  // the key this success resets had piled up failures.
  const account = reservation.outcome === 'charged' ? reservation.charges.find((c) => c.scope === 'acct') : undefined;
  const matched = { username: user.username, user_id: user.id, source_ip: ctx.ip, via: ctx.via };
  if (!browser && account && !account.streakEnded && account.before.pauses > 0) {
    void raiseAuthAlert({
      trigger: 'success-during-attack',
      severity: 'high',
      key: account.key,
      streakStartedAt: account.streakStartedAt,
      title: `New browser signed in to ${user.username} while the account was under attack`,
      description:
        `${user.username} signed in from a browser SIEMBox did not recognize while sign-in to the account was being ` +
        `paused for failed attempts (${account.before.failures} failures, ${account.before.pauses} pauses). ` +
        'Check that it was the account owner.',
      matched: { ...matched, trigger: 'success-during-attack', failures: account.before.failures, pauses: account.before.pauses },
    });
  }
  const worst = before.reduce<(typeof before)[number] | null>((max, key) => (!max || key.failures > max.failures ? key : max), null);
  if (worst && worst.failures >= 5 && worst.streakStartedAt !== null) {
    void raiseAuthAlert({
      trigger: 'success-after-failures',
      severity: 'medium',
      key: worst.key,
      streakStartedAt: worst.streakStartedAt,
      title: `${user.username} signed in after ${worst.failures} failed attempts`,
      description:
        `${user.username} signed in after ${worst.failures} failed attempts in a row` +
        (worst.scope === 'mfa' ? ' at the MFA code' : worst.scope === 'br' ? ' from this browser' : ' from this network') +
        '. Probably a forgotten password; if not, someone may have guessed it.',
      matched: { ...matched, trigger: 'success-after-failures', scope: worst.scope, failures: worst.failures },
    });
  }

  res.json({
    token: session.token,
    user: UserModel.removeSensitiveData(user),
    expiresAt: session.expires_at,
    ...(browserToken ? { browserToken } : {}),
    ...(restricted ? { passwordChangeRequired: true } : {}),
  });
}

// Logout. Open to a session that must change its password (giving up).
router.post('/logout', authenticateAllowingPasswordChange, async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    let token: string | undefined;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
    }

    if (token) {
      await SessionModel.delete(token);
    }

    logger.info('User logged out', { userId: req.user?.id });
    await auditAuth('auth.logout', authContext(req), { userId: req.user?.id ?? null, status: 200 });

    res.json({ message: 'Logged out successfully' });
  } catch {
    throw new ApiError(500, 'Logout failed');
  }
});

// Get current user profile. Open to a session that must change its password:
// the UI reads why (must_change_password_reason) here.
router.get('/me', authenticateAllowingPasswordChange, async (req: Request, res: Response) => {
  try {
    const user = await UserModel.findByIdSafe(req.user!.id);

    if (!user) {
      throw new ApiError(404, 'User not found');
    }

    res.json(user);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to fetch user profile');
  }
});

/**
 * Change the caller's own password. A wrong current password is a 400, never a
 * 401 (the SPA signs out on a 401), and is counted against the pwc key: 5 in a
 * row pause it. The new one is 8 to 1024 characters, not the current one and
 * not the default password. Success clears any requirement to change it (in
 * the same UPDATE), signs the account out everywhere and forgets its browsers
 * and counters. Open to a session that must change its password: this is how
 * it does.
 */
router.put('/me/password', authenticateAllowingPasswordChange, async (req: Request, res: Response) => {
  const { currentPassword, newPassword } = req.body ?? {};
  if (
    typeof currentPassword !== 'string' ||
    typeof newPassword !== 'string' ||
    !currentPassword ||
    !newPassword ||
    currentPassword.length > MAX_PASSWORD_LENGTH
  ) {
    sendError(res, 400, 'Current password and new password are required');
    return;
  }
  const problem = newPasswordProblem(newPassword, currentPassword);
  if (problem) {
    sendError(res, 400, problem);
    return;
  }
  const ctx = authContext(req);

  try {
    const user = await UserModel.findById(req.user!.id);
    if (!user) throw new ApiError(404, 'User not found');

    const key = passwordChangeKey(user.id);
    const reservation = await LoginThrottleModel.reserve([key], ctx.userAgent);
    if (reservation.outcome === 'paused') {
      refusePaused(res, reservation);
      return;
    }
    const ok = await checked(reservation, () => checkPassword(currentPassword, user));
    if (!ok) {
      const pause = await recordFailedCheck({
        ctx,
        reservation,
        stage: 'password_change',
        reason: 'bad_password',
        user,
        username: user.username,
        browser: null,
      });
      if (pause) sendPaused(res, pause.reason, pause.seconds, { cause: 'current_password' });
      else sendError(res, 400, 'Current password is incorrect');
      return;
    }

    // The current password is right: take its charge back now, so a failure
    // to save the new one (a 5xx) is never counted.
    await LoginThrottleModel.refund(reservation);
    // Signs out every session in the same transaction that sets the new
    // password and lifts any requirement; then the browsers and counters.
    const changed = await UserModel.changeOwnPassword(user.id, newPassword);
    const revoked = await revokeAccountAccess(user);
    const forced = user.must_change_password === true;

    logger.info('User changed password', { userId: user.id, ip: ctx.ip, forced });
    await auditAuth('auth.password.changed', ctx, {
      userId: user.id,
      status: 200,
      details: {
        sessionsRevoked: changed.sessionsRevoked + revoked.sessions,
        browsersRevoked: revoked.browsers,
        ...(forced ? { forced: true, reason: user.must_change_password_reason ?? null } : {}),
      },
    });

    res.json({ message: 'Password updated. Sign in again with the new password.' });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to update password');
  }
});

// --- MFA (TOTP) — the logged-in user manages their own MFA ----------------

// Begin enrollment: generate + store a pending secret, return it + the otpauth
// URI for the authenticator app. Does NOT enable MFA yet.
router.post('/me/mfa/setup', authenticate, async (req: Request, res: Response) => {
  try {
    const user = await UserModel.findById(req.user!.id);
    if (!user) throw new ApiError(404, 'User not found');
    if (user.mfa_enabled) throw new ApiError(409, 'MFA is already enabled; disable it first to re-enroll');
    const { secret, otpauthUrl } = await MfaService.startEnrollment(user);
    res.json({ secret, otpauthUrl });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    const msg = error instanceof Error ? error.message : 'MFA setup failed';
    // Surface the encryption-key misconfiguration clearly (startEnrollment encrypts the secret).
    throw new ApiError(/ENCRYPTION_KEY|encrypt/i.test(msg) ? 400 : 500, msg);
  }
});

// Finish enrollment: verify a code against the pending secret, enable MFA, and
// return one-time recovery codes (shown once — the client must save them).
// Not throttled: the code is checked against a secret the caller was just
// given. So never once MFA is on (409, like setup): the code would be checked
// against the active secret instead, unthrottled.
router.post('/me/mfa/enable', authenticate, async (req: Request, res: Response) => {
  try {
    const code = parseCode(req.body?.code);
    if (!code) throw new ApiError(400, 'code is required');
    const user = await UserModel.findById(req.user!.id);
    if (!user) throw new ApiError(404, 'User not found');
    if (user.mfa_enabled) throw new ApiError(409, 'MFA is already enabled; disable it first to re-enroll');
    const { recoveryCodes } = await MfaService.enable(user, code);
    logger.info('User enabled MFA', { userId: user.id });
    await auditAuth('auth.mfa.enabled', authContext(req), { userId: user.id, status: 200 });
    res.json({ enabled: true, recoveryCodes });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (error instanceof MfaService.MfaEnrollmentConflict) throw new ApiError(409, error.message);
    const msg = error instanceof Error ? error.message : 'Failed to enable MFA';
    throw new ApiError(/invalid code|pending/i.test(msg) ? 400 : 500, msg);
  }
});

/**
 * Disable MFA with a current code (TOTP or recovery, used up like at sign-in).
 * Wrong codes count against the same MFA key as sign-in: 400 'Invalid code',
 * then 429 once it pauses. Never a 401 (the SPA signs out on a 401).
 */
router.post('/me/mfa/disable', authenticate, async (req: Request, res: Response) => {
  const code = parseCode(req.body?.code);
  if (!code) {
    sendError(res, 400, 'code is required');
    return;
  }
  const ctx = authContext(req);
  try {
    const user = await UserModel.findById(req.user!.id);
    if (!user) throw new ApiError(404, 'User not found');
    if (!user.mfa_enabled) {
      res.json({ enabled: false });
      return;
    }
    const reservation = await LoginThrottleModel.reserve([mfaKey(user.id)], ctx.userAgent);
    if (reservation.outcome === 'paused') {
      refusePaused(res, reservation);
      return;
    }
    const result = await checked(reservation, () => MfaService.disable(user, code));
    if (!result.ok) {
      const pause = await recordFailedCheck({
        ctx,
        reservation,
        stage: 'mfa_disable',
        reason: result.reason === 'replay' ? 'mfa_replay' : result.reason === 'unavailable' ? 'mfa_unavailable' : 'mfa_invalid',
        user,
        username: user.username,
        browser: null,
      });
      if (pause) sendPaused(res, pause.reason, pause.seconds, { cause: 'code' });
      else sendError(res, 400, 'Invalid code');
      return;
    }
    await LoginThrottleModel.reset([mfaKey(user.id).key]);
    logger.info('User disabled MFA', { userId: user.id });
    await auditAuth('auth.mfa.disabled', ctx, { userId: user.id, status: 200, details: { method: result.method } });
    res.json({ enabled: false });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to disable MFA');
  }
});

// Cleanup expired sessions (can be called periodically). Admin-only, gated at
// the route like every other role check (routeInventory.test.ts runs the gates).
// The sign-in housekeeping job (jobs/signInHousekeeping.ts) also does this hourly.
router.post('/cleanup', authenticate, requireAdmin, async (_req: Request, res: Response) => {
  try {
    const deletedCount = await SessionModel.deleteExpired();

    logger.info('Expired sessions cleaned up', { count: deletedCount });

    res.json({ message: `Cleaned up ${deletedCount} expired sessions` });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Cleanup failed');
  }
});

export default router;
