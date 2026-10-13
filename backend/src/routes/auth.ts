import crypto from 'crypto';
import { Router, Request, Response, NextFunction } from 'express';
import rateLimit, { type ClientRateLimitInfo } from 'express-rate-limit';
import { UserModel } from '../models/User';
import { SessionModel } from '../models/Session';
import { ApiError } from '../middleware/errorHandler';
import { authenticate, requireAdmin } from '../middleware/auth';
import { logger } from '../utils/logger';
import * as MfaService from '../services/auth/mfaService';
import { rateLimitedHandler, signInLimitKey } from '../net/requestLimits';

const router = Router();

/*
 * Stopgap until per-account sign-in protection lands (PR 2 replaces all of
 * this). Two in-memory limits on failed sign-ins, per 15 minutes; a restart
 * clears them:
 *
 * - 10 per account per address (an IPv6 client's /64). An attacker guessing one
 *   account's password gets 10 tries, while everyone else who shares that
 *   address (an office NAT, a reverse proxy SIEMBox doesn't trust) can still
 *   sign in to their own accounts.
 * - 100 per address across all accounts, so trying many accounts is bounded
 *   too. Past it, only accounts that already failed from that address in
 *   their own current 15-minute window are refused: someone who types their
 *   password right is never locked out by other people's failures.
 *
 * Only a completed check that failed counts: not a successful sign-in, not the
 * "MFA code required" answer (it follows a correct password), not a 5xx (no
 * password was checked, e.g. while the database is down) and not a refusal.
 */
const SIGN_IN_WINDOW_MS = 15 * 60 * 1000;
const FAILURES_PER_ACCOUNT = 10;
const FAILURES_PER_ADDRESS = 100;

function notAFailedSignIn(_req: Request, res: Response): boolean {
  const status = res.statusCode;
  return status < 400 || status >= 500 || status === 429 || res.locals.mfaCodeRequested === true;
}

/**
 * The address's sign-in key plus the username as typed, trimmed and
 * lower-cased (so changing its case is no way around the limit), hashed so a
 * key never holds what someone typed.
 */
function signInAccountKey(req: Request): string {
  const username = String(req.body?.username ?? '').trim().toLowerCase();
  const account = crypto.createHash('sha256').update(username).digest('hex').slice(0, 32);
  return `${signInLimitKey(req)}|${account}`;
}

const accountFailureLimiter = rateLimit({
  windowMs: SIGN_IN_WINDOW_MS,
  limit: FAILURES_PER_ACCOUNT,
  skipSuccessfulRequests: true,
  requestWasSuccessful: notAFailedSignIn,
  keyGenerator: signInAccountKey,
  standardHeaders: 'draft-6',
  legacyHeaders: false,
  handler: rateLimitedHandler('Too many failed sign-in attempts for this account from your address.'),
});

const refuseAddress = rateLimitedHandler('Too many failed sign-in attempts from your address.');

const addressFailureLimiter = rateLimit({
  windowMs: SIGN_IN_WINDOW_MS,
  limit: FAILURES_PER_ADDRESS,
  skipSuccessfulRequests: true,
  requestWasSuccessful: notAFailedSignIn,
  keyGenerator: signInLimitKey,
  // The account limiter's RateLimit-* headers are the ones the client sees.
  standardHeaders: false,
  legacyHeaders: false,
  // Over the limit: refuse the account only if it already failed from this
  // address in a window of its own that is still open; otherwise let the
  // attempt through.
  handler: (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(accountFailureLimiter.getKey(signInAccountKey(req)))
      .then((account) => {
        const end = account ? refusalEnd(req, account) : null;
        if (end === null) {
          next();
        } else {
          res.setHeader('Retry-After', String(Math.max(1, Math.ceil((end - Date.now()) / 1000))));
          refuseAddress(req, res);
        }
      })
      .catch(next);
  },
});

/**
 * Past the address's limit, when refusing this account ends, or null when it
 * isn't refused because its entry holds no failure from a window that is
 * still open. (express-rate-limit's MemoryStore.get returns an entry whose
 * window has ended until a sweep every 15 minutes drops it, and the account
 * limiter, which would start a new window, doesn't run for a refused attempt.)
 * Otherwise the refusal ends with the account's window, or with the address's
 * if that comes first and the account hasn't reached its own limit.
 */
function refusalEnd(req: Request, account: ClientRateLimitInfo): number | null {
  const accountEnd = account.resetTime?.getTime();
  if (account.totalHits <= 0 || accountEnd === undefined || accountEnd <= Date.now()) return null;
  const addressEnd = (req as Request & { rateLimit?: { resetTime?: Date } }).rateLimit?.resetTime?.getTime();
  if (addressEnd === undefined || account.totalHits >= FAILURES_PER_ACCOUNT) return accountEnd;
  return Math.min(accountEnd, addressEnd);
}

// Login
router.post('/login', addressFailureLimiter, accountFailureLimiter, async (req: Request, res: Response) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      throw new ApiError(400, 'Username and password are required');
    }

    // Find user
    const user = await UserModel.findByUsername(username);
    if (!user) {
      throw new ApiError(401, 'Invalid username or password');
    }

    // Check if account is enabled
    if (!user.enabled) {
      throw new ApiError(403, 'Account is disabled');
    }

    // Verify password
    const isValid = await UserModel.verifyPassword(user, password);
    if (!isValid) {
      throw new ApiError(401, 'Invalid username or password');
    }

    // MFA gate — only engages for users who deliberately enrolled (mfa_enabled
    // defaults false), so password-only accounts log in exactly as before.
    if (user.mfa_enabled) {
      const code = (req.body?.code ?? '').toString().trim();
      if (!code) {
        res.locals.mfaCodeRequested = true; // not a failed sign-in (notAFailedSignIn)
        res.status(401).json({ message: 'MFA code required', mfaRequired: true });
        return;
      }
      const mfaOk = await MfaService.verifyLogin(user, code);
      if (!mfaOk) {
        res.status(401).json({ message: 'Invalid MFA code', mfaRequired: true });
        return;
      }
    }

    // Create session
    const session = await SessionModel.create(user.id, 24); // 24 hour session

    // Update last login
    await UserModel.updateLastLogin(user.id);

    logger.info('User logged in', { username, userId: user.id });

    res.json({
      token: session.token,
      user: UserModel.removeSensitiveData(user),
      expiresAt: session.expires_at,
    });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Login failed');
  }
});

// Logout
router.post('/logout', authenticate, async (req: Request, res: Response) => {
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

    res.json({ message: 'Logged out successfully' });
  } catch {
    throw new ApiError(500, 'Logout failed');
  }
});

// Get current user profile
router.get('/me', authenticate, async (req: Request, res: Response) => {
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

// Update current user password
router.put('/me/password', authenticate, async (req: Request, res: Response) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      throw new ApiError(400, 'Current password and new password are required');
    }

    if (newPassword.length < 8) {
      throw new ApiError(400, 'New password must be at least 8 characters');
    }

    // Get user with password hash
    const user = await UserModel.findById(req.user!.id);
    if (!user) {
      throw new ApiError(404, 'User not found');
    }

    // Verify current password
    const isValid = await UserModel.verifyPassword(user, currentPassword);
    if (!isValid) {
      throw new ApiError(401, 'Current password is incorrect');
    }

    // Update password
    await UserModel.update(user.id, { password: newPassword });

    // Invalidate all sessions for this user
    await SessionModel.deleteAllForUser(user.id);

    logger.info('User changed password', { userId: user.id });

    res.json({ message: 'Password updated successfully. Please login again.' });
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
router.post('/me/mfa/enable', authenticate, async (req: Request, res: Response) => {
  try {
    const code = (req.body?.code ?? '').toString().trim();
    if (!code) throw new ApiError(400, 'code is required');
    const user = await UserModel.findById(req.user!.id);
    if (!user) throw new ApiError(404, 'User not found');
    const { recoveryCodes } = await MfaService.enable(user, code);
    logger.info('User enabled MFA', { userId: user.id });
    res.json({ enabled: true, recoveryCodes });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    const msg = error instanceof Error ? error.message : 'Failed to enable MFA';
    throw new ApiError(/invalid code|pending/i.test(msg) ? 400 : 500, msg);
  }
});

// Disable MFA — requires a valid current code (TOTP or recovery).
router.post('/me/mfa/disable', authenticate, async (req: Request, res: Response) => {
  try {
    const code = (req.body?.code ?? '').toString().trim();
    if (!code) throw new ApiError(400, 'code is required');
    const user = await UserModel.findById(req.user!.id);
    if (!user) throw new ApiError(404, 'User not found');
    if (!user.mfa_enabled) {
      res.json({ enabled: false });
      return;
    }
    await MfaService.disable(user, code);
    logger.info('User disabled MFA', { userId: user.id });
    res.json({ enabled: false });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    const msg = error instanceof Error ? error.message : 'Failed to disable MFA';
    throw new ApiError(/invalid code/i.test(msg) ? 400 : 500, msg);
  }
});

// Cleanup expired sessions (can be called periodically). Admin-only, gated at
// the route like every other role check (routeInventory.test.ts runs the gates).
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
