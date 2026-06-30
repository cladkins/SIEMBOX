import { Router, Request, Response } from 'express';
import { UserModel } from '../models/User';
import { SessionModel } from '../models/Session';
import { ApiError } from '../middleware/errorHandler';
import { authenticate } from '../middleware/auth';
import { logger } from '../utils/logger';
import * as MfaService from '../services/auth/mfaService';

const router = Router();

// Login
router.post('/login', async (req: Request, res: Response) => {
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
    } else if (req.cookies?.session_token) {
      token = req.cookies.session_token;
    }

    if (token) {
      await SessionModel.delete(token);
    }

    logger.info('User logged out', { userId: req.user?.id });

    res.json({ message: 'Logged out successfully' });
  } catch (error) {
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

// Cleanup expired sessions (can be called periodically)
router.post('/cleanup', authenticate, async (req: Request, res: Response) => {
  try {
    // Only admins can trigger cleanup
    if (req.user?.role !== 'admin') {
      throw new ApiError(403, 'Admin access required');
    }

    const deletedCount = await SessionModel.deleteExpired();

    logger.info('Expired sessions cleaned up', { count: deletedCount });

    res.json({ message: `Cleaned up ${deletedCount} expired sessions` });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Cleanup failed');
  }
});

export default router;
