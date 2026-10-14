import { Router, Request, Response } from 'express';
import { UserModel } from '../models/User';
import { LoginThrottleModel, type UserPauseSummary } from '../models/LoginThrottle';
import { ApiError } from '../middleware/errorHandler';
import { authenticate, requireAdmin } from '../middleware/auth';
import { logger } from '../utils/logger';
import { auditAuth, authContext } from '../services/auth/authEvents';
import { revokeAccountAccess } from '../services/auth/signInService';
import { MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH, usernameHash } from '../services/auth/signInPolicy';

const router = Router();

// All user management routes require authentication
router.use(authenticate);

/** A password an admin sets: a string of 8 to 1024 characters. */
function passwordProblem(password: unknown): string | null {
  if (typeof password !== 'string' || password.length < MIN_PASSWORD_LENGTH || password.length > MAX_PASSWORD_LENGTH) {
    return `Password must be ${MIN_PASSWORD_LENGTH} to ${MAX_PASSWORD_LENGTH} characters`;
  }
  return null;
}

// Get all users (admin only), with any pause on their account: when the last
// sign-in pause ends (signin_paused_until) and which scopes are paused, and
// apart from those a pause on changing their own password (which doesn't stop
// them signing in).
router.get('/', requireAdmin, async (_req: Request, res: Response) => {
  try {
    const users = await UserModel.findAll();
    let paused = new Map<number, UserPauseSummary>();
    try {
      paused = await LoginThrottleModel.pausedSummaryForUsers();
    } catch (error) {
      logger.warn('Users: sign-in pauses unavailable', { error: error instanceof Error ? error.message : String(error) });
    }
    res.json(
      users.map((user) => ({
        ...user,
        signin_paused_until: paused.get(user.id)?.signInPausedUntil ?? null,
        signin_pause_scopes: paused.get(user.id)?.scopes ?? [],
        password_change_paused_until: paused.get(user.id)?.passwordChangePausedUntil ?? null,
      }))
    );
  } catch {
    throw new ApiError(500, 'Failed to fetch users');
  }
});

// Get single user (admin only)
router.get('/:id', requireAdmin, async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id as string);
    const user = await UserModel.findByIdSafe(id);

    if (!user) {
      throw new ApiError(404, 'User not found');
    }

    res.json(user);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to fetch user');
  }
});

// Create user (admin only)
router.post('/', requireAdmin, async (req: Request, res: Response) => {
  try {
    const { username, email, password, role, enabled } = req.body;

    if (!username || !email || !password) {
      throw new ApiError(400, 'Username, email, and password are required');
    }

    const problem = passwordProblem(password);
    if (problem) throw new ApiError(400, problem);

    // Check if username already exists
    const existingUser = await UserModel.findByUsername(username);
    if (existingUser) {
      throw new ApiError(409, 'Username already exists');
    }

    // Check if email already exists
    const existingEmail = await UserModel.findByEmail(email);
    if (existingEmail) {
      throw new ApiError(409, 'Email already exists');
    }

    const user = await UserModel.create({
      username,
      email,
      password,
      role,
      enabled,
    });

    logger.info('User created', { username, createdBy: req.user?.username });
    await auditAuth('user.created', authContext(req), {
      userId: req.user!.id,
      targetUserId: user.id,
      status: 201,
      details: { username: user.username, role: user.role },
    });

    res.status(201).json(user);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to create user');
  }
});

// Update user (admin only). Setting a password is a reset: the user is signed
// out everywhere, their recognized browsers are forgotten and their sign-in
// counters cleared.
router.put('/:id', requireAdmin, async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id as string);
    const { username, email, password, role, enabled } = req.body;

    // Validate the password if one is provided
    const resettingPassword = password !== undefined && password !== null && password !== '';
    if (resettingPassword) {
      const problem = passwordProblem(password);
      if (problem) throw new ApiError(400, problem);
    }

    // Check if username is taken by another user
    if (username) {
      const existing = await UserModel.findByUsername(username);
      if (existing && existing.id !== id) {
        throw new ApiError(409, 'Username already exists');
      }
    }

    // Check if email is taken by another user
    if (email) {
      const existing = await UserModel.findByEmail(email);
      if (existing && existing.id !== id) {
        throw new ApiError(409, 'Email already exists');
      }
    }

    const previous = await UserModel.findByIdSafe(id);
    const user = await UserModel.update(id, {
      username,
      email,
      password: resettingPassword ? password : undefined,
      role,
      enabled,
    });

    if (!user) {
      throw new ApiError(404, 'User not found');
    }

    const ctx = authContext(req);
    const fields = Object.entries({ username, email, role, enabled })
      .filter(([, value]) => value !== undefined)
      .map(([field]) => field);
    if (fields.length > 0) {
      logger.info('User updated', { userId: id, updatedBy: req.user?.username });
      await auditAuth('user.updated', ctx, { userId: req.user!.id, targetUserId: id, status: 200, details: { fields } });
    }
    if (resettingPassword) {
      // Revoke for the old username as well, in case it changed with this request.
      const revoked = await revokeAccountAccess({ id, username: user.username });
      if (previous && previous.username !== user.username) {
        await LoginThrottleModel.clearByUser(id, usernameHash(previous.username));
      }
      logger.info('User password reset', { userId: id, resetBy: req.user?.username });
      await auditAuth('user.password_reset', ctx, {
        userId: req.user!.id,
        targetUserId: id,
        status: 200,
        details: { by: 'admin', sessionsRevoked: revoked.sessions, browsersRevoked: revoked.browsers },
      });
    }

    res.json(user);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to update user');
  }
});

// Delete user (admin only). Sessions, recognized browsers and sign-in counters
// go with the row (ON DELETE CASCADE).
router.delete('/:id', requireAdmin, async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id as string);

    // Prevent self-deletion
    if (id === req.user!.id) {
      throw new ApiError(400, 'Cannot delete your own account');
    }

    const target = await UserModel.findByIdSafe(id);
    const deleted = await UserModel.delete(id);

    if (!deleted) {
      throw new ApiError(404, 'User not found');
    }

    logger.info('User deleted', { userId: id, deletedBy: req.user?.username });
    await auditAuth('user.deleted', authContext(req), {
      userId: req.user!.id,
      status: 200,
      details: { deletedUserId: id, username: target?.username ?? null },
    });

    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to delete user');
  }
});

// Unlock (admin only): clear every sign-in counter and pause of the account,
// from every network and browser. Network-wide pauses are cleared on Settings ->
// Sign-in protection (POST /api/admin/sign-in-protection/clear).
router.post('/:id/unlock', requireAdmin, async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id as string);
    const user = Number.isInteger(id) ? await UserModel.findByIdSafe(id) : null;
    if (!user) throw new ApiError(404, 'User not found');

    const cleared = await LoginThrottleModel.clearByUser(user.id, usernameHash(user.username));
    logger.info('Sign-in unlocked', { userId: user.id, by: req.user?.username, cleared });
    await auditAuth('auth.unlock', authContext(req), {
      userId: req.user!.id,
      targetUserId: user.id,
      status: 200,
      details: { by: 'admin', target: 'user', cleared },
    });
    res.json({ cleared });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to unlock user');
  }
});

export default router;
