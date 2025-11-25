import { Router, Request, Response } from 'express';
import { UserModel } from '../models/User';
import { SessionModel } from '../models/Session';
import { ApiError } from '../middleware/errorHandler';
import { authenticate } from '../middleware/auth';
import { logger } from '../utils/logger';

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
