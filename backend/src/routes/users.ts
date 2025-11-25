import { Router, Request, Response } from 'express';
import { UserModel } from '../models/User';
import { ApiError } from '../middleware/errorHandler';
import { authenticate, requireAdmin } from '../middleware/auth';
import { logger } from '../utils/logger';

const router = Router();

// All user management routes require authentication
router.use(authenticate);

// Get all users (admin only)
router.get('/', requireAdmin, async (req: Request, res: Response) => {
  try {
    const users = await UserModel.findAll();
    res.json(users);
  } catch (error) {
    throw new ApiError(500, 'Failed to fetch users');
  }
});

// Get single user (admin only)
router.get('/:id', requireAdmin, async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
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

    if (password.length < 8) {
      throw new ApiError(400, 'Password must be at least 8 characters');
    }

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

    res.status(201).json(user);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to create user');
  }
});

// Update user (admin only)
router.put('/:id', requireAdmin, async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const { username, email, password, role, enabled } = req.body;

    // Validate password length if provided
    if (password && password.length < 8) {
      throw new ApiError(400, 'Password must be at least 8 characters');
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

    const user = await UserModel.update(id, {
      username,
      email,
      password,
      role,
      enabled,
    });

    if (!user) {
      throw new ApiError(404, 'User not found');
    }

    logger.info('User updated', { userId: id, updatedBy: req.user?.username });

    res.json(user);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to update user');
  }
});

// Delete user (admin only)
router.delete('/:id', requireAdmin, async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);

    // Prevent self-deletion
    if (id === req.user!.id) {
      throw new ApiError(400, 'Cannot delete your own account');
    }

    const deleted = await UserModel.delete(id);

    if (!deleted) {
      throw new ApiError(404, 'User not found');
    }

    logger.info('User deleted', { userId: id, deletedBy: req.user?.username });

    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to delete user');
  }
});

export default router;
