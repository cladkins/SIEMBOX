import { Request, Response, NextFunction } from 'express';
import { SessionModel } from '../models/Session';
import { UserModel } from '../models/User';
import { ApiError } from './errorHandler';

// Extend Express Request to include user
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: number;
        username: string;
        email: string;
        role: 'admin' | 'analyst' | 'viewer' | 'operator';
      };
    }
  }
}

/**
 * Authentication middleware
 * Validates session token and attaches user to request
 */
export const authenticate = async (req: Request, _res: Response, next: NextFunction) => {
  try {
    // Get token from Authorization header or cookie
    const authHeader = req.headers.authorization;
    let token: string | undefined;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
    } else if (req.cookies?.session_token) {
      token = req.cookies.session_token;
    }

    if (!token) {
      throw new ApiError(401, 'Authentication required');
    }

    // Validate session
    const session = await SessionModel.findByToken(token);
    if (!session) {
      throw new ApiError(401, 'Invalid or expired session');
    }

    // Get user
    const user = await UserModel.findById(session.user_id);
    if (!user) {
      throw new ApiError(401, 'User not found');
    }

    if (!user.enabled) {
      throw new ApiError(403, 'Account is disabled');
    }

    // Attach user to request
    req.user = {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
    };

    next();
  } catch (error) {
    next(error);
  }
};

/**
 * Optional authentication middleware
 * Attaches user if authenticated, but doesn't require it
 */
export const optionalAuthenticate = async (
  req: Request,
  _res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.headers.authorization;
    let token: string | undefined;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
    } else if (req.cookies?.session_token) {
      token = req.cookies.session_token;
    }

    if (token) {
      const session = await SessionModel.findByToken(token);
      if (session) {
        const user = await UserModel.findById(session.user_id);
        if (user && user.enabled) {
          req.user = {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
          };
        }
      }
    }

    next();
  } catch (error) {
    // On error, just continue without user
    next();
  }
};

/**
 * Role-based authorization middleware
 * Requires specific roles to access route
 */
export const authorize = (...allowedRoles: ('admin' | 'analyst' | 'viewer' | 'operator')[]) => {
  return (req: Request, _res: Response, next: NextFunction) => {
    if (!req.user) {
      return next(new ApiError(401, 'Authentication required'));
    }

    if (!allowedRoles.includes(req.user.role)) {
      return next(
        new ApiError(403, `Access denied. Required role: ${allowedRoles.join(' or ')}`)
      );
    }

    next();
  };
};

/**
 * Require admin role
 */
export const requireAdmin = authorize('admin');

/**
 * Require admin or analyst role
 */
export const requireAnalyst = authorize('admin', 'analyst');

/**
 * Require operator role or higher
 */
export const requireOperator = authorize('admin', 'operator');
