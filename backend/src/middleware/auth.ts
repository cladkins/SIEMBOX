import { Request, Response, NextFunction } from 'express';
import { SessionModel } from '../models/Session';
import type { User } from '../models/User';
import { ApiError } from './errorHandler';
import { passwordChangeRequiredBody, type PasswordChangeReason } from '../services/auth/passwordChange';

// Extend Express Request to include user
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace -- augmenting @types/express's global Express.Request requires namespace declaration merging
  namespace Express {
    interface Request {
      user?: {
        id: number;
        username: string;
        email: string;
        role: 'admin' | 'analyst' | 'viewer' | 'operator';
        /** The account must change its password before anything else (migration 039). */
        mustChangePassword: boolean;
        passwordChangeReason: PasswordChangeReason | null;
      };
    }
  }
}

/**
 * The session's user, or an ApiError: 401 without a valid session, 403 for a
 * disabled account. Sessions are opaque tokens in the Authorization header
 * (Bearer). Cookie-based auth was removed: the app never issued a
 * session_token cookie, so the fallback was dead code and an unnecessary CSRF
 * surface.
 */
async function sessionUser(req: Request): Promise<User> {
  const authHeader = req.headers.authorization;
  let token: string | undefined;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7);
  }

  if (!token) {
    throw new ApiError(401, 'Authentication required');
  }

  // The session and its account in one statement: a password change that
  // lifts a restriction deletes the sessions in the same transaction, so this
  // sees the restricted session or no session, never the session from before
  // with the account from after (SessionModel.findUserByToken).
  const user = await SessionModel.findUserByToken(token);
  if (!user) {
    throw new ApiError(401, 'Invalid or expired session');
  }

  if (!user.enabled) {
    throw new ApiError(403, 'Account is disabled');
  }
  return user;
}

function attachUser(req: Request, user: User): void {
  const mustChangePassword = user.must_change_password === true;
  req.user = {
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role,
    mustChangePassword,
    passwordChangeReason: mustChangePassword ? (user.must_change_password_reason ?? null) : null,
  };
}

/**
 * Every route that takes a login: validates the session and attaches the user.
 *
 * A session whose account must change its password (users.must_change_password:
 * the initial admin account, an account found on the default password, or a
 * password an admin or the recovery CLI set) is refused here, before any role
 * gate, with 403 PASSWORD_CHANGE_REQUIRED. It is answered directly rather than
 * thrown, so the requests the UI keeps making write no application_errors row
 * and no "API Error" line. The flag is read from the user row on every request,
 * so it restricts every session of the account at once, old ones included.
 * Only the routes in routeInventory.test.ts PASSWORD_CHANGE_ALLOWED use
 * authenticateAllowingPasswordChange instead.
 */
export const authenticate = async function authenticate(req: Request, res: Response, next: NextFunction) {
  try {
    const user = await sessionUser(req);
    attachUser(req, user);
    if (req.user!.mustChangePassword) {
      res.status(403).json(passwordChangeRequiredBody(req.user!.passwordChangeReason));
      return;
    }
    next();
  } catch (error) {
    next(error);
  }
};

/**
 * The same checks as authenticate, without the password-change refusal. Only
 * for the routes a restricted session may call (routeInventory.test.ts
 * PASSWORD_CHANGE_ALLOWED): GET /api/auth/me, PUT /api/auth/me/password and
 * POST /api/auth/logout. A new one needs a reason it can't be used to get
 * around the change.
 */
export async function authenticateAllowingPasswordChange(req: Request, _res: Response, next: NextFunction) {
  try {
    attachUser(req, await sessionUser(req));
    next();
  } catch (error) {
    next(error);
  }
}

/**
 * Role-based authorization middleware
 * Requires specific roles to access route
 */
export const authorize = (...allowedRoles: ('admin' | 'analyst' | 'viewer' | 'operator')[]) => {
  // Named so routeInventory.test.ts can tell a router.use() gate from a handler.
  return function authorizeRoles(req: Request, _res: Response, next: NextFunction) {
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
