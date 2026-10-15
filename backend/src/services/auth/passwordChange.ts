/**
 * Passwords an account must change before it can do anything else, and the
 * rules every new password follows (routes/auth.ts, routes/users.ts,
 * middleware/auth.ts, services/auth/defaultCredentials.ts).
 *
 * An account is restricted (users.must_change_password, migration 039) when it
 * signs in with the password it was created with (the admin account the first
 * start makes), with the default password SIEMBox ships, or with a password
 * an admin or the recovery CLI set for it. While restricted, every one of its
 * sessions may only read its profile, change its password or sign out.
 *
 * Every comparison here is plain string equality: no regex runs on a password.
 */
import { MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH } from './signInPolicy';

/** The password SIEMBox ships as DEFAULT_ADMIN_PASSWORD's fallback (migrate.ts, compose files, .env.example). */
export const SHIPPED_DEFAULT_PASSWORD = 'changeme';

/**
 * Why an account must change its password:
 * - initial: the admin account the first start created (with DEFAULT_ADMIN_PASSWORD, or the default);
 * - default: found using the shipped default password, at startup or at a sign-in;
 * - admin: an administrator set its password (Users page, POST/PUT /api/users);
 * - cli: `auth-admin reset-password` set it.
 */
export type PasswordChangeReason = 'initial' | 'default' | 'admin' | 'cli';

export const PASSWORD_CHANGE_REASONS: readonly PasswordChangeReason[] = ['initial', 'default', 'admin', 'cli'];

export function isPasswordChangeReason(value: unknown): value is PasswordChangeReason {
  return typeof value === 'string' && (PASSWORD_CHANGE_REASONS as readonly string[]).includes(value);
}

/**
 * Exactly the shipped default. Only ever called with a password bcrypt has
 * already accepted for the account (sign-in, step 8), so it tells the caller
 * nothing they don't know: what they typed, and that it worked.
 */
export function isShippedDefaultPassword(password: string): boolean {
  return password === SHIPPED_DEFAULT_PASSWORD;
}

/** The shipped default in any letter case: refused as a new password. */
function isDefaultInAnyCase(password: string): boolean {
  return password.length === SHIPPED_DEFAULT_PASSWORD.length && password.toLowerCase() === SHIPPED_DEFAULT_PASSWORD;
}

/**
 * A new password the user chose for themselves (PUT /api/auth/me/password):
 * its problem, or null. 8 to 1024 characters; not the default password in any
 * letter case; different from `current` when given.
 */
export function newPasswordProblem(password: unknown, current?: string): string | null {
  if (typeof password !== 'string' || password.length < MIN_PASSWORD_LENGTH || password.length > MAX_PASSWORD_LENGTH) {
    return `New password must be ${MIN_PASSWORD_LENGTH} to ${MAX_PASSWORD_LENGTH} characters`;
  }
  if (current !== undefined && password === current) return 'New password must be different from the current one';
  if (isDefaultInAnyCase(password)) return "The default password can't be used";
  return null;
}

/**
 * A password an administrator sets for an account (POST /api/users, PUT
 * /api/users/:id): its problem, or null. 8 to 1024 characters; not the default
 * password in any letter case.
 */
export function assignedPasswordProblem(password: unknown): string | null {
  if (typeof password !== 'string' || password.length < MIN_PASSWORD_LENGTH || password.length > MAX_PASSWORD_LENGTH) {
    return `Password must be ${MIN_PASSWORD_LENGTH} to ${MAX_PASSWORD_LENGTH} characters`;
  }
  if (isDefaultInAnyCase(password)) return "Password can't be the default password";
  return null;
}

const REASON_WORDS: Record<PasswordChangeReason, string> = {
  initial: 'this is the password the account was created with.',
  default: "this account uses SIEMBox's default password.",
  admin: 'an administrator set a temporary password for this account.',
  cli: 'the password was reset from the command line.',
};

export interface PasswordChangeRequiredBody {
  status: 'error';
  statusCode: 403;
  code: 'PASSWORD_CHANGE_REQUIRED';
  reason: PasswordChangeReason | null;
  message: string;
}

/** The 403 every request of a restricted session gets, except the few it may make (middleware/auth.ts). */
export function passwordChangeRequiredBody(reason: PasswordChangeReason | null): PasswordChangeRequiredBody {
  const known = isPasswordChangeReason(reason) ? reason : null;
  const why = known ? REASON_WORDS[known] : 'this account must choose a new password.';
  return {
    status: 'error',
    statusCode: 403,
    code: 'PASSWORD_CHANGE_REQUIRED',
    reason: known,
    message: `Choose a new password before doing anything else (PUT /api/auth/me/password): ${why}`,
  };
}
