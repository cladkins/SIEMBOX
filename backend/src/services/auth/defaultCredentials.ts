/**
 * The default admin account and the default password, at startup.
 *
 * The migrate runner (scripts/migrate.ts) calls, after every migration:
 *
 * 1. seedDefaultAdmin(): only when the users table is empty (a fresh install,
 *    or every account deleted), create `admin` with DEFAULT_ADMIN_PASSWORD
 *    ("changeme" when unset), already required to choose a new password at its
 *    first sign-in (reason 'initial'). It never touches an existing row, so
 *    deleting or renaming `admin` no longer brings it back with the bootstrap
 *    password on the next start, and a renamed `admin` that kept its email no
 *    longer stops the start on users_email_key.
 * 2. flagAdminsOnDefaultPassword(): every admin-role account not already
 *    required to change its password is checked against "changeme" (one bcrypt
 *    compare each); a match is flagged 'default', which restricts its open
 *    sessions at once. Only the publicly known default is checked: an upgraded
 *    admin still on a custom DEFAULT_ADMIN_PASSWORD is left alone. Other roles
 *    are caught at their next sign-in (routes/auth.ts, step 8).
 * 3. defaultPasswordBanner(): the "ADMIN SIGN-IN" lines, only while an admin
 *    account waits for its initial or default password to be changed.
 *
 * Neither ever clears a flag or overwrites a password, so re-running migrate
 * is harmless. The server raises the default-password alert at boot, or for a
 * disabled account when it is enabled (defaultPasswordAlerts.ts), because
 * notifications and AI triage belong to the server process; it dedupes on the
 * flag, so restarts raise nothing new.
 */
import bcrypt from 'bcrypt';
import { query } from '../../config/database';
import { logger } from '../../utils/logger';
import { UserModel } from '../../models/User';
import { auditAuth } from './authEvents';
import { MAX_PASSWORD_LENGTH } from './signInPolicy';
import { SHIPPED_DEFAULT_PASSWORD } from './passwordChange';

export const DEFAULT_ADMIN_USERNAME = 'admin';
export const DEFAULT_ADMIN_EMAIL = 'admin@siembox.local';

/**
 * Create the admin account when no account exists. Resolves to whether it
 * was created (false when the table has rows, or a concurrent start won).
 * Throws when DEFAULT_ADMIN_PASSWORD is longer than sign-in accepts.
 */
export async function seedDefaultAdmin(
  opts: { username?: string; email?: string } = {}
): Promise<{ created: boolean; userId: number | null }> {
  const username = opts.username ?? DEFAULT_ADMIN_USERNAME;
  const email = opts.email ?? DEFAULT_ADMIN_EMAIL;
  const existing = await query('SELECT EXISTS (SELECT 1 FROM users) AS has_users');
  if (existing.rows[0]?.has_users) return { created: false, userId: null };

  const password = process.env.DEFAULT_ADMIN_PASSWORD || SHIPPED_DEFAULT_PASSWORD;
  if (password.length > MAX_PASSWORD_LENGTH) {
    // Nothing derived from the password (not even its length) goes into the
    // message: it is logged here and again by migrate's error handler.
    const message =
      `DEFAULT_ADMIN_PASSWORD is longer than the ${MAX_PASSWORD_LENGTH} characters sign-in accepts, ` +
      'so the admin account could never sign in. Set a shorter DEFAULT_ADMIN_PASSWORD and start again.';
    logger.error(message);
    throw new Error(message);
  }
  const hash = await bcrypt.hash(password, 10);
  // No conflict target: a username or an email taken by a concurrent start is
  // a no-op, not an error.
  const inserted = await query(
    `INSERT INTO users (username, email, password_hash, role, must_change_password, must_change_password_reason, must_change_password_since)
     VALUES ($1, $2, $3, 'admin', TRUE, 'initial', NOW())
     ON CONFLICT DO NOTHING
     RETURNING id`,
    [username, email, hash]
  );
  const userId: number | undefined = inserted.rows[0]?.id;
  if (userId === undefined) return { created: false, userId: null };

  logger.info(`Created the admin account "${username}"; it must choose a new password at its first sign-in.`);
  await auditAuth('user.created', null, {
    userId: null,
    targetUserId: userId,
    status: 201,
    details: { by: 'seed', username, role: 'admin', passwordChangeRequired: 'initial' },
  });
  return { created: true, userId };
}

/** Whether `hash` is the hash of the shipped default (false for a hash bcrypt can't read). */
async function isDefaultHash(hash: unknown): Promise<boolean> {
  if (typeof hash !== 'string') return false;
  try {
    return await bcrypt.compare(SHIPPED_DEFAULT_PASSWORD, hash);
  } catch {
    return false;
  }
}

/**
 * Flag every admin-role account still on the default password that isn't
 * flagged already ('default'), and resolve to the ones this call flagged.
 * Disabled admins are included: flagging them is harmless, and right if they
 * are ever enabled again. They can't sign in meanwhile, so their WARN says
 * so instead of "sign in now", and the banner and the alert leave them out.
 * `onlyUserIds` limits the scan (tests).
 */
export async function flagAdminsOnDefaultPassword(
  opts: { onlyUserIds?: number[] } = {}
): Promise<Array<{ id: number; username: string; since: Date }>> {
  const params: unknown[] = [];
  let only = '';
  if (opts.onlyUserIds) {
    params.push(opts.onlyUserIds);
    only = ' AND id = ANY($1)';
  }
  const candidates = await query(
    `SELECT id, username, password_hash, enabled FROM users
      WHERE role = 'admin' AND must_change_password = FALSE${only}
      ORDER BY id`,
    params
  );
  const flagged: Array<{ id: number; username: string; since: Date }> = [];
  for (const row of candidates.rows as Array<{ id: number; username: string; password_hash: string; enabled: boolean }>) {
    if (!(await isDefaultHash(row.password_hash))) continue;
    // Compare-and-set on the hash: a password changed since the compare is never flagged.
    const since = await UserModel.requirePasswordChange(row.id, 'default', { ifHash: row.password_hash });
    if (!since) continue;
    flagged.push({ id: row.id, username: row.username, since });
    await auditAuth('auth.password.change_required', null, {
      userId: null,
      targetUserId: row.id,
      status: 200,
      details: { by: 'startup', reason: 'default' },
    });
    logger.warn(
      row.enabled
        ? `Account "${row.username}" still uses the default password "${SHIPPED_DEFAULT_PASSWORD}". Anyone who can reach ` +
            'the web UI can sign in and choose its password. Sign in now: SIEMBox asks for a new password before anything else.'
        : `Disabled account "${row.username}" uses the default password "${SHIPPED_DEFAULT_PASSWORD}"; ` +
            'it must choose a new one if it is ever enabled.'
    );
  }
  return flagged;
}

/**
 * The "ADMIN SIGN-IN" banner lines, or [] when no enabled admin account waits
 * for its initial or default password to be changed (a disabled one can't
 * sign in, so there is nothing to tell anyone to do). Never prints a
 * configured password; it names "changeme" only because that one is public.
 */
export async function defaultPasswordBanner(): Promise<string[]> {
  const waiting = await query(
    `SELECT username, must_change_password_reason AS reason FROM users
      WHERE role = 'admin' AND enabled = TRUE AND must_change_password = TRUE
        AND must_change_password_reason IN ('initial', 'default')
      ORDER BY id`
  );
  if (waiting.rows.length === 0) return [];
  const lines = ['==============================================='];
  for (const row of waiting.rows as Array<{ username: string; reason: 'initial' | 'default' }>) {
    lines.push(
      row.reason === 'initial'
        ? `ADMIN SIGN-IN: username "${row.username}". Password: the DEFAULT_ADMIN_PASSWORD the account was created ` +
            `with ("${SHIPPED_DEFAULT_PASSWORD}" if it was unset). SIEMBox asks for a new password at the first sign-in.`
        : `ADMIN SIGN-IN: username "${row.username}". Password: "${SHIPPED_DEFAULT_PASSWORD}", the default. ` +
            'SIEMBox asks for a new password at the next sign-in; sign in before anyone else does.'
    );
  }
  lines.push('===============================================');
  return lines;
}
