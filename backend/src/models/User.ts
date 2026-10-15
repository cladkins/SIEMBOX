import { query } from '../config/database';
import bcrypt from 'bcrypt';
import type { PasswordChangeReason } from '../services/auth/passwordChange';

export interface User {
  id: number;
  username: string;
  email: string;
  password_hash: string;
  role: 'admin' | 'analyst' | 'viewer' | 'operator';
  enabled: boolean;
  last_login: Date | null;
  created_at: Date;
  updated_at: Date;
  // Optional per-user TOTP MFA (additive; defaults to "no MFA").
  mfa_enabled?: boolean;
  /** Encrypted TOTP secret: JSON {encrypted, iv, authTag} or null. */
  mfa_secret?: string | null;
  /** bcrypt hashes of one-time recovery codes, or null. */
  mfa_recovery_codes?: string[] | null;
  /** The last TOTP time step accepted (each code works once), or null. */
  mfa_last_totp_step?: string | number | null;
  /** When the user last changed their own password (PUT /auth/me/password), or null. */
  password_changed_at?: Date | null;
  /**
   * The account must change its password before anything else (migration 039,
   * middleware/auth.ts). Undefined on a database migration 039 hasn't reached.
   */
  must_change_password?: boolean;
  must_change_password_reason?: PasswordChangeReason | null;
  must_change_password_since?: Date | null;
}

export interface UserSafe {
  id: number;
  username: string;
  email: string;
  role: 'admin' | 'analyst' | 'viewer' | 'operator';
  enabled: boolean;
  last_login: Date | null;
  created_at: Date;
  updated_at: Date;
  mfa_enabled?: boolean;
  password_changed_at?: Date | null;
  must_change_password?: boolean;
  must_change_password_reason?: PasswordChangeReason | null;
  must_change_password_since?: Date | null;
}

export interface CreateUserParams {
  username: string;
  email: string;
  password: string;
  role?: 'admin' | 'analyst' | 'viewer' | 'operator';
  enabled?: boolean;
  /**
   * Require a password change at the first sign-in, and why. Default null (no
   * change required): the API's default (routes/users.ts) is decided there.
   */
  requirePasswordChange?: PasswordChangeReason | null;
}

/**
 * What update() changes. A new password always comes with the decision
 * whether the account must change it again (`requirePasswordChange`: why, or
 * null for no): every caller that sets a password makes it, so none can leave
 * a temporary password unflagged, or clear the requirement, by forgetting to.
 */
export type UpdateUserParams = Omit<Partial<CreateUserParams>, 'password' | 'requirePasswordChange'> &
  (
    | { password: string; requirePasswordChange: PasswordChangeReason | null }
    | { password?: undefined; requirePasswordChange?: undefined }
  );

/** The columns every safe read and RETURNING list carries. */
const SAFE_COLUMNS =
  'id, username, email, role, enabled, mfa_enabled, password_changed_at, must_change_password, ' +
  'must_change_password_reason, must_change_password_since, last_login, created_at, updated_at';

export class UserModel {
  static async create(params: CreateUserParams): Promise<UserSafe> {
    const passwordHash = await bcrypt.hash(params.password, 10);
    const reason = params.requirePasswordChange ?? null;

    const result = await query(
      `INSERT INTO users (username, email, password_hash, role, enabled,
                          must_change_password, must_change_password_reason, must_change_password_since)
       VALUES ($1, $2, $3, $4, $5, $6::text IS NOT NULL, $6, CASE WHEN $6::text IS NULL THEN NULL ELSE NOW() END)
       RETURNING ${SAFE_COLUMNS}`,
      [
        params.username,
        params.email,
        passwordHash,
        params.role ?? 'viewer',
        params.enabled ?? true,
        reason,
      ]
    );

    return result.rows[0];
  }

  static async findById(id: number): Promise<User | null> {
    const result = await query('SELECT * FROM users WHERE id = $1', [id]);
    return result.rows[0] || null;
  }

  static async findByIdSafe(id: number): Promise<UserSafe | null> {
    const result = await query(`SELECT ${SAFE_COLUMNS} FROM users WHERE id = $1`, [id]);
    return result.rows[0] || null;
  }

  static async findByUsername(username: string): Promise<User | null> {
    const result = await query('SELECT * FROM users WHERE username = $1', [username]);
    return result.rows[0] || null;
  }

  static async findByEmail(email: string): Promise<User | null> {
    const result = await query('SELECT * FROM users WHERE email = $1', [email]);
    return result.rows[0] || null;
  }

  static async findAll(): Promise<UserSafe[]> {
    const result = await query(`SELECT ${SAFE_COLUMNS} FROM users ORDER BY created_at DESC`);
    return result.rows;
  }

  /**
   * Change an account. With a password (an admin's or the CLI's reset), the
   * same UPDATE sets or clears the password-change requirement as
   * `requirePasswordChange` says (a reason replaces any earlier one and its
   * date); without one, the requirement is left as it is.
   */
  static async update(id: number, params: UpdateUserParams): Promise<UserSafe | null> {
    const updates: string[] = [];
    const values: any[] = [];
    let paramIndex = 1;

    if (params.username !== undefined) {
      updates.push(`username = $${paramIndex++}`);
      values.push(params.username);
    }
    if (params.email !== undefined) {
      updates.push(`email = $${paramIndex++}`);
      values.push(params.email);
    }
    if (params.password !== undefined) {
      if (params.requirePasswordChange === undefined) {
        // A programming error: every caller that sets a password decides this.
        throw new Error('UserModel.update: a new password needs requirePasswordChange (a reason, or null)');
      }
      const passwordHash = await bcrypt.hash(params.password, 10);
      updates.push(`password_hash = $${paramIndex++}`);
      values.push(passwordHash);
      const reasonParam = `$${paramIndex++}::text`;
      updates.push(
        `must_change_password = (${reasonParam} IS NOT NULL)`,
        `must_change_password_reason = ${reasonParam}`,
        `must_change_password_since = CASE WHEN ${reasonParam} IS NULL THEN NULL ELSE NOW() END`
      );
      values.push(params.requirePasswordChange);
    }
    if (params.role !== undefined) {
      updates.push(`role = $${paramIndex++}`);
      values.push(params.role);
    }
    if (params.enabled !== undefined) {
      updates.push(`enabled = $${paramIndex++}`);
      values.push(params.enabled);
    }

    if (updates.length === 0) {
      return this.findByIdSafe(id);
    }

    updates.push(`updated_at = NOW()`);
    values.push(id);

    const result = await query(
      `UPDATE users SET ${updates.join(', ')}
       WHERE id = $${paramIndex}
       RETURNING ${SAFE_COLUMNS}`,
      values
    );

    return result.rows[0] || null;
  }

  /**
   * The user changing their own password: also records when
   * (password_changed_at), which an admin's reset or the recovery CLI don't,
   * and clears any password-change requirement in the same UPDATE. This is
   * the only way out of a requirement other than an admin's reset with
   * "require a change" off.
   */
  static async changeOwnPassword(id: number, newPassword: string): Promise<void> {
    const passwordHash = await bcrypt.hash(newPassword, 10);
    await query(
      `UPDATE users SET password_hash = $2, password_changed_at = NOW(),
              must_change_password = FALSE, must_change_password_reason = NULL, must_change_password_since = NULL,
              updated_at = NOW()
        WHERE id = $1`,
      [id, passwordHash]
    );
  }

  /**
   * Require the account to change its password, for `reason`: only when it
   * isn't required already (an earlier reason and date are kept), and with
   * `ifHash` only while the password hash is still that one (the startup scan
   * compares first, so a password changed in between is never flagged).
   * Resolves to when it was set, or null when nothing changed. Never clears
   * the requirement.
   */
  static async requirePasswordChange(
    id: number,
    reason: PasswordChangeReason,
    opts: { ifHash?: string } = {}
  ): Promise<Date | null> {
    const params: unknown[] = [id, reason];
    let hashCondition = '';
    if (opts.ifHash !== undefined) {
      params.push(opts.ifHash);
      hashCondition = ' AND password_hash = $3';
    }
    const result = await query(
      `UPDATE users SET must_change_password = TRUE, must_change_password_reason = $2,
              must_change_password_since = NOW(), updated_at = NOW()
        WHERE id = $1 AND must_change_password = FALSE${hashCondition}
        RETURNING must_change_password_since`,
      params
    );
    return result.rows[0]?.must_change_password_since ?? null;
  }

  static async delete(id: number): Promise<boolean> {
    const result = await query('DELETE FROM users WHERE id = $1', [id]);
    return (result.rowCount || 0) > 0;
  }

  static async updateLastLogin(id: number): Promise<void> {
    await query('UPDATE users SET last_login = NOW() WHERE id = $1', [id]);
  }

  static async verifyPassword(user: User, password: string): Promise<boolean> {
    return bcrypt.compare(password, user.password_hash);
  }

  static removeSensitiveData(user: User): UserSafe {
    // Strip the password hash AND the MFA secret/recovery hashes; keep the
    // mfa_enabled flag so the UI can show MFA state.
    // eslint-disable-next-line @typescript-eslint/no-unused-vars -- destructured only to omit them from safeUser
    const { password_hash, mfa_secret, mfa_recovery_codes, mfa_last_totp_step, ...safeUser } = user;
    return safeUser as UserSafe;
  }

  // --- MFA -----------------------------------------------------------------

  /** Store the (encrypted) TOTP secret as a PENDING enrollment (not yet enabled). */
  static async setMfaPending(id: number, encryptedSecret: string): Promise<void> {
    await query(
      `UPDATE users SET mfa_secret = $1, mfa_enabled = FALSE, mfa_recovery_codes = NULL,
              mfa_last_totp_step = NULL, updated_at = NOW()
       WHERE id = $2`,
      [encryptedSecret, id]
    );
  }

  /**
   * Activate MFA and store the recovery-code hashes, only while the pending
   * enrollment whose secret the code was checked against (`pendingSecret`) is
   * still the user's and MFA is still off: true when it was enabled. `totpStep`
   * is the step of the code that proved the enrollment, so that code can't sign
   * in too (the step only ever moves forward).
   */
  static async enableMfa(id: number, recoveryHashes: string[], totpStep: number, pendingSecret: string): Promise<boolean> {
    const result = await query(
      `UPDATE users SET mfa_enabled = TRUE, mfa_recovery_codes = $1,
              mfa_last_totp_step = GREATEST(COALESCE(mfa_last_totp_step, 0), $3), updated_at = NOW()
       WHERE id = $2 AND mfa_enabled IS NOT TRUE AND mfa_secret = $4`,
      [JSON.stringify(recoveryHashes), id, totpStep, pendingSecret]
    );
    return (result.rowCount || 0) > 0;
  }

  /**
   * Accept TOTP time step `step` for the user, once: true only if no step at
   * or after it was accepted before. Two requests with the same code race on
   * this one UPDATE, and only one wins.
   */
  static async claimTotpStep(id: number, step: number): Promise<boolean> {
    const result = await query(
      `UPDATE users SET mfa_last_totp_step = $2
       WHERE id = $1 AND (mfa_last_totp_step IS NULL OR mfa_last_totp_step < $2)`,
      [id, step]
    );
    return (result.rowCount || 0) > 0;
  }

  /**
   * Remove one recovery-code hash, by value, in one statement: true only for
   * the request that removed it, so a code can't be used twice at once.
   */
  static async consumeRecoveryCode(id: number, recoveryHash: string): Promise<boolean> {
    const result = await query(
      `UPDATE users SET mfa_recovery_codes = mfa_recovery_codes - $2::text, updated_at = NOW()
       WHERE id = $1 AND mfa_recovery_codes ? $2::text`,
      [id, recoveryHash]
    );
    return (result.rowCount || 0) > 0;
  }

  /** Fully disable MFA and clear all secrets/recovery codes. */
  static async disableMfa(id: number): Promise<void> {
    await query(
      `UPDATE users SET mfa_enabled = FALSE, mfa_secret = NULL, mfa_recovery_codes = NULL,
              mfa_last_totp_step = NULL, updated_at = NOW()
       WHERE id = $1`,
      [id]
    );
  }
}
