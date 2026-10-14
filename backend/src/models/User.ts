import { query } from '../config/database';
import bcrypt from 'bcrypt';

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
}

export interface CreateUserParams {
  username: string;
  email: string;
  password: string;
  role?: 'admin' | 'analyst' | 'viewer' | 'operator';
  enabled?: boolean;
}

export class UserModel {
  static async create(params: CreateUserParams): Promise<UserSafe> {
    const passwordHash = await bcrypt.hash(params.password, 10);

    const result = await query(
      `INSERT INTO users (username, email, password_hash, role, enabled)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, username, email, role, enabled, last_login, created_at, updated_at`,
      [
        params.username,
        params.email,
        passwordHash,
        params.role ?? 'viewer',
        params.enabled ?? true,
      ]
    );

    return result.rows[0];
  }

  static async findById(id: number): Promise<User | null> {
    const result = await query('SELECT * FROM users WHERE id = $1', [id]);
    return result.rows[0] || null;
  }

  static async findByIdSafe(id: number): Promise<UserSafe | null> {
    const result = await query(
      `SELECT id, username, email, role, enabled, mfa_enabled, password_changed_at, last_login, created_at, updated_at
       FROM users WHERE id = $1`,
      [id]
    );
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
    const result = await query(
      `SELECT id, username, email, role, enabled, mfa_enabled, last_login, created_at, updated_at
       FROM users
       ORDER BY created_at DESC`
    );
    return result.rows;
  }

  static async update(
    id: number,
    params: Partial<CreateUserParams>
  ): Promise<UserSafe | null> {
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
      const passwordHash = await bcrypt.hash(params.password, 10);
      updates.push(`password_hash = $${paramIndex++}`);
      values.push(passwordHash);
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
       RETURNING id, username, email, role, enabled, last_login, created_at, updated_at`,
      values
    );

    return result.rows[0] || null;
  }

  /**
   * The user changing their own password: also records when
   * (password_changed_at), which an admin's reset or the recovery CLI don't.
   */
  static async changeOwnPassword(id: number, newPassword: string): Promise<void> {
    const passwordHash = await bcrypt.hash(newPassword, 10);
    await query(
      `UPDATE users SET password_hash = $2, password_changed_at = NOW(), updated_at = NOW() WHERE id = $1`,
      [id, passwordHash]
    );
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
