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
      `SELECT id, username, email, role, enabled, mfa_enabled, last_login, created_at, updated_at
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
    const { password_hash, mfa_secret, mfa_recovery_codes, ...safeUser } = user;
    return safeUser as UserSafe;
  }

  // --- MFA -----------------------------------------------------------------

  /** Store the (encrypted) TOTP secret as a PENDING enrollment (not yet enabled). */
  static async setMfaPending(id: number, encryptedSecret: string): Promise<void> {
    await query(
      `UPDATE users SET mfa_secret = $1, mfa_enabled = FALSE, mfa_recovery_codes = NULL, updated_at = NOW()
       WHERE id = $2`,
      [encryptedSecret, id]
    );
  }

  /** Activate MFA and store the recovery-code hashes. */
  static async enableMfa(id: number, recoveryHashes: string[]): Promise<void> {
    await query(
      `UPDATE users SET mfa_enabled = TRUE, mfa_recovery_codes = $1, updated_at = NOW() WHERE id = $2`,
      [JSON.stringify(recoveryHashes), id]
    );
  }

  /** Replace the stored recovery-code hashes (e.g. after consuming one). */
  static async setRecoveryCodes(id: number, recoveryHashes: string[]): Promise<void> {
    await query(`UPDATE users SET mfa_recovery_codes = $1, updated_at = NOW() WHERE id = $2`, [
      JSON.stringify(recoveryHashes),
      id,
    ]);
  }

  /** Fully disable MFA and clear all secrets/recovery codes. */
  static async disableMfa(id: number): Promise<void> {
    await query(
      `UPDATE users SET mfa_enabled = FALSE, mfa_secret = NULL, mfa_recovery_codes = NULL, updated_at = NOW()
       WHERE id = $1`,
      [id]
    );
  }
}
