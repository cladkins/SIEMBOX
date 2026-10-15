import { query } from '../config/database';
import crypto from 'crypto';
import type { User } from './User';

export interface Session {
  id: number;
  user_id: number;
  token: string;
  expires_at: Date;
  created_at: Date;
}

export class SessionModel {
  static async create(userId: number, expiresInHours: number = 24): Promise<Session> {
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + expiresInHours * 60 * 60 * 1000);

    const result = await query(
      `INSERT INTO sessions (user_id, token, expires_at)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [userId, token, expiresAt]
    );

    return result.rows[0];
  }

  /**
   * Sign-in's session: created only while the account's password hash is still
   * `passwordHash`, the one the sign-in just checked; null when it changed (or
   * the account is gone). The user row is share-locked, so a password change
   * or reset in progress (UserModel, which locks the row, deletes the sessions
   * and sets the new hash in one transaction) is waited for, and then the new
   * hash is seen: a sign-in with the old password that was still running when
   * the password changed never gets a session that outlives it.
   */
  static async createIfPasswordHash(userId: number, passwordHash: string, expiresInHours: number = 24): Promise<Session | null> {
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + expiresInHours * 60 * 60 * 1000);
    const result = await query(
      `INSERT INTO sessions (user_id, token, expires_at)
       SELECT id, $2, $3 FROM users WHERE id = $1 AND password_hash = $4 FOR SHARE
       RETURNING *`,
      [userId, token, expiresAt, passwordHash]
    );
    return result.rows[0] ?? null;
  }

  /**
   * The account of a valid session, read with the session in one statement
   * (middleware/auth.ts, the only session reader): one snapshot, so a password
   * change that lifts a restriction and deletes the sessions in one
   * transaction is seen either not at all (the session, still restricted) or
   * whole (no session). Two separate reads could see the session from before
   * and the account from after, and let a restricted session through.
   */
  static async findUserByToken(token: string): Promise<User | null> {
    const result = await query(
      `SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
        WHERE s.token = $1 AND s.expires_at > NOW()`,
      [token]
    );
    return result.rows[0] ?? null;
  }

  static async delete(token: string): Promise<boolean> {
    const result = await query('DELETE FROM sessions WHERE token = $1', [token]);
    return (result.rowCount || 0) > 0;
  }

  static async deleteExpired(): Promise<number> {
    const result = await query('DELETE FROM sessions WHERE expires_at <= NOW()');
    return result.rowCount || 0;
  }

  static async deleteAllForUser(userId: number): Promise<number> {
    const result = await query('DELETE FROM sessions WHERE user_id = $1', [userId]);
    return result.rowCount || 0;
  }
}
