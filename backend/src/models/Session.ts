import { query } from '../config/database';
import crypto from 'crypto';

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

  static async findByToken(token: string): Promise<Session | null> {
    const result = await query(
      `SELECT * FROM sessions WHERE token = $1 AND expires_at > NOW()`,
      [token]
    );
    return result.rows[0] || null;
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
