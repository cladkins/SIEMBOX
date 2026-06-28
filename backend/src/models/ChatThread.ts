/**
 * AI Analyst chat persistence — per-user threads (chat_sessions) and their
 * user/assistant messages (chat_messages). Every accessor is scoped by user_id
 * so a user can only ever read or mutate their own threads.
 */
import { query } from '../config/database';

export interface ChatSession {
  id: number;
  user_id: number;
  title: string;
  created_at: string;
  updated_at: string;
}

export interface ChatMessageRow {
  id: number;
  session_id: number;
  role: 'user' | 'assistant';
  content: string;
  trace: any | null;
  created_at: string;
}

function cleanTitle(t: string | undefined | null, fallback = 'New chat'): string {
  const s = (t || '').trim().replace(/\s+/g, ' ');
  return s ? s.slice(0, 120) : fallback;
}

export class ChatThreadModel {
  static async createSession(userId: number, title?: string): Promise<ChatSession> {
    const r = await query(
      `INSERT INTO chat_sessions (user_id, title) VALUES ($1, $2) RETURNING *`,
      [userId, cleanTitle(title)]
    );
    return r.rows[0];
  }

  static async listSessions(userId: number, limit = 50): Promise<ChatSession[]> {
    const r = await query(
      `SELECT id, user_id, title, created_at, updated_at
         FROM chat_sessions WHERE user_id = $1
        ORDER BY updated_at DESC LIMIT $2`,
      [userId, Math.min(Math.max(limit, 1), 200)]
    );
    return r.rows;
  }

  static async getSession(id: number, userId: number): Promise<ChatSession | null> {
    const r = await query(`SELECT * FROM chat_sessions WHERE id = $1 AND user_id = $2`, [id, userId]);
    return r.rows[0] || null;
  }

  /** Messages for a session the user owns (returns [] if not owned/found). */
  static async getMessages(sessionId: number, userId: number): Promise<ChatMessageRow[]> {
    const r = await query(
      `SELECT m.id, m.session_id, m.role, m.content, m.trace, m.created_at
         FROM chat_messages m
         JOIN chat_sessions s ON s.id = m.session_id
        WHERE m.session_id = $1 AND s.user_id = $2
        ORDER BY m.created_at ASC, m.id ASC`,
      [sessionId, userId]
    );
    return r.rows;
  }

  static async addMessage(
    sessionId: number,
    role: 'user' | 'assistant',
    content: string,
    trace?: any
  ): Promise<ChatMessageRow> {
    const r = await query(
      `INSERT INTO chat_messages (session_id, role, content, trace) VALUES ($1, $2, $3, $4) RETURNING *`,
      [sessionId, role, content, trace ? JSON.stringify(trace) : null]
    );
    await query(`UPDATE chat_sessions SET updated_at = NOW() WHERE id = $1`, [sessionId]);
    return r.rows[0];
  }

  static async renameSession(id: number, userId: number, title: string): Promise<ChatSession | null> {
    const r = await query(
      `UPDATE chat_sessions SET title = $3, updated_at = NOW() WHERE id = $1 AND user_id = $2 RETURNING *`,
      [id, userId, cleanTitle(title, 'Untitled')]
    );
    return r.rows[0] || null;
  }

  static async deleteSession(id: number, userId: number): Promise<boolean> {
    const r = await query(`DELETE FROM chat_sessions WHERE id = $1 AND user_id = $2`, [id, userId]);
    return (r.rowCount || 0) > 0;
  }
}
