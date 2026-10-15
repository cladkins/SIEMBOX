/**
 * Recognized browsers: the escape hatch against sign-in lockouts.
 *
 * Every full sign-in hands the browser a token (32 random bytes, base64url),
 * which the SPA keeps per username and sends with later sign-ins. Only its
 * sha256 is stored. A sign-in that presents a valid token for that username
 * is counted against the browser's own key (br:<id>) instead of the account's
 * and the network's (signInPolicy.ts), so someone guessing passwords for the
 * account, from anywhere, cannot lock its owner out of a browser they used
 * before.
 *
 * A token never skips the password or MFA: it only picks which counter
 * applies, so a stolen one buys its thief a single bucket of guesses. It is
 * valid for 90 days from its last successful use, touched (not rotated) on
 * each, and dropped after 20 consecutive failures, on a password change or
 * reset, with the user, or when the user has more than 20.
 */
import crypto from 'node:crypto';
import { query } from '../../config/database';
import { logger } from '../../utils/logger';
import { toInet } from '../audit/auditService';

/** A token stays valid this long after its last successful sign-in. */
export const BROWSER_TOKEN_DAYS = 90;
/** Each user keeps at most this many; the least recently used go first. */
export const MAX_BROWSERS_PER_USER = 20;

export interface RecognizedBrowser {
  /** recognized_browsers.id (BIGSERIAL, as text). */
  id: string;
  userId: number;
}

export function newBrowserToken(): string {
  return crypto.randomBytes(32).toString('base64url');
}

export function hashBrowserToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * The browser a token belongs to, if it is valid for this username. The same
 * query runs whether or not the username exists, so it says nothing about
 * that. A database error is logged and treated as "not recognized".
 */
export async function findRecognizedBrowser(token: string, username: string): Promise<RecognizedBrowser | null> {
  try {
    const res = await query(
      `SELECT rb.id::text AS id, rb.user_id
         FROM recognized_browsers rb
         JOIN users u ON u.id = rb.user_id
        WHERE rb.token_hash = $1 AND u.username = $2
          AND rb.last_used_at > NOW() - $3::int * INTERVAL '1 day'`,
      [hashBrowserToken(token), username, BROWSER_TOKEN_DAYS]
    );
    const row = res.rows[0];
    return row ? { id: row.id, userId: Number(row.user_id) } : null;
  } catch (error) {
    logger.error('Recognized-browser lookup failed; treating the browser as new', {
      error: error instanceof Error ? error.message : String(error),
    });
    return null;
  }
}

/**
 * After a full sign-in: touch the browser's token when it presented a valid
 * one (and return it unchanged), otherwise issue a new token. Returns null if
 * that fails (the sign-in still succeeds, the browser just stays new).
 */
export async function issueOrTouchBrowser(params: {
  userId: number;
  browser: RecognizedBrowser | null;
  token?: string;
  ip: string | null;
  userAgent: string | null;
  /**
   * The password hash the sign-in checked: a new browser is recorded only
   * while it is still the account's, so a password change or reset that
   * landed meanwhile (which forgets every browser) leaves none behind.
   */
  passwordHash?: string;
}): Promise<string | null> {
  const ip = toInet(params.ip);
  const agent = params.userAgent ? params.userAgent.slice(0, 256) : null;
  try {
    if (params.browser && params.token && params.browser.userId === params.userId) {
      const touched = await query(
        `UPDATE recognized_browsers SET last_used_at = NOW(), last_ip = $3, user_agent = $4
          WHERE id = $1 AND user_id = $2 RETURNING id`,
        [params.browser.id, params.userId, ip, agent]
      );
      if ((touched.rowCount ?? 0) > 0) return params.token;
    }
    const token = newBrowserToken();
    const inserted = await query(
      `INSERT INTO recognized_browsers (user_id, token_hash, last_ip, user_agent)
       SELECT id, $2, $3, $4 FROM users WHERE id = $1 AND ($5::text IS NULL OR password_hash = $5) FOR SHARE`,
      [params.userId, hashBrowserToken(token), ip, agent, params.passwordHash ?? null]
    );
    if ((inserted.rowCount ?? 0) === 0) return null;
    await query(
      `DELETE FROM recognized_browsers
        WHERE user_id = $1
          AND id NOT IN (SELECT id FROM recognized_browsers WHERE user_id = $1
                          ORDER BY last_used_at DESC, id DESC LIMIT $2)`,
      [params.userId, MAX_BROWSERS_PER_USER]
    );
    return token;
  } catch (error) {
    logger.error('Could not record a recognized browser', {
      userId: params.userId,
      error: error instanceof Error ? error.message : String(error),
    });
    return null;
  }
}

/** Forget every browser of a user (password change or reset). Returns how many. */
export async function revokeBrowsersForUser(userId: number): Promise<number> {
  const res = await query('DELETE FROM recognized_browsers WHERE user_id = $1', [userId]);
  return res.rowCount ?? 0;
}

/** Forget one browser (too many failures from it). */
export async function revokeBrowser(id: string): Promise<boolean> {
  const res = await query('DELETE FROM recognized_browsers WHERE id = $1', [id]);
  return (res.rowCount ?? 0) > 0;
}

/** Housekeeping: browsers not used for 90 days. */
export async function deleteStaleBrowsers(): Promise<number> {
  const res = await query(
    `DELETE FROM recognized_browsers WHERE last_used_at < NOW() - $1::int * INTERVAL '1 day'`,
    [BROWSER_TOKEN_DAYS]
  );
  return res.rowCount ?? 0;
}

/** How many browsers each user has (the CLI's status). */
export async function countBrowsers(userId: number): Promise<number> {
  const res = await query('SELECT COUNT(*)::int AS n FROM recognized_browsers WHERE user_id = $1', [userId]);
  return Number(res.rows[0]?.n ?? 0);
}
