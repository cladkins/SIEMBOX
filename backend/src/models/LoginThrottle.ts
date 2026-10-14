/**
 * Sign-in throttle counters in Postgres (table login_throttle, migration 038;
 * the policy is services/auth/signInPolicy.ts).
 *
 * An attempt is charged BEFORE its password or code is checked, under row
 * locks, and refunded if the check passes. So however many requests arrive at
 * once, a key lets exactly its threshold of checks through before it pauses:
 * the rest see the pause and are refused without a bcrypt call.
 *
 * reserve():
 *   BEGIN;
 *   one INSERT ... ON CONFLICT DO UPDATE ... RETURNING creates the missing rows
 *   and locks every row in key order (the DO UPDATE takes the lock, so a
 *   concurrent DELETE cannot slip in between, and two attempts sharing keys
 *   always lock them in the same order, so they cannot deadlock);
 *   if a key that refuses this attempt is paused: ROLLBACK, refuse with the
 *   longest wait (a paused network key refuses only usernames that failed
 *   from it in the last 15 minutes: signInPolicy.ts refusingPauses);
 *   otherwise charge each key (a streak 24 h old starts over, the threshold-th
 *   failure starts a pause, a key that is already paused keeps its pause as
 *   it is) and COMMIT.
 *
 * refund() undoes one charge: failures - 1, and the pause and timestamps go
 * back to what they were only if they still hold exactly what this attempt
 * wrote. The streak's start goes back only if no other attempt was charged
 * since (last_failure_at is still this one's): a wrong attempt that landed in
 * between keeps the streak this one started. Timestamps are compared as text:
 * a round trip through a JS Date loses the microseconds and the compare would
 * silently never match.
 *
 * Every decision uses the database's NOW() (as differences computed in SQL),
 * never Node's clock. Statements that touch several rows outside reserve()
 * lock them in key order too, or skip locked rows (housekeeping).
 *
 * Fail open: when a throttle statement fails (the table is missing or broken),
 * the attempt goes ahead unthrottled, with an ERROR log line and an entry on
 * the admin dashboard. Sign-in already needs Postgres; a broken throttle table
 * must not lock everyone out. Not when the database can't be reached or is out
 * of connections, though: reserve() then throws and the attempt is answered
 * with a 500 without a password check, so flooding the pool is no way around
 * the counters (the rest of the sign-in would have failed anyway).
 */
import type { PoolClient } from 'pg';
import { getClient, query } from '../config/database';
import { logger } from '../utils/logger';
import { ErrorLogService } from '../services/errors/errorLogService';
import {
  NETWORK_HOLD_SECONDS,
  longestPause,
  pauseSeconds,
  refusingPauses,
  retryAfterSeconds,
  signInSettings,
  streakEnded,
  type KeyState,
  type SignInScope,
  type SignInSettings,
  type ThrottleKeySpec,
} from '../services/auth/signInPolicy';

/** A key's counters, timestamps as Postgres text (see refund()). */
export interface KeySnapshot {
  failures: number;
  pauses: number;
  pausedUntil: string | null;
  firstFailureAt: string | null;
  lastFailureAt: string | null;
}

/** One key charged by a reservation. */
export interface Charge extends ThrottleKeySpec {
  /** The row as it was before this attempt. */
  before: KeySnapshot;
  /** The streak before this attempt was 24 h old (it started over). */
  streakEnded: boolean;
  /** The row as this attempt left it. */
  after: KeySnapshot;
  /**
   * This attempt started a pause (of pauseSeconds): never on a key that was
   * already paused (a network that let this username through).
   */
  pauseStarted: boolean;
  pauseSeconds: number;
  /**
   * How long this key now holds this attempt's username back, in seconds (0
   * when it doesn't): the pause it started, or what is left of the network
   * pause it was let through, a network's at most NETWORK_HOLD_SECONDS. A
   * failed check with any is answered with a 429 for the longest.
   */
  heldSeconds: number;
  /** Epoch seconds of the streak's first failure: one alert per streak (authAlerts.ts). */
  streakStartedAt: number;
}

export type Reservation =
  | { outcome: 'charged'; charges: Charge[] }
  | { outcome: 'paused'; key: string; scope: SignInScope; retryAfter: number }
  | { outcome: 'skipped'; reason: 'protection-off' | 'failed-open' };

/** A key's counters before a reset (a full success). */
export interface ResetKey {
  key: string;
  scope: SignInScope;
  failures: number;
  pauses: number;
  streakStartedAt: number | null;
}

/** A user's paused keys, for the Users page. */
export interface UserPauseSummary {
  /** When the last sign-in pause (any scope but pwc) ends, or null. */
  signInPausedUntil: string | null;
  /** The paused sign-in scopes (never pwc). */
  scopes: SignInScope[];
  /** When the pause on changing their own password ends, or null. */
  passwordChangePausedUntil: string | null;
}

/** One row of the admin page's table (and the CLI's status). */
export interface ThrottleRow {
  key: string;
  scope: SignInScope;
  user_id: number | null;
  username: string | null;
  network: string | null;
  failures: number;
  pauses: number;
  paused_until: string | null;
  paused_seconds: number;
  first_failure_at: string | null;
  last_failure_at: string | null;
  last_user_agent: string | null;
}

/** A paused network holding a user back (the CLI's status <user>). */
export interface NetworkHold extends ThrottleRow {
  /** Seconds it still refuses the user: what is left of the hold or of the network's pause, whichever ends first. */
  held_seconds: number;
  /** Seconds since the user last failed from that network. */
  since_failure_seconds: number;
}

/**
 * Who a paused network holds back (signInPolicy.ts refusingPauses): one row
 * per account+network key (a) linked to a user, with a failure in the last
 * NETWORK_HOLD_SECONDS ($1), whose network key (n) is paused. held_until is
 * when the network stops refusing that user: the end of the hold or of the
 * network's current pause, whichever comes first. The Users page and the
 * CLI's status both read it, so they agree.
 */
const NETWORK_HOLDS_SQL = `
  SELECT a.user_id, n.key AS network_key, a.last_failure_at,
         LEAST(n.paused_until, a.last_failure_at + $1 * INTERVAL '1 second') AS held_until
    FROM login_throttle a
    JOIN login_throttle n ON n.scope = 'ip' AND n.network IS NOT DISTINCT FROM a.network AND n.paused_until > NOW()
   WHERE a.scope = 'aip' AND a.user_id IS NOT NULL AND a.failures > 0
     AND a.last_failure_at > NOW() - $1 * INTERVAL '1 second'`;

interface LockedRow {
  key: string;
  scope: SignInScope;
  failures: number;
  pauses: number;
  paused_until: string | null;
  first_failure_at: string | null;
  last_failure_at: string | null;
  paused_ms: number | null;
  since_last_failure_s: number | null;
}

const DEADLOCK = '40P01';
const MAX_USER_AGENT = 256;

/**
 * SQLSTATE classes of a statement that failed on its own (missing table or
 * column, bad data, a constraint, a rolled-back transaction): the throttle is
 * broken, so sign-in fails open. Anything else (no SQLSTATE: the pool timed
 * out or the connection failed; 08 connection, 53 resources, 57 operator
 * intervention) means the database itself isn't available.
 */
const BROKEN_STATEMENT_CLASSES = new Set(['0A', '22', '23', '25', '40', '42', 'XX']);

export function throttleIsBroken(error: unknown): boolean {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === 'string' && /^[0-9A-Z]{5}$/.test(code) && BROKEN_STATEMENT_CLASSES.has(code.slice(0, 2));
}

function snapshot(row: Pick<LockedRow, 'failures' | 'pauses' | 'paused_until' | 'first_failure_at' | 'last_failure_at'>): KeySnapshot {
  return {
    failures: Number(row.failures),
    pauses: Number(row.pauses),
    pausedUntil: row.paused_until,
    firstFailureAt: row.first_failure_at,
    lastFailureAt: row.last_failure_at,
  };
}

function reportFailure(operation: string, error: unknown): void {
  logger.error(`Sign-in protection: ${operation} failed; sign-in continues without it`, {
    error: error instanceof Error ? error.message : String(error),
  });
  ErrorLogService.logBackgroundError('sign-in-protection', error, { dedupeKey: operation });
}

async function rollback(client: PoolClient): Promise<void> {
  try {
    await client.query('ROLLBACK');
  } catch {
    // the connection is released (and discarded on error) either way
  }
}

/** One reservation attempt; throws on any database error (reserve() retries a deadlock once). */
async function reserveOnce(keys: ThrottleKeySpec[], userAgent: string | null, settings: SignInSettings): Promise<Reservation> {
  const sorted = [...keys].sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  const client = await getClient();
  let released = false;
  try {
    await client.query('BEGIN');
    const locked = await client.query<LockedRow>(
      `INSERT INTO login_throttle AS t (key, scope, user_id, network)
       SELECT k.key, k.scope, k.user_id, k.network
         FROM unnest($1::text[], $2::text[], $3::int[], $4::inet[]) AS k(key, scope, user_id, network)
        ORDER BY k.key
       ON CONFLICT (key) DO UPDATE SET user_id = EXCLUDED.user_id, updated_at = t.updated_at
       RETURNING key, scope, failures, pauses,
                 paused_until::text AS paused_until,
                 first_failure_at::text AS first_failure_at,
                 last_failure_at::text AS last_failure_at,
                 (EXTRACT(EPOCH FROM (paused_until - NOW())) * 1000)::float8 AS paused_ms,
                 EXTRACT(EPOCH FROM (NOW() - last_failure_at))::float8 AS since_last_failure_s`,
      [sorted.map((k) => k.key), sorted.map((k) => k.scope), sorted.map((k) => k.userId), sorted.map((k) => k.network)]
    );
    const rows = new Map(locked.rows.map((row) => [row.key, row]));

    const states = sorted.map((spec) => {
      const row = rows.get(spec.key)!;
      const ended = streakEnded(row.since_last_failure_s);
      return {
        key: spec.key,
        scope: spec.scope,
        remainingMs: ended ? 0 : Math.max(0, Number(row.paused_ms ?? 0)),
        failures: ended ? 0 : Number(row.failures),
        sinceLastFailureS: ended || row.since_last_failure_s === null ? null : Number(row.since_last_failure_s),
      };
    });
    const longest = longestPause(refusingPauses(states));
    if (longest) {
      await client.query('ROLLBACK');
      return { outcome: 'paused', key: longest.key, scope: longest.scope, retryAfter: retryAfterSeconds(longest.remainingMs) };
    }

    const charges: Charge[] = [];
    const chargedStates: Array<KeyState & { key: string }> = [];
    for (const [index, spec] of sorted.entries()) {
      const row = rows.get(spec.key)!;
      const before = snapshot(row);
      const ended = streakEnded(row.since_last_failure_s);
      const baseFailures = ended ? 0 : before.failures;
      const basePauses = ended ? 0 : before.pauses;
      const failures = baseFailures + 1;
      // A key let through while paused (a network, for a username that hasn't
      // failed from it lately) counts the failure but keeps its pause as it
      // is: the guesses a paused network lets through must not start a pause,
      // move its end or lengthen it. The first failure after it ends starts
      // the next one.
      const remainingMs = states[index].remainingMs;
      const pause = remainingMs > 0 ? 0 : pauseSeconds(settings.scopes[spec.scope], failures);
      const updated = await client.query(
        `UPDATE login_throttle SET
           failures = $2,
           pauses = $3,
           paused_until = CASE WHEN $4::int > 0 THEN NOW() + $4::int * INTERVAL '1 second'
                               WHEN $5::boolean THEN NULL ELSE paused_until END,
           first_failure_at = CASE WHEN $6::boolean OR first_failure_at IS NULL THEN NOW() ELSE first_failure_at END,
           last_failure_at = NOW(),
           last_user_agent = $7,
           updated_at = NOW()
         WHERE key = $1
         RETURNING failures, pauses,
                   paused_until::text AS paused_until,
                   first_failure_at::text AS first_failure_at,
                   last_failure_at::text AS last_failure_at,
                   EXTRACT(EPOCH FROM first_failure_at)::float8 AS streak_started_at`,
        [spec.key, failures, basePauses + (pause > 0 ? 1 : 0), pause, ended, baseFailures === 0, userAgent]
      );
      const after = updated.rows[0];
      charges.push({
        ...spec,
        before,
        streakEnded: ended,
        after: snapshot(after),
        pauseStarted: pause > 0,
        pauseSeconds: pause,
        heldSeconds: 0,
        streakStartedAt: Math.floor(Number(after.streak_started_at)),
      });
      chargedStates.push({
        key: spec.key,
        scope: spec.scope,
        remainingMs: pause > 0 ? pause * 1000 : remainingMs,
        failures,
        sinceLastFailureS: 0,
      });
    }
    // How long the keys now hold this attempt's username back: what a failed
    // check is answered with (a network's pause counts only NETWORK_HOLD_SECONDS of it).
    for (const held of refusingPauses(chargedStates)) {
      const charge = charges.find((entry) => entry.key === held.key);
      if (charge) charge.heldSeconds = retryAfterSeconds(held.remainingMs);
    }
    await client.query('COMMIT');
    return { outcome: 'charged', charges };
  } catch (error) {
    await rollback(client);
    client.release(error instanceof Error ? error : true);
    released = true;
    throw error;
  } finally {
    if (!released) client.release();
  }
}

export const LoginThrottleModel = {
  /**
   * Charge one failure to every key, unless one that refuses this attempt is
   * paused (then nothing changes and the answer is the longest wait). With
   * LOGIN_PROTECTION=off nothing is counted. A broken throttle statement lets
   * the attempt through; the database being unreachable or out of connections
   * throws (see the file comment).
   */
  async reserve(keys: ThrottleKeySpec[], userAgent?: string | null): Promise<Reservation> {
    const settings = signInSettings();
    if (!settings.protection) return { outcome: 'skipped', reason: 'protection-off' };
    if (keys.length === 0) return { outcome: 'charged', charges: [] };
    const agent = userAgent ? userAgent.slice(0, MAX_USER_AGENT) : null;
    for (let attempt = 1; ; attempt++) {
      try {
        return await reserveOnce(keys, agent, settings);
      } catch (error) {
        if ((error as { code?: string }).code === DEADLOCK && attempt < 2) continue;
        if (!throttleIsBroken(error)) throw error;
        reportFailure('reserve', error);
        return { outcome: 'skipped', reason: 'failed-open' };
      }
    }
  },

  /** Undo a reservation's charges: the password or code it held back was right. Never throws. */
  async refund(reservation: Reservation): Promise<void> {
    if (reservation.outcome !== 'charged') return;
    for (const charge of reservation.charges) {
      // A charge that started a streak goes back to an empty one.
      const fresh = charge.streakEnded || charge.before.failures === 0;
      const restore: KeySnapshot = fresh
        ? { failures: 0, pauses: 0, pausedUntil: null, firstFailureAt: null, lastFailureAt: charge.before.lastFailureAt }
        : charge.before;
      try {
        await query(
          `UPDATE login_throttle SET
             failures = GREATEST(failures - 1, 0),
             pauses = CASE WHEN paused_until::text IS NOT DISTINCT FROM $2 THEN $3 ELSE pauses END,
             paused_until = CASE WHEN paused_until::text IS NOT DISTINCT FROM $2 THEN $4::timestamptz ELSE paused_until END,
             first_failure_at = CASE WHEN first_failure_at::text IS NOT DISTINCT FROM $5
                                      AND last_failure_at::text IS NOT DISTINCT FROM $7
                                     THEN $6::timestamptz ELSE first_failure_at END,
             last_failure_at = CASE WHEN last_failure_at::text IS NOT DISTINCT FROM $7 THEN $8::timestamptz ELSE last_failure_at END,
             updated_at = NOW()
           WHERE key = $1`,
          [
            charge.key,
            charge.after.pausedUntil,
            restore.pauses,
            restore.pausedUntil,
            charge.after.firstFailureAt,
            restore.firstFailureAt,
            charge.after.lastFailureAt,
            restore.lastFailureAt,
          ]
        );
      } catch (error) {
        reportFailure('refund', error);
      }
    }
  },

  /**
   * Zero the keys after a full success and return what they held (one
   * statement per key, in key order). Never throws; a key with no row is left
   * out.
   */
  async reset(keys: string[]): Promise<ResetKey[]> {
    if (!signInSettings().protection) return [];
    const out: ResetKey[] = [];
    for (const key of [...new Set(keys)].sort()) {
      try {
        const res = await query(
          `WITH old AS (
             SELECT key, scope, failures, pauses, first_failure_at,
                    EXTRACT(EPOCH FROM (NOW() - last_failure_at))::float8 AS since_last_failure_s
               FROM login_throttle WHERE key = $1 FOR UPDATE
           )
           UPDATE login_throttle t
              SET failures = 0, pauses = 0, paused_until = NULL, first_failure_at = NULL, updated_at = NOW()
             FROM old
            WHERE t.key = old.key
           RETURNING old.key, old.scope, old.failures, old.pauses, old.since_last_failure_s,
                     EXTRACT(EPOCH FROM old.first_failure_at)::float8 AS streak_started_at`,
          [key]
        );
        const row = res.rows[0];
        if (!row) continue;
        const ended = streakEnded(row.since_last_failure_s);
        out.push({
          key: row.key,
          scope: row.scope,
          failures: ended ? 0 : Number(row.failures),
          pauses: ended ? 0 : Number(row.pauses),
          streakStartedAt: row.streak_started_at === null ? null : Math.floor(Number(row.streak_started_at)),
        });
      } catch (error) {
        reportFailure('reset', error);
      }
    }
    return out;
  },

  /** Milliseconds left on a key's pause, or 0. Never throws. */
  async remainingPauseMs(key: string): Promise<number> {
    if (!signInSettings().protection) return 0;
    try {
      const res = await query(
        `SELECT (EXTRACT(EPOCH FROM (paused_until - NOW())) * 1000)::float8 AS paused_ms
           FROM login_throttle WHERE key = $1`,
        [key]
      );
      return Math.max(0, Number(res.rows[0]?.paused_ms ?? 0));
    } catch (error) {
      reportFailure('pause check', error);
      return 0;
    }
  },

  /**
   * Keys that are paused, or that failed in the last 24 hours: paused ones
   * first, longest wait first. At most `limit` rows.
   */
  async listActive(opts: { limit?: number; userId?: number } = {}): Promise<ThrottleRow[]> {
    const limit = Math.min(Math.max(opts.limit ?? 500, 1), 500);
    const params: unknown[] = [limit];
    let filter = '';
    if (opts.userId !== undefined) {
      params.push(opts.userId);
      filter = 'AND t.user_id = $2';
    }
    const res = await query(
      `SELECT t.key, t.scope, t.user_id, u.username,
              abbrev(t.network) AS network,
              t.failures, t.pauses,
              t.paused_until, GREATEST(CEIL(EXTRACT(EPOCH FROM (t.paused_until - NOW()))), 0)::int AS paused_seconds,
              t.first_failure_at, t.last_failure_at, t.last_user_agent
         FROM login_throttle t
         LEFT JOIN users u ON u.id = t.user_id
        WHERE (t.paused_until > NOW() OR (t.failures > 0 AND t.last_failure_at > NOW() - INTERVAL '24 hours'))
              ${filter}
        ORDER BY (t.paused_until > NOW()) DESC NULLS LAST, t.paused_until DESC NULLS LAST, t.last_failure_at DESC NULLS LAST
        LIMIT $1`,
      params
    );
    return res.rows.map((row) => ({ ...row, paused_seconds: Number(row.paused_seconds ?? 0) }));
  },

  /**
   * For the Users page: each user with a paused key, or held back by a paused
   * network they failed from in the last NETWORK_HOLD_SECONDS (scope 'ip',
   * until the hold or the network's pause ends, whichever is first: the rule
   * of signInPolicy.ts refusingPauses). Sign-in pauses (when the last ends,
   * and which scopes) are kept apart from a paused password change (pwc),
   * which doesn't stop anyone signing in.
   */
  async pausedSummaryForUsers(): Promise<Map<number, UserPauseSummary>> {
    const res = await query(
      `WITH paused AS (
         SELECT user_id, scope::text AS scope, paused_until
           FROM login_throttle
          WHERE user_id IS NOT NULL AND paused_until > NOW()
         UNION ALL
         SELECT user_id, 'ip' AS scope, held_until AS paused_until FROM (${NETWORK_HOLDS_SQL}) holds
       )
       SELECT user_id,
              MAX(paused_until) FILTER (WHERE scope <> 'pwc') AS signin_until,
              COALESCE(array_agg(DISTINCT scope ORDER BY scope) FILTER (WHERE scope <> 'pwc'), '{}') AS scopes,
              MAX(paused_until) FILTER (WHERE scope = 'pwc') AS password_change_until
         FROM paused
        GROUP BY user_id`,
      [NETWORK_HOLD_SECONDS]
    );
    const iso = (value: unknown) => (value ? new Date(value as string).toISOString() : null);
    return new Map(
      res.rows.map((row) => [
        Number(row.user_id),
        {
          signInPausedUntil: iso(row.signin_until),
          scopes: row.scopes as SignInScope[],
          passwordChangePausedUntil: iso(row.password_change_until),
        },
      ])
    );
  },

  /**
   * The paused networks holding one user back (the rule the Users page
   * lists them by): each network key's row, with how long it still refuses
   * them and how long ago they failed from there. Their own account+network
   * key isn't paused then, so listActive alone shows nothing paused.
   */
  async networkHoldsForUser(userId: number): Promise<NetworkHold[]> {
    const res = await query(
      `SELECT n.key, n.scope, n.user_id, NULL::text AS username,
              abbrev(n.network) AS network,
              n.failures, n.pauses,
              n.paused_until, GREATEST(CEIL(EXTRACT(EPOCH FROM (n.paused_until - NOW()))), 0)::int AS paused_seconds,
              n.first_failure_at, n.last_failure_at, n.last_user_agent,
              GREATEST(CEIL(EXTRACT(EPOCH FROM (h.held_until - NOW()))), 0)::int AS held_seconds,
              GREATEST(FLOOR(EXTRACT(EPOCH FROM (NOW() - h.last_failure_at))), 0)::int AS since_failure_seconds
         FROM (${NETWORK_HOLDS_SQL} AND a.user_id = $2) h
         JOIN login_throttle n ON n.key = h.network_key
        ORDER BY held_seconds DESC, n.key`,
      [NETWORK_HOLD_SECONDS, userId]
    );
    return res.rows.map((row) => ({
      ...row,
      paused_seconds: Number(row.paused_seconds ?? 0),
      held_seconds: Number(row.held_seconds ?? 0),
      since_failure_seconds: Number(row.since_failure_seconds ?? 0),
    }));
  },

  /** Delete the rows a condition selects, locking them in key order first. Returns how many went. */
  async deleteWhere(where: string, params: unknown[]): Promise<number> {
    const res = await query(
      `DELETE FROM login_throttle
        WHERE key IN (SELECT key FROM login_throttle WHERE ${where} ORDER BY key FOR UPDATE)`,
      params
    );
    return res.rowCount ?? 0;
  },

  async clearByKey(key: string): Promise<number> {
    return LoginThrottleModel.deleteWhere('key = $1', [key]);
  },

  /**
   * Every key of one account: those linked to the user, plus the username's
   * keys from before the account existed (or after it was renamed).
   */
  async clearByUser(userId: number, usernameKeyHash?: string): Promise<number> {
    if (!usernameKeyHash) return LoginThrottleModel.deleteWhere('user_id = $1', [userId]);
    return LoginThrottleModel.deleteWhere(`user_id = $1 OR key = $2 OR key LIKE $3`, [
      userId,
      `acct:${usernameKeyHash}`,
      `aip:${usernameKeyHash}:%`,
    ]);
  },

  /** Every key of one network (an IPv4 address or an IPv6 /64), for any account. */
  async clearByNetwork(network: string): Promise<number> {
    if (network === 'unknown') return LoginThrottleModel.deleteWhere('network IS NULL AND scope IN ($1, $2)', ['aip', 'ip']);
    return LoginThrottleModel.deleteWhere('network = $1::inet', [network]);
  },

  async clearAll(): Promise<number> {
    return LoginThrottleModel.deleteWhere('TRUE', []);
  },

  /**
   * Housekeeping: rows that aren't paused and saw no failure (or other
   * change) for 24 hours. Rows another request holds are skipped, so this
   * never waits on, or deadlocks with, a sign-in.
   */
  async deleteIdle(): Promise<number> {
    const res = await query(
      `DELETE FROM login_throttle
        WHERE key IN (
          SELECT key FROM login_throttle
           WHERE (paused_until IS NULL OR paused_until < NOW())
             AND COALESCE(last_failure_at, updated_at) < NOW() - INTERVAL '24 hours'
           FOR UPDATE SKIP LOCKED)`
    );
    return res.rowCount ?? 0;
  },
};
