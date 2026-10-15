/**
 * The default-password alert (siembox-auth, trigger default-password): an
 * account was found on SIEMBox's default password "changeme", flagged by the
 * migrate runner's scan (services/auth/defaultCredentials.ts) or at a correct
 * sign-in with it (routes/auth.ts, step 8). Critical for an admin, high
 * otherwise; one per flag (the event id is keyed on the account and when it was
 * flagged), so restarts and repeated sign-ins raise nothing new.
 *
 * Kept apart from defaultCredentials.ts so the migrate runner doesn't load the
 * notification and AI triage services: the server raises these at boot
 * (raiseDefaultPasswordAlerts) and at sign-in.
 */
import { query } from '../../config/database';
import { logger } from '../../utils/logger';
import type { User } from '../../models/User';
import type { AuthRequestContext } from './authEvents';
import { raiseAuthAlert } from './authAlerts';
import { SHIPPED_DEFAULT_PASSWORD } from './passwordChange';

/**
 * The alert for one account. `ctx` is the sign-in's that found it, or null at
 * startup. Never rejects.
 */
export function raiseDefaultPasswordAlert(
  user: Pick<User, 'id' | 'username' | 'role'>,
  since: Date,
  ctx: AuthRequestContext | null
): Promise<boolean> {
  const where = ctx ? `at a sign-in from ${ctx.ip ?? 'an unknown address'}` : 'at startup';
  return raiseAuthAlert({
    trigger: 'default-password',
    severity: user.role === 'admin' ? 'critical' : 'high',
    key: `dpw:${user.id}`,
    streakStartedAt: Math.floor(new Date(since).getTime() / 1000),
    title: `${user.username} uses SIEMBox's default password`,
    description:
      `The account ${user.username} was found with the default password "${SHIPPED_DEFAULT_PASSWORD}" (${where}). ` +
      'It must choose a new password before it can do anything else, but anyone who knows the default and reaches ' +
      `the web UI first can choose it. Sign in as ${user.username} now; if you can't, run ` +
      `auth-admin reset-password ${user.username}.`,
    matched: {
      trigger: 'default-password',
      username: user.username,
      user_id: user.id,
      found: ctx ? 'sign-in' : 'startup',
      ...(ctx ? { source_ip: ctx.ip, via: ctx.via } : {}),
    },
  });
}

/**
 * At server start: the alert for every account still flagged 'default' (by
 * migrate's scan, or by a sign-in whose alert a restart may have cut short).
 * Repeats are dropped by the alert's event id. Never rejects.
 */
export async function raiseDefaultPasswordAlerts(): Promise<number> {
  try {
    const flagged = await query(
      `SELECT id, username, role, must_change_password_since AS since FROM users
        WHERE must_change_password = TRUE AND must_change_password_reason = 'default' AND must_change_password_since IS NOT NULL
        ORDER BY id`
    );
    let raised = 0;
    for (const row of flagged.rows as Array<Pick<User, 'id' | 'username' | 'role'> & { since: Date }>) {
      if (await raiseDefaultPasswordAlert(row, row.since, null)) raised++;
    }
    return raised;
  } catch (error) {
    logger.warn('Default-password alerts could not be checked', {
      error: error instanceof Error ? error.message : String(error),
    });
    return 0;
  }
}
