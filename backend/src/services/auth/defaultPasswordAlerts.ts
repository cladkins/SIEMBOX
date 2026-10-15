/**
 * The default-password alert (siembox-auth, trigger default-password): an
 * account was found on SIEMBox's default password "changeme", flagged by the
 * migrate runner's scan (services/auth/defaultCredentials.ts) or at a correct
 * sign-in with it (routes/auth.ts, step 8). Critical for an admin, high
 * otherwise; one per flag (the event id is keyed on the account and when it was
 * flagged), so restarts, repeated sign-ins and enabling the account again raise
 * nothing new.
 *
 * Raised once the flagged account can be signed in to: at boot for every
 * enabled one (raiseDefaultPasswordAlerts), when an admin enables a disabled
 * one (routes/users.ts), and at a sign-in with "changeme" (routes/auth.ts, which
 * also catches an account enabled outside the API).
 *
 * Kept apart from defaultCredentials.ts so the migrate runner doesn't load the
 * notification and AI triage services.
 */
import { query } from '../../config/database';
import { logger } from '../../utils/logger';
import type { User } from '../../models/User';
import type { AuthRequestContext } from './authEvents';
import { raiseAuthAlert } from './authAlerts';
import { SHIPPED_DEFAULT_PASSWORD } from './passwordChange';

/**
 * Where the flagged account was seen: at server start, at a sign-in with
 * "changeme" (`ctx` is that request's), or as an admin (`by`) enabled it.
 */
export type DefaultPasswordFinding =
  | { at: 'startup' }
  | { at: 'sign-in'; ctx: AuthRequestContext }
  | { at: 'enabled'; ctx: AuthRequestContext; by: string };

function whereFound(found: DefaultPasswordFinding): string {
  switch (found.at) {
    case 'startup':
      return 'at startup';
    case 'sign-in':
      return `at a sign-in from ${found.ctx.ip ?? 'an unknown address'}`;
    case 'enabled':
      return `when ${found.by} enabled it`;
  }
}

/** The alert for one account. Never rejects. */
export function raiseDefaultPasswordAlert(
  user: Pick<User, 'id' | 'username' | 'role'>,
  since: Date,
  found: DefaultPasswordFinding
): Promise<boolean> {
  const where = whereFound(found);
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
      `docker exec siembox-backend node dist/scripts/auth-admin.js reset-password ${user.username} ` +
      '(see "Locked out of SIEMBox" in docs/operations/TROUBLESHOOTING.md).',
    matched: {
      trigger: 'default-password',
      username: user.username,
      user_id: user.id,
      found: found.at,
      ...(found.at === 'startup' ? {} : { source_ip: found.ctx.ip, via: found.ctx.via }),
      ...(found.at === 'enabled' ? { by: found.by } : {}),
    },
  });
}

/**
 * At server start: the alert for every enabled account still flagged
 * 'default' (by migrate's scan, or by a sign-in whose alert a restart may have
 * cut short). A disabled one can't sign in, so nobody can choose its password
 * yet: it is alerted when an admin enables it (routes/users.ts). Repeats are
 * dropped by the alert's event id. `onlyUserIds` limits it (tests).
 * Never rejects.
 */
export async function raiseDefaultPasswordAlerts(opts: { onlyUserIds?: number[] } = {}): Promise<number> {
  try {
    const params: unknown[] = [];
    let only = '';
    if (opts.onlyUserIds) {
      params.push(opts.onlyUserIds);
      only = ' AND id = ANY($1)';
    }
    const flagged = await query(
      `SELECT id, username, role, must_change_password_since AS since FROM users
        WHERE enabled = TRUE AND must_change_password = TRUE AND must_change_password_reason = 'default'
          AND must_change_password_since IS NOT NULL${only}
        ORDER BY id`,
      params
    );
    let raised = 0;
    for (const row of flagged.rows as Array<Pick<User, 'id' | 'username' | 'role'> & { since: Date }>) {
      if (await raiseDefaultPasswordAlert(row, row.since, { at: 'startup' })) raised++;
    }
    return raised;
  } catch (error) {
    logger.warn('Default-password alerts could not be checked', {
      error: error instanceof Error ? error.message : String(error),
    });
    return 0;
  }
}
