#!/usr/bin/env node
/**
 * Sign-in recovery from the command line, for when the web UI can't be used
 * (every admin locked out, a forgotten password, a lost authenticator):
 *
 *   docker exec siembox-backend node dist/scripts/auth-admin.js <command>
 *   npm run auth-admin -- <command>
 *
 * Commands:
 *   status [username]          paused and recently failing sign-in counters
 *                              (for a user, also the paused networks holding
 *                              them back)
 *   unlock <username>          clear every counter of an account
 *   unlock --network <ip>      clear every counter of a network: an address
 *                              (IPv6: its /64), an IPv6 /64 as status prints
 *                              it, or 'unknown'
 *   unlock --all               clear every counter
 *   reset-password <username>  set a random 20-character password (printed
 *                              once), sign the account out everywhere, forget
 *                              its browsers and clear its counters; the
 *                              account must choose its own password at the
 *                              next sign-in (MFA, if on, is still asked first)
 *   disable-mfa <username>     turn MFA off for an account
 *
 * There is no command that clears a required password change: only changing
 * the password does (docs/operations/TROUBLESHOOTING.md has the SQL last
 * resort).
 *
 * It is a separate process that talks to Postgres, where the counters live,
 * so its changes take effect at once in the running backend. Every change
 * writes an audit row with no user and details.by = 'cli'.
 */
import './cliLogLevel';
import crypto from 'node:crypto';
import { UserModel, type User } from '../models/User';
import { LoginThrottleModel, type NetworkHold, type ThrottleRow } from '../models/LoginThrottle';
import { auditAuth } from '../services/auth/authEvents';
import { revokeAccountAccess } from '../services/auth/signInService';
import { countBrowsers } from '../services/auth/recognizedBrowsers';
import { signInSettings, usernameHash } from '../services/auth/signInPolicy';
import { parseSignInNetwork } from '../net/clientAddress';
import { closePools } from '../config/database';

export interface Io {
  out: (line: string) => void;
  err: (line: string) => void;
}

const defaultIo: Io = {
  out: (line) => process.stdout.write(`${line}\n`),
  err: (line) => process.stderr.write(`${line}\n`),
};

const USAGE = [
  'Usage: auth-admin <command>',
  '  status [username]          paused and recently failing sign-in counters',
  '                             (for a user, also the paused networks holding them back)',
  '  unlock <username>          clear every sign-in counter of an account',
  '  unlock --network <net>     clear every counter of a network: an IP address, an IPv6 /64',
  "                             as status prints it, or 'unknown' (requests without an address)",
  '  unlock --all               clear every counter',
  '  reset-password <username>  set a random password (printed once), sign out everywhere;',
  '                             a new password must be chosen at the next sign-in',
  '  disable-mfa <username>     turn MFA off for an account',
].join('\n');

/** Unambiguous characters (no 0/O, 1/l/I). */
const PASSWORD_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';

export function randomPassword(length = 20): string {
  let out = '';
  for (let i = 0; i < length; i++) out += PASSWORD_ALPHABET[crypto.randomInt(PASSWORD_ALPHABET.length)];
  return out;
}

function describeRow(row: ThrottleRow): string {
  const account = row.username ?? (row.scope === 'aip' || row.scope === 'acct' ? 'unknown username' : '-');
  const pause = row.paused_seconds > 0 ? `paused ${row.paused_seconds}s` : 'not paused';
  const label = signInSettings().scopes[row.scope]?.label ?? row.scope;
  return `${label.padEnd(42)} ${account.padEnd(20)} ${(row.network ?? '-').padEnd(24)} failures ${String(row.failures).padStart(3)}  ${pause}`;
}

/**
 * A paused network holding the user back: its row, then why their own
 * counters read "not paused" while they are refused (signInPolicy.ts
 * refusingPauses), and what lets them in.
 */
function describeHold(hold: NetworkHold, username: string): string[] {
  return [
    describeRow(hold),
    `  holds ${username} back for ${hold.held_seconds}s more (they failed from this network ` +
      `${hold.since_failure_seconds}s ago); 'unlock ${username}' lets them in, the network stays paused`,
  ];
}

/** 'yes (default, since 2026-10-14T09:30:00.000Z)' or 'no'. */
function describePasswordChange(user: User): string {
  if (user.must_change_password !== true) return 'no';
  const since = user.must_change_password_since ? new Date(user.must_change_password_since).toISOString() : 'unknown';
  return `yes (${user.must_change_password_reason ?? 'unknown reason'}, since ${since})`;
}

async function findUser(username: string | undefined, io: Io): Promise<User | null> {
  if (!username) {
    io.err(USAGE);
    return null;
  }
  const user = await UserModel.findByUsername(username);
  if (!user) io.err(`No user named "${username}".`);
  return user;
}

/** Run one command; resolves to the process exit code. */
export async function main(argv: string[], io: Io = defaultIo): Promise<number> {
  const [command, ...args] = argv;
  switch (command) {
    case 'status': {
      const user = args[0] ? await findUser(args[0], io) : null;
      if (args[0] && !user) return 1;
      const rows = await LoginThrottleModel.listActive({ limit: 500, userId: user?.id });
      // A network row has no user, so listActive({ userId }) leaves out the
      // paused networks that refuse this user (as the Users page lists them).
      const holds = user ? await LoginThrottleModel.networkHoldsForUser(user.id) : [];
      const settings = signInSettings();
      io.out(`Sign-in protection: ${settings.protection ? 'on' : 'OFF (LOGIN_PROTECTION=off)'}`);
      if (user) {
        io.out(
          `${user.username}: ${user.enabled ? 'enabled' : 'disabled'}, MFA ${user.mfa_enabled ? 'on' : 'off'}, ` +
            `${await countBrowsers(user.id)} recognized browser(s)`
        );
        io.out(`password change required: ${describePasswordChange(user)}`);
      }
      if (rows.length === 0 && holds.length === 0) {
        io.out('No paused or recently failing sign-in counters.');
      } else {
        for (const row of rows) io.out(describeRow(row));
        for (const hold of holds) for (const line of describeHold(hold, user?.username ?? '')) io.out(line);
      }
      return 0;
    }

    case 'unlock': {
      let cleared: number;
      let details: Record<string, unknown>;
      let target: number | null = null;
      if (args[0] === '--all') {
        cleared = await LoginThrottleModel.clearAll();
        details = { target: 'all' };
      } else if (args[0] === '--network') {
        const network = parseSignInNetwork(args[1]);
        if (!network) {
          io.err("unlock --network needs an IP address, an IPv6 /64 (2001:db8:1:2::/64) or 'unknown'.");
          return 1;
        }
        cleared = await LoginThrottleModel.clearByNetwork(network);
        details = { target: 'network', network };
      } else {
        const user = await findUser(args[0], io);
        if (!user) return 1;
        cleared = await LoginThrottleModel.clearByUser(user.id, usernameHash(user.username));
        details = { target: 'user', userId: user.id };
        target = user.id;
      }
      await auditAuth('auth.unlock', null, {
        userId: null,
        targetUserId: target,
        status: 200,
        details: { by: 'cli', ...details, cleared },
      });
      io.out(`Cleared ${cleared} sign-in counter(s).`);
      return 0;
    }

    case 'reset-password': {
      const user = await findUser(args[0], io);
      if (!user) return 1;
      const password = randomPassword();
      // Always temporary: whoever runs this is either the user, who changes it
      // at once, or hands it over.
      await UserModel.update(user.id, { password, requirePasswordChange: 'cli' });
      const revoked = await revokeAccountAccess(user);
      await auditAuth('user.password_reset', null, {
        userId: null,
        targetUserId: user.id,
        status: 200,
        details: {
          by: 'cli',
          sessionsRevoked: revoked.sessions,
          browsersRevoked: revoked.browsers,
          passwordChangeRequired: 'cli',
        },
      });
      io.out(`New password for ${user.username} (shown only now): ${password}`);
      io.out(
        `Signed out ${revoked.sessions} session(s), forgot ${revoked.browsers} browser(s), cleared ${revoked.counters} counter(s). ` +
          'They must choose a new password at their next sign-in (MFA, if on, is still asked first).'
      );
      return 0;
    }

    case 'disable-mfa': {
      const user = await findUser(args[0], io);
      if (!user) return 1;
      if (!user.mfa_enabled) {
        io.out(`MFA is already off for ${user.username}.`);
        return 0;
      }
      await UserModel.disableMfa(user.id);
      await LoginThrottleModel.clearByKey(`mfa:${user.id}`);
      await auditAuth('auth.mfa.disabled', null, {
        userId: null,
        targetUserId: user.id,
        status: 200,
        details: { by: 'cli' },
      });
      io.out(`MFA disabled for ${user.username}. They can enroll again under Settings -> Account.`);
      return 0;
    }

    default:
      io.err(USAGE);
      return command === undefined || command === 'help' || command === '--help' ? 0 : 1;
  }
}

if (require.main === module) {
  void (async () => {
    let code = 1;
    try {
      code = await main(process.argv.slice(2));
    } catch (error) {
      process.stderr.write(`auth-admin failed: ${error instanceof Error ? error.message : String(error)}\n`);
    }
    await closePools();
    process.exit(code);
  })();
}
