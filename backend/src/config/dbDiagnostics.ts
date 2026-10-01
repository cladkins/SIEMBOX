/**
 * Actionable hints for "can't reach Postgres" startup failures.
 *
 * The raw pg error ("connect ECONNREFUSED 127.0.0.1:5432") says nothing about
 * WHY the backend is dialing the wrong place, and the usual cause is a
 * deployment mistake, not a database fault: DB_HOST set to a loopback address
 * (`localhost` / `127.0.0.1`) while the backend runs on the Compose bridge
 * network. Inside the container that address is the container itself, so
 * nothing listens there, migrations fail, and Docker restarts the container in
 * a crash loop. Loopback is only correct with the optional `network_mode: host`
 * (SIEMBOX_HOST_NETWORKING=true), where Postgres is reached through its
 * 127.0.0.1:5432 host publish.
 *
 * Pure and dependency-free on purpose (no pg Pool import, no logger) so it is
 * unit-testable and safe to call from any startup path. Only the host and port
 * are ever put in a hint -- never the password or any other setting's value.
 */
import fs from 'fs';

export interface DbDiagnosticsContext {
  /** Environment to read DB_HOST / DB_PORT / SIEMBOX_HOST_NETWORKING from. Defaults to process.env. */
  env?: NodeJS.ProcessEnv;
  /** Whether this process runs inside a container. Defaults to probing for /.dockerenv or /run/.containerenv. */
  inContainer?: boolean;
}

/** True for hostnames/addresses that resolve to the machine (or container) itself. */
export function isLoopbackHost(host: string): boolean {
  const h = host.trim().toLowerCase();
  return h === 'localhost' || h === '::1' || h === '[::1]' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h);
}

function detectContainer(): boolean {
  try {
    return fs.existsSync('/.dockerenv') || fs.existsSync('/run/.containerenv');
  } catch {
    return false;
  }
}

/**
 * The connection error code. Node's address-family fallback wraps multi-address
 * failures (e.g. `localhost` resolving to both ::1 and 127.0.0.1) in an
 * AggregateError, so fall back to its first inner error when it has no code.
 */
function connectionErrorCode(err: unknown): string | undefined {
  const e = err as { code?: unknown; errors?: Array<{ code?: unknown }> } | null | undefined;
  if (!e) return undefined;
  if (typeof e.code === 'string' && e.code) return e.code;
  const inner = Array.isArray(e.errors) ? e.errors.find((x) => typeof x?.code === 'string') : undefined;
  return typeof inner?.code === 'string' ? inner.code : undefined;
}

/**
 * Returns a one-paragraph, human-actionable explanation for a database
 * connection failure, or null when the error isn't a connection-level failure
 * this module can say anything useful about (auth errors, SQL errors, ...).
 *
 * The target host/port come from the environment using the same defaults as
 * config/database.ts (DB_HOST=localhost, DB_PORT=5432).
 */
export function diagnoseDbConnectionError(err: unknown, ctx: DbDiagnosticsContext = {}): string | null {
  const code = connectionErrorCode(err);
  if (!code) return null;

  const env = ctx.env ?? process.env;
  const host = env.DB_HOST || 'localhost';
  const port = env.DB_PORT || '5432';
  const inContainer = ctx.inContainer ?? detectContainer();
  const hostNetworking = env.SIEMBOX_HOST_NETWORKING === 'true';

  switch (code) {
    case 'ECONNREFUSED': {
      if (!isLoopbackHost(host)) {
        return (
          `Postgres at ${host}:${port} refused the connection. Check that the database ` +
          `container/service is running and healthy (docker ps; docker logs <postgres container>) ` +
          `and that DB_HOST/DB_PORT are correct.`
        );
      }
      if (hostNetworking) {
        return (
          `Host networking is enabled (SIEMBOX_HOST_NETWORKING=true), so Postgres must be reachable ` +
          `on the host at ${host}:${port}. Check that the postgres container is running and healthy, ` +
          `that it publishes 127.0.0.1:${port}:5432 (see compose.prod.yaml), and that nothing else ` +
          `on the host already holds port ${port} (ss -ltnp 'sport = :${port}').`
        );
      }
      if (inContainer) {
        return (
          `DB_HOST is ${host}, a loopback address. Inside the backend container that is the ` +
          `container itself, not Postgres, so nothing is listening there. On the default bridge ` +
          `network set DB_HOST=postgres (the Compose service name) in the stack's environment/.env ` +
          `and redeploy the stack -- a plain container restart keeps the old environment. Loopback ` +
          `is only correct with the optional network_mode: host (SIEMBOX_HOST_NETWORKING=true), ` +
          `which also needs the compose edits described in DEPLOYMENT.md.`
        );
      }
      return `Nothing is listening on ${host}:${port}. Start PostgreSQL locally, or point DB_HOST/DB_PORT at it.`;
    }
    case 'ENOTFOUND':
    case 'EAI_AGAIN':
      return (
        `DB_HOST "${host}" could not be resolved. In the default Compose setup the database service ` +
        `is named "postgres" and the backend must be on the same Compose network (siembox-network).`
      );
    case 'ETIMEDOUT':
    case 'EHOSTUNREACH':
    case 'ENETUNREACH':
      return (
        `${host}:${port} is unreachable (${code}). Check the network path and any firewall between ` +
        `the backend and the database host.`
      );
    default:
      return null;
  }
}
