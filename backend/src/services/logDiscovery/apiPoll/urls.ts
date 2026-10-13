// URL pieces shared by the poll adapters. Kept free of the adapter registry so
// adapters can import it without an import cycle (pollTarget.ts imports the
// registry, and the registry imports the adapters).
import net from 'net';
import { PollTarget } from './types';

/** The host part of a URL for `ip`: an IPv6 literal must be bracketed (http://[fe80::1]:8123), IPv4 is used as is. */
export function urlHost(ip: string): string {
  return net.isIPv6(ip) ? `[${ip}]` : ip;
}

/**
 * The path an adapter requests: the admin's endpoint override when one is set,
 * else the fingerprint's api_pull endpoint, else the adapter's own default.
 * Without an override this is exactly the expression every adapter used before
 * overrides existed (`target.logAccess.endpoint || default`).
 */
export function resolveEndpoint(target: PollTarget, adapterDefault: string): string {
  return target.endpoint || target.logAccess.endpoint || adapterDefault;
}
