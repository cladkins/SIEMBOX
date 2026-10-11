/**
 * DNS access for the lookalike and DNS-drift collectors: the system resolver
 * (or, for the optional second opinion, one explicit server), with a short
 * per-try timeout, few retries, and a hard per-query deadline on top, so one
 * unresponsive name server cannot stall a run.
 */
import dns from 'dns';

/** The subset of dns.promises.Resolver the collectors use (an interface so tests can fake it). */
export interface DnsResolverLike {
  resolve4(hostname: string): Promise<string[]>;
  resolve6(hostname: string): Promise<string[]>;
  resolveMx(hostname: string): Promise<Array<{ priority: number; exchange: string }>>;
  resolveNs(hostname: string): Promise<string[]>;
  resolveTxt(hostname: string): Promise<string[][]>;
}

export interface ResolverOptions {
  /** Per-try timeout handed to c-ares. */
  timeoutMs?: number;
  tries?: number;
  /** Explicit servers (IP addresses); the system's resolvers when omitted. */
  servers?: string[];
}

export function createResolver(options: ResolverOptions = {}): DnsResolverLike {
  const resolver = new dns.promises.Resolver({
    timeout: options.timeoutMs ?? 2_500,
    tries: options.tries ?? 2,
  });
  if (options.servers && options.servers.length > 0) resolver.setServers(options.servers);
  return resolver;
}

/** NXDOMAIN: the name does not exist. */
export const NXDOMAIN = 'ENOTFOUND';
/** NODATA: the name exists but has no records of the queried type. */
export const NODATA = 'ENODATA';

export type QueryOutcome<T> = { ok: true; value: T } | { ok: false; code: string };

/**
 * Run one query with a hard deadline. Never throws: failures come back as the
 * resolver's error code (ENOTFOUND, ENODATA, ETIMEOUT, ESERVFAIL, ...).
 */
export async function timedQuery<T>(
  run: () => Promise<T>,
  timeoutMs: number
): Promise<QueryOutcome<T>> {
  let timer: NodeJS.Timeout | undefined;
  try {
    const value = await Promise.race([
      run(),
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(
          () => reject(Object.assign(new Error('DNS query timed out'), { code: 'ETIMEOUT' })),
          timeoutMs
        );
      }),
    ]);
    return { ok: true, value };
  } catch (err) {
    const code = (err as { code?: unknown } | null)?.code;
    return { ok: false, code: typeof code === 'string' && code ? code : 'EQUERYFAILED' };
  } finally {
    clearTimeout(timer);
  }
}

/** Map `items` through `fn` with at most `limit` calls in flight; `fn` must not throw. */
export async function mapWithConcurrency<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T) => Promise<R>
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const index = next++;
      results[index] = await fn(items[index]);
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker));
  return results;
}
