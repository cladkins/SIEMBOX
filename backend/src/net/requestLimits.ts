/**
 * Shared pieces for every express-rate-limit limiter: the keys and the 429
 * answer.
 *
 * Every limiter passes its own keyGenerator, so express-rate-limit's default
 * one (and the request.ip, trust-proxy and X-Forwarded-For checks it runs) is
 * never used: the trust decision lives in trustedProxies.ts, and these keys come
 * from the address it produced (clientAddress.ts).
 *
 * Request limiters key on the full address, not the IPv6 /56 that
 * express-rate-limit 8 defaults to: a home network's IPv6 clients usually share
 * one /64, and a coarser key would put a whole household or office in one
 * bucket of the general API limit. Sign-in limits, where an attacker cycling
 * addresses is the concern, key on the /64 instead (signInNetworkKey).
 */
import type { Request, Response } from 'express';
import { clientAddress, signInNetworkKey } from './clientAddress';

/** Limiter key for request limits: the client address, or 'unknown'. */
export function requestLimitKey(req: Request): string {
  return clientAddress(req) ?? 'unknown';
}

/** Limiter key for sign-in limits: the IPv4 address or IPv6 /64, or 'unknown'. */
export function signInLimitKey(req: Request): string {
  return signInNetworkKey(clientAddress(req));
}

/** "45 seconds", "1 minute", "12 minutes". */
export function formatWait(seconds: number): string {
  if (seconds < 60) return `${seconds} second${seconds === 1 ? '' : 's'}`;
  const minutes = Math.ceil(seconds / 60);
  return `${minutes} minute${minutes === 1 ? '' : 's'}`;
}

/** Seconds until the client's window resets: the Retry-After header express-rate-limit just set, else the reset time. */
function retryAfterSeconds(req: Request, res: Response): number {
  const header = Number(res.getHeader('Retry-After'));
  if (Number.isFinite(header) && header > 0) return Math.ceil(header);
  const reset = (req as Request & { rateLimit?: { resetTime?: Date } }).rateLimit?.resetTime;
  const seconds = reset ? Math.ceil((reset.getTime() - Date.now()) / 1000) : 60;
  return Math.max(1, seconds);
}

/**
 * The 429 handler for a limiter: the standard JSON error envelope
 * ({status, statusCode, message}) plus code RATE_LIMITED and retryAfter in
 * seconds, which matches the Retry-After header. `message` is either a sentence
 * that gets " Try again in N minutes." appended, or a function of that wait.
 */
export function rateLimitedHandler(message: string | ((wait: string) => string)) {
  return (req: Request, res: Response): void => {
    const retryAfter = retryAfterSeconds(req, res);
    if (!res.getHeader('Retry-After')) res.setHeader('Retry-After', String(retryAfter));
    const wait = formatWait(retryAfter);
    res.status(429).json({
      status: 'error',
      statusCode: 429,
      code: 'RATE_LIMITED',
      message: typeof message === 'function' ? message(wait) : `${message} Try again in ${wait}.`,
      retryAfter,
    });
  };
}
