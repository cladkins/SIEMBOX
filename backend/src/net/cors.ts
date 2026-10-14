/**
 * Which web pages may call the API from a browser (CORS_ORIGIN).
 *
 * The API authenticates with a Bearer token, never a cookie, and the bundled
 * web UI calls it on its own origin: nginx serves the UI and proxies /api to
 * the backend (frontend/nginx.conf.template), as the Vite dev server does in
 * development. So by default the API sends no CORS headers at all, and a
 * browser lets no page on another origin read its answers or send it a request
 * that needs a preflight (a JSON body, an Authorization header). With `*`, any
 * page a user opened could script sign-in attempts and other calls against
 * port 8421 from inside the network. Same-origin requests and callers that
 * aren't browsers (shippers, endpoint agents, scripts, curl) ignore CORS
 * headers, so they work the same either way.
 *
 * CORS_ORIGIN:
 * - unset or empty: same-origin only (the default).
 * - exact origins, comma-separated: `https://siem.example.com,http://localhost:5173`.
 *   Each is normalized the way browsers send the Origin header (lowercase
 *   scheme and host, no default port, no trailing slash). A request whose
 *   Origin is one of them gets it echoed in Access-Control-Allow-Origin (with
 *   Access-Control-Allow-Credentials, as before, so a cookie or basic auth of a
 *   proxy in front of the API keeps working), and every answer carries
 *   `Vary: Origin`.
 * - `*`: every origin (Access-Control-Allow-Origin: *), the old default. Every
 *   start logs a warning.
 *
 * An entry that isn't an exact http(s) origin (a path, a wildcard, no scheme,
 * `null`) is ignored with a warning and the other entries apply, as with
 * TRUSTED_PROXIES. That fails closed (an ignored entry allows nothing), and the
 * backend, which also receives syslog, shipper and agent traffic, keeps
 * collecting logs instead of refusing to start over a setting only browsers
 * read.
 *
 * Every OPTIONS request is answered here with 204, as the cors package did for
 * every origin before: an allowed origin's preflight gets the allow headers,
 * any other gets none, so the browser never sends the request it asked about.
 *
 * The request's Origin header is only ever compared with the allowed origins
 * as a whole string: it is never parsed or matched with a pattern.
 */
import cors from 'cors';
import type { NextFunction, Request, Response } from 'express';
import { logger } from '../utils/logger';

export type CorsMode = 'same-origin' | 'origins' | 'any';

export interface RejectedOrigin {
  entry: string;
  reason: string;
}

export interface CorsPolicy {
  /** The CORS_ORIGIN value, trimmed ('' when unset). */
  configured: string;
  /** same-origin: no CORS headers; origins: the listed ones; any: `*`. */
  mode: CorsMode;
  /** The allowed origins, normalized (mode 'origins' only). */
  origins: string[];
  /** Entries that were ignored, with the reason. */
  rejected: RejectedOrigin[];
}

export interface Log {
  info(message: string): unknown;
  warn(message: string): unknown;
}

/**
 * An entry as the origin a browser would send in its Origin header
 * (scheme://host[:port]), or why it isn't one.
 */
export function normalizeOrigin(entry: string): { origin: string } | { reason: string } {
  if (entry.includes('*')) return { reason: 'wildcards are not supported; list each origin' };
  if (entry.toLowerCase() === 'null') {
    return { reason: 'sandboxed frames and local files all send the origin "null", so any page could claim it' };
  }
  if (!entry.includes('://')) return { reason: 'an origin starts with http:// or https://' };
  let url: URL;
  try {
    url = new URL(entry);
  } catch {
    return { reason: 'not a valid origin (scheme://host[:port])' };
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { reason: 'only http:// and https:// origins are supported' };
  }
  if (url.username || url.password) return { reason: 'an origin has no user name or password' };
  if (url.pathname !== '/' || url.search || url.hash || entry.includes('?') || entry.includes('#')) {
    return { reason: `an origin has no path, query or fragment; use ${url.origin}` };
  }
  return { origin: url.origin };
}

/** CORS_ORIGIN as a policy. Unset, empty or nothing valid: same-origin only. */
export function parseCorsOrigin(spec: string | undefined): CorsPolicy {
  const configured = (spec ?? '').trim();
  const tokens = [
    ...new Set(
      configured
        .split(',')
        .map((token) => token.trim())
        .filter(Boolean)
    ),
  ];
  if (tokens.length === 1 && tokens[0] === '*') return { configured, mode: 'any', origins: [], rejected: [] };

  const origins: string[] = [];
  const rejected: RejectedOrigin[] = [];
  for (const entry of tokens) {
    if (entry === '*') {
      rejected.push({ entry, reason: '"*" only works on its own; the other entries apply' });
      continue;
    }
    const result = normalizeOrigin(entry);
    if ('reason' in result) rejected.push({ entry, reason: result.reason });
    else if (!origins.includes(result.origin)) origins.push(result.origin);
  }
  return { configured, mode: origins.length > 0 ? 'origins' : 'same-origin', origins, rejected };
}

const STAR_RISK =
  'CORS_ORIGIN=*: every web page your users open can call this API from their browser and read the answers, ' +
  'so a malicious page can try passwords against sign-in and probe the API from inside your network. ' +
  'The web UI does not need it: leave CORS_ORIGIN empty, or list only the origins that need it ' +
  '(CORS_ORIGIN=https://siem.example.com).';

/** What startup logs about the policy: a warning for `*` and for each ignored entry. */
export function logCorsPolicy(policy: CorsPolicy, log: Log = logger): void {
  for (const { entry, reason } of policy.rejected) {
    log.warn(`CORS_ORIGIN entry "${entry}" ignored: ${reason}.`);
  }
  if (policy.mode === 'any') {
    log.warn(STAR_RISK);
  } else if (policy.mode === 'origins') {
    log.info(`CORS: browsers may call the API from ${policy.origins.join(', ')} (CORS_ORIGIN).`);
  } else if (policy.rejected.length > 0) {
    log.warn(
      'CORS_ORIGIN lists no valid origin, so the API is same-origin only: pages on other origins cannot call it ' +
        'from a browser.'
    );
  } else {
    log.info('CORS: same-origin only (CORS_ORIGIN is empty). The web UI does not need CORS.');
  }
}

/**
 * The CORS middleware for a policy. First in app.ts after the address
 * tracker, so preflights are answered before the rate limiter and the routes.
 */
export function corsHeaders(policy: CorsPolicy) {
  const allowAny = cors({ origin: '*' });
  const allowListed = cors({ origin: true, credentials: true });
  const allowed = new Set(policy.origins);
  return function corsHeaders(req: Request, res: Response, next: NextFunction): void {
    if (policy.mode === 'any') {
      allowAny(req, res, next);
      return;
    }
    if (policy.mode === 'origins') {
      const origin = req.headers.origin;
      if (origin !== undefined && allowed.has(origin)) {
        allowListed(req, res, next);
        return;
      }
      // Answers differ by Origin, so a cache must not reuse one for another.
      res.vary('Origin');
    }
    if (req.method === 'OPTIONS') {
      res.statusCode = 204;
      res.setHeader('Content-Length', '0');
      res.end();
      return;
    }
    next();
  };
}
