// Minimal timeout + size-capped HTTP client for poll adapters, shaped like
// activeDiscovery.ts's requestOnce() (same timeout/body-accumulation pattern)
// but generalized to an arbitrary URL/headers instead of a fixed probe.
//
// No hostname allowlist (unlike feedService's external-URL allowlist): the
// target host is always discovery_sources.ip_address, populated only by the
// scan pipeline, never free text from a request — there's no attacker-
// controlled-host surface here even without one.
import http from 'http';
import https from 'https';
import { URL } from 'url';

export interface HttpFetchOptions {
  headers?: Record<string, string>;
  timeoutMs?: number;
  maxBytes?: number;
  /**
   * Defaults to true (verified). Only ever passed false by the authentik
   * adapter, matching the same trade-off already accepted for
   * activeDiscovery.ts's tlsProbe(): homelab LAN devices overwhelmingly serve
   * self-signed certs, and requiring a valid chain would break this against
   * the exact devices it targets.
   */
  rejectUnauthorized?: boolean;
}

export interface HttpFetchResult {
  status: number;
  body: string;
  headers: http.IncomingHttpHeaders;
}

const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_BYTES = 5 * 1024 * 1024; // mainly for home-assistant's full in-memory log buffer

export function httpFetch(url: string, opts: HttpFetchOptions = {}): Promise<HttpFetchResult> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const mod = parsed.protocol === 'https:' ? https : http;
    const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;

    const req = mod.request(
      {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: `${parsed.pathname}${parsed.search}`,
        method: 'GET',
        timeout: timeoutMs,
        headers: opts.headers,
        ...(parsed.protocol === 'https:' ? { rejectUnauthorized: opts.rejectUnauthorized ?? true } : {}),
      },
      (res) => {
        let body = '';
        res.on('data', (chunk: Buffer) => {
          if (body.length < maxBytes) body += chunk.toString('utf8');
        });
        res.on('end', () => {
          resolve({ status: res.statusCode || 0, body: body.slice(0, maxBytes), headers: res.headers });
        });
      }
    );
    req.on('timeout', () => req.destroy(new Error('Fetch timed out')));
    req.on('error', reject);
    req.end();
  });
}

export function basicAuthHeader(username: string, password: string): string {
  return `Basic ${Buffer.from(`${username}:${password}`, 'utf8').toString('base64')}`;
}
