/**
 * The display page's only API client (BIG-DISPLAY.md §4.2, §4.4). Plain fetch:
 * not the main app's axios instance, so no Authorization header is ever sent,
 * no cookie either (credentials: 'omit'), and no response can reach the main
 * app's sign-out, toasts or router. The link's secret travels in
 * X-Display-Token only, never in the path or query string.
 */
import type { DisplaySnapshot, RefusalCode } from './types.ts';

export const SNAPSHOT_PATH = '/api/display/snapshot';
const TIMEOUT_MS = 15_000;

export type FetchError =
  | 'network'
  | 'unavailable'
  | 'token_required'
  | 'invalid'
  | 'revoked'
  | 'expired'
  | 'paused'
  | 'not_allowed'
  | 'rate_limited';

export type FetchResult =
  | { ok: true; snapshot: DisplaySnapshot; sentAt: number; receivedAt: number }
  | { ok: false; error: FetchError; retryAfter?: number; expiresAt?: string | null };

const REFUSALS: Record<RefusalCode, FetchError> = {
  DISPLAY_TOKEN_REQUIRED: 'token_required',
  DISPLAY_LINK_INVALID: 'invalid',
  DISPLAY_LINK_REVOKED: 'revoked',
  DISPLAY_LINK_EXPIRED: 'expired',
  DISPLAY_LINK_PAUSED: 'paused',
  DISPLAY_NETWORK_NOT_ALLOWED: 'not_allowed',
};

/** The token from a location hash such as "#k=sbd1_…" (other parameters are ignored). */
export function tokenFromHash(hash: string): string | null {
  const params = new URLSearchParams(hash.replace(/^#/, ''));
  const k = params.get('k');
  return k ? k.trim() : null;
}

/** Map an HTTP answer to what the screen does with it (§5.8). Only explicit codes stop or wait. */
export function classify(status: number, body: unknown, retryAfterHeader: string | null): FetchResult | null {
  const code = typeof body === 'object' && body !== null ? (body as { code?: unknown }).code : undefined;
  if ((status === 401 || status === 403) && typeof code === 'string' && code in REFUSALS) {
    const error = REFUSALS[code as RefusalCode];
    const expiresAt = (body as { expires_at?: unknown }).expires_at;
    return error === 'expired'
      ? { ok: false, error, expiresAt: typeof expiresAt === 'string' ? expiresAt : null }
      : { ok: false, error };
  }
  if (status === 429) {
    const seconds = Number(retryAfterHeader);
    return { ok: false, error: 'rate_limited', retryAfter: Number.isFinite(seconds) && seconds > 0 ? seconds : 60 };
  }
  if (status !== 200) return { ok: false, error: 'unavailable' };
  return null;
}

function looksLikeSnapshot(body: unknown): body is DisplaySnapshot {
  if (typeof body !== 'object' || body === null) return false;
  const s = body as Partial<DisplaySnapshot>;
  return (
    typeof s.server_time === 'string' &&
    typeof s.display === 'object' &&
    s.display !== null &&
    Array.isArray(s.display.views) &&
    typeof s.panels === 'object' &&
    s.panels !== null
  );
}

export async function fetchSnapshot(token: string): Promise<FetchResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  const sentAt = Date.now();
  try {
    const res = await fetch(SNAPSHOT_PATH, {
      method: 'GET',
      headers: { 'X-Display-Token': token, Accept: 'application/json' },
      cache: 'no-store',
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      signal: controller.signal,
    });
    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      body = null;
    }
    const refused = classify(res.status, body, res.headers.get('Retry-After'));
    if (refused) return refused;
    if (!looksLikeSnapshot(body)) return { ok: false, error: 'unavailable' };
    return { ok: true, snapshot: body, sentAt, receivedAt: Date.now() };
  } catch {
    return { ok: false, error: 'network' };
  } finally {
    clearTimeout(timer);
  }
}
