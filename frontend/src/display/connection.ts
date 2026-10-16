/**
 * The screen's connection state machine (BIG-DISPLAY.md §5.8). Pure: the page
 * feeds it each fetch result and the time, and asks it what to show and when
 * to try again. Only the explicit refusal codes stop or slow the screen;
 * anything else (a network error, a 5xx, an unexpected answer) means "keep
 * the last data on screen and keep retrying". Nothing here ever navigates.
 */
import type { FetchError, FetchResult } from './client.ts';

/** A refusal replaces the board with a full-screen message. */
export type Refusal = 'token_required' | 'invalid' | 'revoked' | 'expired' | 'paused' | 'not_allowed';

export interface ConnectionState {
  /** When the last snapshot arrived (device ms), or null before the first. */
  lastSuccessAt: number | null;
  /** Consecutive failed attempts since then (refusals excluded). */
  failures: number;
  /** The last transient error, cleared by a success. */
  lastError: Extract<FetchError, 'network' | 'unavailable' | 'rate_limited'> | null;
  refusal: Refusal | null;
  /** For the expired message. */
  expiresAt: string | null;
  /** Retry-After from a 429, in seconds. */
  retryAfter: number | null;
}

export type Freshness = 'connecting' | 'live' | 'lagging' | 'offline';

export const OFFLINE_AFTER_MS = 5 * 60 * 1000;
export const BACKOFF_SECONDS = [5, 10, 20, 40] as const;
export const BACKOFF_MAX_SECONDS = 60;

/** How often a refused screen checks again, in seconds; null = it stops. */
export const REFUSAL_RECHECK_SECONDS: Record<Refusal, number | null> = {
  token_required: null, // nothing to poll with; a new link in the address bar restarts the page
  invalid: 600, // in case a backup is restored
  revoked: null, // final
  expired: 600, // extending the expiry revives it
  paused: 60, // resumes by itself
  not_allowed: 300,
};

export function initialState(): ConnectionState {
  return { lastSuccessAt: null, failures: 0, lastError: null, refusal: null, expiresAt: null, retryAfter: null };
}

const REFUSALS = new Set<FetchError>(['token_required', 'invalid', 'revoked', 'expired', 'paused', 'not_allowed']);

export function isRefusal(error: FetchError): error is Refusal {
  return REFUSALS.has(error);
}

/** The state after one fetch. */
export function onResult(state: ConnectionState, result: FetchResult, now: number): ConnectionState {
  if (result.ok) return { ...initialState(), lastSuccessAt: now };
  if (isRefusal(result.error)) {
    return {
      ...state,
      failures: 0,
      lastError: null,
      refusal: result.error,
      expiresAt: result.error === 'expired' ? (result.expiresAt ?? null) : null,
      retryAfter: null,
    };
  }
  const error = result.error as ConnectionState['lastError'];
  return {
    ...state,
    refusal: null,
    expiresAt: null,
    failures: state.failures + 1,
    lastError: error,
    retryAfter: result.error === 'rate_limited' ? (result.retryAfter ?? BACKOFF_MAX_SECONDS) : null,
  };
}

/** ±fraction jitter around ms; `rand` is in [0, 1). */
function jitter(ms: number, fraction: number, rand: number): number {
  return Math.round(ms * (1 + fraction * (2 * rand - 1)));
}

/**
 * Milliseconds until the next fetch, or null when the screen stops polling.
 * Success: the link's refresh ±10 %, so screens don't poll together. Errors:
 * 5, 10, 20, 40 s, then every 60 s (±20 %). 429: Retry-After.
 */
export function nextDelay(state: ConnectionState, refreshSeconds: number, rand: number = Math.random()): number | null {
  if (state.refusal) {
    const seconds = REFUSAL_RECHECK_SECONDS[state.refusal];
    return seconds === null ? null : jitter(seconds * 1000, 0.1, rand);
  }
  if (state.failures === 0) return jitter(refreshSeconds * 1000, 0.1, rand);
  if (state.lastError === 'rate_limited' && state.retryAfter !== null) return state.retryAfter * 1000;
  const seconds = BACKOFF_SECONDS[state.failures - 1] ?? BACKOFF_MAX_SECONDS;
  return jitter(seconds * 1000, 0.2, rand);
}

/** Whether an `online` event or the tab becoming visible should fetch at once. */
export function retryNowOnWake(state: ConnectionState): boolean {
  return state.refusal === null && state.failures > 0;
}

/**
 * Live within 2× refresh of the last success; lagging beyond that; offline
 * after 5 min. Connecting before the first snapshot.
 */
export function freshness(state: ConnectionState, now: number, refreshSeconds: number): Freshness {
  if (state.lastSuccessAt === null) return 'connecting';
  const age = now - state.lastSuccessAt;
  if (age > OFFLINE_AFTER_MS) return 'offline';
  if (age > 2 * refreshSeconds * 1000) return 'lagging';
  return 'live';
}

/** The full-screen message for a refusal (§5.8). */
export function refusalMessage(refusal: Refusal, expiresOn: string | null): { title: string; detail: string } {
  switch (refusal) {
    case 'token_required':
      return { title: 'This page needs a display link.', detail: 'Ask an administrator for one.' };
    case 'invalid':
      return {
        title: "This display link isn't valid any more.",
        detail: 'It may have been replaced. Ask an administrator for the new one.',
      };
    case 'revoked':
      return { title: 'This display link was revoked.', detail: 'Ask an administrator for a new one.' };
    case 'expired':
      return {
        title: expiresOn ? `This display link expired on ${expiresOn}.` : 'This display link has expired.',
        detail: 'An administrator can extend it; this screen checks again every 10 minutes.',
      };
    case 'paused':
      return { title: 'Paused by an administrator.', detail: 'This screen resumes by itself.' };
    case 'not_allowed':
      return {
        title: "This screen's network isn't allowed to use this link.",
        detail: 'Ask an administrator to check the link’s network list.',
      };
  }
}
