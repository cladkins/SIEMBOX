/**
 * Reading the API's sign-in protection answers (backend routes/auth.ts): a
 * 429 with code SIGNIN_PAUSED carries `reason`, `message` and `retryAfter`
 * (seconds, also in the Retry-After header); every error carries `message`.
 */
import type { AxiosError } from 'axios';

export interface ApiErrorBody {
  message?: string;
  code?: string;
  reason?: string;
  retryAfter?: number;
  mfaRequired?: boolean;
}

export function errorBody(error: unknown): ApiErrorBody {
  const data = (error as AxiosError | undefined)?.response?.data;
  return data && typeof data === 'object' ? (data as ApiErrorBody) : {};
}

export function errorStatus(error: unknown): number | null {
  return (error as AxiosError | undefined)?.response?.status ?? null;
}

/** Seconds to wait after a 429: the body's retryAfter, else the Retry-After header, else 60. */
export function retryAfterSeconds(error: unknown): number {
  const body = errorBody(error);
  if (typeof body.retryAfter === 'number' && body.retryAfter > 0) return Math.ceil(body.retryAfter);
  const header = Number((error as AxiosError | undefined)?.response?.headers?.['retry-after']);
  if (Number.isFinite(header) && header > 0) return Math.ceil(header);
  return 60;
}

/** 103 -> '1:43'. */
export function formatCountdown(seconds: number): string {
  const whole = Math.max(0, Math.ceil(seconds));
  const minutes = Math.floor(whole / 60);
  return `${minutes}:${String(whole % 60).padStart(2, '0')}`;
}

/** No answer, a timeout or a 5xx: the server, not the user, is the problem. */
export function isUnavailable(error: unknown): boolean {
  const status = errorStatus(error);
  return status === null || status >= 500;
}

/** What a throttle scope counts, in plain words (Users page, Settings -> Sign-in protection). */
export const SCOPE_WORDS: Record<string, string> = {
  aip: 'this account from one network',
  ip: 'a network, any username',
  acct: 'this account from new browsers',
  br: 'a recognized browser',
  mfa: 'MFA codes',
  pwc: 'current password (password change)',
};
