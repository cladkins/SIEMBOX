/**
 * What a failed graph call means for the page (pure; the error is read by
 * shape, so this runs under `node --test` without axios):
 *
 *   aborted  the user pressed Cancel, or a newer call replaced it: say nothing
 *   busy     503 GRAPH_BUSY: retry once after Retry-After, then offer Try again
 *   bad      400 GRAPH_BAD_ENTITY / GRAPH_BAD_PARAM: the link is wrong
 *   unavailable  404 GRAPH_NOT_AVAILABLE: not something this role can expand
 *   timeout / network / server: an inline error with Try again
 *
 * A 401 never reaches here as a page state: the API client signs out and
 * keeps the page as the target to come back to (stores/auth.ts).
 */

export type GraphFailureKind = 'aborted' | 'busy' | 'bad' | 'unavailable' | 'timeout' | 'network' | 'server';

export interface GraphFailure {
  kind: GraphFailureKind;
  message: string;
  /** busy: seconds to wait before the one automatic retry. */
  retryAfter?: number;
}

interface ErrorShape {
  code?: unknown;
  name?: unknown;
  message?: unknown;
  response?: {
    status?: number;
    headers?: Record<string, unknown>;
    data?: { code?: unknown; message?: unknown; retryAfter?: unknown };
  };
}

function serverMessage(err: ErrorShape): string | null {
  const message = err.response?.data?.message;
  return typeof message === 'string' && message.trim() ? message.trim().slice(0, 300) : null;
}

export function classifyGraphError(error: unknown): GraphFailure {
  const err = (error ?? {}) as ErrorShape;
  if (err.code === 'ERR_CANCELED' || err.name === 'CanceledError' || err.name === 'AbortError') {
    return { kind: 'aborted', message: '' };
  }
  const status = err.response?.status;
  if (status === 503) {
    const header = Number(err.response?.headers?.['retry-after']);
    const body = Number(err.response?.data?.retryAfter);
    const retryAfter = Number.isFinite(header) && header > 0 ? header : Number.isFinite(body) && body > 0 ? body : 2;
    return { kind: 'busy', message: 'SIEMBox is busy. Try again in a few seconds.', retryAfter: Math.min(retryAfter, 30) };
  }
  if (status === 400) return { kind: 'bad', message: serverMessage(err) ?? "That link doesn't name a valid entity." };
  if (status === 404) return { kind: 'unavailable', message: serverMessage(err) ?? 'That relation is not available to your role.' };
  if (status !== undefined) return { kind: 'server', message: serverMessage(err) ?? `The server answered ${status}.` };
  if (err.code === 'ECONNABORTED' || /timeout/i.test(String(err.message ?? ''))) {
    return { kind: 'timeout', message: 'The graph took too long to answer.' };
  }
  return { kind: 'network', message: "Couldn't reach SIEMBox. Check your connection." };
}

/** The message to show inline, or '' when there is nothing to say (aborted). */
export function graphErrorMessage(error: unknown): string {
  return classifyGraphError(error).message;
}
