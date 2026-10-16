/**
 * Where to go after signing in (`/login?redirect=...`, and the target held
 * through a forced password change): a path inside this app, or null.
 *
 * The redirect comes from the address bar, so anyone can put anything there;
 * an open redirect would let a link to SIEMBox's own sign-in page send the
 * user to another site after they sign in. A target is accepted only when it:
 *
 *   - is a string of at most 2,000 characters starting with `/`, but not `//`
 *     or `/\` (both are another host to a browser);
 *   - has no control characters (C0, DEL, C1);
 *   - stays on this origin when the browser resolves it (a backslash anywhere
 *     in the path is a slash to a browser, so `/\evil` is `//evil`);
 *   - resolves (router.resolve) to one of the app's routes other than Login
 *     and ChangePassword. The wall-display page (Big Display, served at
 *     /display by its own entry, never by this router) is never a target
 *     either: it must not share the signed-in session.
 *
 * Pure: the caller passes the router's resolve, so this runs under `node --test`.
 */

export const MAX_REDIRECT_LENGTH = 2000;

/** Route names a redirect never goes to. */
export const REFUSED_ROUTE_NAMES: ReadonlySet<string> = new Set(['Login', 'ChangePassword', 'DisplayGraph']);

/** What safeRedirect needs from router.resolve(path). */
export interface ResolvedTarget {
  name?: unknown;
  matched: readonly unknown[];
  fullPath?: string;
}

export type Resolve = (path: string) => ResolvedTarget;

const BASE = 'http://siembox.invalid';

function hasControlChars(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c <= 0x1f || (c >= 0x7f && c <= 0x9f)) return true;
  }
  return false;
}

/** `value` as an in-app path to navigate to, or null. */
export function safeRedirect(value: unknown, resolve: Resolve): string | null {
  if (typeof value !== 'string') return null;
  if (value.length === 0 || value.length > MAX_REDIRECT_LENGTH) return null;
  if (!value.startsWith('/') || value.startsWith('//') || value.startsWith('/\\')) return null;
  if (hasControlChars(value)) return null;
  let url: URL;
  try {
    url = new URL(value, BASE);
  } catch {
    return null;
  }
  if (url.origin !== BASE) return null;
  // The display page is its own entry (display.html), outside this router.
  if (url.pathname === '/display' || url.pathname.startsWith('/display/') || url.pathname === '/display.html') return null;
  let target: ResolvedTarget;
  try {
    target = resolve(value);
  } catch {
    return null;
  }
  if (!target || !Array.isArray(target.matched) || target.matched.length === 0) return null;
  if (typeof target.name === 'string' && REFUSED_ROUTE_NAMES.has(target.name)) return null;
  return value;
}
