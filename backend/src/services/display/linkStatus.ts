/**
 * A display link's status for the admin list (docs/architecture/BIG-DISPLAY.md
 * §7.5). Pure.
 */

export type DisplayLinkStatus = 'live' | 'idle' | 'never_used' | 'paused' | 'expired' | 'revoked';

/**
 * A screen's use is written at most once a minute per device
 * (middleware/displayAuth.ts touchUsed), so last_used_at can lag a screen
 * that refreshes every 15 s by up to a minute.
 */
export const TOUCH_INTERVAL_SECONDS = 60;

/**
 * How recent last_used_at must be for 'live': three refresh intervals, and
 * never less than the write interval plus two refreshes (otherwise a 15 s
 * screen would read 'idle' between its once-a-minute writes).
 */
export function liveWindowSeconds(refreshSeconds: number): number {
  return Math.max(3 * refreshSeconds, TOUCH_INTERVAL_SECONDS + 2 * refreshSeconds);
}

export interface StatusInput {
  revoked_at: Date | null;
  expires_at: Date | null;
  enabled: boolean;
  last_used_at: Date | null;
}

/** revoked, then expired, then paused; otherwise how recently a screen used it. */
export function displayLinkStatus(link: StatusInput, refreshSeconds: number, now: Date): DisplayLinkStatus {
  if (link.revoked_at) return 'revoked';
  if (link.expires_at && link.expires_at.getTime() <= now.getTime()) return 'expired';
  if (!link.enabled) return 'paused';
  if (!link.last_used_at) return 'never_used';
  return now.getTime() - link.last_used_at.getTime() <= liveWindowSeconds(refreshSeconds) * 1000 ? 'live' : 'idle';
}
