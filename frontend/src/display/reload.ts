/**
 * Keeping a screen that runs for months current (BIG-DISPLAY.md §5.9):
 *
 * - a new backend version (the snapshot's app_version) or a new page (the
 *   ETag of HEAD /display, checked every 10 minutes) asks for a reload;
 * - so does 04:00 local time each day, against slow browser memory growth;
 * - a reload only ever happens right after a successful snapshot, so a screen
 *   never reloads into an outage;
 * - a lazy chunk that fails to load (deleted by a deploy) reloads the page
 *   once, remembered per tab in sessionStorage under
 *   `siembox.display.chunk-reloaded` and cleared by the next success.
 *
 * This is the only display module allowed to touch sessionStorage, and it
 * uses that one key; no display module touches localStorage (eslint.config.js).
 */

export const CHUNK_RELOAD_FLAG = 'siembox.display.chunk-reloaded';
export const ETAG_CHECK_MS = 10 * 60 * 1000;

/** Device ms of the next 04:00 local time after `now`. */
export function nextDailyReload(now: number): number {
  const d = new Date(now);
  const at = new Date(d.getFullYear(), d.getMonth(), d.getDate(), 4, 0, 0, 0);
  if (at.getTime() <= now) at.setDate(at.getDate() + 1);
  return at.getTime();
}

/** Whether a snapshot's version differs from the one the page loaded with. */
export function versionChanged(loaded: string | null, current: string | null | undefined): boolean {
  return loaded !== null && typeof current === 'string' && current !== '' && current !== loaded;
}

function flagStore(): Storage | null {
  try {
    return window.sessionStorage;
  } catch {
    return null; // storage disabled: the chunk reload just isn't limited to once
  }
}

/** A lazy chunk failed to load: reload once per tab, then leave it to the panel's own state. */
export function reloadForStaleChunk(): void {
  const store = flagStore();
  try {
    if (store?.getItem(CHUNK_RELOAD_FLAG)) return;
    store?.setItem(CHUNK_RELOAD_FLAG, '1');
  } catch {
    return;
  }
  window.location.reload();
}

/** After a successful snapshot: a later stale chunk may reload again. */
export function clearChunkReloadFlag(): void {
  try {
    flagStore()?.removeItem(CHUNK_RELOAD_FLAG);
  } catch {
    // nothing to clear
  }
}

/** The page's own ETag (HEAD /display), or null when it can't be read. */
export async function pageEtag(): Promise<string | null> {
  try {
    const res = await fetch('/display', { method: 'HEAD', cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' });
    return res.ok ? res.headers.get('ETag') : null;
  } catch {
    return null;
  }
}

/**
 * Tracks the reasons to reload; the page calls `afterSuccess()` after every
 * good snapshot, which reloads when one is pending.
 */
export class ReloadPlanner {
  private loadedVersion: string | null = null;
  private loadedEtag: string | null = null;
  private pending: string | null = null;
  private dailyAt: number;
  private etagTimer: ReturnType<typeof setInterval> | null = null;
  private readonly reload: () => void;

  constructor(now: number, reload: () => void = () => window.location.reload()) {
    this.dailyAt = nextDailyReload(now);
    this.reload = reload;
  }

  startEtagChecks(): void {
    void pageEtag().then((etag) => {
      this.loadedEtag = etag;
    });
    this.etagTimer = setInterval(async () => {
      const etag = await pageEtag();
      if (etag && this.loadedEtag && etag !== this.loadedEtag) this.pending = 'page';
      if (etag && !this.loadedEtag) this.loadedEtag = etag;
    }, ETAG_CHECK_MS);
  }

  stop(): void {
    if (this.etagTimer) clearInterval(this.etagTimer);
    this.etagTimer = null;
  }

  /** Call with each good snapshot; returns true when it reloads the page. */
  afterSuccess(appVersion: string, now: number): boolean {
    clearChunkReloadFlag();
    if (this.loadedVersion === null) this.loadedVersion = appVersion;
    else if (versionChanged(this.loadedVersion, appVersion)) this.pending = 'version';
    if (now >= this.dailyAt) this.pending = this.pending ?? 'daily';
    if (this.pending === null) return false;
    this.stop();
    this.reload();
    return true;
  }
}
