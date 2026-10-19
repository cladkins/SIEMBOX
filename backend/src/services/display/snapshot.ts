/**
 * Builds a Big Display snapshot (docs/architecture/BIG-DISPLAY.md §7.6, §7.9,
 * §7.10): one envelope per distinct panel key of the display's views, then
 * the privacy check (redact.ts), the alarms and the attributions.
 *
 * - One cache per panel key (snapshotCache.ts), shared by every screen,
 *   preview and signed-in board: concurrent screens share one query, and ten
 *   screens cost the database what one does. A failed refresh serves the last
 *   value (`stale`), with a 20 s failure cooldown.
 * - At most 3 panel queries run at once (a cold build holds at most 3 of the
 *   main pool's 20 connections; display work never uses the ingest pool). Each
 *   runs READ ONLY with a 4 s statement timeout.
 * - A soft 8 s budget: a panel not back by then goes out `stale` (its last
 *   value) or `unavailable`, well inside the screen's 15 s abort. Its query
 *   carries on and fills the cache for the next refresh.
 * - Signed-in boards (role set): a panel whose minRole the user lacks is
 *   `forbidden`, and no alarm comes from it. Display links (no role) can only
 *   hold 'viewer' kinds (config.ts refuses the rest).
 */
import { getClient } from '../../config/database';
import { logger } from '../../utils/logger';
import { APP_VERSION } from '../../utils/appVersion';
import {
  createSnapshotCache,
  isDatabaseBusy,
  runReadOnlyWork,
  type QueryClient,
  type SnapshotCache,
  type SnapshotMeta,
} from '../shippers/snapshotCache';
import { ALARM_TEXT, deriveAlarms, deriveAttributions } from './alarms';
import { describeDisplay, panelKey, parseDisplayConfig, type DisplayConfig, type PanelSpec } from './config';
import { PANEL_KINDS } from './panels';
import { assertDisplaySafe } from './redact';
import type { DisplaySnapshot, PanelEnvelope } from './types';

export const PANEL_STATEMENT_TIMEOUT_MS = 4000;
export const PANEL_FAILURE_COOLDOWN_MS = 20_000;
export const MAX_CONCURRENT_PANEL_QUERIES = 3;
export const SNAPSHOT_BUDGET_MS = 8000;

// --- Semaphore -----------------------------------------------------------------------

export interface Semaphore {
  run<T>(work: () => Promise<T>): Promise<T>;
  /** Running now, and the most that ever ran at once (for the tests). */
  stats(): { active: number; waiting: number; peak: number };
}

export function createSemaphore(limit: number): Semaphore {
  let active = 0;
  let peak = 0;
  const waiting: Array<() => void> = [];
  return {
    async run<T>(work: () => Promise<T>): Promise<T> {
      if (active >= limit) await new Promise<void>((resolve) => waiting.push(resolve));
      else active++;
      peak = Math.max(peak, active);
      try {
        return await work();
      } finally {
        const next = waiting.shift();
        if (next) next(); // the slot passes straight to the next waiter
        else active--;
      }
    },
    stats: () => ({ active, waiting: waiting.length, peak }),
  };
}

// --- Builder ---------------------------------------------------------------------------

export interface BuildInput {
  name: string;
  configVersion: number;
  config: DisplayConfig;
  /** The signed-in user's role; undefined for a display link (and its admin previews). */
  role?: 'admin' | 'operator' | 'analyst' | 'viewer';
}

export interface BuilderDeps {
  /** One panel's fetch: by default under the semaphore, READ ONLY with a 4 s timeout, on the main pool. */
  runPanel: (spec: PanelSpec) => Promise<unknown>;
  now: () => number;
  log: { warn: (msg: string, meta?: unknown) => void; error: (msg: string, meta?: unknown) => void };
  budgetMs: number;
  appVersion: string;
}

const TIMED_OUT = Symbol('timed out');

export function createSnapshotBuilder(deps: BuilderDeps) {
  const caches = new Map<string, SnapshotCache<unknown>>();

  function cacheFor(key: string, spec: PanelSpec): SnapshotCache<unknown> {
    let cache = caches.get(key);
    if (!cache) {
      cache = createSnapshotCache<unknown>(
        { fetch: () => deps.runPanel(spec), now: deps.now, log: deps.log, label: `big-display ${key}` },
        { ttlMs: PANEL_KINDS[spec.id].ttlMs, failureCooldownMs: PANEL_FAILURE_COOLDOWN_MS }
      );
      caches.set(key, cache);
    }
    return cache;
  }

  const reasonOf = (error: unknown): 'busy' | 'error' => (isDatabaseBusy(error) ? 'busy' : 'error');

  /** staleReason null: fresh. */
  function envelope(
    key: string,
    spec: PanelSpec,
    privacy: DisplayConfig['privacy'],
    value: unknown,
    at: number,
    staleReason: 'busy' | 'error' | null
  ): PanelEnvelope {
    let shaped;
    try {
      shaped = PANEL_KINDS[spec.id].shape(value, spec, privacy, at);
    } catch (error) {
      deps.log.error('Big Display: a panel could not be shaped', { panel: key, error: error instanceof Error ? error.message : String(error) });
      return { state: 'unavailable', reason: 'error' };
    }
    if ('not_configured' in shaped) return { state: 'not_configured', message: shaped.not_configured };
    const as_of = new Date(at).toISOString();
    return staleReason ? { state: 'stale', as_of, reason: staleReason, data: shaped.data } : { state: 'ok', as_of, data: shaped.data };
  }

  async function build(input: BuildInput): Promise<DisplaySnapshot> {
    const { config } = input;
    const specs = new Map<string, PanelSpec>();
    for (const view of config.views) for (const panel of view.panels) if (!specs.has(panelKey(panel))) specs.set(panelKey(panel), panel);

    // Cleared as soon as every panel is in; a request in flight keeps the process up anyway.
    let timer: NodeJS.Timeout | undefined;
    const deadline = new Promise<typeof TIMED_OUT>((resolve) => {
      timer = setTimeout(() => resolve(TIMED_OUT), deps.budgetMs);
    });

    const entries = await Promise.all(
      [...specs].map(async ([key, spec]): Promise<[string, PanelEnvelope]> => {
        const kind = PANEL_KINDS[spec.id];
        if (kind.minRole === 'admin' && input.role !== 'admin') {
          return [key, input.role ? { state: 'forbidden' } : { state: 'unavailable', reason: 'error' }];
        }
        const cache = cacheFor(key, spec);
        const outcome = await Promise.race([
          cache.getWithMeta().then(
            (meta: SnapshotMeta<unknown>) => ({ meta }),
            (error: unknown) => ({ error })
          ),
          deadline,
        ]);
        if (outcome === TIMED_OUT) {
          // Not back within the budget: the database is busy. Its query carries on and fills the cache.
          const last = cache.peek();
          return [key, last ? envelope(key, spec, config.privacy, last.value, last.at, 'busy') : { state: 'unavailable', reason: 'busy' }];
        }
        if ('error' in outcome) return [key, { state: 'unavailable', reason: reasonOf(outcome.error) }];
        const { meta } = outcome;
        return [key, envelope(key, spec, config.privacy, meta.value, meta.at, meta.stale ? reasonOf(meta.error) : null)];
      })
    );
    clearTimeout(timer);

    const panels = assertDisplaySafe(Object.fromEntries(entries), config.privacy, deps.log);
    const at = deps.now();
    const alarms = deriveAlarms(panels, at).filter((alarm) => ALARM_TEXT.test(alarm.text));
    const now = new Date(at).toISOString();
    return {
      generated_at: now,
      server_time: now,
      app_version: deps.appVersion,
      display: describeDisplay(input.name, input.configVersion, config),
      alarms,
      attributions: deriveAttributions(panels),
      panels,
    };
  }

  return {
    build,
    /** Drop every cached panel (tests). */
    reset: () => caches.clear(),
  };
}

const semaphore = createSemaphore(MAX_CONCURRENT_PANEL_QUERIES);

/** The process-wide builder every display route uses. */
export const snapshotBuilder = createSnapshotBuilder({
  runPanel: (spec) =>
    semaphore.run(() =>
      runReadOnlyWork(getClient as () => Promise<QueryClient>, PANEL_STATEMENT_TIMEOUT_MS, (q) => PANEL_KINDS[spec.id].fetch(spec, q))
    ),
  now: () => Date.now(),
  log: logger,
  budgetMs: SNAPSHOT_BUDGET_MS,
  appVersion: APP_VERSION,
});

export const panelQueryStats = () => semaphore.stats();

// --- The signed-in board ------------------------------------------------------------------

/**
 * Big Display while signed in (§5.4): SOC overview, Threats and Health,
 * rotating every 30 s. Health includes endpoint health, which only admins see
 * (forbidden for every other role, and dropped from the view by the screen).
 * Operations privacy: the user can already read those labels in the app.
 */
export const SIGNED_IN_CONFIG: DisplayConfig = (() => {
  const parsed = parseDisplayConfig(
    {
      privacy: 'operations',
      rotation: { enabled: true, seconds: 30 },
      views: [
        {
          title: 'SOC overview',
          panels: [
            { id: 'open_alerts' },
            { id: 'alert_pulse' },
            { id: 'ingest' },
            { id: 'sources', silent_after_minutes: 15 },
            { id: 'shippers' },
            { id: 'recent_alerts', min_severity: 'high' },
          ],
        },
        { title: 'Threats', panels: [{ id: 'threat_map', window_days: 1 }, { id: 'top_sources' }, { id: 'top_rules', window_hours: 24 }, { id: 'open_alerts' }] },
        { title: 'Health', panels: [{ id: 'ingest' }, { id: 'sources', silent_after_minutes: 15 }, { id: 'shippers' }, { id: 'vulnerabilities' }, { id: 'endpoints' }] },
      ],
    },
    { forLink: false }
  );
  if (!parsed.ok) throw new Error(`SIGNED_IN_CONFIG is invalid: ${parsed.field}`);
  return parsed.value;
})();

export const SIGNED_IN_NAME = 'Big Display';
