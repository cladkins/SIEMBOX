/**
 * YARA-Forge refresh job (opt-in).
 *
 * Disabled by default: a curated starter bundle (migration 017, version 1) ships
 * out of the box, and auto-distributing the large YARA-Forge pack to every
 * endpoint should be a deliberate choice. Enable with EDR_YARA_FORGE_ENABLED=true.
 *
 * When enabled, it refreshes daily (and shortly after startup). publishYaraBundle
 * is a no-op when the content is unchanged, so this only bumps the bundle version
 * (and thus triggers agent downloads) when YARA-Forge actually changes. Admins can
 * also refresh on demand via POST /api/edr/yara/refresh regardless of this toggle.
 */
import { refreshYaraForge } from '../services/edr/yaraForgeService';
import { logger } from '../utils/logger';
import { ErrorLogService } from '../services/errors/errorLogService';
import { registerRecurringJob, trackJobRun } from '../services/jobs/jobRegistry';

const JOB_KEY = 'yara-forge';

let intervalId: NodeJS.Timeout | null = null;
let startupTimer: NodeJS.Timeout | null = null;
const CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000; // daily
const STARTUP_DELAY_MS = 2 * 60 * 1000; // let boot settle before a large download

function isEnabled(): boolean {
  return /^(1|true|yes|on)$/i.test((process.env.EDR_YARA_FORGE_ENABLED || '').trim());
}

async function tick(): Promise<void> {
  try {
    await trackJobRun(JOB_KEY, async () => {
      const version = await refreshYaraForge();
      if (version) logger.info(`[YARA] YARA-Forge bundle updated to v${version}`);
      return version ? `bundle updated to v${version}` : 'bundle already current';
    });
  } catch (err) {
    // Keep the current bundle on any failure (network, parse, empty) — never crash.
    logger.warn('[YARA] YARA-Forge refresh failed (keeping current bundle):', err instanceof Error ? err.message : err);
    ErrorLogService.logBackgroundError('yara-forge', err, { dedupeKey: 'refresh' });
  }
}

export function startYaraRulesJob(): void {
  const description =
    'Re-fetches the YARA-Forge rule pack and republishes the endpoint bundle when it changes.';
  if (!isEnabled()) {
    // Registered even when off, so the dashboard shows "disabled" instead of
    // omitting the row — an absent row reads as a missing feature.
    registerRecurringJob({
      key: JOB_KEY,
      name: 'YARA-Forge refresh',
      description: `${description} Disabled — set EDR_YARA_FORGE_ENABLED=true to enable.`,
      enabled: false,
    });
    logger.info('[YARA] YARA-Forge refresh job disabled (set EDR_YARA_FORGE_ENABLED=true to enable)');
    return;
  }
  if (intervalId) return;
  registerRecurringJob({
    key: JOB_KEY,
    name: 'YARA-Forge refresh',
    description,
    intervalMs: CHECK_INTERVAL_MS,
  });
  startupTimer = setTimeout(() => {
    void tick();
  }, STARTUP_DELAY_MS);
  intervalId = setInterval(() => {
    void tick();
  }, CHECK_INTERVAL_MS);
  logger.info('[YARA] YARA-Forge refresh job started (daily)');
}

export function stopYaraRulesJob(): void {
  if (startupTimer) {
    clearTimeout(startupTimer);
    startupTimer = null;
  }
  if (intervalId) {
    clearInterval(intervalId);
    intervalId = null;
  }
}
