/**
 * GeoIP database update job.
 *
 * Geo enrichment is fail-open: with no MMDB on disk, `geoipService` logs one
 * warning and every lookup returns null. That is the right runtime behaviour,
 * but it made the feature silently absent — `country_code` never reached
 * `parsed_data`, so it never reached `alerts.matched_data`, so the GeoIP map and
 * the country tables on Threat Intel were permanently empty with nothing on
 * screen explaining why. The only way to get the database was to notice
 * `backend/scripts/update-geoip.sh` in the repo and run it by hand on the host.
 *
 * This job fetches it instead. DB-IP publishes the lite database monthly under a
 * YYYY-MM name, so we try the current month and fall back to the previous one —
 * the same walk the shell script does, which stays for air-gapped installs and
 * for anyone who prefers a host cron.
 *
 * Deliberately conservative about replacing a working database:
 *  - a download is only attempted when the file is missing or older than
 *    MAX_AGE_MS, so the usual cycle is a stat() and nothing else;
 *  - the decompressed bytes must parse as an MMDB before they are installed, so
 *    a captive-portal HTML page or a truncated transfer cannot clobber a good
 *    database with a broken one;
 *  - install is a rename over the destination, which is atomic on the same
 *    filesystem, so a reader never sees a half-written file.
 *
 * Set GEOIP_AUTO_UPDATE=false to disable — the job still registers, so the
 * dashboard shows it as disabled rather than omitting it.
 *
 * DB-IP lite is CC BY 4.0: attribution is required wherever the data is shown.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as zlib from 'zlib';
import { Reader, CountryResponse } from 'mmdb-lib';
import { geoipService } from '../services/geoip/geoipService';
import { logger } from '../utils/logger';
import { ErrorLogService } from '../services/errors/errorLogService';
import { registerRecurringJob, trackJobRun, markJobSkipped } from '../services/jobs/jobRegistry';

const JOB_KEY = 'geoip-update';
const DEFAULT_DB_PATH = '/app/data/dbip-country-lite.mmdb';
const BASE_URL = 'https://download.db-ip.com/free';

/** How often to consider updating. The usual outcome is a stat() and a skip. */
const CHECK_INTERVAL_MS = 12 * 60 * 60 * 1000;
/** Refetch once the local copy is older than this. DB-IP publishes monthly. */
const MAX_AGE_MS = 25 * 24 * 60 * 60 * 1000;
/** Let the rest of boot settle, and don't stampede the other startup jobs. */
const STARTUP_DELAY_MS = 20 * 1000;
const DOWNLOAD_TIMEOUT_MS = 5 * 60 * 1000;

let intervalId: NodeJS.Timeout | null = null;
let startupTimer: NodeJS.Timeout | null = null;

function dbPath(): string {
  return process.env.GEOIP_DB_PATH || DEFAULT_DB_PATH;
}

export function isAutoUpdateEnabled(): boolean {
  return (process.env.GEOIP_AUTO_UPDATE || 'true').toLowerCase() !== 'false';
}

/** YYYY-MM for `monthsAgo` months back, in UTC. */
export function monthStamp(now: Date, monthsAgo = 0): string {
  const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - monthsAgo, 1));
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
}

/** Age of the installed database, or null when there isn't one. */
export function currentDbAgeMs(now: Date, file = dbPath()): number | null {
  try {
    const stat = fs.statSync(file);
    if (!stat.isFile() || stat.size === 0) return null;
    return now.getTime() - stat.mtimeMs;
  } catch {
    return null; // missing or unreadable — treat as "no database"
  }
}

export function needsUpdate(now: Date, file = dbPath()): boolean {
  const age = currentDbAgeMs(now, file);
  return age === null || age > MAX_AGE_MS;
}

/**
 * A downloaded file is only accepted if mmdb-lib can actually read it. Without
 * this an HTTP 200 carrying an error page would be gunzip-failed or, worse,
 * installed as a corrupt database over a working one.
 */
export function isValidMmdb(buffer: Buffer): boolean {
  try {
    const reader = new Reader<CountryResponse>(buffer);
    // Any well-known public address will do; we only care that a lookup runs.
    reader.get('1.1.1.1');
    return true;
  } catch {
    return false;
  }
}

async function downloadMonth(stamp: string): Promise<Buffer | null> {
  const url = `${BASE_URL}/dbip-country-lite-${stamp}.mmdb.gz`;
  const response = await fetch(url, { signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS) });
  if (!response.ok) {
    logger.debug(`[GeoIP] ${stamp} not available (HTTP ${response.status})`);
    return null;
  }

  const gz = Buffer.from(await response.arrayBuffer());
  let raw: Buffer;
  try {
    raw = zlib.gunzipSync(gz);
  } catch {
    logger.warn(`[GeoIP] ${stamp} downloaded but could not be decompressed — ignoring`);
    return null;
  }

  if (!isValidMmdb(raw)) {
    logger.warn(`[GeoIP] ${stamp} decompressed but is not a readable MMDB — ignoring`);
    return null;
  }
  return raw;
}

/** Write next to the destination, then rename — atomic on the same filesystem. */
function install(buffer: Buffer, dest: string): void {
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  const tmp = `${dest}.tmp-${process.pid}`;
  try {
    fs.writeFileSync(tmp, buffer);
    fs.renameSync(tmp, dest);
  } catch (error) {
    try {
      fs.unlinkSync(tmp);
    } catch {
      /* best-effort cleanup */
    }
    throw error;
  }
}

/**
 * One update cycle. Returns the one-line result recorded against the job, or
 * null when nothing was due (the caller marks that as skipped rather than ok, so
 * "up to date" and "ran and downloaded" are distinguishable on the dashboard).
 */
export async function runGeoipUpdate(now = new Date()): Promise<string | null> {
  const dest = dbPath();
  if (!needsUpdate(now, dest)) return null;

  const hadDatabase = currentDbAgeMs(now, dest) !== null;
  for (const monthsAgo of [0, 1]) {
    const stamp = monthStamp(now, monthsAgo);
    const buffer = await downloadMonth(stamp);
    if (!buffer) continue;

    install(buffer, dest);
    geoipService.reload(); // pick it up without a restart
    logger.info(
      `[GeoIP] installed ${stamp} database at ${dest} (${buffer.length} bytes). ` +
        `IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0.`
    );
    return `${hadDatabase ? 'updated to' : 'installed'} ${stamp} (${buffer.length} bytes)`;
  }

  throw new Error(
    `could not download ${monthStamp(now, 0)} or ${monthStamp(now, 1)} from ${BASE_URL}`
  );
}

async function tick(): Promise<void> {
  try {
    await trackJobRun(JOB_KEY, async () => {
      const result = await runGeoipUpdate();
      if (result === null) {
        markJobSkipped(JOB_KEY, 'database is current');
        return 'database is current';
      }
      return result;
    });
  } catch (err) {
    logger.error('[GeoIP] update cycle failed:', err);
    // Deduped, so a blocked-egress install logs once a minute rather than once
    // per cycle. Enrichment stays off; nothing else is affected.
    ErrorLogService.logBackgroundError('geoip', err, { dedupeKey: 'update-cycle' });
  }
}

export function startGeoipUpdateJob(): void {
  if (intervalId) return;

  const enabled = isAutoUpdateEnabled();
  registerRecurringJob({
    key: JOB_KEY,
    name: 'GeoIP database update',
    description:
      'Downloads the monthly DB-IP IP-to-Country Lite database used for country enrichment.',
    intervalMs: CHECK_INTERVAL_MS,
    enabled,
  });

  if (!enabled) {
    logger.info('[GeoIP] auto-update disabled (GEOIP_AUTO_UPDATE=false)');
    return;
  }

  startupTimer = setTimeout(() => {
    void tick();
  }, STARTUP_DELAY_MS);
  intervalId = setInterval(() => {
    void tick();
  }, CHECK_INTERVAL_MS);
  logger.info('[GeoIP] update job started');
}

export function stopGeoipUpdateJob(): void {
  if (startupTimer) {
    clearTimeout(startupTimer);
    startupTimer = null;
  }
  if (intervalId) {
    clearInterval(intervalId);
    intervalId = null;
  }
}
