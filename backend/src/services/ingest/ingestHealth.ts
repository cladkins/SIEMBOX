/**
 * Is ingestion alive? Read by GET /health and by the ingestion health job.
 *
 * Stalled means: at least one shipper with an enabled source has checked in
 * recently (so logs should be arriving), yet the newest raw_logs row is older
 * than the threshold (or there is none). A backend whose database does not
 * answer within the read timeout also counts as unhealthy: that is what a
 * wedged connection pool looks like from outside.
 *
 * In Oct-Nov 2026 ingestion stopped for 4.5 days while /health kept answering
 * 200 (it only reported uptime), shippers kept heartbeating and the process
 * held its connections open. Nothing flagged it.
 *
 * Reads are cached for a few seconds and single-flight, so a burst of health
 * probes costs one query.
 */
import { query } from '../../config/database';
import { envInt } from '../../utils/envInt';
import { SHIPPER_OFFLINE_THRESHOLD_MINUTES } from '../../models/LogShipper';

export interface IngestSnapshot {
  /** created_at of the newest raw_logs row, null when there is none. */
  newestRawLogAt: Date | null;
  /** Shippers with an enabled source and a heartbeat within the offline threshold. */
  onlineShippers: number;
}

export interface IngestHealth {
  ok: boolean;
  /** Why it is not ok (absent when ok). */
  reason?: string;
  /** Seconds since the newest raw log, null when unknown or none. */
  newestRawLogAgeSeconds: number | null;
  onlineShippers: number | null;
  thresholdSeconds: number;
}

/** Newest-row age past which /health fails while shippers are online (HEALTH_INGEST_STALL_SECONDS, default 300; 0 turns the check off). */
export function stallThresholdSeconds(): number {
  return envInt('HEALTH_INGEST_STALL_SECONDS', 300, 0);
}

/** Pure verdict over a snapshot. */
export function evaluateIngestHealth(snapshot: IngestSnapshot, thresholdSeconds: number, now: number = Date.now()): IngestHealth {
  const age = snapshot.newestRawLogAt ? Math.max(0, Math.round((now - snapshot.newestRawLogAt.getTime()) / 1000)) : null;
  const base = { newestRawLogAgeSeconds: age, onlineShippers: snapshot.onlineShippers, thresholdSeconds };
  if (thresholdSeconds <= 0 || snapshot.onlineShippers === 0) return { ok: true, ...base };
  if (age === null) {
    return { ok: false, reason: `${snapshot.onlineShippers} shipper(s) online but no logs have been stored`, ...base };
  }
  if (age > thresholdSeconds) {
    return {
      ok: false,
      reason: `no logs stored for ${age}s (threshold ${thresholdSeconds}s) while ${snapshot.onlineShippers} shipper(s) are online`,
      ...base,
    };
  }
  return { ok: true, ...base };
}

export const SNAPSHOT_SQL = `
  SELECT (SELECT MAX(created_at) FROM raw_logs) AS newest,
         (SELECT COUNT(*)::int FROM log_shippers ls
           WHERE ls.last_seen > NOW() - ($1 * INTERVAL '1 minute')
             AND EXISTS (SELECT 1 FROM shipper_sources s WHERE s.shipper_id = ls.id AND s.enabled)) AS online`;

/** One snapshot read, failing after timeoutMs (a hung pool must not hang /health). */
export async function readIngestSnapshot(timeoutMs = 3000): Promise<IngestSnapshot> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`database did not answer within ${timeoutMs}ms`)), timeoutMs);
  });
  try {
    const result = await Promise.race([query(SNAPSHOT_SQL, [SHIPPER_OFFLINE_THRESHOLD_MINUTES]), timeout]);
    const row = result.rows[0] ?? {};
    return { newestRawLogAt: row.newest ? new Date(row.newest) : null, onlineShippers: Number(row.online ?? 0) };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

const CACHE_MS = 10_000;
let cached: { at: number; health: IngestHealth } | null = null;
let inFlight: Promise<IngestHealth> | null = null;

/** Cached, single-flight health for GET /health. Never rejects. */
export function getIngestHealth(now: number = Date.now()): Promise<IngestHealth> {
  if (cached && now - cached.at < CACHE_MS) return Promise.resolve(cached.health);
  inFlight ??= (async () => {
    const threshold = stallThresholdSeconds();
    let health: IngestHealth;
    try {
      health = evaluateIngestHealth(await readIngestSnapshot(), threshold);
    } catch (error) {
      health = {
        ok: false,
        reason: `cannot read ingest state: ${error instanceof Error ? error.message : String(error)}`,
        newestRawLogAgeSeconds: null,
        onlineShippers: null,
        thresholdSeconds: threshold,
      };
    }
    cached = { at: Date.now(), health };
    return health;
  })().finally(() => {
    inFlight = null;
  });
  return inFlight;
}

/** Test seam. */
export function resetIngestHealthCache(): void {
  cached = null;
  inFlight = null;
}
