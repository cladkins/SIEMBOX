/**
 * Drops shipper lines SIEMBox has already stored: a replayed log.
 *
 * A shipper that re-reads a container log from the start resends lines it
 * already sent. Shipper 1.5.0+ puts each line's ORIGINAL timestamp in the
 * syslog header, so a resent line arrives with the same key as the first copy:
 *
 *   (shipper id, hostname, app name = container, header timestamp, message hash)
 *
 * Keys live in a sliding window (two generations, each up to windowMs, so a
 * key is remembered for at least windowMs and at most twice that), capped at
 * maxKeys in all so memory stays bounded whatever the volume.
 *
 * Only lines whose header timestamp lags their arrival by at least minLagMs
 * are ever dropped. A replay carries old timestamps; a live burst of identical
 * lines in the same second (header timestamps have second precision) arrives
 * with a timestamp of about "now" and is kept. The live copy's key is still
 * recorded, so a later replay of it is caught.
 *
 * Applies only to lines with a shipper id: a direct syslog sender (firewall,
 * NAS) never replays, and its header clock is its own.
 *
 * Env: INGEST_DEDUP_ENABLED (default true), INGEST_DEDUP_WINDOW_SECONDS
 * (3600), INGEST_DEDUP_MAX_KEYS (200000), INGEST_DEDUP_MIN_LAG_SECONDS (30).
 */
import { createHash } from 'crypto';
import { envInt } from '../../utils/envInt';

export interface DedupLine {
  shipperId: string | null;
  hostname: string | null;
  appName: string | null;
  /** The header timestamp (the line's original time for shipper 1.5.0+). */
  timestamp: Date;
  message: string;
}

export interface DedupOptions {
  enabled?: boolean;
  windowMs?: number;
  maxKeys?: number;
  minLagMs?: number;
}

export interface DedupStats {
  enabled: boolean;
  /** Duplicate lines dropped since start. */
  dropped: number;
  /** Keys currently remembered. */
  tracked: number;
  windowSeconds: number;
}

export class IngestDedup {
  readonly enabled: boolean;
  private readonly windowMs: number;
  private readonly maxKeys: number;
  private readonly minLagMs: number;
  private current = new Set<string>();
  private previous = new Set<string>();
  private currentStartedAt: number;
  private dropped = 0;

  constructor(opts: DedupOptions = {}, now: number = Date.now()) {
    this.enabled = opts.enabled ?? true;
    this.windowMs = opts.windowMs ?? 3600_000;
    this.maxKeys = Math.max(2, opts.maxKeys ?? 200_000);
    this.minLagMs = opts.minLagMs ?? 30_000;
    this.currentStartedAt = now;
  }

  /** Options from the environment (see the module comment). */
  static fromEnv(): IngestDedup {
    const flag = (process.env.INGEST_DEDUP_ENABLED ?? '').trim().toLowerCase();
    return new IngestDedup({
      enabled: !['false', '0', 'off', 'no'].includes(flag),
      windowMs: envInt('INGEST_DEDUP_WINDOW_SECONDS', 3600, 1) * 1000,
      maxKeys: envInt('INGEST_DEDUP_MAX_KEYS', 200_000, 2),
      minLagMs: envInt('INGEST_DEDUP_MIN_LAG_SECONDS', 30, 0) * 1000,
    });
  }

  /** The key for a line, or null when the line is not subject to dedup. */
  static keyOf(line: DedupLine): string | null {
    if (!line.shipperId) return null;
    const t = line.timestamp.getTime();
    if (!Number.isFinite(t)) return null;
    const second = Math.floor(t / 1000);
    return createHash('sha1')
      .update(`${line.shipperId}\u0000${line.hostname ?? ''}\u0000${line.appName ?? ''}\u0000${second}\u0000`)
      .update(line.message)
      .digest('base64');
  }

  /**
   * True when the line is a replay of one already seen (and counts the drop).
   * Records the key either way.
   */
  isDuplicate(line: DedupLine, receivedAt: number = Date.now()): boolean {
    if (!this.enabled) return false;
    const key = IngestDedup.keyOf(line);
    if (key === null) return false;
    this.rotate(receivedAt);
    const seen = this.current.has(key) || this.previous.has(key);
    if (seen && receivedAt - line.timestamp.getTime() >= this.minLagMs) {
      this.dropped++;
      return true;
    }
    if (!seen) this.current.add(key);
    return false;
  }

  stats(): DedupStats {
    return {
      enabled: this.enabled,
      dropped: this.dropped,
      tracked: this.current.size + this.previous.size,
      windowSeconds: Math.round(this.windowMs / 1000),
    };
  }

  private rotate(now: number): void {
    if (now - this.currentStartedAt < this.windowMs && this.current.size < this.maxKeys / 2) return;
    this.previous = this.current;
    this.current = new Set<string>();
    this.currentStartedAt = now;
  }
}
