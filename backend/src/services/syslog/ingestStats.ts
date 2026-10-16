/**
 * Read access to the running syslog server's ingest queue counters (depth,
 * processed, and `dropped`: UDP messages refused because the queue was full)
 * from code that has no handle on the server. server.ts keeps its SyslogServer
 * module-local; it registers the server's getIngestStats() here once start()
 * has succeeded, and clears it at shutdown. The Big Display's ingestion panel
 * reads `dropped` through this to show UDP drops in the last 15 minutes.
 */
import type { SyslogServer } from './syslogServer';

export type SyslogIngestStats = ReturnType<SyslogServer['getIngestStats']>;

let source: (() => SyslogIngestStats) | null = null;

/** Register the running server's stats (server.ts, after start()); null clears it. */
export function registerIngestStats(fn: (() => SyslogIngestStats) | null): void {
  source = fn;
}

/**
 * The running syslog server's queue counters, or null when no syslog server is
 * running (before start, after shutdown, and in tests and scripts).
 */
export function getIngestQueueStats(): SyslogIngestStats | null {
  if (!source) return null;
  try {
    return source();
  } catch {
    return null;
  }
}
