// Shared types for the generic API-pull poller (Log Discovery sources whose
// fingerprint declares log_access: [{method: api_pull, ...}]). See poller.ts
// for the orchestration loop and registry.ts for how a fingerprint id resolves
// to one of these.
import { LogAccessMethod } from '../types';

export interface PollCredential {
  /** Only set for HTTP Basic auth (adguard-home today); null for bearer/query-param-token adapters. */
  username: string | null;
  secret: string;
}

export interface PollTarget {
  sourceId: number;
  ip: string;
  openPorts: number[];
  /** discovery_sources.evidence — scan-captured signals (http_responses, etc.), currently unused by any adapter but available for smarter base-URL selection later. */
  evidence: Record<string, unknown>;
  logAccess: LogAccessMethod;
}

export interface PolledEvent {
  /** The bare extracted message — must match what the target catalog parser expects, never a framed/prefixed line (see CLAUDE.md's parser rule). */
  message: string;
  timestamp: Date | null;
  /** Stable per-event id for raw_logs dedup, when the source API provides one. Null means the cursor alone is responsible for not re-ingesting. */
  eventId: string | null;
}

export interface PollFetchResult {
  events: PolledEvent[];
  /** Opaque; only this adapter interprets it. Null resets to "never polled" — an adapter should not normally return null once it has successfully polled at least once. */
  nextCursor: string | null;
}

export interface ApiPollAdapter {
  /** Matches a fingerprint's `id` (fingerprints/<id>.yaml), and discovery_source_pollers.fingerprint_id. */
  fingerprintId: string;
  fetchEvents(target: PollTarget, credential: PollCredential, cursor: string | null): Promise<PollFetchResult>;
}
