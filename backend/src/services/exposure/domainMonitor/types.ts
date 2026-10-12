/**
 * Shared vocabulary of the domain-monitor collectors (Digital Risk, part 2).
 *
 * Every collector is a function from a CollectorContext (the watched domain,
 * its stored baseline and the run's settings) to a CollectorOutput (the new
 * baseline plus the findings it implies). Collectors never touch the
 * database: domainMonitorService records the findings, stores the baseline and
 * isolates one collector's failure from the others.
 */
import crypto from 'crypto';
import type { ExposureSeverity, WatchedDomain } from '../../../models/Exposure';
import type { FindingInput } from '../findingWriter';

export const DOMAIN_MONITOR_SOURCE = 'domain-monitor' as const;

export type CollectorName = 'dns' | 'rdap' | 'lookalike' | 'ct';

/**
 * Run order. CT runs last because, for lookalikes, it checks the domains the
 * lookalike collector just found registered.
 */
export const COLLECTOR_ORDER: readonly CollectorName[] = ['dns', 'rdap', 'lookalike', 'ct'];

export type DomainEventType =
  | 'new_cert'
  | 'unexpected_ca'
  | 'lookalike_registered'
  | 'rdap_change'
  | 'dns_drift'
  | 'expiry_warning';

/** Run-wide settings, read once per run (see settings.getDomainMonitorSettings). */
export interface DomainMonitorConfig {
  /** Warn this many days before a domain's registration expires. */
  expiryWarningDays: number;
  /** Hard cap on lookalike candidates generated (and resolved) per domain. */
  lookalikeMaxCandidates: number;
  /** Optional second DNS resolver (an IP address) that must agree before DNS drift is reported. */
  secondaryResolver: string | null;
  /** Registered lookalikes whose certificates are checked per run (rotating). */
  lookalikeCtChecksPerRun: number;
}

export type MonitoredDomain = Pick<
  WatchedDomain,
  'id' | 'domain' | 'scope' | 'expected_cas' | 'collectors'
>;

export interface SharedLookalikeState {
  /** Every lookalike currently believed registered (the collector's baseline). */
  registered: string[];
  /**
   * Registered lookalikes reported as newly registered recently (see
   * lookalike.ts NEW_REGISTRATION_WINDOW_DAYS). It is derived from the stored
   * snapshot, so the hand-off to CT survives a run in which CT did not run or
   * failed; CT also keeps the ones it has not checked yet (ct.ts pending_new).
   */
  newlyRegistered: string[];
  /**
   * Lookalikes registered again after they had dropped -> when that drop was
   * recorded (lookalike.ts RegisteredInfo.prior_drop). It is part of finding
   * fingerprints, so a new owner's registration is not deduplicated against an
   * earlier owner's findings. Absent when there are none.
   */
  priorDrops?: Record<string, number>;
  /**
   * The same lookalikes -> when that registration was reported (lookalike.ts
   * RegisteredInfo.since). What CT recorded about the name before then belongs
   * to an earlier registration — possibly another owner's certificates — so CT
   * forgets it. Absent when there are none.
   */
  reregisteredAt?: Record<string, number>;
  /**
   * Registered lookalikes that went NXDOMAIN within lookalike.ts
   * REAPPEAR_GRACE_DAYS of when they were last seen registered (a registry
   * hold, or one flapping answer). Back within that time, they are the same
   * registration, so CT keeps what it knows about them meanwhile. Absent when
   * there are none.
   */
  held?: string[];
}

export interface CollectorContext {
  domain: MonitoredDomain;
  /** This collector's stored snapshot; null on its first run. */
  previous: unknown;
  config: DomainMonitorConfig;
  now: Date;
  trigger: 'schedule' | 'manual';
  /** Outputs of the collectors that already ran in this domain run. */
  earlier: Partial<Record<CollectorName, CollectorOutput>>;
  /** Stored snapshots of every collector, as they were when the run began. */
  baselines: Partial<Record<CollectorName, unknown>>;
  /**
   * Every watched domain (lowercase). The organization's own domains are never
   * reported as lookalikes of each other.
   */
  watchedDomains?: readonly string[];
}

export interface CollectorOutput {
  /** The new baseline; undefined leaves the stored one untouched. */
  snapshot?: unknown;
  findings: FindingInput[];
  /** baseline = first run (recorded silently); unsupported = nothing to monitor here. */
  status: 'ok' | 'baseline' | 'unsupported';
  /** One line for the run summary, e.g. "120 candidates checked, 3 registered". */
  note: string;
  /** Small, bounded facts for the run summary (shown by the API). */
  details?: Record<string, unknown>;
  /** Partial failures that did not stop the collector. */
  warnings?: string[];
  /** Set by the lookalike collector for the CT collector. */
  lookalikes?: SharedLookalikeState;
}

export type Collector = (ctx: CollectorContext) => Promise<CollectorOutput>;

/**
 * A collector that could not finish. `transient` failures (timeouts, 5xx,
 * rate limits) are retried sooner than the domain's interval; others wait for
 * the next scheduled run. Either way the baseline is left untouched, so a
 * failed lookup is never mistaken for "nothing changed" or "everything removed".
 *
 * `progress` is the one exception: bookkeeping-only state the service still
 * stores (e.g. which lookalikes CT tried and failed on, so the next attempt
 * moves on to other names instead of repeating the same failing one). A
 * collector must never put a changed baseline in it.
 */
export class CollectorError extends Error {
  readonly transient: boolean;
  readonly progress?: unknown;

  constructor(message: string, transient: boolean, options: { progress?: unknown } = {}) {
    super(message);
    this.name = 'CollectorError';
    this.transient = transient;
    if (options.progress !== undefined) this.progress = options.progress;
  }
}

/**
 * Stable finding fingerprint: sha256 over the JSON encoding of `parts`, so
 * values containing ":" (IPv6 addresses, TXT records) can't collide.
 */
export function fingerprint(...parts: Array<string | number | boolean | null | string[]>): string {
  return crypto.createHash('sha256').update(JSON.stringify(parts)).digest('hex');
}

export interface DomainFindingParams {
  domainId: number;
  eventType: DomainEventType;
  fingerprint: string;
  title: string;
  severity: ExposureSeverity;
  description: string;
  detail: Record<string, unknown>;
}

export function domainFinding(params: DomainFindingParams): FindingInput {
  return {
    source: DOMAIN_MONITOR_SOURCE,
    domainId: params.domainId,
    eventType: params.eventType,
    fingerprint: params.fingerprint,
    title: params.title,
    severity: params.severity,
    description: params.description,
    detail: params.detail,
  };
}

/** Sorted, de-duplicated copy. */
export function sortedUnique(values: Iterable<string>): string[] {
  return [...new Set(values)].sort();
}

/** Order-insensitive equality of two already-sorted string lists. */
export function sameList(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((value, i) => value === b[i]);
}

/** At most `max` items, for details/summaries that must stay small. */
export function capList<T>(values: readonly T[], max: number): T[] {
  return values.slice(0, Math.max(0, max));
}

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
