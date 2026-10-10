/**
 * Leaked-credential checks: is a monitored email address — or any address at a
 * monitored email domain — in a known data breach?
 *
 * Breach data comes from a pluggable ExposureSource; Have I Been Pwned is the
 * one implementation today (bring-your-own-key, see settings.ts). Each breach
 * an identity appears in becomes one exposure finding (and, the first time, one
 * alert) through findingWriter.recordFinding, fingerprinted on
 * kind:value:[alias:]breachName so re-checks are idempotent.
 *
 * Scheduling: runLeakedCredentialChecks() processes the identities that are
 * DUE (never checked, or last checked longer ago than their own interval),
 * sequentially, pacing HIBP calls to the key's plan (requests per minute from
 * subscription/status, the smallest plan's 10 RPM until known). A 429 pauses
 * all checks until HIBP's retry-after has passed and ends the cycle; a
 * rejected key pauses for an hour (or until the key is changed) — neither
 * retries in a loop. The remaining identities stay due for the next cycle.
 */
import crypto from 'crypto';
import { logger } from '../../utils/logger';
import {
  MonitoredIdentityModel,
  type MonitoredIdentity,
  type ExposureSeverity,
} from '../../models/Exposure';
import {
  recordFinding,
  toExposureNotice,
  type FindingInput,
  type RecordFindingResult,
} from './findingWriter';
import { NotificationService, type ExposureNotice } from '../notifications/notificationService';
import { HibpClient, HibpError, DEFAULT_RETRY_AFTER_SECONDS, type HibpBreach } from './hibpClient';
import { getExposureSetting, getHibpApiKey, isHibpEnabled, HIBP_PROVIDER } from './settings';

export const LEAKED_CREDS_SOURCE = 'leaked-creds' as const;
/** Job-registry key of the scheduled run (jobs/leakedCreds.ts). */
export const LEAKED_CREDS_JOB_KEY = 'leaked-creds';

// ---- Source abstraction ------------------------------------------------------

/** Breach metadata, independent of the provider that reported it. */
export interface BreachRecord {
  name: string;
  title: string;
  domain: string | null;
  breachDate: string | null;
  addedDate: string | null;
  dataClasses: string[];
  isVerified: boolean;
  isSensitive: boolean;
  isStealerLog: boolean;
  isSpamList: boolean;
  isFabricated: boolean;
}

/** One account found in one breach. `alias` is set for email-domain searches. */
export interface ExposureHit {
  account: string;
  alias?: string;
  breach: BreachRecord;
}

export type IdentityRef = Pick<MonitoredIdentity, 'kind' | 'value'>;

/**
 * How a check failed, which decides what the run loop does next:
 *  - rate_limited: pause every check until retryAfterSeconds pass; end the cycle
 *  - auth: the key is unusable; pause and end the cycle
 *  - identity: about this identity only (e.g. unverified domain); skip it until
 *    its next interval and carry on
 *  - transient: provider trouble; leave the identity due and carry on, but end
 *    the cycle after repeated failures
 */
export type ExposureSourceErrorKind = 'rate_limited' | 'auth' | 'identity' | 'transient';

export class ExposureSourceError extends Error {
  readonly kind: ExposureSourceErrorKind;
  readonly retryAfterSeconds: number | null;

  constructor(
    kind: ExposureSourceErrorKind,
    message: string,
    retryAfterSeconds: number | null = null
  ) {
    super(message);
    this.name = 'ExposureSourceError';
    this.kind = kind;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

export interface ExposureSource {
  readonly id: string;
  readonly label: string;
  /** Link the data must be attributed to wherever it is shown. */
  readonly attribution: string;
  isConfigured(): Promise<boolean>;
  /** Every breach hit for the identity; throws ExposureSourceError. */
  check(identity: IdentityRef): Promise<ExposureHit[]>;
}

// ---- Severity, fingerprint, finding -------------------------------------------

// Data classes that hand an attacker a way into the account. Hashed passwords
// count too: leaked hashes get cracked offline.
const CREDENTIAL_DATA_CLASSES = new Set(['passwords', 'historical passwords', 'auth tokens']);

export function exposesCredentials(breach: BreachRecord): boolean {
  return breach.dataClasses.some((c) => CREDENTIAL_DATA_CLASSES.has(c.trim().toLowerCase()));
}

/**
 * high   — credential material (passwords, historical passwords, auth tokens),
 *          a stealer log (credentials harvested from an infected device), or a
 *          sensitive breach (only visible to verified-domain searches; an
 *          extortion and phishing lever);
 * low    — a spam list or fabricated breach without credential material: an
 *          address list of doubtful provenance means more spam, not takeover;
 * medium — everything else: personal data that fuels phishing.
 */
export function breachSeverity(breach: BreachRecord): ExposureSeverity {
  if (breach.isStealerLog || exposesCredentials(breach)) return 'high';
  if (breach.isSensitive) return 'high';
  if (breach.isSpamList || breach.isFabricated) return 'low';
  return 'medium';
}

/** sha256(kind:value:[alias:]breachName) — stable across checks and restarts. */
export function breachFingerprint(
  identity: IdentityRef,
  breachName: string,
  alias?: string
): string {
  const parts = [identity.kind, identity.value.toLowerCase()];
  if (alias) parts.push(alias.toLowerCase());
  parts.push(breachName);
  return crypto.createHash('sha256').update(parts.join(':')).digest('hex');
}

type SourceInfo = Pick<ExposureSource, 'id' | 'label' | 'attribution'>;

function describeBreach(source: SourceInfo, hit: ExposureHit): string {
  const b = hit.breach;
  const parts = [
    `${hit.account} appears in the ${b.title} breach${b.domain ? ` (${b.domain})` : ''}.`,
  ];
  if (b.breachDate) parts.push(`Breach date: ${b.breachDate}.`);
  if (b.dataClasses.length > 0) parts.push(`Exposed data: ${b.dataClasses.join(', ')}.`);
  if (exposesCredentials(b) || b.isStealerLog) {
    parts.push('Change this password everywhere it was used and turn on MFA for the account.');
  }
  parts.push(`Source: ${source.label} (${source.attribution}).`);
  return parts.join(' ');
}

export function buildBreachFinding(
  source: SourceInfo,
  identity: Pick<MonitoredIdentity, 'id' | 'kind' | 'value'>,
  hit: ExposureHit
): FindingInput {
  const b = hit.breach;
  return {
    source: LEAKED_CREDS_SOURCE,
    identityId: identity.id,
    eventType: 'breach',
    fingerprint: breachFingerprint(identity, b.name, hit.alias),
    title: `${hit.account} found in ${b.title} breach`,
    severity: breachSeverity(b),
    description: describeBreach(source, hit),
    detail: {
      account: hit.account,
      ...(hit.alias ? { alias: hit.alias } : {}),
      breach_name: b.name,
      breach_title: b.title,
      breach_domain: b.domain,
      breach_date: b.breachDate,
      added_date: b.addedDate,
      data_classes: b.dataClasses,
      is_verified: b.isVerified,
      is_sensitive: b.isSensitive,
      is_stealer_log: b.isStealerLog,
      is_spam_list: b.isSpamList,
      is_fabricated: b.isFabricated,
      source: source.id,
      attribution: source.attribution,
    },
  };
}

// ---- Have I Been Pwned ---------------------------------------------------------

const str = (v: unknown): string | null => (typeof v === 'string' && v.length > 0 ? v : null);

export function toBreachRecord(b: HibpBreach): BreachRecord {
  return {
    name: b.Name,
    title: str(b.Title) ?? b.Name,
    domain: str(b.Domain),
    breachDate: str(b.BreachDate),
    addedDate: str(b.AddedDate),
    dataClasses: Array.isArray(b.DataClasses)
      ? b.DataClasses.filter((c) => typeof c === 'string')
      : [],
    isVerified: b.IsVerified === true,
    isSensitive: b.IsSensitive === true,
    isStealerLog: b.IsStealerLog === true,
    isSpamList: b.IsSpamList === true,
    isFabricated: b.IsFabricated === true,
  };
}

/** A breach the catalog doesn't know (yet): name only, so it maps to medium. */
function unknownBreach(name: string): BreachRecord {
  return toBreachRecord({ Name: name });
}

const DEFAULT_RPM = 10; // HIBP's smallest plan
const RPM_TTL_MS = 6 * 60 * 60 * 1000;
const CATALOG_TTL_MS = 6 * 60 * 60 * 1000;
const CATALOG_MIN_REFRESH_MS = 10 * 60 * 1000;

/** Minimum gap between keyed HIBP calls for a plan's requests-per-minute. */
export function spacingForRpm(rpm: number | null | undefined): number {
  const perMinute = typeof rpm === 'number' && Number.isFinite(rpm) && rpm > 0 ? rpm : DEFAULT_RPM;
  return Math.ceil(60_000 / perMinute) + 100; // + headroom for clock skew
}

type HibpClientLike = Pick<
  HibpClient,
  'breachedAccount' | 'breachedDomain' | 'allBreaches' | 'subscriptionStatus'
>;

export interface HibpSourceOptions {
  getApiKey?: () => Promise<string | undefined>;
  isEnabled?: () => Promise<boolean>;
  createClient?: (apiKey: string) => HibpClientLike;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}

function toSourceError(err: unknown): ExposureSourceError {
  if (err instanceof ExposureSourceError) return err;
  if (!(err instanceof HibpError)) {
    return new ExposureSourceError('transient', err instanceof Error ? err.message : String(err));
  }
  switch (err.kind) {
    case 'rate_limited':
      return new ExposureSourceError(
        'rate_limited',
        err.message,
        err.retryAfterSeconds ?? DEFAULT_RETRY_AFTER_SECONDS
      );
    case 'bad_request':
      return new ExposureSourceError('identity', err.message);
    case 'auth':
      return new ExposureSourceError('auth', err.message);
    default:
      return new ExposureSourceError('transient', err.message);
  }
}

export class HibpSource implements ExposureSource {
  readonly id = 'hibp';
  readonly label = HIBP_PROVIDER.label;
  readonly attribution = HIBP_PROVIDER.attribution;

  private readonly getApiKey: () => Promise<string | undefined>;
  private readonly isEnabled: () => Promise<boolean>;
  private readonly createClient: (apiKey: string) => HibpClientLike;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly now: () => number;

  private lastCallAt = 0;
  private rpm: { value: number | null; at: number } | null = null;
  private catalog: { byName: Map<string, BreachRecord>; at: number } | null = null;

  constructor(options: HibpSourceOptions = {}) {
    this.getApiKey = options.getApiKey ?? getHibpApiKey;
    this.isEnabled = options.isEnabled ?? isHibpEnabled;
    this.createClient = options.createClient ?? ((apiKey) => new HibpClient({ apiKey }));
    this.sleep = options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    this.now = options.now ?? Date.now;
  }

  async isConfigured(): Promise<boolean> {
    return (await this.isEnabled()) && !!(await this.getApiKey());
  }

  /** Forget what was learned about the key (call after the key changes). */
  reset(): void {
    this.rpm = null;
  }

  async check(identity: IdentityRef): Promise<ExposureHit[]> {
    const apiKey = await this.getApiKey();
    if (!apiKey) throw new ExposureSourceError('auth', 'No usable HIBP API key is configured');
    const client = this.createClient(apiKey);
    try {
      await this.learnRateLimit(client);
      await this.pace();
      if (identity.kind === 'email') {
        const breaches = await client.breachedAccount(identity.value);
        return breaches.map((b) => ({ account: identity.value, breach: toBreachRecord(b) }));
      }
      let byAlias: Record<string, string[]>;
      try {
        byAlias = await client.breachedDomain(identity.value);
      } catch (err) {
        // A 403 on a domain search is about that domain, not the key: HIBP only
        // searches domains the key owner has verified (and within the plan's size).
        if (err instanceof HibpError && err.status === 403) {
          throw new ExposureSourceError(
            'identity',
            'HIBP refused the domain search (HTTP 403): verify this domain in your HIBP domain ' +
              'dashboard, and check that your plan covers its number of breached accounts'
          );
        }
        throw err;
      }
      return await this.expandDomainHits(client, identity.value, byAlias);
    } catch (err) {
      throw toSourceError(err);
    }
  }

  /** Space keyed calls so a cycle stays under the plan's requests per minute. */
  private async pace(): Promise<void> {
    const wait = this.lastCallAt + spacingForRpm(this.rpm?.value) - this.now();
    if (wait > 0) await this.sleep(wait);
    this.lastCallAt = this.now();
  }

  /**
   * Read the plan's RPM from subscription/status (cached). Best effort: only a
   * 429 stops the cycle. Any other failure just means pacing for the smallest
   * plan until the next refresh — the breach search that follows is the
   * authoritative key check (HIBP's documented test key, for one, is refused
   * here but accepted by the breach endpoints).
   */
  private async learnRateLimit(client: HibpClientLike): Promise<void> {
    if (this.rpm && this.now() - this.rpm.at < RPM_TTL_MS) return;
    let value: number | null = null;
    try {
      await this.pace();
      const status = await client.subscriptionStatus();
      value = typeof status.Rpm === 'number' && status.Rpm > 0 ? status.Rpm : null;
    } catch (err) {
      if (err instanceof HibpError && err.kind === 'rate_limited') throw err;
    }
    this.rpm = { value, at: this.now() };
  }

  /** The domain search returns names only; fill in each breach from the catalog. */
  private async expandDomainHits(
    client: HibpClientLike,
    domain: string,
    byAlias: Record<string, string[]>
  ): Promise<ExposureHit[]> {
    const names = new Set(Object.values(byAlias).flat());
    if (names.size === 0) return [];
    let catalog = await this.breachCatalog(client, false);
    if ([...names].some((name) => !catalog.has(name.toLowerCase()))) {
      catalog = await this.breachCatalog(client, true); // a breach newer than our copy
    }
    const hits: ExposureHit[] = [];
    for (const [rawAlias, breachNames] of Object.entries(byAlias)) {
      const alias = rawAlias.toLowerCase();
      for (const name of new Set(breachNames)) {
        hits.push({
          account: `${alias}@${domain}`,
          alias,
          breach: catalog.get(name.toLowerCase()) ?? unknownBreach(name),
        });
      }
    }
    return hits;
  }

  private async breachCatalog(
    client: HibpClientLike,
    refresh: boolean
  ): Promise<Map<string, BreachRecord>> {
    const maxAge = refresh ? CATALOG_MIN_REFRESH_MS : CATALOG_TTL_MS;
    if (this.catalog && this.now() - this.catalog.at < maxAge) return this.catalog.byName;
    const breaches = await client.allBreaches();
    this.catalog = {
      byName: new Map(breaches.map((b) => [b.Name.toLowerCase(), toBreachRecord(b)])),
      at: this.now(),
    };
    return this.catalog.byName;
  }
}

// ---- Run loop ----------------------------------------------------------------------

export interface LeakedCredentialRunSummary {
  /** Identities checked successfully. */
  checked: number;
  /** Findings seen for the first time. */
  newFindings: number;
  /** Identities whose check failed (see their last_error). */
  failed: number;
  /** Identities still due after this run (left for the next cycle). */
  remaining: number;
  /** True when the run did no work; `reason` says why. */
  skipped: boolean;
  reason?: string;
  /** Why the run stopped early (rate limit, rejected key, provider down). */
  error?: string;
  /** Set when HIBP rate-limited the run: no checks before this time. */
  rateLimitedUntil?: string;
}

/** Persistence and side effects of a run — swappable so the loop is testable. */
export interface LeakedCredentialStore {
  isEnabled(): Promise<boolean>;
  findDue(limit: number, force: boolean): Promise<MonitoredIdentity[]>;
  countDue(force: boolean): Promise<number>;
  markChecked(id: number): Promise<void>;
  markFailed(id: number, error: string, advance: boolean): Promise<void>;
  recordFinding(input: FindingInput): Promise<RecordFindingResult>;
  notify(notices: ExposureNotice[]): Promise<void>;
}

const dbStore: LeakedCredentialStore = {
  isEnabled: async () => (await getExposureSetting('exposure_leaked_creds_enabled')) === 'true',
  findDue: (limit, force) => MonitoredIdentityModel.findDue(limit, force),
  countDue: (force) => MonitoredIdentityModel.countDue(force),
  markChecked: (id) => MonitoredIdentityModel.markChecked(id),
  markFailed: (id, error, advance) => MonitoredIdentityModel.markFailed(id, error, advance),
  // Notifications are sent once per identity (grouped), not once per finding.
  recordFinding: (input) => recordFinding(input, { notify: false }),
  notify: (notices) => NotificationService.notifyExposure(notices),
};

export interface RunOptions {
  trigger?: 'schedule' | 'manual';
  /** Check every enabled identity, ignoring intervals (admin "run now"). */
  force?: boolean;
  /** Stop starting new checks after this long; the rest stay due. */
  budgetMs?: number;
  maxIdentities?: number;
  source?: ExposureSource;
  store?: LeakedCredentialStore;
}

export const SCHEDULED_RUN_BUDGET_MS = 10 * 60 * 1000;
export const MANUAL_RUN_BUDGET_MS = 90 * 1000;
export const LEAKED_CREDS_ALREADY_RUNNING = 'a leaked-credential check is already running';
const DEFAULT_MAX_IDENTITIES = 100;
const AUTH_PAUSE_MS = 60 * 60 * 1000;
const MAX_CONSECUTIVE_TRANSIENT = 2;

const hibpSource = new HibpSource();

// In-process state, like the job registry: it describes this process's runs.
let inFlight: Promise<LeakedCredentialRunSummary> | null = null;
let pausedUntil = 0;
let pauseReason: string | null = null;
let lastRun: { at: string; trigger: string; summary: LeakedCredentialRunSummary } | null = null;

function pause(untilMs: number, reason: string): void {
  pausedUntil = untilMs;
  pauseReason = reason;
  logger.warn(`[LeakedCreds] ${reason}`);
}

/** Lift a rate-limit/auth pause and forget the cached plan — call when the HIBP key or flag changes. */
export function resetLeakedCredentialPause(): void {
  pausedUntil = 0;
  pauseReason = null;
  hibpSource.reset();
}

export function getLeakedCredentialRunState(): {
  running: boolean;
  paused_until: string | null;
  pause_reason: string | null;
  last_run: { at: string; trigger: string; summary: LeakedCredentialRunSummary } | null;
} {
  const paused = pausedUntil > Date.now();
  return {
    running: inFlight !== null,
    paused_until: paused ? new Date(pausedUntil).toISOString() : null,
    pause_reason: paused ? pauseReason : null,
    last_run: lastRun,
  };
}

const skippedRun = (reason: string): LeakedCredentialRunSummary => ({
  checked: 0,
  newFindings: 0,
  failed: 0,
  remaining: 0,
  skipped: true,
  reason,
});

/** Why a run would do nothing right now, or null when there is work to do. */
export async function getLeakedCredentialSkipReason(
  options: Pick<RunOptions, 'force' | 'source' | 'store'> = {}
): Promise<string | null> {
  const source = options.source ?? hibpSource;
  const store = options.store ?? dbStore;
  const force = options.force === true;
  if (!(await store.isEnabled())) return 'leaked-credential checks are disabled in settings';
  if (!(await source.isConfigured())) {
    return 'no breach-data provider is configured (save an HIBP API key and enable the provider)';
  }
  if (pausedUntil > Date.now())
    return pauseReason ?? `paused until ${new Date(pausedUntil).toISOString()}`;
  if ((await store.countDue(force)) === 0)
    return force ? 'no enabled identities to check' : 'no identities are due';
  return null;
}

/** One-line outcome for the job registry / logs. */
export function describeRunSummary(s: LeakedCredentialRunSummary): string {
  if (s.skipped) return `skipped: ${s.reason}`;
  const parts = [
    `checked ${s.checked} identit${s.checked === 1 ? 'y' : 'ies'}`,
    `${s.newFindings} new finding${s.newFindings === 1 ? '' : 's'}`,
  ];
  if (s.failed) parts.push(`${s.failed} failed`);
  if (s.remaining) parts.push(`${s.remaining} still due`);
  return parts.join(', ') + (s.error ? ` (stopped: ${s.error})` : '');
}

/**
 * Check every due identity once. Concurrent calls don't overlap: while a run
 * is in flight, another call returns a skipped summary straight away.
 */
export function runLeakedCredentialChecks(
  options: RunOptions = {}
): Promise<LeakedCredentialRunSummary> {
  if (inFlight) return Promise.resolve(skippedRun(LEAKED_CREDS_ALREADY_RUNNING));
  const run = executeRun(options).finally(() => {
    inFlight = null;
  });
  inFlight = run;
  return run;
}

async function executeRun(options: RunOptions): Promise<LeakedCredentialRunSummary> {
  const source = options.source ?? hibpSource;
  const store = options.store ?? dbStore;
  const force = options.force === true;

  const reason = await getLeakedCredentialSkipReason({ force, source, store });
  if (reason) return skippedRun(reason);

  const identities = await store.findDue(options.maxIdentities ?? DEFAULT_MAX_IDENTITIES, force);
  const budgetMs = options.budgetMs ?? SCHEDULED_RUN_BUDGET_MS;
  const startedAt = Date.now();
  const summary: LeakedCredentialRunSummary = {
    checked: 0,
    newFindings: 0,
    failed: 0,
    remaining: 0,
    skipped: false,
  };
  let consecutiveTransient = 0;

  for (const identity of identities) {
    if (Date.now() - startedAt >= budgetMs) break; // the rest stay due

    let hits: ExposureHit[];
    try {
      hits = await source.check(identity);
    } catch (err) {
      const e = toSourceError(err);
      if (e.kind === 'rate_limited') {
        const until =
          Date.now() + ((e.retryAfterSeconds ?? DEFAULT_RETRY_AFTER_SECONDS) + 1) * 1000;
        summary.rateLimitedUntil = new Date(until).toISOString();
        summary.error = e.message;
        pause(
          until,
          `${source.label} rate limit reached; checks resume after ${summary.rateLimitedUntil}`
        );
        break;
      }
      if (e.kind === 'auth') {
        summary.error = e.message;
        pause(
          Date.now() + AUTH_PAUSE_MS,
          `${e.message}; checks are paused for an hour or until the key is updated`
        );
        break;
      }
      summary.failed++;
      logger.warn(`[LeakedCreds] check failed for identity #${identity.id}: ${e.message}`);
      await store.markFailed(identity.id, e.message, e.kind === 'identity');
      consecutiveTransient = e.kind === 'transient' ? consecutiveTransient + 1 : 0;
      if (consecutiveTransient >= MAX_CONSECUTIVE_TRANSIENT) {
        summary.error = `${source.label} looks unavailable (${e.message})`;
        break;
      }
      continue;
    }
    consecutiveTransient = 0;

    const fresh: ExposureNotice[] = [];
    for (const hit of hits) {
      const finding = buildBreachFinding(source, identity, hit);
      const result = await store.recordFinding(finding);
      if (result.isNew) summary.newFindings++;
      if (result.alertCreated) fresh.push(toExposureNotice(finding));
    }
    await store.markChecked(identity.id);
    summary.checked++;
    if (fresh.length > 0) await store.notify(fresh);
  }

  summary.remaining = await store.countDue(false);
  lastRun = { at: new Date().toISOString(), trigger: options.trigger ?? 'schedule', summary };
  return summary;
}
