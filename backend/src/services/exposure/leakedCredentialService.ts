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
 *
 * Email domains: HIBP only searches a domain verified on the key's account
 * (403 otherwise). Before searching a due email domain the run makes sure it
 * knows which domains are verified (the subscribeddomains list, kept in
 * system_settings: see hibpDomains.ts, refreshed at most every few hours) and
 * skips the ones a complete list doesn't include: last_status 'unverified',
 * no HIBP call, not a failure. When the list can't be read the domain is
 * searched as before, and a 403 then reads as "unverified" too.
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
import {
  HibpClient,
  HibpError,
  DEFAULT_RETRY_AFTER_SECONDS,
  type HibpBreach,
  type HibpSubscribedDomainList,
  type HibpSubscriptionStatus,
} from './hibpClient';
import { getExposureSetting, getHibpApiKey, isHibpEnabled, HIBP_PROVIDER } from './settings';
import {
  buildSnapshot,
  failedSnapshot,
  hibpDomainStatus,
  isListedState,
  isSkippedState,
  markHibpDomainSnapshotStale,
  needsDomainRefresh,
  planFromStatus,
  readHibpDomainSnapshot,
  skipNote,
  toDomainListError,
  toHibpVerifiedDomainsView,
  updateHibpDomainSnapshot,
  type HibpDomainListError,
  type HibpDomainSnapshot,
  type HibpDomainSnapshotState,
  type HibpPlanSnapshot,
  type HibpVerifiedDomainsView,
  type IdentityHibpDomain,
} from './hibpDomains';

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
  /**
   * Credit the party that supplied the breach asked for (HIBP's `Attribution`):
   * plain text, control characters removed, at most 300 characters; null/absent
   * when there is none.
   */
  attribution?: string | null;
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
 *  - identity: about this identity only (e.g. a malformed value); skip it until
 *    its next interval and carry on
 *  - unverified: the provider won't search this email domain for this account
 *    (HIBP's 403 on a domain search: not verified, or no domain search on the
 *    plan); recorded as 'unverified' rather than a failure, then carry on
 *  - transient: provider trouble; leave the identity due and carry on, but end
 *    the cycle after repeated failures
 */
export type ExposureSourceErrorKind = 'rate_limited' | 'auth' | 'identity' | 'unverified' | 'transient';

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

/** A verified-domain listing: the account's domains and, when known, its plan. */
export interface VerifiedDomainListing {
  list: HibpSubscribedDomainList;
  /** null when the plan couldn't be read (the previous one is kept). */
  plan: HibpPlanSnapshot | null;
}

export interface ExposureSource {
  readonly id: string;
  readonly label: string;
  /** Link the data must be attributed to wherever it is shown. */
  readonly attribution: string;
  /** The data's licence, credited next to the attribution link in descriptions. */
  readonly license?: { name: string; url: string };
  isConfigured(): Promise<boolean>;
  /** Every breach hit for the identity; throws ExposureSourceError. */
  check(identity: IdentityRef): Promise<ExposureHit[]>;
  /**
   * The email domains the account may search (HIBP: subscribeddomains), for a
   * source whose domain search is limited to verified domains. Throws the
   * provider's error (HibpError) so its HTTP status can be classified.
   * `refreshPlan` re-reads the plan instead of using the cached one.
   */
  listVerifiedDomains?(options: { refreshPlan: boolean }): Promise<VerifiedDomainListing>;
}

/** last_error when a domain search was refused (403) while verification was unknown. */
export const FALLBACK_403_NOTE =
  "HIBP refused the domain search (HTTP 403): the domain isn't verified on this HIBP account, or the key's " +
  "plan doesn't include domain search. Verify it in the HIBP dashboard, then re-check verification.";

/** last_error when HIBP refused (403) a domain its own list shows as verified. */
export const CONTRADICTION_NOTE =
  'HIBP refused the domain search (HTTP 403) although the domain is listed as verified on your HIBP account: ' +
  'the plan may not cover it (number of domains, or a plan without domain search), or it was just removed ' +
  'from the dashboard. SIEMBox re-reads the list before the next search.';

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

type SourceInfo = Pick<ExposureSource, 'id' | 'label' | 'attribution' | 'license'>;

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
  // HIBP's licence (CC BY 4.0) asks for clear attribution with a link wherever
  // its data is used: alert descriptions, notifications and exports carry it.
  const license = source.license ? `, licensed under ${source.license.name} (${source.license.url})` : '';
  parts.push(`Source: ${source.label} (${source.attribution})${license}.`);
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
      // Credit the provider of the breach data designated (plain text only).
      ...(b.attribution ? { breach_attribution: b.attribution } : {}),
    },
  };
}

// ---- Have I Been Pwned ---------------------------------------------------------

const str = (v: unknown): string | null => (typeof v === 'string' && v.length > 0 ? v : null);

const MAX_BREACH_ATTRIBUTION_LENGTH = 300;

/**
 * HIBP's per-breach Attribution as plain text: control characters (and the
 * invisible bidi/zero-width formatting ones, which could reorder what is
 * displayed) become spaces; trimmed, capped; null if empty.
 */
export function cleanBreachAttribution(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const text = value
    // eslint-disable-next-line no-control-regex -- stripping control characters is the point
    .replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/g, ' ')
    .trim();
  return text ? text.slice(0, MAX_BREACH_ATTRIBUTION_LENGTH).trim() : null;
}

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
    attribution: cleanBreachAttribution(b.Attribution),
  };
}

/** A breach the catalog doesn't know (yet): name only, so it maps to medium. */
function unknownBreach(name: string): BreachRecord {
  return toBreachRecord({ Name: name });
}

const DEFAULT_RPM = 10; // HIBP's smallest plan
const PLAN_TTL_MS = 6 * 60 * 60 * 1000;
const CATALOG_TTL_MS = 6 * 60 * 60 * 1000;
const CATALOG_MIN_REFRESH_MS = 10 * 60 * 1000;

/** Minimum gap between keyed HIBP calls for a plan's requests-per-minute. */
export function spacingForRpm(rpm: number | null | undefined): number {
  const perMinute = typeof rpm === 'number' && Number.isFinite(rpm) && rpm > 0 ? rpm : DEFAULT_RPM;
  return Math.ceil(60_000 / perMinute) + 100; // + headroom for clock skew
}

type HibpClientLike = Pick<
  HibpClient,
  'breachedAccount' | 'breachedDomain' | 'allBreaches' | 'subscriptionStatus' | 'subscribedDomains'
>;

export interface HibpSourceOptions {
  getApiKey?: () => Promise<string | undefined>;
  isEnabled?: () => Promise<boolean>;
  createClient?: (apiKey: string) => HibpClientLike;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
  /**
   * End of a rate-limit pause (ms since the epoch, as `now`), or 0: no keyed
   * call is sent before it, whoever is calling. The service's own source reads
   * the shared leaked-credential pause.
   */
  pausedUntil?: () => number;
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
  readonly license = { name: HIBP_PROVIDER.license, url: HIBP_PROVIDER.licenseUrl };

  private readonly getApiKey: () => Promise<string | undefined>;
  private readonly isEnabled: () => Promise<boolean>;
  private readonly createClient: (apiKey: string) => HibpClientLike;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly now: () => number;
  private readonly pausedUntil: () => number;

  private lastCallAt = 0;
  /** Every keyed call takes its turn here, so concurrent callers (a run and an admin's re-check) never burst. */
  private paceChain: Promise<void> = Promise.resolve();
  /** subscription/status, cached; `status` null when it couldn't be read. */
  private plan: { status: HibpSubscriptionStatus | null; at: number } | null = null;
  /** The plan lookup in flight, shared by concurrent callers. */
  private planLookup: Promise<HibpSubscriptionStatus | null> | null = null;
  /** Bumped by reset(), so a lookup started for the old key doesn't fill the cache. */
  private planGeneration = 0;
  private catalog: { byName: Map<string, BreachRecord>; at: number } | null = null;

  constructor(options: HibpSourceOptions = {}) {
    this.getApiKey = options.getApiKey ?? getHibpApiKey;
    this.isEnabled = options.isEnabled ?? isHibpEnabled;
    this.createClient = options.createClient ?? ((apiKey) => new HibpClient({ apiKey }));
    this.sleep = options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    this.now = options.now ?? Date.now;
    this.pausedUntil = options.pausedUntil ?? (() => 0);
  }

  async isConfigured(): Promise<boolean> {
    return (await this.isEnabled()) && !!(await this.getApiKey());
  }

  /** Forget what was learned about the key (call after the key changes). */
  reset(): void {
    this.plan = null;
    this.planLookup = null;
    this.planGeneration++;
  }

  async check(identity: IdentityRef): Promise<ExposureHit[]> {
    const apiKey = await this.getApiKey();
    if (!apiKey) throw new ExposureSourceError('auth', 'No usable HIBP API key is configured');
    const client = this.createClient(apiKey);
    try {
      await this.learnPlan(client, false);
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
        // searches domains verified on the key's account, and only on plans with
        // domain search. (A domain larger than the plan is NOT refused: HIBP
        // answers 200 with only its subscription-free breaches.)
        if (err instanceof HibpError && err.status === 403) {
          throw new ExposureSourceError('unverified', FALLBACK_403_NOTE);
        }
        throw err;
      }
      return await this.expandDomainHits(client, identity.value, byAlias);
    } catch (err) {
      throw toSourceError(err);
    }
  }

  /**
   * The domains verified on the key's account (subscribeddomains), with the
   * plan (cached subscription/status, or re-read with `refreshPlan`). Both
   * calls are paced with every other keyed call. Throws HibpError; a failed
   * plan lookup other than a 429 only leaves the plan unknown.
   */
  async listVerifiedDomains(options: { refreshPlan: boolean }): Promise<VerifiedDomainListing> {
    const apiKey = await this.getApiKey();
    if (!apiKey) throw new HibpError('auth', 'No usable HIBP API key is configured');
    const client = this.createClient(apiKey);
    const status = await this.learnPlan(client, options.refreshPlan);
    await this.pace();
    const list = await client.subscribedDomains();
    return { list, plan: planFromStatus(status) };
  }

  /**
   * Space keyed calls so a cycle stays under the plan's requests per minute.
   * Callers queue on one promise chain, so the gap holds between concurrent
   * callers too. A call whose turn comes during a rate-limit pause (a 429 to
   * another caller while it waited) is not sent: it fails as rate-limited.
   */
  private pace(): Promise<void> {
    const turn = this.paceChain.then(async () => {
      const wait = this.lastCallAt + spacingForRpm(this.plan?.status?.Rpm) - this.now();
      if (wait > 0) await this.sleep(wait);
      const until = this.pausedUntil();
      const now = this.now();
      if (until > now) {
        throw new HibpError(
          'rate_limited',
          `HIBP rate limit reached; checks resume after ${new Date(until).toISOString()}`,
          { retryAfterSeconds: Math.ceil((until - now) / 1000) }
        );
      }
      this.lastCallAt = now;
    });
    this.paceChain = turn.catch(() => undefined);
    return turn;
  }

  /**
   * Read the plan from subscription/status (cached for 6 hours; concurrent
   * lookups share one call). Best effort: only a 429 stops the caller. Any
   * other failure just means pacing for the smallest plan until the next
   * refresh — the breach search that follows is the authoritative key check
   * (HIBP's documented test key, for one, is refused here but accepted by the
   * breach endpoints).
   */
  private async learnPlan(client: HibpClientLike, force: boolean): Promise<HibpSubscriptionStatus | null> {
    if (!force && this.plan && this.now() - this.plan.at < PLAN_TTL_MS) return this.plan.status;
    if (this.planLookup) return this.planLookup;
    const generation = this.planGeneration;
    const lookup = (async () => {
      let status: HibpSubscriptionStatus | null = null;
      try {
        await this.pace();
        status = await client.subscriptionStatus();
      } catch (err) {
        if (err instanceof HibpError && err.kind === 'rate_limited') throw err;
      }
      if (generation === this.planGeneration) this.plan = { status, at: this.now() };
      return status;
    })();
    this.planLookup = lookup;
    try {
      return await lookup;
    } finally {
      if (this.planLookup === lookup) this.planLookup = null;
    }
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
  /**
   * Email domains skipped because they aren't verified on the HIBP account (or
   * HIBP refused them with a 403 while that was unknown). Not failures.
   */
  unverified: number;
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
  /** An email domain skipped as not verified on HIBP: last_status 'unverified'. */
  markUnverified(id: number, note: string): Promise<void>;
  recordFinding(input: FindingInput): Promise<RecordFindingResult>;
  notify(notices: ExposureNotice[]): Promise<void>;
  /** The verified-domain snapshot as the stored key sees it (hibpDomains.ts). */
  loadDomainSnapshot(): Promise<HibpDomainSnapshotState>;
  /** Write `build(previous)` unless the stored key changed from `keyRef`; null when dropped. */
  saveDomainSnapshot(
    keyRef: string,
    build: (previous: HibpDomainSnapshot | null) => HibpDomainSnapshot
  ): Promise<HibpDomainSnapshot | null>;
  markDomainSnapshotStale(): Promise<void>;
  /** Make unverified email domains among `values` due again; returns the rows reset. */
  requeueVerified(values: readonly string[]): Promise<Array<{ id: number; enabled: boolean }>>;
  listEmailDomains(): Promise<Array<{ id: number; value: string; enabled: boolean }>>;
}

const dbStore: LeakedCredentialStore = {
  isEnabled: async () => (await getExposureSetting('exposure_leaked_creds_enabled')) === 'true',
  findDue: (limit, force) => MonitoredIdentityModel.findDue(limit, force),
  countDue: (force) => MonitoredIdentityModel.countDue(force),
  markChecked: (id) => MonitoredIdentityModel.markChecked(id),
  markFailed: (id, error, advance) => MonitoredIdentityModel.markFailed(id, error, advance),
  markUnverified: (id, note) => MonitoredIdentityModel.markUnverified(id, note),
  // Notifications are sent once per identity (grouped), not once per finding.
  recordFinding: (input) => recordFinding(input, { notify: false }),
  notify: (notices) => NotificationService.notifyExposure(notices),
  loadDomainSnapshot: () => readHibpDomainSnapshot(),
  saveDomainSnapshot: (keyRef, build) => updateHibpDomainSnapshot(keyRef, build),
  markDomainSnapshotStale: () => markHibpDomainSnapshotStale(),
  requeueVerified: (values) => MonitoredIdentityModel.requeueVerified(values),
  listEmailDomains: () => MonitoredIdentityModel.listEmailDomains(),
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

// A 429 to any caller (a run or an admin's re-check) holds every keyed call,
// including one already waiting its turn in the pacer.
const hibpSource = new HibpSource({ pausedUntil: () => rateLimitPauseEnd() });

// In-process state, like the job registry: it describes this process's runs.
let inFlight: Promise<LeakedCredentialRunSummary> | null = null;
let pausedUntil = 0;
let pauseReason: string | null = null;
let pauseKind: 'rate_limited' | 'auth' | null = null;
let lastRun: { at: string; trigger: string; summary: LeakedCredentialRunSummary } | null = null;

function pause(untilMs: number, reason: string, kind: 'rate_limited' | 'auth'): void {
  pausedUntil = untilMs;
  pauseReason = reason;
  pauseKind = kind;
  logger.warn(`[LeakedCreds] ${reason}`);
}

function liftPause(): void {
  pausedUntil = 0;
  pauseReason = null;
  pauseKind = null;
}

/** End of an active rate-limit pause (ms since the epoch), or 0. */
function rateLimitPauseEnd(): number {
  return pauseKind === 'rate_limited' && pausedUntil > Date.now() ? pausedUntil : 0;
}

/**
 * Lift a rate-limit/auth pause and forget the cached plan — call when a
 * different HIBP key is saved (or the key is cleared): HIBP's rate limit and
 * plan belong to the key.
 */
export function resetLeakedCredentialPause(): void {
  liftPause();
  hibpSource.reset();
}

/**
 * Lift only a rejected-key pause (the admin re-saved the same key or toggled
 * the provider, e.g. after renewing the subscription). A rate-limit pause
 * stays until HIBP's retry-after has passed: the same key gets the same limit.
 */
export function liftLeakedCredentialAuthPause(): void {
  if (pauseKind !== 'auth') return;
  liftPause();
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
  unverified: 0,
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
  if (s.unverified) parts.push(`${s.unverified} skipped (not verified on HIBP)`);
  if (s.remaining) parts.push(`${s.remaining} still due`);
  return parts.join(', ') + (s.error ? ` (stopped: ${s.error})` : '');
}

// ---- Verified HIBP domains (shared by runs and the admin's re-check) ------------------

interface DomainRefreshOutcome {
  /** The snapshot written; null when nothing was written (the key changed meanwhile). */
  snapshot: HibpDomainSnapshot | null;
  /** The listing's failure, or null after a success. */
  error: HibpDomainListError | null;
  /** Identities that turned verified and were made due again. */
  requeued: Array<{ id: number; enabled: boolean }>;
}

// One refresh per key at a time: a run and an admin's re-check share it.
const refreshesInFlight = new Map<string, Promise<DomainRefreshOutcome>>();

function refreshDomainSnapshotShared(
  source: ExposureSource,
  store: LeakedCredentialStore,
  keyRef: string,
  options: { refreshPlan: boolean }
): Promise<DomainRefreshOutcome> {
  const existing = refreshesInFlight.get(keyRef);
  if (existing) return existing;
  const run = refreshDomainSnapshot(source, store, keyRef, options).finally(() => {
    if (refreshesInFlight.get(keyRef) === run) refreshesInFlight.delete(keyRef);
  });
  refreshesInFlight.set(keyRef, run);
  return run;
}

/**
 * Ask the source for the verified list and persist the outcome, success or
 * failure. A success re-queues identities that were skipped as unverified and
 * are now listed, and lifts an auth pause (the key just worked); a 429 pauses
 * every check, after the failure is recorded.
 */
async function refreshDomainSnapshot(
  source: ExposureSource,
  store: LeakedCredentialStore,
  keyRef: string,
  options: { refreshPlan: boolean }
): Promise<DomainRefreshOutcome> {
  if (!source.listVerifiedDomains) return { snapshot: null, error: null, requeued: [] };
  let listing: VerifiedDomainListing;
  try {
    listing = await source.listVerifiedDomains({ refreshPlan: options.refreshPlan });
  } catch (err) {
    const error = toDomainListError(err, Date.now());
    // The kind and status only: never the body, never the key.
    logger.warn(
      `[LeakedCreds] could not list verified HIBP domains: ${error.kind}${error.status !== null ? ` (HTTP ${error.status})` : ''}`
    );
    const snapshot = await store.saveDomainSnapshot(keyRef, (previous) =>
      failedSnapshot(previous, error, keyRef, new Date())
    );
    if (error.kind === 'rate_limited' && error.retry_after) {
      pause(
        Date.parse(error.retry_after),
        `${source.label} rate limit reached; checks resume after ${error.retry_after}`,
        'rate_limited'
      );
    }
    return { snapshot, error, requeued: [] };
  }

  const identities = await store.listEmailDomains();
  const snapshot = await store.saveDomainSnapshot(keyRef, (previous) =>
    buildSnapshot(
      listing.list,
      listing.plan ?? previous?.plan ?? null,
      identities.map((i) => i.value),
      keyRef,
      new Date()
    )
  );
  if (!snapshot) return { snapshot: null, error: null, requeued: [] };
  if (pauseKind === 'auth') liftPause();
  const verified = identities
    .filter((i) => isListedState(hibpDomainStatus(i.value, snapshot, true).state))
    .map((i) => i.value);
  const requeued = await store.requeueVerified(verified);
  return { snapshot, error: null, requeued };
}

export type HibpDomainsRefreshErrorKind = 'no_key' | 'rate_limited';

/** Why an admin's re-check didn't ask HIBP at all. */
export class HibpDomainsRefreshError extends Error {
  readonly kind: HibpDomainsRefreshErrorKind;
  /** rate_limited: when a re-check may call HIBP again (ISO). */
  readonly retryAt: string | null;

  constructor(kind: HibpDomainsRefreshErrorKind, message: string, retryAt: string | null = null) {
    super(message);
    this.name = 'HibpDomainsRefreshError';
    this.kind = kind;
    this.retryAt = retryAt;
  }
}

export interface HibpDomainsRefreshResult {
  view: HibpVerifiedDomainsView;
  /** False when HIBP was asked less than a minute ago and that answer is shown. */
  refreshed: boolean;
  /** Enabled identities that turned verified and are due again. */
  becameDue: number[];
}

/** The account view of the verified domains (never calls HIBP). */
export async function getHibpVerifiedDomainsView(
  options: { store?: LeakedCredentialStore } = {}
): Promise<HibpVerifiedDomainsView> {
  const store = options.store ?? dbStore;
  const [state, identities] = await Promise.all([store.loadDomainSnapshot(), store.listEmailDomains()]);
  return toHibpVerifiedDomainsView({
    snapshot: state.snapshot,
    keyUsable: state.keyUsable,
    identities,
    now: Date.now(),
    pausedUntil: rateLimitPauseEnd(),
    attribution: HIBP_PROVIDER.attribution,
  });
}

/**
 * An admin's "Re-check with HIBP": list the verified domains and the plan now,
 * unless HIBP was asked less than a minute ago (install-wide cooldown; the
 * cached answer comes back with refreshed=false). Concurrent re-checks share
 * one call. Refused without a usable key, and during a rate-limit pause. The
 * provider's enabled flag is not required (like the key test).
 */
export async function refreshHibpVerifiedDomains(
  options: { source?: ExposureSource; store?: LeakedCredentialStore } = {}
): Promise<HibpDomainsRefreshResult> {
  const source = options.source ?? hibpSource;
  const store = options.store ?? dbStore;
  const state = await store.loadDomainSnapshot();
  if (!state.keyRef || !state.keyUsable || !source.listVerifiedDomains) {
    throw new HibpDomainsRefreshError('no_key', 'No usable HIBP API key is saved; save one first');
  }
  const now = Date.now();
  const snapshotRetry =
    state.snapshot?.error?.kind === 'rate_limited' ? Date.parse(state.snapshot.error.retry_after ?? '') || 0 : 0;
  const pauseEnd = Math.max(rateLimitPauseEnd(), snapshotRetry);
  if (pauseEnd > now) {
    const at = new Date(pauseEnd).toISOString();
    throw new HibpDomainsRefreshError('rate_limited', `HIBP rate limit reached; try again after ${at}`, at);
  }

  let outcome: DomainRefreshOutcome | null = null;
  const pending = refreshesInFlight.get(state.keyRef);
  if (pending) outcome = await pending;
  else if (needsDomainRefresh(state.snapshot, now, { mode: 'manual' })) {
    outcome = await refreshDomainSnapshotShared(source, store, state.keyRef, { refreshPlan: true });
  }
  return {
    view: await getHibpVerifiedDomainsView({ store }),
    refreshed: outcome !== null,
    becameDue: outcome ? outcome.requeued.filter((r) => r.enabled).map((r) => r.id) : [],
  };
}

// ---- Runs ---------------------------------------------------------------------------

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

  const limit = options.maxIdentities ?? DEFAULT_MAX_IDENTITIES;
  let identities = await store.findDue(limit, force);
  const budgetMs = options.budgetMs ?? SCHEDULED_RUN_BUDGET_MS;
  const startedAt = Date.now();
  const summary: LeakedCredentialRunSummary = {
    checked: 0,
    newFindings: 0,
    failed: 0,
    unverified: 0,
    remaining: 0,
    skipped: false,
  };
  const finish = async (): Promise<LeakedCredentialRunSummary> => {
    summary.remaining = await store.countDue(false);
    lastRun = { at: new Date().toISOString(), trigger: options.trigger ?? 'schedule', summary };
    return summary;
  };

  // Which email domains HIBP will search: known before the first domain search.
  const listsDomains = typeof source.listVerifiedDomains === 'function';
  let snapshot: HibpDomainSnapshot | null = null;
  if (listsDomains && identities.some((i) => i.kind === 'email_domain')) {
    const state = await store.loadDomainSnapshot();
    snapshot = state.snapshot;
    const skipPending = identities.some(
      (i) => i.kind === 'email_domain' && isSkippedState(hibpDomainStatus(i.value, snapshot, true).state)
    );
    if (
      state.keyRef &&
      needsDomainRefresh(snapshot, Date.now(), { mode: force ? 'force' : 'run', skipPending })
    ) {
      const refreshed = await refreshDomainSnapshotShared(source, store, state.keyRef, {
        refreshPlan: false,
      });
      if (refreshed.error?.kind === 'rate_limited') {
        // The pause is set; nothing else is sent to HIBP this cycle.
        summary.rateLimitedUntil = refreshed.error.retry_after ?? undefined;
        summary.error = refreshed.error.message;
        return finish();
      }
      snapshot = refreshed.snapshot;
      // Newly verified domains were made due: search them in this run.
      if (refreshed.requeued.length > 0) identities = await store.findDue(limit, force);
    }
  }

  let consecutiveTransient = 0;

  for (const identity of identities) {
    if (Date.now() - startedAt >= budgetMs) break; // the rest stay due
    if (pausedUntil > Date.now()) {
      // A 429 to a concurrent call (an admin's re-check) pauses every check,
      // this run's included; the rest stay due.
      summary.error = pauseReason ?? `paused until ${new Date(pausedUntil).toISOString()}`;
      if (pauseKind === 'rate_limited') summary.rateLimitedUntil = new Date(pausedUntil).toISOString();
      break;
    }

    let domainStatus: IdentityHibpDomain | null = null;
    if (identity.kind === 'email_domain' && listsDomains) {
      domainStatus = hibpDomainStatus(identity.value, snapshot, true);
      if (isSkippedState(domainStatus.state)) {
        // An admin's re-check may have listed it since this run read the
        // snapshot (and re-queued it): decide on the snapshot as it is now.
        snapshot = (await store.loadDomainSnapshot()).snapshot;
        domainStatus = hibpDomainStatus(identity.value, snapshot, true);
      }
      if (isSkippedState(domainStatus.state)) {
        // HIBP would refuse it (403): no call, no error, until it is verified.
        await store.markUnverified(identity.id, skipNote(identity.value, domainStatus));
        // A re-check writes its list, then re-queues. If that landed between the
        // read above and this write, the write undid the re-queue: read once
        // more and, if the domain is listed now, re-queue it here instead.
        const after = (await store.loadDomainSnapshot()).snapshot;
        if (isListedState(hibpDomainStatus(identity.value, after, true).state)) {
          await store.requeueVerified([identity.value]);
        } else {
          summary.unverified++;
        }
        continue;
      }
    }

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
          `${source.label} rate limit reached; checks resume after ${summary.rateLimitedUntil}`,
          'rate_limited'
        );
        break;
      }
      if (e.kind === 'auth') {
        summary.error = e.message;
        pause(
          Date.now() + AUTH_PAUSE_MS,
          `${e.message}; checks are paused for an hour or until the key is updated`,
          'auth'
        );
        break;
      }
      if (e.kind === 'unverified') {
        // The list may be out of date: the next run re-reads it (at most hourly).
        if (listsDomains) await store.markDomainSnapshotStale();
        consecutiveTransient = 0;
        if (domainStatus && isListedState(domainStatus.state)) {
          // Listed as verified, yet refused: an anomaly to look at, recorded as an
          // error so the re-queue (which only takes 'unverified' rows) can't loop.
          summary.failed++;
          logger.warn(`[LeakedCreds] HIBP refused listed domain identity #${identity.id} (HTTP 403)`);
          await store.markFailed(identity.id, CONTRADICTION_NOTE, true);
        } else {
          summary.unverified++;
          await store.markUnverified(identity.id, e.message);
        }
        continue;
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

  return finish();
}
