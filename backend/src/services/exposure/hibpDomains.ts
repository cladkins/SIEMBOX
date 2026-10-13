/**
 * Which email domains HIBP will search for this install's key: the verified
 * domains on the key's HIBP account (GET subscribeddomains), kept as one JSON
 * snapshot in system_settings under `exposure_hibp_domains`.
 *
 * HIBP only searches a domain after its owner has proved control of it in the
 * HIBP dashboard; anything else gets HTTP 403. Knowing the verified list lets
 * the leaked-credential job skip unverified domains (no wasted call, no error
 * row) and lets the UI say which domains still need verifying.
 *
 * The snapshot is bound to the stored key by `key_ref`, the first 16 hex
 * characters of SHA-256 over the stored ENCRYPTED envelope (ciphertext, IV and
 * tag). The IV is random, so it changes on every key save, and without
 * CREDENTIAL_ENCRYPTION_KEY it says nothing about the key. Nothing derived from
 * the plaintext key is stored, returned or logged. A snapshot whose key_ref
 * doesn't match the current envelope reads as absent ("not checked").
 *
 * Only a 200 with a JSON array is an answer. A 404, a body that isn't an
 * array, or entries that can't be read make the list "unknown" — never "not
 * verified" — so the job falls back to searching the domain, as before.
 *
 * Every write goes through one in-process queue (there is one backend
 * process), so marking the snapshot stale can't race a refresh writing it.
 *
 * Pure helpers first (unit-tested without a database), persistence last.
 */
import crypto from 'crypto';
import { domainToASCII } from 'url';
import { normalizeDomain } from './validation';
import { HibpError, type HibpSubscribedDomainList, type HibpSubscriptionStatus } from './hibpClient';
import { getExposureSetting, isStoredHibpKeyUsable, setExposureSetting } from './settings';

// ---- Constants ------------------------------------------------------------------

/** A successful listing is reused for this long by the scheduled job. */
export const HIBP_DOMAINS_TTL_MS = 6 * 60 * 60 * 1000;
/** ... or this long when it is marked stale, or a due domain would be skipped. */
export const HIBP_DOMAINS_SKIP_TTL_MS = 60 * 60 * 1000;
/** A failed listing is retried after this long (any failure but a 401 or 429). */
export const HIBP_DOMAINS_FAILURE_RETRY_MS = 30 * 60 * 1000;
/** A listing HIBP answered with 401 is retried after this long. */
export const HIBP_DOMAINS_AUTH_RETRY_MS = 6 * 60 * 60 * 1000;
/** Manual re-checks and forced runs ask HIBP at most this often (install-wide). */
export const HIBP_DOMAINS_REFRESH_COOLDOWN_MS = 60 * 1000;
/** The most verified domains kept in the snapshot (monitored ones first). */
export const HIBP_DOMAINS_MAX_STORED = 2_000;
/** The most subscribeddomains entries read from one answer (hibpClient's cap). */
export const HIBP_DOMAINS_MAX_PARSED = 5_000;
/** Where an account owner adds and verifies domains (a link for people; never fetched). */
export const HIBP_DOMAINS_DASHBOARD_URL = 'https://haveibeenpwned.com/Dashboard/Redirect/Domains';

const SNAPSHOT_VERSION = 1;
const MAX_MESSAGE_LENGTH = 300;

// ---- Types ----------------------------------------------------------------------

export type HibpDomainListErrorKind =
  | 'auth'
  | 'forbidden'
  | 'rate_limited'
  | 'network'
  | 'hibp_unavailable'
  | 'bad_response';

const ERROR_KINDS: readonly HibpDomainListErrorKind[] = [
  'auth',
  'forbidden',
  'rate_limited',
  'network',
  'hibp_unavailable',
  'bad_response',
];

/** Why the latest listing failed. `message` never holds a response body or the key. */
export interface HibpDomainListError {
  kind: HibpDomainListErrorKind;
  status: number | null;
  message: string;
  /** rate_limited only: no listing before this time (ISO). */
  retry_after: string | null;
}

/** The key's plan, from subscription/status. */
export interface HibpPlanSnapshot {
  name: string | null;
  domain_search_max_breached_accounts: number | null;
  /** null = no maximum (or unknown). */
  max_breached_domains: number | null;
  subscribed_until: string | null;
}

/** One verified domain, normalized (lowercase punycode, no trailing dot). */
export interface HibpVerifiedDomainEntry {
  domain: string;
  pwn_count: number | null;
  pwn_count_excluding_spam_lists: number | null;
  pwn_count_excluding_spam_lists_at_last_subscription_renewal: number | null;
  next_subscription_renewal: string | null;
}

export interface HibpDomainSnapshot {
  v: 1;
  key_ref: string;
  /** The latest attempt, success or failure (ISO). */
  checked_at: string;
  /** The latest success (ISO); null if never. */
  listed_at: string | null;
  /** HIBP refused a domain search (403) after this list was written. */
  stale: boolean;
  /** The latest attempt's failure; null after a success. */
  error: HibpDomainListError | null;
  plan: HibpPlanSnapshot | null;
  /** null until the first success; kept when a later attempt fails. */
  domains: HibpVerifiedDomainEntry[] | null;
  /** HIBP listed more than HIBP_DOMAINS_MAX_STORED (or HIBP_DOMAINS_MAX_PARSED) domains. */
  truncated: boolean;
  /** HIBP entries whose DomainName didn't normalize, or weren't readable at all. */
  skipped_entries: number;
}

export type HibpDomainState = 'verified' | 'verified_limited' | 'not_verified' | 'unavailable' | 'unknown';
export type HibpDomainUnknownReason =
  | 'no_key'
  | 'not_checked'
  | 'auth'
  | 'rate_limited'
  | 'network'
  | 'hibp_unavailable'
  | 'bad_response'
  | 'list_incomplete';

/** An email-domain identity's standing with HIBP (GET /api/exposure/identities → hibp_domain). */
export interface IdentityHibpDomain {
  state: HibpDomainState;
  /** Set only for 'unknown'. */
  reason: HibpDomainUnknownReason | null;
  /** not_verified only: a listed parent domain (HIBP verifies each name separately). */
  verified_parent: string | null;
  /** When the list used was fetched. */
  listed_at: string | null;
  message: string;
}

// ---- Key binding ------------------------------------------------------------------

/**
 * The snapshot's binding to the stored key: 16 hex characters of SHA-256 over
 * the stored encrypted envelope (never the plaintext key); null when no key is
 * stored.
 */
export function hibpKeyRef(storedEnvelope: string): string | null {
  if (!storedEnvelope) return null;
  return crypto.createHash('sha256').update(storedEnvelope).digest('hex').slice(0, 16);
}

// ---- Names --------------------------------------------------------------------------

/**
 * A DomainName from HIBP in the form identities are stored in (lowercase
 * punycode, no trailing root dot), or null when it isn't a valid domain.
 * Non-ASCII names go through UTS #46 (url.domainToASCII) first; then the same
 * validation as an identity value, which strips one root dot and rejects
 * wildcards, IPs, underscores and names without a TLD.
 */
export function normalizeHibpDomainName(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  let value = raw.trim();
  if (!value) return null;
  // eslint-disable-next-line no-control-regex -- matching every non-ASCII character
  if (/[^\x00-\x7f]/.test(value)) {
    value = domainToASCII(value);
    if (!value) return null;
  }
  const checked = normalizeDomain(value);
  return checked.ok ? checked.value : null;
}

// ---- Parsing a stored snapshot ------------------------------------------------------

const isObject = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === 'object' && !Array.isArray(v);

const countOrNull = (v: unknown): number | null =>
  typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : null;

const textOrNull = (v: unknown, max = 64): string | null =>
  typeof v === 'string' && v.length > 0 && v.length <= max ? v : null;

const isoOrNull = (v: unknown): string | null => {
  const text = textOrNull(v);
  return text !== null && !Number.isNaN(Date.parse(text)) ? text : null;
};

function parsePlan(v: unknown): HibpPlanSnapshot | null {
  if (!isObject(v)) return null;
  return {
    name: textOrNull(v.name, 200),
    domain_search_max_breached_accounts: countOrNull(v.domain_search_max_breached_accounts),
    max_breached_domains: countOrNull(v.max_breached_domains),
    subscribed_until: textOrNull(v.subscribed_until),
  };
}

function parseError(v: unknown): HibpDomainListError | null {
  if (!isObject(v)) return null;
  const kind = ERROR_KINDS.includes(v.kind as HibpDomainListErrorKind)
    ? (v.kind as HibpDomainListErrorKind)
    : 'bad_response';
  return {
    kind,
    status: typeof v.status === 'number' && Number.isInteger(v.status) ? v.status : null,
    message: textOrNull(v.message, MAX_MESSAGE_LENGTH) ?? 'The verified-domain list could not be read',
    retry_after: kind === 'rate_limited' ? isoOrNull(v.retry_after) : null,
  };
}

function parseEntry(v: unknown): HibpVerifiedDomainEntry | null {
  if (!isObject(v)) return null;
  const domain = normalizeHibpDomainName(v.domain);
  if (!domain) return null;
  return {
    domain,
    pwn_count: countOrNull(v.pwn_count),
    pwn_count_excluding_spam_lists: countOrNull(v.pwn_count_excluding_spam_lists),
    pwn_count_excluding_spam_lists_at_last_subscription_renewal: countOrNull(
      v.pwn_count_excluding_spam_lists_at_last_subscription_renewal
    ),
    next_subscription_renewal: textOrNull(v.next_subscription_renewal),
  };
}

/**
 * The stored snapshot for the current key, or null ("not checked") for '',
 * invalid JSON, another version, or a snapshot written for another key.
 * Tolerates hand-edited rows: unreadable fields fall back, nothing throws.
 */
export function parseHibpDomainSnapshot(
  raw: string | null | undefined,
  currentKeyRef: string | null
): HibpDomainSnapshot | null {
  if (!raw || !currentKeyRef) return null;
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!isObject(value) || value.v !== SNAPSHOT_VERSION || value.key_ref !== currentKeyRef) return null;
  let domains: HibpVerifiedDomainEntry[] | null = null;
  let unreadable = 0;
  if (Array.isArray(value.domains)) {
    domains = [];
    const seen = new Set<string>();
    for (const item of value.domains.slice(0, HIBP_DOMAINS_MAX_STORED)) {
      const entry = parseEntry(item);
      if (!entry) unreadable++;
      else if (!seen.has(entry.domain)) {
        seen.add(entry.domain);
        domains.push(entry);
      }
    }
  }
  const storedSkipped = countOrNull(value.skipped_entries);
  return {
    v: SNAPSHOT_VERSION,
    key_ref: currentKeyRef,
    checked_at: isoOrNull(value.checked_at) ?? new Date(0).toISOString(),
    listed_at: domains === null ? null : isoOrNull(value.listed_at),
    stale: value.stale === true,
    error: parseError(value.error),
    plan: parsePlan(value.plan),
    domains,
    truncated:
      value.truncated === true ||
      (Array.isArray(value.domains) && value.domains.length > HIBP_DOMAINS_MAX_STORED),
    skipped_entries: (storedSkipped === null ? 0 : Math.floor(storedSkipped)) + unreadable,
  };
}

export function serializeHibpDomainSnapshot(snapshot: HibpDomainSnapshot): string {
  return JSON.stringify(snapshot);
}

// ---- Building a snapshot ------------------------------------------------------------

/** The plan fields the snapshot keeps, from a subscription/status answer. */
export function planFromStatus(status: HibpSubscriptionStatus | null | undefined): HibpPlanSnapshot | null {
  if (!status) return null;
  return {
    name: textOrNull(status.SubscriptionName, 200),
    domain_search_max_breached_accounts: countOrNull(status.DomainSearchMaxBreachedAccounts),
    max_breached_domains: countOrNull(status.MaxBreachedDomains),
    subscribed_until: textOrNull(status.SubscribedUntil),
  };
}

/**
 * The snapshot for a successful listing. Names are normalized (unreadable ones
 * counted in skipped_entries) and de-duplicated; at most
 * HIBP_DOMAINS_MAX_STORED are kept, monitored domains first, then the rest
 * alphabetically.
 */
export function buildSnapshot(
  list: HibpSubscribedDomainList,
  plan: HibpPlanSnapshot | null,
  monitoredValues: readonly string[],
  keyRef: string,
  now: Date
): HibpDomainSnapshot {
  const byName = new Map<string, HibpVerifiedDomainEntry>();
  let skipped = list.unreadable;
  for (const d of list.domains) {
    const domain = normalizeHibpDomainName(d.DomainName);
    if (!domain) {
      skipped++;
      continue;
    }
    if (byName.has(domain)) continue;
    byName.set(domain, {
      domain,
      pwn_count: countOrNull(d.PwnCount),
      pwn_count_excluding_spam_lists: countOrNull(d.PwnCountExcludingSpamLists),
      pwn_count_excluding_spam_lists_at_last_subscription_renewal: countOrNull(
        d.PwnCountExcludingSpamListsAtLastSubscriptionRenewal
      ),
      next_subscription_renewal: textOrNull(d.NextSubscriptionRenewal),
    });
  }
  const monitored = new Set(monitoredValues);
  const entries = [...byName.values()].sort((a, b) => {
    const am = monitored.has(a.domain) ? 0 : 1;
    const bm = monitored.has(b.domain) ? 0 : 1;
    return am - bm || (a.domain < b.domain ? -1 : a.domain > b.domain ? 1 : 0);
  });
  const at = now.toISOString();
  return {
    v: SNAPSHOT_VERSION,
    key_ref: keyRef,
    checked_at: at,
    listed_at: at,
    stale: false,
    error: null,
    plan,
    domains: entries.slice(0, HIBP_DOMAINS_MAX_STORED),
    truncated: entries.length > HIBP_DOMAINS_MAX_STORED || list.overLimit > 0,
    skipped_entries: skipped,
  };
}

/** The snapshot after a failed listing: the last good list (if any) stays, with the failure. */
export function failedSnapshot(
  previous: HibpDomainSnapshot | null,
  error: HibpDomainListError,
  keyRef: string,
  now: Date,
  plan: HibpPlanSnapshot | null = null
): HibpDomainSnapshot {
  return {
    v: SNAPSHOT_VERSION,
    key_ref: keyRef,
    checked_at: now.toISOString(),
    listed_at: previous?.listed_at ?? null,
    stale: previous?.stale ?? false,
    error,
    plan: plan ?? previous?.plan ?? null,
    domains: previous?.domains ?? null,
    truncated: previous?.truncated ?? false,
    skipped_entries: previous?.skipped_entries ?? 0,
  };
}

/** Only a complete list (nothing truncated or unreadable) can say a domain isn't verified. */
export function isCompleteList(snapshot: HibpDomainSnapshot): boolean {
  return snapshot.truncated === false && snapshot.skipped_entries === 0;
}

// ---- Classification -----------------------------------------------------------------

/**
 * Whether HIBP searches this domain fully for the plan: the domain's breached
 * addresses (the count locked in at the last renewal, else the current one)
 * against the plan's largest searchable domain. null = unknown.
 */
export function planCoverage(
  entry: Pick<
    HibpVerifiedDomainEntry,
    'pwn_count_excluding_spam_lists' | 'pwn_count_excluding_spam_lists_at_last_subscription_renewal'
  >,
  plan: HibpPlanSnapshot | null
): boolean | null {
  const count =
    entry.pwn_count_excluding_spam_lists_at_last_subscription_renewal ?? entry.pwn_count_excluding_spam_lists;
  const max = plan?.domain_search_max_breached_accounts ?? null;
  if (count === null || max === null || max <= 0) return null;
  return count <= max;
}

export const HIBP_DOMAIN_MESSAGES = {
  verified: 'Verified on your HIBP account.',
  verified_limited:
    'Verified on your HIBP account, but it may be larger than your HIBP plan covers; HIBP then returns only subscription-free breaches for it.',
  not_verified: `Not verified on your HIBP account, so HIBP won't search it and SIEMBox skips it. Verify it in the HIBP dashboard (${HIBP_DOMAINS_DASHBOARD_URL}), then re-check verification.`,
  unavailable:
    "Your HIBP plan doesn't include domain search (HIBP refused to list verified domains, HTTP 403), so email domains are skipped. Email addresses are still checked.",
  no_key: "No usable HIBP API key is saved, so verification can't be checked.",
  not_checked:
    "Not checked with HIBP yet; SIEMBox checks which domains are verified before this domain's next search.",
  auth: "Couldn't check verification: HIBP rejected the API key (HTTP 401). The domain is searched anyway.",
  rate_limited: "Couldn't check verification: HIBP's rate limit was reached.",
  network:
    "Couldn't check verification: haveibeenpwned.com couldn't be reached (is outbound HTTPS blocked?). The domain is searched anyway.",
  hibp_unavailable: "Couldn't check verification: HIBP is temporarily unavailable. The domain is searched anyway.",
  bad_response:
    "Couldn't check verification: HIBP's answer wasn't in the expected format. The domain is searched anyway.",
  list_incomplete:
    "SIEMBox couldn't read HIBP's whole verified-domain list (more than 2,000 domains, or unreadable entries), so this domain is searched directly.",
} as const;

function unknown(reason: HibpDomainUnknownReason, listedAt: string | null): IdentityHibpDomain {
  return { state: 'unknown', reason, verified_parent: null, listed_at: listedAt, message: HIBP_DOMAIN_MESSAGES[reason] };
}

/** The closest listed parent of `value` (mail.example.com → example.com), if any. */
function listedParent(value: string, listed: ReadonlySet<string>): string | null {
  const labels = value.split('.');
  for (let i = 1; i < labels.length - 1; i++) {
    const parent = labels.slice(i).join('.');
    if (listed.has(parent)) return parent;
  }
  return null;
}

/**
 * An email domain's standing with HIBP under `snapshot` (pure). Exact match
 * only: each subdomain is a separate HIBP domain in both directions.
 */
export function hibpDomainStatus(
  value: string,
  snapshot: HibpDomainSnapshot | null,
  keyUsable: boolean
): IdentityHibpDomain {
  if (!keyUsable) return unknown('no_key', null);
  if (!snapshot) return unknown('not_checked', null);
  if (snapshot.error?.kind === 'forbidden') {
    return {
      state: 'unavailable',
      reason: null,
      verified_parent: null,
      listed_at: snapshot.listed_at,
      message: HIBP_DOMAIN_MESSAGES.unavailable,
    };
  }
  if (snapshot.domains === null) {
    return unknown(snapshot.error ? snapshot.error.kind : 'not_checked', null);
  }
  const entry = snapshot.domains.find((d) => d.domain === value);
  if (entry) {
    const limited = planCoverage(entry, snapshot.plan) === false;
    return {
      state: limited ? 'verified_limited' : 'verified',
      reason: null,
      verified_parent: null,
      listed_at: snapshot.listed_at,
      message: limited ? HIBP_DOMAIN_MESSAGES.verified_limited : HIBP_DOMAIN_MESSAGES.verified,
    };
  }
  if (!isCompleteList(snapshot)) return unknown('list_incomplete', snapshot.listed_at);
  const parent = listedParent(value, new Set(snapshot.domains.map((d) => d.domain)));
  return {
    state: 'not_verified',
    reason: null,
    verified_parent: parent,
    listed_at: snapshot.listed_at,
    message: parent
      ? `HIBP verifies each domain separately: ${parent} is verified, ${value} isn't. ${HIBP_DOMAIN_MESSAGES.not_verified}`
      : HIBP_DOMAIN_MESSAGES.not_verified,
  };
}

/** True for the states the job skips (no breacheddomain call). */
export function isSkippedState(state: HibpDomainState): boolean {
  return state === 'not_verified' || state === 'unavailable';
}

/** True for the states of a domain the list shows as verified (re-queued when it was skipped). */
export function isListedState(state: HibpDomainState): boolean {
  return state === 'verified' || state === 'verified_limited';
}

const ms = (iso: string | null | undefined): number => {
  const t = iso ? Date.parse(iso) : NaN;
  return Number.isNaN(t) ? 0 : t;
};

export interface DomainRefreshPolicy {
  /** run: a scheduled run or run-now; force: run-now with force; manual: the admin's Re-check. */
  mode: 'run' | 'force' | 'manual';
  /** A due domain would be skipped (not_verified / unavailable) under the current snapshot. */
  skipPending?: boolean;
}

/** Whether HIBP should be asked for the verified list now (the §3.2 refresh policy). */
export function needsDomainRefresh(
  snapshot: HibpDomainSnapshot | null,
  now: number,
  policy: DomainRefreshPolicy
): boolean {
  if (!snapshot) return true;
  const error = snapshot.error;
  // A 429 asked us to wait; that holds whatever started the refresh.
  if (error?.kind === 'rate_limited' && now < ms(error.retry_after)) return false;
  const sinceChecked = now - ms(snapshot.checked_at);
  if (policy.mode !== 'run') return sinceChecked >= HIBP_DOMAINS_REFRESH_COOLDOWN_MS;
  if (error) {
    if (error.kind === 'rate_limited') return true; // retry_after has passed
    return sinceChecked >= (error.kind === 'auth' ? HIBP_DOMAINS_AUTH_RETRY_MS : HIBP_DOMAINS_FAILURE_RETRY_MS);
  }
  if (snapshot.listed_at === null) return true;
  const sinceListed = now - ms(snapshot.listed_at);
  const ttl = snapshot.stale || policy.skipPending ? HIBP_DOMAINS_SKIP_TTL_MS : HIBP_DOMAINS_TTL_MS;
  return sinceListed >= ttl;
}

/**
 * How a failed subscribeddomains call is recorded. Only a 200 with an array
 * is an answer; 404 (undocumented here), a non-array, invalid JSON, a
 * redirect or another 4xx is 'bad_response', so domains are still searched.
 */
export function domainListErrorKind(err: unknown): HibpDomainListErrorKind {
  if (!(err instanceof HibpError)) {
    const kind = (err as { kind?: unknown } | null)?.kind;
    if (kind === 'rate_limited') return 'rate_limited';
    if (kind === 'auth') return 'auth';
    return 'bad_response';
  }
  if (err.kind === 'rate_limited' || err.status === 429) return 'rate_limited';
  if (err.status === 401) return 'auth';
  if (err.status === 403) return 'forbidden';
  if (err.status !== null && err.status >= 500) return 'hibp_unavailable';
  if (err.status === null) return err.kind === 'auth' ? 'auth' : err.kind === 'transient' ? 'network' : 'bad_response';
  return 'bad_response';
}

/** The stored description of a failed listing (no body, no key: HibpError messages carry neither). */
export function toDomainListError(err: unknown, now: number): HibpDomainListError {
  const kind = domainListErrorKind(err);
  const status = err instanceof HibpError ? err.status : null;
  const retryAfterSeconds =
    err instanceof HibpError
      ? err.retryAfterSeconds
      : typeof (err as { retryAfterSeconds?: unknown } | null)?.retryAfterSeconds === 'number'
        ? (err as { retryAfterSeconds: number }).retryAfterSeconds
        : null;
  const raw = err instanceof Error ? err.message : '';
  return {
    kind,
    status,
    message: (raw || 'The verified-domain list could not be read').slice(0, MAX_MESSAGE_LENGTH),
    retry_after:
      kind === 'rate_limited' ? new Date(now + ((retryAfterSeconds ?? 60) + 1) * 1000).toISOString() : null,
  };
}

/** ISO without milliseconds, as the job notes print times. */
export function isoSeconds(iso: string | null): string {
  const t = iso ? Date.parse(iso) : NaN;
  return Number.isNaN(t) ? 'unknown' : new Date(t).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/** last_error for an email domain the job skipped. */
export function skipNote(value: string, status: IdentityHibpDomain): string {
  if (status.state === 'unavailable') return "Skipped: your HIBP plan doesn't include domain search.";
  return (
    `Skipped: ${value} isn't verified on your HIBP account (as of ${isoSeconds(status.listed_at)}). ` +
    'Verify it in the HIBP dashboard, then re-check verification.'
  );
}

// ---- The admin view (GET /api/exposure/providers/hibp/verified-domains) ------------

export type HibpVerifiedDomainsState = 'no_key' | 'not_checked' | 'listed' | 'error';

export interface HibpVerifiedDomainView extends HibpVerifiedDomainEntry {
  within_plan: boolean | null;
  identity_id: number | null;
}

export interface HibpVerifiedDomainsView {
  state: HibpVerifiedDomainsState;
  checked_at: string | null;
  listed_at: string | null;
  stale: boolean;
  error: HibpDomainListError | null;
  plan: HibpPlanSnapshot | null;
  domains: HibpVerifiedDomainView[] | null;
  truncated: boolean;
  skipped_entries: number;
  /** The earliest time a re-check will call HIBP; null = now. */
  next_refresh_allowed_at: string | null;
  attribution: string;
}

export function toHibpVerifiedDomainsView(input: {
  snapshot: HibpDomainSnapshot | null;
  keyUsable: boolean;
  identities: ReadonlyArray<{ id: number; value: string }>;
  now: number;
  /** End of an active rate-limit pause (ms), or 0. */
  pausedUntil?: number;
  attribution: string;
}): HibpVerifiedDomainsView {
  const { snapshot, keyUsable, now } = input;
  const base: HibpVerifiedDomainsView = {
    state: 'no_key',
    checked_at: null,
    listed_at: null,
    stale: false,
    error: null,
    plan: null,
    domains: null,
    truncated: false,
    skipped_entries: 0,
    next_refresh_allowed_at: null,
    attribution: input.attribution,
  };
  if (!keyUsable) return base;
  const pauseEnd = Math.max(input.pausedUntil ?? 0, snapshot?.error?.kind === 'rate_limited' ? ms(snapshot.error.retry_after) : 0);
  const cooldownEnd = snapshot ? ms(snapshot.checked_at) + HIBP_DOMAINS_REFRESH_COOLDOWN_MS : 0;
  const allowedAt = Math.max(pauseEnd, cooldownEnd);
  base.next_refresh_allowed_at = allowedAt > now ? new Date(allowedAt).toISOString() : null;
  // No list and no recorded failure (only a hand-edited row): nothing was learned yet.
  if (!snapshot || (snapshot.domains === null && !snapshot.error)) return { ...base, state: 'not_checked' };
  const ids = new Map(input.identities.map((i) => [i.value, i.id]));
  return {
    ...base,
    state: snapshot.domains !== null ? 'listed' : 'error',
    checked_at: snapshot.checked_at,
    listed_at: snapshot.listed_at,
    stale: snapshot.stale,
    error: snapshot.error,
    plan: snapshot.plan,
    domains:
      snapshot.domains?.map((d) => ({
        ...d,
        within_plan: planCoverage(d, snapshot.plan),
        identity_id: ids.get(d.domain) ?? null,
      })) ?? null,
    truncated: snapshot.truncated,
    skipped_entries: snapshot.skipped_entries,
  };
}

// ---- Persistence ----------------------------------------------------------------

/** The stored snapshot as the current key sees it. */
export interface HibpDomainSnapshotState {
  /** null when no key is stored. */
  keyRef: string | null;
  /** The stored key decrypts with this backend's CREDENTIAL_ENCRYPTION_KEY. */
  keyUsable: boolean;
  /** null when missing, unreadable, or written for another key. */
  snapshot: HibpDomainSnapshot | null;
}

/** Where the snapshot and the key envelope live (system_settings; swappable for tests). */
export interface HibpDomainSnapshotIO {
  /** The stored exposure_hibp_key value (the encrypted envelope, or ''). */
  readKeyEnvelope(): Promise<string>;
  readSnapshot(): Promise<string>;
  writeSnapshot(value: string): Promise<void>;
  /** Whether the envelope decrypts with this backend's CREDENTIAL_ENCRYPTION_KEY. */
  keyUsable(envelope: string): boolean;
}

export interface HibpDomainSnapshotStore {
  read(): Promise<HibpDomainSnapshotState>;
  /**
   * Write the snapshot `build` makes from the stored one, unless the key
   * changed since `expectedKeyRef` was read (a refresh that raced a key save):
   * then nothing is written and the result is null.
   */
  update(
    expectedKeyRef: string,
    build: (previous: HibpDomainSnapshot | null) => HibpDomainSnapshot
  ): Promise<HibpDomainSnapshot | null>;
  /** HIBP refused a domain search (403): the list may be out of date. */
  markStale(): Promise<void>;
  /** Forget the list (the key was saved or removed). */
  clear(): Promise<void>;
}

/**
 * Snapshot persistence with one write queue: every write (a refresh's result,
 * markStale, clear) runs after the ones queued before it, so a read-modify-write
 * never loses a concurrent one. There is one backend process, so an in-process
 * queue is enough.
 */
export function createHibpDomainSnapshotStore(io: HibpDomainSnapshotIO): HibpDomainSnapshotStore {
  let writes: Promise<unknown> = Promise.resolve();
  const enqueue = <T>(fn: () => Promise<T>): Promise<T> => {
    const run = writes.then(fn, fn);
    writes = run.catch(() => undefined);
    return run;
  };
  const read = async (): Promise<HibpDomainSnapshotState> => {
    const [envelope, raw] = await Promise.all([io.readKeyEnvelope(), io.readSnapshot()]);
    const keyRef = hibpKeyRef(envelope);
    return { keyRef, keyUsable: io.keyUsable(envelope), snapshot: parseHibpDomainSnapshot(raw, keyRef) };
  };
  return {
    read,
    update: (expectedKeyRef, build) =>
      enqueue(async () => {
        const current = await read();
        if (current.keyRef !== expectedKeyRef) return null;
        const next = build(current.snapshot);
        await io.writeSnapshot(serializeHibpDomainSnapshot(next));
        return next;
      }),
    markStale: () =>
      enqueue(async () => {
        const current = await read();
        if (!current.snapshot || current.snapshot.stale) return;
        await io.writeSnapshot(serializeHibpDomainSnapshot({ ...current.snapshot, stale: true }));
      }),
    clear: () => enqueue(() => io.writeSnapshot('')),
  };
}

const settingsStore = createHibpDomainSnapshotStore({
  readKeyEnvelope: () => getExposureSetting('exposure_hibp_key'),
  readSnapshot: () => getExposureSetting('exposure_hibp_domains'),
  writeSnapshot: (value) => setExposureSetting('exposure_hibp_domains', value),
  keyUsable: (envelope) => isStoredHibpKeyUsable(envelope),
});

export const readHibpDomainSnapshot = (): Promise<HibpDomainSnapshotState> => settingsStore.read();
export const updateHibpDomainSnapshot: HibpDomainSnapshotStore['update'] = (expectedKeyRef, build) =>
  settingsStore.update(expectedKeyRef, build);
export const markHibpDomainSnapshotStale = (): Promise<void> => settingsStore.markStale();
export const clearHibpDomainSnapshot = (): Promise<void> => settingsStore.clear();

/**
 * `rows` with each email domain's standing with HIBP (`hibp_domain`; null for
 * an email address). Reads the snapshot and the key once, never calls HIBP.
 */
export async function withHibpDomainStatus<T extends { kind: string; value: string }>(
  rows: readonly T[]
): Promise<Array<T & { hibp_domain: IdentityHibpDomain | null }>> {
  const state = rows.some((r) => r.kind === 'email_domain') ? await readHibpDomainSnapshot() : null;
  return rows.map((row) => ({
    ...row,
    hibp_domain:
      state && row.kind === 'email_domain'
        ? hibpDomainStatus(row.value, state.snapshot, state.keyUsable)
        : null,
  }));
}
