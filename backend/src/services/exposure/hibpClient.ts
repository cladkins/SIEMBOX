/**
 * Have I Been Pwned API v3 — the HTTP layer only, kept apart from the rest of
 * the exposure subsystem so its error mapping is testable without a database.
 *
 * Contract (checked against https://haveibeenpwned.com/API/v3, Oct 2026):
 *  - base https://haveibeenpwned.com/api/v3/; the key goes in `hibp-api-key`;
 *  - every request needs a descriptive User-Agent (none → HTTP 403);
 *  - breachedaccount/{account}?truncateResponse=false → full breach models;
 *    404 = in no breach. Sensitive and retired breaches are never returned here;
 *  - breacheddomain/{domain} → { alias: [breachName, ...] }, only for domains
 *    the key owner verified in the HIBP dashboard (403 otherwise; 404 = none).
 *    Includes sensitive breaches. A verified domain larger than the plan
 *    covers is NOT refused: HIBP answers 200 with only its subscription-free
 *    breaches;
 *  - subscribeddomains → [{ DomainName, PwnCount, ... }], the domains verified
 *    on the key's account (Core and Pro plans). No 404 behaviour is
 *    documented, so a 404 here is an error, never an empty list;
 *  - breaches → every breach model, no key needed (enriches domain results);
 *  - subscription/status → the key's plan, including its requests-per-minute
 *    and the largest domain it can search;
 *  - 401 bad key, 403 forbidden, 429 rate limited (retry-after = seconds),
 *    5xx (often Cloudflare's 503) transient. HIBP's public test key gets 401
 *    from subscribeddomains and subscription/status (it only works on the
 *    breach searches, for HIBP's test accounts).
 *
 * SSRF: the host is a constant baked into a URL object; a user-supplied
 * account or domain only ever lands in ONE path segment via
 * encodeURIComponent, so it cannot change where the request goes. Redirects
 * are not followed, so the API key header is never replayed to another host.
 *
 * Nothing here logs; errors carry the HTTP status, never the key or the body.
 */

export const HIBP_API_BASE = 'https://haveibeenpwned.com/api/v3/';
export const HIBP_USER_AGENT = 'SIEMBox-ExposureMonitor/1.0 (+https://github.com/cladkins/siembox)';
const DEFAULT_TIMEOUT_MS = 15_000;
/** Used when a 429 arrives without a usable retry-after header. */
export const DEFAULT_RETRY_AFTER_SECONDS = 60;

export type HibpErrorKind = 'auth' | 'rate_limited' | 'bad_request' | 'transient';

export class HibpError extends Error {
  readonly kind: HibpErrorKind;
  readonly status: number | null;
  /** Seconds to wait before calling again with the same key (429 only). */
  readonly retryAfterSeconds: number | null;

  constructor(
    kind: HibpErrorKind,
    message: string,
    opts: { status?: number; retryAfterSeconds?: number } = {}
  ) {
    super(message);
    this.name = 'HibpError';
    this.kind = kind;
    this.status = opts.status ?? null;
    this.retryAfterSeconds = opts.retryAfterSeconds ?? null;
  }
}

/** The fields of the v3 breach model this app reads; HIBP may add more at any time. */
export interface HibpBreach {
  Name: string;
  Title?: string;
  Domain?: string;
  BreachDate?: string;
  AddedDate?: string;
  ModifiedDate?: string;
  PwnCount?: number;
  DataClasses?: string[];
  IsVerified?: boolean;
  IsFabricated?: boolean;
  IsSensitive?: boolean;
  IsRetired?: boolean;
  IsSpamList?: boolean;
  IsMalware?: boolean;
  IsStealerLog?: boolean;
  /** Credit the party that provided the data asked for (free text: a handle, an address, a URL). */
  Attribution?: string | null;
}

export interface HibpSubscriptionStatus {
  SubscriptionName?: string;
  Description?: string;
  SubscribedUntil?: string;
  Rpm?: number;
  /** The largest domain (breached addresses, spam lists excluded) the plan can search. */
  DomainSearchMaxBreachedAccounts?: number | null;
  /** How many domains the plan can add; null = no maximum. */
  MaxBreachedDomains?: number | null;
  IncludesStealerLogs?: boolean;
  IncludesAutoSubdomainVerification?: boolean;
  IncludesCustomerDomains?: boolean;
  IncludesBulkDomainAdd?: boolean;
  IncludesKAnon?: boolean;
}

/** One domain verified on the key's account (subscribeddomains), numbers sanitized. */
export interface HibpSubscribedDomain {
  /** As HIBP spells it; services/exposure/hibpDomains.ts normalizes it. */
  DomainName: string;
  /** Breached addresses at the last search; null before the first search. */
  PwnCount: number | null;
  PwnCountExcludingSpamLists: number | null;
  /** The count when the current subscription was taken out (locked in until renewal). */
  PwnCountExcludingSpamListsAtLastSubscriptionRenewal: number | null;
  NextSubscriptionRenewal: string | null;
}

export interface HibpSubscribedDomainList {
  domains: HibpSubscribedDomain[];
  /** Entries left out because they weren't objects with a string DomainName. */
  unreadable: number;
  /** Entries past the parse cap (MAX_SUBSCRIBED_DOMAINS_PARSED), not read at all. */
  overLimit: number;
}

/** The most subscribeddomains entries read from one answer. */
export const MAX_SUBSCRIBED_DOMAINS_PARSED = 5_000;

export type FetchFn = (url: URL, init: RequestInit) => Promise<Response>;

export interface HibpClientOptions {
  /** Required for every call except allBreaches(). */
  apiKey?: string;
  fetchImpl?: FetchFn;
  timeoutMs?: number;
}

/** retry-after is seconds in HIBP's case; an HTTP-date is accepted too. */
export function parseRetryAfter(value: string | null, nowMs = Date.now()): number {
  if (value) {
    const trimmed = value.trim();
    if (/^\d+(\.\d+)?$/.test(trimmed)) return Math.ceil(Number(trimmed));
    const at = Date.parse(trimmed);
    if (!Number.isNaN(at)) return Math.max(0, Math.ceil((at - nowMs) / 1000));
  }
  return DEFAULT_RETRY_AFTER_SECONDS;
}

/** Map a non-200/404 status to a typed error. */
export function errorForStatus(status: number, retryAfter: string | null): HibpError {
  if (status === 400) {
    return new HibpError('bad_request', 'HIBP rejected the request as malformed (HTTP 400)', {
      status,
    });
  }
  if (status === 401) {
    return new HibpError('auth', 'HIBP rejected the API key (HTTP 401)', { status });
  }
  if (status === 403) {
    return new HibpError(
      'auth',
      'HIBP refused the request (HTTP 403): the key has no access to this resource, or the User-Agent was rejected',
      { status }
    );
  }
  if (status === 429) {
    const retryAfterSeconds = parseRetryAfter(retryAfter);
    return new HibpError(
      'rate_limited',
      `HIBP rate limit exceeded; retry after ${retryAfterSeconds}s`,
      {
        status,
        retryAfterSeconds,
      }
    );
  }
  if (status >= 500) {
    return new HibpError('transient', `HIBP is temporarily unavailable (HTTP ${status})`, {
      status,
    });
  }
  return new HibpError('transient', `HIBP returned an unexpected HTTP ${status}`, { status });
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isBreach(value: unknown): value is HibpBreach {
  return isPlainObject(value) && typeof value.Name === 'string' && value.Name.length > 0;
}

function unexpectedShape(): HibpError {
  return new HibpError('transient', 'HIBP returned a response in an unexpected format', {
    status: 200,
  });
}

/** A count HIBP reports: finite and not negative, else null (unknown). */
function countOrNull(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null;
}

/** A date-time string HIBP reports (bounded, parseable), else null. */
function dateTextOrNull(value: unknown): string | null {
  return typeof value === 'string' && value.length <= 64 && !Number.isNaN(Date.parse(value))
    ? value
    : null;
}

/** Read one subscribeddomains entry; null when it has no string DomainName. */
function toSubscribedDomain(entry: unknown): HibpSubscribedDomain | null {
  if (!isPlainObject(entry) || typeof entry.DomainName !== 'string') return null;
  return {
    DomainName: entry.DomainName,
    PwnCount: countOrNull(entry.PwnCount),
    PwnCountExcludingSpamLists: countOrNull(entry.PwnCountExcludingSpamLists),
    PwnCountExcludingSpamListsAtLastSubscriptionRenewal: countOrNull(
      entry.PwnCountExcludingSpamListsAtLastSubscriptionRenewal
    ),
    NextSubscriptionRenewal: dateTextOrNull(entry.NextSubscriptionRenewal),
  };
}

/** Constant host; `value` (user data) is confined to one encoded path segment. */
function endpoint(path: string, value?: string): URL {
  // encodeURIComponent leaves "." alone, and "." / ".." segments would be
  // resolved by the URL parser — refuse them rather than walk the API path.
  if (value !== undefined && (value === '' || value === '.' || value === '..')) {
    throw new HibpError('bad_request', 'Refusing to query HIBP for an empty or dot-only value');
  }
  const url = new URL(HIBP_API_BASE);
  url.pathname += value === undefined ? path : `${path}/${encodeURIComponent(value)}`;
  return url;
}

export class HibpClient {
  private readonly apiKey: string | undefined;
  private readonly fetchImpl: FetchFn;
  private readonly timeoutMs: number;

  constructor(options: HibpClientOptions = {}) {
    this.apiKey = options.apiKey;
    this.fetchImpl = options.fetchImpl ?? ((url, init) => fetch(url, init));
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  /** Full breach models for one address; [] when it is in no breach HIBP returns. */
  async breachedAccount(account: string): Promise<HibpBreach[]> {
    const url = endpoint('breachedaccount', account);
    url.searchParams.set('truncateResponse', 'false');
    const body = await this.get(url, true);
    if (body === null) return [];
    if (!Array.isArray(body)) throw unexpectedShape();
    return body.filter(isBreach);
  }

  /**
   * Breached aliases on a domain the key owner has verified with HIBP:
   * { alias: [breachName, ...] } ({} when nothing is found). Only names come
   * back; allBreaches() supplies the rest of each breach model.
   */
  async breachedDomain(domain: string): Promise<Record<string, string[]>> {
    const body = await this.get(endpoint('breacheddomain', domain), true);
    if (body === null) return {};
    if (!isPlainObject(body)) throw unexpectedShape();
    const out: Record<string, string[]> = {};
    for (const [alias, names] of Object.entries(body)) {
      if (!alias || !Array.isArray(names)) continue;
      const valid = names.filter((n): n is string => typeof n === 'string' && n.length > 0);
      if (valid.length > 0) out[alias] = valid;
    }
    return out;
  }

  /** Every breach in HIBP (no key needed). */
  async allBreaches(): Promise<HibpBreach[]> {
    const body = await this.get(endpoint('breaches'), false);
    if (body === null) return [];
    if (!Array.isArray(body)) throw unexpectedShape();
    return body.filter(isBreach);
  }

  /** The key's subscription — the cheapest call that proves a key works. */
  async subscriptionStatus(): Promise<HibpSubscriptionStatus> {
    const body = await this.get(endpoint('subscription/status'), true);
    if (!isPlainObject(body)) throw unexpectedShape();
    return body as HibpSubscriptionStatus;
  }

  /**
   * The domains verified on the key's account (its domain search dashboard).
   * Only a 200 with a JSON array is an answer: a 404 is undocumented here, so
   * it is an error rather than "no domains" (reading it as an empty list would
   * silently skip every domain if HIBP ever moved the endpoint).
   */
  async subscribedDomains(): Promise<HibpSubscribedDomainList> {
    const body = await this.get(endpoint('subscribeddomains'), true);
    if (body === null) {
      throw new HibpError('transient', 'HIBP answered HTTP 404 for the verified-domain list', {
        status: 404,
      });
    }
    if (!Array.isArray(body)) throw unexpectedShape();
    const domains: HibpSubscribedDomain[] = [];
    let unreadable = 0;
    for (const entry of body.slice(0, MAX_SUBSCRIBED_DOMAINS_PARSED)) {
      const domain = toSubscribedDomain(entry);
      if (domain) domains.push(domain);
      else unreadable++;
    }
    return {
      domains,
      unreadable,
      overLimit: Math.max(0, body.length - MAX_SUBSCRIBED_DOMAINS_PARSED),
    };
  }

  /** Parsed JSON for a 200, null for a 404; throws HibpError for anything else. */
  private async get(url: URL, withKey: boolean): Promise<unknown> {
    const headers: Record<string, string> = {
      'User-Agent': HIBP_USER_AGENT,
      Accept: 'application/json',
    };
    if (withKey) {
      if (!this.apiKey) throw new HibpError('auth', 'No HIBP API key is configured');
      headers['hibp-api-key'] = this.apiKey;
    }

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      let res: Response;
      try {
        res = await this.fetchImpl(url, { headers, signal: ctrl.signal, redirect: 'manual' });
      } catch {
        throw new HibpError(
          'transient',
          ctrl.signal.aborted ? 'HIBP request timed out' : 'HIBP could not be reached'
        );
      }

      if (res.status !== 200) {
        void res.body?.cancel().catch(() => undefined);
        if (res.status === 404) return null;
        throw errorForStatus(res.status, res.headers.get('retry-after'));
      }
      try {
        return await res.json();
      } catch {
        throw ctrl.signal.aborted
          ? new HibpError('transient', 'HIBP request timed out')
          : new HibpError('transient', 'HIBP returned a response that is not valid JSON', {
              status: 200,
            });
      }
    } finally {
      clearTimeout(timer);
    }
  }
}
