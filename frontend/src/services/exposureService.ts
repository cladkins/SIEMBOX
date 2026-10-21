import apiClient from './api';

/**
 * Typed client for the Exposure Monitoring ("Digital Risk") API at
 * /api/exposure (backend/src/routes/exposure.ts; documented in
 * docs/reference/API.md). The Digital Risk page, Settings → Digital Risk and
 * the onboarding checklist all go through this client, so anything entered in
 * one shows up in the others.
 *
 * Every GET is open to any signed-in user except getHibpVerifiedDomains()
 * (the HIBP account's own data, admin-only like the key test). Every write is
 * admin-only (403 otherwise) except checkPassword(), which any signed-in user
 * may call (it is rate limited per IP instead).
 */

export type DomainScope = 'own' | 'brand';
export type IdentityKind = 'email' | 'email_domain';
export type ExposureSeverity = 'low' | 'medium' | 'high' | 'critical';
export type ExposureFindingSource = 'leaked-creds' | 'domain-monitor';
/** Background-job state from the job registry (backend services/jobs/jobRegistry.ts). */
export type ExposureJobStatus = 'idle' | 'running' | 'ok' | 'failed' | 'skipped' | 'disabled';

export const EXPOSURE_SEVERITIES: readonly ExposureSeverity[] = ['low', 'medium', 'high', 'critical'];

/** Every event type a finding is written with (the backend's EXPOSURE_EVENT_TYPES). */
export const EXPOSURE_EVENT_TYPES = [
  'breach',
  'new_cert',
  'unexpected_ca',
  'lookalike_registered',
  'rdap_change',
  'dns_drift',
  'expiry_warning',
] as const;
export type ExposureEventType = (typeof EXPOSURE_EVENT_TYPES)[number];

/**
 * What a finding is about: a leaked account, a lookalike of a watched domain
 * (its registration or a certificate for it), or a change to the watched
 * domain itself. Derived by the backend from the event type and detail.
 */
export type RiskCategory = 'credentials' | 'impersonation' | 'domain_changes';
export const RISK_CATEGORY_KEYS: readonly RiskCategory[] = ['credentials', 'impersonation', 'domain_changes'];

/** The windows GET /summary accepts, in days. */
export const SUMMARY_DAYS = [30, 90, 180, 365] as const;
export type SummaryDays = (typeof SUMMARY_DAYS)[number];

export interface DomainCollectors {
  ct: boolean;
  lookalike: boolean;
  rdap: boolean;
  dns: boolean;
}

export type DomainCollectorName = keyof DomainCollectors;

/**
 * One collector's outcome in a domain's last run: `baseline` (its first run,
 * recorded silently), `ok`, `unsupported` (nothing it can monitor here, e.g. a
 * TLD without RDAP; `note` says why), `error` (with `error`), `disabled`
 * (switched off in `collectors`) or `not_applicable` (not run for the scope).
 */
export interface DomainCollectorRun {
  status: string;
  note?: string;
  error?: string;
  /** For an error: retried before the domain's next regular run. */
  transient?: boolean;
  new_findings?: number;
  /** Partial failures that didn't stop the collector (e.g. a DNS record type a resolver didn't answer). */
  warnings?: string[];
  details?: Record<string, unknown>;
  at?: string;
}

/** A domain's last run, as `last_summary` holds it (the object POST /domains/:id/run-now returns). */
export interface DomainRunSummary {
  trigger?: string;
  started_at?: string;
  status?: string;
  new_findings?: number;
  collectors?: Partial<Record<DomainCollectorName, DomainCollectorRun>>;
}

export interface WatchedDomain {
  id: number;
  domain: string;
  scope: DomainScope;
  enabled: boolean;
  interval_minutes: number;
  collectors: DomainCollectors;
  expected_cas: string[];
  last_checked_at: string | null;
  next_run_at: string | null;
  last_status: string | null;
  last_error: string | null;
  /** Each collector's outcome on the last run: null before the first run; absent from a backend without domain monitoring. */
  last_summary?: DomainRunSummary | null;
  created_at: string;
  updated_at: string;
}

/** Body of POST /domains. Omitted fields take the server defaults (scope 'own', enabled, daily). */
export interface WatchedDomainInput {
  domain: string;
  scope?: DomainScope;
  enabled?: boolean;
  /** Whole minutes, 60-43200. */
  interval_minutes?: number;
  /** Unspecified collectors stay on. */
  collectors?: Partial<DomainCollectors>;
  expected_cas?: string[];
}

/** Body of PUT /domains/:id. The domain itself can't change (delete and re-add instead). */
export type WatchedDomainUpdate = Partial<Omit<WatchedDomainInput, 'domain'>>;

/** An email domain's standing with HIBP for the saved key. */
export type HibpDomainState = 'verified' | 'verified_limited' | 'not_verified' | 'unavailable' | 'unknown';
/** Why verification is unknown (`state: 'unknown'` only). */
export type HibpDomainUnknownReason =
  | 'no_key'
  | 'not_checked'
  | 'auth'
  | 'rate_limited'
  | 'network'
  | 'hibp_unavailable'
  | 'bad_response'
  | 'list_incomplete';

/** GET /identities → hibp_domain (email domains only). Read from the stored list: never a call to HIBP. */
export interface IdentityHibpDomain {
  state: HibpDomainState;
  reason: HibpDomainUnknownReason | null;
  /** not_verified only: a listed parent domain (HIBP verifies each name separately). */
  verified_parent: string | null;
  /** When the list used was fetched. */
  listed_at: string | null;
  /** The server's explanation, shown as-is for 'unknown' (and any state this UI doesn't know). */
  message: string;
}

export interface MonitoredIdentity {
  id: number;
  kind: IdentityKind;
  value: string;
  enabled: boolean;
  interval_minutes: number;
  last_checked_at: string | null;
  /**
   * 'ok', 'error' or 'unverified' (an email domain skipped because it isn't
   * verified on the HIBP account: not a failure); null before the first check.
   * Kept a string so an unknown value still renders.
   */
  last_status: string | null;
  last_error: string | null;
  /** Email domains: whether HIBP will search it. null for an email; absent from older backends. */
  hibp_domain?: IdentityHibpDomain | null;
  created_at: string;
  updated_at: string;
}

/** Body of POST /identities. */
export interface MonitoredIdentityInput {
  kind: IdentityKind;
  value: string;
  enabled?: boolean;
  /** Whole minutes, 60-43200. */
  interval_minutes?: number;
}

/** Body of PUT /identities/:id. kind and value can't change (findings are fingerprinted on them). */
export interface MonitoredIdentityUpdate {
  enabled?: boolean;
  interval_minutes?: number;
}

export interface ExposureFinding {
  id: number;
  source: ExposureFindingSource;
  identity_id: number | null;
  domain_id: number | null;
  event_type: string;
  title: string | null;
  severity: ExposureSeverity;
  /** Scrubbed of secrets server-side. Breach findings carry account, breach_* fields, data_classes and attribution. */
  detail: Record<string, unknown>;
  alert_id: number | null;
  first_seen: string;
  last_seen: string;
  resolved_at: string | null;
  /** Absent from backends before the Digital Risk page. */
  category?: RiskCategory;
  identity_kind: IdentityKind | null;
  identity_value: string | null;
  domain: string | null;
  /** The linked alert's status (new, investigating, closed, false_positive); null without an alert. */
  alert_status?: string | null;
}

export interface ExposureFindingsPage {
  findings: ExposureFinding[];
  total: number;
  limit: number;
  offset: number;
}

export interface ExposureFindingsQuery {
  source?: ExposureFindingSource;
  severity?: ExposureSeverity;
  /** Open findings only. */
  unresolved?: boolean;
  identity_id?: number;
  domain_id?: number;
  event_type?: ExposureEventType;
  category?: RiskCategory;
  /** First seen in the last N days (1-365). */
  since_days?: number;
  /** First seen at or after this ISO timestamp. */
  since?: string;
  alert_id?: number;
  /** Case-insensitive, literal; at most 200 characters. */
  search?: string;
  /** The breached account, whole (case-insensitive). */
  account?: string;
  /** The lookalike domain a finding is about, whole (case-insensitive). */
  lookalike?: string;
  /** 'newest' (default) or 'severity' (most severe first, then newest). */
  sort?: 'newest' | 'severity';
  /** 1-200, default 50. */
  limit?: number;
  offset?: number;
}

export interface ExposureSettings {
  notify_exposure_enabled: boolean;
  notify_exposure_min_severity: ExposureSeverity;
  exposure_leaked_creds_enabled: boolean;
}

/**
 * Cert Spotter, the certificate monitor's fallback when crt.sh is down, as the
 * API shows it: never the key, only whether one is saved. Used with or without
 * a key (without one, within a small hourly limit).
 */
export interface CertSpotterProvider {
  name: 'certspotter';
  label: string;
  docsUrl: string;
  signupUrl: string;
  apiKeysUrl: string;
  /** A key is saved. */
  configured: boolean;
  /** The backend can decrypt the saved key (see ExposureProvider.usable). */
  usable: boolean;
  /** While Cert Spotter's rate limit holds requests back: when they resume (ISO). */
  rate_limited_until: string | null;
}

/** A breach-data provider as the API shows it: never the key, only whether one is saved. */
export interface ExposureProvider {
  name: string;
  label: string;
  docsUrl: string;
  signupUrl: string;
  attribution: string;
  /** The data's licence ("CC BY 4.0"); absent from older backends. */
  license?: string;
  licenseUrl?: string;
  /** A key is saved. */
  configured: boolean;
  enabled: boolean;
  /**
   * The backend can decrypt the saved key. False while `configured` means
   * CREDENTIAL_ENCRYPTION_KEY is missing or has changed since the key was
   * saved, so no breach check can run.
   */
  usable: boolean;
}

export interface HibpSubscription {
  name: string | null;
  description: string | null;
  subscribed_until: string | null;
  /** Requests per minute the plan allows. */
  rpm: number | null;
  domain_search_max_breached_accounts: number | null;
  /** How many domains the plan can add (null: no maximum, or an older backend). */
  max_breached_domains?: number | null;
  includes_stealer_logs: boolean | null;
}

/** Overall state of the HIBP key's verified-domain list. */
export type HibpVerifiedDomainsState = 'no_key' | 'not_checked' | 'listed' | 'error';
export type HibpDomainListErrorKind =
  | 'auth'
  | 'forbidden'
  | 'rate_limited'
  | 'network'
  | 'hibp_unavailable'
  | 'bad_response';

/** Why the latest listing failed. */
export interface HibpDomainListError {
  kind: HibpDomainListErrorKind;
  status: number | null;
  message: string;
  /** rate_limited: no listing before this time. */
  retry_after: string | null;
}

export interface HibpPlanView {
  name: string | null;
  domain_search_max_breached_accounts: number | null;
  /** null: no maximum, or unknown. */
  max_breached_domains: number | null;
  subscribed_until: string | null;
}

export interface HibpVerifiedDomain {
  domain: string;
  pwn_count: number | null;
  pwn_count_excluding_spam_lists: number | null;
  pwn_count_excluding_spam_lists_at_last_subscription_renewal: number | null;
  next_subscription_renewal: string | null;
  /** The plan covers the domain's size; null when unknown. */
  within_plan: boolean | null;
  /** The monitored email_domain identity, if any. */
  identity_id: number | null;
}

/** GET /providers/hibp/verified-domains (admin): the account view; never calls HIBP. */
export interface HibpVerifiedDomainsView {
  state: HibpVerifiedDomainsState;
  checked_at: string | null;
  listed_at: string | null;
  stale: boolean;
  error: HibpDomainListError | null;
  plan: HibpPlanView | null;
  domains: HibpVerifiedDomain[] | null;
  truncated: boolean;
  skipped_entries: number;
  /** The earliest time a re-check will call HIBP (cooldown or rate-limit pause); null = now. */
  next_refresh_allowed_at: string | null;
  attribution: string;
}

/** POST /providers/hibp/verified-domains/refresh. */
export interface HibpVerifiedDomainsRefreshResult extends HibpVerifiedDomainsView {
  /** False: HIBP was asked less than a minute ago, and that answer is shown. */
  refreshed: boolean;
  /** Identities that turned verified and are due again. */
  became_due: number[];
}

export interface HibpTestResult {
  ok: boolean;
  subscription: HibpSubscription;
}

export interface ExposureCounts {
  identities: number;
  identities_enabled: number;
  identities_due: number;
  domains: number;
  domains_enabled: number;
  /** Enabled domains due for a check now. */
  domains_due?: number;
  findings_total: number;
  findings_open: number;
  findings_open_by_severity: Partial<Record<ExposureSeverity, number>>;
}

/** Outcome of one leaked-credential run (POST /run-now, or status.leaked_creds.last_run.summary). */
export interface LeakedCredentialRunSummary {
  checked: number;
  newFindings: number;
  failed: number;
  /** Email domains skipped as not verified on HIBP (not failures); absent from older backends. */
  unverified?: number;
  /** Identities still due afterwards. */
  remaining: number;
  /** True when the run did no work; `reason` says why. */
  skipped: boolean;
  reason?: string;
  /** Why the run stopped early (rate limit, rejected key, provider down). */
  error?: string;
  /** Set when HIBP rate-limited the run: no checks before this time. */
  rateLimitedUntil?: string;
}

export interface LeakedCredentialJobState {
  status: ExposureJobStatus;
  last_run_at: string | null;
  last_result: string | null;
  last_error: string | null;
  next_run_at: string | null;
}

export interface ExposureStatus {
  features: {
    leaked_creds_enabled: boolean;
    password_check_available: boolean;
    /** False until the backend includes the domain-monitoring collectors. */
    domain_monitor_available: boolean;
    /** The exposure_domain_monitor_enabled setting; absent from backends without domain monitoring. */
    domain_monitor_enabled?: boolean;
  };
  notifications: { enabled: boolean; min_severity: ExposureSeverity };
  providers: ExposureProvider[];
  counts: ExposureCounts;
  /** In-process state of this backend: resets when it restarts. */
  leaked_creds: {
    running: boolean;
    /** Set while HIBP rate-limited us or rejected the key. */
    paused_until: string | null;
    pause_reason: string | null;
    last_run: { at: string; trigger: string; summary: LeakedCredentialRunSummary } | null;
    job: LeakedCredentialJobState | null;
  };
  /** In-process state of the domain monitor: resets when the backend restarts. Absent from older backends. */
  domain_monitor?: {
    running: boolean;
    domains_in_progress: number;
    last_run: { at: string; trigger: string; summary: Record<string, unknown> } | null;
    job: LeakedCredentialJobState | null;
  };
}

export type SeverityCounts = Record<ExposureSeverity, number>;

/** GET /summary: the Digital Risk page's aggregates, from one database snapshot. */
export interface ExposureSummary {
  generated_at: string;
  window: { days: SummaryDays; bucket: 'day' | 'week' | 'month'; since: string };
  open: {
    total: number;
    by_severity: SeverityCounts;
    by_source: Record<ExposureFindingSource, number>;
    oldest_critical_high_first_seen: string | null;
  };
  in_window: { new: number; new_by_severity: SeverityCounts; resolved: number; prev_new: number };
  by_type: Array<{
    source: string;
    event_type: string;
    category: RiskCategory;
    open: number;
    open_by_severity: SeverityCounts;
    new: number;
    resolved: number;
  }>;
  trend: ExposureTrendBucket[];
  accounts: {
    total: number;
    to_reset: number;
    top: ExposureSummaryAccount[];
  };
  lookalikes: {
    state: 'not_watched' | 'not_checked' | 'checked';
    candidates_checked: number;
    /** Distinct registered names (one shared by two watched domains counts once); `top` has a row per domain. */
    registered: number;
    with_mx: number;
    with_address: number;
    with_current_cert: number;
    top: ExposureSummaryLookalike[];
  };
}

export interface ExposureTrendBucket {
  start: string;
  new: Record<RiskCategory, number>;
  resolved: number;
  open_at_end: number;
  monitoring_added: { identities: number; domains: number };
}

export interface ExposureSummaryAccount {
  account: string;
  identity_id: number | null;
  /** Open breach findings (one breach reported through two identities is two). */
  open: number;
  credential_exposures: number;
  stealer_log: boolean;
  worst_severity: ExposureSeverity;
  /** Up to three distinct breaches, newest first. */
  breaches: Array<{ title: string; date: string | null }>;
  /** Distinct breaches in all ("+N more" counts from this, not from `open`). */
  breach_count: number;
  last_detected: string;
}

export interface ExposureSummaryLookalike {
  lookalike: string;
  domain_id: number;
  watched_domain: string;
  scope: DomainScope;
  technique: string | null;
  has_mx: boolean | null;
  has_address: boolean | null;
  certs: 'current' | 'none' | 'not_checked';
  reported_at: string | null;
  open_findings: { count: number; worst_severity: ExposureSeverity } | null;
}

export interface PasswordCheckResult {
  pwned: boolean;
  /** Times the password appears in the Pwned Passwords corpus; 0 when not found. */
  count: number;
}

// "Run now" works for up to ~90 s server-side (HIBP calls are paced to the
// key's plan), and the HIBP / Pwned Passwords calls time out at 15 s / 10 s
// on the server; the client's default 10 s timeout would give up first.
const RUN_NOW_TIMEOUT_MS = 150_000;
const HIBP_TEST_TIMEOUT_MS = 30_000;
// A re-check makes two paced HIBP calls, possibly behind a running check
// (about 42 s at 10 requests per minute).
const HIBP_REFRESH_TIMEOUT_MS = 60_000;
/** The axios error code of a request this client gave up waiting for. */
export const CLIENT_TIMEOUT_CODE = 'ECONNABORTED';
const PASSWORD_CHECK_TIMEOUT_MS = 25_000;

// For calls whose every caller shows the API's own message when they fail
// (inline or as a toast): the client's generic error toast would repeat it.
const HANDLED = { skipErrorToast: true } as const;

/**
 * Forget the serialized request body an axios response or error holds on to,
 * so a secret sent in it (an API key, a password) doesn't outlive the request
 * in an object some caller might keep, inspect or log.
 */
function dropRequestBody(holder: unknown): void {
  const obj = holder as { config?: { data?: unknown }; response?: { config?: { data?: unknown } } } | null;
  if (obj?.config) obj.config.data = undefined;
  if (obj?.response?.config) obj.response.config.data = undefined;
}

class ExposureServiceClient {
  // ---- Status & settings ----------------------------------------------------

  async getStatus(): Promise<ExposureStatus> {
    const response = await apiClient.get('/exposure/status');
    return response.data;
  }

  /** The Digital Risk page's aggregates over the last `days` (any signed-in user). */
  async getSummary(days: SummaryDays = 90): Promise<ExposureSummary> {
    const response = await apiClient.get('/exposure/summary', { params: { days }, ...HANDLED });
    return response.data;
  }

  async getSettings(): Promise<ExposureSettings> {
    const response = await apiClient.get('/exposure/settings', HANDLED);
    return response.data;
  }

  /** Update any subset of the settings; returns the full settings. Admin only. */
  async updateSettings(changes: Partial<ExposureSettings>): Promise<ExposureSettings> {
    const response = await apiClient.put('/exposure/settings', changes, HANDLED);
    return response.data;
  }

  // ---- Cert Spotter (optional key for the certificate monitor's fallback) ----

  async getCertSpotterProvider(): Promise<CertSpotterProvider> {
    const response = await apiClient.get('/exposure/providers/certspotter', HANDLED);
    return response.data;
  }

  /**
   * Save a Cert Spotter API key (stored encrypted, never returned). Admin only.
   * An empty key is refused here: clearing only ever happens through
   * removeCertSpotterKey().
   */
  async saveCertSpotterKey(apiKey: string): Promise<CertSpotterProvider> {
    const key = apiKey.trim();
    if (!key) throw new Error('Enter an API key to save');
    try {
      const response = await apiClient.put('/exposure/providers/certspotter', { api_key: key }, HANDLED);
      dropRequestBody(response);
      return response.data;
    } catch (error) {
      dropRequestBody(error);
      throw error;
    }
  }

  /** Delete the stored Cert Spotter key; Cert Spotter is then used unauthenticated. Admin only. */
  async removeCertSpotterKey(): Promise<CertSpotterProvider> {
    const response = await apiClient.put('/exposure/providers/certspotter', { api_key: null }, HANDLED);
    return response.data;
  }

  // ---- HIBP provider (bring-your-own-key) -----------------------------------

  async getProviders(): Promise<ExposureProvider[]> {
    const response = await apiClient.get('/exposure/providers');
    return response.data;
  }

  /**
   * Save a new HIBP key (stored encrypted, never returned), optionally setting
   * the enabled flag in the same call. Admin only.
   *
   * An empty key is refused here instead of being sent: the API treats "" as
   * "clear the key", and clearing must only ever happen through removeHibpKey().
   */
  async saveHibpKey(apiKey: string, enabled?: boolean): Promise<ExposureProvider> {
    const key = apiKey.trim();
    if (!key) throw new Error('Enter an API key to save');
    const body: { api_key: string; enabled?: boolean } = { api_key: key };
    if (enabled !== undefined) body.enabled = enabled;
    try {
      const response = await apiClient.put('/exposure/providers/hibp', body, HANDLED);
      dropRequestBody(response);
      return response.data;
    } catch (error) {
      dropRequestBody(error);
      throw error;
    }
  }

  /** Turn the provider on or off without touching the stored key. Admin only. */
  async setHibpEnabled(enabled: boolean): Promise<ExposureProvider> {
    const response = await apiClient.put('/exposure/providers/hibp', { enabled }, HANDLED);
    return response.data;
  }

  /** Delete the stored HIBP key (the only call that clears it). Admin only. */
  async removeHibpKey(): Promise<ExposureProvider> {
    const response = await apiClient.put('/exposure/providers/hibp', { api_key: null }, HANDLED);
    return response.data;
  }

  /**
   * Validate a key with HIBP's subscription/status call: `apiKey` when given
   * (so it can be checked before saving), otherwise the stored key. Nothing is
   * saved. Admin only. HIBP's public test key always fails this check.
   */
  async testHibpKey(apiKey?: string): Promise<HibpTestResult> {
    const key = apiKey?.trim();
    try {
      const response = await apiClient.post(
        '/exposure/providers/hibp/test',
        key ? { api_key: key } : {},
        { timeout: HIBP_TEST_TIMEOUT_MS, ...HANDLED }
      );
      dropRequestBody(response);
      return response.data;
    } catch (error) {
      dropRequestBody(error);
      throw error;
    }
  }

  /** The HIBP key's verified domains, plan and latest listing. Admin only; never calls HIBP. */
  async getHibpVerifiedDomains(): Promise<HibpVerifiedDomainsView> {
    const response = await apiClient.get('/exposure/providers/hibp/verified-domains', HANDLED);
    return response.data;
  }

  /**
   * Re-check with HIBP which domains are verified (at most once a minute
   * install-wide; otherwise the cached answer with refreshed=false). Admin
   * only. 400 without a usable key; 429 during a rate-limit pause.
   */
  async refreshHibpVerifiedDomains(): Promise<HibpVerifiedDomainsRefreshResult> {
    const response = await apiClient.post('/exposure/providers/hibp/verified-domains/refresh', undefined, {
      timeout: HIBP_REFRESH_TIMEOUT_MS,
      ...HANDLED,
    });
    return response.data;
  }

  // ---- Watched domains ------------------------------------------------------

  async listDomains(): Promise<WatchedDomain[]> {
    const response = await apiClient.get('/exposure/domains');
    return response.data;
  }

  /** Admin only. 400 with the reason for an invalid domain; 409 when it is already watched. */
  async addDomain(input: WatchedDomainInput): Promise<WatchedDomain> {
    const response = await apiClient.post('/exposure/domains', input, HANDLED);
    return response.data;
  }

  async updateDomain(id: number, changes: WatchedDomainUpdate): Promise<WatchedDomain> {
    const response = await apiClient.put(`/exposure/domains/${id}`, changes, HANDLED);
    return response.data;
  }

  /** Also deletes the domain's findings (their alerts stay). Admin only. */
  async deleteDomain(id: number): Promise<void> {
    await apiClient.delete(`/exposure/domains/${id}`, HANDLED);
  }

  // ---- Monitored identities -------------------------------------------------

  async listIdentities(): Promise<MonitoredIdentity[]> {
    const response = await apiClient.get('/exposure/identities');
    return response.data;
  }

  /** Admin only. 400 with the reason for an invalid value; 409 when it is already monitored. */
  async addIdentity(input: MonitoredIdentityInput): Promise<MonitoredIdentity> {
    const response = await apiClient.post('/exposure/identities', input, HANDLED);
    return response.data;
  }

  async updateIdentity(id: number, changes: MonitoredIdentityUpdate): Promise<MonitoredIdentity> {
    const response = await apiClient.put(`/exposure/identities/${id}`, changes, HANDLED);
    return response.data;
  }

  /** Also deletes the identity's findings (their alerts stay). Admin only. */
  async deleteIdentity(id: number): Promise<void> {
    await apiClient.delete(`/exposure/identities/${id}`, HANDLED);
  }

  // ---- Findings -------------------------------------------------------------

  async listFindings(query: ExposureFindingsQuery = {}): Promise<ExposureFindingsPage> {
    const params: Record<string, string | number> = {};
    if (query.source) params.source = query.source;
    if (query.severity) params.severity = query.severity;
    if (query.unresolved) params.unresolved = 'true';
    if (query.identity_id !== undefined) params.identity_id = query.identity_id;
    if (query.domain_id !== undefined) params.domain_id = query.domain_id;
    if (query.event_type) params.event_type = query.event_type;
    if (query.category) params.category = query.category;
    if (query.since_days !== undefined) params.since_days = query.since_days;
    if (query.since) params.since = query.since;
    if (query.alert_id !== undefined) params.alert_id = query.alert_id;
    if (query.search) params.search = query.search;
    if (query.account) params.account = query.account;
    if (query.lookalike) params.lookalike = query.lookalike;
    if (query.sort && query.sort !== 'newest') params.sort = query.sort;
    if (query.limit !== undefined) params.limit = query.limit;
    if (query.offset !== undefined) params.offset = query.offset;
    const response = await apiClient.get('/exposure/findings', { params, ...HANDLED });
    return response.data;
  }

  /** Idempotent; later checks never reopen a resolved finding. Admin only. */
  async resolveFinding(id: number): Promise<ExposureFinding> {
    const response = await apiClient.post(`/exposure/findings/${id}/resolve`, undefined, HANDLED);
    return response.data;
  }

  // ---- Leaked-credential checks ---------------------------------------------

  /**
   * Run the leaked-credential check now: the due identities, or every enabled
   * one with `force`. Admin only. 409 while a check is already running.
   */
  async runNow(force = false): Promise<LeakedCredentialRunSummary> {
    const response = await apiClient.post(
      '/exposure/run-now',
      force ? { force: true } : {},
      { timeout: RUN_NOW_TIMEOUT_MS, ...HANDLED }
    );
    return response.data;
  }

  /**
   * Stateless k-anonymity check of one password against Pwned Passwords (any
   * signed-in user; 30 per 15 minutes per IP). The password travels only in
   * this request's body — never a URL, a log or storage — and the serialized
   * body is dropped from the response or error before either leaves here.
   */
  async checkPassword(password: string): Promise<PasswordCheckResult> {
    try {
      const response = await apiClient.post(
        '/exposure/password-check',
        { password },
        { timeout: PASSWORD_CHECK_TIMEOUT_MS, ...HANDLED }
      );
      dropRequestBody(response);
      return { pwned: response.data?.pwned === true, count: Number(response.data?.count) || 0 };
    } catch (error) {
      dropRequestBody(error);
      throw error;
    }
  }
}

export default new ExposureServiceClient();
