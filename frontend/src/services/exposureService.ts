import apiClient from './api';

/**
 * Typed client for the Exposure Monitoring ("Digital Risk") API at
 * /api/exposure (backend/src/routes/exposure.ts; documented in
 * docs/reference/API.md). Settings → Digital Risk and the onboarding checklist
 * both go through this client, so anything entered in one shows up in the
 * other.
 *
 * Every GET is open to any signed-in user. Every write is admin-only (403
 * otherwise) except checkPassword(), which any signed-in user may call (it is
 * rate limited per IP instead).
 */

export type DomainScope = 'own' | 'brand';
export type IdentityKind = 'email' | 'email_domain';
export type ExposureSeverity = 'low' | 'medium' | 'high' | 'critical';
export type ExposureFindingSource = 'leaked-creds' | 'domain-monitor';
/** Background-job state from the job registry (backend services/jobs/jobRegistry.ts). */
export type ExposureJobStatus = 'idle' | 'running' | 'ok' | 'failed' | 'skipped' | 'disabled';

export const EXPOSURE_SEVERITIES: readonly ExposureSeverity[] = ['low', 'medium', 'high', 'critical'];

export interface DomainCollectors {
  ct: boolean;
  lookalike: boolean;
  rdap: boolean;
  dns: boolean;
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

export interface MonitoredIdentity {
  id: number;
  kind: IdentityKind;
  value: string;
  enabled: boolean;
  interval_minutes: number;
  last_checked_at: string | null;
  /** 'ok' or 'error' once checked; null before the first check. */
  last_status: string | null;
  last_error: string | null;
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
  identity_kind: IdentityKind | null;
  identity_value: string | null;
  domain: string | null;
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
  /** 1-200, default 50. */
  limit?: number;
  offset?: number;
}

export interface ExposureSettings {
  notify_exposure_enabled: boolean;
  notify_exposure_min_severity: ExposureSeverity;
  exposure_leaked_creds_enabled: boolean;
}

/** A breach-data provider as the API shows it: never the key, only whether one is saved. */
export interface ExposureProvider {
  name: string;
  label: string;
  docsUrl: string;
  signupUrl: string;
  attribution: string;
  configured: boolean;
  enabled: boolean;
}

export interface HibpSubscription {
  name: string | null;
  description: string | null;
  subscribed_until: string | null;
  /** Requests per minute the plan allows. */
  rpm: number | null;
  domain_search_max_breached_accounts: number | null;
  includes_stealer_logs: boolean | null;
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
  findings_total: number;
  findings_open: number;
  findings_open_by_severity: Partial<Record<ExposureSeverity, number>>;
}

/** Outcome of one leaked-credential run (POST /run-now, or status.leaked_creds.last_run.summary). */
export interface LeakedCredentialRunSummary {
  checked: number;
  newFindings: number;
  failed: number;
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
    domain_monitor_available: boolean;
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
const PASSWORD_CHECK_TIMEOUT_MS = 25_000;

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

  async getSettings(): Promise<ExposureSettings> {
    const response = await apiClient.get('/exposure/settings');
    return response.data;
  }

  /** Update any subset of the settings; returns the full settings. Admin only. */
  async updateSettings(changes: Partial<ExposureSettings>): Promise<ExposureSettings> {
    const response = await apiClient.put('/exposure/settings', changes);
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
      const response = await apiClient.put('/exposure/providers/hibp', body);
      dropRequestBody(response);
      return response.data;
    } catch (error) {
      dropRequestBody(error);
      throw error;
    }
  }

  /** Turn the provider on or off without touching the stored key. Admin only. */
  async setHibpEnabled(enabled: boolean): Promise<ExposureProvider> {
    const response = await apiClient.put('/exposure/providers/hibp', { enabled });
    return response.data;
  }

  /** Delete the stored HIBP key (the only call that clears it). Admin only. */
  async removeHibpKey(): Promise<ExposureProvider> {
    const response = await apiClient.put('/exposure/providers/hibp', { api_key: null });
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
        { timeout: HIBP_TEST_TIMEOUT_MS }
      );
      dropRequestBody(response);
      return response.data;
    } catch (error) {
      dropRequestBody(error);
      throw error;
    }
  }

  // ---- Watched domains ------------------------------------------------------

  async listDomains(): Promise<WatchedDomain[]> {
    const response = await apiClient.get('/exposure/domains');
    return response.data;
  }

  /** Admin only. 400 with the reason for an invalid domain; 409 when it is already watched. */
  async addDomain(input: WatchedDomainInput): Promise<WatchedDomain> {
    const response = await apiClient.post('/exposure/domains', input);
    return response.data;
  }

  async updateDomain(id: number, changes: WatchedDomainUpdate): Promise<WatchedDomain> {
    const response = await apiClient.put(`/exposure/domains/${id}`, changes);
    return response.data;
  }

  /** Also deletes the domain's findings (their alerts stay). Admin only. */
  async deleteDomain(id: number): Promise<void> {
    await apiClient.delete(`/exposure/domains/${id}`);
  }

  // ---- Monitored identities -------------------------------------------------

  async listIdentities(): Promise<MonitoredIdentity[]> {
    const response = await apiClient.get('/exposure/identities');
    return response.data;
  }

  /** Admin only. 400 with the reason for an invalid value; 409 when it is already monitored. */
  async addIdentity(input: MonitoredIdentityInput): Promise<MonitoredIdentity> {
    const response = await apiClient.post('/exposure/identities', input);
    return response.data;
  }

  async updateIdentity(id: number, changes: MonitoredIdentityUpdate): Promise<MonitoredIdentity> {
    const response = await apiClient.put(`/exposure/identities/${id}`, changes);
    return response.data;
  }

  /** Also deletes the identity's findings (their alerts stay). Admin only. */
  async deleteIdentity(id: number): Promise<void> {
    await apiClient.delete(`/exposure/identities/${id}`);
  }

  // ---- Findings -------------------------------------------------------------

  async listFindings(query: ExposureFindingsQuery = {}): Promise<ExposureFindingsPage> {
    const params: Record<string, string | number> = {};
    if (query.source) params.source = query.source;
    if (query.severity) params.severity = query.severity;
    if (query.unresolved) params.unresolved = 'true';
    if (query.identity_id !== undefined) params.identity_id = query.identity_id;
    if (query.domain_id !== undefined) params.domain_id = query.domain_id;
    if (query.limit !== undefined) params.limit = query.limit;
    if (query.offset !== undefined) params.offset = query.offset;
    const response = await apiClient.get('/exposure/findings', { params });
    return response.data;
  }

  /** Idempotent; later checks never reopen a resolved finding. Admin only. */
  async resolveFinding(id: number): Promise<ExposureFinding> {
    const response = await apiClient.post(`/exposure/findings/${id}/resolve`);
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
      { timeout: RUN_NOW_TIMEOUT_MS }
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
        { timeout: PASSWORD_CHECK_TIMEOUT_MS }
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
