import axios, { AxiosInstance, AxiosError, type AxiosRequestConfig } from 'axios';
import { ElMessage } from 'element-plus';
import { useAuthStore } from '@/stores/auth';
import type { DisplaySnapshot } from '@/display/types';
import type { DisplayConfig, DisplayLinkDetail, DisplayLinkSecret, DisplayLinkSummary } from '@/utils/displayLinks';

const apiClient: AxiosInstance = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '/api',
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor
apiClient.interceptors.request.use(
  (config) => {
    // Every API route the UI calls requires a login (including /assets/scans*,
    // which used to be sent without the token), so always attach it.
    const authStore = useAuthStore();
    if (authStore.token) {
      config.headers.Authorization = `Bearer ${authStore.token}`;
    }

    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

declare module 'axios' {
  interface AxiosRequestConfig {
    /**
     * The caller shows its own message for an error response, so the generic
     * toast below would only repeat it. A 401 still signs out and says so.
     */
    skipErrorToast?: boolean;
    /**
     * The caller also shows its own message when no answer came at all (the
     * API can't be reached, or the request timed out), so skip those toasts
     * too. Only with skipErrorToast.
     */
    skipNetworkErrorToast?: boolean;
  }
}

/**
 * What to tell the user about a 429: the API's message ("Too many requests from
 * your address. Try again in 12 minutes."), or a wait worked out from the
 * Retry-After header (seconds).
 */
function rateLimitMessage(error: AxiosError): string {
  const message = (error.response?.data as { message?: unknown } | undefined)?.message;
  if (typeof message === 'string' && message.trim()) return message;
  const seconds = Number(error.response?.headers?.['retry-after']);
  if (!Number.isFinite(seconds) || seconds <= 0) return 'Too many requests. Please try again later.';
  if (seconds < 60) return `Too many requests — try again in ${Math.ceil(seconds)} s.`;
  const minutes = Math.ceil(seconds / 60);
  return `Too many requests — try again in ${minutes} minute${minutes === 1 ? '' : 's'}.`;
}

// Response interceptor
apiClient.interceptors.response.use(
  (response) => response,
  (error: AxiosError) => {
    // The account must choose a new password first (backend middleware/auth.ts):
    // every route but /auth/me, /auth/me/password and /auth/logout answers this.
    // Checked before skipErrorToast, so calls that show their own errors still
    // land on the change screen, and with no toast: the screen says why. The
    // call never settles, so the caller's own catch ("Failed to fetch ...")
    // doesn't toast over the change screen either: the page that made it is
    // being replaced, and the change screen's own calls never get this answer.
    // What waited on it (a store's loading flag) is dropped with the page:
    // the next sign-in in this tab loads the page afresh (stores/auth.ts,
    // callsLeftPending).
    const refusal = error.response?.data as { code?: unknown; reason?: unknown } | undefined;
    if (error.response?.status === 403 && refusal?.code === 'PASSWORD_CHANGE_REQUIRED') {
      useAuthStore().requirePasswordChange(typeof refusal.reason === 'string' ? refusal.reason : null);
      return new Promise<never>(() => undefined);
    }
    if (error.response && error.response.status !== 401 && error.config?.skipErrorToast) {
      return Promise.reject(error);
    }
    if (!error.response && error.config?.skipErrorToast && error.config.skipNetworkErrorToast) {
      return Promise.reject(error);
    }
    const authStore = useAuthStore();

    if (error.response) {
      switch (error.response.status) {
        case 401:
          // The login endpoint's 401s (wrong password / MFA required) are not
          // session expiries — let the Login view handle them inline.
          if (!/\/auth\/login$/.test(error.config?.url || '')) {
            // Keep the page as the target: after signing in, the user is back
            // on it (a Context Graph link included), not on the Dashboard.
            authStore.logout({ keepTarget: true });
            ElMessage.error('Session expired. Please login again.');
          }
          break;
        case 403:
          ElMessage.error('You do not have permission to perform this action.');
          break;
        case 404:
          ElMessage.error('Resource not found.');
          break;
        case 429:
          // Rate limited. One toast however many requests got the 429 (the UI
          // polls), with the server's own message when it sent one.
          ElMessage({ type: 'error', message: rateLimitMessage(error), grouping: true });
          break;
        case 500:
          ElMessage.error('Server error. Please try again later.');
          break;
        default:
          ElMessage.error('An error occurred. Please try again.');
      }
    } else if (error.code === 'ECONNABORTED' || /timeout/i.test(error.message || '')) {
      // Axios aborts on the client when a request exceeds its timeout; there is
      // no response, so this is distinct from a real connectivity failure. Say so
      // — otherwise a slow endpoint reads as "check your connection".
      ElMessage.error('Request timed out — the server took too long to respond.');
    } else if (error.request) {
      ElMessage.error('Network error. Please check your connection.');
    }

    return Promise.reject(error);
  }
);

export default apiClient;

/** For calls whose caller shows every failure inline, including no answer at all. */
const SHOWN_INLINE = { skipErrorToast: true, skipNetworkErrorToast: true } as const;

/** For calls whose caller shows the API's error answers inline (no answer at all still toasts). */
const INLINE = { skipErrorToast: true } as const;

/** A save that waits for the regex safety check: inline errors, and time for a first analysis. */
const REGEX_GATE = { skipErrorToast: true, timeout: 120000 } as const;
/**
 * How long the browser waits for an AI answer (analyst chat, explain, the
 * builders). The longest server-side run is the AI Analyst at its maximum
 * 240 s time budget plus its 120 s answer call (backend aiBudgets.ts), and the
 * builders' 360 s deadline; nginx allows 420 s (frontend/nginx.conf.template).
 */
const AI_CALL_TIMEOUT_MS = 415_000;

/** Context Graph calls: every failure shown inline, 8 s at most. */
const GRAPH_CALL = { ...SHOWN_INLINE, timeout: 8000 } as const;

/** Big Display boards poll and show a lost connection on the board itself: nothing toasts (a 401 still signs out). */
const BOARD_CALL = { ...SHOWN_INLINE, timeout: 20000 } as const;

export interface GraphNeighborhoodParams {
  entity: string;
  window?: string;
  around?: string;
  limit?: number;
  /** Origins to run, comma-separated in the request. */
  include?: string[];
  vuln_status?: 'open' | 'all';
}

export interface GraphRelationParams extends Omit<GraphNeighborhoodParams, 'include'> {
  rel: string;
  offset?: number;
  q?: string;
  sort?: 'count' | 'last_seen' | 'first_seen';
  order?: 'asc' | 'desc';
}

/** The query of a graph call: `include` as CSV, nothing empty. */
function graphParams(params: GraphNeighborhoodParams | GraphRelationParams): Record<string, string | number> {
  const out: Record<string, string | number> = {};
  for (const [name, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue;
    if (Array.isArray(value)) {
      if (value.length > 0) out[name] = value.join(',');
    } else {
      out[name] = value as string | number;
    }
  }
  return out;
}

// API service methods
export const api = {
  // Auth. The Login view shows every failure itself (wrong password, MFA step,
  // disabled account, a sign-in pause, no answer), so the generic toasts are skipped.
  // browserToken is this browser's token for the username, if it signed in
  // before (stores/auth.ts): it lets the browser sign in while the account or
  // network is paused.
  login: (username: string, password: string, code?: string, browserToken?: string) =>
    apiClient.post(
      '/auth/login',
      { username, password, ...(code ? { code } : {}), ...(browserToken ? { browserToken } : {}) },
      SHOWN_INLINE
    ),
  // Best effort (stores/auth.ts signOut): the caller signs out locally whatever happens.
  logout: () => apiClient.post('/auth/logout', undefined, SHOWN_INLINE),
  getProfile: (config?: AxiosRequestConfig) => apiClient.get('/auth/me', config),
  // A wrong current password is a 400 (429 once paused); the caller shows it,
  // and "unavailable" when no answer came.
  changeOwnPassword: (currentPassword: string, newPassword: string) =>
    apiClient.put('/auth/me/password', { currentPassword, newPassword }, SHOWN_INLINE),
  // MFA (TOTP) — the logged-in user manages their own
  mfaSetup: () => apiClient.post('/auth/me/mfa/setup'),
  mfaEnable: (code: string) => apiClient.post('/auth/me/mfa/enable', { code }, SHOWN_INLINE),
  mfaDisable: (code: string) => apiClient.post('/auth/me/mfa/disable', { code }, SHOWN_INLINE),

  // Logs
  getRawLogs: (params?: any) => apiClient.get('/logs/raw', { params }),
  getParsedLogs: (params?: any) => apiClient.get('/logs/parsed', { params }),
  getParseCoverage: () => apiClient.get('/logs/parse-coverage'),

  // Parsers. Every call that saves or runs a regex shows its failures inline
  // (a refused ReDoS-vulnerable regex, a test run that timed out, an oversized
  // sample), so the generic toast is skipped for those (INLINE). Saves wait for
  // the regex safety check (up to a few seconds per new regex), hence REGEX_GATE.
  getParsers: () => apiClient.get('/parsers'),
  getParserMatchStats: () => apiClient.get('/parsers/match-stats'),
  getParserRecommendations: (refresh = false) =>
    apiClient.get('/parsers/recommendations', { params: refresh ? { refresh: 'true' } : {}, timeout: 60000 }),
  getParser: (id: number) => apiClient.get(`/parsers/${id}`),
  createParser: (data: any) => apiClient.post('/parsers', data, REGEX_GATE),
  updateParser: (id: number, data: any) => apiClient.put(`/parsers/${id}`, data, REGEX_GATE),
  deleteParser: (id: number) => apiClient.delete(`/parsers/${id}`),
  testParser: (id: number, sample: string) => apiClient.post(`/parsers/${id}/test`, { sample }, INLINE),
  testParserConfig: (parser_type: string, pattern: string, field_mappings: any, sample: string) =>
    apiClient.post('/parsers/test', { parser_type, pattern, field_mappings, sample }, INLINE),
  // Portable parser export/import (shareable .parser.json; same format the catalog uses)
  exportParser: (id: number) => apiClient.get(`/parsers/${id}/export`, { responseType: 'blob' }),
  // Prepare a community-catalog contribution (validate + self-test + propose-file URL)
  getParserContribution: (id: number) => apiClient.get(`/parsers/${id}/contribute`, REGEX_GATE),
  validatePortableParser: (parser: any, strict = false) =>
    apiClient.post('/parsers/validate', { parser, strict }, REGEX_GATE),
  importParser: (parser: any, force = false) => apiClient.post('/parsers/import', { parser, force }, REGEX_GATE),
  // Parser catalog (browse/install from a GitHub repo, in-app)
  getCatalog: (refresh = false) => apiClient.get('/parsers/catalog', { params: refresh ? { refresh: true } : {} }),
  getCatalogSource: () => apiClient.get('/parsers/catalog/source'),
  installCatalogParser: (name: string, force = false) =>
    apiClient.post('/parsers/catalog/install', { name, force }, REGEX_GATE),
  installAllCatalogParsers: (force = false) =>
    apiClient.post('/parsers/catalog/install-all', { force }, { ...INLINE, timeout: 300000 }),

  // Detection Rules (same inline/REGEX_GATE treatment for saves)
  getRules: () => apiClient.get('/rules'),
  getRule: (id: number) => apiClient.get(`/rules/${id}`),
  getRuleContribution: (id: number) => apiClient.get(`/rules/${id}/contribute`, REGEX_GATE),
  createRule: (data: any) => apiClient.post('/rules', data, REGEX_GATE),
  updateRule: (id: number, data: any) => apiClient.put(`/rules/${id}`, data, REGEX_GATE),
  deleteRule: (id: number) => apiClient.delete(`/rules/${id}`),
  // MITRE ATT&CK (docs/reference/API.md "ATT&CK Coverage"). `platforms` is a
  // comma-separated list or 'all'; omitted, the scope inferred from your data.
  getAttackMatrix: (platforms?: string) =>
    apiClient.get('/attack/matrix', { params: platforms ? { platforms } : {}, ...SHOWN_INLINE }),
  getAttackCoverage: (platforms?: string, refresh = false) =>
    apiClient.get('/attack/coverage', {
      params: { ...(platforms ? { platforms } : {}), ...(refresh ? { refresh: 1 } : {}) },
      ...SHOWN_INLINE,
      timeout: 60000,
    }),
  setAttackExclusion: (techniqueId: string, note: string) =>
    apiClient.put(`/attack/exclusions/${encodeURIComponent(techniqueId)}`, { note }, INLINE),
  deleteAttackExclusion: (techniqueId: string) =>
    apiClient.delete(`/attack/exclusions/${encodeURIComponent(techniqueId)}`, INLINE),
  getAttackNavigatorLayer: (platforms?: string) =>
    apiClient.get('/attack/navigator-layer', {
      params: platforms ? { platforms } : {},
      responseType: 'blob',
      ...INLINE,
      timeout: 60000,
    }),
  // Detection catalog (browse/install rules from the GitHub repo, in-app)
  // `inline`: the caller shows a failure itself (the ATT&CK panel's catalog suggestions).
  getRuleCatalog: (refresh = false, inline = false) =>
    apiClient.get('/rules/catalog', { params: refresh ? { refresh: true } : {}, ...(inline ? SHOWN_INLINE : {}) }),
  installCatalogRule: (name: string) => apiClient.post('/rules/catalog/install', { name }, REGEX_GATE),
  getRuleRecommendations: (refresh = false) =>
    apiClient.get('/rules/recommendations', { params: refresh ? { refresh: 'true' } : {}, timeout: 60000 }),
  installAllCatalogRules: () => apiClient.post('/rules/catalog/install-all', {}, { ...INLINE, timeout: 300000 }),
  // Sigma import: convert community Sigma YAML to portable detections (preview, then import)
  previewSigmaImport: (sigma: string) => apiClient.post('/rules/import/sigma/preview', { sigma }, REGEX_GATE),
  importSigma: (sigma: string) => apiClient.post('/rules/import/sigma', { sigma }, { ...INLINE, timeout: 300000 }),

  // SigmaHQ library: browse the cached release with compatibility, add/update rules
  getSigmaLibrary: (params: Record<string, string | number | undefined>) =>
    apiClient.get('/sigma/library', { params, ...INLINE, timeout: 60000 }),
  refreshSigmaLibrary: (force = false) => apiClient.post('/sigma/library/refresh', { force }, { ...INLINE, timeout: 120000 }),
  installSigmaRule: (sigmaId: string) => apiClient.post(`/sigma/library/${encodeURIComponent(sigmaId)}/install`, {}, REGEX_GATE),
  updateSigmaRule: (sigmaId: string) => apiClient.post(`/sigma/library/${encodeURIComponent(sigmaId)}/update`, {}, REGEX_GATE),
  installSigmaBulk: (body: { sigma_ids?: string[]; all_compatible?: boolean }) =>
    apiClient.post('/sigma/library/install-bulk', body, { ...INLINE, timeout: 300000 }),

  // Content Packs (curated per-technology parser + detection bundles)
  getContentPacks: () => apiClient.get('/packs'),
  installContentPack: (id: string) => apiClient.post(`/packs/${id}/install`, {}, { timeout: 300000 }),

  // AI builder
  getAiSettings: () => apiClient.get('/settings/ai'),
  updateAiSettings: (data: any) => apiClient.put('/settings/ai', data),
  // Long timeouts (AI_CALL_TIMEOUT_MS): generation runs an auto-refine loop of
  // up to 3 model calls within a 360 s deadline, and an explain call may take 240 s.
  generateParserAI: (sample: string, hints?: string) =>
    apiClient.post('/parsers/ai/generate', { sample, hints }, { timeout: AI_CALL_TIMEOUT_MS }),
  generateDetectionAI: (description: string, context?: string) =>
    apiClient.post('/rules/ai/generate', { description, context }, { timeout: AI_CALL_TIMEOUT_MS }),
  explainWithAI: (kind: string, data: any, question?: string) =>
    apiClient.post('/ai/explain', { kind, data, question }, { timeout: AI_CALL_TIMEOUT_MS }),

  // AI Security Analyst (conversational, read-only tool loop)
  analystChat: (sessionId: number | null, message: string, context?: any) =>
    apiClient.post(
      '/ai/chat',
      { session_id: sessionId ?? undefined, message, context },
      { timeout: AI_CALL_TIMEOUT_MS }
    ),
  getAnalystHealth: () => apiClient.get('/ai/chat/health'),
  listChatSessions: () => apiClient.get('/ai/chat/sessions'),
  getChatSession: (id: number) => apiClient.get(`/ai/chat/sessions/${id}`),
  renameChatSession: (id: number, title: string) =>
    apiClient.patch(`/ai/chat/sessions/${id}`, { title }),
  deleteChatSession: (id: number) => apiClient.delete(`/ai/chat/sessions/${id}`),
  // Separate analyst-model config (admin)
  getChatAiSettings: () => apiClient.get('/settings/ai-chat'),
  updateChatAiSettings: (data: any) => apiClient.put('/settings/ai-chat', data),

  // Agentic SOC triage (automatic alert analysis)
  getTriageHealth: () => apiClient.get('/ai/triage/health'),
  getAlertTriage: (id: number) => apiClient.get(`/alerts/${id}/triage`),
  rerunAlertTriage: (id: number) => apiClient.post(`/alerts/${id}/triage/rerun`),
  getTriageAiSettings: () => apiClient.get('/settings/ai-triage'),
  updateTriageAiSettings: (data: any) => apiClient.put('/settings/ai-triage', data),
  // AI budgets: output lengths, data lookups and time budgets (admin)
  getAiBudgets: () => apiClient.get('/settings/ai-budgets'),
  updateAiBudgets: (data: any) => apiClient.put('/settings/ai-budgets', data),
  getTriageRiskSummary: () => apiClient.get('/alerts/triage-risk-summary'),

  // Alerts
  getAlerts: (params?: any) => apiClient.get('/alerts', { params }),
  exportAlerts: (params: any, format: 'csv' | 'json') =>
    apiClient.get('/alerts/export', { params: { ...params, format }, responseType: 'blob' }),
  getAlertStatistics: () => apiClient.get('/alerts/statistics'),
  getAlertsByCountry: (params?: { days?: number; limit?: number }) =>
    apiClient.get('/alerts/by-country', { params }),

  // Threat Intel (IP-centric geo / events / alerts)
  getThreatIntelIp: (ip: string) => apiClient.get(`/threat-intel/ip/${encodeURIComponent(ip)}`),
  getThreatIntelCountry: (code: string, days = 30) =>
    apiClient.get(`/threat-intel/country/${encodeURIComponent(code)}`, { params: { days } }),

  // External threat feeds + IP reputation (Phase 4)
  getThreatFeeds: () => apiClient.get('/threat-feeds'),
  getThreatFeedSummary: () => apiClient.get('/threat-feeds/summary'),
  updateThreatFeed: (id: number, data: { enabled?: boolean; refresh_interval_minutes?: number }) =>
    apiClient.put(`/threat-feeds/feeds/${id}`, data),
  refreshThreatFeed: (id: number) => apiClient.post(`/threat-feeds/feeds/${id}/refresh`, {}, { timeout: 60000 }),
  refreshAllThreatFeeds: () => apiClient.post('/threat-feeds/refresh', {}, { timeout: 120000 }),
  saveThreatProvider: (name: string, data: { apiKey?: string | null; enabled?: boolean }) =>
    apiClient.put(`/threat-feeds/providers/${name}`, data),
  lookupThreatIp: (ip: string) => apiClient.get(`/threat-feeds/lookup/${encodeURIComponent(ip)}`),
  /** `handled`: the caller shows its own message for an error response (e.g. a 404 for a deleted alert). */
  getAlert: (id: number, handled = false) =>
    apiClient.get(`/alerts/${id}`, handled ? { skipErrorToast: true } : undefined),
  updateAlert: (id: number, data: any) => apiClient.put(`/alerts/${id}`, data),
  deleteAlert: (id: number) => apiClient.delete(`/alerts/${id}`),

  // Users
  getUsers: () => apiClient.get('/users'),
  getUser: (id: number) => apiClient.get(`/users/${id}`),
  createUser: (data: any) => apiClient.post('/users', data),
  updateUser: (id: number, data: any) => apiClient.put(`/users/${id}`, data),
  deleteUser: (id: number) => apiClient.delete(`/users/${id}`),
  // Clear every sign-in counter and pause of an account.
  unlockUser: (id: number) => apiClient.post(`/users/${id}/unlock`),

  // Settings - Retention
  getRetentionSettings: () => apiClient.get('/settings/retention'),
  updateRetentionSettings: (data: any) => apiClient.put('/settings/retention', data),
  runManualCleanup: (data: any) => apiClient.post('/settings/retention/cleanup', data),
  getCleanupStatus: () => apiClient.get('/settings/retention/cleanup/status'),
  getRetentionStatistics: () => apiClient.get('/settings/retention/stats', { timeout: 30000 }),
  getContextGraphSettings: () => apiClient.get('/settings/context-graph', INLINE),
  updateContextGraphSettings: (logEdges: Record<string, number | boolean>) =>
    apiClient.put('/settings/context-graph', { log_edges: logEdges }, INLINE),

  // Settings - Syslog
  getSyslogSettings: () => apiClient.get('/settings/syslog'),
  updateSyslogSettings: (data: any) => apiClient.put('/settings/syslog', data),
  getSyslogStatus: () => apiClient.get('/settings/syslog/status'),

  // Settings - Public URL (links in notifications; admin only)
  getPublicUrl: () => apiClient.get('/settings/public-url'),
  // The card shows the server's message (a 400 names the problem) itself.
  updatePublicUrl: (publicUrl: string) =>
    apiClient.put('/settings/public-url', { public_url: publicUrl }, { skipErrorToast: true }),

  // Settings - Auto-Discovery
  // Backend exposes a single JSON endpoint ({ enabled, interval_minutes,
  // stale_threshold_days }) — there are no per-key setting routes.
  getAutoDiscoverySettings: () => apiClient.get('/settings/auto-discovery'),
  updateAutoDiscoverySettings: (data: any) => apiClient.put('/settings/auto-discovery', data),

  // Log Shippers
  getShippers: () => apiClient.get('/shippers'),
  getShipper: (id: number) => apiClient.get(`/shippers/${id}`),
  createShipper: (data: any) => apiClient.post('/shippers', data),
  updateShipper: (id: number, data: any) => apiClient.put(`/shippers/${id}`, data),
  deleteShipper: (id: number) => apiClient.delete(`/shippers/${id}`),
  getUnknownSources: () => apiClient.get('/shippers/unknown-sources'),
  getDirectSyslogSources: () => apiClient.get('/shippers/direct-syslog-sources'),

  // Shipper Sources
  getShipperSources: (shipperId: number) => apiClient.get(`/shippers/${shipperId}/sources`),
  createShipperSource: (shipperId: number, data: any) => apiClient.post(`/shippers/${shipperId}/sources`, data),
  updateShipperSource: (sourceId: number, data: any) => apiClient.put(`/shippers/sources/${sourceId}`, data),
  deleteShipperSource: (sourceId: number) => apiClient.delete(`/shippers/sources/${sourceId}`),

  // Shipper Volumes
  getShipperVolumes: (shipperId: number) => apiClient.get(`/shippers/${shipperId}/volumes`),
  createShipperVolume: (shipperId: number, data: any) => apiClient.post(`/shippers/${shipperId}/volumes`, data),
  // The backend route is DELETE /shippers/volumes/:volumeId (no shipper id), like sources.
  deleteShipperVolume: (volumeId: number) => apiClient.delete(`/shippers/volumes/${volumeId}`),

  // Shipper API Key Management
  regenerateShipperKey: (id: number) => apiClient.post(`/shippers/${id}/regenerate-key`),

  // Shipper HTTP Log Push (separate key from the syslog api_key above)
  generateShipperPushKey: (id: number) => apiClient.post(`/shippers/${id}/http-push-key`),
  revokeShipperPushKey: (id: number) => apiClient.delete(`/shippers/${id}/http-push-key`),

  // Shipper Activity Log
  getShipperActivity: (id: number, limit?: number) =>
    apiClient.get(`/shippers/${id}/activity`, { params: { limit } }),

  // Settings - IP Whitelist Management
  getIpWhitelist: () => apiClient.get('/settings/ip-whitelist'),
  addIpWhitelist: (data: any) => apiClient.post('/settings/ip-whitelist', data),
  updateIpWhitelist: (id: number, data: any) =>
    apiClient.put(`/settings/ip-whitelist/${id}`, data),
  deleteIpWhitelist: (id: number) =>
    apiClient.delete(`/settings/ip-whitelist/${id}`),
  checkIpWhitelist: (ip: string) =>
    apiClient.post('/settings/ip-whitelist/check', { ip_address: ip }),

  // Settings - General
  getSettings: () => apiClient.get('/settings'),

  // Assets
  getAssets: (params?: any) => apiClient.get('/assets', { params }),
  getAssetStatistics: () => apiClient.get('/assets/statistics'),
  getScans: (params?: any) => apiClient.get('/assets/scans', { params }),
  getScan: (id: number) => apiClient.get(`/assets/scans/${id}`),
  getActiveScans: () => apiClient.get('/assets/scans/active'),

  // Vulnerabilities
  getVulnerabilities: (params?: any) => apiClient.get('/vulnerabilities', { params }),
  getVulnerabilitySummary: () => apiClient.get('/vulnerabilities/summary'),

  // Container image scanning (Trivy)
  scanContainer: (image_ref: string) =>
    apiClient.post('/containers/scan', { image_ref }, { timeout: 30000 }),
  getContainerScans: (limit = 20) => apiClient.get('/containers/scans', { params: { limit } }),
  getContainerScan: (id: number) => apiClient.get(`/containers/scans/${id}`),
  // Images already present on the Docker host (requires the socket to be mounted).
  getDiscoveredImages: () => apiClient.get('/containers/discovered'),
  // Combined inventory: SIEMBox host images + images reported by each log shipper host
  getContainerInventory: () => apiClient.get('/containers/inventory'),

  // Scheduled Scans
  getScheduledScans: () => apiClient.get('/scheduled-scans'),
  createScheduledScan: (data: any) => apiClient.post('/scheduled-scans', data),
  updateScheduledScan: (id: number, data: any) => apiClient.put(`/scheduled-scans/${id}`, data),
  deleteScheduledScan: (id: number) => apiClient.delete(`/scheduled-scans/${id}`),
  runScheduledScan: (id: number) => apiClient.post(`/scheduled-scans/${id}/run`),

  // Notifications - Channels
  getNotificationChannels: () => apiClient.get('/notifications/channels'),
  createNotificationChannel: (data: any) => apiClient.post('/notifications/channels', data),
  updateNotificationChannel: (id: number, data: any) => apiClient.put(`/notifications/channels/${id}`, data),
  deleteNotificationChannel: (id: number) => apiClient.delete(`/notifications/channels/${id}`),
  testNotificationChannel: (id: number) => apiClient.post(`/notifications/channels/${id}/test`),
  sendTestAlert: () => apiClient.post('/notifications/test-alert'),

  // Notifications - Settings
  getNotificationSettings: () => apiClient.get('/notifications/settings'),
  updateNotificationSettings: (data: any) => apiClient.put('/notifications/settings', data),

  // Admin Dashboard
  getAdminOverview: () => apiClient.get('/admin/overview'),
  searchAdminUsers: (query?: string, limit?: number) =>
    apiClient.get('/admin/users/search', { params: { q: query, limit } }),
  getUserActivity: (userId: number, limit?: number, offset?: number) =>
    apiClient.get(`/admin/users/${userId}/activity`, { params: { limit, offset } }),
  getAdminErrors: (hours?: number, limit?: number, offset?: number) =>
    apiClient.get('/admin/errors', { params: { hours, limit, offset } }),
  getAdminJobs: (status?: string, limit?: number, offset?: number) =>
    apiClient.get('/admin/jobs', { params: { status, limit, offset } }),
  // Settings -> Sign-in protection
  getSignInProtection: () => apiClient.get('/admin/sign-in-protection'),
  clearSignInCounters: (target: { key: string } | { userId: number } | { network: string } | { all: true }) =>
    apiClient.post('/admin/sign-in-protection/clear', target),

  // How the API sees the caller (Settings -> Display links shows the address)
  getClientAddress: () => apiClient.get('/admin/client-address'),

  // Settings -> Display links (admin). The editor shows 400s by their field
  // and 409s at the top, so those calls don't toast.
  listDisplayLinks: (includeRevoked = false) =>
    apiClient.get<{ links: DisplayLinkSummary[]; limit: number }>('/display-links', {
      params: includeRevoked ? { include_revoked: 'true' } : undefined,
    }),
  getDisplayLink: (id: number) => apiClient.get<{ link: DisplayLinkDetail }>(`/display-links/${id}`),
  createDisplayLink: (body: { name: string; config: DisplayConfig; expires_at: string | null; allowed_cidrs: string[] }) =>
    apiClient.post<DisplayLinkSecret>('/display-links', body, { skipErrorToast: true }),
  updateDisplayLink: (
    id: number,
    patch: Partial<{ name: string; config: DisplayConfig; enabled: boolean; expires_at: string | null; allowed_cidrs: string[] }>
  ) => apiClient.put<{ link: DisplayLinkDetail }>(`/display-links/${id}`, patch, { skipErrorToast: true }),
  rotateDisplayLink: (id: number) => apiClient.post<DisplayLinkSecret>(`/display-links/${id}/rotate`),
  revokeDisplayLink: (id: number) => apiClient.delete(`/display-links/${id}`),
  // What an unsaved layout would show (the editor's live preview), and a saved link's board.
  previewDisplayLink: (config: DisplayConfig, signal?: AbortSignal) =>
    apiClient.post<DisplaySnapshot>('/display-links/preview', { config }, { ...BOARD_CALL, signal }),
  getDisplayLinkSnapshot: (id: number) => apiClient.get<DisplaySnapshot>(`/display-links/${id}/snapshot`, BOARD_CALL),
  // Big Display on the user's own session and role. A 401 signs out as anywhere else.
  getBigDisplaySnapshot: () => apiClient.get<DisplaySnapshot>('/big-display/snapshot', BOARD_CALL),

  // SIEMBOX Endpoint agents
  getEndpoints: () => apiClient.get('/edr/agents'),
  getEndpoint: (id: string) => apiClient.get(`/edr/agents/${id}`),
  getEndpointVulnerabilities: (id: string) => apiClient.get(`/edr/agents/${id}/vulnerabilities`),
  getEndpointDetections: (id: string, limit = 100) =>
    apiClient.get(`/edr/agents/${id}/detections`, { params: { limit } }),
  deleteEndpoint: (id: string) => apiClient.delete(`/edr/agents/${id}`),
  getEnrollmentTokens: () => apiClient.get('/edr/tokens'),
  createEnrollmentToken: (data: { label?: string; expires_in_hours?: number }) =>
    apiClient.post('/edr/tokens', data),
  revokeEnrollmentToken: (tokenHash: string) => apiClient.delete(`/edr/tokens/${tokenHash}`),
  getYaraStatus: () => apiClient.get('/edr/yara'),
  refreshYaraForge: () => apiClient.post('/edr/yara/refresh'),
  getAgentUpdateStatus: () => apiClient.get('/edr/agent-updates'),
  checkAgentRelease: () => apiClient.post('/edr/agent-updates/check'),
  setAgentAutoUpdate: (autoUpdate: boolean) =>
    apiClient.put('/edr/agent-updates/settings', { auto_update: autoUpdate }),
  updateEndpoint: (id: string) => apiClient.post(`/edr/agents/${id}/update`),
  cancelEndpointUpdate: (id: string) => apiClient.delete(`/edr/agents/${id}/update`),
  updateOutdatedEndpoints: () => apiClient.post('/edr/agents/update-outdated'),

  // Context Graph (GET only, every role). The graph page shows every failure
  // inline (a busy answer retries once), so nothing toasts; an 8 s timeout and
  // the caller's AbortSignal (Cancel) bound each call. A 401 still means only
  // that the session expired: the handler above signs out and keeps the page
  // as the target to come back to after signing in.
  graphSearch: (q: string, signal?: AbortSignal) =>
    apiClient.get('/graph/search', { params: { q }, ...GRAPH_CALL, signal }),
  graphNeighborhood: (params: GraphNeighborhoodParams, signal?: AbortSignal) =>
    apiClient.get('/graph/neighborhood', { params: graphParams(params), ...GRAPH_CALL, signal }),
  graphRelation: (params: GraphRelationParams, signal?: AbortSignal) =>
    apiClient.get('/graph/relation', { params: graphParams(params), ...GRAPH_CALL, signal }),
  // The logs behind a dashed (seen in logs) edge, for one ingest day.
  graphEvidence: (params: { rel: string; a: string; b: string; day?: string; limit?: number }, signal?: AbortSignal) =>
    apiClient.get('/graph/evidence', { params, ...GRAPH_CALL, signal }),

  // Generic methods
  get: (url: string, config?: any) => apiClient.get(url, config),
  post: (url: string, data?: any) => apiClient.post(url, data),
  put: (url: string, data?: any) => apiClient.put(url, data),
  delete: (url: string) => apiClient.delete(url),
};
