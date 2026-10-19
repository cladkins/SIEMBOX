/**
 * What GET /api/settings may return from system_settings.
 *
 * system_settings holds plain configuration (retention days, notification
 * toggles, provider and model names) next to stored credentials: the AI
 * builder, AI Analyst and AI Triage API keys, the AbuseIPDB and OTX reputation
 * keys and the Have I Been Pwned key. Each of those is an AES-256-GCM envelope
 * ({ encrypted, iv, authTag }) written by CredentialEncryption. The raw listing
 * never returns them, not even to an admin: the envelope plus the server's
 * CREDENTIAL_ENCRYPTION_KEY (from a backup or a leaked .env) gives the key back,
 * and the settings pages only ever report a key as configured or not.
 *
 * The rule fails closed. A row's value is returned only when all three hold:
 * 1. Its key is on READABLE_SETTING_KEYS, the reviewed list of plain settings.
 *    A key that is not on the list (a new setting nobody has classified yet)
 *    is withheld until it is added there.
 * 2. Its key is not named like a credential: no word of it (split on anything
 *    but letters and digits, and at camelCase humps) is in SECRET_KEY_WORDS.
 *    That covers *_key, *_api_key, *_token, *_secret, *_password and *_hash.
 * 3. Its value does not hold a credential envelope, whatever the key is called.
 * Every other row comes back with the value withheld (see settingRowForAdmin).
 */

/** Stands in for a withheld value that is set. A withheld value that is not set reads as ''. */
export const REDACTED_VALUE = '[redacted]';

/** One row of GET /api/settings. */
export interface SettingRow {
  setting_key: string;
  /** The stored value; for a redacted row, REDACTED_VALUE when one is stored and '' when not. */
  setting_value: string;
  /** True when the value is withheld. */
  redacted: boolean;
  /** Redacted rows only: whether a value is stored. */
  configured?: boolean;
}

/**
 * Words that mark a setting key as a credential. Matched against whole words
 * of the key, so `ai_api_key` and `smtpPassword` match and `exposure_leaked_creds_enabled`
 * (the leaked-credential feature's on/off switch) does not.
 */
export const SECRET_KEY_WORDS: ReadonlySet<string> = new Set([
  'key',
  'keys',
  'apikey',
  'apikeys',
  'token',
  'tokens',
  'secret',
  'secrets',
  'password',
  'passwords',
  'passwd',
  'pwd',
  'passphrase',
  'hash',
  'hashes',
  'credential',
  'credentials',
]);

/**
 * The settings whose values GET /api/settings returns: every non-secret key the
 * backend and its migrations write, as of this list. Adding a setting does not
 * require an entry here (it is withheld until there is one), but a key named
 * like a credential, or holding one, is withheld even if listed.
 */
export const READABLE_SETTING_KEYS: ReadonlySet<string> = new Set([
  // Asset discovery (migration 001, PUT /api/settings/auto-discovery)
  'auto_discovery_enabled',
  'auto_discovery_interval_minutes',
  'stale_asset_threshold_days',
  // Data retention (migration 004, PUT /api/settings/retention)
  'retention_raw_logs_days',
  'retention_parsed_logs_days',
  'retention_alerts_days',
  'retention_auto_cleanup_enabled',
  // Syslog receiver (PUT /api/settings/syslog)
  'syslog_host',
  'syslog_port',
  // Notification preferences (migration 006, PUT /api/notifications/settings)
  'notify_alerts_enabled',
  'notify_alerts_min_severity',
  'notify_vuln_enabled',
  'notify_vuln_min_severity',
  'notify_ingestion_enabled',
  'notify_ingestion_stall_minutes',
  // AI builder, AI Analyst and AI Triage (services/ai/aiService.ts). Not the *_api_key rows.
  'ai_provider',
  'ai_model',
  'ai_base_url',
  'ai_chat_provider',
  'ai_chat_model',
  'ai_chat_base_url',
  'ai_triage_provider',
  'ai_triage_model',
  'ai_triage_base_url',
  'ai_triage_enabled',
  'ai_triage_min_severity',
  'ai_triage_daily_cap',
  'ai_triage_max_concurrent',
  'ai_triage_dedupe_hours',
  'ai_triage_max_tool_calls',
  'ai_triage_wall_budget_seconds',
  // Reputation providers (services/threatintel/reputationService.ts). Not the ti_*_key rows.
  'ti_abuseipdb_enabled',
  'ti_otx_enabled',
  // Digital Risk (migrations 034 and 035, services/exposure/settings.ts). Not exposure_hibp_key.
  'notify_exposure_enabled',
  'notify_exposure_min_severity',
  'exposure_leaked_creds_enabled',
  'exposure_hibp_enabled',
  'exposure_domain_monitor_enabled',
  'exposure_domain_expiry_warning_days',
  'exposure_lookalike_max_candidates',
  'exposure_dns_secondary_resolver',
  // The HIBP key's verified domains: a JSON snapshot bound to the stored key by
  // a hash of its envelope, never the key (services/exposure/hibpDomains.ts).
  'exposure_hibp_domains',
  // Getting Started completion: {at, by} or '' (services/onboarding/onboardingState.ts)
  'onboarding_completed',
  // Log Discovery scan scope (services/logDiscovery/discoveryScanService.ts)
  'log_discovery_manual_cidrs',
  // Endpoint agent self-update (migration 044, services/edr/agentUpdateService.ts)
  'edr_agent_auto_update',
  'edr_agent_latest_version',
  'edr_agent_latest_checked_at',
  'edr_agent_latest_error',
]);

/**
 * A field of a CredentialEncryption envelope, as JSON: `"encrypted":`, `"iv":`
 * or `"authTag":`, also nested or JSON-encoded a second time (`\"iv\":`).
 * A raw-text match, so a truncated or otherwise unparsable envelope counts too.
 */
const ENVELOPE_FIELD = /\\*"(?:encrypted|iv|authTag)\\*"\s*:/i;

/** The words of a setting key: `ai_api_key` -> ai, api, key; `hibpAPIKey` -> hibp, api, key. */
function keyWords(key: string): string[] {
  return key
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/([A-Z])([A-Z][a-z])/g, '$1_$2')
    .toLowerCase()
    .split(/[^a-z0-9]+/);
}

/** Whether `key` is named like a credential (see SECRET_KEY_WORDS). */
export function isSecretSettingKey(key: string): boolean {
  return keyWords(key).some((word) => SECRET_KEY_WORDS.has(word));
}

/** Whether a stored value holds a CredentialEncryption envelope ({ encrypted, iv, authTag }). */
export function holdsCredentialEnvelope(value: string): boolean {
  return ENVELOPE_FIELD.test(value);
}

/** Whether GET /api/settings may return this row's value (rules 1-3 above). */
export function isReadableSetting(key: string, value: string): boolean {
  return READABLE_SETTING_KEYS.has(key) && !isSecretSettingKey(key) && !holdsCredentialEnvelope(value);
}

/**
 * A system_settings row as GET /api/settings returns it: the value when it is
 * readable, otherwise REDACTED_VALUE (or '' when nothing is stored) with
 * `redacted: true` and `configured` saying whether a value is stored.
 */
export function settingRowForAdmin(key: string, value: string | null | undefined): SettingRow {
  const stored = value ?? '';
  if (isReadableSetting(key, stored)) {
    return { setting_key: key, setting_value: stored, redacted: false };
  }
  const configured = stored !== '';
  return {
    setting_key: key,
    setting_value: configured ? REDACTED_VALUE : '',
    redacted: true,
    configured,
  };
}
