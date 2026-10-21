/**
 * Exposure-monitoring settings, stored in system_settings.
 *
 * The helpers are namespaced: they only accept the keys this subsystem owns, so
 * a typo can't read or overwrite an unrelated setting. The HIBP API key is
 * stored encrypted (AES-256-GCM via CredentialEncryption — the same scheme as
 * the threat-intel provider keys in reputationService.ts). Only getHibpApiKey()
 * ever decrypts it; every public view reports configured/enabled booleans and
 * never the key. The optional Cert Spotter API key (the CT collector's fallback
 * source, domainMonitor/certSpotter.ts) is stored and guarded the same way:
 * only getCertSpotterApiKey() decrypts it.
 */
import { isIP } from 'net';
import { query } from '../../config/database';
import { logger } from '../../utils/logger';
import { CredentialEncryption } from '../credentials/credentialEncryption';
import crypto from 'crypto';
import type { ExposureSeverity } from '../../models/Exposure';
import {
  CERTSPOTTER_PROVIDER,
  certSpotterPausedUntil,
  resetCertSpotterRateLimit,
} from './domainMonitor/certSpotter';

/** Every key this subsystem owns, with the value used when the row is missing. */
export const EXPOSURE_SETTING_DEFAULTS = {
  notify_exposure_enabled: 'false',
  notify_exposure_min_severity: 'medium',
  exposure_leaked_creds_enabled: 'true',
  exposure_hibp_enabled: 'false',
  exposure_hibp_key: '',
  // The verified domains on the HIBP key's account, as one JSON snapshot bound
  // to the stored key (see hibpDomains.ts); '' = not listed yet.
  exposure_hibp_domains: '',
  // Domain monitoring (migration 035).
  exposure_domain_monitor_enabled: 'true',
  exposure_domain_expiry_warning_days: '30',
  exposure_lookalike_max_candidates: '300',
  exposure_dns_secondary_resolver: '', // '' = off: only the system resolver is used
  // Optional Cert Spotter API key (encrypted envelope; '' = none: unauthenticated, small limit).
  exposure_certspotter_key: '',
} as const;

/** Bounds for the numeric domain-monitor settings (the route rejects anything outside). */
export const EXPIRY_WARNING_DAYS_RANGE = { min: 1, max: 365 } as const;
export const LOOKALIKE_CANDIDATES_RANGE = { min: 1, max: 1000 } as const;

function intSetting(raw: string, fallback: number, range: { min: number; max: number }): number {
  const n = /^\d{1,7}$/.test(raw.trim()) ? Number(raw.trim()) : NaN;
  return Number.isInteger(n) && n >= range.min && n <= range.max ? n : fallback;
}

/** '' (off) or a bare IPv4/IPv6 address — never a host name, so it can't be steered by DNS. */
export function isValidResolverSetting(value: string): boolean {
  return value === '' || isIP(value) !== 0;
}

export type ExposureSettingKey = keyof typeof EXPOSURE_SETTING_DEFAULTS;

export const EXPOSURE_SEVERITIES: readonly ExposureSeverity[] = [
  'low',
  'medium',
  'high',
  'critical',
];

export function isExposureSeverity(value: unknown): value is ExposureSeverity {
  return typeof value === 'string' && (EXPOSURE_SEVERITIES as readonly string[]).includes(value);
}

function assertKey(key: string): asserts key is ExposureSettingKey {
  if (!Object.prototype.hasOwnProperty.call(EXPOSURE_SETTING_DEFAULTS, key)) {
    throw new Error(`Not an exposure setting: ${key}`);
  }
}

export async function getExposureSetting(key: ExposureSettingKey): Promise<string> {
  assertKey(key);
  const r = await query('SELECT value FROM system_settings WHERE key = $1', [key]);
  return r.rows[0]?.value ?? EXPOSURE_SETTING_DEFAULTS[key];
}

export async function setExposureSetting(key: ExposureSettingKey, value: string): Promise<void> {
  assertKey(key);
  await query(
    `INSERT INTO system_settings (key, value) VALUES ($1, $2)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
    [key, value]
  );
}

// ---- Operator-facing toggles (GET/PUT /api/exposure/settings) -------------

export interface ExposureSettings {
  notify_exposure_enabled: boolean;
  notify_exposure_min_severity: ExposureSeverity;
  exposure_leaked_creds_enabled: boolean;
  exposure_domain_monitor_enabled: boolean;
  exposure_domain_expiry_warning_days: number;
  exposure_lookalike_max_candidates: number;
  exposure_dns_secondary_resolver: string;
}

export async function getExposureSettings(): Promise<ExposureSettings> {
  const [
    notifyEnabled,
    minSeverity,
    leakedCredsEnabled,
    domainMonitorEnabled,
    expiryWarningDays,
    lookalikeMaxCandidates,
    secondaryResolver,
  ] = await Promise.all([
    getExposureSetting('notify_exposure_enabled'),
    getExposureSetting('notify_exposure_min_severity'),
    getExposureSetting('exposure_leaked_creds_enabled'),
    getExposureSetting('exposure_domain_monitor_enabled'),
    getExposureSetting('exposure_domain_expiry_warning_days'),
    getExposureSetting('exposure_lookalike_max_candidates'),
    getExposureSetting('exposure_dns_secondary_resolver'),
  ]);
  const resolver = secondaryResolver.trim();
  return {
    notify_exposure_enabled: notifyEnabled === 'true',
    notify_exposure_min_severity: isExposureSeverity(minSeverity) ? minSeverity : 'medium',
    exposure_leaked_creds_enabled: leakedCredsEnabled === 'true',
    exposure_domain_monitor_enabled: domainMonitorEnabled === 'true',
    exposure_domain_expiry_warning_days: intSetting(
      expiryWarningDays,
      30,
      EXPIRY_WARNING_DAYS_RANGE
    ),
    exposure_lookalike_max_candidates: intSetting(
      lookalikeMaxCandidates,
      300,
      LOOKALIKE_CANDIDATES_RANGE
    ),
    // A hand-edited, invalid value reads as "off" rather than reaching the resolver.
    exposure_dns_secondary_resolver: isValidResolverSetting(resolver) ? resolver : '',
  };
}

export async function updateExposureSettings(
  input: Partial<ExposureSettings>
): Promise<ExposureSettings> {
  if (input.notify_exposure_enabled !== undefined) {
    await setExposureSetting('notify_exposure_enabled', String(input.notify_exposure_enabled));
  }
  if (input.notify_exposure_min_severity !== undefined) {
    await setExposureSetting('notify_exposure_min_severity', input.notify_exposure_min_severity);
  }
  if (input.exposure_leaked_creds_enabled !== undefined) {
    await setExposureSetting(
      'exposure_leaked_creds_enabled',
      String(input.exposure_leaked_creds_enabled)
    );
  }
  if (input.exposure_domain_monitor_enabled !== undefined) {
    await setExposureSetting(
      'exposure_domain_monitor_enabled',
      String(input.exposure_domain_monitor_enabled)
    );
  }
  if (input.exposure_domain_expiry_warning_days !== undefined) {
    await setExposureSetting(
      'exposure_domain_expiry_warning_days',
      String(input.exposure_domain_expiry_warning_days)
    );
  }
  if (input.exposure_lookalike_max_candidates !== undefined) {
    await setExposureSetting(
      'exposure_lookalike_max_candidates',
      String(input.exposure_lookalike_max_candidates)
    );
  }
  if (input.exposure_dns_secondary_resolver !== undefined) {
    await setExposureSetting(
      'exposure_dns_secondary_resolver',
      input.exposure_dns_secondary_resolver
    );
  }
  return getExposureSettings();
}

// ---- Have I Been Pwned provider (bring-your-own-key) ------------------------

export const HIBP_PROVIDER = {
  name: 'hibp',
  label: 'Have I Been Pwned',
  docsUrl: 'https://haveibeenpwned.com/API/v3',
  signupUrl: 'https://haveibeenpwned.com/API/Key',
  attribution: 'https://haveibeenpwned.com',
  /** HIBP's breach data is licensed CC BY 4.0: credit it wherever it is shown. */
  license: 'CC BY 4.0',
  licenseUrl: 'https://creativecommons.org/licenses/by/4.0/',
} as const;

/** HIBP keys are 32 hex characters (https://haveibeenpwned.com/API/v3#Authorisation). */
export const HIBP_API_KEY_RE = /^[0-9a-f]{32}$/i;

export interface ExposureProviderPublic {
  name: string;
  label: string;
  docsUrl: string;
  signupUrl: string;
  attribution: string;
  /** The data's licence, e.g. "CC BY 4.0". */
  license: string;
  licenseUrl: string;
  configured: boolean;
  enabled: boolean;
  /**
   * A key is saved and this backend can decrypt it. `configured` without
   * `usable` means CREDENTIAL_ENCRYPTION_KEY is missing or has changed since
   * the key was saved: breach checks are skipped until it is restored or the
   * key is saved again.
   */
  usable: boolean;
}

/** Public provider view for the UI — never exposes the key itself. */
export async function getHibpProviderPublic(): Promise<ExposureProviderPublic> {
  const [storedKey, enabled] = await Promise.all([
    getExposureSetting('exposure_hibp_key'),
    getExposureSetting('exposure_hibp_enabled'),
  ]);
  return {
    ...HIBP_PROVIDER,
    configured: storedKey !== '',
    enabled: enabled === 'true',
    usable: isStoredHibpKeyUsable(storedKey),
  };
}

// GET /status and GET /providers report `usable` on every page view, and a
// failed decrypt is logged, so each answer is kept while both of its inputs
// stay the same: the stored value and CREDENTIAL_ENCRYPTION_KEY (by hash).
let usableMemo: { stored: string; keyHash: string; usable: boolean } | null = null;

/** Whether `stored` (the exposure_hibp_key setting) decrypts with the current CREDENTIAL_ENCRYPTION_KEY. */
export function isStoredHibpKeyUsable(stored: string): boolean {
  if (!stored) return false;
  const keyHash = crypto
    .createHash('sha256')
    .update(process.env.CREDENTIAL_ENCRYPTION_KEY ?? '')
    .digest('hex');
  if (usableMemo?.stored === stored && usableMemo.keyHash === keyHash) return usableMemo.usable;
  const usable = decryptStoredHibpKey(stored, false) !== undefined;
  usableMemo = { stored, keyHash, usable };
  return usable;
}

/**
 * Save the HIBP key (encrypted; '' or null clears it) and/or the enabled flag.
 * Throws CredentialEncryption's error when CREDENTIAL_ENCRYPTION_KEY is missing
 * or malformed — the route maps that to a 400 telling the operator how to fix it.
 */
export async function saveHibpProvider(input: {
  apiKey?: string | null;
  enabled?: boolean;
}): Promise<void> {
  if (input.apiKey === null || input.apiKey === '') {
    await setExposureSetting('exposure_hibp_key', '');
  } else if (typeof input.apiKey === 'string') {
    const encrypted = CredentialEncryption.encrypt(input.apiKey);
    await setExposureSetting('exposure_hibp_key', JSON.stringify(encrypted));
  }
  if (typeof input.enabled === 'boolean') {
    await setExposureSetting('exposure_hibp_enabled', String(input.enabled));
  }
}

/**
 * Whether `stored` (the exposure_hibp_key setting) holds exactly `apiKey`
 * (null or '': whether it holds no key at all). A value this backend can't
 * decrypt matches no key, so saving over it (or clearing it) is a change.
 */
export function storedHibpKeyMatches(stored: string, apiKey: string | null): boolean {
  if (!apiKey) return stored === '';
  const saved = decryptStoredHibpKey(stored, false);
  if (saved === undefined) return false;
  const a = Buffer.from(saved);
  const b = Buffer.from(apiKey);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/** Whether `apiKey` is the key already saved (see storedHibpKeyMatches). */
export async function isSavedHibpKey(apiKey: string | null): Promise<boolean> {
  return storedHibpKeyMatches(await getExposureSetting('exposure_hibp_key'), apiKey);
}

export async function isHibpEnabled(): Promise<boolean> {
  return (await getExposureSetting('exposure_hibp_enabled')) === 'true';
}

/**
 * The decrypted HIBP key, for the HTTP client only. Never log, return or
 * persist what this returns. Undefined when unset or undecryptable (e.g.
 * CREDENTIAL_ENCRYPTION_KEY changed since the key was saved).
 */
export async function getHibpApiKey(): Promise<string | undefined> {
  return decryptStoredHibpKey(await getExposureSetting('exposure_hibp_key'), true);
}

/** The key in a stored exposure_hibp_key value, or undefined when there is none this backend can decrypt. */
function decryptStoredHibpKey(stored: string, warn: boolean): string | undefined {
  return decryptStoredKey(stored, warn, 'HIBP');
}

/** The key in a stored key envelope, or undefined; `label` names the provider in warnings. */
function decryptStoredKey(stored: string, warn: boolean, label: string): string | undefined {
  if (!stored) return undefined;
  let envelope: { encrypted?: string; iv?: string; authTag?: string };
  try {
    envelope = JSON.parse(stored);
  } catch {
    // Deliberately not logging the parse error: V8 quotes the input in it, and
    // a hand-edited row could hold a plaintext key.
    if (warn) logger.warn(`[Exposure] the stored ${label} API key is not an encrypted value; re-enter it`);
    return undefined;
  }
  try {
    return CredentialEncryption.decrypt(
      envelope.encrypted ?? '',
      envelope.iv ?? '',
      envelope.authTag ?? ''
    );
  } catch (e) {
    // CredentialEncryption's messages are static (no key material).
    if (warn) {
      logger.warn(`[Exposure] the stored ${label} API key could not be decrypted; re-enter it`, {
        error: e instanceof Error ? e.message : String(e),
      });
    }
    return undefined;
  }
}

// ---- Cert Spotter (optional key for the CT fallback source) -----------------------

export interface CertSpotterProviderPublic {
  name: string;
  label: string;
  docsUrl: string;
  signupUrl: string;
  apiKeysUrl: string;
  /** A key is saved. Without one Cert Spotter is still used, within its small unauthenticated limit. */
  configured: boolean;
  /** The saved key decrypts with the current CREDENTIAL_ENCRYPTION_KEY (see ExposureProviderPublic.usable). */
  usable: boolean;
  /** While a 429's Retry-After runs: when Cert Spotter requests resume (ISO), else null. */
  rate_limited_until: string | null;
}

/** Public view for the UI — never exposes the key itself. */
export async function getCertSpotterProviderPublic(): Promise<CertSpotterProviderPublic> {
  const stored = await getExposureSetting('exposure_certspotter_key');
  const paused = certSpotterPausedUntil();
  return {
    ...CERTSPOTTER_PROVIDER,
    configured: stored !== '',
    usable: stored !== '' && decryptStoredKey(stored, false, 'Cert Spotter') !== undefined,
    rate_limited_until: paused === null ? null : new Date(paused).toISOString(),
  };
}

/**
 * Save the Cert Spotter key (encrypted; '' or null clears it). Throws
 * CredentialEncryption's error when CREDENTIAL_ENCRYPTION_KEY is missing or
 * malformed (the route maps it to a 400). A changed key gets a fresh start
 * on the rate limit: Cert Spotter's limit belongs to the credentials.
 */
export async function saveCertSpotterKey(apiKey: string | null): Promise<void> {
  if (apiKey === null || apiKey === '') {
    await setExposureSetting('exposure_certspotter_key', '');
  } else {
    const encrypted = CredentialEncryption.encrypt(apiKey);
    await setExposureSetting('exposure_certspotter_key', JSON.stringify(encrypted));
  }
  resetCertSpotterRateLimit();
}

/**
 * The decrypted Cert Spotter key, for the HTTP client only. Never log, return
 * or persist what this returns. Undefined when unset or undecryptable (then
 * Cert Spotter is used unauthenticated).
 */
export async function getCertSpotterApiKey(): Promise<string | undefined> {
  return decryptStoredKey(await getExposureSetting('exposure_certspotter_key'), true, 'Cert Spotter');
}
