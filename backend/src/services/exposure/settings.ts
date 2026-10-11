/**
 * Exposure-monitoring settings, stored in system_settings.
 *
 * The helpers are namespaced: they only accept the keys this subsystem owns, so
 * a typo can't read or overwrite an unrelated setting. The HIBP API key is
 * stored encrypted (AES-256-GCM via CredentialEncryption — the same scheme as
 * the threat-intel provider keys in reputationService.ts). Only getHibpApiKey()
 * ever decrypts it; every public view reports configured/enabled booleans and
 * never the key.
 */
import { query } from '../../config/database';
import { logger } from '../../utils/logger';
import { CredentialEncryption } from '../credentials/credentialEncryption';
import type { ExposureSeverity } from '../../models/Exposure';

/** Every key this subsystem owns, with the value used when the row is missing. */
export const EXPOSURE_SETTING_DEFAULTS = {
  notify_exposure_enabled: 'false',
  notify_exposure_min_severity: 'medium',
  exposure_leaked_creds_enabled: 'true',
  exposure_hibp_enabled: 'false',
  exposure_hibp_key: '',
} as const;

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
}

export async function getExposureSettings(): Promise<ExposureSettings> {
  const [notifyEnabled, minSeverity, leakedCredsEnabled] = await Promise.all([
    getExposureSetting('notify_exposure_enabled'),
    getExposureSetting('notify_exposure_min_severity'),
    getExposureSetting('exposure_leaked_creds_enabled'),
  ]);
  return {
    notify_exposure_enabled: notifyEnabled === 'true',
    notify_exposure_min_severity: isExposureSeverity(minSeverity) ? minSeverity : 'medium',
    exposure_leaked_creds_enabled: leakedCredsEnabled === 'true',
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
  return getExposureSettings();
}

// ---- Have I Been Pwned provider (bring-your-own-key) ------------------------

export const HIBP_PROVIDER = {
  name: 'hibp',
  label: 'Have I Been Pwned',
  docsUrl: 'https://haveibeenpwned.com/API/v3',
  signupUrl: 'https://haveibeenpwned.com/API/Key',
  attribution: 'https://haveibeenpwned.com',
} as const;

/** HIBP keys are 32 hex characters (https://haveibeenpwned.com/API/v3#Authorisation). */
export const HIBP_API_KEY_RE = /^[0-9a-f]{32}$/i;

export interface ExposureProviderPublic {
  name: string;
  label: string;
  docsUrl: string;
  signupUrl: string;
  attribution: string;
  configured: boolean;
  enabled: boolean;
}

/** Public provider view for the UI — never exposes the key itself. */
export async function getHibpProviderPublic(): Promise<ExposureProviderPublic> {
  const [storedKey, enabled] = await Promise.all([
    getExposureSetting('exposure_hibp_key'),
    getExposureSetting('exposure_hibp_enabled'),
  ]);
  return { ...HIBP_PROVIDER, configured: storedKey !== '', enabled: enabled === 'true' };
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

export async function isHibpEnabled(): Promise<boolean> {
  return (await getExposureSetting('exposure_hibp_enabled')) === 'true';
}

/**
 * The decrypted HIBP key, for the HTTP client only. Never log, return or
 * persist what this returns. Undefined when unset or undecryptable (e.g.
 * CREDENTIAL_ENCRYPTION_KEY changed since the key was saved).
 */
export async function getHibpApiKey(): Promise<string | undefined> {
  const stored = await getExposureSetting('exposure_hibp_key');
  if (!stored) return undefined;
  let envelope: { encrypted?: string; iv?: string; authTag?: string };
  try {
    envelope = JSON.parse(stored);
  } catch {
    // Deliberately not logging the parse error: V8 quotes the input in it, and
    // a hand-edited row could hold a plaintext key.
    logger.warn('[Exposure] the stored HIBP API key is not an encrypted value; re-enter it');
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
    logger.warn('[Exposure] the stored HIBP API key could not be decrypted; re-enter it', {
      error: e instanceof Error ? e.message : String(e),
    });
    return undefined;
  }
}
