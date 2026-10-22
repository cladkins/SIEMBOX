/**
 * SIEMBox's public URL: the address people use to open the web UI in a
 * browser (https://siem.example.com, or https://example.com/siembox behind a
 * sub-path reverse proxy). Notifications use it to link straight to an alert.
 *
 * Where it comes from, first match wins:
 * 1. The `public_url` system setting (Settings -> System, PUT /api/settings/public-url).
 * 2. The SIEMBOX_PUBLIC_URL environment variable.
 * Neither set (or neither valid): no links, notifications carry the ALR-####
 * reference only, as before.
 *
 * Links are only ever built from this validated value plus fixed in-app paths
 * (services/notifications/notificationLinks.ts), never from a request's Host
 * header or anything else a caller sends.
 */
import { query } from '../../config/database';
import { logger } from '../../utils/logger';

export const PUBLIC_URL_SETTING_KEY = 'public_url';
export const PUBLIC_URL_ENV = 'SIEMBOX_PUBLIC_URL';
export const MAX_PUBLIC_URL_LENGTH = 2048;

export type PublicUrlValidation = { ok: true; value: string } | { ok: false; error: string };

// Whitespace and control characters: the URL parser would silently drop some
// (tab, newline) and percent-encode others, so a pasted value with them in it
// is refused rather than quietly changed. One pass over the characters.
function hasUnsafeChar(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code <= 0x20 || code === 0x7f || /\s/.test(value[i])) return true;
  }
  return false;
}
// The raw value must spell out the scheme and both slashes: the URL parser
// accepts `https:example.com` and `https:/example.com` for special schemes.
const ABSOLUTE_HTTP = /^https?:\/\//i;

/**
 * Validate and normalise a public URL. `''` (or only whitespace) is valid and
 * means "not set". Otherwise it must be an absolute http(s) URL with a host and
 * no credentials, query or fragment; an optional path prefix is kept, without
 * its trailing slash. Scheme and host come back lowercased (the WHATWG URL
 * parser does that, and drops a default port).
 */
export function validatePublicUrl(input: unknown): PublicUrlValidation {
  if (input === null || input === undefined) return { ok: true, value: '' };
  if (typeof input !== 'string') return { ok: false, error: 'public_url must be a string' };
  if (input.length > MAX_PUBLIC_URL_LENGTH) {
    return { ok: false, error: `public_url must be at most ${MAX_PUBLIC_URL_LENGTH} characters` };
  }
  const raw = input.trim();
  if (raw === '') return { ok: true, value: '' };
  if (hasUnsafeChar(raw)) return { ok: false, error: 'public_url must not contain spaces or control characters' };
  if (!ABSOLUTE_HTTP.test(raw)) {
    return {
      ok: false,
      error: 'public_url must be an absolute URL starting with http:// or https:// (e.g. https://siem.example.com)',
    };
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, error: 'public_url is not a valid URL' };
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { ok: false, error: 'public_url must use http or https' };
  }
  if (!url.hostname) return { ok: false, error: 'public_url must include a host name' };
  // The authority is what follows `scheme://` up to the first slash (or
  // backslash, which the parser treats as one for http/https). An `@` there is
  // a credential separator even when both halves are empty (`https://@host`).
  const authority = raw.slice(raw.indexOf('//') + 2).split(/[/\\]/, 1)[0];
  if (url.username || url.password || authority.includes('@')) {
    return { ok: false, error: 'public_url must not contain a username or password (user:pass@)' };
  }
  if (url.search || raw.includes('?')) return { ok: false, error: 'public_url must not contain a query string (?...)' };
  if (url.hash || raw.includes('#')) return { ok: false, error: 'public_url must not contain a fragment (#...)' };

  let path = url.pathname;
  while (path.endsWith('/')) path = path.slice(0, -1);
  const value = `${url.protocol}//${url.host}${path}`;
  if (value.length > MAX_PUBLIC_URL_LENGTH) {
    return { ok: false, error: `public_url must be at most ${MAX_PUBLIC_URL_LENGTH} characters` };
  }
  return { ok: true, value };
}

export type PublicUrlSource = 'setting' | 'env' | 'none';

export interface PublicUrlConfig {
  /** The stored setting ('' when not set). */
  public_url: string;
  /** SIEMBOX_PUBLIC_URL as normalised, '' when unset; env_error says why it is ignored when invalid. */
  env_public_url: string;
  env_error?: string;
  /** What notifications use: the setting, else the env var, else '' (no links). */
  effective_public_url: string;
  source: PublicUrlSource;
}

/** The setting row's raw value ('' when absent or unreadable). */
async function readStoredSetting(): Promise<string> {
  try {
    const r = await query(`SELECT value FROM system_settings WHERE key = $1`, [PUBLIC_URL_SETTING_KEY]);
    return typeof r.rows[0]?.value === 'string' ? r.rows[0].value : '';
  } catch (err) {
    logger.warn('[PublicUrl] could not read the public_url setting', {
      error: err instanceof Error ? err.message : String(err),
    });
    return '';
  }
}

/**
 * Resolve the public URL from a stored setting value and an env value: the
 * setting wins when it is set and valid, then the env var. Pure, so the
 * precedence is testable without a database.
 */
export function resolvePublicUrl(stored: string | null | undefined, envValue: string | null | undefined): PublicUrlConfig {
  const setting = validatePublicUrl(stored ?? '');
  const env = validatePublicUrl(envValue ?? '');
  const config: PublicUrlConfig = {
    public_url: setting.ok ? setting.value : '',
    env_public_url: env.ok ? env.value : '',
    effective_public_url: '',
    source: 'none',
  };
  if (!env.ok) config.env_error = `${PUBLIC_URL_ENV} is ignored: ${env.error.replace(/^public_url/, 'it')}`;
  if (config.public_url) {
    config.effective_public_url = config.public_url;
    config.source = 'setting';
  } else if (config.env_public_url) {
    config.effective_public_url = config.env_public_url;
    config.source = 'env';
  }
  return config;
}

/** The full picture for Settings -> System (admin only). */
export async function getPublicUrlConfig(): Promise<PublicUrlConfig> {
  return resolvePublicUrl(await readStoredSetting(), process.env[PUBLIC_URL_ENV]);
}

/** The validated public URL notifications link to, or null when none is set. */
export async function getPublicUrl(): Promise<string | null> {
  const config = await getPublicUrlConfig();
  return config.effective_public_url || null;
}

/** Store a validated value; '' removes the setting (the env var, if any, then applies). */
export async function savePublicUrl(value: string): Promise<void> {
  if (value === '') {
    await query(`DELETE FROM system_settings WHERE key = $1`, [PUBLIC_URL_SETTING_KEY]);
    return;
  }
  await query(
    `INSERT INTO system_settings (key, value) VALUES ($1, $2)
     ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`,
    [PUBLIC_URL_SETTING_KEY, value]
  );
}
