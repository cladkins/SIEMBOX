/**
 * Settings -> System -> Public URL: the shape of /api/settings/public-url and
 * the helpers the card uses. The server validates and normalises every value
 * (backend/src/services/settings/publicUrl.ts) and answers a 400 naming the
 * problem; nothing here decides what is valid. Pure, so publicUrl.test.ts runs
 * it under node --test.
 */
import { alertRefUrl } from './alertRef.ts';

export type PublicUrlSource = 'setting' | 'env' | 'none';

/** GET/PUT /api/settings/public-url. */
export interface PublicUrlConfig {
  public_url: string;
  env_public_url: string;
  env_error?: string;
  effective_public_url: string;
  source: PublicUrlSource;
}

/**
 * "Use this browser's address": the page's origin plus the app's base path
 * (Vite's BASE_URL, '/' unless the UI is built to be served under a sub-path),
 * without a trailing slash.
 */
export function browserPublicUrl(origin: string, baseUrl: string | undefined): string {
  let base = baseUrl && baseUrl.startsWith('/') ? baseUrl : '/';
  while (base.endsWith('/')) base = base.slice(0, -1);
  let o = origin;
  while (o.endsWith('/')) o = o.slice(0, -1);
  return `${o}${base}`;
}

/** The sample alert the preview links to. */
export const PREVIEW_ALERT_ID = 1234;

/**
 * The link a notification for alert ALR-1234 would carry, or '' when no public
 * URL is in effect. Only ever given the server's validated value, never the
 * text being typed, so it can be rendered as a link.
 */
export function previewAlertLink(effectivePublicUrl: string): string {
  return effectivePublicUrl ? alertRefUrl(PREVIEW_ALERT_ID, effectivePublicUrl) : '';
}

/** One line on where the links come from. */
export function publicUrlSourceText(config: PublicUrlConfig): string {
  if (config.source === 'setting') return 'Notifications link to SIEMBox at this address.';
  if (config.source === 'env') return `Not set here: notifications use SIEMBOX_PUBLIC_URL (${config.env_public_url}).`;
  return 'Not set: notifications carry the alert reference (ALR-1234) but no link.';
}
