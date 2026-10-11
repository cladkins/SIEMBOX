/**
 * Helpers shared by Settings → Digital Risk and the onboarding checklist.
 *
 * The validators mirror backend/src/services/exposure/validation.ts so obvious
 * mistakes (a URL, a wildcard, an IP) are caught before a request is made. The
 * backend stays the source of truth: anything these accept is still checked
 * there, and its 400 message is always shown as-is.
 */
import { format, formatDistanceToNow } from 'date-fns';
import type { ExposureStatus, IdentityKind } from '@/services/exposureService';

// ---- Validation (mirrors the backend) ----------------------------------------

export type ValidationResult = { ok: true; value: string } | { ok: false; error: string };

const MAX_DOMAIN_LENGTH = 253;
const MAX_EMAIL_LENGTH = 254;
const MAX_LOCAL_PART_LENGTH = 64;
const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
// Alphabetic TLDs, or punycode TLDs (xn--...). All-numeric TLDs are never valid.
const TLD_RE = /^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/;
// RFC 5322 dot-atom: atext runs separated by single dots (no quoted local parts).
const LOCAL_PART_RE = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/;
const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
/** HIBP API keys are 32 hex characters (the backend's HIBP_API_KEY_RE). */
export const HIBP_API_KEY_RE = /^[0-9a-f]{32}$/i;

const fail = (error: string): ValidationResult => ({ ok: false, error });

// Stands in for Node's net.isIP. It only picks the error message: an IPv4
// address fails the TLD check and anything with a colon fails the
// bare-domain check anyway, exactly as on the backend.
function isIpAddress(value: string): boolean {
  if (IPV4_RE.test(value)) return true;
  if (!/^[0-9a-f:.]+$/i.test(value)) return false;
  const groups = value.split(':');
  return value.includes('::') || groups.length === 8 || (groups.length === 7 && IPV4_RE.test(groups[6]));
}

/** A bare, lowercase DNS name with a real TLD: no scheme, port, path, wildcard or IP. */
export function normalizeDomain(input: string): ValidationResult {
  let domain = input.trim().toLowerCase();
  if (!domain) return fail('domain is required');
  if (domain.length > MAX_DOMAIN_LENGTH + 1)
    return fail(`domain must be at most ${MAX_DOMAIN_LENGTH} characters`);
  if (/\s/.test(domain)) return fail('domain must not contain spaces');
  if (/[^\x21-\x7e]/.test(domain)) {
    return fail('enter internationalized domains in their ASCII (punycode, "xn--") form');
  }
  if (domain.endsWith('.')) domain = domain.slice(0, -1); // fully-qualified (root dot) form
  if (isIpAddress(domain) || isIpAddress(domain.replace(/^\[(.*)\]$/, '$1')))
    return fail('IP addresses are not domains');
  if (domain.includes('*'))
    return fail('wildcards are not supported; enter the parent domain (e.g. example.com)');
  if (/[/?#@\\:[\]]/.test(domain)) {
    return fail('enter a bare domain such as example.com, without a scheme, port, path or user');
  }
  if (domain.length > MAX_DOMAIN_LENGTH)
    return fail(`domain must be at most ${MAX_DOMAIN_LENGTH} characters`);

  const labels = domain.split('.');
  if (labels.length < 2) return fail('domain must include a top-level domain (e.g. example.com)');
  for (const label of labels) {
    if (!LABEL_RE.test(label)) {
      return fail(
        'each domain label must be 1-63 letters, digits or hyphens, and must not start or end with a hyphen'
      );
    }
  }
  if (!TLD_RE.test(labels[labels.length - 1])) return fail('domain has an invalid top-level domain');
  return { ok: true, value: domain };
}

/** A single address with a dot-atom local part and a domain that passes normalizeDomain. */
export function normalizeEmail(input: string): ValidationResult {
  const email = input.trim().toLowerCase();
  if (!email) return fail('email is required');
  if (email.length > MAX_EMAIL_LENGTH) return fail(`email must be at most ${MAX_EMAIL_LENGTH} characters`);
  const at = email.indexOf('@');
  if (at <= 0 || at !== email.lastIndexOf('@'))
    return fail('enter a single address such as alice@example.com');

  const local = email.slice(0, at);
  if (local.length > MAX_LOCAL_PART_LENGTH || !LOCAL_PART_RE.test(local)) {
    return fail('the part before "@" is not a valid mailbox name');
  }
  const domain = normalizeDomain(email.slice(at + 1));
  if (!domain.ok) return fail(`email domain: ${domain.error}`);
  return { ok: true, value: `${local}@${domain.value}` };
}

export function normalizeIdentityValue(kind: IdentityKind, input: string): ValidationResult {
  return kind === 'email' ? normalizeEmail(input) : normalizeDomain(input);
}

/** Onboarding takes one field for both kinds: an address has an "@", a domain doesn't. */
export function guessIdentityKind(input: string): IdentityKind {
  return input.includes('@') ? 'email' : 'email_domain';
}

export function normalizeHibpKey(input: string): ValidationResult {
  const key = input.trim();
  if (!key) return fail('Enter an API key');
  if (!HIBP_API_KEY_RE.test(key)) return fail('An HIBP API key is 32 hexadecimal characters');
  return { ok: true, value: key };
}

// ---- API errors -------------------------------------------------------------

/** HTTP status of a failed API call, if there was a response. */
export function apiErrorStatus(error: unknown): number | undefined {
  const status = (error as { response?: { status?: unknown } } | null)?.response?.status;
  return typeof status === 'number' ? status : undefined;
}

/**
 * The backend's own message for a failed call ({ message } from ApiError), or
 * `fallback` when there isn't one (network error, timeout, non-JSON body).
 */
export function apiErrorMessage(error: unknown, fallback: string): string {
  const data = (error as { response?: { data?: unknown } } | null)?.response?.data;
  if (data && typeof data === 'object') {
    const body = data as Record<string, unknown>;
    for (const key of ['message', 'error']) {
      const value = body[key];
      if (typeof value === 'string' && value.trim()) return value;
    }
  }
  return fallback;
}

/** True for the 400 the API returns when the server can't encrypt an API key. */
export function isEncryptionKeyError(error: unknown): boolean {
  return (
    apiErrorStatus(error) === 400 &&
    apiErrorMessage(error, '').includes('CREDENTIAL_ENCRYPTION_KEY')
  );
}

// ---- Display ----------------------------------------------------------------

export const HIBP_HOME_URL = 'https://haveibeenpwned.com';
export const HIBP_API_KEY_URL = 'https://haveibeenpwned.com/API/Key';
export const HIBP_DOMAIN_SEARCH_URL = 'https://haveibeenpwned.com/DomainSearch';
export const CC_BY_4_URL = 'https://creativecommons.org/licenses/by/4.0/';

/** Check intervals offered in the UI (the API accepts any whole minutes, 60-43200). */
export const INTERVAL_OPTIONS: ReadonlyArray<{ value: number; label: string }> = [
  { value: 60, label: 'Hourly' },
  { value: 360, label: 'Every 6 hours' },
  { value: 720, label: 'Every 12 hours' },
  { value: 1440, label: 'Daily' },
  { value: 10080, label: 'Weekly' },
  { value: 43200, label: 'Every 30 days' },
];
export const DEFAULT_INTERVAL_MINUTES = 1440;

export function intervalLabel(minutes: number): string {
  const preset = INTERVAL_OPTIONS.find((o) => o.value === minutes);
  if (preset) return preset.label;
  if (minutes % 1440 === 0) return `Every ${minutes / 1440} days`;
  if (minutes % 60 === 0) return `Every ${minutes / 60} hours`;
  return `Every ${minutes} min`;
}

/** The preset options, plus the current value when it was set to something else via the API. */
export function intervalOptionsFor(current: number): Array<{ value: number; label: string }> {
  const options = [...INTERVAL_OPTIONS];
  if (!options.some((o) => o.value === current)) {
    options.push({ value: current, label: intervalLabel(current) });
    options.sort((a, b) => a.value - b.value);
  }
  return options;
}

/** "Oct 10, 2026 09:15", or `fallback` for a missing/unparseable timestamp. */
export function formatWhen(value: string | null | undefined, fallback = 'Never'): string {
  if (!value) return fallback;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? fallback : format(date, 'MMM dd, yyyy HH:mm');
}

/** "5 minutes ago" / "in 10 minutes", or '' for a missing/unparseable timestamp. */
export function formatRelative(value: string | null | undefined): string {
  if (!value) return '';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '' : formatDistanceToNow(date, { addSuffix: true });
}

export type TagType = 'success' | 'info' | 'warning' | 'danger';

/** Tag for a watched domain's or identity's last check. */
export function checkStatusTag(row: {
  enabled: boolean;
  last_status: string | null;
}): { type: TagType; label: string } {
  if (!row.enabled) return { type: 'info', label: 'Disabled' };
  if (row.last_status === 'ok') return { type: 'success', label: 'OK' };
  if (row.last_status === 'error') return { type: 'danger', label: 'Error' };
  if (!row.last_status) return { type: 'info', label: 'Not checked yet' };
  return { type: 'info', label: row.last_status };
}

export function identityKindLabel(kind: IdentityKind): string {
  return kind === 'email' ? 'Email address' : 'Email domain';
}

export function pluralize(count: number, singular: string, plural = `${singular}s`): string {
  return `${count.toLocaleString()} ${count === 1 ? singular : plural}`;
}

// ---- Status banner ------------------------------------------------------------

export interface StatusBanner {
  type: 'success' | 'info' | 'warning' | 'error';
  title: string;
  detail: string;
}

/** Backend messages may or may not end in a period; make it exactly one. */
function sentence(text: string): string {
  const trimmed = text.trim().replace(/[.\s]+$/, '');
  return trimmed ? `${trimmed}.` : '';
}

/**
 * The one state the feature is in, most urgent first: the server can't store
 * keys → checks switched off → no HIBP key → HIBP disabled → paused (rate
 * limit or rejected key) → last run failed → healthy.
 *
 * `encryptionKeyError` is the 400 message from saving the HIBP key: the API
 * has no read-only way to report a missing CREDENTIAL_ENCRYPTION_KEY, so this
 * state appears once a save has hit it.
 */
export function describeExposureStatus(
  status: ExposureStatus,
  encryptionKeyError: string | null
): StatusBanner {
  const provider = status.providers.find((p) => p.name === 'hibp') ?? null;
  const run = status.leaked_creds;
  const counts = status.counts;

  if (encryptionKeyError) {
    return {
      type: 'error',
      title: 'API keys can’t be stored: CREDENTIAL_ENCRYPTION_KEY is missing or invalid',
      detail: `${sentence(encryptionKeyError)} Add it to the backend's environment, restart the backend, then save the HIBP key again.`,
    };
  }
  if (!status.features.leaked_creds_enabled) {
    return {
      type: 'info',
      title: 'Leaked-credential checks are switched off',
      detail:
        'Monitored identities are not checked against Have I Been Pwned. Turn checks on under Notifications and checks. The password check still works.',
    };
  }
  if (!provider?.configured) {
    return {
      type: 'warning',
      title: 'No Have I Been Pwned API key',
      detail:
        'Breach checks for monitored email addresses and domains need an HIBP API key; add one under Have I Been Pwned below. The password check works without a key.',
    };
  }
  if (!provider.enabled) {
    return {
      type: 'warning',
      title: 'Have I Been Pwned is disabled',
      detail: 'A key is saved, but the provider is switched off, so no breach checks run. Enable it under Have I Been Pwned below.',
    };
  }
  if (run.paused_until) {
    const until = formatWhen(run.paused_until, 'later');
    const rateLimited =
      !!run.last_run?.summary.rateLimitedUntil || /rate limit/i.test(run.pause_reason ?? '');
    return rateLimited
      ? {
          type: 'warning',
          title: `Paused by HIBP's rate limit until ${until}`,
          detail: `${sentence(run.pause_reason ?? 'HIBP asked SIEMBox to back off')} Checks resume on their own.`,
        }
      : {
          type: 'error',
          title: `Paused until ${until}: HIBP rejected the API key`,
          detail: `${sentence(run.pause_reason ?? 'HIBP refused the saved key')} Saving a new key resumes checks straight away.`,
        };
  }
  // `last_run` covers manual and scheduled runs; `job` only scheduled ones, and
  // also catches a run that crashed before writing `last_run`. Trust the newer.
  const lastRunAt = run.last_run ? Date.parse(run.last_run.at) : 0;
  const jobRunAt = run.job?.last_run_at ? Date.parse(run.job.last_run_at) : 0;
  const jobFailedSince = run.job?.status === 'failed' && jobRunAt >= lastRunAt;
  const lastError = jobFailedSince ? run.job?.last_error : run.last_run?.summary.error;
  if (lastError) {
    const rateLimited = !jobFailedSince && !!run.last_run?.summary.rateLimitedUntil;
    return {
      type: rateLimited ? 'warning' : 'error',
      title: rateLimited
        ? "The last check was cut short by HIBP's rate limit"
        : 'The last leaked-credential check did not finish',
      detail: `${sentence(lastError)} Identities that weren't checked stay due and are retried on the next run.`,
    };
  }
  if (counts.identities === 0) {
    return {
      type: 'info',
      title: 'Ready: add an email address or email domain to monitor',
      detail: 'Have I Been Pwned is set up. Add identities under Breach-monitored identities to start checking them.',
    };
  }
  if (counts.identities_enabled === 0) {
    return {
      type: 'info',
      title: 'Every monitored identity is disabled',
      detail: 'Have I Been Pwned is set up, but nothing is checked until an identity is enabled.',
    };
  }

  const parts = [`Monitoring ${pluralize(counts.identities_enabled, 'identity', 'identities')}`];
  if (run.running) parts.push('a check is running now');
  else if (run.last_run) parts.push(`last check ${formatRelative(run.last_run.at)}`);
  else parts.push('waiting for the first check');
  if (run.job?.next_run_at) parts.push(`next ${formatRelative(run.job.next_run_at)}`);
  return { type: 'success', title: 'Healthy', detail: `${parts.join(' · ')}.` };
}
