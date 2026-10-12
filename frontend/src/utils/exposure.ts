/**
 * Helpers shared by Settings → Digital Risk and the onboarding checklist.
 *
 * The validators mirror backend/src/services/exposure/validation.ts so obvious
 * mistakes (a URL, a wildcard, an IP) are caught before a request is made. The
 * backend stays the source of truth: anything these accept is still checked
 * there, and its 400 message is always shown as-is.
 */
import { format, formatDistanceToNow } from 'date-fns';
import type {
  DomainCollectorName,
  DomainScope,
  ExposureFinding,
  ExposureStatus,
  IdentityKind,
  WatchedDomain,
} from '@/services/exposureService';

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

/**
 * Onboarding takes one field for both kinds: an address has an "@", a domain
 * doesn't, and "@example.com" is read as the email domain example.com.
 */
export function parseIdentityInput(input: string): { kind: IdentityKind; checked: ValidationResult } {
  const value = input.trim();
  if (/^@[^@]*$/.test(value)) return { kind: 'email_domain', checked: normalizeDomain(value.slice(1)) };
  const kind: IdentityKind = value.includes('@') ? 'email' : 'email_domain';
  return { kind, checked: normalizeIdentityValue(kind, value) };
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

/** A timestamp in ms, reading one without an offset as UTC (as the backend reads crt.sh's); NaN if unparseable. */
function utcMillis(value: unknown): number {
  if (typeof value !== 'string' || !value) return NaN;
  return Date.parse(/T[\d:.]+$/.test(value) ? `${value}Z` : value);
}

/**
 * "Oct 23, 2026": the UTC calendar date, as registries and CT logs give it and
 * the backend's finding titles print it; '' for a missing/unparseable date.
 */
export function formatDay(value: unknown): string {
  const ms = utcMillis(value);
  if (Number.isNaN(ms)) return '';
  const date = new Date(ms);
  // date-fns formats in local time, so hand it the UTC date as a local one.
  return format(new Date(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()), 'MMM dd, yyyy');
}

/**
 * When a watched domain is checked next: "Due now" when it was never
 * scheduled (a new domain: the job takes it on its next tick) or that time has
 * passed, '' for an unparseable time.
 */
export function nextCheckLabel(nextRunAt: string | null | undefined, now = Date.now()): string {
  if (!nextRunAt) return 'Due now';
  const at = Date.parse(nextRunAt);
  if (Number.isNaN(at)) return '';
  return at <= now ? 'Due now' : `Next ${formatRelative(nextRunAt)}`;
}

export type TagType = 'success' | 'info' | 'warning' | 'danger';

/** Tag for an identity's last check (a watched domain's adds its per-check state: domainStatusTag). */
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

/**
 * Whether watched domains are checked: 'unavailable' on a backend without the
 * domain collectors, 'off' while exposure_domain_monitor_enabled is false.
 * Before the status has loaded (or when it failed to) nothing is known, and
 * that counts as 'on' so no "not checked" note flashes up meanwhile.
 */
export type DomainMonitorState = 'on' | 'off' | 'unavailable';

export function domainMonitorState(status: ExposureStatus | null): DomainMonitorState {
  if (!status) return 'on';
  if (!status.features.domain_monitor_available) return 'unavailable';
  return status.features.domain_monitor_enabled === false ? 'off' : 'on';
}

/** Toast after adding a domain: it is only saved while domain monitoring is unavailable or off. */
export function domainAddedMessage(domain: string, state: DomainMonitorState): string {
  if (state === 'unavailable') return `Saved ${domain}; it will be watched once domain monitoring ships`;
  if (state === 'off') return `Saved ${domain}; it isn't checked while domain monitoring is switched off`;
  return `Now watching ${domain}`;
}

/**
 * Whether breach checks can run at all: switched on, and an HIBP key saved,
 * enabled and usable. A pause (rate limit, rejected key) passes on its own.
 */
export function breachChecksReady(status: ExposureStatus): boolean {
  const hibp = status.providers.find((p) => p.name === 'hibp');
  return status.features.leaked_creds_enabled && !!hibp?.configured && hibp.enabled && hibp.usable !== false;
}

/** Toast after adding an identity; `status` null (not loaded) is taken as ready. */
export function identityAddedMessage(value: string, status: ExposureStatus | null): string {
  if (!status || breachChecksReady(status)) return `Now monitoring ${value} for breaches`;
  if (!status.features.leaked_creds_enabled) {
    return `Saved ${value}; it will be checked once leaked-credential checks are switched on`;
  }
  return `Saved ${value}; it will be checked once a usable HIBP API key is saved and enabled`;
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

export interface ExposureStatusContext {
  /**
   * The 400 message from saving the HIBP key: the API has no read-only way to
   * report a missing CREDENTIAL_ENCRYPTION_KEY, so that state appears once a
   * save has hit it.
   */
  encryptionKeyError?: string | null;
  /**
   * Enabled identities whose last check failed (last_status 'error' in GET
   * /identities). Omit it when the list isn't loaded; the last run's `failed`
   * count stands in for it.
   */
  failingIdentities?: number | null;
}

/**
 * The state of the leaked-credential (breach) checks, most urgent first: the
 * server can't store keys → checks switched off → no HIBP key → saved key
 * unusable → HIBP disabled → paused (rate limit or rejected key) → last run
 * failed → nothing to check → identities failing → healthy. Domain monitoring
 * reports per domain, in the domain cards.
 */
export function describeExposureStatus(status: ExposureStatus, context: ExposureStatusContext = {}): StatusBanner {
  const provider = status.providers.find((p) => p.name === 'hibp') ?? null;
  const run = status.leaked_creds;
  const counts = status.counts;
  // Until an identity is monitored nothing needs the key, so setting one up is
  // a next step rather than a problem.
  const keyNeeded = counts.identities_enabled > 0;

  if (context.encryptionKeyError) {
    return {
      type: 'error',
      title: 'API keys can’t be stored: CREDENTIAL_ENCRYPTION_KEY is missing or invalid',
      detail: `${sentence(context.encryptionKeyError)} Add it to the backend's environment, restart the backend, then save the HIBP key again.`,
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
    const keyless = status.features.domain_monitor_available
      ? 'Domain monitoring and the password check work without one.'
      : 'The password check works without one.';
    return {
      type: keyNeeded ? 'warning' : 'info',
      title: 'No Have I Been Pwned API key',
      detail: `Breach checks for email addresses and email domains need an HIBP API key; add one under Have I Been Pwned below. ${keyless}`,
    };
  }
  if (provider.usable === false) {
    return {
      type: 'warning',
      title: 'The saved HIBP key can’t be used',
      detail:
        "The backend can't decrypt the saved key, so no breach checks run. CREDENTIAL_ENCRYPTION_KEY is missing or has " +
        'changed since the key was saved: put the original value back and restart the backend (the other stored ' +
        'credentials need it too), or save the HIBP key again below.',
    };
  }
  if (!provider.enabled) {
    return {
      type: keyNeeded ? 'warning' : 'info',
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

  // Per-identity failures (an unverified email domain, HIBP unreachable for a
  // single check) don't fail the run, so they never reach `error` or the job.
  const failing = Math.min(
    context.failingIdentities ?? run.last_run?.summary.failed ?? 0,
    counts.identities_enabled
  );
  if (failing > 0) {
    const of = pluralize(counts.identities_enabled, 'monitored identity', 'monitored identities');
    return {
      type: 'warning',
      title: `${failing} of ${of} failed ${failing === 1 ? 'its' : 'their'} last check`,
      detail:
        'See the Status column under Breach-monitored identities for the error. An email domain must first be ' +
        'verified in your HIBP domain dashboard; other errors (HIBP unreachable, outbound network access blocked) ' +
        'are retried on the next check.',
    };
  }

  const parts = [`Monitoring ${pluralize(counts.identities_enabled, 'identity', 'identities')}`];
  if (run.running) parts.push('a check is running now');
  else if (run.last_run) parts.push(`last check ${formatRelative(run.last_run.at)}`);
  else parts.push('waiting for the first check');
  if (run.job?.next_run_at) parts.push(`next ${formatRelative(run.job.next_run_at)}`);
  return { type: 'success', title: 'Leaked-credential checks are healthy', detail: `${parts.join(' · ')}.` };
}

// ---- Domain-monitoring finding detail -------------------------------------------

/** One value in a finding's detail; `change` marks a value the change added or removed. */
export interface DetailItem {
  text: string;
  change?: 'added' | 'removed';
}

/** One labelled line of a finding's detail: plain text, a link, inline values or a list. */
export interface DetailLine {
  label: string;
  text?: string;
  /** A link, with `text` as its label. */
  href?: string;
  items?: DetailItem[];
  list?: Array<{ text: string; href?: string }>;
}

const DAY_MS = 86_400_000;
const textOf = (v: unknown): string =>
  typeof v === 'string' ? v : typeof v === 'number' && Number.isFinite(v) ? String(v) : '';
const textsOf = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);
const objectOf = (v: unknown): Record<string, unknown> =>
  v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {};

/** A crt.sh link built from the certificate's numeric id, never from a URL in the detail. */
function crtshHref(id: unknown): string | undefined {
  const n = typeof id === 'number' ? id : typeof id === 'string' && /^\d{1,15}$/.test(id) ? Number(id) : NaN;
  return Number.isSafeInteger(n) && n > 0 ? `https://crt.sh/?id=${n}` : undefined;
}

function marked(values: string[], changed: string[], change: 'added' | 'removed'): DetailItem[] {
  const set = new Set(changed);
  return values.map((text) => (set.has(text) ? { text, change } : { text }));
}

/** Before and after, marking what the change removed and added. */
function beforeAfter(d: Record<string, unknown>): DetailLine[] {
  return [
    { label: 'Before', items: marked(textsOf(d.before), textsOf(d.removed), 'removed') },
    { label: 'After', items: marked(textsOf(d.after), textsOf(d.added), 'added') },
  ];
}

const DNS_RECORD_LABELS: Record<string, string> = {
  NS: 'Nameservers (NS)',
  MX: 'Mail servers (MX)',
  TXT: 'TXT records',
  DMARC: 'DMARC policy',
  A: 'IPv4 addresses (A)',
  AAAA: 'IPv6 addresses (AAAA)',
};

const RDAP_FIELD_LABELS: Record<string, string> = {
  nameservers: 'Nameservers',
  registrar: 'Registrar',
  status: 'Registry status',
  dnssec: 'DNSSEC',
};

// has_address / has_mx are null when that DNS lookup failed.
const yesNoUnknown = (v: unknown): string => (v === true ? 'yes' : v === false ? 'no' : 'unknown (the lookup failed)');

function certificateEntry(cert: unknown): { text: string; href?: string } {
  const c = objectOf(cert);
  const names = textsOf(c.names);
  const parts = [textOf(c.issuer_org) || textOf(c.issuer) || 'unknown issuer'];
  if (names.length) parts.push(names.slice(0, 3).join(', ') + (names.length > 3 ? ` (+${names.length - 3} more)` : ''));
  const until = formatDay(c.not_after);
  if (until) parts.push(`valid until ${until}`);
  return { text: parts.join(' · '), href: crtshHref(c.crtsh_id) };
}

/**
 * A domain-monitoring finding's detail as labelled lines, keyed on its event
 * type (the shapes the domain collectors write), or null for one this UI
 * doesn't know, which is then shown as raw JSON.
 */
export function domainFindingDetail(
  finding: Pick<ExposureFinding, 'source' | 'event_type' | 'detail'>,
  now = Date.now()
): DetailLine[] | null {
  if (finding.source !== 'domain-monitor') return null;
  const d = objectOf(finding.detail);
  const lines: DetailLine[] = [];
  const add = (label: string, text: string) => {
    if (text) lines.push({ label, text });
  };
  const registrable = textOf(d.registrable);
  if (registrable && registrable !== textOf(d.domain)) add('Registered domain', registrable);

  switch (finding.event_type) {
    case 'dns_drift': {
      const type = textOf(d.record_type);
      const kinds = textsOf(d.txt_kinds).map((k) => k.toUpperCase());
      add('Record', `${DNS_RECORD_LABELS[type] ?? type}${kinds.length ? ` (${kinds.join(', ')})` : ''}`);
      lines.push(...beforeAfter(d));
      add('Resolvers', textOf(d.resolvers));
      return lines;
    }
    case 'rdap_change': {
      const field = textOf(d.field);
      add('Changed', RDAP_FIELD_LABELS[field] ?? field);
      lines.push(...beforeAfter(d));
      return lines;
    }
    case 'expiry_warning': {
      // The stored days_left is from the first sighting (a re-check only moves
      // last_seen), so count from expires_at instead. Only the backend says a
      // registration expired: `expired` marks its separate, high-severity
      // finding, raised while RDAP still reports the passed date. A warning
      // whose date has merely passed stays open after a renewal too (RDAP then
      // reports the new date and nothing new is raised), so it never reads as
      // expired here.
      const day = formatDay(d.expires_at);
      const at = utcMillis(d.expires_at);
      if (d.expired === true) add('Expired', day || 'yes');
      else if (at > now) {
        const left = Math.floor((at - now) / DAY_MS);
        add('Expires', `${day} (${left < 1 ? 'less than a day left' : `${pluralize(left, 'day')} left`})`);
      } else if (!Number.isNaN(at)) {
        add(
          'Expiry date',
          `${day} (that date has passed: if the domain was renewed, resolve this warning; ` +
            'if the registration lapsed, a separate "expired" finding is raised)'
        );
      }
      return lines;
    }
    case 'lookalike_registered': {
      add('Lookalike', textOf(d.lookalike));
      add('Technique', textOf(d.fuzzer));
      if ('has_address' in d) add('Resolves to an address', yesNoUnknown(d.has_address));
      if ('has_mx' in d) add('Mail (MX) record', yesNoUnknown(d.has_mx));
      if (d.change === 'mx_added') add('Change', 'gained a mail (MX) record since the last check');
      return lines;
    }
    case 'new_cert':
    case 'unexpected_ca': {
      add('Lookalike', textOf(d.lookalike));
      const expected = textsOf(d.expected_cas);
      if (expected.length) lines.push({ label: 'Expected CAs', items: expected.map((text) => ({ text })) });
      if (Array.isArray(d.certificates)) {
        // A grouped finding: one entry per certificate (the backend keeps up to 25).
        add('Issuer', textOf(d.issuer_org));
        const shown = d.certificates.length;
        const count = typeof d.certificate_count === 'number' ? d.certificate_count : shown;
        lines.push({
          label: count > shown ? `Certificates (${shown} of ${count} shown)` : 'Certificates',
          list: d.certificates.map(certificateEntry),
        });
        return lines;
      }
      add('Issuer', textOf(d.issuer_org) || textOf(d.issuer));
      const names = textsOf(d.names);
      if (names.length) lines.push({ label: 'Names', items: marked(names, textsOf(d.new_names), 'added') });
      const from = formatDay(d.not_before);
      const until = formatDay(d.not_after);
      if (from || until) add('Valid', `${from || '?'} to ${until || '?'}`);
      if (d.new_issuer === true) add('Issuer history', 'the first certificate from this issuer for this domain');
      const href = crtshHref(d.crtsh_id);
      if (href) lines.push({ label: 'Certificate', text: `crt.sh #${textOf(d.crtsh_id)}`, href });
      return lines;
    }
    default:
      return null;
  }
}

// ---- Watched-domain checks (each collector's outcome on the last run) -----------

// The domain-monitor checks in run order, as the UI names them.
const DOMAIN_CHECKS: ReadonlyArray<{ name: DomainCollectorName; label: string }> = [
  { name: 'dns', label: 'DNS' },
  { name: 'rdap', label: 'Registration (RDAP)' },
  { name: 'lookalike', label: 'Lookalikes' },
  { name: 'ct', label: 'Certificates (CT)' },
];

// The checks each scope runs (the backend's SCOPE_COLLECTORS): a brand name is
// only watched for lookalikes and the certificates issued for them.
const SCOPE_CHECKS: Record<DomainScope, readonly DomainCollectorName[]> = {
  own: ['dns', 'rdap', 'lookalike', 'ct'],
  brand: ['lookalike', 'ct'],
};

/** One check's outcome on a watched domain's last run. */
export interface DomainCheckLine {
  name: DomainCollectorName;
  label: string;
  /**
   * ok / baseline (its first run) = it ran; off = switched off for this
   * domain; unavailable = nothing it can monitor here (e.g. a TLD without
   * RDAP); not_run = it doesn't apply to the domain's scope.
   */
  state: 'ok' | 'baseline' | 'error' | 'off' | 'unavailable' | 'not_run' | 'unknown';
  tag: { type: TagType; label: string };
  text: string;
  /** Partial failures that didn't stop the check, e.g. DNS record types a resolver didn't answer. */
  warnings: string[];
}

type DomainCheckFields = Pick<WatchedDomain, 'scope' | 'last_summary'>;

/**
 * Each check's outcome on the domain's last run (`last_summary.collectors`), in
 * run order; [] before the first run, and on a backend without domain monitoring.
 */
export function domainCheckLines(domain: DomainCheckFields): DomainCheckLine[] {
  const runs = objectOf(objectOf(domain.last_summary).collectors);
  const applies = SCOPE_CHECKS[domain.scope] ?? SCOPE_CHECKS.own;
  const lines: DomainCheckLine[] = [];
  for (const { name, label } of DOMAIN_CHECKS) {
    if (!(name in runs)) continue;
    const run = objectOf(runs[name]);
    const status = textOf(run.status);
    const note = textOf(run.note);
    const warnings = textsOf(run.warnings);
    const push = (state: DomainCheckLine['state'], type: TagType, tag: string, text: string) =>
      lines.push({ name, label, state, tag: { type, label: tag }, text, warnings });
    if (!applies.includes(name) || status === 'not_applicable') {
      // The backend reports a switched-off check as 'disabled' even where it doesn't apply.
      push('not_run', 'info', 'Not run', note || `not run for ${domain.scope === 'brand' ? 'brand' : 'owned'} domains`);
    } else if (status === 'disabled') {
      push('off', 'warning', 'Off', 'switched off for this domain');
    } else if (status === 'unsupported') {
      push('unavailable', 'warning', 'Not available', note);
    } else if (status === 'error') {
      push('error', 'danger', 'Error', textOf(run.error) || note || 'failed');
    } else if (status === 'ok' || status === 'baseline') {
      const tag = warnings.length ? pluralize(warnings.length, 'warning') : status === 'ok' ? 'OK' : 'Baseline';
      push(status, warnings.length ? 'warning' : 'success', tag, note);
    } else {
      push('unknown', 'info', status || 'unknown', note || textOf(run.error));
    }
  }
  return lines;
}

/**
 * A watched domain's status tag: checkStatusTag's, except that a check that
 * passed is only "OK" when every check that applies to the domain ran without
 * warnings. "Warnings": one ran with partial failures (e.g. record types a
 * filtering resolver didn't answer, which then aren't watched for changes).
 * "Partly monitored": one is switched off, or can't monitor the domain.
 */
export function domainStatusTag(
  domain: DomainCheckFields & { enabled: boolean; last_status: string | null }
): { type: TagType; label: string } {
  const tag = checkStatusTag(domain);
  if (!domain.enabled || domain.last_status !== 'ok') return tag;
  const lines = domainCheckLines(domain);
  if (lines.some((l) => l.warnings.length > 0)) return { type: 'warning', label: 'Warnings' };
  if (lines.some((l) => l.state === 'off' || l.state === 'unavailable' || l.state === 'error')) {
    return { type: 'warning', label: 'Partly monitored' };
  }
  return tag;
}

/**
 * The line under a watched domain's status tag: the checks that ran with
 * warnings, are switched off, or can't monitor it ('' when there are none, and
 * for a disabled domain, which isn't checked at all).
 */
export function domainCoverageNote(domain: DomainCheckFields & { enabled: boolean }): string {
  if (!domain.enabled) return '';
  const lines = domainCheckLines(domain);
  const labelsOf = (state: DomainCheckLine['state']) => lines.filter((l) => l.state === state).map((l) => l.label);
  const parts = lines
    .filter((l) => l.warnings.length > 0)
    .map((l) => `${l.label}: ${pluralize(l.warnings.length, 'warning')}`);
  const off = labelsOf('off');
  if (off.length) parts.push(`Switched off: ${off.join(', ')}`);
  const unavailable = labelsOf('unavailable');
  if (unavailable.length) parts.push(`Not available: ${unavailable.join(', ')}`);
  return parts.join(' · ');
}
