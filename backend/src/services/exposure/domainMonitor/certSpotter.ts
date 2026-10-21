/**
 * Cert Spotter: SSLMate's Certificate Transparency search API, the CT
 * collector's fallback source when crt.sh can't answer (see ctFallback.ts).
 *
 * Query (https://sslmate.com/help/reference/ct_search_api_v1, Oct 2026):
 *   GET https://api.certspotter.com/v1/issuances?domain=<name>
 *       &include_subdomains=true&expand=dns_names&expand=issuer&expand=cert_der
 *       [&after=<id of the last issuance on the previous page>]
 * It lists the unexpired issuances for the name and its subdomains (a
 * precertificate and its certificate are one issuance), oldest-discovered
 * first, a page at a time; the last page is an empty array. Every page is
 * fetched (at most CERTSPOTTER_MAX_PAGES), so an answer is complete or refused
 * — never the arbitrary subset crt.sh returns past its result limit.
 *
 * Identity: the serial number is read from `cert_der` (the DER encoding) and
 * the issuer from it too, so a certificate gets the same key (ct.ts
 * certificateKey: issuer organisation + serial) as crt.sh gives it, and
 * switching between the two never makes a known certificate look new. A row
 * whose DER can't be read falls back to `certspotter:<tbs_sha256>`.
 *
 * Authentication is optional: without an API key Cert Spotter allows a small
 * number of queries per hour. With one (Settings → Digital Risk), it is sent as
 * `Authorization: Bearer <key>` and nowhere else: never logged, never in an
 * error message (Cert Spotter's own error bodies are not read: they can quote
 * part of the key).
 *
 * Rate limits: requests are paced CERTSPOTTER_MIN_GAP_MS apart process-wide.
 * A 429 is transient. A short Retry-After is waited out once in place; a longer
 * one (or a second 429) pauses every Cert Spotter request until it has passed,
 * process-wide, and the error says when, suggesting an API key when none is set.
 */
import { X509Certificate } from 'crypto';
import {
  CtTooLargeError,
  MAX_CERTS_PER_NAME,
  MAX_NAMES_PER_CERT,
  certificateKey,
  createPacer,
  issuerIdentity,
  normalizeSerial,
  type CertificateSource,
  type CtCertificate,
  type Pacer,
} from './ct';
import { HttpError, httpsGet, type HttpGet } from './http';
import { isValidHostname, isWithinDomain, normalizeName } from './names';
import { CollectorError, errorMessage, isPlainObject, sortedUnique } from './types';

export const CERTSPOTTER_BASE = 'https://api.certspotter.com/v1/issuances';
const CERTSPOTTER_TIMEOUT_MS = 30_000;
/** Per page; pages are small (tens of issuances) even with the DER expanded. */
export const CERTSPOTTER_MAX_BYTES = 8 * 1024 * 1024;
/** Pages fetched for one name before it is refused as too large to monitor. */
export const CERTSPOTTER_MAX_PAGES = 60;
export const CERTSPOTTER_MIN_GAP_MS = 1_000;
/** A Retry-After up to this long is waited out in place (once per page). */
export const CERTSPOTTER_SHORT_WAIT_SECONDS = 10;
/** Used when a 429 has no usable Retry-After. */
export const CERTSPOTTER_DEFAULT_RETRY_AFTER_SECONDS = 30 * 60;
const MAX_RETRY_AFTER_SECONDS = 24 * 3600;
/** A (pre)certificate's DER, base64: real ones are a few KB. */
const MAX_DER_BASE64_LENGTH = 96 * 1024;
const MAX_DNS_NAMES_READ = 2_000;

/**
 * Cert Spotter API keys look like "123_abcdef…" (an id, "_", a secret). Only
 * token68 characters are accepted (RFC 7235), so the value can't break the
 * Authorization header.
 */
export const CERTSPOTTER_API_KEY_RE = /^[A-Za-z0-9._~+/-]{8,256}$/;

export const CERTSPOTTER_PROVIDER = {
  name: 'certspotter',
  label: 'Cert Spotter (SSLMate)',
  docsUrl: 'https://sslmate.com/help/reference/ct_search_api_v1',
  signupUrl: 'https://sslmate.com/signup?for=ct_search_api',
  apiKeysUrl: 'https://sslmate.com/account/api_keys',
} as const;

export type CertSpotterErrorKind = 'rate_limited' | 'auth' | 'refused' | 'too_large' | 'transient';

/** A Cert Spotter failure; `kind` lets the fallback tell the operator what to do. */
export class CertSpotterError extends CollectorError {
  readonly kind: CertSpotterErrorKind;
  /** rate_limited: when requests may resume (epoch ms). */
  readonly retryAtMs?: number;

  constructor(kind: CertSpotterErrorKind, message: string, retryAtMs?: number) {
    super(message, kind === 'rate_limited' || kind === 'transient');
    this.name = 'CertSpotterError';
    this.kind = kind;
    if (retryAtMs !== undefined) this.retryAtMs = retryAtMs;
  }
}

// ---- Rate-limit state (process-wide) ---------------------------------------------

/** Until when (epoch ms) every Cert Spotter request is held back after a 429; 0 = not paused. */
let pausedUntilMs = 0;

export function certSpotterPausedUntil(nowMs = Date.now()): number | null {
  return pausedUntilMs > nowMs ? pausedUntilMs : null;
}

/**
 * Forget a 429's pause. The limit belongs to the credentials (the key, or the
 * address when there is none), so a new or removed key starts afresh.
 */
export function resetCertSpotterRateLimit(): void {
  pausedUntilMs = 0;
}

/** Retry-After as seconds (an HTTP-date is accepted too), bounded; the default when unusable. */
export function parseRetryAfterSeconds(value: unknown, nowMs = Date.now()): number {
  const raw = Array.isArray(value) ? value[0] : value;
  if (typeof raw === 'string') {
    const trimmed = raw.trim();
    let seconds = NaN;
    if (/^\d{1,9}$/.test(trimmed)) seconds = Number(trimmed);
    else {
      const at = Date.parse(trimmed);
      if (!Number.isNaN(at)) seconds = Math.ceil((at - nowMs) / 1000);
    }
    if (Number.isFinite(seconds)) return Math.min(Math.max(seconds, 1), MAX_RETRY_AFTER_SECONDS);
  }
  return CERTSPOTTER_DEFAULT_RETRY_AFTER_SECONDS;
}

function rateLimitedError(untilMs: number, hasKey: boolean): CertSpotterError {
  const advice = hasKey
    ? "this API key's limit"
    : 'the small limit without an API key: add one in Settings → Digital Risk';
  return new CertSpotterError(
    'rate_limited',
    `Cert Spotter is rate-limiting requests (${advice}); paused until ${new Date(untilMs).toISOString()}; will retry`,
    untilMs
  );
}

// ---- Parsing ---------------------------------------------------------------------------

/** "C=US\nO=Cloudflare\, Inc.\nCN=…" (Node's X509Certificate.issuer) -> type/value pairs. */
function multilineDn(text: string): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  for (const line of text.split('\n')) {
    const eq = line.indexOf('=');
    if (eq <= 0) continue;
    out.push([
      line.slice(0, eq).trim().toUpperCase(),
      line
        .slice(eq + 1)
        .replace(/\\(.)/g, '$1')
        .trim(),
    ]);
  }
  return out;
}

/** Pairs -> a DN as crt.sh prints it: `C=US, O="Cloudflare, Inc.", CN=…`. */
function crtshStyleDn(pairs: Array<[string, string]>): string {
  return pairs
    .map(([type, value]) =>
      /[,+"\\;<>=]/.test(value) ? `${type}="${value.replace(/(["\\])/g, '\\$1')}"` : `${type}=${value}`
    )
    .join(', ');
}

function parseTime(value: unknown): string | null {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(value)) return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : new Date(ms).toISOString();
}

const hex64 = (value: unknown): string | null =>
  typeof value === 'string' && /^[0-9a-f]{64}$/i.test(value) ? value.toLowerCase() : null;

/** What the DER says: serial, issuer and DNS SANs; null when it can't be read. */
function readDer(
  value: unknown
): { serial: string | null; issuer: string; subjectCn: string | null; sans: string[] } | null {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_DER_BASE64_LENGTH) {
    return null;
  }
  try {
    const x509 = new X509Certificate(Buffer.from(value, 'base64'));
    const sans = (x509.subjectAltName ?? '')
      .split(/,\s*/)
      .filter((entry) => entry.startsWith('DNS:'))
      .map((entry) => entry.slice(4));
    return {
      serial: normalizeSerial(x509.serialNumber),
      issuer: crtshStyleDn(multilineDn(x509.issuer)),
      subjectCn: multilineDn(x509.subject).find(([type]) => type === 'CN')?.[1] ?? null,
      sans,
    };
  } catch {
    return null;
  }
}

/**
 * One page of Cert Spotter issuances -> certificates covering `domain`. Rows
 * are validated field by field; a malformed one is skipped, and so is one
 * whose names are all outside `domain`. Not an array: transient (an outage
 * page, not "no certificates").
 */
export function parseCertSpotterResponse(body: unknown, domain: string): CtCertificate[] {
  if (!Array.isArray(body)) {
    throw new CertSpotterError(
      'transient',
      'Cert Spotter returned a response in an unexpected format; will retry'
    );
  }
  const byKey = new Map<string, CtCertificate>();
  for (const row of body) {
    if (!isPlainObject(row)) continue;
    const id = typeof row.id === 'string' && /^[0-9A-Za-z_-]{1,64}$/.test(row.id) ? row.id : null;
    const tbs = hex64(row.tbs_sha256);
    if (!id || !tbs) continue;
    const der = readDer(row.cert_der);
    const issuerObj = isPlainObject(row.issuer) ? row.issuer : {};
    const apiIssuer = typeof issuerObj.name === 'string' ? issuerObj.name.slice(0, 500) : '';
    // The DER's issuer, printed as crt.sh prints it, so issuerKey matches crt.sh's.
    const issuer = (der?.issuer || apiIssuer).slice(0, 500);
    const { key: issuerKey, label: issuerLabel } = issuerIdentity(issuer);

    const listed = Array.isArray(row.dns_names)
      ? row.dns_names.slice(0, MAX_DNS_NAMES_READ).filter((n): n is string => typeof n === 'string')
      : (der?.sans ?? []);
    const names = sortedUnique(
      listed
        .map(normalizeName)
        .filter((n) => n && isValidHostname(n.replace(/^\*\./, '')) && isWithinDomain(n, domain))
    ).slice(0, MAX_NAMES_PER_CERT);
    if (names.length === 0) continue;

    const serial = der?.serial ?? null;
    const key = serial ? certificateKey(issuerKey, serial) : `certspotter:${tbs}`;
    const subjectCn = der?.subjectCn ? normalizeName(der.subjectCn) || null : null;
    const cert: CtCertificate = {
      key,
      source: 'certspotter',
      crtshId: null,
      certspotterId: id,
      certSha256: hex64(row.cert_sha256),
      issuer,
      issuerKey,
      issuerLabel,
      serial,
      commonName: subjectCn,
      names,
      notBefore: parseTime(row.not_before),
      notAfter: parseTime(row.not_after),
    };
    const existing = byKey.get(key);
    if (existing) {
      existing.names = sortedUnique([...existing.names, ...names]).slice(0, MAX_NAMES_PER_CERT);
    } else {
      byKey.set(key, cert);
    }
  }
  return [...byKey.values()];
}

// ---- Client -------------------------------------------------------------------------------

/** Constant host; the name and cursor only ever land in encoded query parameters. */
export function certSpotterQueryUrl(domain: string, after?: string): URL {
  const params = new URLSearchParams({ domain, include_subdomains: 'true' });
  for (const field of ['dns_names', 'issuer', 'cert_der']) params.append('expand', field);
  if (after !== undefined) params.set('after', after);
  const url = new URL(CERTSPOTTER_BASE);
  url.search = params.toString();
  return url;
}

// One pacer per process: every domain's Cert Spotter requests share it.
const certSpotterPacer = createPacer(CERTSPOTTER_MIN_GAP_MS);

export interface CertSpotterClientOptions {
  /** Optional; never logged or put in a message. */
  apiKey?: string | null;
  transport?: HttpGet;
  timeoutMs?: number;
  maxBytes?: number;
  maxPages?: number;
  pacer?: Pacer;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}

const sleepMs = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

export class CertSpotterClient implements CertificateSource {
  readonly hasApiKey: boolean;
  // A private field, so the key never shows up in a JSON dump or util.inspect of the client.
  readonly #apiKey: string | null;
  private readonly transport: HttpGet;
  private readonly timeoutMs: number;
  private readonly maxBytes: number;
  private readonly maxPages: number;
  private readonly pacer: Pacer;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly now: () => number;

  constructor(options: CertSpotterClientOptions = {}) {
    const key = options.apiKey?.trim() ?? '';
    this.#apiKey = key && CERTSPOTTER_API_KEY_RE.test(key) ? key : null;
    this.hasApiKey = this.#apiKey !== null;
    this.transport = options.transport ?? httpsGet;
    this.timeoutMs = options.timeoutMs ?? CERTSPOTTER_TIMEOUT_MS;
    this.maxBytes = options.maxBytes ?? CERTSPOTTER_MAX_BYTES;
    this.maxPages = options.maxPages ?? CERTSPOTTER_MAX_PAGES;
    this.pacer = options.pacer ?? certSpotterPacer;
    this.sleep = options.sleep ?? sleepMs;
    this.now = options.now ?? Date.now;
  }

  /** Every page for `name` (and its subdomains), merged. Throws CertSpotterError. */
  async certificatesFor(name: string): Promise<CtCertificate[]> {
    const byKey = new Map<string, CtCertificate>();
    let after: string | undefined;
    for (let page = 0; page < this.maxPages; page++) {
      const rows = await this.page(name, after);
      if (rows.length === 0) return [...byKey.values()];
      const last = rows[rows.length - 1];
      const lastId = isPlainObject(last) && typeof last.id === 'string' ? last.id : '';
      if (!/^[0-9A-Za-z_-]{1,64}$/.test(lastId) || lastId === after) {
        throw new CertSpotterError(
          'transient',
          'Cert Spotter returned a page that can not be continued; will retry'
        );
      }
      after = lastId;
      for (const cert of parseCertSpotterResponse(rows, name)) {
        const existing = byKey.get(cert.key);
        if (existing) {
          existing.names = sortedUnique([...existing.names, ...cert.names]).slice(
            0,
            MAX_NAMES_PER_CERT
          );
        } else {
          byKey.set(cert.key, cert);
        }
      }
      if (byKey.size > MAX_CERTS_PER_NAME) break;
    }
    throw new CtTooLargeError(
      `Cert Spotter lists more certificates for ${name} than SIEMBox reads ` +
        `(${this.maxPages} pages); too many to monitor reliably`
    );
  }

  private async page(name: string, after: string | undefined): Promise<unknown[]> {
    for (let attempt = 0; ; attempt++) {
      const paused = certSpotterPausedUntil(this.now());
      if (paused !== null) throw rateLimitedError(paused, this.hasApiKey);
      await this.pacer.wait();
      let res;
      try {
        res = await this.transport(certSpotterQueryUrl(name, after), {
          timeoutMs: this.timeoutMs,
          maxBytes: this.maxBytes,
          ...(this.#apiKey ? { headers: { Authorization: `Bearer ${this.#apiKey}` } } : {}),
        });
      } catch (err) {
        if (err instanceof HttpError && err.kind === 'too_large') {
          throw new CtTooLargeError(
            `Cert Spotter returned more than ${Math.round(this.maxBytes / 1048576)} MB in one page for ${name}`
          );
        }
        if (err instanceof HttpError && err.kind === 'timeout') {
          throw new CertSpotterError('transient', 'Cert Spotter did not answer in time; will retry');
        }
        // HttpError messages are our own (no request headers in them).
        throw new CertSpotterError(
          'transient',
          `Cert Spotter could not be reached (${errorMessage(err)}); will retry`
        );
      }
      if (res.status === 429) {
        const seconds = parseRetryAfterSeconds(res.headers['retry-after'], this.now());
        if (attempt === 0 && seconds <= CERTSPOTTER_SHORT_WAIT_SECONDS) {
          await this.sleep(seconds * 1000);
          continue;
        }
        pausedUntilMs = Math.max(pausedUntilMs, this.now() + seconds * 1000);
        throw rateLimitedError(pausedUntilMs, this.hasApiKey);
      }
      if (res.status >= 500) {
        throw new CertSpotterError(
          'transient',
          `Cert Spotter is temporarily unavailable (HTTP ${res.status}); will retry`
        );
      }
      if (res.status === 401 || res.status === 402) {
        throw new CertSpotterError(
          'auth',
          this.hasApiKey
            ? `Cert Spotter rejected the API key (HTTP ${res.status}): check or replace it in Settings → Digital Risk`
            : `Cert Spotter refused an unauthenticated request (HTTP ${res.status})`
        );
      }
      if (res.status === 403) {
        throw new CertSpotterError(
          'refused',
          `Cert Spotter refused the query for ${name} (HTTP 403: not allowed for this name or plan)`
        );
      }
      if (res.status !== 200) {
        throw new CertSpotterError('refused', `Cert Spotter answered HTTP ${res.status}`);
      }
      let body: unknown;
      try {
        body = JSON.parse(res.body.toString('utf8'));
      } catch {
        throw new CertSpotterError(
          'transient',
          'Cert Spotter returned a response that is not JSON; will retry'
        );
      }
      if (!Array.isArray(body)) {
        throw new CertSpotterError(
          'transient',
          'Cert Spotter returned a response in an unexpected format; will retry'
        );
      }
      return body;
    }
  }
}
