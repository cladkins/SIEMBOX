/**
 * Certificate Transparency collector, backed by crt.sh's JSON output.
 *
 * Query (checked against crt.sh's source, certwatch_db web_apis.fnc, Oct 2026):
 *   https://crt.sh/?q=<name>&output=json&exclude=expired&deduplicate=Y&match=ILIKE
 * `match=ILIKE` is explicit because crt.sh's auto-selected match mode switches
 * to a full-text mode for any value containing "-", which would change what a
 * hyphenated domain matches. With ILIKE crt.sh matches NAME_VALUE ILIKE
 * '%<name>%', so one request covers the name, its subdomains and wildcards
 * (crt.sh rewrites "%.<name>" to "<name>", so asking for that too would only
 * repeat the same query). Requests are paced 3 s apart process-wide.
 * `deduplicate=Y` folds each precertificate into its final certificate, and
 * certificates are keyed on issuer + serial number anyway — the identity a
 * precertificate and its certificate share — so neither can alert twice.
 *
 * crt.sh is a free community service that is often overloaded: timeouts, 5xx,
 * 429 and non-JSON answers are TRANSIENT (the collector fails, its baseline is
 * kept, and it is retried later); they never mean "no certificates".
 * crt.sh also stops at 10,000 matching (certificate, name) rows, picked in no
 * particular order, and says so only in its HTML output: an answer that
 * reaches the limit (the rows' result_count values add up to it) is a random
 * subset, so it is refused as too large to monitor rather than diffed. For the
 * domain's own certificates that refusal is a warning: the lookalike checks
 * still run.
 *
 * Snapshot (per name): the certificates seen (key -> notAfter, pruned a week
 * after expiry), the host names they covered and the issuers that issued them.
 * Each run's certificates are UNIONED into it, so a partial answer can never
 * make a known certificate look new on the next run.
 *
 * Findings
 *  - unexpected_ca (high): own scope with expected_cas set — a new certificate
 *    from any other CA. Existing certificates are judged too on the first run
 *    and whenever expected_cas changes (one finding per offending CA): an
 *    unexpired certificate from a CA the operator ruled out is a live
 *    mis-issuance risk however old it is.
 *  - new_cert (low): own scope — a new certificate that covers a host name
 *    never seen before, or comes from an issuer never seen before. Plain
 *    renewals (known names, known issuer) are not findings: a busy domain
 *    renews certificates every few weeks, and that is not news. Low keeps the
 *    rest below the default notification threshold (medium) while still
 *    recording new hosts (shadow IT, or a takeover) in the alert queue.
 *  - new_cert (medium) for a lookalike: a certificate for a registered
 *    lookalike is a phishing site going up (both scopes, when the lookalike
 *    collector is on; a few lookalikes per run, rotating).
 * More than 10 findings of one kind for one name in one run become a single
 * grouped finding.
 */
import {
  CollectorError,
  capList,
  domainFinding,
  errorMessage,
  fingerprint,
  isPlainObject,
  sortedUnique,
  type Collector,
  type CollectorContext,
  type CollectorOutput,
  type SharedLookalikeState,
} from './types';
import { HttpError, httpsGet, type HttpGet } from './http';
import { isValidHostname, isWithinDomain, normalizeName } from './names';
import { lookalikeStateFromSnapshot, ownDomainNames, registrationMarker } from './lookalike';
import type { FindingInput } from '../findingWriter';

export const CRTSH_BASE = 'https://crt.sh/';
const CRTSH_TIMEOUT_MS = 45_000;
export const CRTSH_MAX_BYTES = 10 * 1024 * 1024;
const CRTSH_MIN_GAP_MS = 3_000;
/** crt.sh's c_resultLimit: matching (certificate, name) rows per identity search. */
export const CRTSH_RESULT_LIMIT = 10_000;
/** Bound on the certificates a snapshot remembers for one name. */
export const MAX_CERTS_PER_NAME = 20_000;
/** Names no current certificate covers any more are kept up to this many. */
const MAX_SNAPSHOT_NAMES = 5_000;
const MAX_SNAPSHOT_ISSUERS = 200;
const MAX_NAMES_PER_CERT = 100;
const EXPIRED_GRACE_SECONDS = 7 * 86_400;
const UNKNOWN_EXPIRY_TTL_SECONDS = 400 * 86_400;
export const MAX_INDIVIDUAL_FINDINGS = 10;

// ---- Certificates ------------------------------------------------------------------

export interface CtCertificate {
  /** Stable identity: issuer + serial number (shared by a precertificate and its certificate). */
  key: string;
  crtshId: number;
  /** The issuer's distinguished name as crt.sh prints it. */
  issuer: string;
  /** Normalised issuer organisation (or CN) — what "new issuer" compares. */
  issuerKey: string;
  issuerLabel: string;
  serial: string | null;
  commonName: string | null;
  /** Host names under the queried domain (lowercase; wildcards keep their "*."). */
  names: string[];
  notBefore: string | null;
  notAfter: string | null;
}

/** Split a DN such as `C=US, O="Cloudflare, Inc.", CN=…` into [type, value] pairs. */
export function parseDistinguishedName(dn: string): Array<[string, string]> {
  const parts: string[] = [];
  let current = '';
  let quoted = false;
  for (let i = 0; i < dn.length; i++) {
    const ch = dn[i];
    if (ch === '\\' && i + 1 < dn.length) {
      current += ch + dn[++i];
      continue;
    }
    if (ch === '"') quoted = !quoted;
    if (ch === ',' && !quoted) {
      parts.push(current);
      current = '';
      continue;
    }
    current += ch;
  }
  parts.push(current);

  const out: Array<[string, string]> = [];
  for (const part of parts) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    const type = part.slice(0, eq).trim().toUpperCase();
    let value = part.slice(eq + 1).trim();
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"'))
      value = value.slice(1, -1);
    value = value.replace(/\\(.)/g, '$1').trim();
    if (type) out.push([type, value]);
  }
  return out;
}

const caKey = (value: string) => value.toLowerCase().replace(/[^a-z0-9]/g, '');

/** The issuer's organisation (else its CN) — for display and for "new issuer". */
export function issuerIdentity(issuerDn: string): { key: string; label: string } {
  const rdns = parseDistinguishedName(issuerDn);
  const org = rdns.find(([type]) => type === 'O')?.[1];
  const cn = rdns.find(([type]) => type === 'CN')?.[1];
  const label = org || cn || issuerDn.trim() || 'unknown issuer';
  return { key: caKey(label) || 'unknown', label };
}

/**
 * Is the issuer one of the expected CAs? An expected entry matches when,
 * ignoring case and punctuation, it is part of the issuer's O, OU or CN
 * ("Let's Encrypt" matches `O=Let's Encrypt, CN=R11`; "DigiCert" matches
 * `O=DigiCert Inc`), or equals the whole DN.
 */
export function issuerMatchesExpected(issuerDn: string, expectedCas: readonly string[]): boolean {
  const fields = parseDistinguishedName(issuerDn)
    .filter(([type]) => type === 'O' || type === 'OU' || type === 'CN')
    .map(([, value]) => caKey(value));
  const whole = caKey(issuerDn);
  return expectedCas.some((ca) => {
    const wanted = caKey(ca);
    return wanted !== '' && (whole === wanted || fields.some((field) => field.includes(wanted)));
  });
}

/** crt.sh prints UTC timestamps without a zone designator. */
function parseCrtshTime(value: unknown): string | null {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(value)) return null;
  const iso = /(Z|[+-]\d{2}:?\d{2})$/.test(value) ? value : `${value}Z`;
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? null : new Date(ms).toISOString();
}

/**
 * crt.sh's JSON (one row per certificate) -> certificates covering `domain`.
 * Rows are validated field by field; anything malformed is skipped, and a
 * certificate whose names are all outside `domain` (or not host names at all,
 * e.g. e-mail identities) is dropped. An answer cut off at crt.sh's result
 * limit is refused (non-transient): it is a random subset, so diffing it would
 * miss new certificates and report old ones as new.
 */
export function parseCrtshResponse(body: unknown, domain: string): CtCertificate[] {
  if (!Array.isArray(body)) {
    throw new CollectorError(
      'crt.sh returned a response in an unexpected format; will retry',
      true
    );
  }
  // Each row's result_count is how many matching names it stands for; their
  // sum is how many rows crt.sh's limited query returned (a row without one
  // counts once: a lower bound).
  let matchedRows = 0;
  for (const row of body) {
    if (!isPlainObject(row)) continue;
    const count = row.result_count;
    matchedRows +=
      typeof count === 'number' && Number.isSafeInteger(count) && count > 0 ? count : 1;
  }
  if (matchedRows >= CRTSH_RESULT_LIMIT) {
    throw new CollectorError(
      `crt.sh returned only part of the certificates for ${domain}: it stops at ` +
        `${CRTSH_RESULT_LIMIT.toLocaleString('en-US')} matching names and picks them in no ` +
        'particular order, so new certificates could be missed; too many to monitor reliably',
      false
    );
  }
  const byKey = new Map<string, CtCertificate>();
  for (const row of body) {
    if (!isPlainObject(row)) continue;
    const id = row.id;
    if (typeof id !== 'number' || !Number.isSafeInteger(id) || id <= 0) continue;

    const issuer = typeof row.issuer_name === 'string' ? row.issuer_name.slice(0, 500) : '';
    const caId =
      typeof row.issuer_ca_id === 'number' && Number.isSafeInteger(row.issuer_ca_id)
        ? row.issuer_ca_id
        : null;
    const rawSerial = typeof row.serial_number === 'string' ? row.serial_number.trim() : '';
    const serial = /^[0-9a-f]{1,128}$/i.test(rawSerial)
      ? rawSerial.toLowerCase().replace(/^0+(?=.)/, '')
      : null;
    const { key: issuerKey, label: issuerLabel } = issuerIdentity(issuer);

    const rawNames = [
      ...(typeof row.name_value === 'string' ? row.name_value.split(/\s+/) : []),
      ...(typeof row.common_name === 'string' ? [row.common_name] : []),
    ];
    const names = sortedUnique(
      rawNames
        .map(normalizeName)
        .filter((n) => n && isValidHostname(n.replace(/^\*\./, '')) && isWithinDomain(n, domain))
    ).slice(0, MAX_NAMES_PER_CERT);
    if (names.length === 0) continue;

    const key = serial ? `${caId ?? issuerKey}:${serial}` : `crtsh:${id}`;
    const commonName = typeof row.common_name === 'string' ? normalizeName(row.common_name) : null;
    const cert: CtCertificate = {
      key,
      crtshId: id,
      issuer,
      issuerKey,
      issuerLabel,
      serial,
      commonName: commonName || null,
      names,
      notBefore: parseCrtshTime(row.not_before),
      notAfter: parseCrtshTime(row.not_after),
    };
    const existing = byKey.get(key);
    if (existing) {
      existing.names = sortedUnique([...existing.names, ...names]).slice(0, MAX_NAMES_PER_CERT);
      existing.crtshId = Math.min(existing.crtshId, id);
    } else {
      byKey.set(key, cert);
    }
  }
  return [...byKey.values()].sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
}

// ---- crt.sh client -------------------------------------------------------------------

/** Constant host; the identity only ever lands in an encoded query parameter. */
export function crtshQueryUrl(identity: string): URL {
  const url = new URL(CRTSH_BASE);
  url.search = new URLSearchParams({
    q: identity,
    output: 'json',
    exclude: 'expired',
    deduplicate: 'Y',
    match: 'ILIKE',
  }).toString();
  return url;
}

export interface Pacer {
  /** Resolves when the next request may start. */
  wait(): Promise<void>;
}

const sleepMs = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/** Spaces requests at least `gapMs` apart, also across concurrent callers. */
export function createPacer(
  gapMs: number,
  sleep: (ms: number) => Promise<void> = sleepMs,
  now: () => number = Date.now
): Pacer {
  let nextSlot = 0;
  return {
    async wait() {
      const t = now();
      const start = Math.max(t, nextSlot);
      nextSlot = start + gapMs;
      if (start > t) await sleep(start - t);
    },
  };
}

// One pacer per process: every domain's crt.sh requests share it.
const crtshPacer = createPacer(CRTSH_MIN_GAP_MS);

export interface CtClientOptions {
  transport?: HttpGet;
  timeoutMs?: number;
  maxBytes?: number;
  pacer?: Pacer;
}

export interface CertificateSource {
  /** Unexpired certificates for `name` and its subdomains. Throws CollectorError. */
  certificatesFor(name: string): Promise<CtCertificate[]>;
}

export class CtClient implements CertificateSource {
  private readonly transport: HttpGet;
  private readonly timeoutMs: number;
  private readonly maxBytes: number;
  private readonly pacer: Pacer;

  constructor(options: CtClientOptions = {}) {
    this.transport = options.transport ?? httpsGet;
    this.timeoutMs = options.timeoutMs ?? CRTSH_TIMEOUT_MS;
    this.maxBytes = options.maxBytes ?? CRTSH_MAX_BYTES;
    this.pacer = options.pacer ?? crtshPacer;
  }

  /** One request: with match=ILIKE crt.sh matches the name, its subdomains and wildcards. */
  async certificatesFor(name: string): Promise<CtCertificate[]> {
    return this.query(name, name);
  }

  private async query(identity: string, domain: string): Promise<CtCertificate[]> {
    await this.pacer.wait();
    let res;
    try {
      res = await this.transport(crtshQueryUrl(identity), {
        timeoutMs: this.timeoutMs,
        maxBytes: this.maxBytes,
      });
    } catch (err) {
      if (err instanceof HttpError && err.kind === 'too_large') {
        throw new CollectorError(
          `crt.sh returned more than ${Math.round(this.maxBytes / 1048576)} MB for ${identity}; too many certificates to monitor`,
          false
        );
      }
      if (err instanceof HttpError && err.kind === 'timeout') {
        throw new CollectorError(
          err.phase === 'connect'
            ? `could not connect to crt.sh within ${Math.round(this.timeoutMs / 1000)} s ` +
              '(is outbound HTTPS blocked?); will retry'
            : 'crt.sh did not answer in time (it is often overloaded); will retry',
          true
        );
      }
      throw new CollectorError(
        `crt.sh could not be reached (${errorMessage(err)}); will retry`,
        true
      );
    }
    if (res.status === 429 || res.status >= 500) {
      throw new CollectorError(
        `crt.sh is temporarily unavailable (HTTP ${res.status}); will retry`,
        true
      );
    }
    if (res.status !== 200) {
      const redirect = res.status >= 300 && res.status < 400;
      throw new CollectorError(
        `crt.sh answered HTTP ${res.status}${redirect ? ' (redirects are not followed)' : ''}`,
        redirect
      );
    }
    let body: unknown;
    try {
      body = JSON.parse(res.body.toString('utf8'));
    } catch {
      throw new CollectorError(
        'crt.sh returned a response that is not JSON (it is often overloaded); will retry',
        true
      );
    }
    return parseCrtshResponse(body, domain);
  }
}

// ---- Snapshot & diff -------------------------------------------------------------------

export interface CtNameSnapshot {
  /** Certificate key -> notAfter (epoch seconds), for pruning. */
  certs: Record<string, number>;
  names: string[];
  issuers: string[];
}

export interface CtLookalikeSnapshot extends CtNameSnapshot {
  /** When this lookalike's certificates were last fetched (epoch seconds). */
  checked_at: number;
}

/** A lookalike whose last certificate check failed (cleared by the next good check). */
export interface CtLookalikeFailure {
  /** When it was last tried (epoch seconds). */
  at: number;
  /** Failures in a row. */
  count: number;
  /** false: retrying soon won't help (e.g. too many certificates); it backs off for days. */
  transient: boolean;
}

export interface CtSnapshot {
  v: 1;
  /** The watched domain's own certificates (own scope). */
  domain?: CtNameSnapshot;
  /** expected_cas as last applied (normalised), to notice a policy change. */
  expected_cas?: string[];
  /** Registered lookalikes whose certificates have been checked. */
  lookalikes?: Record<string, CtLookalikeSnapshot>;
  /**
   * Registered lookalikes whose last check failed, so the rotation moves on to
   * others instead of retrying the same name first every run.
   */
  lookalike_failures?: Record<string, CtLookalikeFailure>;
  /**
   * Newly registered lookalikes not checked successfully yet. Their first good
   * check is judged as a site going up however long crt.sh takes to answer for
   * them (the lookalike snapshot only lists them as new for a while).
   */
  pending_new?: string[];
}

function parseNameSnapshot(value: unknown): CtNameSnapshot | null {
  if (!isPlainObject(value) || !isPlainObject(value.certs)) return null;
  const certs: Record<string, number> = {};
  for (const [key, notAfter] of Object.entries(value.certs)) {
    if (typeof notAfter === 'number' && Number.isFinite(notAfter)) certs[key] = notAfter;
  }
  const strings = (v: unknown) =>
    Array.isArray(v) ? v.filter((s): s is string => typeof s === 'string') : [];
  return { certs, names: strings(value.names), issuers: strings(value.issuers) };
}

/** A stored CT snapshot, or null when there is none (or it is unreadable: start over). */
export function parseCtSnapshot(value: unknown): CtSnapshot | null {
  if (!isPlainObject(value) || value.v !== 1) return null;
  const out: CtSnapshot = { v: 1 };
  const domain = value.domain === undefined ? null : parseNameSnapshot(value.domain);
  if (domain) out.domain = domain;
  if (Array.isArray(value.expected_cas)) {
    out.expected_cas = value.expected_cas.filter((s): s is string => typeof s === 'string');
  }
  if (Array.isArray(value.pending_new)) {
    out.pending_new = value.pending_new.filter((s): s is string => typeof s === 'string');
  }
  if (isPlainObject(value.lookalike_failures)) {
    out.lookalike_failures = {};
    for (const [name, entry] of Object.entries(value.lookalike_failures)) {
      if (
        isPlainObject(entry) &&
        typeof entry.at === 'number' &&
        Number.isFinite(entry.at) &&
        typeof entry.count === 'number' &&
        Number.isFinite(entry.count)
      ) {
        out.lookalike_failures[name] = {
          at: entry.at,
          count: entry.count,
          transient: entry.transient !== false,
        };
      }
    }
  }
  if (isPlainObject(value.lookalikes)) {
    out.lookalikes = {};
    for (const [name, entry] of Object.entries(value.lookalikes)) {
      const parsed = parseNameSnapshot(entry);
      const checkedAt = isPlainObject(entry) ? entry.checked_at : undefined;
      if (parsed && typeof checkedAt === 'number') {
        out.lookalikes[name] = { ...parsed, checked_at: checkedAt };
      }
    }
  }
  return out;
}

export interface FreshCertificate {
  cert: CtCertificate;
  /** Names this certificate covers that no earlier certificate did. */
  newNames: string[];
  /** Its issuer never issued for this name before. */
  newIssuer: boolean;
}

export interface CertificateDiff {
  next: CtNameSnapshot;
  /** Certificates not in the previous snapshot (every certificate when there was none). */
  fresh: FreshCertificate[];
  /** Fresh certificates with only known names from a known issuer. */
  renewals: number;
}

export function diffCertificates(
  previous: CtNameSnapshot | null,
  certs: readonly CtCertificate[],
  nowSeconds: number
): CertificateDiff {
  const knownIssuers = new Set(previous?.issuers ?? []);
  const seen = previous?.certs ?? {};
  const wasSeen = (cert: CtCertificate) => Object.prototype.hasOwnProperty.call(seen, cert.key);
  // Known names: the snapshot's, plus every name a certificate seen before
  // still covers, so a renewal is a renewal even when the snapshot's name list
  // had to be cut short.
  const knownNames = new Set(previous?.names ?? []);
  for (const cert of certs) {
    if (wasSeen(cert)) for (const name of cert.names) knownNames.add(name);
  }

  const fresh: FreshCertificate[] = [];
  let renewals = 0;
  for (const cert of certs) {
    if (wasSeen(cert)) continue;
    const item = {
      cert,
      newNames: cert.names.filter((n) => !knownNames.has(n)),
      newIssuer: !knownIssuers.has(cert.issuerKey),
    };
    if (item.newNames.length === 0 && !item.newIssuer) renewals++;
    fresh.push(item);
  }

  // Union with what was seen before, minus certificates long expired.
  const merged: Record<string, number> = {};
  for (const [key, notAfter] of Object.entries(seen)) {
    if (notAfter >= nowSeconds - EXPIRED_GRACE_SECONDS) merged[key] = notAfter;
  }
  for (const cert of certs) {
    const notAfter = cert.notAfter ? Math.floor(Date.parse(cert.notAfter) / 1000) : NaN;
    merged[cert.key] = Number.isFinite(notAfter)
      ? notAfter
      : nowSeconds + UNKNOWN_EXPIRY_TTL_SECONDS;
  }
  // Keep the map bounded: drop the soonest-expiring entries first.
  const entries = Object.entries(merged);
  const bounded =
    entries.length > MAX_CERTS_PER_NAME
      ? Object.fromEntries(entries.sort((a, b) => b[1] - a[1]).slice(0, MAX_CERTS_PER_NAME))
      : merged;

  // Every name a current certificate covers is kept (crt.sh's result limit
  // bounds them); names only expired certificates covered fill the rest.
  const currentNames = sortedUnique(certs.flatMap((c) => c.names)).slice(0, MAX_CERTS_PER_NAME);
  const current = new Set(currentNames);
  const olderNames = [...knownNames]
    .filter((n) => !current.has(n))
    .sort()
    .slice(0, Math.max(0, MAX_SNAPSHOT_NAMES - currentNames.length));
  return {
    next: {
      certs: bounded,
      names: sortedUnique([...currentNames, ...olderNames]),
      issuers: sortedUnique([...knownIssuers, ...certs.map((c) => c.issuerKey)]).slice(
        0,
        MAX_SNAPSHOT_ISSUERS
      ),
    },
    fresh,
    renewals,
  };
}

// ---- Findings ------------------------------------------------------------------------------

function certSummary(cert: CtCertificate): Record<string, unknown> {
  return {
    crtsh_id: cert.crtshId,
    crtsh_url: `https://crt.sh/?id=${cert.crtshId}`,
    issuer: cert.issuer,
    issuer_org: cert.issuerLabel,
    serial: cert.serial,
    common_name: cert.commonName,
    names: capList(cert.names, 25),
    not_before: cert.notBefore,
    not_after: cert.notAfter,
  };
}

/** More than MAX_INDIVIDUAL_FINDINGS of one kind become one grouped finding. */
function groupIfMany(
  items: FindingInput[],
  certs: CtCertificate[],
  group: (
    count: number,
    groupFingerprint: string,
    summaries: Record<string, unknown>[]
  ) => FindingInput
): FindingInput[] {
  if (items.length <= MAX_INDIVIDUAL_FINDINGS) return items;
  const memberFingerprints = items.map((i) => i.fingerprint).sort();
  return [
    group(
      items.length,
      fingerprint('ct', 'batch', memberFingerprints),
      capList(certs, 25).map(certSummary)
    ),
  ];
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}

/**
 * first          — no baseline yet: the current certificates become it; only
 *                  the CA policy is judged (one finding per offending CA).
 * policy_changed — expected_cas changed since the last run: the certificates
 *                  already known are re-judged per CA, new ones individually.
 * normal         — only certificates not seen before are judged.
 */
type OwnDomainMode = 'first' | 'policy_changed' | 'normal';

function ownDomainFindings(
  ctx: CollectorContext,
  diff: CertificateDiff,
  mode: OwnDomainMode,
  allCerts: readonly CtCertificate[]
): FindingInput[] {
  const domain = ctx.domain.domain;
  const expected = ctx.domain.expected_cas ?? [];
  const checkCa = expected.length > 0;
  const findings: FindingInput[] = [];
  const isUnexpected = (cert: CtCertificate) =>
    checkCa && !issuerMatchesExpected(cert.issuer, expected);

  if (checkCa && mode !== 'normal') {
    const freshKeys = new Set(diff.fresh.map((f) => f.cert.key));
    const existing = mode === 'first' ? allCerts : allCerts.filter((c) => !freshKeys.has(c.key));
    const byIssuer = new Map<string, CtCertificate[]>();
    for (const cert of existing) {
      if (!isUnexpected(cert)) continue;
      const list = byIssuer.get(cert.issuerKey);
      if (list) list.push(cert);
      else byIssuer.set(cert.issuerKey, [cert]);
    }
    for (const [issuerKey, certs] of byIssuer) {
      const label = certs[0].issuerLabel;
      findings.push(
        domainFinding({
          domainId: ctx.domain.id,
          eventType: 'unexpected_ca',
          fingerprint: fingerprint('ct', 'unexpected_ca_existing', domain, issuerKey),
          severity: 'high',
          title: `${plural(certs.length, 'current certificate')} for ${domain} issued by ${label}, which is not an expected CA`,
          description:
            `Certificate Transparency logs show ${plural(certs.length, 'unexpired certificate')} for ${domain} ` +
            `issued by ${label}, which is not in this domain's expected CAs (${expected.join(', ')}). ` +
            'If your organization did not request them, revoke them with the CA and investigate how they ' +
            'were obtained (DNS or web-server compromise); if it did, add the CA to expected_cas.',
          detail: {
            collector: 'ct',
            domain,
            issuer_org: label,
            expected_cas: expected,
            certificate_count: certs.length,
            certificates: capList(certs, 25).map(certSummary),
          },
        })
      );
    }
  }
  if (mode === 'first') return findings;

  const unexpected = diff.fresh.filter((f) => isUnexpected(f.cert));
  const interesting = diff.fresh.filter(
    (f) => !isUnexpected(f.cert) && (f.newNames.length > 0 || f.newIssuer)
  );

  findings.push(
    ...groupIfMany(
      unexpected.map(({ cert }) =>
        domainFinding({
          domainId: ctx.domain.id,
          eventType: 'unexpected_ca',
          fingerprint: fingerprint('ct', 'unexpected_ca', cert.key),
          severity: 'high',
          title: `Certificate for ${cert.names[0]} issued by unexpected CA ${cert.issuerLabel}`,
          description:
            `crt.sh logged a new certificate for ${cert.names.join(', ')} from ${cert.issuerLabel}, ` +
            `which is not in this domain's expected CAs (${expected.join(', ')}). If your organization did ` +
            'not request it, revoke it with the CA and investigate how it was obtained. ' +
            `https://crt.sh/?id=${cert.crtshId}`,
          detail: { collector: 'ct', domain, expected_cas: expected, ...certSummary(cert) },
        })
      ),
      unexpected.map((f) => f.cert),
      (count, fp, certificates) =>
        domainFinding({
          domainId: ctx.domain.id,
          eventType: 'unexpected_ca',
          fingerprint: fp,
          severity: 'high',
          title: `${count} new certificates for ${domain} from unexpected CAs`,
          description: `crt.sh logged ${count} new certificates for ${domain} from CAs outside this domain's expected CAs (${expected.join(', ')}).`,
          detail: {
            collector: 'ct',
            domain,
            expected_cas: expected,
            certificate_count: count,
            certificates,
          },
        })
    )
  );

  findings.push(
    ...groupIfMany(
      interesting.map(({ cert, newNames, newIssuer }) =>
        domainFinding({
          domainId: ctx.domain.id,
          eventType: 'new_cert',
          fingerprint: fingerprint('ct', 'new_cert', cert.key),
          severity: 'low',
          title: newNames.length
            ? `New TLS certificate for ${newNames[0]}${newNames.length > 1 ? ` (+${newNames.length - 1} more)` : ''} from ${cert.issuerLabel}`
            : `First certificate from ${cert.issuerLabel} for ${cert.names[0]}`,
          description:
            `crt.sh logged a new certificate for ${cert.names.join(', ')} from ${cert.issuerLabel}` +
            (newNames.length
              ? `; it covers host names not seen before (${newNames.join(', ')})`
              : '') +
            (newIssuer ? `; it is the first certificate from this issuer for ${domain}` : '') +
            `. Confirm your organization requested it. https://crt.sh/?id=${cert.crtshId}`,
          detail: {
            collector: 'ct',
            domain,
            new_names: capList(newNames, 25),
            new_issuer: newIssuer,
            ...certSummary(cert),
          },
        })
      ),
      interesting.map((f) => f.cert),
      (count, fp, certificates) =>
        domainFinding({
          domainId: ctx.domain.id,
          eventType: 'new_cert',
          fingerprint: fp,
          severity: 'low',
          title: `${count} new TLS certificates for ${domain}`,
          description: `crt.sh logged ${count} new certificates for ${domain} that cover new host names or come from new issuers.`,
          detail: { collector: 'ct', domain, certificate_count: count, certificates },
        })
    )
  );
  return findings;
}

function lookalikeFindings(
  ctx: CollectorContext,
  lookalike: string,
  diff: CertificateDiff,
  firstCheck: boolean,
  newlyRegistered: boolean,
  priorDrop: number | undefined
): FindingInput[] {
  const watched = ctx.domain.domain;
  if (firstCheck) {
    // Known lookalikes are baselined silently. One registered since the last
    // run that already has certificates is a site going up: one finding (per
    // registration: a new owner after a drop is told apart by priorDrop).
    if (!newlyRegistered || diff.fresh.length === 0) return [];
    const certs = diff.fresh.map((f) => f.cert);
    return [
      domainFinding({
        domainId: ctx.domain.id,
        eventType: 'new_cert',
        fingerprint: fingerprint(
          'ct',
          'lookalike_certs',
          lookalike,
          ...registrationMarker(priorDrop)
        ),
        severity: 'medium',
        title: `Newly registered lookalike ${lookalike} already has ${plural(certs.length, 'TLS certificate')}`,
        description:
          `${lookalike} (a lookalike of ${watched}) was registered recently and already has ` +
          `${plural(certs.length, 'certificate')} in Certificate Transparency logs — a site may be going up. ` +
          'Check what it serves and consider a takedown request.',
        detail: {
          collector: 'ct',
          domain: watched,
          lookalike,
          certificate_count: certs.length,
          certificates: capList(certs, 25).map(certSummary),
        },
      }),
    ];
  }
  const interesting = diff.fresh.filter((f) => f.newNames.length > 0 || f.newIssuer);
  return groupIfMany(
    interesting.map(({ cert, newNames }) =>
      domainFinding({
        domainId: ctx.domain.id,
        eventType: 'new_cert',
        fingerprint: fingerprint('ct', 'lookalike_cert', lookalike, cert.key),
        severity: 'medium',
        title: `TLS certificate issued for lookalike ${newNames[0] ?? cert.names[0]} (${cert.issuerLabel})`,
        description:
          `crt.sh logged a certificate for ${cert.names.join(', ')}, a lookalike of ${watched}, from ` +
          `${cert.issuerLabel}. A certificate usually means a site is going up; check what it serves. ` +
          `https://crt.sh/?id=${cert.crtshId}`,
        detail: {
          collector: 'ct',
          domain: watched,
          lookalike,
          new_names: capList(newNames, 25),
          ...certSummary(cert),
        },
      })
    ),
    interesting.map((f) => f.cert),
    (count, fp, certificates) =>
      domainFinding({
        domainId: ctx.domain.id,
        eventType: 'new_cert',
        fingerprint: fp,
        severity: 'medium',
        title: `${count} new TLS certificates for lookalike ${lookalike}`,
        description: `crt.sh logged ${count} new certificates for ${lookalike}, a lookalike of ${watched}.`,
        detail: {
          collector: 'ct',
          domain: watched,
          lookalike,
          certificate_count: count,
          certificates,
        },
      })
  );
}

/**
 * The lookalikes CT should look at: this run's result, else the stored
 * lookalike baseline (which also remembers which ones were newly registered),
 * never the organization's own watched domains.
 */
function lookalikeState(ctx: CollectorContext, nowSeconds: number): SharedLookalikeState | null {
  if (!ctx.domain.collectors.lookalike) return null;
  const stored = ctx.baselines.lookalike;
  const state =
    ctx.earlier.lookalike?.lookalikes ??
    (stored === undefined || stored === null
      ? null
      : lookalikeStateFromSnapshot(stored, nowSeconds));
  if (!state) return null;
  const own = ownDomainNames(ctx.watchedDomains);
  return {
    registered: state.registered.filter((n) => !own.has(n)),
    newlyRegistered: state.newlyRegistered.filter((n) => !own.has(n)),
    ...(state.priorDrops ? { priorDrops: state.priorDrops } : {}),
  };
}

/** A lookalike whose check failed for good (not transiently) is left alone this long. */
const PERMANENT_FAILURE_BACKOFF_SECONDS = 7 * 86_400;
/** A newly registered lookalike stays ahead of the rotation for this many failed checks in a row. */
export const MAX_PENDING_ATTEMPTS = 3;

/**
 * The lookalikes to check this run, at most `max`: newly registered ones never
 * tried yet first, then newly registered ones whose check failed transiently
 * (fewer than MAX_PENDING_ATTEMPTS times in a row; least recently tried
 * first), then the rest by when they were last touched — checked or tried —
 * oldest (or never) first. Any other name that just failed goes to the back of
 * the rotation, so one crt.sh can't answer for never blocks the others; one
 * that failed for good waits PERMANENT_FAILURE_BACKOFF_SECONDS.
 */
export function selectLookalikesForCt(
  state: SharedLookalikeState,
  checked: Record<string, { checked_at: number }>,
  max: number,
  failures: Record<string, CtLookalikeFailure> = {},
  nowSeconds = Math.floor(Date.now() / 1000)
): string[] {
  const fresh = new Set(state.newlyRegistered);
  const rank = (name: string): [number, number] => {
    const failure = failures[name];
    if (fresh.has(name)) {
      if (!failure) return [0, 0];
      if (failure.transient && failure.count < MAX_PENDING_ATTEMPTS) return [1, failure.at];
    }
    return [2, Math.max(checked[name]?.checked_at ?? 0, failure?.at ?? 0)];
  };
  return [...new Set(state.registered)]
    .filter((name) => {
      const failure = failures[name];
      return (
        !failure ||
        failure.transient ||
        failure.at <= nowSeconds - PERMANENT_FAILURE_BACKOFF_SECONDS
      );
    })
    .sort((a, b) => {
      const [ra, ta] = rank(a);
      const [rb, tb] = rank(b);
      return ra - rb || ta - tb || (a < b ? -1 : a > b ? 1 : 0);
    })
    .slice(0, Math.max(0, max));
}

const normalizedPolicy = (cas: readonly string[]) => sortedUnique(cas.map(caKey).filter(Boolean));

export interface CtCollectorDeps {
  source?: CertificateSource;
}

export function createCtCollector(deps: CtCollectorDeps = {}): Collector {
  return async (ctx: CollectorContext): Promise<CollectorOutput> => {
    const source = deps.source ?? new CtClient();
    const previous = parseCtSnapshot(ctx.previous);
    const nowSeconds = Math.floor(ctx.now.getTime() / 1000);
    const next: CtSnapshot = { v: 1 };
    const findings: FindingInput[] = [];
    const warnings: string[] = [];
    const details: Record<string, unknown> = {};
    const notes: string[] = [];

    // 1. The domain's own certificates (own scope: its certificates are ours to police).
    let ownCerts: CtCertificate[] | null = null;
    if (ctx.domain.scope === 'own') {
      try {
        ownCerts = await source.certificatesFor(ctx.domain.domain);
      } catch (err) {
        // crt.sh struggling (transient) fails the collector, so it is retried
        // soon. An answer retrying won't fix (too many certificates to monitor)
        // must not stop the lookalike checks below: it is a warning, and the
        // domain's own baseline stays as it was.
        if (!(err instanceof CollectorError) || err.transient) throw err;
        const message = errorMessage(err);
        warnings.push(`${ctx.domain.domain}: ${message}`);
        details.own_domain_error = message;
        notes.push('own certificates not checked (see warnings)');
      }
    }
    if (ownCerts !== null) {
      const firstRun = previous?.domain === undefined;
      const policy = normalizedPolicy(ctx.domain.expected_cas ?? []);
      const policyChanged =
        !firstRun && JSON.stringify(previous?.expected_cas ?? []) !== JSON.stringify(policy);
      const diff = diffCertificates(previous?.domain ?? null, ownCerts, nowSeconds);
      next.domain = diff.next;
      next.expected_cas = policy;
      const mode: OwnDomainMode = firstRun ? 'first' : policyChanged ? 'policy_changed' : 'normal';
      findings.push(...ownDomainFindings(ctx, diff, mode, ownCerts));
      details.certificates = ownCerts.length;
      if (firstRun) {
        notes.push(`baseline recorded: ${plural(ownCerts.length, 'unexpired certificate')}`);
      } else {
        details.new_certificates = diff.fresh.length;
        details.renewals = diff.renewals;
        notes.push(
          `${plural(ownCerts.length, 'unexpired certificate')} (${diff.fresh.length} new, ${plural(diff.renewals, 'renewal')})`
        );
      }
    } else if (previous?.domain) {
      // Not checked this run (refused above, or the scope switched to brand and
      // may switch back): the baseline stays as it was.
      next.domain = previous.domain;
      if (previous.expected_cas) next.expected_cas = previous.expected_cas;
    }

    // 2. Certificates for registered lookalikes (both scopes).
    const state = lookalikeState(ctx, nowSeconds);
    const storedLookalikes = previous?.lookalikes ?? {};
    if (state) {
      const registered = new Set(state.registered);
      next.lookalikes = Object.fromEntries(
        Object.entries(storedLookalikes).filter(([name]) => registered.has(name))
      );
      const failures: Record<string, CtLookalikeFailure> = Object.fromEntries(
        Object.entries(previous?.lookalike_failures ?? {}).filter(([name]) => registered.has(name))
      );
      // Newly registered lookalikes whose certificates were never checked: their
      // first good check is judged as a site going up, however many runs that
      // takes (CT failing, crt.sh not answering for them, the per-run cap). They
      // are kept here because the lookalike snapshot lists them as new only for
      // NEW_REGISTRATION_WINDOW_DAYS.
      const pending = new Set(
        [...(previous?.pending_new ?? []), ...state.newlyRegistered].filter(
          (n) => registered.has(n) && !storedLookalikes[n]
        )
      );
      const selected = selectLookalikesForCt(
        { registered: state.registered, newlyRegistered: [...pending] },
        storedLookalikes,
        ctx.config.lookalikeCtChecksPerRun,
        failures,
        nowSeconds
      );
      let checkedOk = 0;
      let firstFailure: CollectorError | null = null;
      for (const lookalike of selected) {
        try {
          const certs = await source.certificatesFor(lookalike);
          const before = storedLookalikes[lookalike] ?? null;
          const diff = diffCertificates(before, certs, nowSeconds);
          next.lookalikes[lookalike] = { ...diff.next, checked_at: nowSeconds };
          delete failures[lookalike];
          findings.push(
            ...lookalikeFindings(
              ctx,
              lookalike,
              diff,
              before === null,
              pending.has(lookalike),
              state.priorDrops?.[lookalike]
            )
          );
          pending.delete(lookalike);
          checkedOk++;
        } catch (err) {
          warnings.push(`${lookalike}: ${errorMessage(err)}`);
          const transient = err instanceof CollectorError && err.transient;
          // Remembered, so the next run moves on to other lookalikes first.
          failures[lookalike] = {
            at: nowSeconds,
            count: (failures[lookalike]?.count ?? 0) + 1,
            transient,
          };
          if (transient) {
            firstFailure = firstFailure ?? (err as CollectorError);
            break; // crt.sh is struggling: don't keep asking it this run
          }
        }
      }
      if (Object.keys(failures).length > 0) next.lookalike_failures = failures;
      if (pending.size > 0) next.pending_new = [...pending].sort();
      if (ctx.domain.scope === 'brand' && selected.length > 0 && checkedOk === 0 && firstFailure) {
        // Nothing was checked: retry the collector later, keeping only the
        // bookkeeping (what was tried, what still awaits its first check) that
        // decides which lookalikes the retry asks for.
        throw new CollectorError(firstFailure.message, firstFailure.transient, {
          progress: next,
        });
      }
      details.lookalikes_registered = registered.size;
      details.lookalikes_checked = checkedOk;
      notes.push(
        registered.size === 0
          ? 'no registered lookalikes to check'
          : `${checkedOk} of ${plural(registered.size, 'registered lookalike')} checked this run`
      );
    } else {
      if (previous?.lookalikes) next.lookalikes = previous.lookalikes;
      if (previous?.lookalike_failures) next.lookalike_failures = previous.lookalike_failures;
      if (previous?.pending_new) next.pending_new = previous.pending_new;
      if (ctx.domain.scope === 'brand') {
        return {
          findings: [],
          status: 'unsupported',
          note: 'for brand domains, CT checks the registered lookalikes: turn on the lookalike collector',
        };
      }
    }

    return {
      snapshot: next,
      findings,
      status: previous === null ? 'baseline' : 'ok',
      note: notes.join('; '),
      details,
      ...(warnings.length ? { warnings } : {}),
    };
  };
}
