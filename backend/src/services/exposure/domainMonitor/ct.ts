/**
 * Certificate Transparency collector, backed by crt.sh's JSON output.
 *
 * Query (checked against crt.sh's source, certwatch_db web_apis.fnc, Oct 2026):
 *   https://crt.sh/?q=<identity>&output=json&exclude=expired&deduplicate=Y&match=ILIKE
 * `match=ILIKE` is explicit because crt.sh's auto-selected match mode switches
 * to a full-text mode for any value containing "-", which would change what a
 * hyphenated domain matches. "%.example.com" matches subdomains and wildcards
 * only, so the bare name is queried too: two requests per name, paced 3 s
 * apart process-wide. `deduplicate=Y` folds each precertificate into its final
 * certificate, and certificates are keyed on issuer + serial number anyway — the
 * identity a precertificate and its certificate share — so neither can alert twice.
 *
 * crt.sh is a free community service that is often overloaded: timeouts, 5xx,
 * 429 and non-JSON answers are TRANSIENT (the collector fails, its baseline is
 * kept, and it is retried later); they never mean "no certificates".
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
import { registeredFromSnapshot } from './lookalike';
import type { FindingInput } from '../findingWriter';

export const CRTSH_BASE = 'https://crt.sh/';
const CRTSH_TIMEOUT_MS = 45_000;
export const CRTSH_MAX_BYTES = 10 * 1024 * 1024;
const CRTSH_MIN_GAP_MS = 3_000;
/** More unexpired certificates than this for one name is too many to monitor. */
export const MAX_CERTS_PER_NAME = 20_000;
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
 * e.g. e-mail identities) is dropped.
 */
export function parseCrtshResponse(body: unknown, domain: string): CtCertificate[] {
  if (!Array.isArray(body)) {
    throw new CollectorError(
      'crt.sh returned a response in an unexpected format; will retry',
      true
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

function mergeCertificates(lists: CtCertificate[][]): CtCertificate[] {
  const byKey = new Map<string, CtCertificate>();
  for (const cert of lists.flat()) {
    const existing = byKey.get(cert.key);
    if (existing) {
      existing.names = sortedUnique([...existing.names, ...cert.names]).slice(
        0,
        MAX_NAMES_PER_CERT
      );
      existing.crtshId = Math.min(existing.crtshId, cert.crtshId);
    } else {
      byKey.set(cert.key, { ...cert, names: [...cert.names] });
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

  async certificatesFor(name: string): Promise<CtCertificate[]> {
    const exact = await this.query(name, name);
    const below = await this.query(`%.${name}`, name);
    const merged = mergeCertificates([exact, below]);
    if (merged.length > MAX_CERTS_PER_NAME) {
      throw new CollectorError(
        `${name} has more than ${MAX_CERTS_PER_NAME} unexpired certificates; too many to monitor`,
        false
      );
    }
    return merged;
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
          'crt.sh did not answer in time (it is often overloaded); will retry',
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

export interface CtSnapshot {
  v: 1;
  /** The watched domain's own certificates (own scope). */
  domain?: CtNameSnapshot;
  /** expected_cas as last applied (normalised), to notice a policy change. */
  expected_cas?: string[];
  /** Registered lookalikes whose certificates have been checked. */
  lookalikes?: Record<string, CtLookalikeSnapshot>;
  /**
   * Lookalikes registered since a previous run whose certificates have not
   * been checked yet (the per-run cap was reached): their first check still
   * counts as "newly registered".
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
  const knownNames = new Set(previous?.names ?? []);
  const knownIssuers = new Set(previous?.issuers ?? []);
  const seen = previous?.certs ?? {};

  const fresh: FreshCertificate[] = [];
  let renewals = 0;
  for (const cert of certs) {
    if (Object.prototype.hasOwnProperty.call(seen, cert.key)) continue;
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

  return {
    next: {
      certs: bounded,
      names: sortedUnique([...knownNames, ...certs.flatMap((c) => c.names)]).slice(
        0,
        MAX_SNAPSHOT_NAMES
      ),
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
      byIssuer.set(cert.issuerKey, [...(byIssuer.get(cert.issuerKey) ?? []), cert]);
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
  newlyRegistered: boolean
): FindingInput[] {
  const watched = ctx.domain.domain;
  if (firstCheck) {
    // Known lookalikes are baselined silently. One registered since the last
    // run that already has certificates is a site going up: one finding.
    if (!newlyRegistered || diff.fresh.length === 0) return [];
    const certs = diff.fresh.map((f) => f.cert);
    return [
      domainFinding({
        domainId: ctx.domain.id,
        eventType: 'new_cert',
        fingerprint: fingerprint('ct', 'lookalike_certs', lookalike),
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

/** The lookalikes CT should look at: this run's result, else the stored lookalike baseline. */
function lookalikeState(ctx: CollectorContext): SharedLookalikeState | null {
  if (!ctx.domain.collectors.lookalike) return null;
  const fromRun = ctx.earlier.lookalike?.lookalikes;
  if (fromRun) return fromRun;
  const stored = ctx.baselines.lookalike;
  if (stored === undefined || stored === null) return null;
  return { registered: registeredFromSnapshot(stored), newlyRegistered: [] };
}

/** Newly registered first, then never checked, then least recently checked. */
export function selectLookalikesForCt(
  state: SharedLookalikeState,
  checked: Record<string, { checked_at: number }>,
  max: number
): string[] {
  const fresh = new Set(state.newlyRegistered);
  const rank = (name: string): [number, number] =>
    fresh.has(name) ? [0, 0] : checked[name] ? [2, checked[name].checked_at] : [1, 0];
  return [...new Set(state.registered)]
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
    if (ctx.domain.scope === 'own') {
      const certs = await source.certificatesFor(ctx.domain.domain);
      const firstRun = previous?.domain === undefined;
      const policy = normalizedPolicy(ctx.domain.expected_cas ?? []);
      const policyChanged =
        !firstRun && JSON.stringify(previous?.expected_cas ?? []) !== JSON.stringify(policy);
      const diff = diffCertificates(previous?.domain ?? null, certs, nowSeconds);
      next.domain = diff.next;
      next.expected_cas = policy;
      const mode: OwnDomainMode = firstRun ? 'first' : policyChanged ? 'policy_changed' : 'normal';
      findings.push(...ownDomainFindings(ctx, diff, mode, certs));
      details.certificates = certs.length;
      if (firstRun) {
        notes.push(`baseline recorded: ${plural(certs.length, 'unexpired certificate')}`);
      } else {
        details.new_certificates = diff.fresh.length;
        details.renewals = diff.renewals;
        notes.push(
          `${plural(certs.length, 'unexpired certificate')} (${diff.fresh.length} new, ${plural(diff.renewals, 'renewal')})`
        );
      }
    } else if (previous?.domain) {
      next.domain = previous.domain; // scope switched to brand: keep it in case it switches back
      if (previous.expected_cas) next.expected_cas = previous.expected_cas;
    }

    // 2. Certificates for registered lookalikes (both scopes).
    const state = lookalikeState(ctx);
    const storedLookalikes = previous?.lookalikes ?? {};
    if (state) {
      const registered = new Set(state.registered);
      next.lookalikes = Object.fromEntries(
        Object.entries(storedLookalikes).filter(([name]) => registered.has(name))
      );
      // Newly registered now, or earlier but not checked yet (the cap was reached).
      const pending = new Set(
        [...(previous?.pending_new ?? []), ...state.newlyRegistered].filter((n) =>
          registered.has(n)
        )
      );
      const selected = selectLookalikesForCt(
        { registered: state.registered, newlyRegistered: [...pending] },
        storedLookalikes,
        ctx.config.lookalikeCtChecksPerRun
      );
      let checkedOk = 0;
      let firstFailure: CollectorError | null = null;
      for (const lookalike of selected) {
        try {
          const certs = await source.certificatesFor(lookalike);
          const before = storedLookalikes[lookalike] ?? null;
          const diff = diffCertificates(before, certs, nowSeconds);
          next.lookalikes[lookalike] = { ...diff.next, checked_at: nowSeconds };
          findings.push(
            ...lookalikeFindings(ctx, lookalike, diff, before === null, pending.has(lookalike))
          );
          pending.delete(lookalike);
          checkedOk++;
        } catch (err) {
          warnings.push(`${lookalike}: ${errorMessage(err)}`);
          if (err instanceof CollectorError && err.transient) {
            firstFailure = firstFailure ?? err;
            break; // crt.sh is struggling: don't keep asking it this run
          }
        }
      }
      if (ctx.domain.scope === 'brand' && selected.length > 0 && checkedOk === 0 && firstFailure) {
        throw firstFailure; // nothing was checked: retry the whole collector later
      }
      if (pending.size > 0) next.pending_new = [...pending].sort().slice(0, 500);
      details.lookalikes_registered = registered.size;
      details.lookalikes_checked = checkedOk;
      notes.push(
        registered.size === 0
          ? 'no registered lookalikes to check'
          : `${checkedOk} of ${plural(registered.size, 'registered lookalike')} checked this run`
      );
    } else {
      if (previous?.lookalikes) next.lookalikes = previous.lookalikes;
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
