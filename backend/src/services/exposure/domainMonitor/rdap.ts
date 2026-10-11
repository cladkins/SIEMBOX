/**
 * RDAP collector: the registry's record of the registered domain — registrar,
 * nameservers, status, DNSSEC and expiry — found through IANA's bootstrap file.
 *
 * Flow: GET https://data.iana.org/rdap/dns.json (constant host; cached 24 h,
 * served stale for up to 7 days if IANA is unreachable) -> the base URL for the
 * longest matching suffix (RFC 9224) -> GET <base>domain/<registrable name>.
 *
 * SSRF: that base URL is external data, so it is validated before use —
 * https only, no credentials, no explicit port, no IP-literal host, no
 * internal-only names (localhost, .local, .internal, .lan, ...) — and its host
 * must resolve to public addresses only (no private, loopback, link-local,
 * CGNAT, ULA, multicast or reserved ranges). The connection is then pinned to
 * addresses vetted at connect time (http.ts), so DNS rebinding can't redirect
 * it. The registrable name, already validated, only ever fills one encoded
 * path segment. Redirects are never followed; responses are capped at 1 MB.
 *
 * TLDs with no RDAP service (or only a plain-http one) degrade gracefully: the
 * collector reports "unsupported" with the reason and raises nothing. A server
 * whose host resolves to a non-public address is refused with an error (that
 * smells of DNS tampering); one that can't be resolved right now is retried.
 *
 * Snapshot: registrar, nameservers (sorted), status (sorted, minus transient
 * grace-period states such as "auto renew period"), DNSSEC. A field the server
 * did not report this time keeps its previous value — missing data is never a
 * change. Changes (never on the first run): nameservers or registrar ->
 * critical (the classic hijack), status or DNSSEC -> high, anything else ->
 * medium. Expiry within exposure_domain_expiry_warning_days -> expiry_warning
 * (medium; high once expired), fingerprinted per expiry date: it alerts once
 * per registration term, including on the first run — a lapsing domain is
 * actionable whatever the history.
 */
import { HttpError, httpsGet, type HttpGet } from './http';
import { registrableDomain, isValidHostname, normalizeName } from './names';
import {
  UnsafeTargetError,
  hostnameRejection,
  resolvePublicAddresses,
  systemLookupAll,
  type LookupAllFn,
} from './netSafety';
import {
  CollectorError,
  domainFinding,
  errorMessage,
  fingerprint,
  isPlainObject,
  sameList,
  sortedUnique,
  type Collector,
  type CollectorContext,
  type CollectorOutput,
} from './types';
import type { ExposureSeverity } from '../../../models/Exposure';
import type { FindingInput } from '../findingWriter';

export const IANA_RDAP_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';
const BOOTSTRAP_TTL_MS = 24 * 60 * 60 * 1000;
const BOOTSTRAP_STALE_MS = 7 * 24 * 60 * 60 * 1000;
const BOOTSTRAP_MAX_BYTES = 2 * 1024 * 1024;
const BOOTSTRAP_TIMEOUT_MS = 20_000;
const RDAP_TIMEOUT_MS = 20_000;
export const RDAP_MAX_BYTES = 1024 * 1024;
const MAX_NAMESERVERS = 20;
const MAX_STATUSES = 30;
const DAY_MS = 86_400_000;

// ---- Bootstrap ------------------------------------------------------------------------

export interface RdapBootstrap {
  /** Suffix ("com", "co.uk") -> its RDAP base URLs, as published. */
  services: Map<string, string[]>;
  publication: string | null;
}

export function parseBootstrap(body: unknown): RdapBootstrap {
  if (!isPlainObject(body) || !Array.isArray(body.services)) {
    throw new CollectorError("IANA's RDAP bootstrap file is malformed; will retry", true);
  }
  const services = new Map<string, string[]>();
  for (const entry of body.services) {
    if (!Array.isArray(entry) || !Array.isArray(entry[0]) || !Array.isArray(entry[1])) continue;
    const urls = entry[1].filter((u): u is string => typeof u === 'string' && u.length <= 2048);
    if (urls.length === 0) continue;
    for (const suffix of entry[0]) {
      if (typeof suffix === 'string' && suffix)
        services.set(normalizeName(suffix).replace(/^\./, ''), urls);
    }
  }
  if (services.size === 0) {
    throw new CollectorError("IANA's RDAP bootstrap file lists no services; will retry", true);
  }
  return {
    services,
    publication: typeof body.publication === 'string' ? body.publication : null,
  };
}

/** RFC 9224 lookup: the longest suffix of `domain` that has an entry. */
export function rdapServersFor(
  bootstrap: RdapBootstrap,
  domain: string
): { suffix: string; urls: string[] } | null {
  const labels = domain.split('.');
  for (let i = 0; i < labels.length; i++) {
    const suffix = labels.slice(i).join('.');
    const urls = bootstrap.services.get(suffix);
    if (urls) return { suffix, urls };
  }
  return null;
}

// ---- Base-URL validation (SSRF) ------------------------------------------------------------

/**
 * Why a base URL can't be used:
 *  - unusable:     the published URL itself breaks the rules (http, IP host, ...)
 *  - unsafe:       its host resolves to a non-public address
 *  - unresolvable: its host could not be resolved right now (retry later)
 */
export type UrlCheck =
  | { ok: true; url: URL }
  | { ok: false; reason: string; kind: 'unusable' | 'unsafe' | 'unresolvable' };

const unusable = (reason: string): UrlCheck => ({ ok: false, reason, kind: 'unusable' });

/** Checks that need no DNS: scheme, credentials, port, host name. */
export function checkRdapBaseUrlSyntax(raw: string): UrlCheck {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return unusable('not a valid URL');
  }
  if (url.protocol !== 'https:') {
    return unusable(`it uses ${url.protocol.replace(/:$/, '')}, not https`);
  }
  if (url.username || url.password) return unusable('it contains credentials');
  if (url.port !== '') return unusable('it uses a non-default port');
  const rejection = hostnameRejection(url.hostname);
  if (rejection) return unusable(rejection);
  if (!url.pathname.endsWith('/')) url.pathname += '/';
  url.search = '';
  url.hash = '';
  return { ok: true, url };
}

/** Syntax checks, then every address the host resolves to must be public. */
export async function validateRdapBaseUrl(
  raw: string,
  lookup: LookupAllFn = systemLookupAll
): Promise<UrlCheck> {
  const syntax = checkRdapBaseUrlSyntax(raw);
  if (!syntax.ok) return syntax;
  try {
    await resolvePublicAddresses(syntax.url.hostname, lookup);
  } catch (err) {
    const retryable = err instanceof UnsafeTargetError && err.retryable;
    return { ok: false, reason: errorMessage(err), kind: retryable ? 'unresolvable' : 'unsafe' };
  }
  return syntax;
}

/** <base>domain/<name>: the name fills exactly one encoded segment under the base path. */
export function rdapDomainUrl(base: URL, domain: string): URL {
  if (!isValidHostname(domain)) throw new UnsafeTargetError(`not a domain name: ${domain}`);
  const url = new URL(`domain/${encodeURIComponent(domain)}`, base);
  if (url.origin !== base.origin || !url.pathname.startsWith(base.pathname)) {
    throw new UnsafeTargetError('the RDAP query URL left the server it was built for');
  }
  return url;
}

// ---- Response parsing ----------------------------------------------------------------------

export interface RdapRegistrar {
  name: string | null;
  iana_id: string | null;
}

export interface RdapDomainInfo {
  ldhName: string | null;
  /** null = not reported by the server (never "removed"). */
  registrar: RdapRegistrar | null;
  nameservers: string[] | null;
  status: string[] | null;
  dnssec: boolean | null;
  registeredAt: string | null;
  expiresAt: string | null;
  lastChangedAt: string | null;
}

/** RFC 8056 status words ("client transfer prohibited"); EPP camelCase is accepted too. */
export function normalizeRdapStatus(value: string): string {
  const words = value
    .trim()
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .replace(/[\s_-]+/g, ' ');
  return words === 'ok' ? 'active' : words;
}

function vcardValue(vcardArray: unknown, property: string): string | null {
  // ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar, Inc."]]]
  if (!Array.isArray(vcardArray) || vcardArray[0] !== 'vcard' || !Array.isArray(vcardArray[1])) {
    return null;
  }
  for (const item of vcardArray[1]) {
    if (!Array.isArray(item) || item[0] !== property) continue;
    const raw = item[3];
    const text = Array.isArray(raw)
      ? raw.filter((v) => typeof v === 'string').join(' ')
      : typeof raw === 'string'
        ? raw
        : '';
    if (text.trim()) return text.trim().slice(0, 200);
  }
  return null;
}

function parseRegistrar(entities: unknown): RdapRegistrar | null {
  if (!Array.isArray(entities)) return null;
  for (const entity of entities.slice(0, 50)) {
    if (
      !isPlainObject(entity) ||
      !Array.isArray(entity.roles) ||
      !entity.roles.includes('registrar')
    ) {
      continue;
    }
    let ianaId: string | null = null;
    if (Array.isArray(entity.publicIds)) {
      for (const id of entity.publicIds) {
        if (
          isPlainObject(id) &&
          typeof id.type === 'string' &&
          /iana registrar id/i.test(id.type) &&
          (typeof id.identifier === 'string' || typeof id.identifier === 'number')
        ) {
          ianaId = String(id.identifier).trim().slice(0, 32) || null;
        }
      }
    }
    const name =
      vcardValue(entity.vcardArray, 'fn') ??
      vcardValue(entity.vcardArray, 'org') ??
      (typeof entity.handle === 'string' ? entity.handle.slice(0, 200) : null);
    if (name || ianaId) return { name, iana_id: ianaId };
  }
  return null;
}

function eventDate(events: unknown, action: string): string | null {
  if (!Array.isArray(events)) return null;
  for (const event of events) {
    if (
      !isPlainObject(event) ||
      event.eventAction !== action ||
      typeof event.eventDate !== 'string'
    ) {
      continue;
    }
    const ms = Date.parse(event.eventDate);
    if (!Number.isNaN(ms)) return new Date(ms).toISOString();
  }
  return null;
}

export function parseRdapDomain(body: unknown): RdapDomainInfo {
  if (!isPlainObject(body)) {
    throw new CollectorError('the RDAP server returned a response in an unexpected format', true);
  }
  if (typeof body.objectClassName === 'string' && body.objectClassName !== 'domain') {
    throw new CollectorError(
      `the RDAP server returned a "${body.objectClassName.slice(0, 40)}" object instead of a domain`,
      false
    );
  }
  const nameservers = Array.isArray(body.nameservers)
    ? sortedUnique(
        body.nameservers
          .map((ns) =>
            isPlainObject(ns) && typeof ns.ldhName === 'string' ? normalizeName(ns.ldhName) : ''
          )
          .filter((ns) => ns && isValidHostname(ns))
      ).slice(0, MAX_NAMESERVERS)
    : [];
  const status = Array.isArray(body.status)
    ? sortedUnique(
        body.status
          .filter((s): s is string => typeof s === 'string' && s.trim().length > 0)
          .map(normalizeRdapStatus)
      ).slice(0, MAX_STATUSES)
    : [];
  const secure = body.secureDNS;
  return {
    ldhName: typeof body.ldhName === 'string' ? normalizeName(body.ldhName) : null,
    registrar: parseRegistrar(body.entities),
    // Some servers leave fields out of a response: that is "not reported", not "removed".
    nameservers: nameservers.length > 0 ? nameservers : null,
    status: status.length > 0 ? status : null,
    dnssec:
      isPlainObject(secure) && typeof secure.delegationSigned === 'boolean'
        ? secure.delegationSigned
        : null,
    registeredAt: eventDate(body.events, 'registration'),
    expiresAt: eventDate(body.events, 'expiration'),
    lastChangedAt: eventDate(body.events, 'last changed'),
  };
}

// ---- Snapshot, diff, expiry ------------------------------------------------------------------

/** Grace periods and in-flight operations come and go on their own; they are not changes. */
export const TRANSIENT_STATUSES: ReadonlySet<string> = new Set([
  'add period',
  'auto renew period',
  'renew period',
  'transfer period',
  'pending renew',
  'pending update',
  'pending create',
]);

export interface RdapSnapshot {
  v: 1;
  registrar: RdapRegistrar | null;
  nameservers: string[] | null;
  status: string[] | null;
  dnssec: boolean | null;
  /** Informational: a renewal moves it and is not a change. */
  expires_at: string | null;
}

export function parseRdapSnapshot(value: unknown): RdapSnapshot | null {
  if (!isPlainObject(value) || value.v !== 1) return null;
  const list = (v: unknown) =>
    Array.isArray(v) ? v.filter((s): s is string => typeof s === 'string') : null;
  const registrar = isPlainObject(value.registrar)
    ? {
        name: typeof value.registrar.name === 'string' ? value.registrar.name : null,
        iana_id: typeof value.registrar.iana_id === 'string' ? value.registrar.iana_id : null,
      }
    : null;
  return {
    v: 1,
    registrar,
    nameservers: list(value.nameservers),
    status: list(value.status),
    dnssec: typeof value.dnssec === 'boolean' ? value.dnssec : null,
    expires_at: typeof value.expires_at === 'string' ? value.expires_at : null,
  };
}

const stableStatus = (status: string[] | null) =>
  status === null ? null : status.filter((s) => !TRANSIENT_STATUSES.has(s));

/** The new baseline: what was reported now, else what was known before. */
export function mergeRdapSnapshot(
  previous: RdapSnapshot | null,
  info: RdapDomainInfo
): RdapSnapshot {
  return {
    v: 1,
    registrar: info.registrar ?? previous?.registrar ?? null,
    nameservers: info.nameservers ?? previous?.nameservers ?? null,
    status: stableStatus(info.status) ?? previous?.status ?? null,
    dnssec: info.dnssec ?? previous?.dnssec ?? null,
    expires_at: info.expiresAt ?? previous?.expires_at ?? null,
  };
}

export type RdapField = 'nameservers' | 'registrar' | 'status' | 'dnssec';

export const RDAP_CHANGE_SEVERITY: Record<RdapField, ExposureSeverity> = {
  nameservers: 'critical',
  registrar: 'critical',
  status: 'high',
  dnssec: 'high',
};

export interface RdapChange {
  field: RdapField;
  severity: ExposureSeverity;
  before: string[];
  after: string[];
}

const registrarKey = (r: RdapRegistrar) => (r.name ?? '').toLowerCase().replace(/[^a-z0-9]/g, '');
const registrarText = (r: RdapRegistrar) =>
  `${r.name ?? 'unknown registrar'}${r.iana_id ? ` (IANA ${r.iana_id})` : ''}`;

function registrarChanged(a: RdapRegistrar, b: RdapRegistrar): boolean {
  // The IANA id identifies a registrar; names get rebranded or re-punctuated.
  if (a.iana_id && b.iana_id) return a.iana_id !== b.iana_id;
  return registrarKey(a) !== registrarKey(b);
}

/** Changes between the stored snapshot and this response (fields reported on both sides only). */
export function diffRdap(previous: RdapSnapshot, info: RdapDomainInfo): RdapChange[] {
  const changes: RdapChange[] = [];
  const change = (field: RdapField, before: string[], after: string[]) =>
    changes.push({ field, severity: RDAP_CHANGE_SEVERITY[field], before, after });

  if (
    previous.nameservers &&
    info.nameservers &&
    !sameList(previous.nameservers, info.nameservers)
  ) {
    change('nameservers', previous.nameservers, info.nameservers);
  }
  if (
    previous.registrar &&
    info.registrar &&
    registrarChanged(previous.registrar, info.registrar)
  ) {
    change('registrar', [registrarText(previous.registrar)], [registrarText(info.registrar)]);
  }
  const status = stableStatus(info.status);
  if (previous.status && status && !sameList(previous.status, status)) {
    change('status', previous.status, status);
  }
  if (previous.dnssec !== null && info.dnssec !== null && previous.dnssec !== info.dnssec) {
    change(
      'dnssec',
      [previous.dnssec ? 'signed' : 'unsigned'],
      [info.dnssec ? 'signed' : 'unsigned']
    );
  }
  return changes;
}

export interface ExpiryState {
  daysLeft: number;
  expired: boolean;
}

/** Non-null when the registration expires within `warningDays` (or already has). */
export function expiryState(
  expiresAt: string | null,
  now: Date,
  warningDays: number
): ExpiryState | null {
  if (!expiresAt) return null;
  const at = Date.parse(expiresAt);
  if (Number.isNaN(at)) return null;
  const daysLeft = Math.floor((at - now.getTime()) / DAY_MS);
  if (daysLeft > warningDays) return null;
  return { daysLeft, expired: at <= now.getTime() };
}

/** One per registration term: the expiry date is part of the fingerprint. */
export function expiryFingerprint(registrable: string, expiresAt: string): string {
  return fingerprint('rdap', 'expiry_warning', registrable, expiresAt.slice(0, 10));
}

export function rdapChangeFingerprint(registrable: string, change: RdapChange): string {
  return fingerprint('rdap', change.field, registrable, change.before, change.after);
}

const FIELD_LABEL: Record<RdapField, string> = {
  nameservers: 'Nameservers',
  registrar: 'Registrar',
  status: 'Registry status',
  dnssec: 'DNSSEC',
};

function changeFinding(
  ctx: CollectorContext,
  registrable: string,
  change: RdapChange
): FindingInput {
  const added = change.after.filter((v) => !change.before.includes(v));
  const removed = change.before.filter((v) => !change.after.includes(v));
  let title = `${FIELD_LABEL[change.field]} changed for ${registrable}`;
  let advice =
    'If nobody in your organization made this change, contact your registrar immediately: ' +
    'registration changes are how domains are hijacked.';
  if (change.field === 'registrar') {
    title = `Registrar changed for ${registrable}: ${change.before[0]} -> ${change.after[0]}`;
  } else if (change.field === 'dnssec') {
    title = `DNSSEC turned ${change.after[0] === 'signed' ? 'on' : 'off'} for ${registrable}`;
  } else if (change.field === 'status' && removed.some((s) => s.endsWith('transfer prohibited'))) {
    title = `Transfer lock removed from ${registrable}`;
    advice =
      'Without a transfer lock the domain can be moved to another registrar; re-lock it unless a transfer is planned.';
  }
  return domainFinding({
    domainId: ctx.domain.id,
    eventType: 'rdap_change',
    fingerprint: rdapChangeFingerprint(registrable, change),
    severity: change.severity,
    title,
    description:
      `The registry's RDAP record for ${registrable} changed (${change.field}): ` +
      `${change.before.join(', ') || 'none'} -> ${change.after.join(', ') || 'none'}. ${advice}`,
    detail: {
      collector: 'rdap',
      domain: ctx.domain.domain,
      registrable,
      field: change.field,
      before: change.before,
      after: change.after,
      added,
      removed,
    },
  });
}

function expiryFinding(
  ctx: CollectorContext,
  registrable: string,
  expiresAt: string,
  state: ExpiryState
): FindingInput {
  const date = expiresAt.slice(0, 10);
  const when = state.expired
    ? `expired on ${date}`
    : state.daysLeft <= 0
      ? `expires today (${date})`
      : `expires in ${state.daysLeft} day${state.daysLeft === 1 ? '' : 's'} (${date})`;
  return domainFinding({
    domainId: ctx.domain.id,
    eventType: 'expiry_warning',
    fingerprint: expiryFingerprint(registrable, expiresAt),
    severity: state.expired ? 'high' : 'medium',
    title: `${registrable} registration ${when}`,
    description:
      `The registry's RDAP record shows ${registrable} ${when}. Renew it (or confirm auto-renewal ` +
      'and the payment method): a lapsed domain can be registered by anyone, along with its mail.',
    detail: {
      collector: 'rdap',
      domain: ctx.domain.domain,
      registrable,
      expires_at: expiresAt,
      days_left: state.daysLeft,
      expired: state.expired,
      warning_days: ctx.config.expiryWarningDays,
    },
  });
}

// ---- Client --------------------------------------------------------------------------------------

export type RdapLookupResult =
  | { kind: 'ok'; info: RdapDomainInfo; server: string }
  | { kind: 'unsupported'; reason: string };

export interface RdapSource {
  lookup(registrable: string): Promise<RdapLookupResult>;
}

export interface RdapClientOptions {
  transport?: HttpGet;
  lookup?: LookupAllFn;
  now?: () => number;
}

function httpFailure(what: string, err: unknown): CollectorError {
  if (err instanceof HttpError && err.kind === 'blocked') {
    return new CollectorError(`refused to contact ${what}: ${err.message}`, false);
  }
  if (err instanceof HttpError && err.kind === 'too_large') {
    return new CollectorError(`${what} sent an oversized response (${err.message})`, false);
  }
  if (err instanceof HttpError && err.kind === 'timeout') {
    return new CollectorError(`${what} did not answer in time; will retry`, true);
  }
  return new CollectorError(
    `${what} could not be reached (${errorMessage(err)}); will retry`,
    true
  );
}

export class RdapClient implements RdapSource {
  private readonly transport: HttpGet;
  private readonly lookupAll: LookupAllFn;
  private readonly now: () => number;
  private cache: { data: RdapBootstrap; fetchedAt: number } | null = null;

  constructor(options: RdapClientOptions = {}) {
    this.transport = options.transport ?? httpsGet;
    this.lookupAll = options.lookup ?? systemLookupAll;
    this.now = options.now ?? Date.now;
  }

  /** The bootstrap file: cached for a day, and served stale for a week if IANA is down. */
  async bootstrap(): Promise<RdapBootstrap> {
    const age = this.cache ? this.now() - this.cache.fetchedAt : Infinity;
    if (this.cache && age < BOOTSTRAP_TTL_MS) return this.cache.data;
    try {
      const data = await this.fetchBootstrap();
      this.cache = { data, fetchedAt: this.now() };
      return data;
    } catch (err) {
      if (this.cache && age < BOOTSTRAP_STALE_MS) return this.cache.data;
      throw err;
    }
  }

  private async fetchBootstrap(): Promise<RdapBootstrap> {
    const what = "IANA's RDAP bootstrap file";
    let res;
    try {
      res = await this.transport(new URL(IANA_RDAP_BOOTSTRAP_URL), {
        timeoutMs: BOOTSTRAP_TIMEOUT_MS,
        maxBytes: BOOTSTRAP_MAX_BYTES,
      });
    } catch (err) {
      throw httpFailure(what, err);
    }
    if (res.status !== 200) {
      throw new CollectorError(
        `${what} could not be downloaded (HTTP ${res.status}); will retry`,
        true
      );
    }
    try {
      return parseBootstrap(JSON.parse(res.body.toString('utf8')));
    } catch (err) {
      if (err instanceof CollectorError) throw err;
      throw new CollectorError(`${what} is not valid JSON; will retry`, true);
    }
  }

  async lookup(registrable: string): Promise<RdapLookupResult> {
    const bootstrap = await this.bootstrap();
    const tld = registrable.split('.').pop() as string;
    const servers = rdapServersFor(bootstrap, registrable);
    if (!servers) {
      return { kind: 'unsupported', reason: `no RDAP service is published for .${tld}` };
    }
    // Prefer https entries; validate each until one passes.
    const ordered = [...servers.urls].sort(
      (a, b) => Number(!a.startsWith('https:')) - Number(!b.startsWith('https:'))
    );
    const failures: Array<Extract<UrlCheck, { ok: false }>> = [];
    let base: URL | null = null;
    for (const raw of ordered) {
      const check = await validateRdapBaseUrl(raw, this.lookupAll);
      if (check.ok) {
        base = check.url;
        break;
      }
      failures.push(check);
    }
    if (!base) {
      const server = `the RDAP server for .${servers.suffix}`;
      const reasons = (kind: string) =>
        failures
          .filter((f) => f.kind === kind)
          .map((f) => f.reason)
          .join('; ');
      if (failures.some((f) => f.kind === 'unresolvable')) {
        throw new CollectorError(`${server}: ${reasons('unresolvable')}; will retry`, true);
      }
      if (failures.some((f) => f.kind === 'unsafe')) {
        // Suspicious (DNS poisoning, a split-horizon resolver): an error the operator sees.
        throw new CollectorError(`refused to contact ${server}: ${reasons('unsafe')}`, false);
      }
      return {
        kind: 'unsupported',
        reason: `${server} can't be used safely (${reasons('unusable')})`,
      };
    }

    const what = `the RDAP server for .${servers.suffix} (${base.hostname})`;
    const url = rdapDomainUrl(base, registrable);
    let res;
    try {
      res = await this.transport(url, {
        timeoutMs: RDAP_TIMEOUT_MS,
        maxBytes: RDAP_MAX_BYTES,
        headers: { Accept: 'application/rdap+json, application/json' },
        // Pin the connection to addresses vetted at connect time (no DNS rebinding).
        resolve: (host) => resolvePublicAddresses(host, this.lookupAll),
      });
    } catch (err) {
      throw httpFailure(what, err);
    }
    if (res.status === 404) {
      throw new CollectorError(`${what} has no record of ${registrable}; is it registered?`, false);
    }
    if (res.status === 429 || res.status >= 500) {
      throw new CollectorError(
        `${what} is temporarily unavailable (HTTP ${res.status}); will retry`,
        true
      );
    }
    if (res.status !== 200) {
      const redirect = res.status >= 300 && res.status < 400;
      throw new CollectorError(
        `${what} answered HTTP ${res.status}${redirect ? ' (redirects are not followed)' : ''}`,
        false
      );
    }
    let body: unknown;
    try {
      body = JSON.parse(res.body.toString('utf8'));
    } catch {
      throw new CollectorError(`${what} returned a response that is not JSON; will retry`, true);
    }
    return { kind: 'ok', info: parseRdapDomain(body), server: base.hostname };
  }
}

// ---- Collector -------------------------------------------------------------------------------------

// One client per process, so the bootstrap cache is shared by every domain.
const sharedClient = new RdapClient();

export interface RdapCollectorDeps {
  source?: RdapSource;
}

export function createRdapCollector(deps: RdapCollectorDeps = {}): Collector {
  return async (ctx: CollectorContext): Promise<CollectorOutput> => {
    const source = deps.source ?? sharedClient;
    const registrable = registrableDomain(ctx.domain.domain);
    const result = await source.lookup(registrable);
    if (result.kind === 'unsupported') {
      return {
        findings: [],
        status: 'unsupported',
        note: `${result.reason}; registration changes and expiry can't be monitored for ${registrable}`,
      };
    }
    const { info } = result;
    const previous = parseRdapSnapshot(ctx.previous);
    const findings: FindingInput[] = [];

    const expiry = expiryState(info.expiresAt, ctx.now, ctx.config.expiryWarningDays);
    if (expiry && info.expiresAt)
      findings.push(expiryFinding(ctx, registrable, info.expiresAt, expiry));
    if (previous) {
      for (const change of diffRdap(previous, info))
        findings.push(changeFinding(ctx, registrable, change));
    }

    const daysLeft = info.expiresAt
      ? Math.floor((Date.parse(info.expiresAt) - ctx.now.getTime()) / DAY_MS)
      : null;
    const noteParts = [
      info.registrar ? `registrar ${registrarText(info.registrar)}` : 'registrar not reported',
      `${info.nameservers?.length ?? 0} nameservers`,
      info.expiresAt
        ? `expires ${info.expiresAt.slice(0, 10)} (${daysLeft} days)`
        : 'no expiry date reported',
    ];
    if (!previous) noteParts.push('baseline recorded');
    return {
      snapshot: mergeRdapSnapshot(previous, info),
      findings,
      status: previous ? 'ok' : 'baseline',
      note: noteParts.join('; '),
      details: {
        registrable,
        server: result.server,
        registrar: info.registrar,
        nameservers: info.nameservers ?? [],
        status: info.status ?? [],
        dnssec: info.dnssec,
        registered_at: info.registeredAt,
        expires_at: info.expiresAt,
        last_changed_at: info.lastChangedAt,
        days_left: daysLeft,
      },
    };
  };
}
