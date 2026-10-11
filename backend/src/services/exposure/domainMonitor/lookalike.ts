/**
 * Lookalike / typosquat collector.
 *
 * generateLookalikes() is a native TypeScript permutation engine (no Python in
 * the image). It permutes the registrable label ("example" in
 * mail.example.co.uk) with these fuzzers, in this order — roughly how often
 * each kind of name is registered to deceive:
 *   homoglyph (ASCII: rn/m, vv/w, 0/o, 1/l/i) · tld-swap · omission ·
 *   transposition · repetition · replacement (QWERTY-adjacent keys) ·
 *   hyphenation · vowel-swap · addition · bitsquatting
 * The list is de-duplicated, never contains the domain itself, is identical
 * for identical input, and is HARD-capped (exposure_lookalike_max_candidates,
 * default 300, at most 1000). When `dnstwist` is on the PATH its permutations
 * are appended after the native ones — under the same cap — and never required.
 *
 * Registration check (checkRegistrations): node's resolver, at most 10
 * candidates in flight, a hard deadline per query and per run. NS first: NXDOMAIN
 * means unregistered (one query for most candidates); a delegation means
 * registered, and A/AAAA/MX are then asked to judge how ready it is. Lookups
 * that fail (timeouts, SERVFAIL) leave a candidate "unknown": it keeps whatever
 * state it had, so a flaky resolver never looks like a registration or a drop.
 * One random, certainly-unregistered name per suffix is probed first: where it
 * resolves (a wildcard TLD, or a resolver rewriting NXDOMAIN to an ad server),
 * only an NS delegation counts as a registration.
 *
 * Snapshot: the registered lookalikes (with whether they had an address / MX).
 * Findings (never on the first run, which records the baseline silently):
 *   lookalike_registered — newly registered: high with an A/AAAA or MX record
 *   (a site or a mailbox can go live), medium otherwise; and high when a
 *   registered lookalike gains an MX record (mail-based phishing being prepared).
 */
import { execFile } from 'child_process';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { normalizeDomain } from '../validation';
import { isValidHostname, isValidLabel, splitRegistrable } from './names';
import {
  NODATA,
  NXDOMAIN,
  createResolver,
  mapWithConcurrency,
  timedQuery,
  type DnsResolverLike,
  type QueryOutcome,
} from './resolver';
import {
  CollectorError,
  capList,
  domainFinding,
  fingerprint,
  isPlainObject,
  sortedUnique,
  type Collector,
  type CollectorContext,
  type CollectorOutput,
} from './types';
import type { FindingInput } from '../findingWriter';

export type Fuzzer =
  | 'homoglyph'
  | 'tld-swap'
  | 'omission'
  | 'transposition'
  | 'repetition'
  | 'replacement'
  | 'hyphenation'
  | 'vowel-swap'
  | 'addition'
  | 'bitsquatting'
  | 'dnstwist';

export const FUZZER_ORDER: readonly Exclude<Fuzzer, 'dnstwist'>[] = [
  'homoglyph',
  'tld-swap',
  'omission',
  'transposition',
  'repetition',
  'replacement',
  'hyphenation',
  'vowel-swap',
  'addition',
  'bitsquatting',
];

export const DEFAULT_MAX_CANDIDATES = 300;
export const MAX_CANDIDATES_CEILING = 1000;

export interface LookalikeCandidate {
  domain: string;
  fuzzer: Fuzzer;
}

// Same-row neighbours first (the most common slip), then the row above, then below.
// prettier-ignore
const QWERTY_NEIGHBOURS: Record<string, string> = {
  '1': '2q', '2': '13qw', '3': '24we', '4': '35er', '5': '46rt',
  '6': '57ty', '7': '68yu', '8': '79ui', '9': '80io', '0': '9op',
  q: 'w12a', w: 'qe23as', e: 'wr34sd', r: 'et45df', t: 'ry56fg',
  y: 'tu67gh', u: 'yi78hj', i: 'uo89jk', o: 'ip90kl', p: 'o0l',
  a: 'sqwz', s: 'adwezx', d: 'sferxc', f: 'dgrtcv', g: 'fhtyvb',
  h: 'gjyubn', j: 'hkuinm', k: 'jliom', l: 'kop',
  z: 'xas', x: 'zcsd', c: 'xvdf', v: 'cbfg', b: 'vngh', n: 'bmhj', m: 'njk',
};

// ASCII homoglyphs, most deceptive first. Each pair is applied one occurrence
// at a time, then to every occurrence at once.
const HOMOGLYPHS: ReadonlyArray<readonly [string, string]> = [
  ['m', 'rn'],
  ['rn', 'm'],
  ['l', '1'],
  ['1', 'l'],
  ['o', '0'],
  ['0', 'o'],
  ['i', 'l'],
  ['l', 'i'],
  ['i', '1'],
  ['1', 'i'],
  ['w', 'vv'],
  ['vv', 'w'],
];

const VOWELS = 'aeiou';
const ADDITION_CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789';
/** A small, commonly abused set; the domain's own suffix is skipped. */
// prettier-ignore
export const TLD_SWAPS: readonly string[] = [
  'com', 'net', 'org', 'co', 'io', 'info', 'biz', 'us', 'app', 'online', 'site', 'xyz',
];

function occurrences(s: string, needle: string): number[] {
  const out: number[] = [];
  for (let i = s.indexOf(needle); i !== -1; i = s.indexOf(needle, i + 1)) out.push(i);
  return out;
}

function homoglyphs(s: string): string[] {
  const out: string[] = [];
  for (const [from, to] of HOMOGLYPHS) {
    const at = occurrences(s, from);
    for (const i of at) out.push(s.slice(0, i) + to + s.slice(i + from.length));
    if (at.length > 1) out.push(s.split(from).join(to));
  }
  return out;
}

const LABEL_FUZZERS: Record<Exclude<Fuzzer, 'tld-swap' | 'dnstwist'>, (s: string) => string[]> = {
  homoglyph: homoglyphs,
  omission: (s) => [...s].map((_c, i) => s.slice(0, i) + s.slice(i + 1)),
  transposition: (s) =>
    [...s]
      .slice(0, -1)
      .map((c, i) => (c === s[i + 1] ? '' : s.slice(0, i) + s[i + 1] + c + s.slice(i + 2))),
  repetition: (s) => [...s].map((c, i) => (c === '-' ? '' : s.slice(0, i) + c + s.slice(i))),
  replacement: (s) =>
    [...s].flatMap((c, i) =>
      [...(QWERTY_NEIGHBOURS[c] ?? '')].map((n) => s.slice(0, i) + n + s.slice(i + 1))
    ),
  hyphenation: (s) =>
    [...s]
      .slice(1)
      .map((c, j) => (c === '-' || s[j] === '-' ? '' : s.slice(0, j + 1) + '-' + s.slice(j + 1))),
  'vowel-swap': (s) =>
    [...s].flatMap((c, i) =>
      VOWELS.includes(c)
        ? [...VOWELS].filter((v) => v !== c).map((v) => s.slice(0, i) + v + s.slice(i + 1))
        : []
    ),
  addition: (s) => [...ADDITION_CHARS].map((c) => s + c),
  bitsquatting: (s) =>
    [...s].flatMap((c, i) =>
      Array.from({ length: 8 }, (_unused, bit) => String.fromCharCode(c.charCodeAt(0) ^ (1 << bit)))
        .filter((flipped) => /^[a-z0-9-]$/.test(flipped))
        .map((flipped) => s.slice(0, i) + flipped + s.slice(i + 1))
    ),
};

function tldSwaps(suffix: string): string[] {
  const out = TLD_SWAPS.filter((t) => t !== suffix);
  // example.co.uk -> also example.uk
  const last = suffix.split('.').pop() as string;
  if (suffix.includes('.') && !out.includes(last)) out.push(last);
  return out;
}

export function clampCandidateCap(max: number | undefined): number {
  if (typeof max !== 'number' || !Number.isFinite(max)) return DEFAULT_MAX_CANDIDATES;
  return Math.min(Math.max(Math.floor(max), 0), MAX_CANDIDATES_CEILING);
}

/**
 * Lookalike candidates for the registrable part of `domain`, most likely
 * first, de-duplicated, without the domain itself, and at most `max` long.
 * `extra` (dnstwist output) is appended in sorted order under the same cap.
 */
export function generateLookalikes(
  domain: string,
  options: {
    max?: number;
    extra?: readonly string[];
    /** Names never to return (the organization's other watched domains); applied before the cap. */
    exclude?: Iterable<string>;
  } = {}
): LookalikeCandidate[] {
  const max = clampCandidateCap(options.max);
  const { label, suffix, registrable } = splitRegistrable(domain);
  const out: LookalikeCandidate[] = [];
  const seen = new Set<string>([registrable, ...(options.exclude ?? [])]);
  const add = (name: string, fuzzer: Fuzzer) => {
    if (out.length >= max || seen.has(name) || !isValidHostname(name)) return;
    seen.add(name);
    out.push({ domain: name, fuzzer });
  };

  // Permuting a punycode ("xn--") label would only produce garbage encodings.
  const permutable = !label.startsWith('xn--');
  for (const fuzzer of FUZZER_ORDER) {
    if (out.length >= max) break;
    if (fuzzer === 'tld-swap') {
      for (const tld of tldSwaps(suffix)) add(`${label}.${tld}`, fuzzer);
    } else if (permutable) {
      for (const variant of LABEL_FUZZERS[fuzzer](label)) {
        if (variant && isValidLabel(variant)) add(`${variant}.${suffix}`, fuzzer);
      }
    }
  }
  for (const name of sortedUnique(options.extra ?? [])) add(name, 'dnstwist');
  return out;
}

// ---- dnstwist (optional) -------------------------------------------------------------

export type DnstwistRunner = (domain: string) => Promise<string[]>;

const DNSTWIST_TIMEOUT_MS = 30_000;
const DNSTWIST_MAX_OUTPUT = 4 * 1024 * 1024;
const DETECT_TTL_MS = 10 * 60 * 1000;
let detected: { at: number; path: string | null } | null = null;

/** The absolute path of an executable on PATH, or null. */
export function findOnPath(binary: string, pathEnv = process.env.PATH ?? ''): string | null {
  for (const dir of pathEnv.split(path.delimiter)) {
    if (!dir || !path.isAbsolute(dir)) continue; // never resolve against the working directory
    const candidate = path.join(dir, binary);
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      if (fs.statSync(candidate).isFile()) return candidate;
    } catch {
      // not here
    }
  }
  return null;
}

/**
 * A runner for dnstwist when it is installed (checked every 10 minutes), else
 * null. `--format list` only prints permutations — dnstwist does no DNS
 * lookups of its own, so resolution stays under this module's limits.
 */
export function detectDnstwist(now = Date.now()): DnstwistRunner | null {
  if (!detected || now - detected.at > DETECT_TTL_MS) {
    detected = { at: now, path: findOnPath('dnstwist') };
  }
  const binary = detected.path;
  if (!binary) return null;
  return (domain) =>
    new Promise((resolve, reject) => {
      execFile(
        binary,
        ['--format', 'list', domain],
        { timeout: DNSTWIST_TIMEOUT_MS, maxBuffer: DNSTWIST_MAX_OUTPUT, windowsHide: true },
        (err, stdout) => {
          if (err) {
            reject(new Error(`dnstwist failed: ${err.message.split('\n')[0]}`));
            return;
          }
          const names: string[] = [];
          for (const line of String(stdout).split('\n')) {
            const parsed = normalizeDomain(line);
            if (parsed.ok) names.push(parsed.value);
          }
          resolve(names);
        }
      );
    });
}

// ---- Registration check -----------------------------------------------------------------

export type RegistrationState =
  | { state: 'registered'; ns: boolean; addr: boolean; mx: boolean }
  | { state: 'unregistered' }
  | { state: 'unknown'; reason: string };

export interface RegistrationCheckOptions {
  resolver: DnsResolverLike;
  concurrency?: number;
  /** Hard deadline for each DNS query. */
  queryTimeoutMs?: number;
  /** Candidates not started by then are left unknown. */
  budgetMs?: number;
  now?: () => number;
}

export const DEFAULT_DNS_CONCURRENCY = 10;
const MAX_DNS_CONCURRENCY = 32;
const DEFAULT_QUERY_TIMEOUT_MS = 4_000;
const DEFAULT_REGISTRATION_BUDGET_MS = 3 * 60 * 1000;

const hasRecords = (outcome: QueryOutcome<unknown[]>) => outcome.ok && outcome.value.length > 0;
const isCode = (outcome: QueryOutcome<unknown>, code: string) =>
  !outcome.ok && outcome.code === code;

/**
 * Registration state of one candidate (1 query when unregistered, 4 when
 * registered). Under a suffix that answers for names that do not exist (a
 * wildcard TLD, or a resolver that rewrites NXDOMAIN into an ad server's
 * address), only an NS delegation proves a registration.
 */
export async function checkRegistration(
  name: string,
  resolver: DnsResolverLike,
  queryTimeoutMs = DEFAULT_QUERY_TIMEOUT_MS,
  wildcardSuffix = false
): Promise<RegistrationState> {
  const ns = await timedQuery(() => resolver.resolveNs(name), queryTimeoutMs);
  if (isCode(ns, NXDOMAIN)) return { state: 'unregistered' };
  const [a, aaaa, mx] = await Promise.all([
    timedQuery(() => resolver.resolve4(name), queryTimeoutMs),
    timedQuery(() => resolver.resolve6(name), queryTimeoutMs),
    timedQuery(() => resolver.resolveMx(name), queryTimeoutMs),
  ]);
  const registered = (nsFound: boolean): RegistrationState => ({
    state: 'registered',
    ns: nsFound,
    addr: hasRecords(a) || hasRecords(aaaa),
    mx: mx.ok && mx.value.some((r) => r.exchange !== ''), // a null MX ("0 .") refuses mail
  });
  if (hasRecords(ns)) return registered(true);
  if (wildcardSuffix) {
    return {
      state: 'unknown',
      reason: 'the suffix answers for unregistered names; no NS delegation',
    };
  }
  if (hasRecords(a) || hasRecords(aaaa) || hasRecords(mx)) return registered(false);
  // Conflicting answers (some resolvers answer NODATA for every non-A type):
  // NXDOMAIN on any query wins, so a resolver quirk can't invent a registration.
  if ([a, aaaa, mx].some((q) => isCode(q, NXDOMAIN))) return { state: 'unregistered' };
  // The name exists (NODATA everywhere) but publishes nothing yet.
  if ([ns, a, aaaa, mx].every((q) => q.ok || isCode(q, NODATA))) return registered(false);
  const failed = [ns, a, aaaa, mx].find((q) => !q.ok && q.code !== NODATA);
  return { state: 'unknown', reason: failed && !failed.ok ? failed.code : 'no answer' };
}

const suffixOf = (name: string) => name.slice(name.indexOf('.') + 1);

/**
 * Suffixes under which a random, certainly-unregistered name still resolves:
 * one A query per distinct suffix per run.
 */
export async function findWildcardSuffixes(
  names: readonly string[],
  resolver: DnsResolverLike,
  queryTimeoutMs = DEFAULT_QUERY_TIMEOUT_MS,
  probeLabel = `siembox-nx-${crypto.randomBytes(6).toString('hex')}`
): Promise<Set<string>> {
  const suffixes = sortedUnique(names.map(suffixOf));
  const answers = await mapWithConcurrency(suffixes, 5, (suffix) =>
    timedQuery(() => resolver.resolve4(`${probeLabel}.${suffix}`), queryTimeoutMs)
  );
  return new Set(suffixes.filter((_suffix, i) => hasRecords(answers[i])));
}

export async function checkRegistrations(
  names: readonly string[],
  options: RegistrationCheckOptions
): Promise<Map<string, RegistrationState>> {
  const now = options.now ?? Date.now;
  const startedAt = now();
  const budget = options.budgetMs ?? DEFAULT_REGISTRATION_BUDGET_MS;
  const concurrency = Math.min(
    Math.max(1, Math.floor(options.concurrency ?? DEFAULT_DNS_CONCURRENCY)),
    MAX_DNS_CONCURRENCY
  );
  const wildcards = await findWildcardSuffixes(names, options.resolver, options.queryTimeoutMs);
  const states = await mapWithConcurrency(names, concurrency, async (name) => {
    if (now() - startedAt >= budget) {
      return { state: 'unknown', reason: 'time budget exhausted' } as RegistrationState;
    }
    try {
      return await checkRegistration(
        name,
        options.resolver,
        options.queryTimeoutMs,
        wildcards.has(suffixOf(name))
      );
    } catch (err) {
      return {
        state: 'unknown',
        reason: err instanceof Error ? err.message : String(err),
      } as RegistrationState;
    }
  });
  return new Map(names.map((name, i) => [name, states[i]]));
}

// ---- Snapshot & diff ---------------------------------------------------------------------

interface RegisteredInfo {
  mx: boolean;
  addr: boolean;
  fuzzer: string;
}

export interface LookalikeSnapshot {
  v: 1;
  /** Registered lookalike -> what it had when last resolved. */
  registered: Record<string, RegisteredInfo>;
}

const MAX_SNAPSHOT_REGISTERED = 2 * MAX_CANDIDATES_CEILING;

export function parseLookalikeSnapshot(value: unknown): LookalikeSnapshot | null {
  if (!isPlainObject(value) || value.v !== 1 || !isPlainObject(value.registered)) return null;
  const registered: Record<string, RegisteredInfo> = {};
  for (const [name, info] of Object.entries(value.registered)) {
    if (!isPlainObject(info)) continue;
    registered[name] = {
      mx: info.mx === true,
      addr: info.addr === true,
      fuzzer: typeof info.fuzzer === 'string' ? info.fuzzer : 'unknown',
    };
  }
  return { v: 1, registered };
}

/** The registered lookalikes in a stored snapshot (for the CT collector). */
export function registeredFromSnapshot(value: unknown): string[] {
  return Object.keys(parseLookalikeSnapshot(value)?.registered ?? {}).sort();
}

export interface LookalikeChange {
  domain: string;
  fuzzer: string;
  info: RegisteredInfo;
}

export interface LookalikeDiff {
  next: LookalikeSnapshot;
  /** Registered now, not before (always empty without a previous snapshot). */
  newlyRegistered: LookalikeChange[];
  /** Were registered without an MX record, now have one. */
  mxAdded: LookalikeChange[];
  unknown: number;
  dropped: number;
}

export function diffLookalikes(
  previous: LookalikeSnapshot | null,
  candidates: readonly LookalikeCandidate[],
  states: ReadonlyMap<string, RegistrationState>
): LookalikeDiff {
  // Lookalikes that were not re-checked this run (e.g. the cap was lowered) keep their state.
  const registered: Record<string, RegisteredInfo> = { ...(previous?.registered ?? {}) };
  const newlyRegistered: LookalikeChange[] = [];
  const mxAdded: LookalikeChange[] = [];
  let unknown = 0;
  let dropped = 0;

  for (const { domain, fuzzer } of candidates) {
    const state = states.get(domain);
    if (!state || state.state === 'unknown') {
      unknown++;
      continue;
    }
    if (state.state === 'unregistered') {
      if (registered[domain]) dropped++;
      delete registered[domain];
      continue;
    }
    const before = previous?.registered[domain];
    const info: RegisteredInfo = {
      mx: state.mx,
      addr: state.addr,
      fuzzer: before?.fuzzer ?? fuzzer,
    };
    registered[domain] = info;
    if (!previous) continue; // first run: everything is baseline
    if (!before) newlyRegistered.push({ domain, fuzzer: info.fuzzer, info });
    else if (!before.mx && info.mx) mxAdded.push({ domain, fuzzer: info.fuzzer, info });
  }

  const names = Object.keys(registered).sort().slice(0, MAX_SNAPSHOT_REGISTERED);
  return {
    next: { v: 1, registered: Object.fromEntries(names.map((n) => [n, registered[n]])) },
    newlyRegistered,
    mxAdded,
    unknown,
    dropped,
  };
}

function readiness(info: RegisteredInfo): string {
  const parts = [info.addr ? 'it resolves to an address' : 'no address yet'];
  parts.push(info.mx ? 'it can receive mail (MX)' : 'no MX record');
  return parts.join('; ');
}

function lookalikeFinding(
  ctx: CollectorContext,
  registrable: string,
  change: LookalikeChange,
  kind: 'registered' | 'mx'
): FindingInput {
  const { domain: lookalike, fuzzer, info } = change;
  const severity = kind === 'mx' || info.mx || info.addr ? 'high' : 'medium';
  const title =
    kind === 'mx'
      ? `Lookalike ${lookalike} now has a mail (MX) record`
      : `Lookalike domain registered: ${lookalike} (looks like ${registrable})`;
  const description =
    (kind === 'mx'
      ? `${lookalike}, a registered lookalike of ${registrable}, has started accepting mail. `
      : `${lookalike} — a ${fuzzer} lookalike of ${registrable} — is now registered (${readiness(info)}). `) +
    'An MX record usually means someone is getting ready to send phishing mail. Check who registered it ' +
    '(RDAP/WHOIS), consider blocking it at your mail and web gateways, and request a takedown if it is abusive.';
  return domainFinding({
    domainId: ctx.domain.id,
    eventType: 'lookalike_registered',
    fingerprint: fingerprint('lookalike', kind, registrable, lookalike),
    severity,
    title,
    description,
    detail: {
      collector: 'lookalike',
      domain: ctx.domain.domain,
      registrable,
      lookalike,
      fuzzer,
      has_address: info.addr,
      has_mx: info.mx,
      ...(kind === 'mx' ? { change: 'mx_added' } : {}),
    },
  });
}

export interface LookalikeCollectorDeps {
  resolver?: DnsResolverLike;
  /** undefined: detect dnstwist on PATH; null: never use it. */
  dnstwist?: DnstwistRunner | null;
  concurrency?: number;
  queryTimeoutMs?: number;
  budgetMs?: number;
}

export function createLookalikeCollector(deps: LookalikeCollectorDeps = {}): Collector {
  return async (ctx: CollectorContext): Promise<CollectorOutput> => {
    const { registrable } = splitRegistrable(ctx.domain.domain);
    const previous = parseLookalikeSnapshot(ctx.previous);
    const warnings: string[] = [];

    const dnstwist = deps.dnstwist === undefined ? detectDnstwist() : deps.dnstwist;
    let extra: string[] = [];
    if (dnstwist) {
      try {
        extra = await dnstwist(registrable);
      } catch (err) {
        warnings.push(err instanceof Error ? err.message : String(err));
      }
    }
    // The organization's own watched domains (and their registered names) are not lookalikes.
    const own = (ctx.watchedDomains ?? []).flatMap((d) => [d, splitRegistrable(d).registrable]);
    const candidates = generateLookalikes(registrable, {
      max: ctx.config.lookalikeMaxCandidates,
      extra,
      exclude: own,
    });
    const states = await checkRegistrations(
      candidates.map((c) => c.domain),
      {
        resolver: deps.resolver ?? createResolver(),
        concurrency: deps.concurrency,
        queryTimeoutMs: deps.queryTimeoutMs,
        budgetMs: deps.budgetMs,
      }
    );
    const diff = diffLookalikes(previous, candidates, states);
    if (candidates.length > 0 && diff.unknown === candidates.length) {
      const reasons = sortedUnique(
        [...states.values()].flatMap((s) => (s.state === 'unknown' ? [s.reason] : []))
      );
      throw new CollectorError(
        `DNS lookups failed for every lookalike candidate (${capList(reasons, 3).join(', ')}); will retry`,
        true
      );
    }
    if (diff.unknown > 0)
      warnings.push(`${diff.unknown} candidate(s) could not be resolved this run`);

    const findings = [
      ...diff.newlyRegistered.map((c) => lookalikeFinding(ctx, registrable, c, 'registered')),
      ...diff.mxAdded.map((c) => lookalikeFinding(ctx, registrable, c, 'mx')),
    ];
    const registeredNames = Object.keys(diff.next.registered);
    const note =
      `${candidates.length} candidates checked, ${registeredNames.length} registered` +
      (previous ? ` (${diff.newlyRegistered.length} new)` : ' (baseline recorded)');
    return {
      snapshot: diff.next,
      findings,
      status: previous ? 'ok' : 'baseline',
      note,
      details: {
        registrable,
        candidates: candidates.length,
        registered: registeredNames.length,
        registered_lookalikes: capList(registeredNames, 50),
        unresolved: diff.unknown,
        dnstwist: dnstwist !== null,
      },
      ...(warnings.length ? { warnings } : {}),
      lookalikes: {
        registered: registeredNames,
        newlyRegistered: diff.newlyRegistered.map((c) => c.domain),
      },
    };
  };
}
