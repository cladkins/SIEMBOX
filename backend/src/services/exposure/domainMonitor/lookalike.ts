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
 * registered, and A/AAAA/MX are then asked to judge how ready it is (each of
 * those is true, false, or null when its lookup failed). Lookups that fail
 * (timeouts, SERVFAIL) leave a candidate "unknown": it keeps whatever state it
 * had, so a flaky resolver never looks like a registration or a drop. One
 * random, certainly-unregistered name per suffix is probed first: only a
 * definite NXDOMAIN for it clears the suffix; where it resolves (a wildcard
 * TLD, or a resolver rewriting NXDOMAIN to an ad server) or the probe fails,
 * only an NS delegation counts as a registration. There, when the resolver
 * returns the suffix's own NS records (so it answers NS queries), NODATA for a
 * candidate's NS means "not delegated", which confirms it unregistered.
 *
 * Snapshot: the registered lookalikes (whether they had an address / MX, when
 * they were last seen registered and when they were reported as newly
 * registered), the candidates confirmed unregistered, and registered ones that
 * recently stopped resolving (with what was known about them when they did).
 * Findings:
 *   lookalike_registered — a registration of a name that was confirmed
 *   unregistered before: high with an A/AAAA or MX record (a site or a mailbox
 *   can go live), medium otherwise; and high when a registered lookalike that
 *   had no MX record gains one (mail-based phishing being prepared).
 * A name seen registered on its first definite answer — the first run, a
 * raised candidate cap, dnstwist appearing, a lookup that failed until now —
 * is recorded silently: nobody knows when it was registered. So is one that
 * comes back within REAPPEAR_GRACE_DAYS of when it was last seen registered (a
 * registry hold lifted, or a flapping answer): it is the same registration, and
 * carries on from what was known when it dropped (an MX record added meanwhile
 * is reported; its fingerprints stay its own). One that comes back later may
 * have a new owner: it is reported, and its findings are fingerprinted apart
 * from the earlier registration's.
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
  type SharedLookalikeState,
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

/**
 * `addr` / `mx`: true, false, or null when the lookups that would tell failed.
 * `undelegated`: no NS delegation (NODATA) under a wildcard suffix whose
 * resolver answers NS queries — not registered as far as DNS can tell. It
 * confirms a candidate unregistered, but never drops a registered lookalike
 * (see diffLookalikes).
 */
export type RegistrationState =
  | { state: 'registered'; ns: boolean; addr: boolean | null; mx: boolean | null }
  | { state: 'unregistered' }
  | { state: 'undelegated' }
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
/** An answer that settles the question: records, NODATA or NXDOMAIN (not a timeout or SERVFAIL). */
const isDefinite = (outcome: QueryOutcome<unknown>) =>
  outcome.ok || isCode(outcome, NODATA) || isCode(outcome, NXDOMAIN);

/**
 * Registration state of one candidate (1 query when unregistered, 4 when
 * registered). Under a suffix that answers for names that do not exist (a
 * wildcard TLD, or a resolver that rewrites NXDOMAIN into an ad server's
 * address), only an NS delegation proves a registration; when the resolver is
 * known to answer NS queries there (`nsAnswered`), NODATA for NS is a definite
 * "not delegated".
 */
export async function checkRegistration(
  name: string,
  resolver: DnsResolverLike,
  queryTimeoutMs = DEFAULT_QUERY_TIMEOUT_MS,
  wildcardSuffix = false,
  nsAnswered = false
): Promise<RegistrationState> {
  const ns = await timedQuery(() => resolver.resolveNs(name), queryTimeoutMs);
  if (isCode(ns, NXDOMAIN)) return { state: 'unregistered' };
  if (wildcardSuffix && nsAnswered && isCode(ns, NODATA)) return { state: 'undelegated' };
  const [a, aaaa, mx] = await Promise.all([
    timedQuery(() => resolver.resolve4(name), queryTimeoutMs),
    timedQuery(() => resolver.resolve6(name), queryTimeoutMs),
    timedQuery(() => resolver.resolveMx(name), queryTimeoutMs),
  ]);
  // A failed A/AAAA/MX lookup is "don't know", never "none": storing it as
  // "no MX" would make the next good answer look like an MX record being added.
  const registered = (nsFound: boolean): RegistrationState => ({
    state: 'registered',
    ns: nsFound,
    addr:
      hasRecords(a) || hasRecords(aaaa) ? true : isDefinite(a) && isDefinite(aaaa) ? false : null,
    mx: mx.ok
      ? mx.value.some((r) => r.exchange !== '') // a null MX ("0 .") refuses mail
      : isDefinite(mx)
        ? false
        : null,
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
 * Suffixes under which only an NS delegation proves a registration: one A
 * query per distinct suffix per run for a random, certainly-unregistered name.
 * Only a definite NXDOMAIN clears a suffix. An answer (a wildcard TLD, or a
 * resolver rewriting NXDOMAIN to an ad server) or a failed probe (a timeout,
 * SERVFAIL) does not: one lost probe must not turn every candidate under the
 * suffix into a registration.
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
  return new Set(suffixes.filter((_suffix, i) => !isCode(answers[i], NXDOMAIN)));
}

/**
 * Of the wildcard suffixes, those whose own NS records the resolver returns:
 * it answers NS queries there, so NODATA for a name's NS means "not
 * delegated". A resolver that answers NODATA for every non-A type (they exist)
 * fails this, and its NODATA proves nothing.
 */
export async function suffixesAnsweringNs(
  wildcards: ReadonlySet<string>,
  resolver: DnsResolverLike,
  queryTimeoutMs = DEFAULT_QUERY_TIMEOUT_MS
): Promise<Set<string>> {
  const suffixes = [...wildcards].sort();
  const answers = await mapWithConcurrency(suffixes, 5, (suffix) =>
    timedQuery(() => resolver.resolveNs(suffix), queryTimeoutMs)
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
  const nsAnswered = await suffixesAnsweringNs(wildcards, options.resolver, options.queryTimeoutMs);
  const states = await mapWithConcurrency(names, concurrency, async (name) => {
    if (now() - startedAt >= budget) {
      return { state: 'unknown', reason: 'time budget exhausted' } as RegistrationState;
    }
    try {
      const suffix = suffixOf(name);
      return await checkRegistration(
        name,
        options.resolver,
        options.queryTimeoutMs,
        wildcards.has(suffix),
        nsAnswered.has(suffix)
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

const DAY_SECONDS = 86_400;
/**
 * A registered lookalike that goes NXDOMAIN and is back within this many days
 * of when it was last seen registered is the same registration (a registry
 * hold lifted, or one flapping answer). A lapsed gTLD name stays NXDOMAIN for
 * longer than this (30 days of redemption plus 5 of pending delete) before
 * anyone else can register it, and it went NXDOMAIN after it was last seen
 * registered — however long the domain's interval is.
 */
export const REAPPEAR_GRACE_DAYS = 30;
/** How long a reported registration counts as "newly registered" for the CT collector. */
export const NEW_REGISTRATION_WINDOW_DAYS = 30;

/** A lookalike last seen registered at `droppedAt` that is back by `nowSeconds` is the same registration. */
export function withinReappearGrace(droppedAt: number, nowSeconds: number): boolean {
  return nowSeconds - droppedAt <= REAPPEAR_GRACE_DAYS * DAY_SECONDS;
}

export interface RegisteredInfo {
  /** null: the lookup failed every time so far (unknown, never "none"). */
  mx: boolean | null;
  addr: boolean | null;
  fuzzer: string;
  /** When it was reported as newly registered (epoch seconds); null when recorded silently. */
  since: number | null;
  /** When it last had a definite registered answer (epoch seconds); null in older snapshots. */
  seen_at: number | null;
  /**
   * Registered again after it had dropped: the `dropped` time of that drop,
   * which tells this registration's findings apart from an earlier owner's
   * (it is part of their fingerprints). null for a name never seen dropping.
   */
  prior_drop: number | null;
}

export interface LookalikeSnapshot {
  v: 1;
  /** Registered lookalike -> what it had when last resolved. */
  registered: Record<string, RegisteredInfo>;
  /**
   * Candidates with a definite "not registered" answer (NXDOMAIN, or no
   * delegation under a wildcard suffix) -> since when (epoch seconds). Only a
   * name confirmed unregistered can later be reported as newly registered.
   */
  unregistered: Record<string, number>;
  /**
   * Registered lookalikes that went NXDOMAIN -> when they were last seen
   * registered (epoch seconds; the first NXDOMAIN answer in older snapshots).
   */
  dropped: Record<string, number>;
  /**
   * Dropped lookalikes -> the registration as it was when it dropped, so one
   * back within REAPPEAR_GRACE_DAYS carries on as the same registration (its
   * prior_drop marker, its since for the CT hand-off, its MX/address state).
   * Only names in `dropped` have one; absent when empty and in older snapshots.
   */
  dropped_info?: Record<string, RegisteredInfo>;
}

const MAX_SNAPSHOT_REGISTERED = 2 * MAX_CANDIDATES_CEILING;

const optionalBoolean = (value: unknown): boolean | null =>
  typeof value === 'boolean' ? value : null;
const optionalEpoch = (value: unknown): number | null =>
  typeof value === 'number' && Number.isFinite(value) ? value : null;

function epochMap(value: unknown): Record<string, number> {
  if (!isPlainObject(value)) return {};
  return Object.fromEntries(
    Object.entries(value).filter(
      (entry): entry is [string, number] =>
        typeof entry[1] === 'number' && Number.isFinite(entry[1])
    )
  );
}

function parseRegisteredInfo(info: Record<string, unknown>): RegisteredInfo {
  return {
    mx: optionalBoolean(info.mx),
    addr: optionalBoolean(info.addr),
    fuzzer: typeof info.fuzzer === 'string' ? info.fuzzer : 'unknown',
    since: optionalEpoch(info.since),
    seen_at: optionalEpoch(info.seen_at),
    prior_drop: optionalEpoch(info.prior_drop),
  };
}

export function parseLookalikeSnapshot(value: unknown): LookalikeSnapshot | null {
  if (!isPlainObject(value) || value.v !== 1 || !isPlainObject(value.registered)) return null;
  const registered: Record<string, RegisteredInfo> = {};
  for (const [name, info] of Object.entries(value.registered)) {
    if (isPlainObject(info)) registered[name] = parseRegisteredInfo(info);
  }
  const dropped = epochMap(value.dropped);
  const droppedInfo: Record<string, RegisteredInfo> = {};
  if (isPlainObject(value.dropped_info)) {
    for (const [name, info] of Object.entries(value.dropped_info)) {
      if (isPlainObject(info) && Object.prototype.hasOwnProperty.call(dropped, name)) {
        droppedInfo[name] = parseRegisteredInfo(info);
      }
    }
  }
  return {
    v: 1,
    registered,
    unregistered: epochMap(value.unregistered),
    dropped,
    ...(Object.keys(droppedInfo).length ? { dropped_info: droppedInfo } : {}),
  };
}

/** The registered lookalikes in a stored snapshot. */
export function registeredFromSnapshot(value: unknown): string[] {
  return Object.keys(parseLookalikeSnapshot(value)?.registered ?? {}).sort();
}

/**
 * What the CT collector needs from a lookalike snapshot: every registered
 * lookalike, those reported as newly registered in the last
 * NEW_REGISTRATION_WINDOW_DAYS, those registered again after a drop (the
 * drop, and when that registration was reported), and those on hold (dropped,
 * but still within the comeback grace). Read from the stored snapshot, the
 * hand-off survives a run in which CT failed or did not run.
 */
export function lookalikeStateFromSnapshot(
  value: unknown,
  nowSeconds: number
): SharedLookalikeState {
  const snapshot = parseLookalikeSnapshot(value);
  const registered = snapshot?.registered ?? {};
  const names = Object.keys(registered).sort();
  const recent = nowSeconds - NEW_REGISTRATION_WINDOW_DAYS * DAY_SECONDS;
  const priorDrops: Record<string, number> = {};
  const reregisteredAt: Record<string, number> = {};
  for (const name of names) {
    const { prior_drop: priorDrop, since } = registered[name];
    if (priorDrop === null) continue;
    priorDrops[name] = priorDrop;
    if (since !== null) reregisteredAt[name] = since;
  }
  const held = Object.entries(snapshot?.dropped ?? {})
    .filter(([name, at]) => !registered[name] && withinReappearGrace(at, nowSeconds))
    .map(([name]) => name)
    .sort();
  return {
    registered: names,
    newlyRegistered: names.filter((name) => {
      const since = registered[name].since;
      return since !== null && since >= recent;
    }),
    ...(Object.keys(priorDrops).length ? { priorDrops } : {}),
    ...(Object.keys(reregisteredAt).length ? { reregisteredAt } : {}),
    ...(held.length ? { held } : {}),
  };
}

/** Fingerprint parts that tell a registration after a drop apart from earlier ones. */
export function registrationMarker(priorDrop: number | null | undefined): number[] {
  return priorDrop === null || priorDrop === undefined ? [] : [priorDrop];
}

/** The organization's own names (every watched domain and its registered name): never lookalikes. */
export function ownDomainNames(watchedDomains: readonly string[] | undefined): Set<string> {
  return new Set((watchedDomains ?? []).flatMap((d) => [d, splitRegistrable(d).registrable]));
}

export interface LookalikeChange {
  domain: string;
  fuzzer: string;
  info: RegisteredInfo;
}

export interface LookalikeDiff {
  next: LookalikeSnapshot;
  /** Registered now, and confirmed unregistered (or long gone) before. */
  newlyRegistered: LookalikeChange[];
  /** Were registered without an MX record, now have one. */
  mxAdded: LookalikeChange[];
  unknown: number;
  dropped: number;
}

export interface LookalikeDiffOptions {
  /** This run's time, epoch seconds. */
  nowSeconds: number;
  /** Names that are never lookalikes (the organization's own, see ownDomainNames). */
  exclude?: ReadonlySet<string>;
  /**
   * This run's candidate list is incomplete (dnstwist failed): names the
   * previous snapshot knew as unregistered or dropped that are not candidates
   * now keep that state — a failed lookup is never a state change.
   */
  keepUnlisted?: boolean;
}

export function diffLookalikes(
  previous: LookalikeSnapshot | null,
  candidates: readonly LookalikeCandidate[],
  states: ReadonlyMap<string, RegistrationState>,
  options: LookalikeDiffOptions
): LookalikeDiff {
  const { nowSeconds } = options;
  const exclude = options.exclude ?? new Set<string>();
  // Lookalikes that were not re-checked this run (e.g. the cap was lowered)
  // keep their state; the organization's own names never stay in the list.
  const registered: Record<string, RegisteredInfo> = {};
  for (const [name, info] of Object.entries(previous?.registered ?? {})) {
    if (!exclude.has(name)) registered[name] = info;
  }
  // Rebuilt from this run's candidates, so both stay bounded by the candidate
  // cap; an incomplete list keeps the previous entries for the names it lacks.
  const unregistered: Record<string, number> = {};
  const dropped: Record<string, number> = {};
  const droppedInfo: Record<string, RegisteredInfo> = {};
  /** A drop the previous snapshot knew about, with the registration it ended. */
  const keepDropped = (name: string, at: number) => {
    dropped[name] = at;
    const info = previous?.dropped_info?.[name];
    if (info) droppedInfo[name] = info;
  };
  if (options.keepUnlisted && previous) {
    const listed = new Set(candidates.map((c) => c.domain));
    const unlisted = (name: string) => !listed.has(name) && !exclude.has(name);
    for (const [name, at] of Object.entries(previous.unregistered)) {
      if (unlisted(name)) unregistered[name] = at;
    }
    for (const [name, at] of Object.entries(previous.dropped)) {
      if (unlisted(name)) keepDropped(name, at);
    }
  }
  const newlyRegistered: LookalikeChange[] = [];
  const mxAdded: LookalikeChange[] = [];
  let unknown = 0;
  let droppedNow = 0;

  for (const { domain, fuzzer } of candidates) {
    const state = states.get(domain);
    const unregisteredSince = previous?.unregistered[domain];
    const droppedAt = previous?.dropped[domain];
    // No delegation under a wildcard suffix never drops a registered lookalike
    // (only NXDOMAIN does): it stays as it was.
    if (state?.state === 'undelegated' && registered[domain]) continue;
    if (!state || state.state === 'unknown') {
      // Not answered this run: whatever was known stays known.
      unknown++;
      if (unregisteredSince !== undefined) unregistered[domain] = unregisteredSince;
      if (droppedAt !== undefined) keepDropped(domain, droppedAt);
      continue;
    }
    if (state.state === 'unregistered' || state.state === 'undelegated') {
      if (registered[domain]) {
        droppedNow++;
        // The grace before a comeback counts as a new registration runs from
        // when it was last seen registered, not from when the drop was noticed.
        dropped[domain] = registered[domain].seen_at ?? nowSeconds;
        droppedInfo[domain] = registered[domain];
        delete registered[domain];
      } else if (droppedAt !== undefined) {
        keepDropped(domain, droppedAt);
      } else {
        unregistered[domain] = unregisteredSince ?? nowSeconds;
      }
      continue;
    }

    // Back within the grace: the same registration (a hold lifted, or one
    // flapping answer), so it carries on from what was known when it dropped —
    // its prior_drop marker, its since, and its MX state to compare against.
    const sameRegistration =
      !registered[domain] && droppedAt !== undefined && withinReappearGrace(droppedAt, nowSeconds);
    const before =
      registered[domain] ?? (sameRegistration ? previous?.dropped_info?.[domain] : undefined);
    const info: RegisteredInfo = {
      // A lookup that failed this time keeps what was known.
      mx: state.mx ?? before?.mx ?? null,
      addr: state.addr ?? before?.addr ?? null,
      fuzzer: before?.fuzzer ?? fuzzer,
      since: before?.since ?? null,
      seen_at: nowSeconds,
      prior_drop: before?.prior_drop ?? null,
    };
    if (before) {
      if (before.mx === false && info.mx === true) {
        mxAdded.push({ domain, fuzzer: info.fuzzer, info });
      }
    } else if (sameRegistration) {
      // Back from a hold, from a snapshot that didn't keep what it had: restored silently.
    } else if (unregisteredSince !== undefined || droppedAt !== undefined) {
      info.since = nowSeconds;
      // Back after a drop: possibly a new owner, so its findings get their own
      // fingerprints. droppedAt comes from the stored baseline, so a re-run
      // after a crash still produces the same ones.
      if (droppedAt !== undefined) info.prior_drop = droppedAt;
      newlyRegistered.push({ domain, fuzzer: info.fuzzer, info });
    }
    // Otherwise this is the first definite answer for the name (the first run,
    // a raised cap, dnstwist appearing, a lookup failing until now): nobody
    // knows when it was registered, so it is recorded silently.
    registered[domain] = info;
  }

  const names = Object.keys(registered).sort().slice(0, MAX_SNAPSHOT_REGISTERED);
  return {
    next: {
      v: 1,
      registered: Object.fromEntries(names.map((n) => [n, registered[n]])),
      unregistered,
      dropped,
      ...(Object.keys(droppedInfo).length ? { dropped_info: droppedInfo } : {}),
    },
    newlyRegistered,
    mxAdded,
    unknown,
    dropped: droppedNow,
  };
}

function readiness(info: RegisteredInfo): string {
  const parts = [
    info.addr === null
      ? 'its address lookup failed'
      : info.addr
        ? 'it resolves to an address'
        : 'no address yet',
  ];
  parts.push(
    info.mx === null
      ? 'its MX lookup failed'
      : info.mx
        ? 'it can receive mail (MX)'
        : 'no MX record'
  );
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
    // A registration after a drop has its own marker: a new owner alerts again.
    fingerprint: fingerprint(
      'lookalike',
      kind,
      registrable,
      lookalike,
      ...registrationMarker(info.prior_drop)
    ),
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
    let dnstwistFailed = false;
    if (dnstwist) {
      try {
        extra = await dnstwist(registrable);
      } catch (err) {
        dnstwistFailed = true;
        warnings.push(err instanceof Error ? err.message : String(err));
      }
    }
    // The organization's own watched domains (and their registered names) are not lookalikes.
    const own = ownDomainNames(ctx.watchedDomains);
    const nowSeconds = Math.floor(ctx.now.getTime() / 1000);
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
    const diff = diffLookalikes(previous, candidates, states, {
      nowSeconds,
      exclude: own,
      // Its candidates are missing this run, not gone: they keep what was known about them.
      keepUnlisted: dnstwistFailed,
    });
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
      lookalikes: lookalikeStateFromSnapshot(diff.next, nowSeconds),
    };
  };
}
