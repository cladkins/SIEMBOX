/**
 * ReDoS (catastrophic-backtracking) scanning for portable parser regexes.
 *
 * Every regex a parser ships runs on the syslog hot path — one bad pattern can
 * pin a CPU on hostile input. This module gathers all of a parser's regex
 * sources (the main `pattern`, plus every `derivations[].extract.pattern` and
 * `derivations[].when.*.matches`) and checks each with `recheck`, the same
 * analyzer the published catalog's CI uses. Sharing the check between the
 * `validate-parsers` CLI (the CI gate), the in-app contribute endpoint, and the
 * AI parser builder means "passes locally" and "passes catalog CI" can never
 * diverge again.
 *
 * This file is the SYNCHRONOUS scan (recheck's checkSync blocks the calling
 * thread until the analysis ends): right for the CLI validators, wrong for a
 * request handler. The app's write-time gate (services/regex/regexSafety) runs
 * the same analysis in a worker thread and reuses the verdict mapping and the
 * message wording below, so the CLI, the contribute check and the gate say the
 * same thing about the same regex.
 *
 * recheck is loaded lazily so the server never fails to boot if it is missing;
 * callers that must not silently skip the gate (CI) pass `required: true`.
 */

export interface RedosFinding {
  /** Where in the parser the regex came from, e.g. "pattern" or "derivations[2].extract.user". */
  location: string;
  source: string;
  flags: string;
  status: 'vulnerable' | 'unknown' | 'error';
  complexity?: string;
  detail?: string;
  /** For a vulnerable regex: recheck's attack string, e.g. `'a'.repeat(31) + '\x00'`. */
  attack?: string;
}

/** Structural shape this module needs from a portable parser. */
interface ScannableParser {
  parser_type?: string;
  pattern?: string;
  derivations?: any[] | null;
}

export interface RegexRef {
  location: string;
  source: string;
  flags: string;
}

/**
 * Time budget for each analysis pass of one regex in the CLI validators
 * (RECHECK_ANALYSIS): recheck's own default, now explicit so the check itself
 * can never hang. A regex the analyzer cannot decide within it is reported as
 * 'unknown' (a warning, never a failure).
 */
export const CLI_REDOS_TIMEOUT_MS = 10_000;

/**
 * recheck's analysis parameters, shared by the CLI scan and the app's worker
 * scan (and part of the gate's checker id, so a change re-analyzes stored
 * verdicts). recheck's defaults miss a whole class of real stalls:
 *
 *  - maxRepeatCount / maxSimpleRepeatCount (default 30): a bounded quantifier
 *    up to that count is expanded and treated as constant, so
 *    ^(?:a|a|a|a|a|a|a|a){1,12}$ is "safe" although 'a'.repeat(10) + '!' costs
 *    8^10 steps (tens of seconds). At 5, any larger bound goes to the fuzzer,
 *    which measures it.
 *  - attackLimit (default 1.5e9 steps): the fuzzer only reports an attack
 *    string past that many steps, tens of seconds of V8 time on ONE line. At
 *    1e7 (tens of milliseconds) a pattern that can be driven that far is
 *    reported.
 *
 * Measured on every regex SIEMBox ships (141 parser, 17 rule regexes): no new
 * finding, and no slower in total.
 *
 * attackLimit applies to the fuzz backend, and the repeat counts decide when
 * 'auto' leaves a regex to it; the automaton backend never sees a large
 * constant cost at all (RECHECK_ANALYSIS).
 */
export const RECHECK_PARAMS = Object.freeze({ attackLimit: 10_000_000, maxRepeatCount: 5, maxSimpleRepeatCount: 5 });

/**
 * How a regex is analyzed (part of the gate's checker id, so verdicts made any
 * other way are redone): recheck's 'auto' first, then, when 'auto' chose the
 * automaton backend and it said safe, the fuzz backend too. The stricter
 * verdict wins.
 *
 * The automaton backend decides how the cost of a match GROWS with the input,
 * so it rates a large but constant cost "safe": ten overlapping fixed-width
 * alternations, ^(?:a|a|a|a|a|a|a|a)(?:a|a|a|a|a|a|a|a)…$ (ten groups, no
 * quantifier), cost 8^10 backtracking steps on 'a'.repeat(10) + '!' (about
 * 14 s in V8, for one 11-byte log line), and recheck's 'auto' picks the
 * automaton for it. The fuzz backend measures the steps a match takes, so it
 * finds such a pattern (and every regex the automaton calls vulnerable is
 * refused without it). Fuzzing is a search, not a proof: it runs with
 * recheck's fixed default seed, so a regex gets the same verdict every time,
 * and the ingest path keeps its own bound (services/regex/linearFallback.ts).
 *
 * Measured on every regex SIEMBox ships (158): no new finding. The pure-JS
 * analyzer (the Alpine image's) took 167 s for all of them instead of 119 s,
 * and no regex the first pass decides took more than 7 s for both passes.
 */
export const RECHECK_ANALYSIS = 'auto+fuzz';

/** Does a first-pass ('auto') result need the fuzz pass? Only an automaton "safe" does. */
export function needsFuzzPass(result: { status?: string; checker?: string } | null | undefined): boolean {
  return result?.status === 'safe' && result?.checker === 'automaton';
}

/**
 * recheck's parameters for one pass of the analysis. Each pass has its own
 * time budget, so one regex costs at most twice `timeoutMs`.
 */
export function recheckParams(pass: 'auto' | 'fuzz', timeoutMs: number): Record<string, unknown> {
  return { ...RECHECK_PARAMS, checker: pass, timeout: timeoutMs };
}

/** What one recheck analysis concluded, independent of where the regex came from. */
export interface RegexVerdict {
  status: 'safe' | 'vulnerable' | 'unknown';
  complexity?: string;
  detail?: string;
  attack?: string;
  /**
   * An 'unknown' that only means the analysis ran out of time (load, a slow
   * analyzer backend), not a fact about the regex: never stored permanently,
   * so it is analyzed again later.
   */
  outOfTime?: boolean;
}

/** recheck's checkSync, or null if the package is unavailable. Cached. */
let checker: ((src: string, flags: string, params?: Record<string, unknown>) => any) | null | undefined;
function getChecker(): ((src: string, flags: string, params?: Record<string, unknown>) => any) | null {
  if (checker === undefined) {
    try {
      // Lazy CJS require: keeps recheck off the startup path and lets the server
      // run without it (the CLI opts into strict "required" mode instead).
      // eslint-disable-next-line @typescript-eslint/no-require-imports -- lazy, optional load (see above)
      const mod = require('recheck');
      checker = typeof mod.checkSync === 'function' ? mod.checkSync : null;
    } catch {
      checker = null;
    }
  }
  return checker ?? null;
}

/** Is the recheck analyzer available in this process? */
export function redosCheckerAvailable(): boolean {
  return getChecker() !== null;
}

/** recheck's `g`/`y` don't affect backtracking; strip them before analysis. */
export function analysisFlags(flags: string): string {
  return flags.replace(/[gy]/g, '');
}

/** Why recheck gave up, in words a user can act on. */
function unknownDetail(error: { kind?: string; message?: string } | undefined): string | undefined {
  switch (error?.kind) {
    case 'timeout':
      return 'the analysis hit its time budget';
    case 'cancel':
      return 'the analysis was cancelled';
    case 'unsupported':
      return `the analyzer does not support this syntax${error.message ? ` (${error.message})` : ''}`;
    case 'invalid':
      return `the analyzer could not parse it${error.message ? ` (${error.message})` : ''}`;
    default:
      return error?.message || undefined;
  }
}

/** Map recheck's Diagnostics object to a verdict. Shared with the worker-thread scan. */
export function verdictFromDiagnostics(result: any): RegexVerdict {
  if (result?.status === 'safe') return { status: 'safe' };
  if (result?.status === 'vulnerable') {
    const c = result.complexity || {};
    const complexity = c.degree != null ? `${c.type}, degree ${c.degree}` : c.type;
    const attack = typeof result.attack?.pattern === 'string' ? result.attack.pattern.slice(0, 200) : undefined;
    return { status: 'vulnerable', complexity, attack };
  }
  const kind = result?.error?.kind;
  const verdict: RegexVerdict = { status: 'unknown', detail: unknownDetail(result?.error) };
  if (kind === 'timeout' || kind === 'cancel') verdict.outOfTime = true;
  return verdict;
}

/**
 * Collect every regex source a parser will compile at runtime.
 *
 * Only string values are collected because only strings are compiled: the
 * runtime (runParser, derive.ts) skips a `pattern`, `extract.*.pattern` or
 * `when.*.matches` that is not a string instead of letting `new RegExp`
 * stringify it, and the write paths refuse one. So what this returns is
 * exactly what can run — an array-wrapped `["^(a+)+$"]` is neither analyzed
 * nor executed.
 */
export function collectParserRegexes(parser: ScannableParser): RegexRef[] {
  const refs: RegexRef[] = [];
  // JSON parsers use `pattern` as an ignored placeholder ("" or ".*"), so only
  // treat the main pattern as a live regex for regex/grok parsers.
  if (parser.parser_type !== 'json' && typeof parser.pattern === 'string' && parser.pattern.length > 0) {
    refs.push({ location: 'pattern', source: parser.pattern, flags: '' });
  }
  const rules = Array.isArray(parser.derivations) ? parser.derivations : [];
  rules.forEach((rule, i) => {
    if (!rule || typeof rule !== 'object') return;
    const extract = rule.extract && typeof rule.extract === 'object' ? rule.extract : {};
    for (const [field, spec] of Object.entries(extract as Record<string, any>)) {
      if (spec && typeof spec.pattern === 'string' && spec.pattern.length > 0) {
        refs.push({ location: `derivations[${i}].extract.${field}`, source: spec.pattern, flags: '' });
      }
    }
    const when = rule.when && typeof rule.when === 'object' ? rule.when : {};
    for (const [field, matcher] of Object.entries(when as Record<string, any>)) {
      if (matcher && typeof matcher.matches === 'string' && matcher.matches.length > 0) {
        // derive.ts always tests `matches` case-insensitively.
        refs.push({ location: `derivations[${i}].when.${field}.matches`, source: matcher.matches, flags: 'i' });
      }
    }
  });
  return refs;
}

/**
 * Scan one regex source. Returns null when it is safe (constant/linear), or a
 * finding when it is vulnerable / indeterminate / errored.
 */
export function scanRegex(
  location: string,
  source: string,
  flags: string,
  opts: { timeoutMs?: number } = {}
): RedosFinding | null {
  const check = getChecker();
  if (!check) {
    return { location, source, flags, status: 'error', detail: 'recheck unavailable' };
  }
  let result: any;
  const timeoutMs = opts.timeoutMs ?? CLI_REDOS_TIMEOUT_MS;
  try {
    // RECHECK_ANALYSIS: 'auto', then the fuzz pass when the automaton said safe.
    result = check(source, analysisFlags(flags), recheckParams('auto', timeoutMs));
    if (needsFuzzPass(result)) result = check(source, analysisFlags(flags), recheckParams('fuzz', timeoutMs));
  } catch (e) {
    return { location, source, flags, status: 'error', detail: e instanceof Error ? e.message : String(e) };
  }
  const verdict = verdictFromDiagnostics(result);
  if (verdict.status === 'safe') return null;
  // The CLI and contribute wording predates `detail`; keep it off unknown findings here.
  return verdict.status === 'vulnerable'
    ? { location, source, flags, status: 'vulnerable', complexity: verdict.complexity, attack: verdict.attack }
    : { location, source, flags, status: 'unknown' };
}

/**
 * Scan all of a parser's regexes.
 *
 * @param opts.required  when true (CI), a missing recheck analyzer is reported
 *   as an error finding instead of being silently skipped.
 */
export function scanParserRedos(
  parser: ScannableParser,
  opts: { required?: boolean; timeoutMs?: number } = {}
): RedosFinding[] {
  return scanRegexRefs(collectParserRegexes(parser), opts);
}

/** Scan a list of regex references (a parser's, or a detection rule's). */
export function scanRegexRefs(refs: RegexRef[], opts: { required?: boolean; timeoutMs?: number } = {}): RedosFinding[] {
  if (!redosCheckerAvailable()) {
    return opts.required
      ? [{ location: 'redos', source: '', flags: '', status: 'error', detail: 'recheck analyzer not installed' }]
      : [];
  }
  const findings: RedosFinding[] = [];
  for (const ref of refs) {
    const f = scanRegex(ref.location, ref.source, ref.flags, { timeoutMs: opts.timeoutMs });
    if (f) findings.push(f);
  }
  return findings;
}

/**
 * The one sentence for a proven-vulnerable regex, used by the contribute check
 * ("before contributing") and by the write-time gate ("before saving").
 */
export function redosErrorMessage(f: RedosFinding, action: 'contributing' | 'saving'): string {
  return `ReDoS: regex at ${f.location} is vulnerable${f.complexity ? ` (${f.complexity})` : ''} — rewrite it linear before ${action}`;
}

/** The one sentence for a regex recheck could not decide. */
export function redosWarningMessage(f: RedosFinding): string {
  return `ReDoS: regex at ${f.location} could not be proven safe (${f.status}${f.detail ? `: ${f.detail}` : ''})`;
}
