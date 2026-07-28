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
}

/** Structural shape this module needs from a portable parser. */
interface ScannableParser {
  parser_type?: string;
  pattern?: string;
  derivations?: any[] | null;
}

interface RegexRef {
  location: string;
  source: string;
  flags: string;
}

/** recheck's checkSync, or null if the package is unavailable. Cached. */
let checker: ((src: string, flags: string) => any) | null | undefined;
function getChecker(): ((src: string, flags: string) => any) | null {
  if (checker === undefined) {
    try {
      // Lazy CJS require: keeps recheck off the startup path and lets the server
      // run without it (the CLI opts into strict "required" mode instead).
      // eslint-disable-next-line @typescript-eslint/no-var-requires
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

/** Collect every regex source a parser will compile at runtime. */
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
export function scanRegex(location: string, source: string, flags: string): RedosFinding | null {
  const check = getChecker();
  if (!check) {
    return { location, source, flags, status: 'error', detail: 'recheck unavailable' };
  }
  let result: any;
  try {
    result = check(source, flags.replace(/[gy]/g, '')); // g/y don't affect backtracking analysis
  } catch (e) {
    return { location, source, flags, status: 'error', detail: e instanceof Error ? e.message : String(e) };
  }
  if (result?.status === 'safe') return null;
  const c = result?.complexity || {};
  const complexity = c.degree != null ? `${c.type} (degree ${c.degree})` : c.type;
  return { location, source, flags, status: result?.status === 'vulnerable' ? 'vulnerable' : 'unknown', complexity };
}

/**
 * Scan all of a parser's regexes.
 *
 * @param opts.required  when true (CI), a missing recheck analyzer is reported
 *   as an error finding instead of being silently skipped.
 */
export function scanParserRedos(
  parser: ScannableParser,
  opts: { required?: boolean } = {}
): RedosFinding[] {
  if (!redosCheckerAvailable()) {
    return opts.required
      ? [{ location: 'redos', source: '', flags: '', status: 'error', detail: 'recheck analyzer not installed' }]
      : [];
  }
  const findings: RedosFinding[] = [];
  for (const ref of collectParserRegexes(parser)) {
    const f = scanRegex(ref.location, ref.source, ref.flags);
    if (f) findings.push(f);
  }
  return findings;
}
