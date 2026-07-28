/**
 * Compilation of caller-supplied detection regexes.
 *
 * Rule patterns are data written by humans and by the AI builder, and they used
 * to be compiled with a bare `new RegExp(value)` — no flags, no way to ask for
 * any. That has bitten twice:
 *
 *  - Matching was always case-sensitive, so PROXY-001 missed `union select`
 *    while catching `UNION SELECT`. Authors reach for `(?i)`, which JavaScript
 *    rejects outright ("Invalid group"), and the resulting throw was swallowed
 *    into `return false` — a rule that silently never fires.
 *  - The engine, the recommendations preview and the validator each compiled
 *    independently, so they could disagree about whether a rule matches.
 *
 * This module is the single place that turns an authored pattern into a RegExp.
 * It accepts flags two ways: an explicit `flags` property on the condition, and
 * a leading inline group (`(?i)`, `(?im)`, …) which is translated rather than
 * rejected, because that is the syntax authors copy from Python/Go/PCRE.
 */

/**
 * Flags an author may ask for.
 *
 * `g` and `y` are deliberately excluded: both make the RegExp stateful via
 * `lastIndex`, so a cached (or merely reused) instance alternates between
 * matching and not matching on identical input. That failure is intermittent
 * and effectively undebuggable in a detection pipeline.
 */
const ALLOWED_FLAGS = 'imsu';

/** Leading inline flag group, e.g. "(?i)" or "(?im)" — PCRE syntax JS lacks. */
const INLINE_FLAGS = /^\(\?([a-zA-Z]+)\)/;

export interface CompiledRegex {
  regex: RegExp;
  /** Flags actually applied, after merging inline and explicit sources. */
  flags: string;
}

export class UserRegexError extends Error {}

/**
 * Split a leading inline flag group off a pattern.
 * `"(?i)foo"` -> `{ source: "foo", flags: "i" }`; a pattern without one is
 * returned unchanged. Only a group at the very start is treated as flags — one
 * appearing mid-pattern is a real (if unsupported) construct, not our business.
 */
export function extractInlineFlags(pattern: string): { source: string; flags: string } {
  const match = pattern.match(INLINE_FLAGS);
  if (!match) return { source: pattern, flags: '' };
  return { source: pattern.slice(match[0].length), flags: match[1] };
}

function validateFlags(flags: string, pattern: string): string {
  const unique = Array.from(new Set(flags.split(''))).sort().join('');
  for (const flag of unique) {
    if (!ALLOWED_FLAGS.includes(flag)) {
      throw new UserRegexError(
        `unsupported regex flag "${flag}" in pattern ${JSON.stringify(pattern)} ` +
          `(allowed: ${ALLOWED_FLAGS.split('').join(', ')}; ` +
          `"g" and "y" are rejected because they make matching stateful)`
      );
    }
  }
  return unique;
}

/**
 * Bounded compile cache. `evaluateCondition` runs per condition per event, so on
 * a busy install this compiles the same handful of patterns millions of times a
 * day. Keyed on source + flags; cleared wholesale when it grows past the cap
 * (rule sets are small, so this should never actually trip).
 */
const cache = new Map<string, RegExp>();
const MAX_CACHED = 500;

/**
 * Compile an authored pattern. Throws UserRegexError for a bad flag and the
 * native SyntaxError for a bad pattern, so callers can report which it was.
 */
export function compileUserRegex(pattern: string, explicitFlags?: string): CompiledRegex {
  const { source, flags: inline } = extractInlineFlags(pattern);
  const flags = validateFlags(`${inline}${explicitFlags ?? ''}`, pattern);

  // NUL separator: a regex source may contain any printable character, so the
  // delimiter has to be one it cannot. Written as an escape rather than a raw
  // byte — a literal NUL makes git treat this file as binary, which hides the
  // entire file from diffs and code review.
  const key = `${flags}\u0000${source}`;
  const hit = cache.get(key);
  if (hit) return { regex: hit, flags };

  const regex = new RegExp(source, flags);
  if (cache.size >= MAX_CACHED) cache.clear();
  cache.set(key, regex);
  return { regex, flags };
}

/**
 * Compile and test in one step, returning false when the pattern is unusable.
 * The shared path for the engine and the recommendations preview, so a rule
 * cannot behave one way live and another in the "what would this match" view.
 */
export function testUserRegex(
  pattern: string,
  subject: string,
  explicitFlags?: string
): { matched: boolean; error?: string } {
  try {
    const { regex } = compileUserRegex(pattern, explicitFlags);
    return { matched: regex.test(subject) };
  } catch (error) {
    return { matched: false, error: error instanceof Error ? error.message : String(error) };
  }
}

/** Validation helper: returns an error string, or null when the pattern is fine. */
export function validateUserRegex(pattern: string, explicitFlags?: string): string | null {
  try {
    compileUserRegex(pattern, explicitFlags);
    return null;
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
}

/** Test seam — the cache is process-wide and would otherwise leak between cases. */
export function clearUserRegexCache(): void {
  cache.clear();
}
