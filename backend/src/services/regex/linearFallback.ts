/**
 * The ingest path's own bound on a backtracking regex.
 *
 * Parser patterns, derivation regexes and detection-rule regexes run on the
 * event loop for every log line (ParserEngine.processLog, RulesEngine), against
 * text a remote sender controls. A worker round trip per line would cost more
 * than the parsing, so that path is protected by the write-time gate
 * (regexSafety.ts) and the startup scan. But no static analysis catches every
 * catastrophic pattern (recheck's fuzz pass is a search, not a proof).
 *
 * V8 ships a second, non-backtracking regex engine that runs in time linear in
 * the input. With --enable-experimental-regexp-engine-on-excessive-backtracks, a
 * match that backtracks more than --regexp-backtracks-before-fallback times is
 * abandoned and run again on that engine. So a pattern such as
 * ^(?:a|a|a|a|a|a|a|a)…$ (ten groups) on 'a'.repeat(10) + '!', 14 s of
 * backtracking, answers in under 10 ms, and so does ^(a+)+$ on any input.
 *
 * The threshold is 1,000,000 backtracks (LINEAR_FALLBACK_BACKTRACKS), not V8's
 * default of 50,000. A linear pattern that backtracks about once per character,
 * such as ^(?<prefix>.*?)?user=(?<user>\S+), crosses 50,000 on any line over
 * about 50 KB (TCP lines run to 256 KB), and on Node 22 the linear engine is
 * much slower per line: about 80 ms instead of 3 ms on a 250 KB line, which a
 * sender can repeat (40 such lines took 4 s to ingest instead of 0.7 s). At
 * 1,000,000 such a line never leaves the backtracking engine, and an
 * exponential match is still cut after 5-10 ms (0.3 ms at 50,000).
 *
 * Results: on Node 22 (the images' runtime) the fallback's matches and captures
 * were identical to the backtracking engine's in every comparison made (the
 * shipped catalog, and over 100,000 random regex/input pairs with the fallback
 * forced on every match). Node 20 (V8 11.3), which only a custom build on older
 * Node still runs, differs in one corner, in about 0.7% of those pairs: a
 * quantified group whose body can match the empty string, such as (?<x>.*?)?
 * or (x|){0,2}, may capture "" (or pick the empty alternative) where the
 * backtracking engine leaves it unset or captures text. That only happens on a
 * match that has already backtracked a million times; with V8's default
 * threshold it happened on ordinary long lines.
 *
 * It catches exponential and large-constant blowups, not polynomial ones: an
 * unanchored "X, then later Y" such as curl.*\| rescans the line from every
 * start, and V8 counts too few backtracks there to fall back (0.45 s per 64 KB
 * line, 6.8 s per 256 KB TCP line, with or without it). Those the gate's
 * automaton pass proves and refuses.
 *
 * The bound covers only what the linear engine can run: the flags g, m, s and
 * y (a parser `pattern` and a derivation `extract` regex are compiled with none;
 * a rule regex with none unless its author asked for one), no lookahead, no
 * backreferences, counted repeats up to about 16 in all, and lookbehind (on
 * Node 22; Node 20's engine has no lookbehind). Anything else (a
 * case-insensitive rule regex or any derivation `matches`, ^(?:a|a){1,30}$, a
 * backreference, lookbehind on a custom build on Node 20) backtracks as before
 * and relies on the gate alone. linearFallbackCovers() asks V8 itself, and the
 * gate refuses a regex it could not decide that the fallback does not cover
 * (regexSafety.ts). The flags are process-wide, so the regex worker threads
 * get them too.
 *
 * On by default; REGEX_LINEAR_FALLBACK=false turns it off (troubleshooting).
 * server.ts sets it once at startup, before the syslog listeners open.
 */
import * as v8 from 'v8';

export const LINEAR_FALLBACK_V8_FLAG = '--enable-experimental-regexp-engine-on-excessive-backtracks';

/** Backtracks one match may take before V8 finishes it on the linear engine (V8's default: 50,000). */
export const LINEAR_FALLBACK_BACKTRACKS = 1_000_000;

/** Every V8 flag enableLinearRegexFallback sets, in order. */
export const LINEAR_FALLBACK_V8_FLAGS: readonly string[] = Object.freeze([
  LINEAR_FALLBACK_V8_FLAG,
  `--regexp-backtracks-before-fallback=${LINEAR_FALLBACK_BACKTRACKS}`,
]);

/**
 * Makes V8 accept the `l` flag (run this regex on the linear engine), so a
 * regex can be asked whether it is inside that engine. Nothing compiles a
 * caller's regex with `l`: rule regex flags are limited to i, m, s and u
 * (rules/userRegex.ts), and parser regexes get fixed flags.
 */
export const LINEAR_ENGINE_PROBE_FLAG = '--enable-experimental-regexp-engine';

/** Is the fallback wanted? Anything but an explicit false/0/off/no means yes. */
export function linearFallbackWanted(env: NodeJS.ProcessEnv = process.env): boolean {
  const raw = (env.REGEX_LINEAR_FALLBACK ?? '').trim().toLowerCase();
  return !['false', '0', 'off', 'no'].includes(raw);
}

/**
 * Turn the fallback on for this process unless REGEX_LINEAR_FALLBACK disables
 * it. Returns whether it is on. (`setFlags` is a test seam.)
 */
export function enableLinearRegexFallback(
  env: NodeJS.ProcessEnv = process.env,
  setFlags: (flags: string) => void = v8.setFlagsFromString
): boolean {
  if (!linearFallbackWanted(env)) return false;
  for (const flag of LINEAR_FALLBACK_V8_FLAGS) setFlags(flag);
  return true;
}

let probeReady = false;

/**
 * Can the server's fallback bound this regex when it runs on a log line? False
 * when REGEX_LINEAR_FALLBACK turns the fallback off (the server reads the same
 * environment), or when V8's linear engine cannot run the regex. V8 decides:
 * the regex is compiled once with the `l` flag, which V8 refuses ("Cannot be
 * executed in linear time") for anything outside that engine. Compiling does
 * not run it. If the probe flag stops working in some V8, every regex reads as
 * not covered, so the gate fails closed.
 */
export function linearFallbackCovers(source: string, flags: string, env: NodeJS.ProcessEnv = process.env): boolean {
  return linearFallbackWanted(env) && linearEngineRuns(source, flags);
}

/** Does V8's linear engine accept this regex? (Compiles it with `l`; never runs it.) */
function linearEngineRuns(source: string, flags: string): boolean {
  if (!probeReady) {
    v8.setFlagsFromString(LINEAR_ENGINE_PROBE_FLAG);
    probeReady = true;
  }
  try {
    new RegExp(source, `${flags}l`);
    return true;
  } catch {
    return false;
  }
}

/**
 * Why the fallback cannot bound a regex, for the gate's refusal (a best guess
 * at what to change; linearFallbackCovers is what decides).
 */
export function linearFallbackObstacle(source: string, flags: string, env: NodeJS.ProcessEnv = process.env): string {
  if (!linearFallbackWanted(env)) return "V8's linear-time fallback is off (REGEX_LINEAR_FALLBACK=false)";
  const what: string[] = [];
  if (flags.includes('i')) what.push('the i flag, which every derivation `matches` has');
  if (flags.includes('u')) what.push('the u flag');
  if (/\(\?[=!]/.test(source)) what.push('lookahead');
  // Node 22's engine (the images') runs lookbehind; Node 20's does not.
  if (/\(\?<[=!]/.test(source) && !linearEngineRuns('(?<=a)b', '')) {
    what.push(`lookbehind, on Node ${process.versions.node}`);
  }
  if (/\\[1-9]|\\k</.test(source)) what.push('a backreference');
  // Without the u flag, \u{17} is "u" seventeen times.
  const counts = [...source.matchAll(/\{(\d+)(?:,(\d*))?\}/g)].map((m) => Math.max(Number(m[1]), Number(m[2] || 0)));
  if (counts.some((n) => n > 16) || (what.length === 0 && counts.length > 0)) what.push('a counted repeat over 16');
  return `V8's linear-time fallback cannot run it (${what.length ? what.join('; ') : 'syntax outside its engine'})`;
}
