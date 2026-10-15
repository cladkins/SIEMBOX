/**
 * The ingest path's own bound on a backtracking regex.
 *
 * Parser patterns, derivation regexes and detection-rule regexes run on the
 * event loop for every log line (ParserEngine.processLog, RulesEngine), against
 * text a remote sender controls. A worker round trip per line would cost more
 * than the parsing, so that path is protected by the write-time gate
 * (regexSafety.ts) and the startup scan. But no static analysis catches every
 * catastrophic pattern (recheck's fuzz pass is a search, not a proof), and a
 * regex the gate rated "could not be proven safe" is saved with a warning.
 *
 * V8 ships a second, non-backtracking regex engine that runs in time linear in
 * the input. With --enable-experimental-regexp-engine-on-excessive-backtracks, a
 * match that backtracks more than --regexp-backtracks-before-fallback times
 * (V8's default, 50,000: far more than a well-behaved log pattern needs) is
 * abandoned and run again on that engine, with the same result. So a pattern
 * such as ^(?:a|a|a|a|a|a|a|a)…$ (ten groups) on 'a'.repeat(10) + '!', 14 s of
 * backtracking, answers in about 2 ms, and so does ^(a+)+$ on any input.
 *
 * The bound covers what that engine supports, which in Node 20 and 22 is: the
 * flags g, m, s and y (a parser `pattern` and a derivation `extract` regex are
 * compiled with none; a rule regex with none unless its author asked for one),
 * no lookahead and no backreferences, and bounded quantifiers up to a count of
 * about 16. Anything else (a case-insensitive rule regex or derivation
 * `matches`, ^(?:a|a){1,30}$, a backreference) backtracks as before and relies
 * on the gate alone. The flag is process-wide, so the regex worker threads get
 * it too.
 *
 * On by default; REGEX_LINEAR_FALLBACK=false turns it off (troubleshooting).
 * server.ts sets it once at startup, before the syslog listeners open.
 */
import * as v8 from 'v8';

export const LINEAR_FALLBACK_V8_FLAG = '--enable-experimental-regexp-engine-on-excessive-backtracks';

/** Is the fallback wanted? Anything but an explicit false/0/off/no means yes. */
export function linearFallbackWanted(env: NodeJS.ProcessEnv = process.env): boolean {
  const raw = (env.REGEX_LINEAR_FALLBACK ?? '').trim().toLowerCase();
  return !['false', '0', 'off', 'no'].includes(raw);
}

/**
 * Turn the fallback on for this process unless REGEX_LINEAR_FALLBACK disables
 * it. Returns whether it is on.
 */
export function enableLinearRegexFallback(env: NodeJS.ProcessEnv = process.env): boolean {
  if (!linearFallbackWanted(env)) return false;
  v8.setFlagsFromString(LINEAR_FALLBACK_V8_FLAG);
  return true;
}
