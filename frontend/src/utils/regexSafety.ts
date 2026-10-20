/**
 * Regex safety in the UI: turning the API's refusals, timeouts and warnings
 * into the inline problem the parser editor, rule editor and import dialogs
 * show (backend services/regex, docs/reference/API.md "Regex safety").
 *
 *   422 REGEX_UNSAFE      a regex is ReDoS-vulnerable; nothing was saved
 *   422 REGEX_UNDECIDED   a regex the check cannot read, which nothing would
 *                         bound at run time; nothing was saved
 *   422 REGEX_TIMEOUT     a test run outlived its time budget and was stopped
 *   422 REGEX_TEST_FAILED the pattern could not run (e.g. it does not compile)
 *   413 SAMPLE_TOO_LARGE  the sample is over the size cap
 *   503 REGEX_BUSY        the checker is saturated; retry shortly
 */

export interface RegexFinding {
  location: string;
  source: string;
  flags: string;
  status: 'vulnerable' | 'unknown' | 'error';
  complexity?: string;
  detail?: string;
  /** recheck's attack string, e.g. 'a'.repeat(31) + '\x00' */
  attack?: string;
}

/** `regex_safety` on a parser or rule row (GET /api/parsers, /api/rules). */
export interface RegexSafetySummary {
  status: 'none' | 'safe' | 'unknown' | 'vulnerable' | 'pending';
  vulnerable: RegexFinding[];
  unknown: RegexFinding[];
}

/** What a dialog shows inline instead of a generic toast. */
export interface InlineProblem {
  type: 'error' | 'warning';
  title: string;
  lines: string[];
  /** The regexes concerned, shown with their source. */
  findings: RegexFinding[];
  code?: string;
}

const TITLES: Record<string, string> = {
  REGEX_UNSAFE: 'Refused: a regex can backtrack catastrophically (ReDoS)',
  REGEX_UNDECIDED: 'Refused: a regex could not be checked for ReDoS, and nothing would bound it',
  REGEX_TIMEOUT: 'Stopped: the pattern ran out of time on this input',
  REGEX_TEST_FAILED: 'The pattern could not be run',
  SAMPLE_TOO_LARGE: 'The sample is too large',
  REGEX_BUSY: 'The regex checker is busy — try again in a moment',
  ATTACK_TAG_INVALID: 'Not saved: an ATT&CK tag is not a valid technique or tactic',
};

/**
 * The inline problem for a failed API call: the server's own message (and,
 * for a refused regex, which regexes and why), or `fallback` when no answer
 * came at all.
 */
export function problemFromError(error: any, fallback: string): InlineProblem {
  const data = error?.response?.data ?? {};
  const code: string | undefined = typeof data.code === 'string' ? data.code : undefined;
  if (code === 'REGEX_UNSAFE' || code === 'REGEX_UNDECIDED') {
    const safety = data.regex_safety ?? {};
    return {
      type: 'error',
      code,
      title: TITLES[code],
      lines: Array.isArray(data.errors) && data.errors.length ? data.errors : [data.message],
      findings: [
        ...(Array.isArray(safety.vulnerable) ? safety.vulnerable : []),
        ...(Array.isArray(safety.undecided) ? safety.undecided : []),
      ],
    };
  }
  // 422 ATTACK_TAG_INVALID (rule create/update): one line per bad tag, as the
  // validator words it ("attack.t1086: T1086 … was revoked …; use attack.t1059.001").
  if (code === 'ATTACK_TAG_INVALID') {
    const errors = Array.isArray(data.errors) ? data.errors.filter((e: unknown) => typeof e === 'string') : [];
    return {
      type: 'error',
      code,
      title: TITLES[code],
      lines: errors.length ? errors : [typeof data.message === 'string' ? data.message : fallback],
      findings: [],
    };
  }
  const message: string =
    (typeof data.message === 'string' && data.message) ||
    (error?.code === 'ECONNABORTED' ? 'The request timed out.' : '') ||
    fallback;
  return {
    type: code === 'REGEX_BUSY' ? 'warning' : 'error',
    code,
    title: (code && TITLES[code]) || fallback,
    lines: message === fallback && !(code && TITLES[code]) ? [] : [message],
    findings: [],
  };
}

/** The inline warning for a save that went ahead with indeterminate regexes, or null. */
export function warningsProblem(warnings: unknown, title: string): InlineProblem | null {
  if (!Array.isArray(warnings) || warnings.length === 0) return null;
  return { type: 'warning', title, lines: warnings.map(String), findings: [] };
}

/**
 * The inline result of a batch (catalog "Install all", Sigma import): every
 * skipped item with its reason (a refused regex names the regex and why), then
 * installed items whose regexes could not be proven safe. Null when clean.
 */
export function batchProblem(
  summary: string,
  data: {
    failed?: Array<{ name?: string; title?: string; reason: string }>;
    warnings?: Array<{ name?: string; title?: string; warnings: string[] }>;
  }
): InlineProblem | null {
  const label = (item: { name?: string; title?: string }) => item.name ?? item.title ?? '(untitled)';
  const failed = (data.failed ?? []).map((f) => `${label(f)}: ${f.reason}`);
  const warned = (data.warnings ?? []).flatMap((w) => w.warnings.map((line) => `${label(w)}: ${line}`));
  if (failed.length === 0 && warned.length === 0) return null;
  return {
    type: 'warning',
    title: failed.length ? summary : `${summary} — but some regexes could not be proven safe`,
    lines: [...failed, ...warned],
    findings: [],
  };
}

/** The inline alert for a stored parser or rule the startup scan flagged. */
export function storedUnsafeProblem(safety: RegexSafetySummary | undefined, kind: 'parser' | 'rule'): InlineProblem | null {
  if (safety?.status !== 'vulnerable') return null;
  return {
    type: 'error',
    title: `This ${kind} has an unsafe regex (ReDoS)`,
    lines: [
      `It still runs on every ${kind === 'parser' ? 'log line' : 'parsed log'}, and a crafted line can stall ingestion. ` +
        'Rewrite it so no two parts of the pattern can match the same text; saving a change to it is refused until it is linear.',
    ],
    findings: safety.vulnerable,
  };
}

/** Tooltip for the "Unsafe regex" tag. */
export function unsafeRegexTooltip(safety: RegexSafetySummary | undefined): string {
  if (!safety || safety.status !== 'vulnerable') return '';
  const what = safety.vulnerable
    .map((f) => `${f.location}${f.complexity ? ` (${f.complexity})` : ''}`)
    .join(', ');
  return (
    `ReDoS-vulnerable regex at ${what}: a crafted log line can stall ingestion. ` +
    'It still runs — open it to see the pattern and rewrite it linear (Troubleshooting: "Unsafe regex tag").'
  );
}
