/**
 * The HTTP side of regex safety, shared by the parser, rule and pack routes:
 * how a refused regex, a timed-out test run and a saturated checker answer.
 *
 *   422 REGEX_UNSAFE      a regex recheck proves vulnerable; nothing was saved
 *   422 REGEX_UNDECIDED   a regex recheck cannot read, that V8's linear-time
 *                         fallback cannot bound either; nothing was saved
 *   422 REGEX_TIMEOUT     a test run outlived its budget and was stopped
 *   422 REGEX_TEST_FAILED a test run could not run (e.g. the pattern does not compile)
 *   413 SAMPLE_TOO_LARGE  a sample over the size cap (sent by the routes)
 *   503 REGEX_BUSY        the workers are saturated; retry shortly
 */
import type { Response } from 'express';
import { regexRunErrorResponse } from './boundedRegex';
import { isRefused, refusalBody, type RegexSafetyReport } from './regexSafety';

/** Answer a bounded-run failure (timeout 422, busy 503); false if `error` is not one. */
export function sendRegexRunError(res: Response, error: unknown, what?: string): boolean {
  const answer = regexRunErrorResponse(error, what);
  if (!answer) return false;
  res.status(answer.status).json(answer.body);
  return true;
}

/**
 * Run a write-time gate check and answer the request when the write must not
 * go ahead (422 REGEX_UNSAFE or REGEX_UNDECIDED, 503 REGEX_BUSY), returning null; otherwise the
 * report, whose `warnings` (indeterminate regexes) go back to the caller.
 */
export async function gateOrRefuse(
  res: Response,
  subject: string,
  check: () => Promise<RegexSafetyReport>
): Promise<RegexSafetyReport | null> {
  let report: RegexSafetyReport;
  try {
    report = await check();
  } catch (error) {
    if (sendRegexRunError(res, error)) return null;
    throw error;
  }
  if (isRefused(report)) {
    res.status(422).json(refusalBody(subject, report));
    return null;
  }
  return report;
}
