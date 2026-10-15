/**
 * Time-bounded execution of regexes SIEMBox has not vetted.
 *
 * "Try this pattern" requests (the parser builder's Test button, the import
 * preview's self-tests, a saved parser tried on a caller's sample) and the
 * recommendation dry-runs over live log samples all run a regex someone else
 * wrote against input someone else chose. On the main thread a catastrophic
 * pattern would stall the API, syslog ingestion and every job until it ended.
 * Here each run goes to the regex test pool: a worker thread with a hard
 * wall-clock budget (REGEX_TEST_TIMEOUT_MS, default 1000 ms), terminated and
 * replaced when the budget runs out, and inputs are capped in size first.
 *
 * The ingest path itself (ParserEngine.processLog, RulesEngine.evaluateLog) is
 * NOT routed through here: a worker round trip per log line would cost more
 * than the parsing. It is protected by the write-time gate (regexSafety.ts),
 * the startup scan of stored regexes and V8's linear-time fallback
 * (linearFallback.ts) instead.
 */
import { RegexWorkerPool, RegexTimeoutError, RegexPoolBusyError, RegexWorkerError } from './workerPool';
import type { ParserDef, RunContext, RunResult } from '../parser/runParser';
import type { PortableParser, SelfTestResult } from '../parser/parserPortable';
import type { RecommendationResult, SourceSample } from '../parser/parserRecommendations';
import type { CandidateRule, RuleSourceSample, RuleRecommendation } from '../rules/detectionRecommendations';

/** Largest sample a caller may test a pattern on: the HTTP log-push message cap. */
export const MAX_SAMPLE_BYTES = 64 * 1024;
/** Most self-test samples one portable parser may carry. */
export const MAX_TEST_SAMPLES = 100;
/** Budget for a recommendation dry-run (every candidate × every sample in one task). */
const RECOMMENDATION_TIMEOUT_MS = 20_000;

function envInt(name: string, fallback: number, min: number): number {
  const n = parseInt(process.env[name] ?? '', 10);
  return Number.isFinite(n) && n >= min ? n : fallback;
}

let pool: RegexWorkerPool | null = null;

/** The shared regex test pool (created on first use). */
export function regexTestPool(): RegexWorkerPool {
  if (!pool) {
    pool = new RegexWorkerPool({
      name: 'regex test pool',
      size: envInt('REGEX_TEST_WORKERS', 2, 1),
      timeoutMs: envInt('REGEX_TEST_TIMEOUT_MS', 1000, 50),
      maxQueue: 32,
      maxQueueWaitMs: 5000,
      // A match result or a self-test report is small; a worker that needs
      // more than this is building something pathological. Running out ends
      // the worker (and its task), never the process.
      resourceLimits: { maxOldGenerationSizeMb: 128, maxYoungGenerationSizeMb: 32 },
    });
  }
  return pool;
}

/** Test seam: stop the pool's workers (a new pool is created on next use). */
export async function closeRegexTestPool(): Promise<void> {
  const p = pool;
  pool = null;
  if (p) await p.close();
}

/** Only the fields runParser reads: Dates and DB columns need not cross the thread boundary. */
function parserDef(p: ParserDef): ParserDef {
  return {
    name: p.name,
    parser_type: p.parser_type,
    pattern: p.pattern,
    field_mappings: p.field_mappings || {},
    derivations: p.derivations ?? null,
    event_type: p.event_type ?? null,
  };
}

/** runParser in the test pool. Rejects with RegexTimeoutError past the budget. */
export function runParserBounded(parser: ParserDef, message: string, ctx: RunContext = {}): Promise<RunResult | null> {
  return regexTestPool().run<RunResult | null>('runParser', { parser: parserDef(parser), message, ctx });
}

/** runSelfTests in the test pool: one budget covers all of the parser's samples. */
export function runSelfTestsBounded(parser: PortableParser): Promise<SelfTestResult> {
  return regexTestPool().run<SelfTestResult>('selfTest', { parser });
}

/** recommendParsers (catalog regexes × live raw log samples) in the test pool. */
export function recommendParsersBounded(samples: SourceSample[], candidates: PortableParser[]): Promise<RecommendationResult> {
  return regexTestPool().run<RecommendationResult>(
    'recommendParsers',
    { samples, candidates },
    { timeoutMs: RECOMMENDATION_TIMEOUT_MS }
  );
}

/** recommendRules (catalog rule regexes × live parsed samples) in the test pool. */
export function recommendRulesBounded(
  sources: RuleSourceSample[],
  candidates: CandidateRule[]
): Promise<{ recommendations: RuleRecommendation[] }> {
  return regexTestPool().run<{ recommendations: RuleRecommendation[] }>(
    'recommendRules',
    { sources, candidates },
    { timeoutMs: RECOMMENDATION_TIMEOUT_MS }
  );
}

function kib(bytes: number): string {
  return `${Math.ceil(bytes / 1024)} KB`;
}

/** Why a test sample is refused before any regex runs on it, or null. */
export function sampleProblem(sample: unknown, what = 'sample'): string | null {
  if (typeof sample !== 'string') return `${what} must be a string`;
  const bytes = Buffer.byteLength(sample, 'utf8');
  if (bytes > MAX_SAMPLE_BYTES) {
    return `${what} is ${kib(bytes)}; the limit is ${kib(MAX_SAMPLE_BYTES)} (the largest log message SIEMBox accepts over HTTP push)`;
  }
  return null;
}

/** Why a portable parser's test_samples are refused before they run, or null. */
export function testSamplesProblem(parser: { test_samples?: unknown }): string | null {
  const samples = parser?.test_samples;
  if (!Array.isArray(samples)) return null;
  if (samples.length > MAX_TEST_SAMPLES) {
    return `test_samples has ${samples.length} entries; the limit is ${MAX_TEST_SAMPLES}`;
  }
  for (let i = 0; i < samples.length; i++) {
    const input = samples[i]?.input;
    if (typeof input === 'string') {
      const problem = sampleProblem(input, `test_samples[${i}].input`);
      if (problem) return problem;
    }
  }
  return null;
}

export interface RegexHttpError {
  status: number;
  body: { message: string; code: string; timeout_ms?: number };
}

/**
 * The answer for a bounded run that did not produce a result, or null when the
 * error is not one of ours (the caller's own 500 handling applies).
 */
export function regexRunErrorResponse(error: unknown, what = 'The regex'): RegexHttpError | null {
  if (error instanceof RegexTimeoutError) {
    return {
      status: 422,
      body: {
        code: 'REGEX_TIMEOUT',
        timeout_ms: error.timeoutMs,
        message:
          `${what} did not finish within ${error.timeoutMs} ms on this input and was stopped. ` +
          'It backtracks catastrophically (ReDoS): two parts of the pattern can match the same text, so the work grows ' +
          'exponentially or polynomially with the input. Rewrite it so each part matches distinct text — see ' +
          '"Regex safety" in docs/reference/PARSERS.md.',
      },
    };
  }
  if (error instanceof RegexPoolBusyError) {
    return { status: 503, body: { code: 'REGEX_BUSY', message: error.message } };
  }
  if (error instanceof RegexWorkerError) {
    return { status: 422, body: { code: 'REGEX_TEST_FAILED', message: `${what} could not be run: ${error.message}` } };
  }
  return null;
}
