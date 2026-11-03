/**
 * A time budget for parser regexes on the ingest path.
 *
 * ParserEngine.processLog runs every enabled parser's regexes on the event
 * loop, for every line, against text a remote sender controls. The write-time
 * gate, the startup scan and V8's linear fallback (linearFallback.ts) catch
 * most catastrophic patterns, but not all: a polynomial blowup such as the
 * legacy vaultwarden-access pattern (migration 007, degree 2) passes the
 * fallback untouched, and parsers stored before the gate existed run as they
 * are. One slow match blocks syslog ingestion, the API and every job.
 *
 * So each parser runs one of two ways:
 *
 * - inline (the fast path, unchanged), timed. A parser whose single run
 *   exceeds the budget SLOW_RUNS_BEFORE_DEMOTION times within
 *   SLOW_RUN_WINDOW_MS is demoted to the bounded path until the next reload.
 * - bounded: in a worker thread with a hard wall-clock budget
 *   (INGEST_REGEX_BUDGET_MS, default 100). Past it the worker is terminated
 *   and the line counts as "this parser did not match". Parsers whose stored
 *   verdict is "vulnerable" start here.
 *
 * A worker round trip costs well under a millisecond, which is fine for the
 * few flagged parsers and too much for all of them, hence two paths. When the
 * bounded pool is saturated the parser is skipped for that line (counted)
 * rather than queued without limit: ingestion keeps moving.
 */
import { performance } from 'perf_hooks';
import { RegexWorkerPool, RegexPoolBusyError, RegexTimeoutError } from '../regex/workerPool';
import { peekRegexSafety } from '../regex/regexSafety';
import { collectParserRegexes } from './redos';
import { runParser, type ParserDef, type RunContext, type RunResult } from './runParser';
import { envInt } from '../../utils/envInt';
import { logger } from '../../utils/logger';
import { ErrorLogService } from '../errors/errorLogService';

/** Inline runs over budget, within the window, that demote a parser. */
export const SLOW_RUNS_BEFORE_DEMOTION = 3;
export const SLOW_RUN_WINDOW_MS = 10 * 60 * 1000;

export interface IngestRegexStats {
  budgetMs: number;
  /** Parser runs cut off at the budget (bounded path). */
  timeouts: number;
  /** Parser runs skipped because the bounded pool was saturated. */
  skippedBusy: number;
  /** Inline runs that took longer than the budget. */
  slowInline: number;
  /** Parser ids currently on the bounded path. */
  boundedParsers: number[];
}

export type ParserLike = ParserDef & { id: number };

interface ParserState {
  route: 'inline' | 'bounded';
  /** True once the route is final (verdict known or demoted). */
  settled: boolean;
  slowRuns: number[];
}

export class IngestRegexGuard {
  readonly budgetMs: number;
  private pool: RegexWorkerPool | null = null;
  private state = new Map<number, ParserState>();
  private timeouts = 0;
  private skippedBusy = 0;
  private slowInline = 0;

  constructor(
    opts: {
      budgetMs?: number;
      workers?: number;
      /** Verdict lookup (test seam): true when the parser's regexes are proven vulnerable, null while unknown. */
      isFlagged?: (parser: ParserLike) => boolean | null;
      now?: () => number;
    } = {}
  ) {
    this.budgetMs = opts.budgetMs ?? envInt('INGEST_REGEX_BUDGET_MS', 100, 5);
    this.workers = opts.workers ?? envInt('INGEST_REGEX_WORKERS', 2, 1);
    this.isFlagged = opts.isFlagged ?? defaultIsFlagged;
    this.now = opts.now ?? Date.now;
  }

  private readonly workers: number;
  private readonly isFlagged: (parser: ParserLike) => boolean | null;
  private readonly now: () => number;

  /** Forget routes (parsers were reloaded: their regexes may have changed). */
  reset(): void {
    this.state.clear();
  }

  /** runParser under the budget. Never throws for a timeout or a busy pool (returns null). */
  async run(parser: ParserLike, message: string, ctx: RunContext): Promise<RunResult | null> {
    const st = this.routeOf(parser);
    if (st.route === 'bounded') return this.runBounded(parser, message, ctx);

    const t0 = performance.now();
    const result = runParser(parser, message, ctx);
    const elapsed = performance.now() - t0;
    if (elapsed > this.budgetMs) this.noteSlow(parser, st, elapsed);
    return result;
  }

  stats(): IngestRegexStats {
    return {
      budgetMs: this.budgetMs,
      timeouts: this.timeouts,
      skippedBusy: this.skippedBusy,
      slowInline: this.slowInline,
      boundedParsers: [...this.state.entries()].filter(([, s]) => s.route === 'bounded').map(([id]) => id),
    };
  }

  async close(): Promise<void> {
    const p = this.pool;
    this.pool = null;
    if (p) await p.close();
  }

  private routeOf(parser: ParserLike): ParserState {
    let st = this.state.get(parser.id);
    if (st?.settled) return st;
    const flagged = this.isFlagged(parser);
    if (!st) {
      st = { route: flagged ? 'bounded' : 'inline', settled: flagged !== null, slowRuns: [] };
      this.state.set(parser.id, st);
    } else if (flagged !== null) {
      if (flagged) st.route = 'bounded';
      st.settled = true;
    }
    if (st.route === 'bounded' && flagged) {
      logger.warn(
        `Parser "${parser.name}" (id ${parser.id}) has a ReDoS-vulnerable regex: it runs in a worker with a ` +
          `${this.budgetMs} ms budget per line. Rewrite it or reinstall it from the catalog (Troubleshooting -> "Unsafe regex tag").`
      );
    }
    return st;
  }

  private noteSlow(parser: ParserLike, st: ParserState, elapsed: number): void {
    this.slowInline++;
    const now = this.now();
    st.slowRuns = st.slowRuns.filter((t) => now - t < SLOW_RUN_WINDOW_MS);
    st.slowRuns.push(now);
    if (st.slowRuns.length < SLOW_RUNS_BEFORE_DEMOTION) return;
    st.route = 'bounded';
    st.settled = true;
    const message =
      `Parser "${parser.name}" (id ${parser.id}) took over ${this.budgetMs} ms per line ${st.slowRuns.length} times ` +
      `(last ${Math.round(elapsed)} ms); it now runs in a worker with a ${this.budgetMs} ms budget so it cannot stall ingestion.`;
    logger.warn(message);
    ErrorLogService.logBackgroundError('parser-engine', new Error(message), { dedupeKey: `slow-parser:${parser.id}` });
  }

  private async runBounded(parser: ParserLike, message: string, ctx: RunContext): Promise<RunResult | null> {
    try {
      return await this.boundedPool().run<RunResult | null>('runParser', {
        parser: {
          name: parser.name,
          parser_type: parser.parser_type,
          pattern: parser.pattern,
          field_mappings: parser.field_mappings || {},
          derivations: parser.derivations ?? null,
          event_type: parser.event_type ?? null,
        },
        message,
        ctx,
      });
    } catch (error) {
      if (error instanceof RegexTimeoutError) {
        this.timeouts++;
        logger.warn(`Parser "${parser.name}" (id ${parser.id}) ran out of its ${this.budgetMs} ms budget on a line; treated as no match`);
        return null;
      }
      if (error instanceof RegexPoolBusyError) {
        this.skippedBusy++;
        return null;
      }
      throw error;
    }
  }

  private boundedPool(): RegexWorkerPool {
    this.pool ??= new RegexWorkerPool({
      name: 'ingest regex pool',
      size: this.workers,
      timeoutMs: this.budgetMs,
      maxQueue: 2000,
      maxQueueWaitMs: 2000,
      // A replacement worker loads runParser and its imports before its first
      // line; that must not count as the line blowing its budget.
      bootAllowanceMs: 5000,
      resourceLimits: { maxOldGenerationSizeMb: 128, maxYoungGenerationSizeMb: 32 },
    });
    return this.pool;
  }
}

/** Vulnerable per the regex-safety verdict cache; null while a verdict is pending. */
function defaultIsFlagged(parser: ParserLike): boolean | null {
  const summary = peekRegexSafety(collectParserRegexes(parser));
  if (summary.status === 'pending') return null;
  return summary.status === 'vulnerable';
}
