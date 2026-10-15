/**
 * Regex safety gate: one check for every regex SIEMBox is asked to store.
 *
 * A saved parser pattern, derivation regex or detection-rule `regex` condition
 * runs on every incoming log line, on the event loop that also serves the API
 * and syslog ingestion, against text a remote sender controls. One pattern that
 * backtracks catastrophically (^(a+)+$, or the quieter polynomial `curl.*\|`)
 * lets anyone who can send a log line stall the whole process. So every write
 * path — parser create/update/import, catalog and content-pack installs, rule
 * create/update, Sigma import, the bundled-rule importer — asks this module
 * first:
 *
 *   - proven vulnerable (recheck found an attack string): refused, 422, with
 *     the same sentence the parser contribute check uses;
 *   - indeterminate (recheck ran out of its time budget, or does not support
 *     the syntax): accepted, with a warning returned to the caller;
 *   - safe: accepted.
 *
 * The analysis is recheck (the analyzer the catalog CI already uses, run the
 * same way: parser/redos.ts RECHECK_ANALYSIS and RECHECK_PARAMS — 'auto', then
 * the fuzz backend when the automaton said safe, because the automaton rates a
 * large constant blowup "safe") with an explicit time budget per pass
 * (REGEX_SAFETY_CHECK_TIMEOUT_MS, default 10000 ms, the CLI gate's), run in a
 * worker thread (the regex scan pool) with a hard wall-clock backstop, so the
 * check itself can neither hang nor block the event loop. Verdicts are
 * content-addressed (sha256 of flags + source) and cached in memory and in the
 * regex_safety_verdicts table, so each distinct regex is analyzed once per
 * checker (recheck version, analysis, parameters, budget), not once per save
 * or per restart. An analysis that only ran out of time is the exception: it
 * is kept in memory for a while and never stored, so it is tried again rather
 * than remembered as "unknown" forever.
 */
import * as crypto from 'crypto';
import { RegexWorkerPool, RegexTimeoutError, RegexPoolBusyError } from './workerPool';
import {
  CLI_REDOS_TIMEOUT_MS,
  collectParserRegexes,
  RECHECK_ANALYSIS,
  RECHECK_PARAMS,
  redosErrorMessage,
  redosWarningMessage,
  type RedosFinding,
  type RegexRef,
  type RegexVerdict,
} from '../parser/redos';
import { collectRuleRegexes } from '../rules/rulePortable';
import { query } from '../../config/database';
import { logger } from '../../utils/logger';

export type { RegexRef, RegexVerdict, RedosFinding };
export { collectRuleRegexes };

function envInt(name: string, fallback: number, min: number): number {
  const n = parseInt(process.env[name] ?? '', 10);
  return Number.isFinite(n) && n >= min ? n : fallback;
}

/**
 * recheck's time budget for each analysis pass of one regex at write time (a
 * regex gets at most two: parser/redos.ts RECHECK_ANALYSIS). The default
 * matches the CLI validators' (parser/redos.ts CLI_REDOS_TIMEOUT_MS): the
 * pure-JS analyzer (the one the Alpine image runs) needs about 6 s for a
 * common sshd pattern.
 */
export function checkTimeoutMs(): number {
  return envInt('REGEX_SAFETY_CHECK_TIMEOUT_MS', CLI_REDOS_TIMEOUT_MS, 100);
}

function recheckVersion(): string {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports -- version tag only; recheck may be absent
    return String(require('recheck/package.json').version);
  } catch {
    return 'none';
  }
}

/**
 * What produced a verdict. A stored verdict is reused only by the same checker:
 * a recheck upgrade, a different analysis (which backends run), different
 * parameters or a different time budget analyzes the regex again.
 */
export function checkerId(): string {
  const params = Object.entries(RECHECK_PARAMS)
    .map(([k, v]) => `${k}=${v}`)
    .join(';');
  return `recheck@${recheckVersion()};analysis=${RECHECK_ANALYSIS};${params};timeout=${checkTimeoutMs()}`;
}

/** Content address of a regex: sha256 over flags NUL source. */
export function regexKey(source: string, flags: string): string {
  return crypto.createHash('sha256').update(`${flags}\u0000${source}`).digest('hex');
}

// ---------------------------------------------------------------------------
// Verdict cache: memory first, then the regex_safety_verdicts table.
// ---------------------------------------------------------------------------

/**
 * A verdict plus whether it may be persisted. A transient one (the analyzer is
 * missing or failed, or the analysis ran out of time) says nothing lasting
 * about the regex: it is never stored, and memory keeps it only for a while
 * (from `rememberedAt`), then the regex is analyzed again.
 */
interface CachedVerdict extends RegexVerdict {
  transient?: boolean;
  rememberedAt?: number;
}

export interface VerdictStore {
  load(keys: string[], checker: string): Promise<Map<string, RegexVerdict>>;
  loadAll(checker: string): Promise<Map<string, RegexVerdict>>;
  save(entries: Array<{ key: string; verdict: RegexVerdict }>, checker: string): Promise<void>;
}

const dbStore: VerdictStore = {
  async load(keys, checker) {
    const out = new Map<string, RegexVerdict>();
    if (keys.length === 0) return out;
    const result = await query(
      `SELECT regex_key, status, complexity, detail, attack FROM regex_safety_verdicts
       WHERE regex_key = ANY($1) AND checker = $2`,
      [keys, checker]
    );
    for (const row of result.rows) out.set(row.regex_key, rowToVerdict(row));
    return out;
  },
  async loadAll(checker) {
    const out = new Map<string, RegexVerdict>();
    const result = await query(
      `SELECT regex_key, status, complexity, detail, attack FROM regex_safety_verdicts WHERE checker = $1`,
      [checker]
    );
    for (const row of result.rows) out.set(row.regex_key, rowToVerdict(row));
    return out;
  },
  async save(entries, checker) {
    for (const { key, verdict } of entries) {
      await query(
        `INSERT INTO regex_safety_verdicts (regex_key, checker, status, complexity, detail, attack, checked_at)
         VALUES ($1, $2, $3, $4, $5, $6, NOW())
         ON CONFLICT (regex_key) DO UPDATE SET
           checker = EXCLUDED.checker, status = EXCLUDED.status, complexity = EXCLUDED.complexity,
           detail = EXCLUDED.detail, attack = EXCLUDED.attack, checked_at = NOW()`,
        [key, checker, verdict.status, verdict.complexity ?? null, verdict.detail ?? null, verdict.attack ?? null]
      );
    }
  },
};

function rowToVerdict(row: any): RegexVerdict {
  const v: RegexVerdict = { status: row.status };
  if (row.complexity) v.complexity = row.complexity;
  if (row.detail) v.detail = row.detail;
  if (row.attack) v.attack = row.attack;
  return v;
}

let store: VerdictStore | null = dbStore;
const memory = new Map<string, CachedVerdict>();
const MAX_MEMORY = 20_000;
const inflight = new Map<string, Promise<CachedVerdict>>();
/** How long memory answers with a transient verdict before the regex is analyzed again. */
let transientTtlMs = 10 * 60_000;

/** Test seam: replace (or, with null, disable) the persistent verdict store. */
export function setVerdictStore(next: VerdictStore | null): void {
  store = next;
}

/** Test seam: forget every cached verdict. */
export function clearRegexVerdictCache(): void {
  memory.clear();
}

/** Test seam: how long a transient verdict is kept in memory (default 10 minutes). */
export function setTransientVerdictTtl(ms: number): void {
  transientTtlMs = ms;
}

/** Memory is keyed by checker too, so a changed time budget never reuses an old verdict. */
function memKey(key: string): string {
  return `${checkerId()}|${key}`;
}

function recall(key: string): CachedVerdict | undefined {
  const k = memKey(key);
  const hit = memory.get(k);
  if (hit?.rememberedAt !== undefined && Date.now() - hit.rememberedAt >= transientTtlMs) {
    memory.delete(k);
    return undefined;
  }
  return hit;
}

function remember(key: string, verdict: CachedVerdict): void {
  if (memory.size >= MAX_MEMORY) memory.clear();
  memory.set(memKey(key), verdict.transient ? { ...verdict, rememberedAt: Date.now() } : verdict);
}

/** Load every stored verdict for the current checker into memory (startup). */
export async function warmVerdictCache(): Promise<number> {
  if (!store) return 0;
  try {
    const all = await store.loadAll(checkerId());
    for (const [key, verdict] of all) remember(key, verdict);
    return all.size;
  } catch (error) {
    logger.warn('[regex-safety] could not load stored verdicts; regexes will be analyzed again', {
      error: error instanceof Error ? error.message : String(error),
    });
    return 0;
  }
}

// ---------------------------------------------------------------------------
// The scan pool.
// ---------------------------------------------------------------------------

let scanPool: RegexWorkerPool | null = null;

function regexScanPool(): RegexWorkerPool {
  if (!scanPool) {
    const budget = checkTimeoutMs();
    scanPool = new RegexWorkerPool({
      name: 'regex safety check',
      size: envInt('REGEX_SAFETY_WORKERS', 2, 1),
      // recheck stops each of its (at most two) passes at the budget; this
      // backstop covers loading the analyzer in a fresh worker and an analyzer
      // that ignores its budget.
      timeoutMs: 2 * budget + 5000,
      maxQueue: 64,
      // A save waits for the check of its own regexes; background scans queue behind.
      maxQueueWaitMs: 60_000,
      resourceLimits: { maxOldGenerationSizeMb: 512 },
    });
  }
  return scanPool;
}

/** Test seam: stop the scan workers (a new pool is created on next use). */
export async function closeRegexScanPool(): Promise<void> {
  const p = scanPool;
  scanPool = null;
  if (p) await p.close();
}

async function analyze(ref: { source: string; flags: string }, priority: 'high' | 'low'): Promise<CachedVerdict> {
  const timeoutMs = checkTimeoutMs();
  try {
    const verdict = await regexScanPool().run<RegexVerdict>(
      'scan',
      { source: ref.source, flags: ref.flags, timeoutMs },
      { priority }
    );
    // The analyzer missing is an installation problem, and running out of time
    // depends on the load and the analyzer backend: neither is a fact about the
    // regex, so neither is stored (an overrun stored once would be "unknown"
    // for good, even where a quieter moment or a faster analyzer settles it).
    const transient =
      verdict.status === 'unknown' && (verdict.outOfTime === true || /not installed/.test(verdict.detail ?? ''));
    return transient ? { ...verdict, transient } : verdict;
  } catch (error) {
    if (error instanceof RegexTimeoutError) {
      return { status: 'unknown', detail: 'the analysis hit its time budget', outOfTime: true, transient: true };
    }
    // Fail closed: a saturated checker must not turn "not checked yet" into
    // "accepted with a warning". The caller answers 503 and the client retries.
    if (error instanceof RegexPoolBusyError) throw error;
    return {
      status: 'unknown',
      detail: `the analysis failed: ${error instanceof Error ? error.message : String(error)}`,
      transient: true,
    };
  }
}

/**
 * How many of ONE call's regexes are analyzed at a time: as many as there are
 * scan workers. A save with 80 new regexes then takes its turn a few at a
 * time instead of filling the pool's queue at once, whose cap is there to
 * detect saturation from concurrent callers (503 REGEX_BUSY), not to refuse
 * one large save on an idle server.
 */
function perCallConcurrency(): number {
  return regexScanPool().options.size;
}

/** Verdicts for distinct regexes, from memory, the store, or a fresh analysis. */
async function verdictsFor(
  refs: Array<{ key: string; source: string; flags: string }>,
  priority: 'high' | 'low'
): Promise<Map<string, CachedVerdict>> {
  const out = new Map<string, CachedVerdict>();
  const missing: typeof refs = [];
  for (const ref of refs) {
    const hit = recall(ref.key);
    if (hit) out.set(ref.key, hit);
    else missing.push(ref);
  }
  if (missing.length === 0) return out;

  const checker = checkerId();
  if (store) {
    try {
      const stored = await store.load(
        missing.filter((r) => !inflight.has(memKey(r.key))).map((r) => r.key),
        checker
      );
      for (const [key, verdict] of stored) {
        remember(key, verdict);
        out.set(key, verdict);
      }
    } catch (error) {
      logger.debug('[regex-safety] verdict store unavailable', {
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  const fresh: Array<{ key: string; verdict: RegexVerdict }> = [];
  const verdictOf = (ref: { key: string; source: string; flags: string }): Promise<CachedVerdict> => {
    let pending = inflight.get(memKey(ref.key));
    if (!pending) {
      pending = analyze(ref, priority).then((verdict) => {
        remember(ref.key, verdict);
        if (!verdict.transient) fresh.push({ key: ref.key, verdict });
        return verdict;
      });
      inflight.set(memKey(ref.key), pending);
      void pending.finally(() => inflight.delete(memKey(ref.key))).catch(() => undefined);
    }
    return pending;
  };

  const todo = missing.filter((ref) => !out.has(ref.key));
  let next = 0;
  let failure: { error: unknown } | null = null;
  const lane = async () => {
    while (!failure && next < todo.length) {
      const ref = todo[next++];
      try {
        out.set(ref.key, await verdictOf(ref));
      } catch (error) {
        failure ??= { error };
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(todo.length, perCallConcurrency()) }, lane));

  // Whatever was analyzed is kept, even when the call as a whole fails (busy).
  if (store && fresh.length > 0) {
    try {
      await store.save(fresh, checker);
    } catch (error) {
      logger.debug('[regex-safety] could not persist verdicts', {
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }
  if (failure) throw (failure as { error: unknown }).error;
  return out;
}

// ---------------------------------------------------------------------------
// The gate.
// ---------------------------------------------------------------------------

export interface RegexSafetyReport {
  /** Proven super-linear (an attack string exists): the write is refused. */
  vulnerable: RedosFinding[];
  /** Could not be decided: the write goes ahead with these as warnings. */
  unknown: RedosFinding[];
  /** One sentence per vulnerable regex (same wording as the contribute check). */
  errors: string[];
  /** One sentence per indeterminate regex. */
  warnings: string[];
}

export function emptyReport(): RegexSafetyReport {
  return { vulnerable: [], unknown: [], errors: [], warnings: [] };
}

/** Prefix every location (e.g. "rules[2].") when one report covers several items. */
export function mergeReports(parts: Array<{ prefix?: string; report: RegexSafetyReport }>): RegexSafetyReport {
  const out = emptyReport();
  for (const { prefix = '', report } of parts) {
    const vulnerable = report.vulnerable.map((f) => ({ ...f, location: `${prefix}${f.location}` }));
    const unknown = report.unknown.map((f) => ({ ...f, location: `${prefix}${f.location}` }));
    out.vulnerable.push(...vulnerable);
    out.unknown.push(...unknown);
    out.errors.push(...vulnerable.map((f) => redosErrorMessage(f, 'saving')));
    out.warnings.push(...unknown.map(redosWarningMessage));
  }
  return out;
}

/**
 * Check regexes before they are stored. Never blocks the event loop; resolves
 * when every distinct regex has a verdict. Rejects only with RegexPoolBusyError
 * (the checker is saturated: answer 503, never "accepted").
 */
export async function assessRegexes(
  refs: RegexRef[],
  opts: { priority?: 'high' | 'low' } = {}
): Promise<RegexSafetyReport> {
  const keyed = refs.map((r) => ({ ...r, key: regexKey(r.source, r.flags) }));
  const distinct = [...new Map(keyed.map((r) => [r.key, r])).values()];
  const verdicts = await verdictsFor(distinct, opts.priority ?? 'high');
  return reportFrom(keyed, (key) => verdicts.get(key));
}

function reportFrom(
  refs: Array<RegexRef & { key: string }>,
  verdictOf: (key: string) => RegexVerdict | undefined
): RegexSafetyReport {
  const report = emptyReport();
  for (const ref of refs) {
    const v = verdictOf(ref.key);
    if (!v || v.status === 'safe') continue;
    const base = { location: ref.location, source: ref.source, flags: ref.flags };
    if (v.status === 'vulnerable') {
      const f: RedosFinding = { ...base, status: 'vulnerable', complexity: v.complexity, attack: v.attack };
      report.vulnerable.push(f);
      report.errors.push(redosErrorMessage(f, 'saving'));
    } else {
      const f: RedosFinding = { ...base, status: 'unknown', detail: v.detail };
      report.unknown.push(f);
      report.warnings.push(redosWarningMessage(f));
    }
  }
  return report;
}

export function assessParserRegexes(
  parser: Parameters<typeof collectParserRegexes>[0],
  opts: { priority?: 'high' | 'low' } = {}
): Promise<RegexSafetyReport> {
  return assessRegexes(collectParserRegexes(parser), opts);
}

export function assessRuleRegexes(rule: unknown, opts: { priority?: 'high' | 'low' } = {}): Promise<RegexSafetyReport> {
  return assessRegexes(collectRuleRegexes(rule), opts);
}

/** The 422 body for a refused write. `subject` names it: `Parser "nginx"`. */
export function refusalBody(subject: string, report: RegexSafetyReport) {
  return {
    code: 'REGEX_UNSAFE',
    message: `${subject} was not saved: ${report.errors.join('; ')}`,
    errors: report.errors,
    warnings: report.warnings,
    regex_safety: { vulnerable: report.vulnerable, unknown: report.unknown },
  };
}

/** A one-line reason for a refused item in a batch result (install-all, packs, Sigma). */
export function refusalReason(report: RegexSafetyReport): string {
  return report.errors.join('; ');
}

// ---------------------------------------------------------------------------
// What the UI shows for stored parsers and rules (cache only, never waits).
// ---------------------------------------------------------------------------

export interface RegexSafetySummary {
  /** 'pending' while a regex has no verdict yet (it is being analyzed in the background). */
  status: 'none' | 'safe' | 'unknown' | 'vulnerable' | 'pending';
  vulnerable: RedosFinding[];
  unknown: RedosFinding[];
}

/**
 * The cached verdicts for these regexes, without waiting. A regex with no
 * verdict yet is queued for a background analysis and reported as pending.
 */
export function peekRegexSafety(refs: RegexRef[]): RegexSafetySummary {
  if (refs.length === 0) return { status: 'none', vulnerable: [], unknown: [] };
  const keyed = refs.map((r) => ({ ...r, key: regexKey(r.source, r.flags) }));
  const missing = keyed.filter((r) => !recall(r.key));
  if (missing.length > 0) {
    void assessRegexes(missing, { priority: 'low' }).catch(() => undefined);
  }
  const report = reportFrom(keyed, recall);
  const status: RegexSafetySummary['status'] =
    report.vulnerable.length > 0
      ? 'vulnerable'
      : missing.length > 0
        ? 'pending'
        : report.unknown.length > 0
          ? 'unknown'
          : 'safe';
  return { status, vulnerable: report.vulnerable, unknown: report.unknown };
}

/** A parser row as the API returns it, with its regex safety summary. */
export function withParserRegexSafety<T extends Parameters<typeof collectParserRegexes>[0]>(
  parser: T
): T & { regex_safety: RegexSafetySummary } {
  return { ...parser, regex_safety: peekRegexSafety(collectParserRegexes(parser)) };
}

/** A detection rule row as the API returns it, with its regex safety summary. */
export function withRuleRegexSafety<T extends object>(rule: T): T & { regex_safety: RegexSafetySummary } {
  return { ...rule, regex_safety: peekRegexSafety(collectRuleRegexes(rule)) };
}
