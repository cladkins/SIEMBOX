/**
 * Startup scan of stored regexes.
 *
 * The write-time gate (regexSafety.ts) keeps new vulnerable regexes out, but
 * parsers and rules saved before it existed may already hold one, and those
 * run on every log line. Once per start, in the background, every stored
 * parser and rule regex gets a verdict: each vulnerable one is logged as a
 * WARN naming the parser or rule, and the Parsers / Detection Rules pages show
 * it with an "Unsafe regex" tag (they read the same verdict cache).
 *
 * Nothing is disabled: turning a parser off silently drops the parsing (and the
 * detections) its logs depend on, which an operator must decide. The fix is to
 * rewrite the regex (docs/operations/TROUBLESHOOTING.md, "Unsafe regex tag").
 *
 * Cheap after the first start: verdicts live in regex_safety_verdicts, so only
 * regexes never analyzed by this recheck version and budget cost anything, and
 * that work runs at low priority in the scan worker, off the event loop.
 */
import { ParserModel } from '../../models/Parser';
import { DetectionRuleModel } from '../../models/DetectionRule';
import { collectParserRegexes } from '../parser/redos';
import { assessRegexes, collectRuleRegexes, warmVerdictCache, type RedosFinding } from './regexSafety';
import { logger } from '../../utils/logger';

export interface StoredRegexFlag {
  kind: 'parser' | 'rule';
  id: number;
  name: string;
  enabled: boolean;
  vulnerable: RedosFinding[];
}

export interface StoredRegexScanResult {
  parsers: number;
  rules: number;
  regexes: number;
  /** Verdicts already stored before the scan began. */
  cached: number;
  vulnerable: StoredRegexFlag[];
  ms: number;
}

/** Scan every stored parser and rule regex; WARN for each vulnerable one. */
export async function scanStoredRegexes(): Promise<StoredRegexScanResult> {
  const started = Date.now();
  const cached = await warmVerdictCache();
  const parsers = await ParserModel.findAll();
  const rules = await DetectionRuleModel.findAll();
  const items = [
    ...parsers.map((p) => ({ kind: 'parser' as const, id: p.id, name: p.name, enabled: p.enabled, refs: collectParserRegexes(p) })),
    ...rules.map((r) => ({ kind: 'rule' as const, id: r.id, name: r.name, enabled: r.enabled, refs: collectRuleRegexes(r) })),
  ].filter((item) => item.refs.length > 0);

  const vulnerable: StoredRegexFlag[] = [];
  let regexes = 0;
  // One item at a time keeps the background queue short, so a person's save
  // never waits behind a whole install's worth of analyses.
  for (const item of items) {
    regexes += item.refs.length;
    let report;
    try {
      report = await assessRegexes(item.refs, { priority: 'low' });
    } catch (error) {
      // Only a saturated checker rejects; the page reads "pending" and asks again.
      logger.debug(`[regex-safety] startup scan skipped ${item.kind} "${item.name}"`, {
        error: error instanceof Error ? error.message : String(error),
      });
      continue;
    }
    if (report.vulnerable.length === 0) continue;
    vulnerable.push({ kind: item.kind, id: item.id, name: item.name, enabled: item.enabled, vulnerable: report.vulnerable });
    for (const f of report.vulnerable) {
      logger.warn(
        `[regex-safety] ${item.kind === 'parser' ? 'Parser' : 'Detection rule'} "${item.name}" (id ${item.id}${item.enabled ? '' : ', disabled'}) ` +
          `has an unsafe regex at ${f.location}: ReDoS-vulnerable (${f.complexity ?? 'super-linear'}). ` +
          `It runs on every ${item.kind === 'parser' ? 'log line' : 'parsed log'} and a crafted line can stall ingestion. ` +
          'It stays active; rewrite it (docs/operations/TROUBLESHOOTING.md, "Unsafe regex tag").',
        { regex: f.source.slice(0, 200), flags: f.flags, attack: f.attack }
      );
    }
  }

  const result: StoredRegexScanResult = {
    parsers: parsers.length,
    rules: rules.length,
    regexes,
    cached,
    vulnerable,
    ms: Date.now() - started,
  };
  logger.info(
    `[regex-safety] checked ${regexes} stored regex(es) in ${items.length} parser(s)/rule(s) in ${result.ms} ms: ` +
      `${vulnerable.length === 0 ? 'none unsafe' : `${vulnerable.length} with an unsafe regex (see the WARN lines above)`}`
  );
  return result;
}
