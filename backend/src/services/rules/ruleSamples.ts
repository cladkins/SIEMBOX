/**
 * Recent parsed_data samples per parser: what the rule dry runs
 * (conditionsMatchSample) are evaluated against. Shared by the detection
 * recommendations (GET /api/rules/recommendations) and ATT&CK coverage
 * (GET /api/attack/coverage), so "your data satisfies this rule" means the same
 * thing in both places.
 *
 * Bounded: one indexed pass over a time window (idx_parsed_logs_created_at),
 * at most `perPartition` rows per partition, and with `scanLimit` at most that
 * many of the window's newest rows are ranked at all.
 */
import { query } from '../../config/database';

export interface ParserSamples {
  parser_id: number;
  parser_name: string;
  samples: Array<Record<string, any>>;
}

export interface SampleOptions {
  /** How far back to look. */
  windowHours: number;
  /** Rows kept per parser (or per parser and event type, with byEventType). */
  perPartition: number;
  /**
   * Partition by parser AND parsed_logs.event_type, so a parser's rarer event
   * kinds (a failed login among many accepted ones) are sampled too.
   */
  byEventType?: boolean;
  /** Rank only the window's newest N rows (bounds the work on a busy install). */
  scanLimit?: number;
  /** Most samples returned in all. */
  maxSamples?: number;
}

/** Per-parser samples, newest first. Parsers with no row in the window are absent. */
export async function recentParserSamples(opts: SampleOptions): Promise<Map<number, ParserSamples>> {
  const hours = Math.max(1, Math.floor(opts.windowHours));
  const per = Math.max(1, Math.floor(opts.perPartition));
  const partition = opts.byEventType ? 'parser_id, event_type' : 'parser_id';
  const scan = opts.scanLimit ? `ORDER BY created_at DESC LIMIT ${Math.max(1, Math.floor(opts.scanLimit))}` : '';
  const cap = opts.maxSamples ? `ORDER BY r.rn, r.id DESC LIMIT ${Math.max(1, Math.floor(opts.maxSamples))}` : '';
  // The ranking carries only ids; parsed_data is fetched for the kept rows.
  const result = await query(
    `WITH recent AS (
       SELECT id, parser_id, event_type FROM parsed_logs
        WHERE created_at >= NOW() - make_interval(hours => $1) AND parser_id IS NOT NULL
        ${scan}
     ), ranked AS (
       SELECT id, parser_id, ROW_NUMBER() OVER (PARTITION BY ${partition} ORDER BY id DESC) AS rn FROM recent
     )
     SELECT r.parser_id, p.name AS parser_name, pl.parsed_data
       FROM ranked r
       JOIN parsed_logs pl ON pl.id = r.id
       JOIN parsers p ON p.id = r.parser_id
      WHERE r.rn <= $2
      ${cap}`,
    [hours, per]
  );
  const out = new Map<number, ParserSamples>();
  for (const row of result.rows) {
    const id = Number(row.parser_id);
    let entry = out.get(id);
    if (!entry) {
      entry = { parser_id: id, parser_name: row.parser_name, samples: [] };
      out.set(id, entry);
    }
    entry.samples.push(row.parsed_data || {});
  }
  return out;
}
