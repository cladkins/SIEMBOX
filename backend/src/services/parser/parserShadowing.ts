/**
 * Cross-parser shadowing check: does each parser actually get the logs its own
 * samples describe, once every other parser in the set is installed too?
 *
 * The engine (ParserEngine.processLog) tries enabled parsers in ascending
 * `priority` and stops at the first one that matches. A parser's self-tests run
 * it in isolation, so they pass even when an earlier parser claims the same line
 * in production and the parser never fires. This module replays that selection
 * over a whole set of parsers:
 *
 *   For every sample of every non-catch-all parser (the "owner"), find the first
 *   parser in engine order that matches the line the engine would see. If that
 *   claimer is not the owner, it must still produce every field the owner
 *   produces for the sample's `expect` — otherwise the owner is shadowed and
 *   the expected fields are lost.
 *
 * A claimer that yields a superset of the owner's expected fields is fine (a
 * stricter, more specific parser may sit ahead of a general one). Catch-all
 * parsers — no `field_mappings`, e.g. the generic `json-parser` — are exempt as
 * owners (every specific parser of that format is meant to win over them), but
 * still count as claimers.
 *
 * Order: ascending priority (missing = 100, the DB default), then by name. The
 * DB breaks priority ties by row id, i.e. install order, which a file-based
 * check cannot know; name is the deterministic stand-in. Equal priorities whose
 * samples overlap are therefore order-dependent in production — give them
 * distinct priorities.
 *
 * Pure and DB-free: used by `validate-parsers` (catalog CI) and by the
 * catalog tests.
 */
import { runParser, ParserDef, RunResult } from './runParser';
import { expectedFieldMatches, sampleEngineInput, ParserTestSample } from './parserPortable';

export const DEFAULT_PARSER_PRIORITY = 100;

export interface ShadowingParser extends ParserDef {
  priority?: number;
  test_samples?: ParserTestSample[];
}

export interface FieldMismatch {
  field: string;
  expected: string | number | boolean | null;
  actual: unknown;
}

export interface ShadowConflict {
  /** The parser whose sample was hijacked. */
  owner: string;
  ownerPriority: number;
  sampleIndex: number;
  description?: string;
  /** The line the engine sees for this sample (header-stripped when applicable). */
  input: string;
  /** True when `input` is the header-stripped form of a full syslog sample. */
  stripped: boolean;
  /** The parser that matches first in engine order. */
  claimedBy: string;
  claimedByPriority: number;
  /** Expected fields the claimer gets wrong or does not produce. */
  mismatches: FieldMismatch[];
}

export function priorityOf(p: { priority?: number | null }): number {
  return typeof p.priority === 'number' ? p.priority : DEFAULT_PARSER_PRIORITY;
}

/** Engine selection order: ascending priority, ties by name (stand-in for DB id). */
export function engineOrder<T extends ShadowingParser>(parsers: readonly T[]): T[] {
  return [...parsers].sort((a, b) => priorityOf(a) - priorityOf(b) || compareNames(a.name, b.name));
}

function compareNames(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0; // locale-independent so CI and laptops agree
}

/** A catch-all declares no field_mappings: it claims anything of its format and maps nothing. */
export function isCatchAll(p: Pick<ParserDef, 'field_mappings'>): boolean {
  return Object.keys(p.field_mappings || {}).length === 0;
}

function toDef(p: ShadowingParser): ParserDef {
  return {
    name: p.name,
    parser_type: p.parser_type,
    pattern: p.pattern,
    field_mappings: p.field_mappings || {},
    derivations: p.derivations,
    event_type: p.event_type,
  };
}

/** The first parser in `ordered` that matches `message`, as the engine would pick it. */
export function selectFirstMatch<T extends ShadowingParser>(
  ordered: readonly T[],
  message: string,
  packetSourceIp?: string
): { parser: T; result: RunResult } | null {
  for (const parser of ordered) {
    const result = runParser(toDef(parser), message, { packetSourceIp });
    if (result) return { parser, result };
  }
  return null;
}

/**
 * Every sample (of a non-catch-all parser) that an earlier parser claims without
 * producing the fields the sample expects. Empty means no parser shadows another.
 */
export function findShadowingConflicts(parsers: readonly ShadowingParser[]): ShadowConflict[] {
  const ordered = engineOrder(parsers);
  const conflicts: ShadowConflict[] = [];

  for (const owner of ordered) {
    if (isCatchAll(owner)) continue;
    const ownerDef = toDef(owner);

    (owner.test_samples || []).forEach((sample, sampleIndex) => {
      const { input, stripped } = sampleEngineInput(sample);
      const ctx = { packetSourceIp: sample.packet_source_ip };

      // Only what the owner itself delivers on the engine's input is at stake.
      // A negative sample (owner doesn't match) or an expectation the owner
      // misses is the self-tests' business, not a shadowing conflict.
      const own = runParser(ownerDef, input, ctx);
      if (!own) return;
      const expected = Object.entries(sample.expect || {}).filter(([field, value]) =>
        expectedFieldMatches(own.fields[field], value)
      );
      if (expected.length === 0) return;

      const first = selectFirstMatch(ordered, input, sample.packet_source_ip);
      if (!first || first.parser === owner) return;

      const mismatches: FieldMismatch[] = [];
      for (const [field, value] of expected) {
        if (!expectedFieldMatches(first.result.fields[field], value)) {
          mismatches.push({ field, expected: value, actual: first.result.fields[field] });
        }
      }
      if (mismatches.length === 0) return;

      conflicts.push({
        owner: owner.name,
        ownerPriority: priorityOf(owner),
        sampleIndex,
        description: sample.description,
        input,
        stripped,
        claimedBy: first.parser.name,
        claimedByPriority: priorityOf(first.parser),
        mismatches,
      });
    });
  }

  return conflicts;
}

/** Human-readable lines for one conflict (validator output). */
export function formatShadowConflict(c: ShadowConflict): string[] {
  const sample = `${c.owner} sample[${c.sampleIndex}]${c.description ? ` "${c.description}"` : ''}`;
  const tie = c.ownerPriority === c.claimedByPriority ? ' (same priority: tie broken by name here, by install order in production)' : '';
  const lines = [
    `✗ ${sample} is claimed by ${c.claimedBy} (priority ${c.claimedByPriority}) before ${c.owner} (priority ${c.ownerPriority})${tie}`,
    `    ${c.stripped ? 'engine input (header-stripped)' : 'engine input'}: ${JSON.stringify(c.input.length > 160 ? `${c.input.slice(0, 160)}…` : c.input)}`,
  ];
  for (const m of c.mismatches) {
    lines.push(`    ${m.field}: expected ${JSON.stringify(m.expected)}, ${c.claimedBy} gives ${JSON.stringify(m.actual)}`);
  }
  lines.push(
    `    Fix: give ${c.owner} a lower priority number than ${c.claimedBy}, or make ${c.claimedBy}'s pattern ` +
      `stop matching this line (or make it produce these fields).`
  );
  return lines;
}
