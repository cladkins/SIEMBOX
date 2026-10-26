#!/usr/bin/env node
/**
 * Validate portable parser files and run their self-tests — the entry point the
 * community catalog's CI uses to gate submissions. DB-free: it only exercises the
 * pure parse->derive->normalize pipeline (services/parser/runParser), so it runs
 * anywhere with just Node.
 *
 * Usage:
 *   node dist/scripts/validate-parsers.js <file-or-dir> [more...]
 *   node dist/scripts/validate-parsers.js catalog/parsers
 *
 * When more than one parser is given, they are also checked AS A SET, the way the
 * engine runs them (ascending priority, first match wins): every sample of a
 * non-catch-all parser must be claimed by that parser, or by an earlier one that
 * still produces all of the sample's expected fields. See
 * services/parser/parserShadowing.ts.
 *
 * Exits 0 if every file passes (strict) validation AND all self-tests pass AND no
 * parser shadows another; 1 otherwise.
 */
import * as fs from 'fs';
import * as path from 'path';
import { validatePortableParser, runSelfTests, PortableParser } from '../services/parser/parserPortable';
import { isUndecidedUnbounded, redosUndecidedMessage, scanParserRedos } from '../services/parser/redos';
import { findShadowingConflicts, formatShadowConflict } from '../services/parser/parserShadowing';

function findParserFiles(target: string): string[] {
  const stat = fs.statSync(target);
  if (stat.isFile()) return [target];
  const out: string[] = [];
  for (const entry of fs.readdirSync(target, { withFileTypes: true })) {
    const full = path.join(target, entry.name);
    if (entry.isDirectory()) out.push(...findParserFiles(full));
    else if (entry.isFile() && (entry.name.endsWith('.parser.json') || entry.name.endsWith('.parser.yaml') || entry.name.endsWith('.parser.yml'))) {
      out.push(full);
    }
  }
  return out;
}

interface FileResult {
  ok: boolean;
  lines: string[];
  /** Set once the file passes schema validation, for the cross-parser check. */
  parser?: PortableParser;
}

function validateFile(file: string): FileResult {
  const lines: string[] = [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    return { ok: false, lines: [`✗ ${file}`, `    JSON parse error: ${(e as Error).message}`] };
  }

  const validation = validatePortableParser(parsed, { strict: true });
  for (const w of validation.warnings) lines.push(`    ⚠ ${w}`);
  if (!validation.ok) {
    return { ok: false, lines: [`✗ ${file}`, ...validation.errors.map((e) => `    error: ${e}`), ...lines] };
  }

  const parser = parsed as PortableParser;
  const selfTest = runSelfTests(parser);
  if (!selfTest.ok) {
    const fl: string[] = [`✗ ${file}  (${selfTest.passed}/${selfTest.total} self-tests passed)`, ...lines];
    for (const f of selfTest.failures) {
      fl.push(`    sample[${f.index}]${f.description ? ` "${f.description}"` : ''}${f.matched ? '' : ' — PARSER DID NOT MATCH'}`);
      for (const m of f.mismatches) {
        fl.push(`      ${m.field}: expected ${JSON.stringify(m.expected)}, got ${JSON.stringify(m.actual)}`);
      }
      if (f.note) fl.push(`      two-stage transport: ${f.note}`);
    }
    return { ok: false, lines: fl, parser };
  }

  // ReDoS gate: every shipped regex must be non-backtracking — the same scan the
  // published catalog's CI runs, so local == CI. `required` makes a missing
  // analyzer fail loudly rather than silently skipping the check. PROVEN
  // backtracking (status 'vulnerable') fails the build, and so does a regex
  // recheck cannot read that V8's linear-time fallback cannot bound either (the
  // app refuses both on install). Any other per-regex 'unknown' (recheck ran
  // out of time, common for very large patterns) is surfaced as a warning so a
  // complex-but-safe pattern isn't blocked.
  const redos = scanParserRedos(parsed as PortableParser, { required: true });
  const fatal = redos.filter(
    (f) => f.status === 'vulnerable' || isUndecidedUnbounded(f) || (f.location === 'redos' && f.status === 'error')
  );
  for (const f of redos.filter((x) => !fatal.includes(x))) {
    lines.push(`    ⚠ ReDoS ${f.location}: ${f.status}${f.complexity ? ` — ${f.complexity}` : ''}${f.detail ? ` (${f.detail})` : ''}`);
  }
  if (fatal.length > 0) {
    const why = fatal.every(isUndecidedUnbounded) ? 'regex the ReDoS check cannot read' : 'ReDoS-vulnerable regex';
    const fl: string[] = [`✗ ${file}  (${why})`];
    for (const f of fatal) {
      if (isUndecidedUnbounded(f)) {
        fl.push(`    ${redosUndecidedMessage(f, 'contributing')}`);
        continue;
      }
      const what = f.status === 'error' ? f.detail || 'analyzer error' : `${f.status}${f.complexity ? ` — ${f.complexity}` : ''}`;
      fl.push(`    ${f.location}: ${what}`);
    }
    fl.push('    Rewrite to avoid catastrophic backtracking: anchor segments, avoid adjacent \\s+/.* over the same text, prefer bounded character classes.');
    return { ok: false, lines: [...fl, ...lines], parser };
  }

  return { ok: true, lines: [`✓ ${file}  (${selfTest.total} self-tests passed, ReDoS-safe)`, ...lines], parser };
}

function main() {
  const targets = process.argv.slice(2);
  if (targets.length === 0) {
    console.error('usage: validate-parsers <file-or-dir> [more...]');
    process.exit(2);
  }

  const files: string[] = [];
  for (const t of targets) {
    if (!fs.existsSync(t)) {
      console.error(`✗ path not found: ${t}`);
      process.exit(2);
    }
    files.push(...findParserFiles(t));
  }

  if (files.length === 0) {
    console.error('No *.parser.json files found.');
    process.exit(2);
  }

  let failed = 0;
  const parsers: PortableParser[] = [];
  for (const file of files.sort()) {
    const { ok, lines, parser } = validateFile(file);
    if (!ok) failed++;
    if (parser) parsers.push(parser);
    console.log(lines.join('\n'));
  }
  console.log(`\n${files.length - failed}/${files.length} parser file(s) passed.`);

  // Cross-parser check: a parser that passes its own self-tests can still never
  // fire if an earlier parser (lower priority number) claims its logs.
  let conflicts = 0;
  if (parsers.length > 1) {
    const found = findShadowingConflicts(parsers);
    conflicts = found.length;
    console.log(
      `\nParser selection order (${parsers.length} parsers, ascending priority, first match wins; ` +
        'ties broken by name here, by install order in production):'
    );
    for (const c of found) console.log(formatShadowConflict(c).join('\n'));
    console.log(
      conflicts === 0
        ? '✓ no parser claims another parser\'s samples without producing their expected fields.'
        : `\n${conflicts} sample(s) claimed by the wrong parser.`
    );
  }

  process.exit(failed > 0 || conflicts > 0 ? 1 : 0);
}

main();
