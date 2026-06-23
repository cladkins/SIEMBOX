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
 * Exits 0 if every file passes (strict) validation AND all self-tests pass; 1 otherwise.
 */
import * as fs from 'fs';
import * as path from 'path';
import { validatePortableParser, runSelfTests, PortableParser } from '../services/parser/parserPortable';

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

function validateFile(file: string): { ok: boolean; lines: string[] } {
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

  const selfTest = runSelfTests(parsed as PortableParser);
  if (!selfTest.ok) {
    const fl: string[] = [`✗ ${file}  (${selfTest.passed}/${selfTest.total} self-tests passed)`, ...lines];
    for (const f of selfTest.failures) {
      fl.push(`    sample[${f.index}]${f.description ? ` "${f.description}"` : ''}${f.matched ? '' : ' — PARSER DID NOT MATCH'}`);
      for (const m of f.mismatches) {
        fl.push(`      ${m.field}: expected ${JSON.stringify(m.expected)}, got ${JSON.stringify(m.actual)}`);
      }
    }
    return { ok: false, lines: fl };
  }

  return { ok: true, lines: [`✓ ${file}  (${selfTest.total} self-tests passed)`, ...lines] };
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
  for (const file of files.sort()) {
    const { ok, lines } = validateFile(file);
    if (!ok) failed++;
    console.log(lines.join('\n'));
  }

  console.log(`\n${files.length - failed}/${files.length} parser file(s) passed.`);
  process.exit(failed > 0 ? 1 : 0);
}

main();
