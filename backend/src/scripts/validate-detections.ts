#!/usr/bin/env node
/**
 * Validate detection-rule YAML files — the CI gate for community detection
 * submissions, and a local check for the rules/ directory. DB-free.
 *
 * Usage:
 *   node dist/scripts/validate-detections.js <file-or-dir> [more...]
 *   node dist/scripts/validate-detections.js rules
 *
 * Exits 0 if every file passes strict validation; 1 otherwise.
 */
import * as fs from 'fs';
import * as path from 'path';
import * as yaml from '../utils/yaml';
import { validateRule, collectRuleRegexes } from '../services/rules/rulePortable';
import { scanRegexRefs } from '../services/parser/redos';

function findRuleFiles(target: string): string[] {
  const stat = fs.statSync(target);
  if (stat.isFile()) return [target];
  const out: string[] = [];
  for (const entry of fs.readdirSync(target, { withFileTypes: true })) {
    const full = path.join(target, entry.name);
    if (entry.isDirectory()) out.push(...findRuleFiles(full));
    else if (entry.isFile() && (entry.name.endsWith('.yaml') || entry.name.endsWith('.yml'))) out.push(full);
  }
  return out;
}

function validateFile(file: string): { ok: boolean; lines: string[] } {
  let doc: unknown;
  try {
    doc = yaml.load(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    return { ok: false, lines: [`✗ ${file}`, `    YAML parse error: ${(e as Error).message}`] };
  }
  const v = validateRule(doc, { strict: true });
  const warn = v.warnings.map((w) => `    ⚠ ${w}`);
  if (!v.ok) {
    return { ok: false, lines: [`✗ ${file}`, ...v.errors.map((e) => `    error: ${e}`), ...warn] };
  }

  // ReDoS gate, the same as validate-parsers': a rule's regex conditions run on
  // every parsed log, so a PROVEN-vulnerable one (exponential or polynomial)
  // fails; an indeterminate one ('unknown') is a warning. `required` makes a
  // missing analyzer fail loudly rather than skip the check. The app's
  // write-time gate refuses the same regexes on install.
  const redos = scanRegexRefs(collectRuleRegexes(doc), { required: true });
  const fatal = redos.filter((f) => f.status === 'vulnerable' || (f.location === 'redos' && f.status === 'error'));
  for (const f of redos.filter((x) => !fatal.includes(x))) {
    warn.push(`    ⚠ ReDoS ${f.location}: ${f.status}${f.detail ? ` (${f.detail})` : ''}`);
  }
  if (fatal.length > 0) {
    const fl = [`✗ ${file}  (ReDoS-vulnerable regex)`];
    for (const f of fatal) {
      const what = f.status === 'error' ? f.detail || 'analyzer error' : `${f.status}${f.complexity ? ` — ${f.complexity}` : ''}`;
      fl.push(`    ${f.location}: ${what}`);
    }
    fl.push(
      '    Rewrite it linear: no two parts of the pattern may match the same text. For "A, later B" use a gap that cannot contain A (e.g. curl(?:[^c|]|c(?!url))*\\|) — see RULES.md, "Regex safety".'
    );
    return { ok: false, lines: [...fl, ...warn] };
  }
  return { ok: true, lines: [`✓ ${file}`, ...warn] };
}

function main() {
  const targets = process.argv.slice(2);
  if (targets.length === 0) {
    console.error('usage: validate-detections <file-or-dir> [more...]');
    process.exit(2);
  }
  const files: string[] = [];
  for (const t of targets) {
    if (!fs.existsSync(t)) { console.error(`✗ path not found: ${t}`); process.exit(2); }
    files.push(...findRuleFiles(t));
  }
  if (files.length === 0) { console.error('No .yaml/.yml rule files found.'); process.exit(2); }

  let failed = 0;
  for (const file of files.sort()) {
    const { ok, lines } = validateFile(file);
    if (!ok) failed++;
    console.log(lines.join('\n'));
  }
  console.log(`\n${files.length - failed}/${files.length} rule file(s) passed.`);
  process.exit(failed > 0 ? 1 : 0);
}

main();
