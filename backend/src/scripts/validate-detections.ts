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
import * as yaml from 'js-yaml';
import { validateRule } from '../services/rules/rulePortable';

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
