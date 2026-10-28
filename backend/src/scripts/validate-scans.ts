#!/usr/bin/env node
/**
 * Validate suggested-scan files (scans/<id>.scan.yaml) — the CI gate for the
 * catalog's suggested scans, and a local check for this repo's mirror
 * (catalog/scans/). DB-free and network-free.
 *
 * Usage:
 *   node dist/scripts/validate-scans.js <scans-dir-or-file> [more...]
 *
 *   npm run validate-scans -- ../catalog/scans
 *   npm run validate-scans -- <siembox-catalog>/scans
 *
 * Checks (services/scanSuggestions/scanFormat.ts): strict schema, the file name
 * matches the id, ids and names are unique, the schedule is a valid calendar
 * schedule (utils/scheduleTiming, the Scheduled Scans rules) without a time
 * zone, the options pass the checks the Scheduled Scans route
 * (services/scanner/scheduleOptions) or the endpoint scan-policy route
 * (services/edr/scanPolicies) applies, every input the kind needs is listed,
 * no target is named anywhere (no IPs, CIDRs or host names in options or
 * inputs; no IPs or CIDRs in any text), Nuclei template selections are well
 * formed, and a selection that can run intrusive templates is declared
 * intrusive: true with a note. Unknown Nuclei tags are warnings.
 *
 * Exits 0 if every file passes; 1 otherwise; 2 on bad usage.
 */
import * as fs from 'fs';
import * as path from 'path';
import * as yaml from '../utils/yaml';
import { SCAN_FILE_SUFFIX, crossCheckSuggestions, validateSuggestion, type ScanSuggestion } from '../services/scanSuggestions/scanFormat';

function findFiles(target: string, accept: (name: string) => boolean): string[] {
  const stat = fs.statSync(target);
  if (stat.isFile()) return [target];
  const out: string[] = [];
  for (const entry of fs.readdirSync(target, { withFileTypes: true })) {
    const full = path.join(target, entry.name);
    if (entry.isDirectory()) out.push(...findFiles(full, accept));
    else if (entry.isFile() && accept(entry.name)) out.push(full);
  }
  return out;
}

function describe(s: ScanSuggestion): string {
  const timing = s.schedule ? `${s.schedule.frequency}${s.schedule.time ? ` ${s.schedule.time}` : ''}` : 'per-scan timing';
  const inputs = s.inputs.map((i) => `${i.field}${i.required ? '' : '?'}`).join(', ') || 'nothing';
  return `    ${s.name} (${s.kind}, ${s.category}; ${timing}; fill in: ${inputs}${s.intrusive ? '; INTRUSIVE' : ''})`;
}

function main() {
  const targets = process.argv.slice(2);
  if (targets.length === 0) {
    console.error('usage: validate-scans <scans-dir-or-file> [more...]');
    process.exit(2);
  }
  for (const t of targets) {
    if (!fs.existsSync(t)) {
      console.error(`✗ path not found: ${t}`);
      process.exit(2);
    }
  }
  const files = targets.flatMap((t) => findFiles(t, (n) => n.endsWith(SCAN_FILE_SUFFIX) || n.endsWith('.scan.yml') || n.endsWith('.scan.json'))).sort();
  if (files.length === 0) {
    console.error(`No *${SCAN_FILE_SUFFIX} files found.`);
    process.exit(2);
  }

  const results = new Map<string, { errors: string[]; warnings: string[]; suggestion?: ScanSuggestion }>();
  const all: ScanSuggestion[] = [];
  for (const file of files) {
    const r = { errors: [] as string[], warnings: [] as string[], suggestion: undefined as ScanSuggestion | undefined };
    results.set(file, r);
    const base = path.basename(file);
    if (!base.endsWith(SCAN_FILE_SUFFIX)) {
      r.errors.push(`suggestion files are named <id>${SCAN_FILE_SUFFIX}`);
      continue;
    }
    let doc: unknown;
    try {
      doc = yaml.load(fs.readFileSync(file, 'utf8'));
    } catch (e) {
      r.errors.push(`YAML parse error: ${(e as Error).message}`);
      continue;
    }
    const v = validateSuggestion(doc, { strict: true, expectId: base.slice(0, -SCAN_FILE_SUFFIX.length) });
    r.errors.push(...v.errors);
    r.warnings.push(...v.warnings);
    if (!v.suggestion) continue;
    r.suggestion = v.suggestion;
    all.push(v.suggestion);
  }
  for (const p of crossCheckSuggestions(all)) {
    for (const r of results.values()) if (r.suggestion?.id === p.id) r.errors.push(p.error);
  }

  let failed = 0;
  for (const file of files) {
    const r = results.get(file)!;
    if (r.errors.length > 0) failed++;
    console.log(
      [
        `${r.errors.length ? '✗' : '✓'} ${file}`,
        ...r.errors.map((e) => `    error: ${e}`),
        ...(r.errors.length === 0 && r.suggestion ? [describe(r.suggestion)] : []),
        ...r.warnings.map((w) => `    ⚠ ${w}`),
      ].join('\n')
    );
  }
  console.log(`\n${files.length - failed}/${files.length} suggested scan file(s) passed.`);
  process.exit(failed > 0 ? 1 : 0);
}

if (require.main === module) main();
