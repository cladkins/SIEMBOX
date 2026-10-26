#!/usr/bin/env node
/**
 * Validate application signature files (applications/<id>.app.yaml) — the CI
 * gate for the catalog's application signatures, and a local check for this
 * repo's mirror (catalog/applications/). DB-free and network-free.
 *
 * Usage:
 *   node dist/scripts/validate-applications.js <applications-dir-or-file> [more...] [--parsers <catalog parsers dir>]
 *
 *   npm run validate-applications -- ../catalog/applications --parsers ../catalog/parsers
 *   npm run validate-applications -- <siembox-catalog>/applications   # finds ../parsers
 *
 * Checks: strict schema (appFormat.validateApplication), the file name matches
 * the id, ids are unique, no matcher value is claimed by two applications,
 * every `supersedes` names a signature in the set, every referenced parser
 * exists in the parsers dir, every regex passes the ReDoS check (recheck, the
 * same analysis and the same refusals as validate-parsers / -detections), and
 * every signature's own tests pass when run against the WHOLE set (so a test
 * also proves that no other signature takes the evidence instead).
 *
 * Exits 0 if every file passes; 1 otherwise; 2 on bad usage.
 */
import * as fs from 'fs';
import * as path from 'path';
import * as yaml from '../utils/yaml';
import {
  APP_FILE_SUFFIX,
  collectAppRegexes,
  crossCheckApplications,
  matcherKinds,
  validateApplication,
  type AppSignature,
} from '../services/applications/appFormat';
import { AppIndex, runAppTests } from '../services/applications/matchers';
import { isUndecidedUnbounded, redosUndecidedMessage, scanRegexRefs } from '../services/parser/redos';

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

function parserNames(dir: string): Set<string> {
  const names = new Set<string>();
  for (const f of findFiles(dir, (n) => n.endsWith('.parser.json'))) {
    try {
      const p = JSON.parse(fs.readFileSync(f, 'utf8'));
      if (p && typeof p.name === 'string') names.add(p.name);
    } catch {
      /* validate-parsers reports unreadable parser files */
    }
  }
  return names;
}

/** The ReDoS gate for one signature: fatal findings as error lines, the rest as warnings. */
export function redosProblems(app: AppSignature): { errors: string[]; warnings: string[] } {
  const findings = scanRegexRefs(collectAppRegexes(app), { required: true });
  const errors: string[] = [];
  const warnings: string[] = [];
  for (const f of findings) {
    if (f.status === 'vulnerable') {
      errors.push(`ReDoS: regex at ${f.location} is vulnerable${f.complexity ? ` (${f.complexity})` : ''} — rewrite it linear before contributing`);
    } else if (isUndecidedUnbounded(f)) {
      errors.push(redosUndecidedMessage(f, 'contributing'));
    } else if (f.location === 'redos' && f.status === 'error') {
      errors.push(`ReDoS check unavailable: ${f.detail ?? 'analyzer error'}`);
    } else {
      warnings.push(`ReDoS ${f.location}: ${f.status}${f.detail ? ` (${f.detail})` : ''}`);
    }
  }
  return { errors, warnings };
}

function main() {
  const args = process.argv.slice(2);
  const targets: string[] = [];
  let parsersDir: string | undefined;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--parsers') parsersDir = args[++i];
    else targets.push(args[i]);
  }
  if (targets.length === 0) {
    console.error('usage: validate-applications <applications-dir-or-file> [more...] [--parsers <dir>]');
    process.exit(2);
  }
  for (const t of [...targets, parsersDir]) {
    if (t !== undefined && !fs.existsSync(t)) {
      console.error(`✗ path not found: ${t}`);
      process.exit(2);
    }
  }
  const first = fs.statSync(targets[0]).isDirectory() ? targets[0] : path.dirname(targets[0]);
  if (parsersDir === undefined) {
    const sibling = path.join(first, '..', 'parsers');
    if (fs.existsSync(sibling) && fs.statSync(sibling).isDirectory()) parsersDir = sibling;
  }
  const parsers = parsersDir ? parserNames(parsersDir) : null;
  if (!parsers) console.log('⚠ no parsers dir (--parsers): match.parser references are not checked');

  const files = targets.flatMap((t) => findFiles(t, (n) => n.endsWith(APP_FILE_SUFFIX) || n.endsWith('.app.yml') || n.endsWith('.app.json'))).sort();
  if (files.length === 0) {
    console.error(`No *${APP_FILE_SUFFIX} files found.`);
    process.exit(2);
  }

  const results = new Map<string, { errors: string[]; warnings: string[]; lines: string[]; app?: AppSignature }>();
  const apps: AppSignature[] = [];
  const fileOf = new Map<string, string>();
  for (const file of files) {
    const r = { errors: [] as string[], warnings: [] as string[], lines: [] as string[], app: undefined as AppSignature | undefined };
    results.set(file, r);
    const base = path.basename(file);
    if (!base.endsWith(APP_FILE_SUFFIX)) {
      r.errors.push(`signature files are named <id>${APP_FILE_SUFFIX}`);
      continue;
    }
    let doc: unknown;
    try {
      doc = yaml.load(fs.readFileSync(file, 'utf8'));
    } catch (e) {
      r.errors.push(`YAML parse error: ${(e as Error).message}`);
      continue;
    }
    const v = validateApplication(doc, { strict: true, expectId: base.slice(0, -APP_FILE_SUFFIX.length) });
    r.errors.push(...v.errors);
    r.warnings.push(...v.warnings);
    if (!v.app) continue;
    r.app = v.app;
    if (parsers) for (const p of v.app.match.parser) if (!parsers.has(p)) r.errors.push(`match.parser "${p}" is not a parser in ${parsersDir}`);
    const redos = redosProblems(v.app);
    r.errors.push(...redos.errors);
    r.warnings.push(...redos.warnings);
    if (fileOf.has(v.app.id)) r.errors.push(`application id "${v.app.id}" is also used by ${fileOf.get(v.app.id)}`);
    else {
      fileOf.set(v.app.id, file);
      apps.push(v.app);
    }
  }

  // Across the set: claims, supersedes, then each signature's tests against all of them.
  for (const p of crossCheckApplications(apps)) {
    const file = fileOf.get(p.id);
    if (file) results.get(file)!.errors.push(p.error);
  }
  const index = new AppIndex(apps);
  for (const app of apps) {
    const r = results.get(fileOf.get(app.id)!)!;
    r.errors.push(...runAppTests(app, index));
    if (r.errors.length === 0) {
      r.lines.push(`    ${app.name} (${app.category}): ${matcherKinds(app.match).join(', ')}; ${app.tests.length} test(s) passed`);
    }
  }

  let failed = 0;
  for (const file of files) {
    const r = results.get(file)!;
    if (r.errors.length > 0) failed++;
    console.log(
      [`${r.errors.length ? '✗' : '✓'} ${file}`, ...r.errors.map((e) => `    error: ${e}`), ...r.lines, ...r.warnings.map((w) => `    ⚠ ${w}`)].join('\n')
    );
  }
  console.log(`\n${files.length - failed}/${files.length} application signature file(s) passed.`);
  process.exit(failed > 0 ? 1 : 0);
}

if (require.main === module) main();
