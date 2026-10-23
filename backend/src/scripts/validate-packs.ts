#!/usr/bin/env node
/**
 * Validate Content Pack files (packs/<id>.pack.yaml) — the CI gate for the
 * catalog's packs, and a local check for this repo's mirror (catalog/packs/).
 * DB-free and network-free.
 *
 * Usage:
 *   node dist/scripts/validate-packs.js <packs-dir-or-file> [more...]
 *        [--parsers <catalog parsers dir>] [--detections <catalog detections dir>]
 *
 *   npm run validate-packs -- ../catalog/packs --parsers ../catalog/parsers --detections ../rules
 *   npm run validate-packs -- <siembox-catalog>/packs    # finds ../parsers and ../detections
 *
 * Checks: strict schema (packFormat.validatePack), the file name matches the
 * pack id, ids are unique, every referenced parser exists in the parsers dir,
 * every detection category / tag / name matches a rule in the detections dir,
 * Sigma ids are UUIDs (not looked up: no network), setup guide size caps, and
 * no raw HTML, images or unsafe links in the guide markdown. Without a parsers
 * or detections dir (none given and no sibling found) those references are not
 * checked, and the run says so.
 *
 * Exits 0 if every pack passes; 1 otherwise; 2 on bad usage.
 */
import * as fs from 'fs';
import * as path from 'path';
import * as yaml from '../utils/yaml';
import { PACK_FILE_SUFFIX, validatePack, type PackCatalogIndex } from '../services/packs/packFormat';

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

function parserIndex(dir: string): Set<string> {
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

function detectionIndex(dir: string): NonNullable<PackCatalogIndex['detections']> {
  const out: NonNullable<PackCatalogIndex['detections']> = [];
  for (const f of findFiles(dir, (n) => n.endsWith('.yaml') || n.endsWith('.yml'))) {
    try {
      const r = yaml.load(fs.readFileSync(f, 'utf8')) as any;
      if (!r || typeof r.name !== 'string') continue;
      out.push({
        name: r.name,
        // As the catalog lists it: detections/<category>/<file>.
        path: ['detections', ...path.relative(dir, f).split(path.sep)].join('/'),
        tags: Array.isArray(r.tags) ? r.tags.map(String) : [],
      });
    } catch {
      /* validate-detections reports unreadable rule files */
    }
  }
  return out;
}

function main() {
  const args = process.argv.slice(2);
  const targets: string[] = [];
  let parsersDir: string | undefined;
  let detectionsDir: string | undefined;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--parsers') parsersDir = args[++i];
    else if (args[i] === '--detections') detectionsDir = args[++i];
    else targets.push(args[i]);
  }
  if (targets.length === 0) {
    console.error('usage: validate-packs <packs-dir-or-file> [more...] [--parsers <dir>] [--detections <dir>]');
    process.exit(2);
  }
  for (const t of [...targets, parsersDir, detectionsDir]) {
    if (t !== undefined && !fs.existsSync(t)) {
      console.error(`✗ path not found: ${t}`);
      process.exit(2);
    }
  }
  // The catalog layout: packs/, parsers/ and detections/ side by side.
  const first = fs.statSync(targets[0]).isDirectory() ? targets[0] : path.dirname(targets[0]);
  const sibling = (name: string) => {
    const p = path.join(first, '..', name);
    return fs.existsSync(p) && fs.statSync(p).isDirectory() ? p : undefined;
  };
  parsersDir ??= sibling('parsers');
  detectionsDir ??= sibling('detections');

  const index: PackCatalogIndex = {};
  if (parsersDir) index.parsers = parserIndex(parsersDir);
  else console.log('⚠ no parsers dir (--parsers): parser references are not checked');
  if (detectionsDir) index.detections = detectionIndex(detectionsDir);
  else console.log('⚠ no detections dir (--detections): detection selectors are not checked');

  const files = targets.flatMap((t) => findFiles(t, (n) => n.endsWith(PACK_FILE_SUFFIX) || n.endsWith('.pack.yml') || n.endsWith('.pack.json')));
  if (files.length === 0) {
    console.error(`No *${PACK_FILE_SUFFIX} files found.`);
    process.exit(2);
  }

  let failed = 0;
  const seen = new Map<string, string>();
  for (const file of files.sort()) {
    const lines: string[] = [];
    const base = path.basename(file);
    let errors: string[] = [];
    let warnings: string[] = [];
    if (!base.endsWith(PACK_FILE_SUFFIX)) {
      errors.push(`pack files are named <id>${PACK_FILE_SUFFIX}`);
    } else {
      let doc: unknown;
      try {
        doc = yaml.load(fs.readFileSync(file, 'utf8'));
      } catch (e) {
        errors.push(`YAML parse error: ${(e as Error).message}`);
      }
      if (errors.length === 0) {
        const v = validatePack(doc, { strict: true, index, expectId: base.slice(0, -PACK_FILE_SUFFIX.length) });
        errors = v.errors;
        warnings = v.warnings;
        if (v.pack) {
          const other = seen.get(v.pack.id);
          if (other) errors.push(`pack id "${v.pack.id}" is also used by ${other}`);
          else seen.set(v.pack.id, file);
          if (errors.length === 0) {
            const p = v.pack;
            const d = p.detections;
            lines.push(
              `    v${p.version}: ${p.parsers.length} parser(s), detections ${[
                d.categories.length ? `categories ${d.categories.join(', ')}` : '',
                d.tags.length ? `tags ${d.tags.join(', ')}` : '',
                d.names.length ? `${d.names.length} by name` : '',
              ]
                .filter(Boolean)
                .join('; ') || 'none'}, ${p.sigma.length} Sigma rule(s), ${p.setup.length} setup step(s)`
            );
          }
        }
      }
    }
    if (errors.length > 0) failed++;
    console.log(
      [
        `${errors.length ? '✗' : '✓'} ${file}`,
        ...errors.map((e) => `    error: ${e}`),
        ...lines,
        ...warnings.map((w) => `    ⚠ ${w}`),
      ].join('\n')
    );
  }
  console.log(`\n${files.length - failed}/${files.length} pack file(s) passed.`);
  process.exit(failed > 0 ? 1 : 0);
}

main();
