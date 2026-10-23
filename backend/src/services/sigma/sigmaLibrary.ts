/**
 * SigmaHQ library: the SigmaHQ release archive -> library entries (DB-free,
 * unit-tested). The fetch, the DB cache and the routes live in sigmaStore.ts.
 *
 * Each rule file of the archive is parsed with the backend's YAML loader
 * (utils/yaml, js-yaml 4: data only, no custom tags, no code) and converted
 * with the same converter as the Sigma import (rules/sigmaConvert.ts: OR
 * becomes "(part i of N)" rules, NOT becomes exclude groups). A rule is
 * convertible only when every part converts, nothing of its detection was
 * skipped (a dropped selection field or exclusion would make the rule match
 * more than the Sigma rule does) and every part passes validateRule.
 *
 * Each converted part carries attribution, as the Detection Rule License 1.1
 * requires: author, Sigma id, release and a link to the rule file.
 */
import crypto from 'crypto';
import * as yaml from '../../utils/yaml';
import { readZip, type ZipLimits } from '../../utils/zipReader';
import { sigmaToPortableAll } from '../rules/sigmaConvert';
import { validateRule, type PortableRule } from '../rules/rulePortable';
import { analyzeAttackTags } from '../attack/attackTags';

/** The SigmaHQ repository the release comes from (fixed: outbound fetches go only to GitHub). */
export const SIGMAHQ_REPO = 'SigmaHQ/sigma';

/**
 * Release assets an install may choose (SIGMAHQ_RELEASE_ASSET). The default,
 * sigma_core+.zip, is SigmaHQ's stable set: rules with status stable or test
 * and level medium, high or critical. sigma_core.zip drops the medium rules,
 * sigma_core++.zip adds experimental ones, sigma_all_rules.zip adds the
 * emerging-threats rules too. Deprecated and unsupported rules are in none.
 */
export const SIGMAHQ_ASSETS = [
  'sigma_core+.zip',
  'sigma_core.zip',
  'sigma_core++.zip',
  'sigma_all_rules.zip',
  'sigma_emerging_threats_addon.zip',
] as const;
export const DEFAULT_SIGMAHQ_ASSET = 'sigma_core+.zip';

/** Zip-bomb guards. sigma_all_rules.zip (r2026-07-01) is 3.2 MB, 3,303 entries, 5.0 MB unpacked, largest file 295 KB. */
export const SIGMA_ZIP_LIMITS: ZipLimits = {
  maxArchiveBytes: 32 * 1024 * 1024,
  maxEntries: 20_000,
  maxEntryBytes: 1024 * 1024,
  maxTotalBytes: 64 * 1024 * 1024,
};

/** Statuses the library shows; deprecated and unsupported rules are left out. */
export const LISTED_STATUSES = new Set(['stable', 'test', 'experimental']);

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface SigmaLibraryRule {
  sigma_id: string;
  /** Path inside the release, e.g. rules/web/proxy_generic/proxy_ua_hacktool.yml. */
  path: string;
  title: string;
  description: string | null;
  level: string | null;
  status: string | null;
  product: string | null;
  category: string | null;
  service: string | null;
  tags: string[];
  author: string | null;
  rule_date: string | null;
  modified: string | null;
  refs: string[];
  /** sha256 of the rule file: what "update available" compares. */
  content_hash: string;
  convertible: boolean;
  errors: string[];
  warnings: string[];
  /** The converted SIEMBox rules, one per OR alternative (empty when not convertible). */
  parts: PortableRule[];
  /** Fields the converted conditions key on. */
  fields: string[];
}

export interface SigmaReleaseInfo {
  tag: string;
  asset: string;
  release_date: string | null;
  commit_hash: string | null;
}

export interface SigmaBuildStats {
  files: number;
  rules: number;
  convertible: number;
  skipped: { not_listed: number; no_id: number; duplicate_id: number; unreadable: number };
}

/** The upstream rule file at a release (DRL attribution link). */
export function sigmaRuleUrl(tag: string, path: string): string {
  const safePath = path.split('/').map(encodeURIComponent).join('/');
  return `https://github.com/${SIGMAHQ_REPO}/blob/${encodeURIComponent(tag)}/${safePath}`;
}

function str(v: unknown): string | null {
  if (typeof v === 'string') return v.trim() || null;
  if (v instanceof Date && !isNaN(v.getTime())) return v.toISOString().slice(0, 10);
  if (typeof v === 'number') return String(v);
  return null;
}

function strList(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}

/** A rule file in the archive: rules*\/...\/*.yml. */
export function isRuleFile(name: string): boolean {
  return /^rules[a-z-]*\//.test(name) && /\.ya?ml$/i.test(name);
}

/** The `Release Date:` / `Commit-Hash:` lines of the archive's version.txt. */
export function parseVersionTxt(text: string): { release_date: string | null; commit_hash: string | null } {
  const line = (key: string) => {
    for (const l of text.split('\n')) {
      const i = l.indexOf(':');
      if (i > 0 && l.slice(0, i).trim().toLowerCase() === key) return l.slice(i + 1).trim().slice(0, 64) || null;
    }
    return null;
  };
  return { release_date: line('release date'), commit_hash: line('commit-hash') };
}

/** Warnings that mean the conversion dropped part of the detection. */
function isLossy(warning: string): boolean {
  return warning.startsWith('Skipped ') || warning.startsWith('Dropped an exclusion');
}

/** Description + attribution (DRL 1.1) for each converted part. */
function attribution(rule: { sigma_id: string; author: string | null; path: string }, tag: string): string {
  return (
    `SigmaHQ rule ${rule.sigma_id}${rule.author ? ` by ${rule.author}` : ''}, release ${tag}: ` +
    `${sigmaRuleUrl(tag, rule.path)}. Licensed under the Detection Rule License (DRL) 1.1.`
  );
}

/** One rule file -> a library entry, or the reason it is left out. */
export function libraryRuleFromYaml(
  path: string,
  text: string,
  tag: string
): { rule: SigmaLibraryRule } | { skip: 'not_listed' | 'no_id' | 'unreadable' } {
  let doc: any;
  try {
    const docs = (yaml.loadAll(text) as unknown[]).filter((d) => d !== null && d !== undefined);
    if (docs.length !== 1) return { skip: 'unreadable' }; // one rule per file in SigmaHQ
    doc = docs[0];
  } catch {
    return { skip: 'unreadable' };
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return { skip: 'unreadable' };
  const sigmaId = typeof doc.id === 'string' ? doc.id.trim().toLowerCase() : '';
  if (!UUID_RE.test(sigmaId)) return { skip: 'no_id' };
  const status = str(doc.status)?.toLowerCase() ?? null;
  if (status && !LISTED_STATUSES.has(status)) return { skip: 'not_listed' };
  const title = str(doc.title);
  if (!title) return { skip: 'unreadable' };

  const logsource = doc.logsource && typeof doc.logsource === 'object' ? doc.logsource : {};
  const base = {
    sigma_id: sigmaId,
    path,
    title: title.slice(0, 250),
    description: str(doc.description),
    level: str(doc.level)?.toLowerCase() ?? null,
    status,
    product: str(logsource.product)?.toLowerCase() ?? null,
    category: str(logsource.category)?.toLowerCase() ?? null,
    service: str(logsource.service)?.toLowerCase() ?? null,
    tags: strList(doc.tags),
    author: str(doc.author),
    rule_date: str(doc.date),
    modified: str(doc.modified),
    refs: strList(doc.references),
    content_hash: crypto.createHash('sha256').update(text).digest('hex'),
  };

  const errors: string[] = [];
  const warnings: string[] = [];
  const parts: PortableRule[] = [];
  const fields = new Set<string>();
  let converted;
  try {
    converted = sigmaToPortableAll(doc);
  } catch (e) {
    converted = [{ rule: null, errors: [`conversion failed: ${e instanceof Error ? e.message : String(e)}`], warnings: [] }];
  }
  for (const c of converted) {
    for (const w of c.warnings) if (!warnings.includes(w)) warnings.push(w);
    if (!c.rule) {
      for (const e of c.errors) if (!errors.includes(e)) errors.push(e);
      continue;
    }
    const v = validateRule(c.rule, { strict: false });
    if (!v.ok) {
      for (const e of v.errors) if (!errors.includes(e)) errors.push(e);
      continue;
    }
    const rule: PortableRule = {
      ...c.rule,
      // `sigmahq` marks library installs; `imported` is the paste import's marker.
      tags: (c.rule.tags ?? []).map((t) => (t === 'imported' ? 'sigmahq' : t)),
      description: [c.rule.description, attribution(base, tag)].filter(Boolean).join('\n\n'),
      enabled: false,
    };
    parts.push(rule);
    for (const f of c.fieldsUsed ?? []) fields.add(f);
  }
  const lossy = warnings.filter(isLossy);
  if (errors.length === 0 && lossy.length > 0) {
    errors.push(`not converted faithfully: ${lossy.join('; ')}`);
  }
  const convertible = errors.length === 0 && parts.length > 0;
  return {
    rule: {
      ...base,
      convertible,
      errors,
      warnings: warnings.filter((w) => !isLossy(w)),
      parts: convertible ? parts : [],
      fields: convertible ? [...fields] : [],
    },
  };
}

/**
 * Unpack the release archive (in memory, capped) and build the library. Throws
 * ZipError for an archive outside the caps, and Error when it holds no rules.
 */
export function buildSigmaLibrary(
  archive: Buffer,
  release: { tag: string; asset: string }
): { info: SigmaReleaseInfo; rules: SigmaLibraryRule[]; stats: SigmaBuildStats } {
  const entries = readZip(archive, SIGMA_ZIP_LIMITS, (name) => isRuleFile(name) || name === 'version.txt');
  const version = entries.find((e) => e.name === 'version.txt');
  const info: SigmaReleaseInfo = {
    tag: release.tag,
    asset: release.asset,
    ...(version ? parseVersionTxt(version.data.toString('utf8')) : { release_date: null, commit_hash: null }),
  };
  const stats: SigmaBuildStats = {
    files: 0,
    rules: 0,
    convertible: 0,
    skipped: { not_listed: 0, no_id: 0, duplicate_id: 0, unreadable: 0 },
  };
  const byId = new Map<string, SigmaLibraryRule>();
  for (const e of entries) {
    if (e.name === 'version.txt') continue;
    stats.files++;
    const r = libraryRuleFromYaml(e.name, e.data.toString('utf8'), release.tag);
    if ('skip' in r) {
      stats.skipped[r.skip]++;
      continue;
    }
    if (byId.has(r.rule.sigma_id)) {
      stats.skipped.duplicate_id++;
      continue;
    }
    byId.set(r.rule.sigma_id, r.rule);
  }
  const rules = [...byId.values()].sort((a, b) => a.title.localeCompare(b.title));
  if (rules.length === 0) throw new Error('the SigmaHQ archive holds no readable rules');
  stats.rules = rules.length;
  stats.convertible = rules.filter((r) => r.convertible).length;
  return { info, rules, stats };
}

/** ATT&CK techniques and tactics of a library rule (for chips and filters). */
export function sigmaAttack(rule: Pick<SigmaLibraryRule, 'tags'>): { techniques: string[]; tactics: string[] } {
  const report = analyzeAttackTags(rule.tags);
  const tactics = [...new Set([...report.tactics, ...report.explicitTactics])];
  return { techniques: report.techniques, tactics };
}
