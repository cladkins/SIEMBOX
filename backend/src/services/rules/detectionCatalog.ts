/**
 * Detection catalog (hub) — browse and install detection rules from the same
 * GitHub repo as the parser catalog (detections/ alongside parsers/). Reuses the
 * shared GitHub fetch machinery from the parser catalogService and the strict
 * rule validator, so a rule that passes CI installs and evaluates identically.
 *
 *   SIEMBOX_CATALOG_DETECTIONS_PATH  default "detections"
 * (repo/ref/token are shared with the parser catalog — see catalogService.)
 */
import * as yaml from 'js-yaml';
import { logger } from '../../utils/logger';
import { validateRule } from './rulePortable';
import {
  CatalogSource,
  HttpGetter,
  httpsGet,
  listTreeFiles,
  fetchRawText,
  catalogRepoRef,
  stableStringify,
} from '../parser/catalogService';

export function getDetectionSource(): CatalogSource {
  const { repo, ref } = catalogRepoRef();
  return {
    repo,
    ref,
    path: (process.env.SIEMBOX_CATALOG_DETECTIONS_PATH || 'detections').replace(/^\/+|\/+$/g, ''),
  };
}

export interface DetectionEntry {
  name: string;
  description?: string;
  severity?: string;
  tags: string[];
  path: string;
  valid: boolean;
  errors: string[];
  warnings: string[];
  /** stable content signature (severity+tags+description+conditions+aggregation+alert). */
  signature: string;
}

/**
 * Stable signature of a rule's meaningful content. Accepts either a parsed YAML
 * rule (conditions/aggregation/alert at top level) or a DB row (in rule_logic).
 * Excludes `enabled` (operator-controlled) so a toggle isn't seen as an update.
 */
export function ruleSignature(r: any): string {
  const rl = r?.rule_logic || {};
  return stableStringify({
    severity: r?.severity ?? null,
    description: r?.description ?? null,
    tags: (Array.isArray(r?.tags) ? r.tags.slice().sort() : []),
    conditions: r?.conditions ?? rl.conditions ?? null,
    aggregation: r?.aggregation ?? rl.aggregation ?? null,
    alert: r?.alert ?? rl.alert ?? null,
  });
}

interface DetCacheShape {
  source: string;
  at: number;
  rules: Map<string, { rule_yaml: string; parsed: any }>;
  entries: DetectionEntry[];
}
let cache: DetCacheShape | null = null;
const CACHE_TTL = 5 * 60 * 1000;

/** Fetch + validate the detection catalog (cached). `get` is injectable for tests. */
export async function fetchDetectionCatalog(
  force = false,
  get: HttpGetter = httpsGet
): Promise<{ source: CatalogSource; entries: DetectionEntry[] }> {
  const src = getDetectionSource();
  const key = `${src.repo}@${src.ref}:${src.path}`;
  if (!force && cache && cache.source === key && Date.now() - cache.at < CACHE_TTL) {
    return { source: src, entries: cache.entries };
  }

  const paths = await listTreeFiles(src, get, '.yaml');
  const rules = new Map<string, { rule_yaml: string; parsed: any }>();
  const entries: DetectionEntry[] = [];

  for (const filePath of paths) {
    const fallbackName = filePath.split('/').pop()!.replace(/\.ya?ml$/, '');
    try {
      const text = await fetchRawText(src, filePath, get);
      const parsed = yaml.load(text) as any;
      const v = validateRule(parsed, { strict: true });
      const name = (parsed && parsed.name) || fallbackName;
      if (parsed && parsed.name) rules.set(parsed.name, { rule_yaml: text, parsed });
      entries.push({
        name,
        description: parsed?.description,
        severity: parsed?.severity,
        tags: Array.isArray(parsed?.tags) ? parsed.tags : [],
        path: filePath,
        valid: v.ok,
        errors: v.errors,
        warnings: v.warnings,
        signature: v.ok ? ruleSignature(parsed) : '',
      });
    } catch (error) {
      logger.warn('Detection catalog: failed to load rule file', {
        filePath,
        error: error instanceof Error ? error.message : String(error),
      });
      entries.push({
        name: fallbackName,
        tags: [],
        path: filePath,
        valid: false,
        errors: [`Could not load: ${error instanceof Error ? error.message : String(error)}`],
        warnings: [],
        signature: '',
      });
    }
  }

  entries.sort((a, b) => a.name.localeCompare(b.name));
  cache = { source: key, at: Date.now(), rules, entries };
  return { source: src, entries };
}

/** Get one catalog rule (its raw YAML + parsed form) by name. */
export async function getCatalogDetection(
  name: string
): Promise<{ rule_yaml: string; parsed: any } | null> {
  if (!cache || Date.now() - cache.at >= CACHE_TTL || !cache.rules.has(name)) {
    await fetchDetectionCatalog(true);
  }
  return cache?.rules.get(name) || null;
}

export function clearDetectionCache(): void {
  cache = null;
}
