/**
 * Suggested scans from the catalog: scans/<id>.scan.yaml in the same GitHub
 * repo and ref as the parser, detection, pack and application catalogs, read
 * with the same fetch machinery (one git-trees call, then raw.githubusercontent
 * for each file) and cached the same way (CACHE_TTL, concurrent callers share
 * one fetch).
 *
 *   SIEMBOX_CATALOG_SCANS_PATH  default "scans"
 * (repo/ref/token are shared with the parser catalog — see catalogService.)
 *
 * Fallbacks, so the suggestions stay available while the catalog is unreachable:
 *  - the catalog cannot be reached, a previous read worked   -> that last read (memory)
 *  - nothing read since the start, or the catalog has no scans/ -> the bundled starter set
 * The result says which (`source`) and why (`error`), and the page shows it.
 *
 * Each suggestion is validated (scanFormat.validateSuggestion, non-strict: an
 * unknown key from a newer catalog is a warning, not a missing suggestion);
 * an invalid one is left out and listed in `invalid`.
 */
import * as yaml from '../../utils/yaml';
import { logger } from '../../utils/logger';
import { CatalogSource, HttpGetter, httpsGet, listTreeFiles, fetchRawText, catalogRepoRef } from '../parser/catalogService';
import { SCAN_FILE_SUFFIX, crossCheckSuggestions, validateSuggestion, type ScanSuggestion } from './scanFormat';
import { BUNDLED_SCAN_DOCS } from './bundledScans';

const CACHE_TTL = 5 * 60 * 1000;
export const MAX_SCAN_FILES = 500;
export const MAX_SCAN_FILE_BYTES = 32 * 1024;

export function getScanSource(): CatalogSource {
  const { repo, ref } = catalogRepoRef();
  return {
    repo,
    ref,
    path: (process.env.SIEMBOX_CATALOG_SCANS_PATH || 'scans').replace(/^\/+|\/+$/g, ''),
  };
}

export type ScanCatalogSource = 'catalog' | 'cache' | 'bundled';

export interface ScanCatalog {
  source: ScanCatalogSource;
  repo: string;
  ref: string;
  suggestions: ScanSuggestion[];
  invalid: Array<{ path: string; errors: string[] }>;
  /** When the suggestions in use were read from the catalog (null for bundled). */
  fetched_at: string | null;
  error: string | null;
}

/** Validate a list of suggestion documents: the valid ones, and why the others are not. */
export function suggestionsFrom(docs: unknown[], label: string): { suggestions: ScanSuggestion[]; invalid: ScanCatalog['invalid'] } {
  const suggestions: ScanSuggestion[] = [];
  const invalid: ScanCatalog['invalid'] = [];
  docs.forEach((doc, i) => {
    const v = validateSuggestion(doc, { strict: false });
    const id = (doc as { id?: unknown })?.id;
    if (!v.ok || !v.suggestion) invalid.push({ path: `${label}[${typeof id === 'string' ? id : i}]`, errors: v.errors });
    else if (suggestions.some((s) => s.id === v.suggestion!.id)) invalid.push({ path: `${label}[${v.suggestion.id}]`, errors: ['duplicate id'] });
    else suggestions.push(v.suggestion);
  });
  return { suggestions, invalid };
}

export function bundledSuggestions(): ScanSuggestion[] {
  return suggestionsFrom(BUNDLED_SCAN_DOCS, 'bundled').suggestions;
}

let cache: { key: string; at: number; value: ScanCatalog } | null = null;
let lastGood: { key: string; value: ScanCatalog } | null = null;
let inflight: { key: string; promise: Promise<ScanCatalog> } | null = null;

function sorted(list: ScanSuggestion[]): ScanSuggestion[] {
  const order = ['asset', 'vulnerability', 'container', 'log_discovery', 'endpoint_policy'];
  return [...list].sort((a, b) => order.indexOf(a.kind) - order.indexOf(b.kind) || a.name.localeCompare(b.name));
}

function fallback(src: CatalogSource, why: string, key: string): ScanCatalog {
  if (lastGood && lastGood.key === key) {
    return { ...lastGood.value, source: 'cache', error: `${why}; using the suggestions read at ${lastGood.value.fetched_at}` };
  }
  return {
    source: 'bundled',
    repo: src.repo,
    ref: src.ref,
    suggestions: sorted(bundledSuggestions()),
    invalid: [],
    fetched_at: null,
    error: `${why}; using the starter set built into SIEMBox`,
  };
}

async function load(src: CatalogSource, key: string, get: HttpGetter): Promise<ScanCatalog> {
  let value: ScanCatalog;
  try {
    const paths = (await listTreeFiles(src, get, SCAN_FILE_SUFFIX)).sort();
    if (paths.length === 0) {
      value = fallback(src, `the catalog has no ${src.path}/ yet`, key);
    } else {
      const suggestions: ScanSuggestion[] = [];
      const invalid: ScanCatalog['invalid'] = [];
      for (const filePath of paths.slice(0, MAX_SCAN_FILES)) {
        const fileId = filePath.split('/').pop()!.slice(0, -SCAN_FILE_SUFFIX.length);
        try {
          const text = await fetchRawText(src, filePath, get);
          if (text.length > MAX_SCAN_FILE_BYTES) throw new Error(`larger than ${MAX_SCAN_FILE_BYTES} bytes`);
          const v = validateSuggestion(yaml.load(text), { strict: false, expectId: fileId });
          if (!v.ok || !v.suggestion) invalid.push({ path: filePath, errors: v.errors });
          else if (suggestions.some((s) => s.id === v.suggestion!.id)) invalid.push({ path: filePath, errors: [`duplicate id "${v.suggestion.id}"`] });
          else suggestions.push(v.suggestion);
        } catch (error) {
          invalid.push({ path: filePath, errors: [`could not load: ${error instanceof Error ? error.message : String(error)}`] });
        }
      }
      if (paths.length > MAX_SCAN_FILES) invalid.push({ path: src.path, errors: [`more than ${MAX_SCAN_FILES} files; the rest were not read`] });
      for (const p of crossCheckSuggestions(suggestions)) invalid.push({ path: `${src.path}/${p.id}${SCAN_FILE_SUFFIX}`, errors: [p.error] });
      for (const i of invalid) logger.warn('[Scan suggestions] catalog suggestion problem', i);
      if (suggestions.length === 0) {
        value = { ...fallback(src, `none of the catalog's ${paths.length} suggestion file(s) is valid`, key), invalid };
      } else {
        value = {
          source: 'catalog',
          repo: src.repo,
          ref: src.ref,
          suggestions: sorted(suggestions),
          invalid,
          fetched_at: new Date().toISOString(),
          error: invalid.length > 0 ? `${invalid.length} catalog suggestion problem(s); see the list` : null,
        };
        lastGood = { key, value };
      }
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.warn('[Scan suggestions] catalog suggestions unavailable', { error: message });
    value = fallback(src, `the catalog could not be reached (${message})`, key);
  }
  cache = { key, at: Date.now(), value };
  return value;
}

/** The suggestions in use (cached CACHE_TTL; `force` re-reads the catalog). `get` is injectable for tests. */
export async function fetchScanCatalog(opts: { force?: boolean; get?: HttpGetter } = {}): Promise<ScanCatalog> {
  const src = getScanSource();
  const key = `${src.repo}@${src.ref}:${src.path}`;
  if (!opts.force && cache && cache.key === key && Date.now() - cache.at < CACHE_TTL) return cache.value;
  if (!inflight || inflight.key !== key) {
    const promise = load(src, key, opts.get ?? httpsGet).finally(() => {
      if (inflight?.promise === promise) inflight = null;
    });
    inflight = { key, promise };
  }
  return inflight.promise;
}

/** Test seam: forget the cache and the last good read. */
export function clearScanCatalogCache(): void {
  cache = null;
  lastGood = null;
  inflight = null;
}
