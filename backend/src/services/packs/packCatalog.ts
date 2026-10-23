/**
 * Content Packs from the catalog: packs/<id>.pack.yaml in the same GitHub repo
 * and ref as the parser and detection catalogs, read with the same fetch
 * machinery (one git-trees call, then raw.githubusercontent for each file) and
 * cached the same way (CACHE_TTL, concurrent callers share one fetch).
 *
 *   SIEMBOX_CATALOG_PACKS_PATH  default "packs"
 * (repo/ref/token are shared with the parser catalog — see catalogService.)
 *
 * Fallbacks, so nothing regresses before the catalog carries packs:
 *  - the catalog has no packs/ (an older catalog)      -> the bundled packs
 *  - the catalog cannot be reached, a previous read worked -> that last read
 *  - the catalog cannot be reached, nothing cached yet -> the bundled packs
 * The result says which (`source`) and why (`error`), and the page shows it.
 *
 * Each pack is validated (packFormat.validatePack, non-strict: an unknown key
 * from a newer catalog is a warning, not a hidden pack); an invalid one is
 * left out and listed in `invalid`.
 */
import * as yaml from '../../utils/yaml';
import { logger } from '../../utils/logger';
import {
  CatalogSource,
  HttpGetter,
  httpsGet,
  listTreeFiles,
  fetchRawText,
  catalogRepoRef,
} from '../parser/catalogService';
import { PACK_FILE_SUFFIX, validatePack, type ContentPack } from './packFormat';
import { CONTENT_PACKS } from './contentPacks';

const CACHE_TTL = 5 * 60 * 1000;
/** Caps on what one catalog read takes in. */
export const MAX_PACK_FILES = 200;
export const MAX_PACK_FILE_BYTES = 256 * 1024;

export function getPackSource(): CatalogSource {
  const { repo, ref } = catalogRepoRef();
  return {
    repo,
    ref,
    path: (process.env.SIEMBOX_CATALOG_PACKS_PATH || 'packs').replace(/^\/+|\/+$/g, ''),
  };
}

export interface PackCatalog {
  /** catalog: read now; cache: the last good read (the catalog is unreachable); bundled: the built-in fallback. */
  source: 'catalog' | 'cache' | 'bundled';
  repo: string;
  ref: string;
  packs: ContentPack[];
  /** Pack files the catalog has that failed validation (left out). */
  invalid: Array<{ path: string; errors: string[] }>;
  /** When the packs in use were read from the catalog (null for bundled). */
  fetched_at: string | null;
  /** Why the catalog's packs are not (all) in use, if they are not. */
  error: string | null;
}

let cache: { key: string; at: number; value: PackCatalog } | null = null;
/** The last read that came from the catalog, kept for when it becomes unreachable. */
let lastGood: { key: string; value: PackCatalog } | null = null;
let inflight: { key: string; promise: Promise<PackCatalog> } | null = null;

function bundled(src: CatalogSource, error: string): PackCatalog {
  return { source: 'bundled', repo: src.repo, ref: src.ref, packs: CONTENT_PACKS, invalid: [], fetched_at: null, error };
}

async function loadPackCatalog(src: CatalogSource, key: string, get: HttpGetter): Promise<PackCatalog> {
  let value: PackCatalog;
  try {
    const paths = (await listTreeFiles(src, get, PACK_FILE_SUFFIX)).sort();
    if (paths.length === 0) {
      value = bundled(src, `the catalog has no ${src.path}/ yet; using the packs built into SIEMBox`);
    } else {
      const packs: ContentPack[] = [];
      const invalid: PackCatalog['invalid'] = [];
      for (const filePath of paths.slice(0, MAX_PACK_FILES)) {
        const fileId = filePath.split('/').pop()!.slice(0, -PACK_FILE_SUFFIX.length);
        try {
          const text = await fetchRawText(src, filePath, get);
          if (text.length > MAX_PACK_FILE_BYTES) throw new Error(`larger than ${MAX_PACK_FILE_BYTES} bytes`);
          const v = validatePack(yaml.load(text), { strict: false, expectId: fileId });
          if (!v.ok || !v.pack) invalid.push({ path: filePath, errors: v.errors });
          else if (packs.some((p) => p.id === v.pack!.id)) invalid.push({ path: filePath, errors: [`duplicate pack id "${v.pack.id}"`] });
          else packs.push(v.pack);
        } catch (error) {
          invalid.push({ path: filePath, errors: [`could not load: ${error instanceof Error ? error.message : String(error)}`] });
        }
      }
      if (paths.length > MAX_PACK_FILES) {
        invalid.push({ path: src.path, errors: [`more than ${MAX_PACK_FILES} pack files; the rest were not read`] });
      }
      for (const i of invalid) logger.warn('[Packs] catalog pack left out', i);
      if (packs.length === 0) {
        const why = `none of the catalog's ${paths.length} pack file(s) is valid`;
        value =
          lastGood && lastGood.key === key
            ? { ...lastGood.value, source: 'cache', invalid, error: `${why}; showing the packs read at ${lastGood.value.fetched_at}` }
            : { ...bundled(src, `${why}; using the packs built into SIEMBox`), invalid };
        cache = { key, at: Date.now(), value };
        return value;
      }
      value = {
        source: 'catalog',
        repo: src.repo,
        ref: src.ref,
        packs: packs.sort((a, b) => a.name.localeCompare(b.name)),
        invalid,
        fetched_at: new Date().toISOString(),
        error: invalid.length > 0 ? `${invalid.length} catalog pack file(s) failed validation and are left out` : null,
      };
      lastGood = { key, value };
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.warn('[Packs] catalog packs unavailable', { error: message });
    value =
      lastGood && lastGood.key === key
        ? { ...lastGood.value, source: 'cache', error: `the catalog could not be reached (${message}); showing the packs read at ${lastGood.value.fetched_at}` }
        : bundled(src, `the catalog could not be reached (${message}); using the packs built into SIEMBox`);
  }
  cache = { key, at: Date.now(), value };
  return value;
}

/** The packs in use (cached CACHE_TTL; `force` re-reads the catalog). `get` is injectable for tests. */
export async function fetchPackCatalog(force = false, get: HttpGetter = httpsGet): Promise<PackCatalog> {
  const src = getPackSource();
  const key = `${src.repo}@${src.ref}:${src.path}`;
  if (!force && cache && cache.key === key && Date.now() - cache.at < CACHE_TTL) return cache.value;
  if (!inflight || inflight.key !== key) {
    const promise = loadPackCatalog(src, key, get).finally(() => {
      if (inflight?.promise === promise) inflight = null;
    });
    inflight = { key, promise };
  }
  return inflight.promise;
}

/** Test seam: forget the cache and the last good read. */
export function clearPackCache(): void {
  cache = null;
  lastGood = null;
  inflight = null;
}
