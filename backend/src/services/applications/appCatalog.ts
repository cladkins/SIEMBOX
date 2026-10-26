/**
 * Application signatures from the catalog: applications/<id>.app.yaml in the
 * same GitHub repo and ref as the parser, detection and pack catalogs, read
 * with the same fetch machinery (one git-trees call, then raw.githubusercontent
 * for each file) and cached the same way (CACHE_TTL, concurrent callers share
 * one fetch).
 *
 *   SIEMBOX_CATALOG_APPLICATIONS_PATH  default "applications"
 * (repo/ref/token are shared with the parser catalog — see catalogService.)
 *
 * Fallbacks, so the inventory keeps working while the catalog is unreachable:
 *  - the catalog cannot be reached, a previous read worked     -> that last read (memory)
 *  - ... nothing read since the start, an earlier read stored   -> the stored set
 *    (application_signatures, written by the rollup after each catalog read)
 *  - the catalog has no applications/, or nothing at all       -> the bundled starter set
 * The result says which (`source`) and why (`error`), and the page shows it.
 *
 * Each signature is validated (appFormat.validateApplication, non-strict: an
 * unknown key from a newer catalog is a warning, not a missing application);
 * an invalid one is left out and listed in `invalid`. Signature regexes run
 * on attacker-controlled text (user agents), so before an index is built
 * every regex goes through the write-time safety gate (gateSignatureRegexes):
 * a refused one is left out of the index, the rest of its signature still
 * matches.
 */
import * as yaml from '../../utils/yaml';
import { logger } from '../../utils/logger';
import { CatalogSource, HttpGetter, httpsGet, listTreeFiles, fetchRawText, catalogRepoRef } from '../parser/catalogService';
import { APP_FILE_SUFFIX, collectAppRegexes, crossCheckApplications, validateApplication, type AppSignature } from './appFormat';
import { BUNDLED_APPLICATION_DOCS } from './bundledApplications';
import { assessRegexes, type RegexRef } from '../regex/regexSafety';

const CACHE_TTL = 5 * 60 * 1000;
export const MAX_APP_FILES = 2000;
export const MAX_APP_FILE_BYTES = 64 * 1024;

export function getApplicationSource(): CatalogSource {
  const { repo, ref } = catalogRepoRef();
  return {
    repo,
    ref,
    path: (process.env.SIEMBOX_CATALOG_APPLICATIONS_PATH || 'applications').replace(/^\/+|\/+$/g, ''),
  };
}

export type AppCatalogSource = 'catalog' | 'cache' | 'stored' | 'bundled';

export interface AppCatalog {
  source: AppCatalogSource;
  repo: string;
  ref: string;
  apps: AppSignature[];
  invalid: Array<{ path: string; errors: string[] }>;
  /** When the signatures in use were read from the catalog (null for bundled). */
  fetched_at: string | null;
  error: string | null;
}

/** Validate a list of signature documents (bundled or stored): the valid ones, and why the others are not. */
export function signaturesFrom(docs: unknown[], label: string): { apps: AppSignature[]; invalid: AppCatalog['invalid'] } {
  const apps: AppSignature[] = [];
  const invalid: AppCatalog['invalid'] = [];
  docs.forEach((doc, i) => {
    const v = validateApplication(doc, { strict: false });
    const id = (doc as { id?: unknown })?.id;
    if (!v.ok || !v.app) invalid.push({ path: `${label}[${typeof id === 'string' ? id : i}]`, errors: v.errors });
    else if (apps.some((a) => a.id === v.app!.id)) invalid.push({ path: `${label}[${v.app.id}]`, errors: ['duplicate id'] });
    else apps.push(v.app);
  });
  return { apps, invalid };
}

export function bundledSignatures(): AppSignature[] {
  return signaturesFrom(BUNDLED_APPLICATION_DOCS, 'bundled').apps;
}

/** The signature set stored by the last rollup that used a catalog read, or null. Injectable for tests. */
export type StoredLoader = () => Promise<{ docs: unknown[]; fetched_at: string | null } | null>;

let cache: { key: string; at: number; value: AppCatalog } | null = null;
let lastGood: { key: string; value: AppCatalog } | null = null;
let inflight: { key: string; promise: Promise<AppCatalog> } | null = null;

async function fallback(src: CatalogSource, why: string, key: string, loadStored?: StoredLoader): Promise<AppCatalog> {
  if (lastGood && lastGood.key === key) {
    return { ...lastGood.value, source: 'cache', error: `${why}; using the signatures read at ${lastGood.value.fetched_at}` };
  }
  if (loadStored) {
    try {
      const stored = await loadStored();
      if (stored && stored.docs.length > 0) {
        const { apps, invalid } = signaturesFrom(stored.docs, 'stored');
        if (apps.length > 0) {
          return {
            source: 'stored',
            repo: src.repo,
            ref: src.ref,
            apps,
            invalid,
            fetched_at: stored.fetched_at,
            error: `${why}; using the signatures stored from the catalog read at ${stored.fetched_at ?? 'an earlier run'}`,
          };
        }
      }
    } catch (error) {
      logger.warn('[Applications] stored signatures unavailable', { error: error instanceof Error ? error.message : String(error) });
    }
  }
  return { source: 'bundled', repo: src.repo, ref: src.ref, apps: bundledSignatures(), invalid: [], fetched_at: null, error: `${why}; using the starter set built into SIEMBox` };
}

async function load(src: CatalogSource, key: string, get: HttpGetter, loadStored?: StoredLoader): Promise<AppCatalog> {
  let value: AppCatalog;
  try {
    const paths = (await listTreeFiles(src, get, APP_FILE_SUFFIX)).sort();
    if (paths.length === 0) {
      value = await fallback(src, `the catalog has no ${src.path}/ yet`, key, undefined);
    } else {
      const apps: AppSignature[] = [];
      const invalid: AppCatalog['invalid'] = [];
      for (const filePath of paths.slice(0, MAX_APP_FILES)) {
        const fileId = filePath.split('/').pop()!.slice(0, -APP_FILE_SUFFIX.length);
        try {
          const text = await fetchRawText(src, filePath, get);
          if (text.length > MAX_APP_FILE_BYTES) throw new Error(`larger than ${MAX_APP_FILE_BYTES} bytes`);
          const v = validateApplication(yaml.load(text), { strict: false, expectId: fileId });
          if (!v.ok || !v.app) invalid.push({ path: filePath, errors: v.errors });
          else if (apps.some((a) => a.id === v.app!.id)) invalid.push({ path: filePath, errors: [`duplicate id "${v.app.id}"`] });
          else apps.push(v.app);
        } catch (error) {
          invalid.push({ path: filePath, errors: [`could not load: ${error instanceof Error ? error.message : String(error)}`] });
        }
      }
      if (paths.length > MAX_APP_FILES) invalid.push({ path: src.path, errors: [`more than ${MAX_APP_FILES} files; the rest were not read`] });
      // A value two signatures claim cannot say which application it is: both
      // keep their other matchers, the claim is reported (catalog CI refuses it).
      for (const p of crossCheckApplications(apps, { checkSupersedes: false })) invalid.push({ path: `${src.path}/${p.id}${APP_FILE_SUFFIX}`, errors: [p.error] });
      for (const i of invalid) logger.warn('[Applications] catalog signature problem', i);
      if (apps.length === 0) {
        value = { ...(await fallback(src, `none of the catalog's ${paths.length} signature file(s) is valid`, key, loadStored)), invalid };
      } else {
        value = {
          source: 'catalog',
          repo: src.repo,
          ref: src.ref,
          apps: apps.sort((a, b) => a.name.localeCompare(b.name)),
          invalid,
          fetched_at: new Date().toISOString(),
          error: invalid.length > 0 ? `${invalid.length} catalog signature problem(s); see the list` : null,
        };
        lastGood = { key, value };
      }
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.warn('[Applications] catalog signatures unavailable', { error: message });
    value = await fallback(src, `the catalog could not be reached (${message})`, key, loadStored);
  }
  cache = { key, at: Date.now(), value };
  return value;
}

/** The signatures in use (cached CACHE_TTL; `force` re-reads the catalog). `get` and `loadStored` are injectable for tests. */
export async function fetchAppCatalog(opts: { force?: boolean; get?: HttpGetter; loadStored?: StoredLoader } = {}): Promise<AppCatalog> {
  const src = getApplicationSource();
  const key = `${src.repo}@${src.ref}:${src.path}`;
  if (!opts.force && cache && cache.key === key && Date.now() - cache.at < CACHE_TTL) return cache.value;
  if (!inflight || inflight.key !== key) {
    const promise = load(src, key, opts.get ?? httpsGet, opts.loadStored).finally(() => {
      if (inflight?.promise === promise) inflight = null;
    });
    inflight = { key, promise };
  }
  return inflight.promise;
}

/** Test seam: forget the cache and the last good read. */
export function clearAppCatalogCache(): void {
  cache = null;
  lastGood = null;
  inflight = null;
}

export interface RegexGateResult {
  /** Regex sources left out of the index. */
  skip: Set<string>;
  refused: Array<{ appId: string; location: string; source: string; reason: string }>;
}

/**
 * Put every signature regex through the write-time safety gate (worker
 * thread, cached verdicts). Refused ones (proven vulnerable, or undecidable
 * and unbounded) are left out of the index. If the checker is saturated, all
 * regex matchers are left out of this run (nothing unchecked ever runs) and
 * the next run asks again. `assess` is injectable for tests.
 */
export async function gateSignatureRegexes(
  apps: AppSignature[],
  assess: (refs: RegexRef[]) => Promise<{ vulnerable: Array<{ location: string; source: string }>; undecided: Array<{ location: string; source: string }> }> = (refs) =>
    assessRegexes(refs, { priority: 'low' })
): Promise<RegexGateResult> {
  const refs: RegexRef[] = [];
  for (const a of apps) for (const r of collectAppRegexes(a)) refs.push({ ...r, location: `${a.id}:${r.location}` });
  const out: RegexGateResult = { skip: new Set(), refused: [] };
  if (refs.length === 0) return out;
  try {
    const report = await assess(refs);
    for (const f of [...report.vulnerable, ...report.undecided]) {
      const [appId, location] = f.location.split(':');
      out.skip.add(f.source);
      out.refused.push({ appId, location, source: f.source, reason: report.vulnerable.includes(f) ? 'ReDoS-vulnerable' : 'cannot be checked or bounded' });
    }
  } catch (error) {
    for (const r of refs) out.skip.add(r.source);
    out.refused.push({ appId: '*', location: '*', source: '*', reason: `the regex checker is unavailable (${error instanceof Error ? error.message : String(error)}); regex matchers are off for this run` });
  }
  return out;
}
