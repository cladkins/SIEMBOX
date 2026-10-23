/**
 * SigmaHQ library: the DB cache (migration 046), refresh, compatibility and
 * the provenance the Detection Rules list shows.
 *
 *   SIGMAHQ_RELEASE_ASSET  which release asset (default sigma_core+.zip; see
 *                          SIGMAHQ_ASSETS in sigmaLibrary.ts)
 *   SIGMAHQ_AUTO_REFRESH   "false" turns the daily refresh off (air-gapped
 *                          installs; Refresh on the page still works)
 *
 * The parsed library is kept in memory after the first read (a few MB) and
 * dropped when a refresh stores a new one. Compatibility depends on live logs,
 * so it is cached for COMPAT_TTL_MS only.
 */
import crypto from 'crypto';
import { getClient, query } from '../../config/database';
import { logger } from '../../utils/logger';
import { recentParserSamples } from '../rules/ruleSamples';
import { sigmaMatchesBounded } from '../regex/boundedRegex';
import {
  DEFAULT_SIGMAHQ_ASSET,
  SIGMAHQ_ASSETS,
  buildSigmaLibrary,
  sigmaRuleUrl,
  type SigmaBuildStats,
  type SigmaLibraryRule,
} from './sigmaLibrary';
import { fetchSigmaRelease, type SigmaFetcher } from './sigmaFetch';
import { planSigmaCompat, type CompatResult } from './sigmaCompat';

/** Bump when the conversion of a release would come out differently (rebuilds the cache). */
export const SIGMA_BUILDER_VERSION = 1;
const COMPAT_TTL_MS = 5 * 60 * 1000;

export interface SigmaLibraryState {
  release_tag: string | null;
  asset: string | null;
  release_date: string | null;
  commit_hash: string | null;
  archive_bytes: number | null;
  rule_count: number;
  convertible_count: number;
  builder_version: number | null;
  fetched_at: string | null;
  last_attempt_at: string | null;
  last_error: string | null;
  last_error_at: string | null;
}

export function sigmaAsset(): string {
  const wanted = (process.env.SIGMAHQ_RELEASE_ASSET || '').trim();
  return (SIGMAHQ_ASSETS as readonly string[]).includes(wanted) ? wanted : DEFAULT_SIGMAHQ_ASSET;
}

export function sigmaAutoRefresh(): boolean {
  return !['false', '0', 'off', 'no'].includes(String(process.env.SIGMAHQ_AUTO_REFRESH ?? '').trim().toLowerCase());
}

const EMPTY_STATE: SigmaLibraryState = {
  release_tag: null,
  asset: null,
  release_date: null,
  commit_hash: null,
  archive_bytes: null,
  rule_count: 0,
  convertible_count: 0,
  builder_version: null,
  fetched_at: null,
  last_attempt_at: null,
  last_error: null,
  last_error_at: null,
};

export async function getSigmaState(): Promise<SigmaLibraryState> {
  const r = await query('SELECT * FROM sigma_library_state WHERE id = 1');
  const row = r.rows[0];
  if (!row) return { ...EMPTY_STATE };
  const iso = (v: unknown) => (v instanceof Date ? v.toISOString() : (v as string | null) ?? null);
  return {
    release_tag: row.release_tag,
    asset: row.asset,
    release_date: row.release_date,
    commit_hash: row.commit_hash,
    archive_bytes: row.archive_bytes,
    rule_count: row.rule_count ?? 0,
    convertible_count: row.convertible_count ?? 0,
    builder_version: row.builder_version,
    fetched_at: iso(row.fetched_at),
    last_attempt_at: iso(row.last_attempt_at),
    last_error: row.last_error,
    last_error_at: iso(row.last_error_at),
  };
}

// ---------------------------------------------------------------------------
// The library in memory.
// ---------------------------------------------------------------------------

interface LoadedLibrary {
  /** Changes with every stored refresh (compatibility cache key). */
  version: string;
  /** The cached release (null before the first refresh). */
  tag: string | null;
  rules: SigmaLibraryRule[];
  byId: Map<string, SigmaLibraryRule>;
}

let loaded: LoadedLibrary | null = null;
let loading: Promise<LoadedLibrary> | null = null;

function rowToRule(row: any): SigmaLibraryRule {
  return {
    sigma_id: row.sigma_id,
    path: row.path,
    title: row.title,
    description: row.description,
    level: row.level,
    status: row.status,
    product: row.product,
    category: row.category,
    service: row.service,
    tags: row.tags ?? [],
    author: row.author,
    rule_date: row.rule_date,
    modified: row.modified,
    refs: row.refs ?? [],
    content_hash: row.content_hash,
    convertible: row.convertible,
    errors: row.errors ?? [],
    warnings: row.warnings ?? [],
    parts: row.parts ?? [],
    fields: row.fields ?? [],
  };
}

/** The cached library (empty before the first refresh). */
export async function loadSigmaLibrary(): Promise<LoadedLibrary> {
  if (loaded) return loaded;
  loading ??= (async () => {
    try {
      const state = await getSigmaState();
      const r = await query('SELECT * FROM sigma_library_rules ORDER BY title ASC');
      const rules = r.rows.map(rowToRule);
      loaded = {
        version: `${state.release_tag ?? ''}@${state.fetched_at ?? ''}`,
        tag: state.release_tag,
        rules,
        byId: new Map(rules.map((x) => [x.sigma_id, x])),
      };
      return loaded;
    } finally {
      loading = null;
    }
  })();
  return loading;
}

/** Test seam and refresh hook: forget the in-memory library and compatibility. */
export function clearSigmaMemory(): void {
  loaded = null;
  compat = null;
}

// ---------------------------------------------------------------------------
// Refresh.
// ---------------------------------------------------------------------------

export interface SigmaRefreshResult {
  status: 'updated' | 'unchanged';
  release_tag: string;
  stats?: SigmaBuildStats;
}

let refreshing: Promise<SigmaRefreshResult> | null = null;

async function storeLibrary(
  info: { tag: string; asset: string; release_date: string | null; commit_hash: string | null },
  rules: SigmaLibraryRule[],
  archive: Buffer
): Promise<void> {
  const client = await getClient();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM sigma_library_rules');
    for (let i = 0; i < rules.length; i += 250) {
      const chunk = rules.slice(i, i + 250).map((r) => ({ ...r, release_tag: info.tag }));
      await client.query(
        `INSERT INTO sigma_library_rules (sigma_id, release_tag, path, title, description, level, status, product, category,
            service, tags, author, rule_date, modified, refs, content_hash, convertible, errors, warnings, parts, fields)
         SELECT sigma_id, release_tag, path, title, description, level, status, product, category,
            service, tags, author, rule_date, modified, refs, content_hash, convertible, errors, warnings, parts, fields
           FROM jsonb_to_recordset($1::jsonb) AS x(sigma_id TEXT, release_tag TEXT, path TEXT, title TEXT, description TEXT,
            level TEXT, status TEXT, product TEXT, category TEXT, service TEXT, tags TEXT[], author TEXT, rule_date TEXT,
            modified TEXT, refs TEXT[], content_hash TEXT, convertible BOOLEAN, errors JSONB, warnings JSONB, parts JSONB,
            fields TEXT[])`,
        [JSON.stringify(chunk)]
      );
    }
    await client.query(
      `INSERT INTO sigma_library_state (id, release_tag, asset, release_date, commit_hash, archive_bytes, archive_sha256,
          rule_count, convertible_count, builder_version, fetched_at, last_attempt_at, last_error, last_error_at)
       VALUES (1, $1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW(), NULL, NULL)
       ON CONFLICT (id) DO UPDATE SET release_tag = EXCLUDED.release_tag, asset = EXCLUDED.asset,
          release_date = EXCLUDED.release_date, commit_hash = EXCLUDED.commit_hash,
          archive_bytes = EXCLUDED.archive_bytes, archive_sha256 = EXCLUDED.archive_sha256,
          rule_count = EXCLUDED.rule_count, convertible_count = EXCLUDED.convertible_count,
          builder_version = EXCLUDED.builder_version, fetched_at = NOW(), last_attempt_at = NOW(),
          last_error = NULL, last_error_at = NULL`,
      [
        info.tag,
        info.asset,
        info.release_date,
        info.commit_hash,
        archive.length,
        crypto.createHash('sha256').update(archive).digest('hex'),
        rules.length,
        rules.filter((r) => r.convertible).length,
        SIGMA_BUILDER_VERSION,
      ]
    );
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

async function recordAttempt(error: string | null): Promise<void> {
  await query(
    `INSERT INTO sigma_library_state (id, last_attempt_at, last_error, last_error_at)
     VALUES (1, NOW(), $1, CASE WHEN $1::text IS NULL THEN NULL ELSE NOW() END)
     ON CONFLICT (id) DO UPDATE SET last_attempt_at = NOW(),
        last_error = EXCLUDED.last_error,
        last_error_at = CASE WHEN EXCLUDED.last_error IS NULL THEN sigma_library_state.last_error_at ELSE NOW() END`,
    [error ? error.slice(0, 500) : null]
  );
}

/**
 * Fetch the latest release and store it, unless the cache already holds that
 * release (built by this converter version) and `force` is off. A failure is
 * recorded in sigma_library_state and re-thrown; the previous cache stays.
 * Concurrent calls share one refresh.
 */
export function refreshSigmaLibrary(opts: { force?: boolean; fetcher?: SigmaFetcher } = {}): Promise<SigmaRefreshResult> {
  refreshing ??= (async () => {
    try {
      const state = await getSigmaState();
      const asset = sigmaAsset();
      const current =
        !opts.force && state.asset === asset && state.builder_version === SIGMA_BUILDER_VERSION && state.rule_count > 0
          ? state.release_tag
          : null;
      const { tag, archive } = await fetchSigmaRelease(asset, { currentTag: current, fetcher: opts.fetcher });
      if (!archive) {
        await recordAttempt(null);
        return { status: 'unchanged' as const, release_tag: tag };
      }
      const built = buildSigmaLibrary(archive, { tag, asset });
      await storeLibrary(built.info, built.rules, archive);
      clearSigmaMemory();
      logger.info(
        `[sigma] SigmaHQ ${tag} (${asset}): ${built.stats.rules} rules, ${built.stats.convertible} convertible`
      );
      return { status: 'updated' as const, release_tag: tag, stats: built.stats };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      await recordAttempt(message).catch(() => undefined);
      throw error;
    } finally {
      refreshing = null;
    }
  })();
  return refreshing;
}

// ---------------------------------------------------------------------------
// Compatibility with this install's logs.
// ---------------------------------------------------------------------------

export interface SigmaCompatibility {
  computed_at: string;
  sampled_parsers: number;
  /** The dry run's match counts are missing (the regex pool was busy or out of time). */
  dry_run_error?: string;
  results: Map<string, CompatResult>;
}

let compat: { version: string; at: number; value: SigmaCompatibility } | null = null;
let compatInflight: Promise<SigmaCompatibility> | null = null;

/** Compatibility of every convertible rule (cached COMPAT_TTL_MS; `refresh` recomputes). */
export async function sigmaCompatibility(opts: { refresh?: boolean } = {}): Promise<SigmaCompatibility> {
  const lib = await loadSigmaLibrary();
  if (!opts.refresh && compat && compat.version === lib.version && Date.now() - compat.at < COMPAT_TTL_MS) {
    return compat.value;
  }
  compatInflight ??= (async () => {
    try {
      const samples = await recentParserSamples({ windowHours: 24, perPartition: 10, byEventType: true, scanLimit: 20_000, maxSamples: 1500 });
      const sources = [...samples.values()].map((s) => ({ parser_name: s.parser_name, samples: s.samples }));
      const candidates = lib.rules
        .filter((r) => r.convertible)
        .map((r) => ({ sigma_id: r.sigma_id, product: r.product, category: r.category, service: r.service, parts: r.parts }));
      const plan = planSigmaCompat(candidates, sources);
      const value: SigmaCompatibility = {
        computed_at: new Date().toISOString(),
        sampled_parsers: plan.sources.length,
        results: plan.results,
      };
      if (plan.pairs.length > 0) {
        try {
          const counts = await sigmaMatchesBounded(plan.sources, plan.pairs);
          for (const [id, perParser] of Object.entries(counts)) {
            const res = plan.results.get(id);
            if (!res) continue;
            for (const p of res.parsers) p.matched = perParser[p.parser_name] ?? 0;
          }
        } catch (error) {
          value.dry_run_error = error instanceof Error ? error.message : String(error);
        }
      }
      compat = { version: lib.version, at: Date.now(), value };
      return value;
    } finally {
      compatInflight = null;
    }
  })();
  return compatInflight;
}

// ---------------------------------------------------------------------------
// Provenance on installed rules.
// ---------------------------------------------------------------------------

export interface SigmaRuleProvenance {
  sigma_id: string;
  release: string | null;
  part: number | null;
  /** The upstream rule file, at the release it was installed from (DRL attribution). */
  url: string | null;
  title: string | null;
  author: string | null;
  /** The cached release has a different version of this rule. */
  update_available: boolean;
  /** The cached release no longer has the rule (SigmaHQ deprecates by moving rules out of the release sets). */
  deprecated: boolean;
}

/** Per-rule provenance for detection_rules rows added from the library (keyed by row id). */
export async function sigmaProvenance(
  rows: Array<{ id: number; sigma_id?: string | null; sigma_release?: string | null; sigma_hash?: string | null; sigma_part?: number | null }>
): Promise<Map<number, SigmaRuleProvenance>> {
  const out = new Map<number, SigmaRuleProvenance>();
  if (!rows.some((r) => r.sigma_id)) return out;
  let lib: LoadedLibrary;
  try {
    lib = await loadSigmaLibrary();
  } catch {
    return out;
  }
  const hasCache = lib.rules.length > 0;
  for (const r of rows) {
    if (!r.sigma_id) continue;
    const entry = lib.byId.get(r.sigma_id);
    const release = r.sigma_release ?? null;
    out.set(r.id, {
      sigma_id: r.sigma_id,
      release,
      part: r.sigma_part ?? null,
      url: entry ? sigmaRuleUrl(release ?? lib.tag ?? 'master', entry.path) : null,
      title: entry?.title ?? null,
      author: entry?.author ?? null,
      update_available: !!entry && entry.convertible && entry.content_hash !== r.sigma_hash,
      deprecated: hasCache && (!entry || entry.status === 'deprecated'),
    });
  }
  return out;
}
