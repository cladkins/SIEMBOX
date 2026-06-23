/**
 * Parser catalog (hub) — browse and install portable parsers from a GitHub repo,
 * in-app. Mirrors the Nuclei template fetch pattern (templateService) but for the
 * small JSON parser files: list the repo tree once via the GitHub API, then pull
 * each *.parser.json from raw.githubusercontent (not API-rate-limited), and reuse
 * the SAME validator + self-test runner the import endpoint and CI use.
 *
 * Source is configurable so the catalog can move without a code change:
 *   PARSER_CATALOG_REPO   default "cladkins/siembox-parsers" (the standalone catalog)
 *   PARSER_CATALOG_REF    default "main"
 *   PARSER_CATALOG_PATH   default "parsers"
 *   PARSER_CATALOG_TOKEN / GITHUB_TOKEN  optional, raises GitHub API rate limit
 */
import * as https from 'https';
import { logger } from '../../utils/logger';
import {
  validatePortableParser,
  runSelfTests,
  PortableParser,
  ValidationResult,
  SelfTestResult,
} from './parserPortable';

export interface CatalogSource {
  repo: string;
  ref: string;
  path: string;
}

export interface CatalogEntry {
  name: string;
  description?: string;
  parser_type?: string;
  priority?: number;
  tags: string[];
  log_source?: string;
  author?: string;
  references: string[];
  path: string;
  valid: boolean;
  errors: string[];
  warnings: string[];
  self_test: { ok: boolean; passed: number; total: number } | null;
  /** content signature (parser_type+pattern+field_mappings+derivations+event_type). */
  signature: string;
}

export function getCatalogSource(): CatalogSource {
  return {
    repo: process.env.PARSER_CATALOG_REPO || 'cladkins/siembox-parsers',
    ref: process.env.PARSER_CATALOG_REF || 'main',
    path: (process.env.PARSER_CATALOG_PATH || 'parsers').replace(/^\/+|\/+$/g, ''),
  };
}

/** Deterministic JSON: object keys sorted recursively, array order preserved. */
function stableStringify(v: any): string {
  if (Array.isArray(v)) return '[' + v.map(stableStringify).join(',') + ']';
  if (v && typeof v === 'object') {
    return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + stableStringify(v[k])).join(',') + '}';
  }
  return JSON.stringify(v ?? null);
}

/**
 * Stable signature of the meaningful parser fields, to detect installed/updatable.
 * Order-independent (Postgres jsonb does not preserve object key order, so a naive
 * JSON.stringify would flag a freshly-installed parser as "update available").
 * Deliberately excludes priority/enabled/description/test_samples — those are
 * operator-tunable and should not count as a content change.
 */
export function parserSignature(p: {
  parser_type?: string;
  pattern?: string;
  field_mappings?: Record<string, string>;
  derivations?: any[] | null;
  event_type?: string | null;
}): string {
  return stableStringify({
    parser_type: p.parser_type ?? null,
    pattern: p.pattern ?? null,
    field_mappings: p.field_mappings ?? {},
    derivations: p.derivations ?? null,
    event_type: p.event_type ?? null,
  });
}

/** HTTP getter seam — defaults to real https, overridable in tests. */
export type HttpGetter = (url: string, headers?: Record<string, string>) => Promise<{ status: number; body: string }>;

function httpsGet(url: string, headers: Record<string, string> = {}): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const make = (target: string, redirects = 0) => {
      if (redirects > 5) return reject(new Error('Too many redirects'));
      const req = https.get(target, { headers: { 'User-Agent': 'SIEMBox', ...headers } }, (res) => {
        const status = res.statusCode || 0;
        if ((status === 301 || status === 302 || status === 307 || status === 308) && res.headers.location) {
          res.resume();
          return make(res.headers.location, redirects + 1);
        }
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (c) => (body += c));
        res.on('end', () => resolve({ status, body }));
      });
      req.on('error', reject);
      req.setTimeout(20000, () => req.destroy(new Error('Catalog request timed out')));
    };
    make(url);
  });
}

function apiHeaders(): Record<string, string> {
  const token = process.env.PARSER_CATALOG_TOKEN || process.env.GITHUB_TOKEN;
  const h: Record<string, string> = { Accept: 'application/vnd.github+json' };
  if (token) h.Authorization = `Bearer ${token}`;
  return h;
}

/** List catalog file paths in the source repo via the git-trees API (one request). */
async function listParserPaths(src: CatalogSource, get: HttpGetter): Promise<string[]> {
  const url = `https://api.github.com/repos/${src.repo}/git/trees/${encodeURIComponent(src.ref)}?recursive=1`;
  const { status, body } = await get(url, apiHeaders());
  if (status !== 200) {
    throw new Error(`GitHub tree request failed (${status})${status === 403 ? ' — rate limited; set GITHUB_TOKEN' : ''}`);
  }
  const json = JSON.parse(body);
  const tree: Array<{ path: string; type: string }> = Array.isArray(json.tree) ? json.tree : [];
  const prefix = src.path + '/';
  return tree
    .filter((e) => e.type === 'blob' && e.path.startsWith(prefix) && e.path.endsWith('.parser.json'))
    .map((e) => e.path);
}

async function fetchRawParser(src: CatalogSource, filePath: string, get: HttpGetter): Promise<PortableParser> {
  const url = `https://raw.githubusercontent.com/${src.repo}/${encodeURIComponent(src.ref)}/${filePath
    .split('/')
    .map(encodeURIComponent)
    .join('/')}`;
  const { status, body } = await get(url);
  if (status !== 200) throw new Error(`Failed to fetch ${filePath} (${status})`);
  return JSON.parse(body) as PortableParser;
}

interface CacheShape {
  source: string;
  at: number;
  parsers: Map<string, PortableParser>;
  entries: CatalogEntry[];
}
let cache: CacheShape | null = null;
const CACHE_TTL = 5 * 60 * 1000;

function toEntry(p: PortableParser, filePath: string, v: ValidationResult, t: SelfTestResult | null): CatalogEntry {
  return {
    name: p?.name,
    description: p?.description,
    parser_type: p?.parser_type,
    priority: p?.priority,
    tags: p?.metadata?.tags || [],
    log_source: p?.metadata?.log_source,
    author: p?.metadata?.author,
    references: p?.metadata?.references || [],
    path: filePath,
    valid: v.ok && (t ? t.ok : true),
    errors: v.errors,
    warnings: v.warnings,
    self_test: t ? { ok: t.ok, passed: t.passed, total: t.total } : null,
    signature: parserSignature(p || ({} as any)),
  };
}

/** Fetch + validate the whole catalog (cached). `get` is injectable for tests. */
export async function fetchCatalog(
  force = false,
  get: HttpGetter = httpsGet
): Promise<{ source: CatalogSource; entries: CatalogEntry[] }> {
  const src = getCatalogSource();
  const key = `${src.repo}@${src.ref}:${src.path}`;
  if (!force && cache && cache.source === key && Date.now() - cache.at < CACHE_TTL) {
    return { source: src, entries: cache.entries };
  }

  const paths = await listParserPaths(src, get);
  const parsers = new Map<string, PortableParser>();
  const entries: CatalogEntry[] = [];

  for (const filePath of paths) {
    try {
      const p = await fetchRawParser(src, filePath, get);
      const v = validatePortableParser(p, { strict: true });
      const t = v.ok ? runSelfTests(p) : null;
      if (p?.name) parsers.set(p.name, p);
      entries.push(toEntry(p, filePath, v, t));
    } catch (error) {
      logger.warn('Catalog: failed to load parser file', {
        filePath,
        error: error instanceof Error ? error.message : String(error),
      });
      entries.push({
        name: filePath.split('/').pop()!.replace(/\.parser\.json$/, ''),
        tags: [],
        references: [],
        path: filePath,
        valid: false,
        errors: [`Could not load: ${error instanceof Error ? error.message : String(error)}`],
        warnings: [],
        self_test: null,
        signature: '',
      });
    }
  }

  entries.sort((a, b) => a.name.localeCompare(b.name));
  cache = { source: key, at: Date.now(), parsers, entries };
  return { source: src, entries };
}

/** Get one catalog parser by name (uses the cache; refreshes if missing). */
export async function getCatalogParser(name: string): Promise<PortableParser | null> {
  if (!cache || Date.now() - cache.at >= CACHE_TTL || !cache.parsers.has(name)) {
    await fetchCatalog(true);
  }
  return cache?.parsers.get(name) || null;
}

export function clearCatalogCache(): void {
  cache = null;
}
