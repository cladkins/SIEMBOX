import { Router, Request, Response } from 'express';
import { ParserModel, Parser } from '../models/Parser';

/**
 * Validates the body of POST / (the "Create Parser" button). pattern must
 * always be present as a string -- the column is NOT NULL -- but only needs
 * to be non-empty for regex/grok; JSON parsers don't take one. Mirrors the
 * same rule services/parser/parserPortable.ts already enforces on every
 * other parser-ingestion path (validate/import/catalog install), which this
 * one plain route predated and duplicated incorrectly.
 * Returns an error message, or null if the body is valid.
 */
export function validateCreateParserBody(body: {
  name?: unknown;
  parser_type?: unknown;
  pattern?: unknown;
  field_mappings?: unknown;
}): string | null {
  const { name, parser_type, pattern, field_mappings } = body;
  if (!name || !parser_type || !field_mappings || typeof pattern !== 'string') {
    return 'Missing required fields';
  }
  if (parser_type !== 'json' && !pattern) {
    return 'pattern is required for regex/grok parsers';
  }
  return null;
}

/**
 * Type checks on the regex fields of PUT /:id, before the regex gate runs.
 * The gate analyzes string regexes only, and the runtime compiles only
 * strings; without these checks an array-wrapped `pattern` would be stored
 * as its node-postgres array literal (`{"..."}`, a string the gate never
 * saw), and an array-wrapped derivation regex would be stored as a matcher
 * that never matches. Returns an error message, or null.
 */
export function validateUpdateParserBody(body: { pattern?: unknown; derivations?: unknown }): string | null {
  if (body.pattern !== undefined && typeof body.pattern !== 'string') {
    return 'pattern must be a string';
  }
  if (body.derivations !== undefined && body.derivations !== null) {
    const errors = validateDerivations(body.derivations);
    if (errors.length > 0) return `Invalid derivations: ${errors.join('; ')}`;
  }
  return null;
}
import { validateDerivations } from '../services/parser/derive';
import { ParserEngine } from '../services/parser/parserEngine';
import {
  validatePortableParser,
  toPortableParser,
  PortableParser,
  SelfTestResult,
} from '../services/parser/parserPortable';
import {
  fetchCatalog,
  getCatalogParser,
  getCatalogParsers,
  getCatalogSource,
  clearCatalogCache,
  parserSignature,
  catalogNewFileUrl,
} from '../services/parser/catalogService';
import { RecommendationResult, SourceSample, HIGH_SEVERITY_MAX } from '../services/parser/parserRecommendations';
import { generateParser } from '../services/ai/aiService';
import { collectParserRegexes, redosErrorMessage, redosUndecidedMessage, redosWarningMessage } from '../services/parser/redos';
import {
  assessParserRegexes,
  isRefused,
  peekRegexSafety,
  refusalCode,
  refusalReason,
  withParserRegexSafety,
  type RegexSafetyReport,
} from '../services/regex/regexSafety';
import { gateOrRefuse, sendRegexRunError } from '../services/regex/regexHttp';
import {
  recommendParsersBounded,
  regexRunErrorResponse,
  runParserBounded,
  runSelfTestsBounded,
  sampleProblem,
  testSamplesProblem,
} from '../services/regex/boundedRegex';
import { authorize } from '../middleware/auth';
import { hasRequiredRole, requireScanPermission, UserRole } from '../middleware/scanPermissions';
import { ApiError } from '../middleware/errorHandler';
import { query } from '../config/database';

const router = Router();

// app.ts mounts this router behind `authenticate`, so the reads are open to every
// role. Anything that changes a parser, or runs a regex the caller supplies
// (/validate, /test), needs analyst or higher. A refused call is written to
// audit_logs. POST /:id/test stays open: it runs a saved parser on a sample the
// caller supplies.
//
// Regex safety (services/regex): every write refuses a regex recheck proves
// vulnerable to catastrophic backtracking (422 REGEX_UNSAFE) or cannot read when
// V8's linear-time fallback cannot bound it either (422 REGEX_UNDECIDED), and
// accepts any other indeterminate one with a warning; every route that runs a pattern on a
// caller's sample runs it in a worker thread with a hard time budget (422
// REGEX_TIMEOUT), never on the event loop that serves the API and ingestion.
const requireParserWrite = requireScanPermission(UserRole.Analyst, 'parser');

/** The write-time regex gate for one parser (answers 422/503 itself and returns null). */
function gateParser(
  res: Response,
  subject: string,
  parser: Parameters<typeof assessParserRegexes>[0]
): Promise<RegexSafetyReport | null> {
  return gateOrRefuse(res, subject, () => assessParserRegexes(parser));
}

/** A portable parser's self-tests in the regex test pool; answers 422/503 itself and returns null. */
async function boundedSelfTests(res: Response, parser: PortableParser): Promise<SelfTestResult | null> {
  try {
    return await runSelfTestsBounded(parser);
  } catch (error) {
    if (sendRegexRunError(res, error, "The parser's self-tests")) return null;
    throw error;
  }
}

/** Fields of a parser whose change can change which regexes run. */
const REGEX_FIELDS = ['pattern', 'derivations', 'parser_type'] as const;

/** Upsert a (already-validated) portable parser by name. Shared by import + catalog install. */
async function upsertPortableParser(portable: PortableParser): Promise<{ action: 'created' | 'updated'; parser: Parser | null }> {
  const params = {
    name: portable.name,
    description: portable.description,
    enabled: portable.enabled,
    priority: portable.priority,
    parser_type: portable.parser_type,
    pattern: portable.pattern,
    field_mappings: portable.field_mappings,
    test_samples: portable.test_samples,
    event_type: portable.event_type ?? undefined,
    derivations: portable.derivations ?? null,
  };
  const existing = await ParserModel.findByName(portable.name);
  const saved = existing
    ? await ParserModel.update(existing.id, params)
    : await ParserModel.create(params);
  // Apply to the running syslog engine immediately — no restart needed.
  await ParserEngine.getInstance().reload();
  return { action: existing ? 'updated' : 'created', parser: saved };
}

// Get all parsers. Each carries `regex_safety` (cached verdicts only, never
// waits): status 'vulnerable' is the Parsers page's "Unsafe regex" tag.
router.get('/', async (_req: Request, res: Response) => {
  try {
    const parsers = await ParserModel.findAll();
    res.json(parsers.map(withParserRegexSafety));
  } catch {
    throw new ApiError(500, 'Failed to fetch parsers');
  }
});

// Per-parser match counts over the last 24h, so the Parsers page can show which
// parsers actually fire in production. A parser with zero matches is either
// unnecessary or — worse — silently failing against the real log stream while
// its self-tests pass (the CI-green/production-dead class). Uses
// idx_parsed_logs_timestamp; parser_id NULL rows are the unparsed fallback.
router.get('/match-stats', async (_req: Request, res: Response) => {
  try {
    // Reads the incrementally-maintained hourly counters (see migration 024 and
    // ParserEngine.bumpMatchCount) — the previous parsed_logs GROUP BY scanned
    // millions of rows on busy installs and timed out the UI. parser_id 0 is
    // the unparsed fallback; `since` marks where counter data begins (the
    // window fills over the first day after an upgrade).
    const result = await query(
      `SELECT parser_id, SUM(matches)::bigint AS matches, MIN(hour) AS since
       FROM parser_match_hourly
       WHERE hour >= NOW() - INTERVAL '24 hours'
       GROUP BY parser_id`
    );
    const byParser: Record<string, number> = {};
    let unparsed = 0;
    let since: string | null = null;
    for (const row of result.rows) {
      if (Number(row.parser_id) === 0) unparsed = Number(row.matches);
      else byParser[String(row.parser_id)] = Number(row.matches);
      if (since === null || row.since < since) since = row.since;
    }
    res.json({ window: '24h', since, by_parser: byParser, unparsed });
  } catch {
    throw new ApiError(500, 'Failed to compute parser match stats');
  }
});

// Parser recommendations: dry-run every not-installed catalog parser against a
// severity-stratified sample of recent UNPARSED logs (the real runParser
// pipeline — no heuristics), and rank by how much detection-visible coverage
// each would add, weighting warning-or-worse traffic 10×. Expensive-ish (one
// 24h aggregate + a windowed sample + regex dry-runs), so the result is cached
// for 10 minutes; `?refresh=true` bypasses.
let recommendationsCache: { at: number; body: any } | null = null;
const RECOMMENDATIONS_TTL = 10 * 60 * 1000;

router.get('/recommendations', async (req: Request, res: Response) => {
  try {
    if (
      req.query.refresh !== 'true' &&
      recommendationsCache &&
      Date.now() - recommendationsCache.at < RECOMMENDATIONS_TTL
    ) {
      res.json(recommendationsCache.body);
      return;
    }

    // Per-source unparsed volume over 24h, with the warning-or-worse share.
    const volumes = await query(
      `SELECT r.app_name,
              COUNT(*)::bigint AS unparsed_daily,
              COUNT(*) FILTER (WHERE r.severity IS NOT NULL AND r.severity <= $1)::bigint AS unparsed_high_sev_daily
       FROM parsed_logs pl
       JOIN raw_logs r ON r.id = pl.raw_log_id
       WHERE pl.parser_id IS NULL
         AND pl.created_at >= NOW() - INTERVAL '24 hours'
       GROUP BY r.app_name
       ORDER BY 3 DESC, 2 DESC
       LIMIT 40`,
      [HIGH_SEVERITY_MAX]
    );

    // Recent messages per source (up to 20), stratified so warning-or-worse
    // lines are sampled first (a source's error format is what detections care
    // about), recency breaking ties. One pass over a 6h window. 20 (vs the
    // earlier 12) tightens candidate match rates and gives the AI-builder
    // handoff enough raw lines to derive several structurally-distinct samples.
    const sampleRows = await query(
      `SELECT app_name, raw_message FROM (
         SELECT app_name, raw_message,
                ROW_NUMBER() OVER (
                  PARTITION BY app_name
                  ORDER BY (CASE WHEN severity IS NOT NULL AND severity <= $1 THEN 0 ELSE 1 END), id DESC
                ) AS rn
         FROM raw_logs
         WHERE created_at >= NOW() - INTERVAL '6 hours'
       ) t WHERE rn <= 20`,
      [HIGH_SEVERITY_MAX]
    );
    const messagesByApp = new Map<string | null, string[]>();
    for (const row of sampleRows.rows) {
      const key = row.app_name ?? null;
      if (!messagesByApp.has(key)) messagesByApp.set(key, []);
      messagesByApp.get(key)!.push(row.raw_message);
    }

    const samples: SourceSample[] = volumes.rows.map((v: any) => ({
      app_name: v.app_name ?? null,
      messages: messagesByApp.get(v.app_name ?? null) || [],
      unparsed_daily: Number(v.unparsed_daily),
      unparsed_high_sev_daily: Number(v.unparsed_high_sev_daily),
    }));

    // Candidates: valid catalog parsers the user doesn't effectively already
    // have. Dedup by BOTH name and content signature: name alone missed a
    // catalog parser installed under a renamed local copy (same content, no
    // name match) — it would be recommended back to the user. Signature is the
    // parser_type+pattern+field_mappings+derivations+event_type fingerprint the
    // catalog browser uses, so a byte-identical parser is excluded whatever it
    // is named locally. Name dedup is kept too, so a locally-edited install
    // (same name, drifted content) still isn't re-suggested.
    const localParsers = await ParserModel.findAll();
    const installedNames = new Set(localParsers.map((p) => p.name));
    const installedSigs = new Set(localParsers.map((p) => parserSignature(p)).filter(Boolean));
    const { entries } = await fetchCatalog(false);
    const portable = await getCatalogParsers();
    // A candidate already known to be ReDoS-vulnerable is not dry-run (it could
    // not be installed anyway). The rest run in the regex test pool: they are
    // catalog regexes against live log lines a remote sender wrote.
    const candidates = entries
      .filter((e) => e.valid && !installedNames.has(e.name) && !(e.signature && installedSigs.has(e.signature)))
      .map((e) => portable.get(e.name))
      .filter((p): p is PortableParser => !!p)
      .filter((p) => peekRegexSafety(collectParserRegexes(p)).status !== 'vulnerable');

    let result: RecommendationResult;
    try {
      result = await recommendParsersBounded(samples, candidates);
    } catch (error) {
      const answer = regexRunErrorResponse(error, 'The recommendation dry-run');
      if (!answer) throw error;
      res.status(503).json(answer.body);
      return;
    }
    const body = {
      window: '24h',
      sampled_sources: samples.length,
      candidates_considered: candidates.length,
      computed_at: new Date().toISOString(),
      ...result,
    };
    recommendationsCache = { at: Date.now(), body };
    res.json(body);
  } catch (error) {
    throw new ApiError(
      502,
      `Failed to compute parser recommendations: ${error instanceof Error ? error.message : 'unknown error'}`
    );
  }
});

// Validate a portable parser (and run its self-tests) WITHOUT saving. Used by the
// import preview UI and shares the exact logic the catalog CI runs, plus the
// import's own regex safety gate, so the preview refuses what the import would
// refuse (422 REGEX_UNSAFE). Self-tests run in the regex test pool (422
// REGEX_TIMEOUT when a pattern backtracks past the budget on a sample).
router.post('/validate', requireParserWrite, async (req: Request, res: Response) => {
  try {
    const { parser, strict } = req.body ?? {};
    const validation = validatePortableParser(parser, { strict: !!strict });
    if (!validation.ok) {
      res.json({ ok: false, validation, self_test: null });
      return;
    }
    const portable = parser as PortableParser;
    const tooBig = testSamplesProblem(portable);
    if (tooBig) {
      res.status(413).json({ code: 'SAMPLE_TOO_LARGE', message: tooBig });
      return;
    }
    const safety = await gateParser(res, `Parser "${portable.name}"`, portable);
    if (!safety) return;
    const selfTest = await boundedSelfTests(res, portable);
    if (!selfTest) return;
    res.json({
      ok: selfTest.ok,
      validation: { ...validation, warnings: [...validation.warnings, ...safety.warnings] },
      self_test: selfTest,
      regex_safety: { vulnerable: [], unknown: safety.unknown },
    });
  } catch {
    throw new ApiError(500, 'Failed to validate parser');
  }
});

// Import a portable parser: validate -> regex safety gate -> run self-tests ->
// upsert by name. Refuses a ReDoS-vulnerable regex (422 REGEX_UNSAFE), or an
// undecided one nothing bounds (422 REGEX_UNDECIDED), whatever `force` says, and a parser whose own test_samples fail unless `force` is set.
router.post('/import', requireParserWrite, async (req: Request, res: Response) => {
  try {
    const { parser, force } = req.body ?? {};
    const validation = validatePortableParser(parser, { strict: false });
    if (!validation.ok) {
      res.status(422).json({ message: 'Parser failed validation', validation });
      return;
    }

    const portable = parser as PortableParser;
    const tooBig = testSamplesProblem(portable);
    if (tooBig) {
      res.status(413).json({ code: 'SAMPLE_TOO_LARGE', message: tooBig });
      return;
    }
    const safety = await gateParser(res, `Parser "${portable.name}"`, portable);
    if (!safety) return;
    const selfTest = await boundedSelfTests(res, portable);
    if (!selfTest) return;
    if (!selfTest.ok && !force) {
      res.status(422).json({
        message: 'Parser self-tests failed; pass force=true to import anyway',
        self_test: selfTest,
      });
      return;
    }

    const result = await upsertPortableParser(portable);
    res.status(result.action === 'created' ? 201 : 200).json({
      action: result.action,
      parser: result.parser,
      self_test: selfTest,
      warnings: [...validation.warnings, ...safety.warnings],
      regex_safety: { vulnerable: [], unknown: safety.unknown },
    });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to import parser');
  }
});

// AI: generate a portable parser from a log sample (validated + self-tested,
// with an auto-refine loop). Returns the proposed parser + its check results.
router.post('/ai/generate', authorize('admin'), async (req: Request, res: Response) => {
  try {
    const { sample, hints, maxAttempts } = req.body ?? {};
    if (!sample || typeof sample !== 'string') {
      throw new ApiError(400, 'sample is required');
    }
    const result = await generateParser({ sample, hints, maxAttempts });
    res.json(result);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, `AI generation failed: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
});

// Browse the parser catalog (remote GitHub repo), annotated with install status.
// `?refresh=true` bypasses the 5-minute cache for analyst and up, the roles that
// may POST /catalog/refresh: a forced fetch lists the repo through the GitHub API
// (60 unauthenticated calls an hour), so a viewer's flag is ignored and they get
// the cached listing.
router.get('/catalog', async (req: Request, res: Response) => {
  try {
    const force = req.query.refresh === 'true' && hasRequiredRole(req.user?.role ?? '', UserRole.Analyst);
    const { source, entries } = await fetchCatalog(force);
    const installed = await ParserModel.findAll();
    const bySig = new Map(installed.map((p) => [p.name, parserSignature(p)]));
    // Cached verdicts only (an entry not analyzed yet is queued in the background,
    // which also warms the cache before an "Install all").
    const portableByName = await getCatalogParsers();
    const parsers = entries.map((e) => {
      const isInstalled = bySig.has(e.name);
      const portable = portableByName.get(e.name);
      return {
        ...e,
        installed: isInstalled,
        update_available: isInstalled && e.signature !== '' && bySig.get(e.name) !== e.signature,
        regex_safety: portable ? peekRegexSafety(collectParserRegexes(portable)) : undefined,
      };
    });
    res.json({ source, parsers });
  } catch (error) {
    throw new ApiError(502, `Failed to load catalog: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
});

// Current catalog source (for display/config hints).
router.get('/catalog/source', (_req: Request, res: Response) => {
  res.json(getCatalogSource());
});

// Install (or update) a parser from the catalog by name: fetch -> validate ->
// self-test -> upsert. Refuses on failing self-tests unless `force`.
router.post('/catalog/install', requireParserWrite, async (req: Request, res: Response) => {
  try {
    const { name, force } = req.body ?? {};
    if (!name || typeof name !== 'string') {
      throw new ApiError(400, 'name is required');
    }

    const portable = await getCatalogParser(name);
    if (!portable) {
      throw new ApiError(404, `Parser "${name}" not found in catalog`);
    }

    const validation = validatePortableParser(portable, { strict: false });
    if (!validation.ok) {
      res.status(422).json({ message: 'Catalog parser failed validation', validation });
      return;
    }
    // The catalog is remote content (and SIEMBOX_CATALOG_REPO can point at any
    // repository): its regexes pass the same gate as a pasted import.
    const safety = await gateParser(res, `Catalog parser "${portable.name}"`, portable);
    if (!safety) return;
    const selfTest = await boundedSelfTests(res, portable);
    if (!selfTest) return;
    if (!selfTest.ok && !force) {
      res.status(422).json({ message: 'Catalog parser self-tests failed', self_test: selfTest });
      return;
    }

    const result = await upsertPortableParser(portable);
    res.status(result.action === 'created' ? 201 : 200).json({
      action: result.action,
      parser: result.parser,
      self_test: selfTest,
      warnings: safety.warnings,
      regex_safety: { vulnerable: [], unknown: safety.unknown },
    });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to install parser from catalog');
  }
});

// Install (or update) EVERY parser in the catalog — the "Install all" action,
// the populate path for a catalog-only (unseeded) install. Each item is
// validated + self-tested; a bad item is recorded in `failed` and skipped
// rather than aborting the batch. `force` installs items whose self-tests fail.
router.post('/catalog/install-all', requireParserWrite, async (req: Request, res: Response) => {
  try {
    const force = !!(req.body && req.body.force);
    const { entries } = await fetchCatalog(req.query.refresh === 'true');
    const results = {
      total: entries.length,
      installed: 0,
      updated: 0,
      failed: [] as Array<{ name: string; reason: string; code?: string }>,
      /** Installed, but a regex could not be proven safe (indeterminate). */
      warnings: [] as Array<{ name: string; warnings: string[] }>,
    };
    for (const entry of entries) {
      try {
        const portable = await getCatalogParser(entry.name);
        if (!portable) {
          results.failed.push({ name: entry.name, reason: 'not found in catalog' });
          continue;
        }
        const validation = validatePortableParser(portable, { strict: false });
        if (!validation.ok) {
          results.failed.push({ name: entry.name, reason: 'failed validation' });
          continue;
        }
        let safety: RegexSafetyReport;
        let selfTestOk: boolean;
        try {
          safety = await assessParserRegexes(portable);
          if (isRefused(safety)) {
            results.failed.push({ name: entry.name, reason: refusalReason(safety), code: refusalCode(safety) });
            continue;
          }
          selfTestOk = (await runSelfTestsBounded(portable)).ok;
        } catch (error) {
          const answer = regexRunErrorResponse(error, "The parser's self-tests");
          if (!answer) throw error;
          results.failed.push({ name: entry.name, reason: answer.body.message, code: answer.body.code });
          continue;
        }
        if (!selfTestOk && !force) {
          results.failed.push({ name: entry.name, reason: 'self-tests failed' });
          continue;
        }
        if (safety.warnings.length > 0) results.warnings.push({ name: entry.name, warnings: safety.warnings });
        const r = await upsertPortableParser(portable);
        if (r.action === 'created') results.installed++;
        else results.updated++;
      } catch (e) {
        results.failed.push({
          name: entry.name,
          reason: e instanceof Error ? e.message : 'install error',
        });
      }
    }
    res.json(results);
  } catch (error) {
    throw new ApiError(
      502,
      `Failed to install catalog: ${error instanceof Error ? error.message : 'unknown error'}`
    );
  }
});

// Force a catalog cache refresh.
router.post('/catalog/refresh', requireParserWrite, async (_req: Request, res: Response) => {
  try {
    clearCatalogCache();
    const { entries } = await fetchCatalog(true);
    res.json({ refreshed: true, count: entries.length });
  } catch (error) {
    throw new ApiError(502, `Failed to refresh catalog: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
});

// Get single parser
router.get('/:id', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id as string);
    const parser = await ParserModel.findById(id);

    if (!parser) {
      throw new ApiError(404, 'Parser not found');
    }

    res.json(withParserRegexSafety(parser));
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to fetch parser');
  }
});

// Export a saved parser as a portable .parser.json (the catalog-shareable format).
router.get('/:id/export', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id as string);
    const parser = await ParserModel.findById(id);
    if (!parser) {
      throw new ApiError(404, 'Parser not found');
    }
    const portable = toPortableParser(parser);
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${parser.name}.parser.json"`);
    res.send(JSON.stringify(portable, null, 2));
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to export parser');
  }
});

// Prepare a community-catalog contribution for a saved parser: export -> validate
// -> self-test, and (only if clean) build a no-auth GitHub "propose new file" URL
// the user finishes in their own browser. SIEMBox never opens the PR or holds a
// credential; the catalog's CI + maintainer review are the merge gate.
router.get('/:id/contribute', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id as string);
    const parser = await ParserModel.findById(id);
    if (!parser) throw new ApiError(404, 'Parser not found');

    const portable = toPortableParser(parser);
    const validation = validatePortableParser(portable, { strict: true });
    // The stored regexes may predate the write-time gate: self-tests run in the
    // regex test pool, never on the event loop.
    const selfTest = validation.ok ? await boundedSelfTests(res, portable) : null;
    if (validation.ok && !selfTest) return;
    // ReDoS gate mirrors the published catalog's CI, so users see (and fix) a
    // vulnerable pattern here instead of hitting a red CI on their PR. The
    // analysis is the write-time gate's (same recheck verdicts, in a worker
    // thread: the old synchronous scan blocked the event loop for up to 10 s
    // per regex). A PROVEN-vulnerable regex blocks the link, and so does one
    // recheck cannot read that the linear-time fallback cannot bound; any other
    // 'unknown' is surfaced but not blocking (matches the validate-parsers CLI gate).
    let safety: RegexSafetyReport | null = null;
    if (validation.ok) {
      try {
        safety = await assessParserRegexes(portable);
      } catch (error) {
        if (sendRegexRunError(res, error)) return;
        throw error;
      }
    }
    const redos = safety ? [...safety.vulnerable, ...safety.undecided, ...safety.unknown] : [];
    const ready = validation.ok && !!selfTest?.ok && !(safety && isRefused(safety));

    const filePath = `${getCatalogSource().path}/${parser.name}.parser.json`;
    const content = JSON.stringify(portable, null, 2);

    res.json({
      kind: 'parser',
      name: parser.name,
      path: filePath,
      content,
      valid: validation.ok,
      // Fold ReDoS findings into the lists the dialog already renders: proven
      // vulnerabilities alongside errors (they block `ready`), indeterminate
      // results as warnings.
      errors: [
        ...validation.errors,
        ...(safety?.vulnerable ?? []).map((f) => redosErrorMessage(f, 'contributing')),
        ...(safety?.undecided ?? []).map((f) => redosUndecidedMessage(f, 'contributing')),
      ],
      warnings: [...validation.warnings, ...(safety?.unknown ?? []).map(redosWarningMessage)],
      self_test: selfTest,
      redos, // vulnerable/indeterminate regexes, if any (empty = clean)
      ready, // only offer the PR link when it would pass the catalog's CI
      contribute_url: ready ? catalogNewFileUrl(filePath, content) : null,
    });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to prepare contribution');
  }
});

// Create parser
router.post('/', requireParserWrite, async (req: Request, res: Response) => {
  try {
    const { name, description, enabled, priority, parser_type, pattern, field_mappings, test_samples } = req.body;

    const bodyError = validateCreateParserBody(req.body);
    if (bodyError) {
      throw new ApiError(400, bodyError);
    }

    const safety = await gateParser(res, `Parser "${name}"`, { parser_type, pattern });
    if (!safety) return;

    const parser = await ParserModel.create({
      name,
      description,
      enabled,
      priority,
      parser_type,
      pattern,
      field_mappings,
      test_samples,
    });
    await ParserEngine.getInstance().reload();

    res.status(201).json({ ...withParserRegexSafety(parser), warnings: safety.warnings });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to create parser');
  }
});

// Update parser. A change to pattern, derivations or parser_type passes the
// regex gate for the parser as it will be saved (so a vulnerable derivation
// left from before the gate must be fixed in the same edit). Other edits —
// enable/disable included, the immediate mitigation for an unsafe parser —
// are never refused for a regex they do not touch.
router.put('/:id', requireParserWrite, async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id as string);
    const body = req.body ?? {};
    const bodyError = validateUpdateParserBody(body);
    if (bodyError) {
      throw new ApiError(400, bodyError);
    }
    let warnings: string[] = [];
    if (REGEX_FIELDS.some((field) => body[field] !== undefined)) {
      const existing = await ParserModel.findById(id);
      if (!existing) {
        throw new ApiError(404, 'Parser not found');
      }
      const merged = {
        parser_type: body.parser_type ?? existing.parser_type,
        pattern: body.pattern ?? existing.pattern,
        derivations: body.derivations !== undefined ? body.derivations : existing.derivations,
      };
      const safety = await gateParser(res, `Parser "${body.name ?? existing.name}"`, merged);
      if (!safety) return;
      warnings = safety.warnings;
    }

    const parser = await ParserModel.update(id, body);

    if (!parser) {
      throw new ApiError(404, 'Parser not found');
    }

    // Enable/disable/edit takes effect on the running engine immediately.
    await ParserEngine.getInstance().reload();
    res.json({ ...withParserRegexSafety(parser), warnings });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to update parser');
  }
});

// Delete parser
router.delete('/:id', requireParserWrite, async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id as string);
    const deleted = await ParserModel.delete(id);

    if (!deleted) {
      throw new ApiError(404, 'Parser not found');
    }

    await ParserEngine.getInstance().reload();
    res.json({ message: 'Parser deleted successfully' });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to delete parser');
  }
});

// Test a saved parser against a caller's sample. Open to every role: the
// parser's regexes may predate the write-time gate, so the run goes to the
// regex test pool (422 REGEX_TIMEOUT past the budget) and the sample is capped
// (413 SAMPLE_TOO_LARGE).
router.post('/:id/test', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id as string);
    const { sample } = req.body;

    if (!sample) {
      throw new ApiError(400, 'Sample log is required');
    }
    const tooBig = sampleProblem(sample);
    if (tooBig) {
      res.status(413).json({ code: 'SAMPLE_TOO_LARGE', message: tooBig });
      return;
    }

    const parser = await ParserModel.findById(id);
    if (!parser) {
      throw new ApiError(404, 'Parser not found');
    }

    let result;
    try {
      result = await runParserBounded(parser, sample);
    } catch (error) {
      if (sendRegexRunError(res, error, 'The parser')) return;
      throw error;
    }

    res.json({
      matched: result !== null,
      fields: result ? result.fields : null,
    });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to test parser');
  }
});

// Test parser configuration without saving (for parser builder). The pattern is
// the caller's and has not been through the gate: it runs in the regex test
// pool with a hard time budget (422 REGEX_TIMEOUT), on a capped sample (413).
// An invalid pattern answers 422 REGEX_TEST_FAILED with the compiler's message.
router.post('/test', requireParserWrite, async (req: Request, res: Response) => {
  try {
    const { parser_type, pattern, field_mappings, sample } = req.body;

    if (!parser_type || !pattern || !field_mappings || !sample) {
      throw new ApiError(400, 'Missing required fields: parser_type, pattern, field_mappings, sample');
    }
    if (typeof pattern !== 'string' || typeof field_mappings !== 'object') {
      throw new ApiError(400, 'pattern must be a string and field_mappings an object');
    }
    const tooBig = sampleProblem(sample);
    if (tooBig) {
      res.status(413).json({ code: 'SAMPLE_TOO_LARGE', message: tooBig });
      return;
    }

    let result;
    try {
      result = await runParserBounded({ name: 'Test Parser', parser_type, pattern, field_mappings, event_type: null }, sample);
    } catch (error) {
      if (sendRegexRunError(res, error, 'The pattern')) return;
      throw error;
    }

    res.json({
      matched: result !== null,
      fields: result ? result.fields : null,
    });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to test parser');
  }
});

export default router;
