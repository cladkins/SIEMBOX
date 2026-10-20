import { Router, Request, Response } from 'express';
import { DetectionRuleModel } from '../models/DetectionRule';
import * as yaml from '../utils/yaml';
import { ApiError } from '../middleware/errorHandler';
import { RulesEngine } from '../services/rules/rulesEngine';
import { validateRule, toPortableRule, portableRuleToYaml, ruleRegexTypeErrors } from '../services/rules/rulePortable';
import { convertSigmaYaml } from '../services/rules/sigmaConvert';
import { catalogNewFileUrl } from '../services/parser/catalogService';
import {
  fetchDetectionCatalog,
  getCatalogDetection,
  getCatalogDetections,
  getDetectionSource,
  clearDetectionCache,
  ruleSignature,
} from '../services/rules/detectionCatalog';
import { RuleSourceSample, CandidateRule } from '../services/rules/detectionRecommendations';
import { generateDetection } from '../services/ai/aiService';
import { authorize } from '../middleware/auth';
import { hasRequiredRole, requireScanPermission, UserRole } from '../middleware/scanPermissions';
import { query } from '../config/database';
import { redosErrorMessage, redosUndecidedMessage, redosWarningMessage } from '../services/parser/redos';
import {
  assessRuleRegexes,
  collectRuleRegexes,
  isRefused,
  peekRegexSafety,
  refusalCode,
  refusalReason,
  withRuleRegexSafety,
  type RegexSafetyReport,
} from '../services/regex/regexSafety';
import { recommendRulesBounded, regexRunErrorResponse } from '../services/regex/boundedRegex';
import { gateOrRefuse, sendRegexRunError } from '../services/regex/regexHttp';
import { analyzeAttackTags } from '../services/attack/attackTags';

const router = Router();

// app.ts mounts this router behind `authenticate`, so the reads are open to every
// role. Creating, changing, deleting or installing a detection needs analyst or
// higher (a viewer could otherwise disable detections); a refused call is
// written to audit_logs. The AI builder and Sigma import stay admin-only.
//
// Regex safety (services/regex): a rule's `regex` conditions run on every parsed
// log. Every write path refuses one recheck proves vulnerable to catastrophic
// backtracking (422 REGEX_UNSAFE; a batch records it in `failed`), refuses one
// recheck cannot read that V8's linear-time fallback cannot bound either (422
// REGEX_UNDECIDED), and accepts any other indeterminate one with a warning.
const requireRuleWrite = requireScanPermission(UserRole.Analyst, 'detection_rule');

/** The write-time regex gate for one rule (answers 422/503 itself and returns null). */
function gateRule(res: Response, subject: string, rule: unknown): Promise<RegexSafetyReport | null> {
  return gateOrRefuse(res, subject, () => assessRuleRegexes(rule));
}

/**
 * The ATT&CK tag check for a rule write: 422 ATTACK_TAG_INVALID (nothing saved)
 * for an unknown, revoked or deprecated technique or an unknown tactic, with
 * the validator's own messages. Tags in `previous` (the stored rule's) are not
 * refused again, so an edit that keeps an old tag (enable/disable) still
 * saves. Returns the warnings, or null when it answered the request.
 */
function gateAttackTags(res: Response, subject: string, tags: unknown, previous: unknown = []): string[] | null {
  if (!Array.isArray(tags)) return [];
  const report = analyzeAttackTags(tags);
  const kept = new Set(Array.isArray(previous) ? previous : []);
  const errors = report.errors.filter((_e, i) => !kept.has(report.invalidTags[i]));
  if (errors.length > 0) {
    res.status(422).json({
      code: 'ATTACK_TAG_INVALID',
      message: `${subject} was not saved: ${errors.join('; ')}`,
      errors,
      warnings: report.warnings,
    });
    return null;
  }
  return report.warnings;
}

type BatchGate = { ok: true; report: RegexSafetyReport } | { ok: false; reason: string; code: string };

/** The gate for one item of a batch (catalog install-all, Sigma import): it never answers the request. */
async function batchGate(rule: unknown): Promise<BatchGate> {
  try {
    const report = await assessRuleRegexes(rule);
    if (isRefused(report)) return { ok: false, reason: refusalReason(report), code: refusalCode(report) };
    return { ok: true, report };
  } catch (error) {
    const answer = regexRunErrorResponse(error);
    if (!answer) throw error;
    return { ok: false, reason: answer.body.message, code: answer.body.code };
  }
}

// Get all rules
router.get('/', async (_req: Request, res: Response) => {
  try {
    const rules = await DetectionRuleModel.findAll();
    // `regex_safety` (cached verdicts only): status 'vulnerable' is the
    // Detection Rules page's "Unsafe regex" tag.
    res.json(rules.map(withRuleRegexSafety));
  } catch {
    throw new ApiError(500, 'Failed to fetch rules');
  }
});

// AI: generate a detection rule from a natural-language description (+ optional
// context about available fields), validated against the engine contract with an
// auto-refine loop. Returns the proposed rule + validation.
router.post('/ai/generate', authorize('admin'), async (req: Request, res: Response) => {
  try {
    const { description, context, maxAttempts } = req.body ?? {};
    if (!description || typeof description !== 'string') {
      throw new ApiError(400, 'description is required');
    }
    const result = await generateDetection({ description, context, maxAttempts });
    res.json(result);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, `AI generation failed: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
});

// Detection-rule recommendations: dry-run every not-installed catalog rule's
// conditions against samples of recent PARSED logs using the real condition
// evaluator, ranked by matching traffic per day × rule severity. Empirical —
// a recommended rule is one your live data actually satisfies. Cached 10 min;
// `?refresh=true` bypasses.
let ruleRecsCache: { at: number; body: any } | null = null;
const RULE_RECS_TTL = 10 * 60 * 1000;

router.get('/recommendations', async (req: Request, res: Response) => {
  try {
    if (req.query.refresh !== 'true' && ruleRecsCache && Date.now() - ruleRecsCache.at < RULE_RECS_TTL) {
      res.json(ruleRecsCache.body);
      return;
    }

    // Per-parser daily volumes from the incrementally-maintained counters
    // (parser_id 0 is the unparsed fallback — rules never see those logs).
    const volumes = await query(
      `SELECT h.parser_id, p.name, SUM(h.matches)::bigint AS daily_volume
       FROM parser_match_hourly h
       JOIN parsers p ON p.id = h.parser_id
       WHERE h.parser_id <> 0 AND h.hour >= NOW() - INTERVAL '24 hours'
       GROUP BY h.parser_id, p.name`
    );

    // Recent parsed_data samples per parser — one pass over a 6h window.
    const sampleRows = await query(
      `SELECT parser_id, parsed_data FROM (
         SELECT parser_id, parsed_data,
                ROW_NUMBER() OVER (PARTITION BY parser_id ORDER BY id DESC) AS rn
         FROM parsed_logs
         WHERE created_at >= NOW() - INTERVAL '6 hours' AND parser_id IS NOT NULL
       ) t WHERE rn <= 12`
    );
    const samplesByParser = new Map<number, Array<Record<string, any>>>();
    for (const row of sampleRows.rows) {
      const id = Number(row.parser_id);
      if (!samplesByParser.has(id)) samplesByParser.set(id, []);
      samplesByParser.get(id)!.push(row.parsed_data || {});
    }

    const sources: RuleSourceSample[] = volumes.rows.map((v: any) => ({
      parser_name: v.name,
      samples: samplesByParser.get(Number(v.parser_id)) || [],
      daily_volume: Number(v.daily_volume),
    }));

    // Candidates: valid catalog rules the user doesn't effectively already
    // have. Dedup by BOTH name and content signature so a catalog rule
    // installed under a renamed local copy (same conditions/aggregation/alert,
    // different name) isn't recommended back. Name dedup is kept so a
    // locally-edited install (same name, drifted content) also isn't re-suggested.
    const { entries } = await fetchDetectionCatalog(false);
    const localRules = await DetectionRuleModel.findAll();
    const installedNames = new Set(localRules.map((r) => r.name));
    const installedSigs = new Set(localRules.map((r) => ruleSignature(r)).filter(Boolean));
    const parsedByName = await getCatalogDetections();
    // A candidate already known to be ReDoS-vulnerable is not dry-run; the rest
    // run in the regex test pool (catalog regexes against live log fields).
    const candidates: CandidateRule[] = entries
      .filter((e) => e.valid && !installedNames.has(e.name) && !(e.signature && installedSigs.has(e.signature)))
      .map((e) => parsedByName.get(e.name))
      .filter((r): r is CandidateRule => !!r)
      .filter((r) => peekRegexSafety(collectRuleRegexes(r)).status !== 'vulnerable');

    let recommended: Awaited<ReturnType<typeof recommendRulesBounded>>;
    try {
      recommended = await recommendRulesBounded(sources, candidates);
    } catch (error) {
      const answer = regexRunErrorResponse(error, 'The recommendation dry-run');
      if (!answer) throw error;
      res.status(503).json(answer.body);
      return;
    }
    const body = {
      window: '24h',
      sampled_parsers: sources.length,
      candidates_considered: candidates.length,
      computed_at: new Date().toISOString(),
      ...recommended,
    };
    ruleRecsCache = { at: Date.now(), body };
    res.json(body);
  } catch (error) {
    throw new ApiError(
      502,
      `Failed to compute rule recommendations: ${error instanceof Error ? error.message : 'unknown error'}`
    );
  }
});

// Browse the detection catalog (remote GitHub repo), annotated with install status.
// `?refresh=true` bypasses the 5-minute cache for analyst and up only, as in
// GET /api/parsers/catalog: a viewer's flag is ignored.
router.get('/catalog', async (req: Request, res: Response) => {
  try {
    const force = req.query.refresh === 'true' && hasRequiredRole(req.user?.role ?? '', UserRole.Analyst);
    const { source, entries } = await fetchDetectionCatalog(force);
    const installed = await DetectionRuleModel.findAll();
    const bySig = new Map(installed.map((r) => [r.name, ruleSignature(r)]));
    // Cached verdicts only; entries not analyzed yet are queued in the background.
    const parsedByName = await getCatalogDetections();
    const rules = entries.map((e) => {
      const isInstalled = bySig.has(e.name);
      const parsed = parsedByName.get(e.name);
      return {
        ...e,
        installed: isInstalled,
        update_available: isInstalled && e.signature !== '' && bySig.get(e.name) !== e.signature,
        regex_safety: parsed ? peekRegexSafety(collectRuleRegexes(parsed)) : undefined,
      };
    });
    res.json({ source, rules });
  } catch (error) {
    throw new ApiError(502, `Failed to load detection catalog: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
});

// Current detection catalog source (for display/config hints).
router.get('/catalog/source', (_req: Request, res: Response) => {
  res.json(getDetectionSource());
});

// Install (or update) a detection rule from the catalog by name: fetch -> validate
// -> upsert. Preserves the operator's enabled toggle on update (like the importer).
router.post('/catalog/install', requireRuleWrite, async (req: Request, res: Response) => {
  try {
    const { name } = req.body ?? {};
    if (!name || typeof name !== 'string') {
      throw new ApiError(400, 'name is required');
    }

    const found = await getCatalogDetection(name);
    if (!found) {
      throw new ApiError(404, `Rule "${name}" not found in catalog`);
    }

    const { rule_yaml, parsed } = found;
    const validation = validateRule(parsed, { strict: false });
    if (!validation.ok) {
      res.status(422).json({ message: 'Catalog rule failed validation', validation });
      return;
    }
    const safety = await gateRule(res, `Catalog rule "${parsed.name}"`, parsed);
    if (!safety) return;

    const rule_logic = {
      conditions: parsed.conditions,
      aggregation: parsed.aggregation,
      alert: parsed.alert,
    };
    const existing = await DetectionRuleModel.findByName(parsed.name);
    const saved = existing
      ? await DetectionRuleModel.update(existing.id, {
          description: parsed.description,
          severity: parsed.severity,
          rule_yaml,
          rule_logic,
          tags: parsed.tags || [],
        })
      : await DetectionRuleModel.create({
          name: parsed.name,
          description: parsed.description,
          enabled: parsed.enabled !== false,
          severity: parsed.severity,
          rule_yaml,
          rule_logic,
          tags: parsed.tags || [],
        });

    await RulesEngine.getInstance().reload();
    res.status(existing ? 200 : 201).json({
      action: existing ? 'updated' : 'created',
      rule: saved,
      warnings: safety.warnings,
      regex_safety: { vulnerable: [], unknown: safety.unknown },
    });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to install rule from catalog');
  }
});

// Install (or update) EVERY detection in the catalog — the "Install all" action,
// the populate path for a catalog-only (unseeded) install. Bad items are
// recorded in `failed` and skipped rather than aborting the batch; the engine is
// reloaded once at the end.
router.post('/catalog/install-all', requireRuleWrite, async (req: Request, res: Response) => {
  try {
    const { entries } = await fetchDetectionCatalog(req.query.refresh === 'true');
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
        const found = await getCatalogDetection(entry.name);
        if (!found) {
          results.failed.push({ name: entry.name, reason: 'not found in catalog' });
          continue;
        }
        const { rule_yaml, parsed } = found;
        const validation = validateRule(parsed, { strict: false });
        if (!validation.ok) {
          results.failed.push({ name: entry.name, reason: `failed validation: ${validation.errors.join('; ')}` });
          continue;
        }
        const gate = await batchGate(parsed);
        if (!gate.ok) {
          results.failed.push({ name: entry.name, reason: gate.reason, code: gate.code });
          continue;
        }
        if (gate.report.warnings.length > 0) results.warnings.push({ name: entry.name, warnings: gate.report.warnings });
        const rule_logic = {
          conditions: parsed.conditions,
          aggregation: parsed.aggregation,
          alert: parsed.alert,
        };
        const existing = await DetectionRuleModel.findByName(parsed.name);
        if (existing) {
          await DetectionRuleModel.update(existing.id, {
            description: parsed.description,
            severity: parsed.severity,
            rule_yaml,
            rule_logic,
            tags: parsed.tags || [],
          });
          results.updated++;
        } else {
          await DetectionRuleModel.create({
            name: parsed.name,
            description: parsed.description,
            enabled: parsed.enabled !== false,
            severity: parsed.severity,
            rule_yaml,
            rule_logic,
            tags: parsed.tags || [],
          });
          results.installed++;
        }
      } catch (e) {
        results.failed.push({
          name: entry.name,
          reason: e instanceof Error ? e.message : 'install error',
        });
      }
    }
    await RulesEngine.getInstance().reload();
    res.json(results);
  } catch (error) {
    throw new ApiError(
      502,
      `Failed to install detection catalog: ${error instanceof Error ? error.message : 'unknown error'}`
    );
  }
});

// Force a detection catalog cache refresh.
router.post('/catalog/refresh', requireRuleWrite, async (_req: Request, res: Response) => {
  try {
    clearDetectionCache();
    const { entries } = await fetchDetectionCatalog(true);
    res.json({ refreshed: true, count: entries.length });
  } catch (error) {
    throw new ApiError(502, `Failed to refresh detection catalog: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
});

// Preview a Sigma import: convert one-or-many Sigma YAML docs to portable rules
// and return the result (rule + per-doc errors/warnings) WITHOUT saving, so the
// UI can show exactly what will be created before the user commits.
router.post('/import/sigma/preview', authorize('admin'), async (req: Request, res: Response) => {
  const sigma = req.body?.sigma;
  if (typeof sigma !== 'string' || sigma.trim() === '') {
    throw new ApiError(400, 'sigma (YAML string) is required');
  }
  // Each converted rule passes the import's regex gate here too, so the
  // preview shows (inline, per document) the refusal the import would give.
  const results = [];
  for (const r of convertSigmaYaml(sigma)) {
    let errors = r.errors;
    let warnings = r.warnings;
    let regex_safety: { vulnerable: unknown[]; undecided: unknown[]; unknown: unknown[] } | undefined;
    if (r.rule) {
      let report: RegexSafetyReport;
      try {
        report = await assessRuleRegexes(r.rule);
      } catch (error) {
        if (sendRegexRunError(res, error)) return;
        throw error;
      }
      errors = [...errors, ...report.errors];
      warnings = [...warnings, ...report.warnings];
      regex_safety = { vulnerable: report.vulnerable, undecided: report.undecided, unknown: report.unknown };
    }
    results.push({
      title: r.title,
      ok: !!r.rule && (regex_safety?.vulnerable.length ?? 0) === 0 && (regex_safety?.undecided.length ?? 0) === 0,
      rule: r.rule,
      errors,
      warnings,
      fieldsUsed: r.fieldsUsed,
      regex_safety,
    });
  }
  res.json({
    total: results.length,
    convertible: results.filter((r) => r.ok).length,
    results,
  });
});

// Import Sigma rules: convert -> validate -> upsert each representable rule.
// Non-convertible docs are reported (with the reason) and skipped rather than
// aborting the batch. Imported rules are created DISABLED so the user reviews and
// enables them; updates preserve the existing enabled toggle (like the importer).
router.post('/import/sigma', authorize('admin'), async (req: Request, res: Response) => {
  const sigma = req.body?.sigma;
  if (typeof sigma !== 'string' || sigma.trim() === '') {
    throw new ApiError(400, 'sigma (YAML string) is required');
  }

  const converted = convertSigmaYaml(sigma);
  const results = {
    total: converted.length,
    created: 0,
    updated: 0,
    failed: [] as Array<{ title?: string; reason: string; code?: string }>,
    /** Imported, but a regex could not be proven safe (indeterminate). */
    warnings: [] as Array<{ title?: string; warnings: string[] }>,
  };

  for (const c of converted) {
    if (!c.rule) {
      results.failed.push({ title: c.title, reason: c.errors.join('; ') || 'not convertible' });
      continue;
    }
    const validation = validateRule(c.rule, { strict: false });
    if (!validation.ok) {
      results.failed.push({ title: c.title, reason: `validation: ${validation.errors.join('; ')}` });
      continue;
    }
    const gate = await batchGate(c.rule);
    if (!gate.ok) {
      results.failed.push({ title: c.title, reason: gate.reason, code: gate.code });
      continue;
    }
    if (gate.report.warnings.length > 0) results.warnings.push({ title: c.title, warnings: gate.report.warnings });
    try {
      const rule_logic = {
        conditions: c.rule.conditions,
        aggregation: c.rule.aggregation,
        alert: c.rule.alert,
      };
      const rule_yaml = portableRuleToYaml(c.rule);
      const existing = await DetectionRuleModel.findByName(c.rule.name);
      if (existing) {
        await DetectionRuleModel.update(existing.id, {
          description: c.rule.description,
          severity: c.rule.severity,
          rule_yaml,
          rule_logic,
          tags: c.rule.tags || [],
        });
        results.updated++;
      } else {
        await DetectionRuleModel.create({
          name: c.rule.name,
          description: c.rule.description,
          enabled: false, // imported disabled for review
          severity: c.rule.severity,
          rule_yaml,
          rule_logic,
          tags: c.rule.tags || [],
        });
        results.created++;
      }
    } catch (e) {
      results.failed.push({ title: c.title, reason: e instanceof Error ? e.message : 'save error' });
    }
  }

  if (results.created > 0 || results.updated > 0) {
    await RulesEngine.getInstance().reload();
  }
  res.json(results);
});

// Get single rule
router.get('/:id', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id as string);
    const rule = await DetectionRuleModel.findById(id);

    if (!rule) {
      throw new ApiError(404, 'Rule not found');
    }

    res.json(withRuleRegexSafety(rule));
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to fetch rule');
  }
});

// Prepare a community-catalog contribution for a saved detection: rebuild its
// portable YAML -> validate, and (only if clean) build a no-auth GitHub "propose
// new file" URL the user finishes in their own browser. SIEMBox never opens the
// PR or holds a credential; the catalog's CI + maintainer review are the gate.
router.get('/:id/contribute', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id as string);
    const rule = await DetectionRuleModel.findById(id);
    if (!rule) throw new ApiError(404, 'Rule not found');

    const portable = toPortableRule(rule);
    const validation = validateRule(portable, { strict: true });
    // The detection catalog's CI (validate-detections) refuses a ReDoS-vulnerable
    // regex, and one recheck cannot read that the linear-time fallback cannot
    // bound, so this check does too: same verdicts as the write-time gate, same
    // wording as the parser contribute check. Any other 'unknown' is a warning.
    let safety: RegexSafetyReport | null = null;
    if (validation.ok) {
      try {
        safety = await assessRuleRegexes(portable);
      } catch (error) {
        if (sendRegexRunError(res, error)) return;
        throw error;
      }
    }
    const ready = validation.ok && !(safety && isRefused(safety));

    const slug = String(rule.name || `rule-${id}`).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || `rule-${id}`;
    const filePath = `${getDetectionSource().path}/${slug}.yaml`;
    const content = portableRuleToYaml(rule);

    res.json({
      kind: 'detection',
      name: rule.name,
      path: filePath,
      content,
      valid: validation.ok,
      errors: [
        ...validation.errors,
        ...(safety?.vulnerable ?? []).map((f) => redosErrorMessage(f, 'contributing')),
        ...(safety?.undecided ?? []).map((f) => redosUndecidedMessage(f, 'contributing')),
      ],
      warnings: [...validation.warnings, ...(safety?.unknown ?? []).map(redosWarningMessage)],
      redos: safety ? [...safety.vulnerable, ...safety.undecided, ...safety.unknown] : [],
      self_test: null, // detections have no self-tests (parsers do)
      ready,
      contribute_url: ready ? catalogNewFileUrl(filePath, content) : null,
    });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to prepare contribution');
  }
});

// Create rule
router.post('/', requireRuleWrite, async (req: Request, res: Response) => {
  try {
    const { name, description, enabled, severity, rule_yaml, tags } = req.body;

    if (!name || !severity || !rule_yaml) {
      throw new ApiError(400, 'Missing required fields');
    }

    // Parse YAML to extract rule logic
    let rule_logic;
    try {
      rule_logic = yaml.load(rule_yaml) as any;
    } catch {
      throw new ApiError(400, 'Invalid YAML format');
    }
    const typeErrors = ruleRegexTypeErrors(rule_logic);
    if (typeErrors.length > 0) {
      throw new ApiError(400, `Invalid rule: ${typeErrors.join('; ')}`);
    }

    const attackWarnings = gateAttackTags(res, `Rule "${name}"`, tags);
    if (!attackWarnings) return;

    const safety = await gateRule(res, `Rule "${name}"`, rule_logic);
    if (!safety) return;

    const rule = await DetectionRuleModel.create({
      name,
      description,
      enabled,
      severity,
      rule_yaml,
      rule_logic,
      tags,
    });

    res.status(201).json({ ...withRuleRegexSafety(rule), warnings: [...attackWarnings, ...safety.warnings] });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to create rule');
  }
});

// Update rule
router.put('/:id', requireRuleWrite, async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id as string);
    const updateData = req.body;

    // If rule_yaml is being updated, parse it
    if (updateData.rule_yaml) {
      try {
        updateData.rule_logic = yaml.load(updateData.rule_yaml) as any;
      } catch {
        throw new ApiError(400, 'Invalid YAML format');
      }
    }

    // New rule logic (from YAML, or sent directly) passes the regex gate. An
    // edit that leaves the logic alone (enable/disable, rename) is never refused
    // for a regex it does not touch: disabling is the mitigation for an unsafe one.
    let warnings: string[] = [];
    if (Array.isArray(updateData.tags)) {
      const subject = typeof updateData.name === 'string' ? `Rule "${updateData.name}"` : `Rule ${id}`;
      const existing = await DetectionRuleModel.findById(id);
      const attackWarnings = gateAttackTags(res, subject, updateData.tags, existing?.tags);
      if (!attackWarnings) return;
      warnings = attackWarnings;
    }
    if (updateData.rule_logic !== undefined) {
      const typeErrors = ruleRegexTypeErrors(updateData.rule_logic);
      if (typeErrors.length > 0) {
        throw new ApiError(400, `Invalid rule: ${typeErrors.join('; ')}`);
      }
      const subject = typeof updateData.name === 'string' ? `Rule "${updateData.name}"` : `Rule ${id}`;
      const safety = await gateRule(res, subject, updateData.rule_logic);
      if (!safety) return;
      warnings = [...warnings, ...safety.warnings];
    }

    const rule = await DetectionRuleModel.update(id, updateData);

    if (!rule) {
      throw new ApiError(404, 'Rule not found');
    }

    // Reload rules engine to pick up the changes
    await RulesEngine.getInstance().reload();

    res.json({ ...withRuleRegexSafety(rule), warnings });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to update rule');
  }
});

// Delete rule
router.delete('/:id', requireRuleWrite, async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id as string);
    const deleted = await DetectionRuleModel.delete(id);

    if (!deleted) {
      throw new ApiError(404, 'Rule not found');
    }

    // Reload rules engine to pick up the changes
    await RulesEngine.getInstance().reload();

    res.json({ message: 'Rule deleted successfully' });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to delete rule');
  }
});

export default router;
