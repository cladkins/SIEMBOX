import { Router, Request, Response } from 'express';
import { ApiError } from '../middleware/errorHandler';
import { hasRequiredRole, requireScanPermission, UserRole } from '../middleware/scanPermissions';
import { DetectionRuleModel, type DetectionRule } from '../models/DetectionRule';
import { RulesEngine } from '../services/rules/rulesEngine';
import { collectRuleRegexes, peekRegexSafety, type RegexSafetySummary } from '../services/regex/regexSafety';
import { sigmaAttack, sigmaRuleUrl, type SigmaLibraryRule } from '../services/sigma/sigmaLibrary';
import {
  getSigmaState,
  loadSigmaLibrary,
  refreshSigmaLibrary,
  sigmaAsset,
  sigmaAutoRefresh,
  sigmaCompatibility,
} from '../services/sigma/sigmaStore';
import {
  installSigmaRule,
  updateSigmaRule,
  SigmaInstallError,
  MAX_BULK_INSTALL,
} from '../services/sigma/sigmaInstall';
import type { CompatResult } from '../services/sigma/sigmaCompat';

const router = Router();

// app.ts mounts this router behind `authenticate`: browsing is open to every
// role. Adding or updating rules needs analyst or higher, as every other
// detection write does (refusals are written to audit_logs). Refresh is open
// to viewers too, but only analyst and up fetch from GitHub; a viewer's call
// answers with the cache, as GET /api/rules/catalog?refresh=true does.
const requireRuleWrite = requireScanPermission(UserRole.Analyst, 'detection_rule');

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const LEVELS = ['informational', 'low', 'medium', 'high', 'critical'];

function sigmaIdParam(req: Request): string {
  const id = String(req.params.sigmaId ?? '').toLowerCase();
  if (!UUID_RE.test(id)) throw new ApiError(400, 'sigmaId must be a Sigma rule id (UUID)');
  return id;
}

function str(v: unknown, max = 200): string {
  return typeof v === 'string' ? v.trim().slice(0, max) : '';
}

function sendInstallError(res: Response, error: unknown): boolean {
  if (!(error instanceof SigmaInstallError)) return false;
  res.status(error.status).json({ code: error.code, message: error.message, ...error.extra });
  return true;
}

interface Installed {
  rule_ids: number[];
  enabled: number;
  update_available: boolean;
}

function installedBySigmaId(rules: DetectionRule[], lib: Map<string, SigmaLibraryRule>): Map<string, Installed> {
  const out = new Map<string, Installed>();
  for (const r of rules) {
    if (!r.sigma_id) continue;
    const i = out.get(r.sigma_id) ?? { rule_ids: [], enabled: 0, update_available: false };
    i.rule_ids.push(r.id);
    if (r.enabled) i.enabled++;
    const entry = lib.get(r.sigma_id);
    if (entry && entry.convertible && entry.content_hash !== r.sigma_hash) i.update_available = true;
    out.set(r.sigma_id, i);
  }
  return out;
}

function regexSummary(entry: SigmaLibraryRule): RegexSafetySummary {
  return peekRegexSafety(entry.parts.flatMap((p, i) => collectRuleRegexes(p).map((ref) => ({ ...ref, location: `part ${i + 1} ${ref.location}` }))));
}

function rowFor(entry: SigmaLibraryRule, tag: string, compat: CompatResult | undefined, installed: Installed | undefined, withSafety: boolean) {
  const attack = sigmaAttack(entry);
  const regex_safety = withSafety && entry.convertible ? regexSummary(entry) : undefined;
  let not_installable: string | null = null;
  if (!entry.convertible) not_installable = entry.errors.join('; ') || 'does not convert';
  else if (regex_safety?.status === 'vulnerable') {
    not_installable = `a converted regex is vulnerable to catastrophic backtracking (${regex_safety.vulnerable.map((f) => f.location).join(', ')})`;
  }
  return {
    sigma_id: entry.sigma_id,
    title: entry.title,
    description: entry.description,
    level: entry.level,
    status: entry.status,
    logsource: { product: entry.product, category: entry.category, service: entry.service },
    tags: entry.tags,
    attack,
    author: entry.author,
    date: entry.rule_date,
    modified: entry.modified,
    references: entry.refs,
    url: sigmaRuleUrl(tag, entry.path),
    path: entry.path,
    convertible: entry.convertible,
    errors: entry.errors,
    warnings: entry.warnings,
    parts: entry.parts.length,
    fields: entry.fields,
    compatibility: compat
      ? {
          compatible: compat.compatible,
          keyword: compat.keyword,
          parsers: compat.parsers,
          missing_field: compat.missing_field ?? null,
          logsource_mismatch: compat.logsource_mismatch ?? null,
        }
      : null,
    installed: installed ?? null,
    regex_safety,
    installable: not_installable === null,
    not_installable_reason: not_installable,
  };
}

/** Distinct values with counts, most common first. */
function facet(values: Array<string | null | undefined>): Array<{ value: string; count: number }> {
  const m = new Map<string, number>();
  for (const v of values) if (v) m.set(v, (m.get(v) ?? 0) + 1);
  return [...m.entries()].map(([value, count]) => ({ value, count })).sort((a, b) => b.count - a.count || a.value.localeCompare(b.value));
}

// Browse the library: GET /api/sigma/library?view=compatible|convertible|not_convertible
//   &q=&product=&category=&service=&level=&status=&tactic=&technique=&installed=added|updates|not_added
//   &page=1&page_size=50
router.get('/library', async (req: Request, res: Response) => {
  try {
    const [state, lib] = await Promise.all([getSigmaState(), loadSigmaLibrary()]);
    const view = ['compatible', 'convertible', 'not_convertible'].includes(String(req.query.view)) ? String(req.query.view) : 'compatible';
    const compat = lib.rules.length > 0 ? await sigmaCompatibility({ refresh: req.query.recheck === 'true' }) : null;
    const installed = installedBySigmaId(await DetectionRuleModel.findAll(), lib.byId);
    const tag = lib.tag ?? 'master';

    const q = str(req.query.q).toLowerCase();
    const product = str(req.query.product).toLowerCase();
    const category = str(req.query.category).toLowerCase();
    const service = str(req.query.service).toLowerCase();
    const level = str(req.query.level).toLowerCase();
    const status = str(req.query.status).toLowerCase();
    const tactic = str(req.query.tactic).toLowerCase().replace(/_/g, '-');
    const technique = str(req.query.technique).toUpperCase();
    const installedFilter = str(req.query.installed);

    const listed = lib.rules.filter((r) => r.status !== 'deprecated' && r.status !== 'unsupported');
    const inView = listed.filter((r) => {
      if (view === 'not_convertible') return !r.convertible;
      if (!r.convertible) return false;
      return view === 'convertible' || compat?.results.get(r.sigma_id)?.compatible === true;
    });
    const filtered = inView.filter((r) => {
      if (product && r.product !== product) return false;
      if (category && r.category !== category) return false;
      if (service && r.service !== service) return false;
      if (level && r.level !== level) return false;
      if (status && r.status !== status) return false;
      if (tactic || technique) {
        const a = sigmaAttack(r);
        if (tactic && !a.tactics.includes(tactic)) return false;
        if (technique && !a.techniques.some((t) => t === technique || t.startsWith(`${technique}.`))) return false;
      }
      if (installedFilter === 'added' && !installed.has(r.sigma_id)) return false;
      if (installedFilter === 'not_added' && installed.has(r.sigma_id)) return false;
      if (installedFilter === 'updates' && !installed.get(r.sigma_id)?.update_available) return false;
      if (q) {
        const hay = `${r.title}\n${r.description ?? ''}\n${r.sigma_id}\n${r.tags.join(' ')}\n${r.author ?? ''}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
    // Highest level first, then title.
    const rank = (l: string | null) => -LEVELS.indexOf(l ?? '');
    filtered.sort((a, b) => rank(a.level) - rank(b.level) || a.title.localeCompare(b.title));

    const pageSize = Math.min(100, Math.max(1, parseInt(String(req.query.page_size ?? '50'), 10) || 50));
    const page = Math.max(1, parseInt(String(req.query.page ?? '1'), 10) || 1);
    const slice = filtered.slice((page - 1) * pageSize, page * pageSize);

    const convertible = listed.filter((r) => r.convertible);
    res.json({
      source: {
        repo: 'SigmaHQ/sigma',
        asset: sigmaAsset(),
        auto_refresh: sigmaAutoRefresh(),
        license: 'Detection Rule License (DRL) 1.1',
        license_url: 'https://github.com/SigmaHQ/Detection-Rule-License',
      },
      state,
      counts: {
        rules: listed.length,
        convertible: convertible.length,
        not_convertible: listed.length - convertible.length,
        compatible: compat ? convertible.filter((r) => compat.results.get(r.sigma_id)?.compatible).length : 0,
        added: installed.size,
        updates: [...installed.values()].filter((i) => i.update_available).length,
      },
      compatibility: compat
        ? { computed_at: compat.computed_at, sampled_parsers: compat.sampled_parsers, dry_run_error: compat.dry_run_error ?? null }
        : null,
      facets: {
        products: facet(inView.map((r) => r.product)),
        categories: facet(inView.map((r) => r.category)),
        services: facet(inView.map((r) => r.service)),
        levels: facet(inView.map((r) => r.level)),
        statuses: facet(inView.map((r) => r.status)),
        tactics: facet(inView.flatMap((r) => sigmaAttack(r).tactics)),
      },
      view,
      page,
      page_size: pageSize,
      total: filtered.length,
      rules: slice.map((r) => rowFor(r, tag, compat?.results.get(r.sigma_id), installed.get(r.sigma_id), true)),
    });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, `Failed to load the SigmaHQ library: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
});

// Fetch the latest SigmaHQ release (analyst and up). A viewer's call changes
// nothing and answers with the cached state.
router.post('/library/refresh', async (req: Request, res: Response) => {
  if (!hasRequiredRole(req.user?.role ?? '', UserRole.Analyst)) {
    res.json({ refreshed: false, reason: 'Only analysts and above can refresh the SigmaHQ library', state: await getSigmaState() });
    return;
  }
  try {
    const result = await refreshSigmaLibrary({ force: req.body?.force === true });
    res.json({ refreshed: true, ...result, state: await getSigmaState() });
  } catch (error) {
    res.status(502).json({
      code: 'SIGMAHQ_UNREACHABLE',
      message: `Could not refresh the SigmaHQ library (the cached copy is kept): ${error instanceof Error ? error.message : 'unknown error'}`,
      state: await getSigmaState(),
    });
  }
});

// Add every part of one Sigma rule, disabled.
router.post('/library/:sigmaId/install', requireRuleWrite, async (req: Request, res: Response) => {
  const sigmaId = sigmaIdParam(req);
  try {
    const result = await installSigmaRule(sigmaId);
    await RulesEngine.getInstance().reload();
    res.status(201).json(result);
  } catch (error) {
    if (sendInstallError(res, error)) return;
    throw new ApiError(500, `Failed to add the Sigma rule: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
});

// Update an added Sigma rule to the cached release (keeps enabled and ids).
router.post('/library/:sigmaId/update', requireRuleWrite, async (req: Request, res: Response) => {
  const sigmaId = sigmaIdParam(req);
  try {
    const result = await updateSigmaRule(sigmaId);
    await RulesEngine.getInstance().reload();
    res.json(result);
  } catch (error) {
    if (sendInstallError(res, error)) return;
    throw new ApiError(500, `Failed to update the Sigma rule: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
});

// Add several rules: { sigma_ids: [...] } or { all_compatible: true }. Rules
// already added are skipped; a refused one is reported in `failed`.
router.post('/library/install-bulk', requireRuleWrite, async (req: Request, res: Response) => {
  let ids: string[];
  if (req.body?.all_compatible === true) {
    const lib = await loadSigmaLibrary();
    const compat = await sigmaCompatibility();
    ids = lib.rules.filter((r) => r.convertible && compat.results.get(r.sigma_id)?.compatible).map((r) => r.sigma_id);
  } else if (Array.isArray(req.body?.sigma_ids)) {
    ids = [...new Set((req.body.sigma_ids as unknown[]).map((v) => String(v).toLowerCase()))];
    if (ids.some((id) => !UUID_RE.test(id))) throw new ApiError(400, 'sigma_ids must be Sigma rule ids (UUIDs)');
  } else {
    throw new ApiError(400, 'Send sigma_ids (a list of Sigma rule ids) or all_compatible: true');
  }
  if (ids.length > MAX_BULK_INSTALL) throw new ApiError(400, `At most ${MAX_BULK_INSTALL} rules per call`);

  const results = {
    total: ids.length,
    added: 0,
    rules_created: 0,
    skipped: [] as string[],
    failed: [] as Array<{ sigma_id: string; reason: string; code: string }>,
  };
  for (const id of ids) {
    try {
      const r = await installSigmaRule(id);
      results.added++;
      results.rules_created += r.rules.length;
    } catch (error) {
      if (error instanceof SigmaInstallError && error.code === 'SIGMA_ALREADY_ADDED') results.skipped.push(id);
      else if (error instanceof SigmaInstallError) results.failed.push({ sigma_id: id, reason: error.message, code: error.code });
      else results.failed.push({ sigma_id: id, reason: error instanceof Error ? error.message : 'install error', code: 'ERROR' });
    }
  }
  if (results.added > 0) await RulesEngine.getInstance().reload();
  res.json(results);
});

export default router;
