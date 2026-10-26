import { Router, Request, Response } from 'express';
import { ApiError } from '../middleware/errorHandler';
import { authorize } from '../middleware/auth';
import { requireScanPermission, UserRole } from '../middleware/scanPermissions';
import { query } from '../config/database';
import {
  getApplication,
  listApplications,
  listApplicationVulnerabilities,
  listUnmatchedWithCounts,
  readInventoryStatus,
  type ListFilters,
} from '../services/applications/inventory';
import { describeInventoryRun, loadStoredSignatures } from '../services/applications/rollup';
import { kickApplicationInventory, runApplicationInventoryNow } from '../jobs/applicationInventory';
import { fetchAppCatalog, gateSignatureRegexes, getApplicationSource } from '../services/applications/appCatalog';
import { collectAppRegexes, validateApplication, type AppSignature } from '../services/applications/appFormat';
import {
  catalogPath,
  catalogStatus,
  checkSignature,
  countCustomSignatures,
  deleteCustomSignature,
  getCustomSignature,
  ignoreUnmatched,
  insertCustomSignature,
  listCustomSignatures,
  loadCustomSignatures,
  MAX_LOCAL_SIGNATURES,
  mergeSignatures,
  readSignatureInput,
  requestRescan,
  signatureToYaml,
  unignoreUnmatched,
  updateCustomSignature,
  type SignatureCheck,
} from '../services/applications/customSignatures';
import { testSignatureAgainstEvidence } from '../services/applications/evidenceTest';
import { AI_DRAFT_MAX_ITEMS, draftSignatureWithAi, type DraftItem } from '../services/applications/aiDraft';
import { isUnmatchedKind } from '../services/applications/gaps';
import { assessRegexes } from '../services/regex/regexSafety';
import { sendRegexRunError } from '../services/regex/regexHttp';
import { callProvider, getAiConfig, getAiPublicConfig } from '../services/ai/aiService';
import { getAiBudgets } from '../services/ai/aiBudgets';
import { catalogNewFileUrl } from '../services/parser/catalogService';

const router = Router();

// Reads are open to every role (app.ts mounts this router behind
// `authenticate`). Writing local signatures, ignoring Not identified values,
// and the editor's checks (they run a regex the caller wrote) are analyst and
// up, as the parser routes are; a refusal is written to audit_logs. The AI
// draft is admin-only, as the parser and detection builders are.
const requireSignatureWrite = requireScanPermission(UserRole.Analyst, 'application_signature');
const ID_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;

const str = (v: unknown): string | undefined => (typeof v === 'string' && v.length > 0 ? v.slice(0, 255) : undefined);
const VIEWS = new Set(['all', 'drift', 'vulnerable', 'unmanaged']);

// Application Monitoring page: the inventory (every role; read-only).
// ?category= &source= &host= &search= &view=all|drift|vulnerable|unmanaged
router.get('/', async (req: Request, res: Response) => {
  const view = str(req.query.view);
  const filters: ListFilters = {
    category: str(req.query.category),
    source: str(req.query.source),
    host: str(req.query.host),
    search: str(req.query.search),
    view: view && VIEWS.has(view) ? (view as ListFilters['view']) : 'all',
  };
  try {
    const [applications, status] = await Promise.all([listApplications(filters), readInventoryStatus()]);
    res.json({ applications, status });
  } catch (error) {
    throw new ApiError(500, `Failed to list applications: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
});

// Values no signature matched (log programs, parsers, container images,
// installed packages, nmap services, user-agent products, DNS domains), each
// with a draft signature and a link that opens it pre-filled in the catalog.
// ?source= &search= &limit= (per kind) &noise=true (system packages, CDN
// domains, generic services) &ignored=true
router.get('/unmatched', async (req: Request, res: Response) => {
  const limit = Number.parseInt(String(req.query.limit ?? ''), 10);
  res.json(
    await listUnmatchedWithCounts(str(req.query.source), Number.isFinite(limit) ? limit : undefined, {
      search: str(req.query.search),
      noise: req.query.noise === 'true',
      ignored: req.query.ignored === 'true',
    })
  );
});

function unmatchedKey(body: unknown): { source: string; value: string } {
  const b = (body ?? {}) as Record<string, unknown>;
  if (!isUnmatchedKind(b.source)) throw new ApiError(400, 'source must be a Not identified kind');
  if (typeof b.value !== 'string' || b.value.length === 0 || b.value.length > 200) throw new ApiError(400, 'value must be a string of 1 to 200 characters');
  return { source: b.source, value: b.value };
}

// "Not an application": hide a value from the Not identified list (analyst and up).
router.post('/unmatched/ignore', requireSignatureWrite, async (req: Request, res: Response) => {
  const { source, value } = unmatchedKey(req.body);
  await ignoreUnmatched(source, value, req.user?.username ?? null);
  res.json({ ignored: true, source, value });
});

router.post('/unmatched/unignore', requireSignatureWrite, async (req: Request, res: Response) => {
  const { source, value } = unmatchedKey(req.body);
  res.json({ ignored: false, removed: await unignoreUnmatched(source, value), source, value });
});

// ---------------------------------------------------------------------------
// Local signatures
// ---------------------------------------------------------------------------

interface SignatureSet {
  catalogApps: AppSignature[];
  catalogSource: string;
  local: AppSignature[];
  effective: AppSignature[];
  skip: Set<string>;
  parserNames: Set<string>;
}

/** The set in use now (catalog with its fallbacks, plus the enabled local signatures). */
async function signatureSet(): Promise<SignatureSet> {
  const catalog = await fetchAppCatalog({ loadStored: () => loadStoredSignatures((sql, p) => query(sql, p)) });
  const local = (await loadCustomSignatures()).apps;
  const effective = mergeSignatures(catalog.apps, local).apps;
  const gate = await gateSignatureRegexes(effective);
  const parserNames = new Set<string>((await query(`SELECT name FROM parsers`)).rows.map((r) => r.name));
  return { catalogApps: catalog.apps, catalogSource: catalog.source, local, effective, skip: gate.skip, parserNames };
}

/**
 * The save's checks for a signature document, with its regexes through the
 * write-time gate first (answers 503 itself when the checker is saturated,
 * and returns null).
 */
async function checkDoc(res: Response, doc: unknown, set: SignatureSet, expectId?: string): Promise<(SignatureCheck & { regex_refused: boolean }) | null> {
  const loose = validateApplication(doc, { strict: false, expectId });
  let regex = null;
  if (loose.ok && loose.app) {
    const refs = collectAppRegexes(loose.app);
    if (refs.length) {
      try {
        regex = await assessRegexes(refs, { priority: 'high' });
      } catch (error) {
        if (sendRegexRunError(res, error)) return null;
        throw error;
      }
    }
  }
  const check = checkSignature(doc, { effective: set.effective, parserNames: set.parserNames, regex, expectId, skipRegex: set.skip });
  return { ...check, regex_refused: !!regex && (regex.vulnerable.length > 0 || regex.undecided.length > 0) };
}

function catalogInfo(set: SignatureSet, app: AppSignature | null) {
  if (!app) return { exists: false, status: null };
  const inCatalog = set.catalogApps.find((a) => a.id === app.id);
  return { exists: !!inCatalog, status: catalogStatus(app, inCatalog), source: set.catalogSource };
}

function readInput(body: unknown): { doc: unknown; text?: string } {
  const input = readSignatureInput(body);
  if (input.error) throw new ApiError(400, input.error);
  return { doc: input.doc, text: input.text };
}

/** Apply a saved change at once: queue the look back and start a rollup run (a running one leaves it to the next). */
async function applySaved(ids: string[]): Promise<void> {
  await requestRescan(ids);
  kickApplicationInventory();
}

// Local signatures with their catalog status, and whether the AI draft is available.
router.get('/signatures', async (_req: Request, res: Response) => {
  const [rows, set, ai, state] = await Promise.all([
    listCustomSignatures(),
    signatureSet(),
    getAiPublicConfig().catch(() => null),
    query(`SELECT rescan_apps, rescan_pending, rescan_next, rescan_from, rescan_total, rescan_started_at FROM application_inventory_state WHERE id = 1`),
  ]);
  const st = state.rows[0] ?? {};
  const signatures = rows.map((r) => {
    const v = validateApplication(r.definition, { strict: false, expectId: r.id });
    const inCatalog = set.catalogApps.find((a) => a.id === r.id);
    return {
      id: r.id,
      name: r.definition.name,
      vendor: r.definition.vendor,
      category: r.definition.category,
      enabled: r.enabled,
      origin: inCatalog ? 'override' : 'local',
      catalog_status: v.app ? catalogStatus(v.app, inCatalog) : inCatalog ? 'differs' : 'not_in_catalog',
      valid: v.ok,
      errors: v.errors,
      created_by: r.created_by,
      updated_by: r.updated_by,
      created_at: r.created_at,
      updated_at: r.updated_at,
    };
  });
  const remaining = st.rescan_next !== null && st.rescan_next !== undefined && st.rescan_from !== null ? Math.max(0, Number(st.rescan_next) - Number(st.rescan_from)) : 0;
  res.json({
    signatures,
    catalog: { count: set.catalogApps.length, source: set.catalogSource, repo: getApplicationSource().repo },
    ai_available: !!ai?.configured,
    rescan: {
      apps: st.rescan_apps ?? [],
      pending: st.rescan_pending ?? [],
      progress: st.rescan_total ? Math.min(1, 1 - remaining / Number(st.rescan_total)) : null,
      started_at: st.rescan_started_at ?? null,
    },
  });
});

// Check a signature as the editor has it (not saved): the save's checks, the
// catalog's stricter ones, the canonical YAML, and whether the id is a catalog one.
router.post('/signatures/validate', requireSignatureWrite, async (req: Request, res: Response) => {
  const { doc } = readInput(req.body);
  const expectId = typeof req.body?.id === 'string' && ID_RE.test(req.body.id) ? req.body.id : undefined;
  const set = await signatureSet();
  const check = await checkDoc(res, doc, set, expectId);
  if (!check) return;
  res.json({ ...check, catalog: catalogInfo(set, check.signature) });
});

// "Test": what the signature would identify in the evidence SIEMBox has now.
router.post('/signatures/test', requireSignatureWrite, async (req: Request, res: Response) => {
  const { doc } = readInput(req.body);
  const set = await signatureSet();
  const check = await checkDoc(res, doc, set);
  if (!check) return;
  if (!check.signature) {
    res.status(422).json({ message: 'The signature is not valid yet.', ...check });
    return;
  }
  if (check.regex_refused) {
    res.status(422).json({ message: 'A regex was refused by the safety check; fix it before testing.', ...check });
    return;
  }
  const result = await testSignatureAgainstEvidence(check.signature, set.effective, set.skip);
  res.json({ check, result });
});

// Draft a signature for Not identified values with the AI Builder's model (admin).
router.post('/signatures/ai-draft', authorize('admin'), async (req: Request, res: Response) => {
  const raw = Array.isArray(req.body?.items) ? req.body.items : [];
  const items: DraftItem[] = raw
    .slice(0, AI_DRAFT_MAX_ITEMS)
    .filter((i: any) => i && typeof i.value === 'string' && i.value.length > 0 && typeof i.source === 'string')
    .map((i: any) => ({
      source: String(i.source).slice(0, 32),
      value: String(i.value).slice(0, 300),
      sample: typeof i.sample === 'string' ? i.sample.slice(0, 1024) : null,
      detail: i.detail && typeof i.detail === 'object' && !Array.isArray(i.detail) ? i.detail : null,
    }));
  if (items.length === 0) throw new ApiError(400, 'items: one or more { source, value, sample?, detail? } is required');
  const pub = await getAiPublicConfig();
  if (!pub.configured) throw new ApiError(409, 'No AI provider is configured (Settings -> AI).');
  const hints = typeof req.body?.hints === 'string' ? req.body.hints.slice(0, 1000) : undefined;
  const set = await signatureSet();
  const { builder } = await getAiBudgets();
  let gateBusy = false;
  const result = await draftSignatureWithAi(
    { items, hints, maxTokens: builder.maxTokens },
    {
      cfg: await getAiConfig(),
      complete: callProvider,
      check: async (doc) => {
        const loose = validateApplication(doc, { strict: false });
        let regex = null;
        if (loose.ok && loose.app && collectAppRegexes(loose.app).length) {
          try {
            regex = await assessRegexes(collectAppRegexes(loose.app), { priority: 'high' });
          } catch {
            gateBusy = true;
          }
        }
        return checkSignature(doc, { effective: set.effective, parserNames: set.parserNames, regex, skipRegex: set.skip });
      },
    }
  );
  res.json({ ...result, ...(gateBusy ? { warning: 'The regex checker was busy; check the draft again before saving.' } : {}) });
});

// One signature: a local one (with its YAML) or, read-only, a catalog one (to copy or override).
router.get('/signatures/:id', async (req: Request, res: Response) => {
  const id = String(req.params.id);
  if (!ID_RE.test(id)) throw new ApiError(404, 'Signature not found');
  const row = await getCustomSignature(id);
  const set = await signatureSet();
  const inCatalog = set.catalogApps.find((a) => a.id === id);
  if (row) {
    const v = validateApplication(row.definition, { strict: false, expectId: id });
    res.json({
      ...row,
      origin: inCatalog ? 'override' : 'local',
      catalog_status: v.app ? catalogStatus(v.app, inCatalog) : 'differs',
      catalog_yaml: inCatalog ? signatureToYaml(inCatalog) : null,
    });
    return;
  }
  if (!inCatalog) throw new ApiError(404, 'Signature not found');
  res.json({ id, origin: 'catalog', definition: inCatalog, yaml: signatureToYaml(inCatalog), enabled: true, catalog_status: 'same', catalog_yaml: signatureToYaml(inCatalog) });
});

// Save a new local signature. It takes effect at once (the next rollup run, started now).
router.post('/signatures', requireSignatureWrite, async (req: Request, res: Response) => {
  const { doc, text } = readInput(req.body);
  if ((await countCustomSignatures()) >= MAX_LOCAL_SIGNATURES) throw new ApiError(409, `At most ${MAX_LOCAL_SIGNATURES} local signatures`);
  const set = await signatureSet();
  const check = await checkDoc(res, doc, set);
  if (!check) return;
  if (!check.ok || !check.signature) {
    res.status(422).json({ message: `The signature was not saved: ${check.errors.slice(0, 5).join('; ')}`, ...check });
    return;
  }
  const saved = await insertCustomSignature(check.signature, text ?? check.yaml ?? '', req.user?.username ?? null);
  if (!saved) throw new ApiError(409, `A local signature "${check.signature.id}" already exists; edit it instead`);
  await applySaved([saved.id]);
  res.status(201).json({ signature: saved, check, catalog: catalogInfo(set, check.signature) });
});

// Change a local signature (its content, or enabled). The id cannot change.
router.put('/signatures/:id', requireSignatureWrite, async (req: Request, res: Response) => {
  const id = String(req.params.id);
  if (!ID_RE.test(id)) throw new ApiError(404, 'Signature not found');
  const existing = await getCustomSignature(id);
  if (!existing) throw new ApiError(404, 'Signature not found');
  const enabled = typeof req.body?.enabled === 'boolean' ? req.body.enabled : undefined;
  const hasContent = typeof req.body?.yaml === 'string' || (req.body?.signature && typeof req.body.signature === 'object');
  if (!hasContent && enabled === undefined) throw new ApiError(400, 'send yaml or signature, and/or enabled');
  let check: SignatureCheck | null = null;
  let text: string | undefined;
  if (hasContent) {
    const input = readInput(req.body);
    text = input.text;
    const set = await signatureSet();
    check = await checkDoc(res, input.doc, set, id);
    if (!check) return;
    if (!check.ok || !check.signature) {
      res.status(422).json({ message: `The signature was not saved: ${check.errors.slice(0, 5).join('; ')}`, ...check });
      return;
    }
  }
  const saved = await updateCustomSignature(id, { app: check?.signature ?? undefined, text: hasContent ? (text ?? check?.yaml ?? undefined) : undefined, enabled }, req.user?.username ?? null);
  if (!saved) throw new ApiError(404, 'Signature not found');
  await applySaved([id]);
  res.json({ signature: saved, check });
});

router.delete('/signatures/:id', requireSignatureWrite, async (req: Request, res: Response) => {
  const id = String(req.params.id);
  if (!ID_RE.test(id)) throw new ApiError(404, 'Signature not found');
  const set = await signatureSet();
  const removed = await deleteCustomSignature(id, set.catalogApps.some((a) => a.id === id));
  if (!removed) throw new ApiError(404, 'Signature not found');
  kickApplicationInventory();
  res.json({ deleted: true, id });
});

// Prepare a catalog contribution for a local signature: the catalog CI's
// strict checks, the regex gate, the tests against the set, and (only when it
// would pass) GitHub's pre-filled "propose new file" URL the author finishes
// in their own browser. SIEMBox never opens the PR or holds a credential.
router.get('/signatures/:id/contribute', async (req: Request, res: Response) => {
  const id = String(req.params.id);
  if (!ID_RE.test(id)) throw new ApiError(404, 'Signature not found');
  const row = await getCustomSignature(id);
  if (!row) throw new ApiError(404, 'Signature not found');
  const set = await signatureSet();
  const check = await checkDoc(res, row.definition, set, id);
  if (!check) return;
  const inCatalog = set.catalogApps.find((a) => a.id === id);
  const status = check.signature ? catalogStatus(check.signature, inCatalog) : null;
  const warnings = [...check.warnings];
  if (inCatalog) {
    warnings.unshift(
      status === 'same'
        ? `The catalog already has "${id}" with this content: nothing to contribute (you can delete the local copy).`
        : `The catalog already has "${id}": this proposes a change to it, so say why in the pull request.`
    );
  }
  const filePath = catalogPath(id, getApplicationSource().path);
  const content = check.yaml ?? row.yaml;
  const ready = check.ready && status !== 'same';
  res.json({
    kind: 'application',
    id,
    path: filePath,
    content,
    valid: check.ok,
    errors: [...check.errors, ...check.contribute_errors],
    warnings,
    tests: check.tests,
    exists_in_catalog: !!inCatalog,
    catalog_status: status,
    ready,
    contribute_url: ready ? catalogNewFileUrl(filePath, content) : null,
  });
});

// Open vulnerabilities linked to applications (?app= &severity=).
router.get('/vulnerabilities', async (req: Request, res: Response) => {
  res.json({ vulnerabilities: await listApplicationVulnerabilities({ app: str(req.query.app), severity: str(req.query.severity) }) });
});

// Re-read the catalog and run the rollup now (analyst and up).
router.post('/refresh', authorize('admin', 'operator', 'analyst'), async (_req: Request, res: Response) => {
  const result = await runApplicationInventoryNow();
  if (result === 'busy') {
    res.status(409).json({ message: 'The inventory is already being built; try again in a moment.' });
    return;
  }
  res.json({ summary: result ? describeInventoryRun(result) : 'switched off in Settings -> Application Monitoring', result, status: await readInventoryStatus() });
});

// One application: where it runs, versions, evidence samples, vulnerabilities.
router.get('/:id', async (req: Request, res: Response) => {
  const id = String(req.params.id);
  if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(id)) throw new ApiError(404, 'Application not found');
  const app = await getApplication(id);
  if (!app) throw new ApiError(404, 'Application not found');
  res.json(app);
});

export default router;
