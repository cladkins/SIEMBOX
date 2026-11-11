/**
 * Threat Hunting API (/api/hunts). See docs/threat-hunting.md.
 *
 * Every signed-in role reads hunts, sources and STIX exports. Analysts and up
 * create, edit, run and delete hunts and sources. Admins manage the TAXII
 * client tokens. The TAXII 2.1 collection itself is routes/taxii.ts.
 */
import { Router, Request, Response } from 'express';
import { ApiError } from '../middleware/errorHandler';
import { authorize } from '../middleware/auth';
import { AuditService } from '../services/audit/auditService';
import {
  addHypothesis,
  addIndicator,
  clampLookback,
  createHunt,
  deleteHunt,
  deleteHypothesis,
  getHuntDetail,
  huntStixBundle,
  HuntError,
  huntSummary,
  importStixHunt,
  listHunts,
  queueRun,
  reextractHunt,
  setIndicatorEnabled,
  updateHunt,
  updateHypothesis,
} from '../services/hunting/huntService';
import { checkSource, createSource, deleteSource, listSources, updateSource } from '../services/hunting/sourceMonitor';
import { urlRejection } from '../services/hunting/fetchSource';
import { StixImportError, STIX_MEDIA_TYPE } from '../services/hunting/stix';
import { TaxiiTokenModel } from '../services/hunting/taxiiTokens';
import { HUNTS_COLLECTION_ID } from './taxii';

const router = Router();
const analystUp = authorize('admin', 'operator', 'analyst');

const MIN_TEXT = 20;
const MAX_TEXT = 1_000_000;
const HUNT_STATUSES = ['pending', 'extracting', 'ready', 'running', 'completed', 'failed'];

function intParam(raw: unknown, what: string): number {
  const n = parseInt(String(raw ?? ''), 10);
  if (Number.isNaN(n) || n < 1) throw new ApiError(400, `Invalid ${what}`);
  return n;
}

/** Map service errors to API errors. */
async function handle<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof HuntError) throw new ApiError(err.status, err.message);
    if (err instanceof StixImportError) throw new ApiError(400, err.message);
    throw err;
  }
}

// ---- Overview -----------------------------------------------------------------------

router.get('/summary', async (_req: Request, res: Response) => {
  res.json(await huntSummary());
});

router.get('/', async (req: Request, res: Response) => {
  const limit = Math.min(Math.max(parseInt(String(req.query.limit ?? '50'), 10) || 50, 1), 200);
  const offset = Math.max(parseInt(String(req.query.offset ?? '0'), 10) || 0, 0);
  const status = typeof req.query.status === 'string' && HUNT_STATUSES.includes(req.query.status) ? req.query.status : undefined;
  const sourceId = req.query.source_id ? intParam(req.query.source_id, 'source_id') : undefined;
  const search = typeof req.query.search === 'string' && req.query.search.trim() ? req.query.search.trim().slice(0, 200) : undefined;
  res.json(await listHunts({ limit, offset, status, sourceId, search }));
});

/** Start a hunt from a URL or from pasted text. */
router.post('/', analystUp, async (req: Request, res: Response) => {
  const url = typeof req.body?.url === 'string' ? req.body.url.trim() : '';
  const text = typeof req.body?.text === 'string' ? req.body.text : '';
  if (!url && !text.trim()) throw new ApiError(400, 'Send a url or the report text.');
  if (url) {
    const why = urlRejection(url);
    if (why) throw new ApiError(400, why);
  } else if (text.trim().length < MIN_TEXT || text.length > MAX_TEXT) {
    throw new ApiError(400, `The text must be ${MIN_TEXT} to ${MAX_TEXT} characters.`);
  }
  const hunt = await handle(() =>
    createHunt({
      origin: url ? 'url' : 'text',
      url: url || null,
      text: url ? null : text,
      title: typeof req.body?.title === 'string' && req.body.title.trim() ? req.body.title.trim() : null,
      lookbackDays: clampLookback(req.body?.lookback_days),
      alertOnMatch: req.body?.alert_on_match === true,
      useAi: req.body?.use_ai !== false,
      createdBy: req.user?.id ?? null,
    })
  );
  res.status(202).json(hunt);
});

/** Start a hunt from a STIX 2.x bundle (the JSON body, or { bundle, lookback_days, ... }). */
router.post('/import', analystUp, async (req: Request, res: Response) => {
  const body = req.body ?? {};
  const bundle = body.bundle ?? body;
  const hunt = await handle(() =>
    importStixHunt(bundle, {
      lookbackDays: clampLookback(body.lookback_days),
      alertOnMatch: body.alert_on_match === true,
      createdBy: req.user?.id ?? null,
      run: body.run !== false,
    })
  );
  res.status(201).json(hunt);
});

// ---- Monitored sources ------------------------------------------------------------------

router.get('/sources', async (_req: Request, res: Response) => {
  res.json({ sources: await listSources() });
});

router.post('/sources', analystUp, async (req: Request, res: Response) => {
  const source = await handle(() => createSource(req.body ?? {}, req.user?.id ?? null));
  res.status(201).json(source);
});

router.put('/sources/:id', analystUp, async (req: Request, res: Response) => {
  const id = intParam(req.params.id, 'source id');
  const source = await handle(() => updateSource(id, req.body ?? {}));
  if (!source) throw new ApiError(404, 'Source not found');
  res.json(source);
});

router.delete('/sources/:id', analystUp, async (req: Request, res: Response) => {
  const id = intParam(req.params.id, 'source id');
  if (!(await deleteSource(id))) throw new ApiError(404, 'Source not found');
  res.json({ deleted: true });
});

router.post('/sources/:id/check', analystUp, async (req: Request, res: Response) => {
  const id = intParam(req.params.id, 'source id');
  const result = await checkSource(id);
  if (!result.ok && result.error === 'Source not found') throw new ApiError(404, 'Source not found');
  res.json(result);
});

// ---- TAXII client tokens (admin) -----------------------------------------------------------

router.get('/taxii-tokens', authorize('admin'), async (_req: Request, res: Response) => {
  res.json({ tokens: await TaxiiTokenModel.list(), collection_id: HUNTS_COLLECTION_ID });
});

router.post('/taxii-tokens', authorize('admin'), async (req: Request, res: Response) => {
  const name = typeof req.body?.name === 'string' ? req.body.name.trim().slice(0, 100) : '';
  if (!name) throw new ApiError(400, 'name is required');
  const { token, row } = await TaxiiTokenModel.create(name, req.user?.id ?? null);
  await AuditService.log({
    userId: req.user?.id ?? null,
    action: 'taxii_token.create',
    resourceType: 'taxii_token',
    resourceId: row.id,
    ipAddress: req.ip ?? null,
    userAgent: req.get('user-agent') ?? null,
    responseStatus: 201,
    details: { name },
  });
  res.status(201).json({ ...row, token });
});

router.delete('/taxii-tokens/:id', authorize('admin'), async (req: Request, res: Response) => {
  const id = intParam(req.params.id, 'token id');
  if (!(await TaxiiTokenModel.revoke(id))) throw new ApiError(404, 'Token not found or already revoked');
  await AuditService.log({
    userId: req.user?.id ?? null,
    action: 'taxii_token.revoke',
    resourceType: 'taxii_token',
    resourceId: id,
    ipAddress: req.ip ?? null,
    userAgent: req.get('user-agent') ?? null,
    responseStatus: 200,
  });
  res.json({ revoked: true });
});

// ---- One hunt -----------------------------------------------------------------------------

router.get('/:id', async (req: Request, res: Response) => {
  const hunt = await getHuntDetail(intParam(req.params.id, 'hunt id'));
  if (!hunt) throw new ApiError(404, 'Hunt not found');
  res.json(hunt);
});

/** The hunt as a STIX 2.1 bundle (download). */
router.get('/:id/stix', async (req: Request, res: Response) => {
  const id = intParam(req.params.id, 'hunt id');
  const bundle = await huntStixBundle(id);
  if (!bundle) throw new ApiError(404, 'Hunt not found');
  res
    .type(STIX_MEDIA_TYPE)
    .set('Content-Disposition', `attachment; filename="siembox-hunt-${id}.stix.json"`)
    .send(JSON.stringify(bundle, null, 2));
});

router.put('/:id', analystUp, async (req: Request, res: Response) => {
  const id = intParam(req.params.id, 'hunt id');
  const hunt = await updateHunt(id, {
    title: req.body?.title,
    lookback_days: req.body?.lookback_days,
    alert_on_match: req.body?.alert_on_match,
  });
  if (!hunt) throw new ApiError(404, 'Hunt not found');
  res.json(hunt);
});

router.delete('/:id', analystUp, async (req: Request, res: Response) => {
  const id = intParam(req.params.id, 'hunt id');
  if (!(await handle(() => deleteHunt(id)))) throw new ApiError(404, 'Hunt not found');
  res.json({ deleted: true });
});

router.post('/:id/run', analystUp, async (req: Request, res: Response) => {
  const id = intParam(req.params.id, 'hunt id');
  await handle(() => queueRun(id));
  res.status(202).json({ queued: true });
});

router.post('/:id/reextract', analystUp, async (req: Request, res: Response) => {
  const id = intParam(req.params.id, 'hunt id');
  await handle(() => reextractHunt(id));
  res.status(202).json({ queued: true });
});

router.post('/:id/indicators', analystUp, async (req: Request, res: Response) => {
  const id = intParam(req.params.id, 'hunt id');
  const indicator = await handle(() =>
    addIndicator(id, String(req.body?.type ?? ''), String(req.body?.value ?? ''), req.body?.context)
  );
  res.status(201).json(indicator);
});

router.put('/:id/indicators/:indicatorId', analystUp, async (req: Request, res: Response) => {
  const id = intParam(req.params.id, 'hunt id');
  const indicatorId = intParam(req.params.indicatorId, 'indicator id');
  if (typeof req.body?.enabled !== 'boolean') throw new ApiError(400, 'enabled (true or false) is required');
  if (!(await setIndicatorEnabled(id, indicatorId, req.body.enabled))) throw new ApiError(404, 'Indicator not found');
  res.json({ id: indicatorId, enabled: req.body.enabled });
});

router.post('/:id/hypotheses', analystUp, async (req: Request, res: Response) => {
  const id = intParam(req.params.id, 'hunt id');
  res.status(201).json(await handle(() => addHypothesis(id, req.body ?? {})));
});

router.put('/:id/hypotheses/:hypothesisId', analystUp, async (req: Request, res: Response) => {
  const id = intParam(req.params.id, 'hunt id');
  const hypothesisId = intParam(req.params.hypothesisId, 'hypothesis id');
  const row = await handle(() => updateHypothesis(id, hypothesisId, req.body ?? {}));
  if (!row) throw new ApiError(404, 'Hypothesis not found');
  res.json(row);
});

router.delete('/:id/hypotheses/:hypothesisId', analystUp, async (req: Request, res: Response) => {
  const id = intParam(req.params.id, 'hunt id');
  const hypothesisId = intParam(req.params.hypothesisId, 'hypothesis id');
  if (!(await deleteHypothesis(id, hypothesisId))) throw new ApiError(404, 'Hypothesis not found');
  res.json({ deleted: true });
});

export default router;
