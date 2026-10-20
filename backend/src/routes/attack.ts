/**
 * MITRE ATT&CK coverage (mounted at /api/attack behind `authenticate`).
 *
 *   GET    /matrix?platforms=             tactics in order, in-scope techniques, dataset version
 *   GET    /coverage?platforms=&refresh=1 per-technique coverage level, reasons, headline numbers
 *   GET    /navigator-layer?platforms=    the coverage as an ATT&CK Navigator layer (4.5)
 *   PUT    /exclusions/:techniqueId       mark a technique not applicable ({ note }) — analyst+
 *   DELETE /exclusions/:techniqueId       undo it — analyst+
 *
 * Reads are open to every role (viewers see coverage read-only). `?refresh=1`
 * recomputes the cached coverage for analyst and up; a viewer's flag is
 * ignored and they get the cached result. Without ?platforms= the scope is the
 * one inferred from the user's data (services/attack/attackCoverage.ts).
 * See docs/reference/API.md ("ATT&CK Coverage Endpoints").
 */
import { Router, type Request, type Response } from 'express';
import { query } from '../config/database';
import { hasRequiredRole, requireScanPermission, UserRole } from '../middleware/scanPermissions';
import { getTechnique, techniqueDisplayName } from '../services/attack/attackData';
import { buildMatrix, buildNavigatorLayer, parsePlatformsParam } from '../services/attack/attackCoverage';
import { getCoverage, getPlatformInference } from '../services/attack/coverageService';
import { invalidateAttackCoverage } from '../services/attack/coverageCache';

const router = Router();
const requireExclusionWrite = requireScanPermission(UserRole.Analyst, 'attack_exclusion');
const MAX_NOTE = 1000;
const TECHNIQUE_ID_RE = /^t\d{4}(?:\.\d{3})?$/i;

function badRequest(res: Response, code: string, message: string): void {
  res.status(400).json({ status: 'error', statusCode: 400, code, message });
}

/** The ?platforms= scope, or null for the inferred one; answers 400 itself (returns undefined). */
function platformsOf(req: Request, res: Response): string[] | null | undefined {
  const parsed = parsePlatformsParam(req.query.platforms);
  if ('error' in parsed) {
    badRequest(res, 'ATTACK_BAD_PLATFORM', parsed.error);
    return undefined;
  }
  return parsed.platforms;
}

function wantsRefresh(req: Request): boolean {
  const flag = req.query.refresh;
  return (flag === '1' || flag === 'true') && hasRequiredRole(req.user?.role ?? '', UserRole.Analyst);
}

/** A live technique ID from the path (canonical), or null after answering 400. */
function techniqueParam(req: Request, res: Response): string | null {
  const raw = String(req.params.techniqueId ?? '');
  if (!TECHNIQUE_ID_RE.test(raw)) {
    badRequest(res, 'ATTACK_UNKNOWN_TECHNIQUE', 'techniqueId must be an ATT&CK technique ID such as T1110 or T1110.001');
    return null;
  }
  const id = raw.toUpperCase();
  const t = getTechnique(id);
  if (!t || t.revoked || t.deprecated) {
    badRequest(
      res,
      'ATTACK_UNKNOWN_TECHNIQUE',
      !t
        ? `${id} is not a technique in the bundled ATT&CK dataset`
        : `${id} "${techniqueDisplayName(id)}" is ${t.revoked ? 'revoked' : 'deprecated'}${t.revokedBy ? `; use ${t.revokedBy}` : ''}`
    );
    return null;
  }
  return id;
}

router.get('/matrix', async (req: Request, res: Response) => {
  const platforms = platformsOf(req, res);
  if (platforms === undefined) return;
  const inferred = platforms ? null : await getPlatformInference();
  const scope = platforms ?? inferred!.platforms;
  res.json({
    ...buildMatrix(scope),
    scope: { platforms: scope, source: platforms ? 'query' : 'inferred', ...(inferred ? { inferred } : {}) },
  });
});

router.get('/coverage', async (req: Request, res: Response) => {
  const platforms = platformsOf(req, res);
  if (platforms === undefined) return;
  res.json(await getCoverage(platforms, wantsRefresh(req)));
});

router.get('/navigator-layer', async (req: Request, res: Response) => {
  const platforms = platformsOf(req, res);
  if (platforms === undefined) return;
  const coverage = await getCoverage(platforms, false);
  const layer = buildNavigatorLayer(coverage, { generatedAt: coverage.computed_at });
  res.setHeader('Content-Disposition', 'attachment; filename="siembox-attack-coverage.json"');
  res.json(layer);
});

router.put('/exclusions/:techniqueId', requireExclusionWrite, async (req: Request, res: Response) => {
  const id = techniqueParam(req, res);
  if (!id) return;
  const note = req.body?.note;
  if (note !== undefined && note !== null && typeof note !== 'string') {
    badRequest(res, 'ATTACK_BAD_NOTE', 'note must be text');
    return;
  }
  const text = typeof note === 'string' ? note.trim() : '';
  if (text.length > MAX_NOTE) {
    badRequest(res, 'ATTACK_BAD_NOTE', `note may be at most ${MAX_NOTE} characters`);
    return;
  }
  const result = await query(
    `INSERT INTO attack_technique_exclusions (technique_id, note, created_by, created_at)
     VALUES ($1, $2, $3, NOW())
     ON CONFLICT (technique_id) DO UPDATE SET note = EXCLUDED.note, created_by = EXCLUDED.created_by, created_at = NOW()
     RETURNING technique_id, note, created_at`,
    [id, text || null, req.user!.id]
  );
  invalidateAttackCoverage();
  const row = result.rows[0];
  res.json({
    technique_id: row.technique_id,
    name: techniqueDisplayName(id),
    excluded: true,
    note: row.note,
    created_by: req.user!.username ?? null,
    created_at: row.created_at,
  });
});

router.delete('/exclusions/:techniqueId', requireExclusionWrite, async (req: Request, res: Response) => {
  const id = techniqueParam(req, res);
  if (!id) return;
  const result = await query('DELETE FROM attack_technique_exclusions WHERE technique_id = $1', [id]);
  invalidateAttackCoverage();
  if ((result.rowCount ?? 0) === 0) {
    res.status(404).json({ status: 'error', statusCode: 404, code: 'ATTACK_NOT_EXCLUDED', message: `${id} is not excluded` });
    return;
  }
  res.json({ technique_id: id, excluded: false });
});

export default router;
