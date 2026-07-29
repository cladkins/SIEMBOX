import { Router, Request, Response } from 'express';
import { AlertModel } from '../models/Alert';
import { AlertTriageModel } from '../models/AlertTriage';
import { triageAlert } from '../services/ai/triageService';
import { getTriageOperationalConfig } from '../services/ai/aiService';
import { ApiError } from '../middleware/errorHandler';
import { authorize } from '../middleware/auth';

const router = Router();

const SEVERITY_RANK: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };

// Per-user sliding-window rate limit for manual re-run, mirroring routes/ai.ts's
// chat guard — re-run is cheap to spam-click but still costs one LLM call.
const rerunHits = new Map<number, number[]>();
const RERUN_RATE_MAX = 10;
const RERUN_RATE_WINDOW_MS = 5 * 60 * 1000;
function allowRerun(userId: number): boolean {
  const now = Date.now();
  const arr = (rerunHits.get(userId) || []).filter((t) => now - t < RERUN_RATE_WINDOW_MS);
  if (arr.length >= RERUN_RATE_MAX) {
    rerunHits.set(userId, arr);
    return false;
  }
  arr.push(now);
  rerunHits.set(userId, arr);
  return true;
}

// Get all alerts
router.get('/', async (req: Request, res: Response) => {
  try {
    const limit = parseInt(req.query.limit as string) || 100;
    const offset = parseInt(req.query.offset as string) || 0;
    const severity = req.query.severity as string;
    const status = req.query.status as string;
    const ruleId = req.query.ruleId ? parseInt(req.query.ruleId as string) : undefined;
    const startTime = req.query.startTime ? new Date(req.query.startTime as string) : undefined;
    const endTime = req.query.endTime ? new Date(req.query.endTime as string) : undefined;
    const search = (req.query.search as string)?.trim().slice(0, 200) || undefined;
    const triageStatus = req.query.triageStatus as string | undefined;
    const triageVerdict = req.query.triageVerdict as string | undefined;
    const minRiskScore = req.query.minRiskScore ? parseInt(req.query.minRiskScore as string) : undefined;
    const sortBy = req.query.sortBy === 'risk_score' ? 'risk_score' : undefined;

    // ?group=event collapses the list to one row per triggering log, since one
    // event can satisfy several rules. Opt-in: the flat list stays the default
    // so existing callers and the export are unaffected.
    const groupByEvent = req.query.group === 'event';

    const filters = {
      limit,
      offset,
      severity,
      status,
      ruleId,
      startTime,
      endTime,
      search,
      triageStatus,
      triageVerdict,
      minRiskScore,
    };
    const result = groupByEvent
      ? await AlertModel.findAllGrouped(filters)
      : await AlertModel.findAll({ ...filters, sortBy });

    res.json({
      alerts: result.alerts,
      total: result.total,
      limit,
      offset,
      grouped: groupByEvent,
    });
  } catch (error) {
    throw new ApiError(500, 'Failed to fetch alerts');
  }
});

// Export alerts (CSV or JSON) using the same filters as the list view. Capped so
// a click can't try to stream the whole table; narrow the filters for more.
const EXPORT_MAX = 10000;
function csvCell(value: unknown): string {
  const s = value == null ? '' : String(value);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
router.get('/export', async (req: Request, res: Response) => {
  try {
    const format = (req.query.format as string) === 'json' ? 'json' : 'csv';
    const severity = req.query.severity as string;
    const status = req.query.status as string;
    const ruleId = req.query.ruleId ? parseInt(req.query.ruleId as string) : undefined;
    const startTime = req.query.startTime ? new Date(req.query.startTime as string) : undefined;
    const endTime = req.query.endTime ? new Date(req.query.endTime as string) : undefined;
    const search = (req.query.search as string)?.trim().slice(0, 200) || undefined;

    const { alerts } = await AlertModel.findAll({
      limit: EXPORT_MAX,
      offset: 0,
      severity,
      status,
      ruleId,
      startTime,
      endTime,
      search,
    });

    const stamp = new Date().toISOString().replace(/[:.]/g, '-');

    if (format === 'json') {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="siembox-alerts-${stamp}.json"`);
      res.send(JSON.stringify(alerts, null, 2));
      return;
    }

    const cols = ['id', 'created_at', 'severity', 'status', 'source', 'title', 'source_ip', 'country_code', 'description'];
    const lines = [cols.join(',')];
    for (const a of alerts as any[]) {
      const md = a.matched_data || {};
      lines.push(
        [
          a.id,
          a.created_at instanceof Date ? a.created_at.toISOString() : a.created_at,
          a.severity,
          a.status,
          a.source || 'rule',
          a.title,
          md.source_ip || md.ip || md.client_ip || '',
          md.country_code || '',
          a.description || '',
        ]
          .map(csvCell)
          .join(',')
      );
    }
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="siembox-alerts-${stamp}.csv"`);
    res.send(lines.join('\r\n'));
  } catch (error) {
    throw new ApiError(500, 'Failed to export alerts');
  }
});

// Get alert statistics
router.get('/statistics', async (_req: Request, res: Response) => {
  try {
    const stats = await AlertModel.getStatistics();
    res.json(stats);
  } catch (error) {
    throw new ApiError(500, 'Failed to fetch alert statistics');
  }
});

// Alerts grouped by GeoIP country (for the dashboard "Alerts by Country" widget)
router.get('/by-country', async (req: Request, res: Response) => {
  try {
    const days = Math.min(Math.max(parseInt(String(req.query.days)) || 30, 1), 365);
    const limit = Math.min(Math.max(parseInt(String(req.query.limit)) || 50, 1), 250);
    const rows = await AlertModel.getCountByCountry(days, limit);
    res.json(rows);
  } catch (error) {
    throw new ApiError(500, 'Failed to fetch alerts by country');
  }
});

// Distribution of completed SOC triage verdicts by risk band, for the
// dashboard's "SOC Triage Risk Rating" chart. Must stay ahead of '/:id'
// below, or express would match this path as an alert id.
router.get('/triage-risk-summary', async (_req: Request, res: Response) => {
  try {
    const summary = await AlertTriageModel.getRiskRatingSummary();
    res.json(summary);
  } catch (error) {
    throw new ApiError(500, 'Failed to fetch triage risk summary');
  }
});

// Get single alert
router.get('/:id', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const alert = await AlertModel.findById(id);

    if (!alert) {
      throw new ApiError(404, 'Alert not found');
    }

    res.json(alert);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to fetch alert');
  }
});

// Get an alert's AI triage verdict (or its current pending/analyzing/absent
// state). Always 200 — `triage: null` means "no run yet" rather than a 404,
// so the frontend's poll never trips the axios error interceptor.
router.get('/:id/triage', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const alert = await AlertModel.findById(id);
    if (!alert) throw new ApiError(404, 'Alert not found');

    const [triage, opCfg] = await Promise.all([
      AlertTriageModel.findByAlertId(id),
      getTriageOperationalConfig(),
    ]);
    const rank = SEVERITY_RANK[alert.severity] ?? 0;
    const minRank = SEVERITY_RANK[opCfg.minSeverity] ?? 1;

    res.json({
      triage,
      enabled: opCfg.enabled,
      eligible: rank >= minRank,
    });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to fetch alert triage');
  }
});

// Manually (re-)run AI triage for an alert, bypassing the severity/dedupe
// gates. Responds immediately — the analysis (up to ~110s) runs in the
// background; the frontend polls GET /:id/triage for the result.
router.post('/:id/triage/rerun', authorize('admin', 'analyst', 'operator'), async (req: Request, res: Response) => {
  try {
    if (!req.user) throw new ApiError(401, 'Authentication required');
    const id = parseInt(req.params.id);
    const alert = await AlertModel.findById(id);
    if (!alert) throw new ApiError(404, 'Alert not found');

    if (!allowRerun(req.user.id)) {
      throw new ApiError(429, 'Too many re-run requests — please wait a moment and try again.');
    }

    void triageAlert(id, { triggeredBy: 'manual', requestedBy: req.user.id, force: true });
    res.status(202).json({ status: 'pending' });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to start triage re-run');
  }
});

// Update alert (change status, assign user)
router.put('/:id', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const { status, assigned_to, description } = req.body;

    const alert = await AlertModel.update(id, {
      status,
      assigned_to,
      description,
    });

    if (!alert) {
      throw new ApiError(404, 'Alert not found');
    }

    res.json(alert);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to update alert');
  }
});

// Delete alert
router.delete('/:id', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const deleted = await AlertModel.delete(id);

    if (!deleted) {
      throw new ApiError(404, 'Alert not found');
    }

    res.json({ message: 'Alert deleted successfully' });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to delete alert');
  }
});

export default router;
