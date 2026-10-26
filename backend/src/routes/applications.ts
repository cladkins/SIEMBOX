import { Router, Request, Response } from 'express';
import { ApiError } from '../middleware/errorHandler';
import { authorize } from '../middleware/auth';
import {
  getApplication,
  listApplications,
  listApplicationVulnerabilities,
  listUnmatched,
  readInventoryStatus,
  type ListFilters,
} from '../services/applications/inventory';
import { describeInventoryRun } from '../services/applications/rollup';
import { runApplicationInventoryNow } from '../jobs/applicationInventory';

const router = Router();

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

// Values no signature matched (syslog programs, container images, user-agent
// products), each with a link that opens a pre-filled signature in the catalog.
router.get('/unmatched', async (req: Request, res: Response) => {
  const limit = Number.parseInt(String(req.query.limit ?? ''), 10);
  res.json({ unmatched: await listUnmatched(str(req.query.source), Number.isFinite(limit) ? limit : undefined) });
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
