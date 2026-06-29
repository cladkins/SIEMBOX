import { Router, Request, Response } from 'express';
import { AlertModel } from '../models/Alert';
import { ApiError } from '../middleware/errorHandler';

const router = Router();

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

    const result = await AlertModel.findAll({
      limit,
      offset,
      severity,
      status,
      ruleId,
      startTime,
      endTime,
      search,
    });

    res.json({
      alerts: result.alerts,
      total: result.total,
      limit,
      offset,
    });
  } catch (error) {
    throw new ApiError(500, 'Failed to fetch alerts');
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
