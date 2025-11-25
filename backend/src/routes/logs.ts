import { Router, Request, Response } from 'express';
import { RawLogModel } from '../models/RawLog';
import { ParsedLogModel } from '../models/ParsedLog';
import { ApiError } from '../middleware/errorHandler';

const router = Router();

// Get raw logs
router.get('/raw', async (req: Request, res: Response) => {
  try {
    const limit = parseInt(req.query.limit as string) || 100;
    const offset = parseInt(req.query.offset as string) || 0;
    const sourceIp = req.query.source_ip as string;
    const search = req.query.search as string;
    const startTime = req.query.start_date ? new Date(req.query.start_date as string) : undefined;
    const endTime = req.query.end_date ? new Date(req.query.end_date as string) : undefined;

    const result = await RawLogModel.findAll({
      limit,
      offset,
      sourceIp,
      search,
      startTime,
      endTime,
    });

    res.json({
      logs: result.logs,
      total: result.total,
      limit,
      offset,
    });
  } catch (error) {
    throw new ApiError(500, 'Failed to fetch raw logs');
  }
});

// Get parsed logs
router.get('/parsed', async (req: Request, res: Response) => {
  try {
    const limit = parseInt(req.query.limit as string) || 100;
    const offset = parseInt(req.query.offset as string) || 0;
    const sourceIp = req.query.source_ip as string;
    const eventType = req.query.event_type as string;
    const search = req.query.search as string;
    const startTime = req.query.start_date ? new Date(req.query.start_date as string) : undefined;
    const endTime = req.query.end_date ? new Date(req.query.end_date as string) : undefined;

    const result = await ParsedLogModel.findAll({
      limit,
      offset,
      sourceIp,
      eventType,
      search,
      startTime,
      endTime,
    });

    res.json({
      logs: result.logs,
      total: result.total,
      limit,
      offset,
    });
  } catch (error) {
    throw new ApiError(500, 'Failed to fetch parsed logs');
  }
});

// Search parsed logs by field
router.get('/parsed/search', async (req: Request, res: Response) => {
  try {
    const field = req.query.field as string;
    const value = req.query.value as string;
    const limit = parseInt(req.query.limit as string) || 100;
    const offset = parseInt(req.query.offset as string) || 0;

    if (!field || !value) {
      throw new ApiError(400, 'Field and value are required');
    }

    const result = await ParsedLogModel.searchByField(field, value, { limit, offset });

    res.json({
      logs: result.logs,
      total: result.total,
      limit,
      offset,
    });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to search logs');
  }
});

export default router;
