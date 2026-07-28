import { Router, Request, Response } from 'express';
import { RawLogModel } from '../models/RawLog';
import { ParsedLogModel } from '../models/ParsedLog';
import { ApiError } from '../middleware/errorHandler';
import { query } from '../config/database';

const router = Router();

// Parse coverage over the last 24h: how much of the log stream is visible to
// detection. Rules are only evaluated on parser-matched logs — the unparsed
// fallback is stored but NEVER runs detections — so a low parsed share means
// rules are silently starved regardless of how correct they are. Surfacing this
// is what turns "detections aren't working" from a mystery into a one-glance
// diagnosis. Uses idx_parsed_logs_timestamp.
router.get('/parse-coverage', async (_req: Request, res: Response) => {
  try {
    // Reads the incrementally-maintained hourly counters (see migration 024 and
    // ParserEngine.bumpMatchCount) — O(rows-per-day), never a parsed_logs scan.
    // After an upgrade the counters start empty and the 24h window fills over
    // the following day; `since` marks where the data actually begins.
    const result = await query(
      `SELECT COALESCE(SUM(matches), 0)::bigint AS total,
              COALESCE(SUM(matches) FILTER (WHERE parser_id = 0), 0)::bigint AS unparsed,
              MIN(hour) AS since
       FROM parser_match_hourly
       WHERE hour >= NOW() - INTERVAL '24 hours'`
    );
    const total = Number(result.rows[0]?.total || 0);
    const unparsed = Number(result.rows[0]?.unparsed || 0);
    const parsed = total - unparsed;
    res.json({
      window: '24h',
      since: result.rows[0]?.since ?? null,
      total,
      parsed,
      unparsed,
      parsed_pct: total > 0 ? Math.round((parsed / total) * 1000) / 10 : null,
    });
  } catch (error) {
    throw new ApiError(500, 'Failed to compute parse coverage');
  }
});

// Get raw logs
router.get('/raw', async (req: Request, res: Response) => {
  try {
    const limit = parseInt(req.query.limit as string) || 100;
    const offset = parseInt(req.query.offset as string) || 0;
    const sourceIp = req.query.source_ip as string;
    const appName = req.query.app_name as string;
    const hostname = req.query.hostname as string;
    const search = req.query.search as string;
    const severity = req.query.severity !== undefined ? parseInt(req.query.severity as string) : undefined;
    const startTime = req.query.start_date ? new Date(req.query.start_date as string) : undefined;
    const endTime = req.query.end_date ? new Date(req.query.end_date as string) : undefined;

    const result = await RawLogModel.findAll({
      limit,
      offset,
      sourceIp,
      appName,
      hostname,
      search,
      severity,
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
    const appName = req.query.app_name as string;
    const parserId =
      req.query.parser_id !== undefined && req.query.parser_id !== ''
        ? parseInt(req.query.parser_id as string, 10)
        : undefined;
    // parse_status separates real parser matches from the generic unparsed
    // fallback, which is stored in parsed_logs too but never runs detections.
    const rawParseStatus = (req.query.parse_status as string) || '';
    const parseStatus =
      rawParseStatus === 'parsed' || rawParseStatus === 'unparsed' ? rawParseStatus : undefined;
    const search = req.query.search as string;
    const startTime = req.query.start_date ? new Date(req.query.start_date as string) : undefined;
    const endTime = req.query.end_date ? new Date(req.query.end_date as string) : undefined;

    const result = await ParsedLogModel.findAll({
      limit,
      offset,
      sourceIp,
      eventType,
      appName,
      parserId,
      parseStatus,
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
