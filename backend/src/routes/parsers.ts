import { Router, Request, Response } from 'express';
import { ParserModel, Parser } from '../models/Parser';
import { ParserEngine } from '../services/parser/parserEngine';
import { ApiError } from '../middleware/errorHandler';

const router = Router();

// Get all parsers
router.get('/', async (_req: Request, res: Response) => {
  try {
    const parsers = await ParserModel.findAll();
    res.json(parsers);
  } catch (error) {
    throw new ApiError(500, 'Failed to fetch parsers');
  }
});

// Get single parser
router.get('/:id', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const parser = await ParserModel.findById(id);

    if (!parser) {
      throw new ApiError(404, 'Parser not found');
    }

    res.json(parser);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to fetch parser');
  }
});

// Create parser
router.post('/', async (req: Request, res: Response) => {
  try {
    const { name, description, enabled, priority, parser_type, pattern, field_mappings, test_samples } = req.body;

    if (!name || !parser_type || !pattern || !field_mappings) {
      throw new ApiError(400, 'Missing required fields');
    }

    const parser = await ParserModel.create({
      name,
      description,
      enabled,
      priority,
      parser_type,
      pattern,
      field_mappings,
      test_samples,
    });

    res.status(201).json(parser);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to create parser');
  }
});

// Update parser
router.put('/:id', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const parser = await ParserModel.update(id, req.body);

    if (!parser) {
      throw new ApiError(404, 'Parser not found');
    }

    res.json(parser);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to update parser');
  }
});

// Delete parser
router.delete('/:id', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const deleted = await ParserModel.delete(id);

    if (!deleted) {
      throw new ApiError(404, 'Parser not found');
    }

    res.json({ message: 'Parser deleted successfully' });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to delete parser');
  }
});

// Test parser against sample log (saved parser)
router.post('/:id/test', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const { sample } = req.body;

    if (!sample) {
      throw new ApiError(400, 'Sample log is required');
    }

    const parser = await ParserModel.findById(id);
    if (!parser) {
      throw new ApiError(404, 'Parser not found');
    }

    const parserEngine = new ParserEngine();
    const result = await parserEngine.testParser(parser, sample);

    res.json({
      matched: result !== null,
      fields: result,
    });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to test parser');
  }
});

// Test parser configuration without saving (for parser builder)
router.post('/test', async (req: Request, res: Response) => {
  try {
    const { parser_type, pattern, field_mappings, sample } = req.body;

    if (!parser_type || !pattern || !field_mappings || !sample) {
      throw new ApiError(400, 'Missing required fields: parser_type, pattern, field_mappings, sample');
    }

    // Create temporary parser object for testing
    const tempParser: Parser = {
      id: 0,
      name: 'Test Parser',
      description: null,
      enabled: true,
      priority: 100,
      parser_type,
      pattern,
      field_mappings,
      test_samples: null,
      event_type: null,
      created_at: new Date(),
      updated_at: new Date(),
    };

    const parserEngine = new ParserEngine();
    const result = await parserEngine.testParser(tempParser, sample);

    res.json({
      matched: result !== null,
      fields: result,
    });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to test parser');
  }
});

export default router;
