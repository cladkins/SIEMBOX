import { Router, Request, Response } from 'express';
import { ParserModel, Parser } from '../models/Parser';
import { ParserEngine } from '../services/parser/parserEngine';
import {
  validatePortableParser,
  runSelfTests,
  toPortableParser,
  PortableParser,
} from '../services/parser/parserPortable';
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

// Validate a portable parser (and run its self-tests) WITHOUT saving. Used by the
// import preview UI and shares the exact logic the catalog CI runs.
router.post('/validate', async (req: Request, res: Response) => {
  try {
    const { parser, strict } = req.body ?? {};
    const validation = validatePortableParser(parser, { strict: !!strict });
    const selfTest = validation.ok ? runSelfTests(parser as PortableParser) : null;
    res.json({
      ok: validation.ok && (selfTest ? selfTest.ok : true),
      validation,
      self_test: selfTest,
    });
  } catch (error) {
    throw new ApiError(500, 'Failed to validate parser');
  }
});

// Import a portable parser: validate -> run self-tests -> upsert by name. Refuses
// to import a parser whose own test_samples fail, unless `force` is set.
router.post('/import', async (req: Request, res: Response) => {
  try {
    const { parser, force } = req.body ?? {};
    const validation = validatePortableParser(parser, { strict: false });
    if (!validation.ok) {
      res.status(422).json({ message: 'Parser failed validation', validation });
      return;
    }

    const portable = parser as PortableParser;
    const selfTest = runSelfTests(portable);
    if (!selfTest.ok && !force) {
      res.status(422).json({
        message: 'Parser self-tests failed; pass force=true to import anyway',
        self_test: selfTest,
      });
      return;
    }

    const params = {
      name: portable.name,
      description: portable.description,
      enabled: portable.enabled,
      priority: portable.priority,
      parser_type: portable.parser_type,
      pattern: portable.pattern,
      field_mappings: portable.field_mappings,
      test_samples: portable.test_samples,
      event_type: portable.event_type ?? undefined,
      derivations: portable.derivations ?? null,
    };

    const existing = await ParserModel.findByName(portable.name);
    const saved = existing
      ? await ParserModel.update(existing.id, params)
      : await ParserModel.create(params);

    res.status(existing ? 200 : 201).json({
      action: existing ? 'updated' : 'created',
      parser: saved,
      self_test: selfTest,
      warnings: validation.warnings,
    });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to import parser');
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

// Export a saved parser as a portable .parser.json (the catalog-shareable format).
router.get('/:id/export', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const parser = await ParserModel.findById(id);
    if (!parser) {
      throw new ApiError(404, 'Parser not found');
    }
    const portable = toPortableParser(parser);
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${parser.name}.parser.json"`);
    res.send(JSON.stringify(portable, null, 2));
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to export parser');
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
