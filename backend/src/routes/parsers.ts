import { Router, Request, Response } from 'express';
import { ParserModel, Parser } from '../models/Parser';
import { ParserEngine } from '../services/parser/parserEngine';
import {
  validatePortableParser,
  runSelfTests,
  toPortableParser,
  PortableParser,
} from '../services/parser/parserPortable';
import {
  fetchCatalog,
  getCatalogParser,
  getCatalogSource,
  clearCatalogCache,
  parserSignature,
  catalogNewFileUrl,
} from '../services/parser/catalogService';
import { generateParser } from '../services/ai/aiService';
import { authorize } from '../middleware/auth';
import { ApiError } from '../middleware/errorHandler';

const router = Router();

/** Upsert a (already-validated) portable parser by name. Shared by import + catalog install. */
async function upsertPortableParser(portable: PortableParser): Promise<{ action: 'created' | 'updated'; parser: Parser | null }> {
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
  // Apply to the running syslog engine immediately — no restart needed.
  await ParserEngine.getInstance().reload();
  return { action: existing ? 'updated' : 'created', parser: saved };
}

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

    const result = await upsertPortableParser(portable);
    res.status(result.action === 'created' ? 201 : 200).json({
      action: result.action,
      parser: result.parser,
      self_test: selfTest,
      warnings: validation.warnings,
    });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to import parser');
  }
});

// AI: generate a portable parser from a log sample (validated + self-tested,
// with an auto-refine loop). Returns the proposed parser + its check results.
router.post('/ai/generate', authorize('admin'), async (req: Request, res: Response) => {
  try {
    const { sample, hints, maxAttempts } = req.body ?? {};
    if (!sample || typeof sample !== 'string') {
      throw new ApiError(400, 'sample is required');
    }
    const result = await generateParser({ sample, hints, maxAttempts });
    res.json(result);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, `AI generation failed: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
});

// Browse the parser catalog (remote GitHub repo), annotated with install status.
// `?refresh=true` bypasses the 5-minute cache.
router.get('/catalog', async (req: Request, res: Response) => {
  try {
    const { source, entries } = await fetchCatalog(req.query.refresh === 'true');
    const installed = await ParserModel.findAll();
    const bySig = new Map(installed.map((p) => [p.name, parserSignature(p)]));
    const parsers = entries.map((e) => {
      const isInstalled = bySig.has(e.name);
      return {
        ...e,
        installed: isInstalled,
        update_available: isInstalled && e.signature !== '' && bySig.get(e.name) !== e.signature,
      };
    });
    res.json({ source, parsers });
  } catch (error) {
    throw new ApiError(502, `Failed to load catalog: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
});

// Current catalog source (for display/config hints).
router.get('/catalog/source', (_req: Request, res: Response) => {
  res.json(getCatalogSource());
});

// Install (or update) a parser from the catalog by name: fetch -> validate ->
// self-test -> upsert. Refuses on failing self-tests unless `force`.
router.post('/catalog/install', async (req: Request, res: Response) => {
  try {
    const { name, force } = req.body ?? {};
    if (!name || typeof name !== 'string') {
      throw new ApiError(400, 'name is required');
    }

    const portable = await getCatalogParser(name);
    if (!portable) {
      throw new ApiError(404, `Parser "${name}" not found in catalog`);
    }

    const validation = validatePortableParser(portable, { strict: false });
    if (!validation.ok) {
      res.status(422).json({ message: 'Catalog parser failed validation', validation });
      return;
    }
    const selfTest = runSelfTests(portable);
    if (!selfTest.ok && !force) {
      res.status(422).json({ message: 'Catalog parser self-tests failed', self_test: selfTest });
      return;
    }

    const result = await upsertPortableParser(portable);
    res.status(result.action === 'created' ? 201 : 200).json({
      action: result.action,
      parser: result.parser,
      self_test: selfTest,
    });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to install parser from catalog');
  }
});

// Install (or update) EVERY parser in the catalog — the "Install all" action,
// the populate path for a catalog-only (unseeded) install. Each item is
// validated + self-tested; a bad item is recorded in `failed` and skipped
// rather than aborting the batch. `force` installs items whose self-tests fail.
router.post('/catalog/install-all', async (req: Request, res: Response) => {
  try {
    const force = !!(req.body && req.body.force);
    const { entries } = await fetchCatalog(req.query.refresh === 'true');
    const results = {
      total: entries.length,
      installed: 0,
      updated: 0,
      failed: [] as Array<{ name: string; reason: string }>,
    };
    for (const entry of entries) {
      try {
        const portable = await getCatalogParser(entry.name);
        if (!portable) {
          results.failed.push({ name: entry.name, reason: 'not found in catalog' });
          continue;
        }
        const validation = validatePortableParser(portable, { strict: false });
        if (!validation.ok) {
          results.failed.push({ name: entry.name, reason: 'failed validation' });
          continue;
        }
        if (!runSelfTests(portable).ok && !force) {
          results.failed.push({ name: entry.name, reason: 'self-tests failed' });
          continue;
        }
        const r = await upsertPortableParser(portable);
        if (r.action === 'created') results.installed++;
        else results.updated++;
      } catch (e) {
        results.failed.push({
          name: entry.name,
          reason: e instanceof Error ? e.message : 'install error',
        });
      }
    }
    res.json(results);
  } catch (error) {
    throw new ApiError(
      502,
      `Failed to install catalog: ${error instanceof Error ? error.message : 'unknown error'}`
    );
  }
});

// Force a catalog cache refresh.
router.post('/catalog/refresh', async (_req: Request, res: Response) => {
  try {
    clearCatalogCache();
    const { entries } = await fetchCatalog(true);
    res.json({ refreshed: true, count: entries.length });
  } catch (error) {
    throw new ApiError(502, `Failed to refresh catalog: ${error instanceof Error ? error.message : 'unknown error'}`);
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

// Prepare a community-catalog contribution for a saved parser: export -> validate
// -> self-test, and (only if clean) build a no-auth GitHub "propose new file" URL
// the user finishes in their own browser. SIEMBox never opens the PR or holds a
// credential; the catalog's CI + maintainer review are the merge gate.
router.get('/:id/contribute', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const parser = await ParserModel.findById(id);
    if (!parser) throw new ApiError(404, 'Parser not found');

    const portable = toPortableParser(parser);
    const validation = validatePortableParser(portable, { strict: true });
    const selfTest = validation.ok ? runSelfTests(portable) : null;
    const ready = validation.ok && !!selfTest?.ok;

    const filePath = `${getCatalogSource().path}/${parser.name}.parser.json`;
    const content = JSON.stringify(portable, null, 2);

    res.json({
      kind: 'parser',
      name: parser.name,
      path: filePath,
      content,
      valid: validation.ok,
      errors: validation.errors,
      warnings: validation.warnings,
      self_test: selfTest,
      ready, // only offer the PR link when it would pass the catalog's CI
      contribute_url: ready ? catalogNewFileUrl(filePath, content) : null,
    });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to prepare contribution');
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
    await ParserEngine.getInstance().reload();

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

    // Enable/disable/edit takes effect on the running engine immediately.
    await ParserEngine.getInstance().reload();
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

    await ParserEngine.getInstance().reload();
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
