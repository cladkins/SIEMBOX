import { Router, Request, Response } from 'express';
import { DetectionRuleModel } from '../models/DetectionRule';
import yaml from 'js-yaml';
import { ApiError } from '../middleware/errorHandler';
import { RulesEngine } from '../services/rules/rulesEngine';
import { validateRule } from '../services/rules/rulePortable';
import {
  fetchDetectionCatalog,
  getCatalogDetection,
  getDetectionSource,
  clearDetectionCache,
  ruleSignature,
} from '../services/rules/detectionCatalog';
import { generateDetection } from '../services/ai/aiService';
import { authorize } from '../middleware/auth';

const router = Router();

// Get all rules
router.get('/', async (_req: Request, res: Response) => {
  try {
    const rules = await DetectionRuleModel.findAll();
    res.json(rules);
  } catch (error) {
    throw new ApiError(500, 'Failed to fetch rules');
  }
});

// AI: generate a detection rule from a natural-language description (+ optional
// context about available fields), validated against the engine contract with an
// auto-refine loop. Returns the proposed rule + validation.
router.post('/ai/generate', authorize('admin'), async (req: Request, res: Response) => {
  try {
    const { description, context, maxAttempts } = req.body ?? {};
    if (!description || typeof description !== 'string') {
      throw new ApiError(400, 'description is required');
    }
    const result = await generateDetection({ description, context, maxAttempts });
    res.json(result);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, `AI generation failed: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
});

// Browse the detection catalog (remote GitHub repo), annotated with install status.
router.get('/catalog', async (req: Request, res: Response) => {
  try {
    const { source, entries } = await fetchDetectionCatalog(req.query.refresh === 'true');
    const installed = await DetectionRuleModel.findAll();
    const bySig = new Map(installed.map((r) => [r.name, ruleSignature(r)]));
    const rules = entries.map((e) => {
      const isInstalled = bySig.has(e.name);
      return {
        ...e,
        installed: isInstalled,
        update_available: isInstalled && e.signature !== '' && bySig.get(e.name) !== e.signature,
      };
    });
    res.json({ source, rules });
  } catch (error) {
    throw new ApiError(502, `Failed to load detection catalog: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
});

// Current detection catalog source (for display/config hints).
router.get('/catalog/source', (_req: Request, res: Response) => {
  res.json(getDetectionSource());
});

// Install (or update) a detection rule from the catalog by name: fetch -> validate
// -> upsert. Preserves the operator's enabled toggle on update (like the importer).
router.post('/catalog/install', async (req: Request, res: Response) => {
  try {
    const { name } = req.body ?? {};
    if (!name || typeof name !== 'string') {
      throw new ApiError(400, 'name is required');
    }

    const found = await getCatalogDetection(name);
    if (!found) {
      throw new ApiError(404, `Rule "${name}" not found in catalog`);
    }

    const { rule_yaml, parsed } = found;
    const validation = validateRule(parsed, { strict: false });
    if (!validation.ok) {
      res.status(422).json({ message: 'Catalog rule failed validation', validation });
      return;
    }

    const rule_logic = {
      conditions: parsed.conditions,
      aggregation: parsed.aggregation,
      alert: parsed.alert,
    };
    const existing = await DetectionRuleModel.findByName(parsed.name);
    const saved = existing
      ? await DetectionRuleModel.update(existing.id, {
          description: parsed.description,
          severity: parsed.severity,
          rule_yaml,
          rule_logic,
          tags: parsed.tags || [],
        })
      : await DetectionRuleModel.create({
          name: parsed.name,
          description: parsed.description,
          enabled: parsed.enabled !== false,
          severity: parsed.severity,
          rule_yaml,
          rule_logic,
          tags: parsed.tags || [],
        });

    await RulesEngine.getInstance().reload();
    res.status(existing ? 200 : 201).json({ action: existing ? 'updated' : 'created', rule: saved });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to install rule from catalog');
  }
});

// Install (or update) EVERY detection in the catalog — the "Install all" action,
// the populate path for a catalog-only (unseeded) install. Bad items are
// recorded in `failed` and skipped rather than aborting the batch; the engine is
// reloaded once at the end.
router.post('/catalog/install-all', async (req: Request, res: Response) => {
  try {
    const { entries } = await fetchDetectionCatalog(req.query.refresh === 'true');
    const results = {
      total: entries.length,
      installed: 0,
      updated: 0,
      failed: [] as Array<{ name: string; reason: string }>,
    };
    for (const entry of entries) {
      try {
        const found = await getCatalogDetection(entry.name);
        if (!found) {
          results.failed.push({ name: entry.name, reason: 'not found in catalog' });
          continue;
        }
        const { rule_yaml, parsed } = found;
        const validation = validateRule(parsed, { strict: false });
        if (!validation.ok) {
          results.failed.push({ name: entry.name, reason: 'failed validation' });
          continue;
        }
        const rule_logic = {
          conditions: parsed.conditions,
          aggregation: parsed.aggregation,
          alert: parsed.alert,
        };
        const existing = await DetectionRuleModel.findByName(parsed.name);
        if (existing) {
          await DetectionRuleModel.update(existing.id, {
            description: parsed.description,
            severity: parsed.severity,
            rule_yaml,
            rule_logic,
            tags: parsed.tags || [],
          });
          results.updated++;
        } else {
          await DetectionRuleModel.create({
            name: parsed.name,
            description: parsed.description,
            enabled: parsed.enabled !== false,
            severity: parsed.severity,
            rule_yaml,
            rule_logic,
            tags: parsed.tags || [],
          });
          results.installed++;
        }
      } catch (e) {
        results.failed.push({
          name: entry.name,
          reason: e instanceof Error ? e.message : 'install error',
        });
      }
    }
    await RulesEngine.getInstance().reload();
    res.json(results);
  } catch (error) {
    throw new ApiError(
      502,
      `Failed to install detection catalog: ${error instanceof Error ? error.message : 'unknown error'}`
    );
  }
});

// Force a detection catalog cache refresh.
router.post('/catalog/refresh', async (_req: Request, res: Response) => {
  try {
    clearDetectionCache();
    const { entries } = await fetchDetectionCatalog(true);
    res.json({ refreshed: true, count: entries.length });
  } catch (error) {
    throw new ApiError(502, `Failed to refresh detection catalog: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
});

// Get single rule
router.get('/:id', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const rule = await DetectionRuleModel.findById(id);

    if (!rule) {
      throw new ApiError(404, 'Rule not found');
    }

    res.json(rule);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to fetch rule');
  }
});

// Create rule
router.post('/', async (req: Request, res: Response) => {
  try {
    const { name, description, enabled, severity, rule_yaml, tags } = req.body;

    if (!name || !severity || !rule_yaml) {
      throw new ApiError(400, 'Missing required fields');
    }

    // Parse YAML to extract rule logic
    let rule_logic;
    try {
      rule_logic = yaml.load(rule_yaml) as any;
    } catch (error) {
      throw new ApiError(400, 'Invalid YAML format');
    }

    const rule = await DetectionRuleModel.create({
      name,
      description,
      enabled,
      severity,
      rule_yaml,
      rule_logic,
      tags,
    });

    res.status(201).json(rule);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to create rule');
  }
});

// Update rule
router.put('/:id', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const updateData = req.body;

    // If rule_yaml is being updated, parse it
    if (updateData.rule_yaml) {
      try {
        updateData.rule_logic = yaml.load(updateData.rule_yaml) as any;
      } catch (error) {
        throw new ApiError(400, 'Invalid YAML format');
      }
    }

    const rule = await DetectionRuleModel.update(id, updateData);

    if (!rule) {
      throw new ApiError(404, 'Rule not found');
    }

    // Reload rules engine to pick up the changes
    await RulesEngine.getInstance().reload();

    res.json(rule);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to update rule');
  }
});

// Delete rule
router.delete('/:id', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const deleted = await DetectionRuleModel.delete(id);

    if (!deleted) {
      throw new ApiError(404, 'Rule not found');
    }

    // Reload rules engine to pick up the changes
    await RulesEngine.getInstance().reload();

    res.json({ message: 'Rule deleted successfully' });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to delete rule');
  }
});

export default router;
