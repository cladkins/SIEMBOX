import { Router, Request, Response } from 'express';
import { DetectionRuleModel } from '../models/DetectionRule';
import yaml from 'js-yaml';
import { ApiError } from '../middleware/errorHandler';

const router = Router();

// Get all rules
router.get('/', async (req: Request, res: Response) => {
  try {
    const rules = await DetectionRuleModel.findAll();
    res.json(rules);
  } catch (error) {
    throw new ApiError(500, 'Failed to fetch rules');
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

    res.json({ message: 'Rule deleted successfully' });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to delete rule');
  }
});

export default router;
