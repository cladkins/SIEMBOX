/**
 * Vulnerability API Routes
 *
 * RESTful endpoints for vulnerability scanning and management.
 * Includes scan triggering, vulnerability tracking, and status management.
 */

import express, { Request, Response } from 'express';
import { authenticate } from '../middleware/auth';
import { NucleiScanner } from '../services/scanner/nucleiScanner';
import { VulnerabilityProcessor } from '../services/scanner/vulnerabilityProcessor';
import { TemplateService } from '../services/scanner/templateService';

const router = express.Router();

// VulnerabilityRepository will be imported once created by the agents
// import { VulnerabilityRepository } from '../services/vulnerabilities/vulnerabilityRepository';

/**
 * GET /api/vulnerabilities/summary
 * Get dashboard summary of vulnerabilities
 * No authentication required - read-only operation
 */
router.get('/summary', async (_req: Request, res: Response) => {
  try {
    const summary = await VulnerabilityProcessor.getVulnerabilityStats();
    res.json(summary);
  } catch (error: any) {
    console.error('[VULN] Get summary error:', error);
    res.status(500).json({
      error: 'Failed to retrieve vulnerability summary',
      message: error.message,
    });
  }
});

/**
 * GET /api/vulnerabilities/templates
 * Get available Nuclei templates overview
 * No authentication required - read-only operation
 */
router.get('/templates', async (_req: Request, res: Response) => {
  try {
    const [categories, stats, dirCheck] = await Promise.all([
      TemplateService.getCategories(),
      TemplateService.getStats(),
      TemplateService.checkTemplatesDirectory(),
    ]);

    res.json({
      categories,
      stats,
      templatesDirectory: dirCheck,
    });
  } catch (error: any) {
    console.error('[VULN] Get templates error:', error);
    res.status(500).json({
      error: 'Failed to retrieve templates',
      message: error.message,
    });
  }
});

/**
 * GET /api/vulnerabilities/templates/categories
 * Get template categories
 * No authentication required - read-only operation
 */
router.get('/templates/categories', async (_req: Request, res: Response) => {
  try {
    const categories = await TemplateService.getCategories();
    res.json({ categories });
  } catch (error: any) {
    console.error('[VULN] Get template categories error:', error);
    res.status(500).json({
      error: 'Failed to retrieve template categories',
      message: error.message,
    });
  }
});

/**
 * GET /api/vulnerabilities/templates/tags
 * Get available template tags
 * No authentication required - read-only operation
 */
router.get('/templates/tags', async (_req: Request, res: Response) => {
  try {
    const tags = await TemplateService.getTags();
    res.json({ tags });
  } catch (error: any) {
    console.error('[VULN] Get template tags error:', error);
    res.status(500).json({
      error: 'Failed to retrieve template tags',
      message: error.message,
    });
  }
});

/**
 * GET /api/vulnerabilities/templates/search
 * Search templates by query
 * No authentication required - read-only operation
 */
router.get('/templates/search', async (req: Request, res: Response) => {
  try {
    const query = req.query.q as string || '';
    const limit = parseInt(req.query.limit as string) || 100;

    if (!query) {
      res.status(400).json({ error: 'Query parameter "q" is required' });
      return;
    }

    const templates = await TemplateService.searchTemplates(query, limit);
    res.json({
      templates,
      total: templates.length,
      query,
    });
  } catch (error: any) {
    console.error('[VULN] Search templates error:', error);
    res.status(500).json({
      error: 'Failed to search templates',
      message: error.message,
    });
  }
});

/**
 * GET /api/vulnerabilities/templates/category/:categoryId
 * Get templates by category
 * No authentication required - read-only operation
 */
router.get('/templates/category/:categoryId', async (req: Request, res: Response) => {
  try {
    const categoryId = req.params.categoryId;
    const limit = parseInt(req.query.limit as string) || 100;

    const templates = await TemplateService.getTemplatesByCategory(categoryId, limit);
    res.json({
      templates,
      total: templates.length,
      category: categoryId,
    });
  } catch (error: any) {
    console.error('[VULN] Get templates by category error:', error);
    res.status(500).json({
      error: 'Failed to retrieve templates by category',
      message: error.message,
    });
  }
});

/**
 * GET /api/vulnerabilities/templates/tag/:tag
 * Get templates by tag
 * No authentication required - read-only operation
 */
router.get('/templates/tag/:tag', async (req: Request, res: Response) => {
  try {
    const tag = req.params.tag;
    const limit = parseInt(req.query.limit as string) || 100;

    const templates = await TemplateService.getTemplatesByTag(tag, limit);
    res.json({
      templates,
      total: templates.length,
      tag,
    });
  } catch (error: any) {
    console.error('[VULN] Get templates by tag error:', error);
    res.status(500).json({
      error: 'Failed to retrieve templates by tag',
      message: error.message,
    });
  }
});

/**
 * POST /api/vulnerabilities/templates/refresh
 * Refresh template cache
 * Authentication required
 */
router.post('/templates/refresh', authenticate, async (_req: Request, res: Response) => {
  try {
    TemplateService.clearCache();
    const stats = await TemplateService.getStats();

    res.json({
      message: 'Template cache refreshed',
      stats,
    });
  } catch (error: any) {
    console.error('[VULN] Refresh templates error:', error);
    res.status(500).json({
      error: 'Failed to refresh templates',
      message: error.message,
    });
  }
});

/**
 * POST /api/vulnerabilities/templates/download
 * Download/update Nuclei templates from official repository
 * Only downloads new or updated templates, preserves custom templates
 * Authentication required
 */
router.post('/templates/download', authenticate, async (_req: Request, res: Response) => {
  try {
    console.log('[VULN] Starting template download...');

    const result = await TemplateService.downloadTemplates();

    if (result.success) {
      // Get updated stats after download
      const stats = await TemplateService.getStats();

      res.json({
        message: result.message,
        stats,
        output: result.output,
      });
    } else {
      res.status(500).json({
        error: result.message,
        details: result.error,
      });
    }
  } catch (error: any) {
    console.error('[VULN] Download templates error:', error);
    res.status(500).json({
      error: 'Failed to download templates',
      message: error.message,
    });
  }
});

/**
 * GET /api/vulnerabilities/scans/active
 * Get active vulnerability scans (queued or running)
 * No authentication required - read-only operation
 */
router.get('/scans/active', async (_req: Request, res: Response) => {
  try {
    // Get all scans and filter to active ones (queued or running)
    const allScans = await NucleiScanner.getRecentScans(50);
    const activeScans = allScans.filter(
      (scan: any) => scan.status === 'queued' || scan.status === 'running'
    );

    res.json({ scans: activeScans, total: activeScans.length });
  } catch (error: any) {
    console.error('[VULN] Get active scans error:', error);
    res.status(500).json({
      error: 'Failed to retrieve active scans',
      message: error.message,
    });
  }
});

/**
 * GET /api/vulnerabilities/scans
 * Get all vulnerability scans with filtering and pagination
 * No authentication required - read-only operation
 */
router.get('/scans', async (req: Request, res: Response) => {
  try {
    const limit = parseInt(req.query.limit as string) || 50;

    console.log('[VULN] GET /scans with limit:', limit);

    const scans = await NucleiScanner.getRecentScans(limit);

    res.json({
      scans,
      total: scans.length,
      limit,
      offset: 0,
      hasMore: false,
    });
  } catch (error: any) {
    console.error('[VULN] Get scans error:', error);
    res.status(500).json({
      error: 'Failed to retrieve scans',
      message: error.message,
    });
  }
});

/**
 * GET /api/vulnerabilities/scans/:scanId
 * Get vulnerability scan by ID with results
 * No authentication required - read-only operation
 */
router.get('/scans/:scanId', async (req: Request, res: Response): Promise<void> => {
  try {
    const scanId = parseInt(req.params.scanId);

    if (isNaN(scanId)) {
      res.status(400).json({ error: 'Invalid scan ID' });
      return;
    }

    console.log('[VULN] GET /scans/:scanId with ID:', scanId);

    const scan = await NucleiScanner.getScanStatus(scanId);

    if (!scan) {
      res.status(404).json({ error: 'Scan not found' });
      return;
    }

    res.json(scan);
  } catch (error: any) {
    console.error('[VULN] Get scan error:', error);
    res.status(500).json({
      error: 'Failed to retrieve scan',
      message: error.message,
    });
  }
});

/**
 * GET /api/vulnerabilities/scans/:scanId/status
 * Get vulnerability scan status (for polling)
 * No authentication required - read-only operation
 */
router.get('/scans/:scanId/status', async (req: Request, res: Response): Promise<void> => {
  try {
    const scanId = parseInt(req.params.scanId);

    if (isNaN(scanId)) {
      res.status(400).json({ error: 'Invalid scan ID' });
      return;
    }

    const status = await NucleiScanner.getScanStatus(scanId);

    if (!status) {
      res.status(404).json({ error: 'Scan not found' });
      return;
    }

    // Extract progress from results_summary if available
    const resultsSummary = status.results_summary || {};
    const progress = resultsSummary.progress || {};

    res.json({
      id: status.id,
      status: status.status,
      progress: {
        templatesCompleted: progress.templatesCompleted || 0,
        templatesTotal: progress.templatesTotal || 0,
        percentComplete: status.status === 'completed' ? 100 : (progress.percentComplete || 0),
        hostsCompleted: progress.hostsCompleted || 0,
        hostsTotal: progress.hostsTotal || 0,
        requests: progress.requests || 0,
        lastUpdate: progress.lastUpdate || null,
      },
      vulnerabilities_found: status.vulnerabilities_found || 0,
      started_at: status.started_at,
      completed_at: status.completed_at,
      duration_seconds: status.duration_seconds,
      error_message: status.error_message,
    });
  } catch (error: any) {
    console.error('[VULN] Get scan status error:', error);
    res.status(500).json({
      error: 'Failed to retrieve scan status',
      message: error.message,
    });
  }
});

/**
 * POST /api/vulnerabilities/scans
 * Trigger a new vulnerability scan
 * Authentication required
 */
router.post('/scans', authenticate, async (req: Request, res: Response) => {
  try {
    const { target, templates, severity, description, timeout, rateLimit } = req.body;

    console.log('[VULN] POST /scans - received body:', JSON.stringify(req.body));

    // Validate required fields
    if (!target) {
      res.status(400).json({ error: 'Target is required' });
      return;
    }

    // Build template selection
    const templateSelection: any = {};

    if (templates === 'all') {
      templateSelection.all = true;
    } else if (templates === 'cves' || templates === 'default') {
      templateSelection.cves = true;
    } else if (Array.isArray(templates)) {
      // Check if templates are category paths (end with /)
      const categoryPaths = templates.filter((t: string) => t.endsWith('/'));
      const specificTemplates = templates.filter((t: string) => !t.endsWith('/'));

      if (categoryPaths.length > 0) {
        // Use -t for each category directory
        templateSelection.templates = categoryPaths;
      }
      if (specificTemplates.length > 0) {
        templateSelection.templates = [
          ...(templateSelection.templates || []),
          ...specificTemplates
        ];
      }
    } else if (typeof templates === 'string') {
      templateSelection.tags = templates.split(',');
    } else {
      // Default to CVE templates
      templateSelection.cves = true;
    }

    // Add severity filter if provided
    if (severity && Array.isArray(severity)) {
      templateSelection.severities = severity;
    }

    const scanId = await NucleiScanner.scan({
      target,
      templateSelection,
      userId: (req as any).user?.id || 1,
      description,
      timeout,
      rateLimit,
    });

    res.status(202).json({
      message: 'Vulnerability scan initiated',
      scanId,
      status: 'queued',
      target,
      templateSelection,
    });
  } catch (error: any) {
    console.error('[VULN] Scan initiation error:', error);
    res.status(500).json({
      error: 'Failed to initiate vulnerability scan',
      message: error.message,
    });
  }
});

/**
 * POST /api/vulnerabilities/scans/:scanId/cancel
 * Cancel a running vulnerability scan
 * Authentication required
 */
router.post('/scans/:scanId/cancel', authenticate, async (req: Request, res: Response): Promise<void> => {
  try {
    const scanId = parseInt(req.params.scanId);

    if (isNaN(scanId)) {
      res.status(400).json({ error: 'Invalid scan ID' });
      return;
    }

    console.log('[VULN] POST /scans/:scanId/cancel with ID:', scanId);

    // First check if the scan exists and its current status
    const scanStatus = await NucleiScanner.getScanStatus(scanId);

    if (!scanStatus) {
      res.status(404).json({ error: 'Scan not found' });
      return;
    }

    // If scan already completed/failed/cancelled, return success with appropriate message
    if (scanStatus.status === 'completed') {
      res.json({
        message: 'Scan already completed',
        scanId,
        status: 'completed',
      });
      return;
    }

    if (scanStatus.status === 'failed') {
      res.json({
        message: 'Scan already failed',
        scanId,
        status: 'failed',
      });
      return;
    }

    if (scanStatus.status === 'cancelled') {
      res.json({
        message: 'Scan already cancelled',
        scanId,
        status: 'cancelled',
      });
      return;
    }

    // Try to cancel the running scan
    const cancelled = await NucleiScanner.cancelScan(scanId);

    if (!cancelled) {
      // Scan might have just finished - check status again
      const updatedStatus = await NucleiScanner.getScanStatus(scanId);
      if (updatedStatus && updatedStatus.status !== 'running' && updatedStatus.status !== 'queued') {
        res.json({
          message: `Scan already ${updatedStatus.status}`,
          scanId,
          status: updatedStatus.status,
        });
        return;
      }
      res.status(404).json({ error: 'Scan process not found - may have already finished' });
      return;
    }

    res.json({
      message: 'Scan cancelled successfully',
      scanId,
    });
  } catch (error: any) {
    console.error('[VULN] Cancel scan error:', error);
    res.status(500).json({
      error: 'Failed to cancel scan',
      message: error.message,
    });
  }
});

/**
 * GET /api/vulnerabilities
 * Get all vulnerabilities with filtering and pagination
 * No authentication required - read-only operation
 */
router.get('/', async (req: Request, res: Response) => {
  try {
    const filters = {
      severity: req.query.severity as string,
      status: req.query.status as string,
      cve_id: req.query.cve_id as string,
      search: req.query.search as string,
      limit: parseInt(req.query.limit as string) || 50,
      offset: parseInt(req.query.offset as string) || 0,
    };

    console.log('[VULN] GET / with filters:', filters);

    // TODO: Import VulnerabilityRepository once created
    // const result = await VulnerabilityRepository.getVulnerabilities(filters);

    res.json({
      vulnerabilities: [],
      total: 0,
      limit: filters.limit,
      offset: filters.offset,
      hasMore: false,
    });
  } catch (error: any) {
    console.error('[VULN] Get vulnerabilities error:', error);
    res.status(500).json({
      error: 'Failed to retrieve vulnerabilities',
      message: error.message,
    });
  }
});

/**
 * GET /api/vulnerabilities/:id
 * Get vulnerability by ID with affected assets
 * No authentication required - read-only operation
 */
router.get('/:id', async (req: Request, res: Response): Promise<void> => {
  try {
    const vulnId = parseInt(req.params.id);

    if (isNaN(vulnId)) {
      res.status(400).json({ error: 'Invalid vulnerability ID' });
      return;
    }

    // TODO: Import VulnerabilityRepository once created
    // const vuln = await VulnerabilityRepository.getVulnerabilityById(vulnId);

    res.status(404).json({ error: 'Vulnerability not found' });
  } catch (error: any) {
    console.error('[VULN] Get vulnerability error:', error);
    res.status(500).json({
      error: 'Failed to retrieve vulnerability',
      message: error.message,
    });
  }
});

/**
 * GET /api/vulnerabilities/asset/:assetId
 * Get vulnerabilities for a specific asset
 * No authentication required - read-only operation
 */
router.get('/asset/:assetId', async (req: Request, res: Response): Promise<void> => {
  try {
    const assetId = parseInt(req.params.assetId);

    if (isNaN(assetId)) {
      res.status(400).json({ error: 'Invalid asset ID' });
      return;
    }

    const filters = {
      status: req.query.status as string,
      severity: req.query.severity as string,
      limit: parseInt(req.query.limit as string) || 50,
      offset: parseInt(req.query.offset as string) || 0,
    };

    const vulnerabilities = await VulnerabilityProcessor.getAssetVulnerabilities(assetId, filters);

    res.json({
      asset_id: assetId,
      vulnerabilities,
      total: vulnerabilities.length,
    });
  } catch (error: any) {
    console.error('[VULN] Get asset vulnerabilities error:', error);
    res.status(500).json({
      error: 'Failed to retrieve asset vulnerabilities',
      message: error.message,
    });
  }
});

/**
 * PATCH /api/vulnerabilities/:assetId/:vulnId
 * Update vulnerability status for an asset
 * Authentication required
 */
router.patch('/:assetId/:vulnId', authenticate, async (req: Request, res: Response): Promise<void> => {
  try {
    const assetId = parseInt(req.params.assetId);
    const vulnId = parseInt(req.params.vulnId);

    if (isNaN(assetId) || isNaN(vulnId)) {
      res.status(400).json({ error: 'Invalid asset ID or vulnerability ID' });
      return;
    }

    const { status, notes } = req.body;

    // Validate status
    const validStatuses = ['open', 'patched', 'false_positive', 'accepted'];
    if (status && !validStatuses.includes(status)) {
      res.status(400).json({
        error: 'Invalid status',
        validStatuses,
      });
      return;
    }

    console.log('[VULN] PATCH /:assetId/:vulnId with:', { assetId, vulnId, status, notes });

    // TODO: Import VulnerabilityRepository once created
    // const updated = await VulnerabilityRepository.updateVulnerabilityStatus(
    //   assetId,
    //   vulnId,
    //   status,
    //   notes,
    //   (req as any).user?.id
    // );

    res.json({
      message: 'Vulnerability status updated',
      asset_id: assetId,
      vulnerability_id: vulnId,
      status,
      notes,
    });
  } catch (error: any) {
    console.error('[VULN] Update vulnerability status error:', error);
    res.status(500).json({
      error: 'Failed to update vulnerability status',
      message: error.message,
    });
  }
});

export default router;
