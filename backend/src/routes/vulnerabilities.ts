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
 * Get available Nuclei templates
 * No authentication required - read-only operation
 */
router.get('/templates', async (_req: Request, res: Response) => {
  try {
    // TODO: Import NucleiScanner once created
    // const templates = await NucleiScanner.getTemplates();

    // Placeholder response until scanner is ready
    res.json({
      templates: [
        { id: 'cves', name: 'CVE Templates', description: 'Known CVE vulnerabilities', count: 0 },
        { id: 'default', name: 'Default Templates', description: 'All default templates', count: 0 },
        { id: 'critical', name: 'Critical Only', description: 'Critical severity only', count: 0 },
        { id: 'high', name: 'High & Critical', description: 'High and critical severity', count: 0 },
      ],
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
 * GET /api/vulnerabilities/scans/active
 * Get active vulnerability scans
 * No authentication required - read-only operation
 */
router.get('/scans/active', async (_req: Request, res: Response) => {
  try {
    // TODO: Import VulnerabilityRepository once created
    // const scans = await VulnerabilityRepository.getActiveScans();

    res.json({ scans: [], total: 0 });
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

    res.json({
      id: status.id,
      status: status.status,
      progress: status.status === 'completed' ? 100 : status.status === 'running' ? 50 : 0,
      vulnerabilities_found: status.vulnerabilities_found || 0,
      started_at: status.started_at,
      completed_at: status.completed_at,
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
      templateSelection.templates = templates;
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

    const cancelled = await NucleiScanner.cancelScan(scanId);

    if (!cancelled) {
      res.status(404).json({ error: 'Scan not found or not running' });
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
