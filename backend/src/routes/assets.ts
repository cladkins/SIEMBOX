/**
 * Asset API Routes
 *
 * RESTful endpoints for asset discovery and management.
 * Includes CRUD operations, scanning, and statistics.
 */

import express, { Request, Response } from 'express';
import { authenticate } from '../middleware/auth';
import { AssetRepository } from '../services/assets/assetRepository';
import { NmapScanner } from '../services/scanner/nmapScanner';
import { AutoDiscoveryService } from '../services/assets/autoDiscoveryService';
import { ScanRepository } from '../services/assets/scanRepository';
import { AssetStatus, AssetCriticality, AssetType } from '../models/Asset';
import { query } from '../config/database';
import { VulnerabilityRepository } from '../services/vulnerabilities/vulnerabilityRepository';
import { geoipService } from '../services/geoip/geoipService';
import { OFFLINE_THRESHOLD_MINUTES } from '../models/EdrAgent';

const router = express.Router();

/**
 * GET /api/assets
 * Get all assets with filtering and pagination
 * No authentication required - read-only operation
 */
router.get('/', async (req: Request, res: Response) => {
  try {
    const filters = {
      status: req.query.status as AssetStatus | undefined,
      criticality: req.query.criticality as AssetCriticality | undefined,
      asset_type: req.query.asset_type as AssetType | undefined,
      search: req.query.search as string | undefined,
      limit: req.query.limit ? parseInt(req.query.limit as string) : 50,
      offset: req.query.offset ? parseInt(req.query.offset as string) : 0,
    };

    const result = await AssetRepository.getAll(filters);

    res.json({
      assets: result.assets,
      total: result.total,
      limit: filters.limit,
      offset: filters.offset,
      hasMore: filters.offset + filters.limit < result.total,
    });
  } catch (error: any) {
    console.error('Get assets error:', error);
    res.status(500).json({
      error: 'Failed to retrieve assets',
      message: error.message,
    });
  }
});

/**
 * GET /api/assets/statistics
 * Get asset discovery statistics
 * No authentication required - read-only operation
 */
router.get('/statistics', async (_req: Request, res: Response) => {
  try {
    const stats = await AutoDiscoveryService.getStatistics();
    res.json(stats);
  } catch (error: any) {
    console.error('Get statistics error:', error);
    res.status(500).json({
      error: 'Failed to retrieve statistics',
      message: error.message,
    });
  }
});

/**
 * GET /api/assets/scans/active
 * Get active asset discovery scans (queued or running)
 * Excludes vulnerability scans - those are shown on the Vulnerability Scanning page
 * No authentication required - read-only operation for system visibility
 */
router.get('/scans/active', async (_req: Request, res: Response) => {
  try {
    // Exclude vulnerability scans - they should only appear on the Vulnerability Scanning page
    const scans = await ScanRepository.getActiveScans(['vulnerability']);
    res.json({ scans, total: scans.length });
  } catch (error: any) {
    console.error('Get active scans error:', error);
    res.status(500).json({
      error: 'Failed to retrieve active scans',
      message: error.message,
    });
  }
});

/**
 * GET /api/assets/scans/statistics
 * Get scan statistics
 * No authentication required - read-only operation for system visibility
 */
router.get('/scans/statistics', async (_req: Request, res: Response) => {
  try {
    const stats = await ScanRepository.getStatistics();
    res.json(stats);
  } catch (error: any) {
    console.error('Get scan statistics error:', error);
    res.status(500).json({
      error: 'Failed to retrieve scan statistics',
      message: error.message,
    });
  }
});

/**
 * GET /api/assets/scans
 * Get asset discovery scans with filtering and pagination
 * Excludes vulnerability scans by default - those are shown on the Vulnerability Scanning page
 * IMPORTANT: Must come BEFORE /scans/:scanId to prevent route conflicts
 * Query parameters should not be interpreted as path parameters
 * No authentication required - read-only operation for system visibility
 */
router.get('/scans', async (req: Request, res: Response) => {
  try {
    console.log('[ASSETS] GET /scans route hit with query:', req.query);

    const filters = {
      status: req.query.status as string,
      scan_type: req.query.scan_type as string,
      limit: parseInt(req.query.limit as string) || 50,
      offset: parseInt(req.query.offset as string) || 0,
      excludeTypes: ['vulnerability'], // Exclude vulnerability scans on the assets page
    };

    const result = await ScanRepository.getScans(filters);

    res.json({
      scans: result.scans,
      total: result.total,
      limit: filters.limit,
      offset: filters.offset,
      hasMore: filters.offset + filters.limit < result.total,
    });
  } catch (error: any) {
    console.error('Get scans error:', error);
    res.status(500).json({
      error: 'Failed to retrieve scans',
      message: error.message,
    });
  }
});

/**
 * GET /api/assets/scans/:scanId
 * Get scan status and results
 * IMPORTANT: Must come AFTER /scans and /scans/active and /scans/statistics
 * More specific routes must be defined first to avoid catching them as parameters
 * No authentication required - read-only operation for system visibility
 */
router.get('/scans/:scanId', async (req: Request, res: Response): Promise<void> => {
  try {
    console.log('[ASSETS] GET /scans/:scanId route hit with param:', req.params.scanId, 'query:', req.query);
    const scanId = parseInt(req.params.scanId);

    if (isNaN(scanId)) {
      console.log('[ASSETS] Invalid scanId, returning 400');
      res.status(400).json({ error: 'Invalid scan ID' });
      return;
    }

    const scan = await ScanRepository.getScanById(scanId);

    if (!scan) {
      res.status(404).json({ error: 'Scan not found' });
      return;
    }

    res.json(scan);
  } catch (error: any) {
    console.error('Get scan error:', error);
    res.status(500).json({
      error: 'Failed to retrieve scan',
      message: error.message,
    });
  }
});

/**
 * GET /api/assets/:id
 * Get asset by ID with services
 * IMPORTANT: Must come AFTER all /scans routes to prevent catching "scans" as an asset ID
 * No authentication required - read-only operation
 */
router.get('/:id', async (req: Request, res: Response): Promise<void> => {
  try {
    const assetId = parseInt(req.params.id);

    if (isNaN(assetId)) {
      res.status(400).json({ error: 'Invalid asset ID' });
      return;
    }

    const asset = await AssetRepository.getById(assetId);

    if (!asset) {
      res.status(404).json({ error: 'Asset not found' });
      return;
    }

    res.json(asset);
  } catch (error: any) {
    console.error('Get asset error:', error);
    res.status(500).json({
      error: 'Failed to retrieve asset',
      message: error.message,
    });
  }
});

/**
 * GET /api/assets/:id/related
 * Asset-360: everything correlated to this asset in one call —
 *   - agent          the EDR endpoint agent reporting on this asset (if any)
 *   - shipper        the log shipper matched by hostname/IP (if any)
 *   - geo            GeoIP country for the asset's IP (null for private IPs)
 *   - vulnerabilities the asset's open/closed findings (nested vuln shape)
 *   - alerts         alerts linked by asset_id OR whose source_ip matches the IP
 * No authentication required - read-only, consistent with the sibling GET /:id.
 */
router.get('/:id/related', async (req: Request, res: Response): Promise<void> => {
  try {
    const assetId = parseInt(req.params.id);

    if (isNaN(assetId)) {
      res.status(400).json({ error: 'Invalid asset ID' });
      return;
    }

    const asset = await AssetRepository.getById(assetId);
    if (!asset) {
      res.status(404).json({ error: 'Asset not found' });
      return;
    }

    const ip = asset.ip_address ? String(asset.ip_address) : null;
    const hostname = asset.hostname || null;

    // Run the independent lookups concurrently.
    const [agentResult, shipperResult, alertsResult, vulnerabilities] = await Promise.all([
      // EDR agent reporting on this asset (never expose the api key hash).
      query(
        `SELECT agent_id, asset_id, hostname, os, os_version, arch, agent_version, ip,
                status, config_version, last_seen, created_at,
                (last_seen IS NOT NULL
                   AND last_seen > NOW() - ($2::int * INTERVAL '1 minute'))
                  AS online
           FROM edr_agents
          WHERE asset_id = $1
          ORDER BY last_seen DESC NULLS LAST
          LIMIT 1`,
        [assetId, OFFLINE_THRESHOLD_MINUTES]
      ),
      // Log shipper matched by hostname or IP.
      query(
        `SELECT id, name, status, version, last_seen, ip_address, hostname
           FROM log_shippers
          WHERE ($1::text IS NOT NULL AND hostname = $1)
             OR ($2::text IS NOT NULL AND ip_address = $2)
          ORDER BY last_seen DESC NULLS LAST
          LIMIT 1`,
        [hostname, ip]
      ),
      // Alerts linked to the asset, or whose extracted source_ip matches the IP.
      query(
        `SELECT id, rule_id, severity, title, description, status, source, event_id,
                matched_data, created_at
           FROM alerts
          WHERE asset_id = $1
             OR ($2::text IS NOT NULL AND matched_data->>'source_ip' = $2)
          ORDER BY created_at DESC
          LIMIT 100`,
        [assetId, ip]
      ),
      // Reuse the existing nested asset-vuln shape (vulnerability.* fields).
      VulnerabilityRepository.getAssetVulnerabilities(assetId),
    ]);

    res.json({
      agent: agentResult.rows[0] || null,
      shipper: shipperResult.rows[0] || null,
      geo: ip ? geoipService.lookup(ip) : null,
      vulnerabilities,
      alerts: alertsResult.rows,
    });
  } catch (error: any) {
    console.error('Get related asset data error:', error);
    res.status(500).json({
      error: 'Failed to retrieve related asset data',
      message: error.message,
    });
  }
});

/**
 * POST /api/assets
 * Create or update asset manually
 */
router.post('/', authenticate, async (req: Request, res: Response): Promise<void> => {
  try {
    // Validate required fields
    if (!req.body.ip_address) {
      res.status(400).json({ error: 'IP address is required' });
      return;
    }

    const asset = await AssetRepository.create({
      ...req.body,
      discovery_method: 'manual',
    });

    res.status(201).json(asset);
  } catch (error: any) {
    console.error('Create asset error:', error);
    res.status(500).json({
      error: 'Failed to create asset',
      message: error.message,
    });
  }
});

/**
 * PUT /api/assets/:id
 * Update existing asset
 */
router.put('/:id', authenticate, async (req: Request, res: Response): Promise<void> => {
  try {
    const assetId = parseInt(req.params.id);

    if (isNaN(assetId)) {
      res.status(400).json({ error: 'Invalid asset ID' });
      return;
    }

    // Verify asset exists
    const existingAsset = await AssetRepository.getById(assetId);
    if (!existingAsset) {
      res.status(404).json({ error: 'Asset not found' });
      return;
    }

    const updatedAsset = await AssetRepository.update(assetId, req.body);

    res.json(updatedAsset);
  } catch (error: any) {
    console.error('Update asset error:', error);
    res.status(500).json({
      error: 'Failed to update asset',
      message: error.message,
    });
  }
});

/**
 * DELETE /api/assets/:id
 * Delete asset
 */
router.delete('/:id', authenticate, async (req: Request, res: Response): Promise<void> => {
  try {
    const assetId = parseInt(req.params.id);

    if (isNaN(assetId)) {
      res.status(400).json({ error: 'Invalid asset ID' });
      return;
    }

    // Verify asset exists
    const existingAsset = await AssetRepository.getById(assetId);
    if (!existingAsset) {
      res.status(404).json({ error: 'Asset not found' });
      return;
    }

    await AssetRepository.delete(assetId);

    res.status(204).send();
  } catch (error: any) {
    console.error('Delete asset error:', error);
    res.status(500).json({
      error: 'Failed to delete asset',
      message: error.message,
    });
  }
});

/**
 * GET /api/assets/:id/services
 * Get services for an asset
 * No authentication required - read-only operation
 */
router.get('/:id/services', async (req: Request, res: Response): Promise<void> => {
  try {
    const assetId = parseInt(req.params.id);

    if (isNaN(assetId)) {
      res.status(400).json({ error: 'Invalid asset ID' });
      return;
    }

    const services = await AssetRepository.getServices(assetId);

    res.json({ services });
  } catch (error: any) {
    console.error('Get services error:', error);
    res.status(500).json({
      error: 'Failed to retrieve services',
      message: error.message,
    });
  }
});

/**
 * POST /api/assets/scan
 * Trigger asset discovery scan
 * No authentication required
 */
router.post(
  '/scan',
  async (req: Request, res: Response) => {
    try {
      const { targets, scanType, description } = req.body;

      console.log(`[ASSETS] POST /scan - received body:`, JSON.stringify(req.body));
      console.log(`[ASSETS] Targets:`, JSON.stringify(targets), `Type:`, typeof targets);

      const scanId = await NmapScanner.scan({
        targets,
        scanType: scanType || 'port',
        userId: 1, // Default to admin user for system scans
        description,
      });

      res.status(202).json({
        message: 'Scan initiated successfully',
        scanId,
        status: 'queued',
      });
    } catch (error: any) {
      console.error('Scan initiation error:', error);
      res.status(500).json({
        error: 'Failed to initiate scan',
        message: error.message,
      });
    }
  }
);

/**
 * POST /api/assets/discover
 * Trigger auto-discovery from logs
 * No authentication required
 */
router.post('/discover', async (_req: Request, res: Response) => {
  try {
    const result = await AutoDiscoveryService.runFullDiscovery();

    res.json({
      message: 'Auto-discovery completed',
      discovered: result.discovered,
      staleMarked: result.staleMarked,
      enriched: result.enriched,
    });
  } catch (error: any) {
    console.error('Auto-discovery error:', error);
    res.status(500).json({
      error: 'Failed to run auto-discovery',
      message: error.message,
    });
  }
});

export default router;
