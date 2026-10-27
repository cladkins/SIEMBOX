/**
 * Asset API Routes
 *
 * RESTful endpoints for asset discovery and management.
 * Includes CRUD operations, scanning, and statistics.
 *
 * Access: app.ts mounts this router behind `authenticate`, so every route
 * requires a login (the per-route `authenticate` on the write routes is
 * redundant but harmless). Reads are open to any role. Every write (create,
 * edit or delete an asset, POST /scan, POST /discover) requires admin, analyst
 * or operator: the roles that can open the Asset Inventory page
 * (frontend/src/router/index.ts), which is where the UI makes these calls.
 */

import express, { Request, Response } from 'express';
import { authenticate } from '../middleware/auth';
import { requireAssetScanPermission, requireScanPermission, UserRole } from '../middleware/scanPermissions';
import { AssetRepository } from '../services/assets/assetRepository';
import { NmapScanner, validateScanTargets } from '../services/scanner/nmapScanner';
import { auditPublicTargetConfirmation, enforcePublicTargets } from '../services/scanner/publicTargetGuard';
import { AutoDiscoveryService } from '../services/assets/autoDiscoveryService';
import { ScanRepository } from '../services/assets/scanRepository';
import { LogShipperModel } from '../models/LogShipper';
import { AssetStatus, AssetCriticality, AssetType } from '../models/Asset';
import { getAssetContext } from '../services/assets/assetContext';

const router = express.Router();

// Asset inventory writes: analyst or higher (admin, analyst, operator), with
// denials written to audit_logs. POST /scan and POST /discover use the same
// level through requireAssetScanPermission.
const requireAssetWrite = requireScanPermission(UserRole.Analyst, 'asset');

/**
 * GET /api/assets
 * Get all assets with filtering and pagination
 * Any logged-in role (read-only).
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
 * Any logged-in role (read-only).
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
 * Any logged-in role (read-only).
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
 * Any logged-in role (read-only).
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
 * Any logged-in role (read-only).
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
 * Any logged-in role (read-only).
 */
router.get('/scans/:scanId', async (req: Request, res: Response): Promise<void> => {
  try {
    console.log('[ASSETS] GET /scans/:scanId route hit with param:', req.params.scanId, 'query:', req.query);
    const scanId = parseInt(req.params.scanId as string);

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
 * Any logged-in role (read-only).
 */
router.get('/:id', async (req: Request, res: Response): Promise<void> => {
  try {
    const assetId = parseInt(req.params.id as string);

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
 * Any logged-in role (read-only), like the sibling GET /:id.
 */
router.get('/:id/related', async (req: Request, res: Response): Promise<void> => {
  try {
    const assetId = parseInt(req.params.id as string);

    if (isNaN(assetId)) {
      res.status(400).json({ error: 'Invalid asset ID' });
      return;
    }

    const context = await getAssetContext(assetId);
    if (!context) {
      res.status(404).json({ error: 'Asset not found' });
      return;
    }

    res.json(context);
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
 * Admin, analyst or operator.
 */
router.post('/', authenticate, requireAssetWrite, async (req: Request, res: Response): Promise<void> => {
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
 * Admin, analyst or operator.
 */
router.put('/:id', authenticate, requireAssetWrite, async (req: Request, res: Response): Promise<void> => {
  try {
    const assetId = parseInt(req.params.id as string);

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
 * Admin, analyst or operator (Asset Inventory's Delete button).
 */
router.delete('/:id', authenticate, requireAssetWrite, async (req: Request, res: Response): Promise<void> => {
  try {
    const assetId = parseInt(req.params.id as string);

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
 * Any logged-in role (read-only).
 */
router.get('/:id/services', async (req: Request, res: Response): Promise<void> => {
  try {
    const assetId = parseInt(req.params.id as string);

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
 *
 * Requires authentication plus the admin/analyst/operator roles the frontend
 * already restricts the "Trigger Scan" button to (see `canTriggerScans` in
 * frontend/src/views/Assets.vue; requireAssetScanPermission is analyst or
 * higher) -- this route used to have no auth check at all. `targets` is
 * validated against validateScanTargets() before it goes
 * anywhere near nmap: node-nmap builds its argv by splitting the joined
 * target string on whitespace before spawning the real `nmap` binary, so an
 * unvalidated target containing a space could carry extra nmap flags through
 * to that (root, in the container) process -- including ones that read or
 * write files. A target in public address space (outside RFC 1918 and the
 * other private/reserved ranges) is refused with a 400 naming it unless the
 * body carries allow_public_targets: true (services/scanner/publicTargetGuard.ts).
 */
router.post(
  '/scan',
  authenticate,
  requireAssetScanPermission,
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { targets, scanType, description } = req.body;

      const targetError = validateScanTargets(targets);
      if (targetError) {
        res.status(400).json({ error: targetError });
        return;
      }

      // Public address space is refused unless the request confirms it
      // (allow_public_targets: true): see services/scanner/publicTargetGuard.ts.
      const publicCheck = enforcePublicTargets(targets, req, res);
      if (!publicCheck) return;

      // Optional: run this scan from a log shipper out on the LAN instead of on
      // the backend (whose nmap can't see the real network from inside the
      // Docker bridge). Accept either spelling from the client. When set, the
      // shipper must exist -- otherwise the scan would queue forever with no one
      // to claim it -- so validate here and 400 rather than relying on the FK.
      const rawShipperId = req.body.assignedShipperId ?? req.body.assigned_shipper_id;
      let assignedShipperId: number | undefined;
      if (rawShipperId !== undefined && rawShipperId !== null && rawShipperId !== '') {
        assignedShipperId = Number(rawShipperId);
        if (!Number.isInteger(assignedShipperId) || assignedShipperId <= 0) {
          res.status(400).json({ error: 'assignedShipperId must be a positive integer' });
          return;
        }
        const shipper = await LogShipperModel.findById(assignedShipperId);
        if (!shipper) {
          res.status(400).json({ error: `No log shipper with id ${assignedShipperId}` });
          return;
        }
      }

      console.log(`[ASSETS] POST /scan - received body:`, JSON.stringify(req.body));
      console.log(`[ASSETS] Targets:`, JSON.stringify(targets), `Type:`, typeof targets);

      const scanId = await NmapScanner.scan({
        targets,
        scanType: scanType || 'port',
        userId: req.user!.id,
        description,
        assignedShipperId,
        origin: { page: 'assets' },
        publicTargetsConfirmation: publicCheck.confirmation,
      });
      await auditPublicTargetConfirmation(req, publicCheck.confirmation, { type: 'scan', id: scanId, targets });

      res.status(202).json({
        message: assignedShipperId
          ? 'Scan queued for log shipper'
          : 'Scan initiated successfully',
        scanId,
        status: 'queued',
        assignedShipperId: assignedShipperId ?? null,
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
 *
 * Admin, analyst or operator, like the other asset writes. This duplicates on
 * demand what the scheduled auto-discovery job (jobs/autoDiscovery.ts) already
 * runs on its own -- it has no frontend caller -- but as a mutating endpoint it
 * shouldn't be triggerable by anyone who can merely reach the API.
 */
router.post('/discover', authenticate, requireAssetScanPermission, async (_req: Request, res: Response) => {
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
