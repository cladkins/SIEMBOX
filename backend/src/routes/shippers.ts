import { Router, Request, Response } from 'express';
import { LogShipperModel, ShipperSourceModel, ShipperVolumeModel, ShipperActivityModel } from '../models/LogShipper';
import { ApiError } from '../middleware/errorHandler';
import { query } from '../config/database';
import { logger } from '../utils/logger';
import crypto from 'crypto';

const router = Router();

// Generate API key for new shipper
function generateApiKey(): string {
  return crypto.randomBytes(32).toString('hex');
}

// Get syslog server settings from system_settings
async function getSyslogSettings(): Promise<{ siem_host: string; siem_port: number }> {
  try {
    const result = await query(
      `SELECT key, value FROM system_settings WHERE key IN ('syslog_host', 'syslog_port')`
    );

    const settings: { siem_host: string; siem_port: number } = {
      siem_host: '',
      siem_port: 514,
    };

    result.rows.forEach((row) => {
      if (row.key === 'syslog_host') {
        settings.siem_host = row.value;
      } else if (row.key === 'syslog_port') {
        settings.siem_port = parseInt(row.value, 10);
      }
    });

    return settings;
  } catch (error) {
    return { siem_host: '', siem_port: 514 };
  }
}

// Calculate shipper status based on last_seen timestamp
function calculateStatus(lastSeen: Date | null, currentStatus: string): 'pending' | 'online' | 'offline' | 'error' {
  if (!lastSeen) {
    return 'pending';
  }

  const now = new Date();
  const lastSeenTime = new Date(lastSeen);
  const minutesSinceLastSeen = (now.getTime() - lastSeenTime.getTime()) / 1000 / 60;

  // Consider offline if no heartbeat for 3 minutes (2x heartbeat interval + buffer)
  if (minutesSinceLastSeen > 3) {
    return 'offline';
  }

  return currentStatus === 'error' ? 'error' : 'online';
}

// Get all shippers
router.get('/', async (_req: Request, res: Response) => {
  try {
    const shippers = await LogShipperModel.findAll();

    // Calculate dynamic status based on last_seen
    const shippersWithStatus = shippers.map((shipper: any) => ({
      ...shipper,
      status: calculateStatus(shipper.last_seen, shipper.status)
    }));

    res.json(shippersWithStatus);
  } catch (error) {
    throw new ApiError(500, 'Failed to fetch shippers');
  }
});

// Get unknown sources (shipper IDs in raw_logs but not in log_shippers)
router.get('/unknown-sources', async (_req: Request, res: Response) => {
  try {
    // Query for shipper_ids in raw_logs that don't have a matching log_shipper
    // NOTE: API keys are stored as 64-char hex strings. We must use decode(api_key, 'hex')
    // to convert them to binary before hashing, matching the shipper script's behavior:
    // echo -n "$api_key" | xxd -r -p | sha256sum | cut -c1-8
    // Pre-compute each shipper's possible short IDs in a CTE. The WHERE filter
    // runs before the SELECT projection, so decode() only ever sees valid hex —
    // a single malformed api_key can no longer abort the whole query (#17).
    const result = await query(`
      WITH shipper_hashes AS (
        SELECT
          LOWER(SUBSTRING(MD5(decode(api_key, 'hex')), 1, 8)) AS md5_id,
          LOWER(SUBSTRING(ENCODE(SHA256(decode(api_key, 'hex')), 'hex'), 1, 8)) AS sha256_id
        FROM log_shippers
        WHERE api_key ~ '^([0-9a-fA-F]{2})+$'
      )
      SELECT
        rl.shipper_id,
        COUNT(*) as log_count,
        MIN(rl.created_at) as first_seen,
        MAX(rl.created_at) as last_seen,
        ARRAY_AGG(DISTINCT rl.source_ip) as source_ips,
        ARRAY_AGG(DISTINCT rl.hostname) as hostnames,
        ARRAY_AGG(DISTINCT rl.app_name) as app_names
      FROM raw_logs rl
      WHERE rl.shipper_id IS NOT NULL
        AND NOT EXISTS (
          SELECT 1 FROM shipper_hashes sh
          WHERE LOWER(rl.shipper_id) = sh.md5_id
             OR LOWER(rl.shipper_id) = sh.sha256_id
        )
      GROUP BY rl.shipper_id
      ORDER BY MAX(rl.created_at) DESC
    `);

    const unknownSources = result.rows.map((row: any) => ({
      shipper_id: row.shipper_id,
      log_count: parseInt(row.log_count, 10),
      first_seen: row.first_seen,
      last_seen: row.last_seen,
      source_ips: row.source_ips.filter((ip: string | null) => ip !== null),
      hostnames: row.hostnames.filter((h: string | null) => h !== null),
      app_names: row.app_names.filter((a: string | null) => a !== null),
    }));

    res.json(unknownSources);
  } catch (error) {
    logger.error('Failed to fetch unknown sources:', error);
    throw new ApiError(500, 'Failed to fetch unknown sources');
  }
});

// Get single shipper with full config
router.get('/:id', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const shipper = await LogShipperModel.getFullConfig(id);

    if (!shipper) {
      throw new ApiError(404, 'Shipper not found');
    }

    // Calculate dynamic status
    shipper.status = calculateStatus(shipper.last_seen, shipper.status);

    res.json(shipper);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to fetch shipper');
  }
});

// Create new shipper
router.post('/', async (req: Request, res: Response) => {
  try {
    const { name, description, hostname } = req.body;

    if (!name) {
      throw new ApiError(400, 'Shipper name is required');
    }

    const apiKey = generateApiKey();

    const shipper = await LogShipperModel.create({
      name,
      description,
      hostname,
      api_key: apiKey,
    });

    await ShipperActivityModel.log(shipper.id, 'created', 'Shipper created');

    res.status(201).json(shipper);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to create shipper');
  }
});

// Update shipper
router.put('/:id', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const updates = req.body;

    // Don't allow updating api_key directly
    delete updates.api_key;

    const shipper = await LogShipperModel.update(id, updates);

    if (!shipper) {
      throw new ApiError(404, 'Shipper not found');
    }

    await ShipperActivityModel.log(id, 'config_updated', 'Shipper configuration updated');

    res.json(shipper);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to update shipper');
  }
});

// Delete shipper
router.delete('/:id', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const deleted = await LogShipperModel.delete(id);

    if (!deleted) {
      throw new ApiError(404, 'Shipper not found');
    }

    res.json({ message: 'Shipper deleted successfully' });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to delete shipper');
  }
});

// Get shipper sources
router.get('/:id/sources', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const sources = await ShipperSourceModel.findByShipperId(id);
    res.json(sources);
  } catch (error) {
    throw new ApiError(500, 'Failed to fetch sources');
  }
});

// Add source to shipper
router.post('/:id/sources', async (req: Request, res: Response) => {
  try {
    const shipper_id = parseInt(req.params.id);
    const { source_type, enabled, file_path, container_name, journal_unit, tag, facility } = req.body;

    if (!source_type || !tag) {
      throw new ApiError(400, 'source_type and tag are required');
    }

    const source = await ShipperSourceModel.create({
      shipper_id,
      source_type,
      enabled,
      file_path,
      container_name,
      journal_unit,
      tag,
      facility: facility || 'local0',
    });

    await ShipperActivityModel.log(shipper_id, 'source_added', `Added ${source_type} source: ${tag}`);

    res.status(201).json(source);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to add source');
  }
});

// Update source
router.put('/sources/:sourceId', async (req: Request, res: Response) => {
  try {
    const sourceId = parseInt(req.params.sourceId);
    const updates = req.body;

    const source = await ShipperSourceModel.update(sourceId, updates);

    if (!source) {
      throw new ApiError(404, 'Source not found');
    }

    await ShipperActivityModel.log(source.shipper_id, 'source_updated', `Updated source: ${source.tag}`);

    res.json(source);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to update source');
  }
});

// Delete source
router.delete('/sources/:sourceId', async (req: Request, res: Response) => {
  try {
    const sourceId = parseInt(req.params.sourceId);
    const deleted = await ShipperSourceModel.delete(sourceId);

    if (!deleted) {
      throw new ApiError(404, 'Source not found');
    }

    res.json({ message: 'Source deleted successfully' });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to delete source');
  }
});

// Get shipper volumes
router.get('/:id/volumes', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const volumes = await ShipperVolumeModel.findByShipperId(id);
    res.json(volumes);
  } catch (error) {
    throw new ApiError(500, 'Failed to fetch volumes');
  }
});

// Add volume to shipper
router.post('/:id/volumes', async (req: Request, res: Response) => {
  try {
    const shipper_id = parseInt(req.params.id);
    const { host_path, container_path, read_only } = req.body;

    if (!host_path || !container_path) {
      throw new ApiError(400, 'host_path and container_path are required');
    }

    // Convert read_only boolean to mode string
    const mode = read_only === false ? 'rw' : 'ro';

    const volume = await ShipperVolumeModel.create({
      shipper_id,
      host_path,
      container_path,
      mode,
    });

    await ShipperActivityModel.log(shipper_id, 'volume_added', `Added volume: ${host_path}`);

    // Convert mode back to read_only for response
    const response = {
      ...volume,
      read_only: volume.mode === 'ro'
    };

    res.status(201).json(response);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to add volume');
  }
});

// Delete volume
router.delete('/volumes/:volumeId', async (req: Request, res: Response) => {
  try {
    const volumeId = parseInt(req.params.volumeId);
    const deleted = await ShipperVolumeModel.delete(volumeId);

    if (!deleted) {
      throw new ApiError(404, 'Volume not found');
    }

    res.json({ message: 'Volume deleted successfully' });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to delete volume');
  }
});

// Get shipper activity log
router.get('/:id/activity', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const limit = parseInt(req.query.limit as string) || 50;
    const activity = await ShipperActivityModel.getRecentActivity(id, limit);
    res.json(activity);
  } catch (error) {
    throw new ApiError(500, 'Failed to fetch activity');
  }
});

// Regenerate API key
router.post('/:id/regenerate-key', async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const newApiKey = generateApiKey();

    const shipper = await LogShipperModel.update(id, { api_key: newApiKey });

    if (!shipper) {
      throw new ApiError(404, 'Shipper not found');
    }

    await ShipperActivityModel.log(id, 'key_regenerated', 'API key regenerated');

    res.json({ api_key: newApiKey });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to regenerate API key');
  }
});

// ============================================================================
// PUBLIC ENDPOINTS (for shippers to call - no authentication required)
// ============================================================================

// Shipper heartbeat/registration
router.post('/register', async (req: Request, res: Response) => {
  try {
    const { api_key, version, hostname, metadata } = req.body;

    if (!api_key) {
      throw new ApiError(400, 'API key is required');
    }

    const shipper = await LogShipperModel.findByApiKey(api_key);

    if (!shipper) {
      throw new ApiError(404, 'Invalid API key');
    }

    const ip_address = req.ip || req.socket.remoteAddress || 'unknown';

    // Update shipper info
    await LogShipperModel.update(shipper.id, {
      version,
      hostname,
      metadata,
      ip_address,
      last_seen: new Date(),
      status: 'online',
    });

    // Return current configuration with syslog settings injected at top level
    const config = await LogShipperModel.getFullConfig(shipper.id);
    const syslogSettings = await getSyslogSettings();

    // Inject syslog settings at top level (not nested in config.config)
    const fullConfig = {
      ...config,
      ...syslogSettings,
    };

    res.json(fullConfig);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to register shipper');
  }
});

// Get shipper configuration (for shipper to poll)
router.get('/config/:api_key', async (req: Request, res: Response) => {
  try {
    const { api_key } = req.params;

    const shipper = await LogShipperModel.findByApiKey(api_key);

    if (!shipper) {
      throw new ApiError(404, 'Invalid API key');
    }

    // Update heartbeat
    const ip_address = req.ip || req.socket.remoteAddress || 'unknown';
    await LogShipperModel.updateHeartbeat(api_key, ip_address);

    // Get full configuration with syslog settings injected at top level
    const config = await LogShipperModel.getFullConfig(shipper.id);
    const syslogSettings = await getSyslogSettings();

    // Inject syslog settings at top level (not nested in config.config)
    const fullConfig = {
      ...config,
      ...syslogSettings,
    };

    res.json(fullConfig);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to fetch configuration');
  }
});

export default router;
