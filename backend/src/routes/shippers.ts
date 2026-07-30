import { Router, Request, Response } from 'express';
import { LogShipperModel, ShipperSourceModel, ShipperVolumeModel, ShipperActivityModel, withHttpPushStatus } from '../models/LogShipper';
import { ApiError } from '../middleware/errorHandler';
import { query } from '../config/database';
import { logger } from '../utils/logger';
import crypto from 'crypto';
import { groupContainers, DockerContainer } from '../services/scanner/dockerDiscovery';
import { ShipperContainerModel } from '../models/ShipperContainer';
import { authenticate, authorize } from '../middleware/auth';
import { authenticateShipperPush } from '../middleware/shipperPushAuth';
import { sha256hex } from '../models/EdrAgent';
import { ingestPushedLogs, MAX_LOG_PUSH_BATCH_SIZE } from '../services/shippers/logPushService';

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
      ...withHttpPushStatus(shipper),
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
          LOWER(SUBSTRING(ENCODE(SHA256(decode(api_key, 'hex')), 'hex'), 1, 8)) AS sha256_id,
          LOWER(SUBSTRING(http_push_key_hash, 1, 8)) AS http_push_id
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
             OR LOWER(rl.shipper_id) = sh.http_push_id
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

    res.json(withHttpPushStatus(shipper));
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
// HTTP LOG-PUSH KEY MANAGEMENT (admin only — a key SEPARATE from the syslog
// api_key above, used only to authenticate POST /shippers/logs. The router as
// a whole isn't gated by app.ts, so these two routes gate themselves rather
// than inheriting the "no auth" posture the rest of this file has today.)
// ============================================================================

// Generate (or rotate) the HTTP push key. Returned once — never retrievable
// again, unlike the syslog api_key above.
router.post('/:id/http-push-key', authenticate, authorize('admin'), async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const shipper = await LogShipperModel.findById(id);
    if (!shipper) {
      throw new ApiError(404, 'Shipper not found');
    }

    const pushKey = generateApiKey();
    await LogShipperModel.setHttpPushKey(id, sha256hex(pushKey));
    await ShipperActivityModel.log(id, 'http_push_key_generated', 'HTTP log-push key (re)generated');

    res.json({ http_push_key: pushKey });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to generate HTTP push key');
  }
});

// Revoke the HTTP push key. Disables POST /shippers/logs for this shipper
// immediately (no "ghost shipper" grace period — that concept only applies
// to the syslog path, see CLAUDE.md).
router.delete('/:id/http-push-key', authenticate, authorize('admin'), async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const shipper = await LogShipperModel.findById(id);
    if (!shipper) {
      throw new ApiError(404, 'Shipper not found');
    }

    await LogShipperModel.revokeHttpPushKey(id);
    await ShipperActivityModel.log(id, 'http_push_key_revoked', 'HTTP log-push key revoked');

    res.json({ revoked: true });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to revoke HTTP push key');
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

    // Inject syslog settings at top level (not nested in config.config).
    // config is stripped of http_push_key_hash first — this is the shipper's
    // own record, but the hash still has no reason to leave the server.
    const fullConfig = {
      ...(config ? withHttpPushStatus(config) : config),
      ...syslogSettings,
    };

    res.json(fullConfig);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to register shipper');
  }
});

// Shipper reports the container images on its host (it mounts the Docker socket
// for log collection). SIEMBox stores them so they can be scanned (Trivy) like
// the SIEMBox host's own containers. Auth: the shipper API key (in the body).
router.post('/containers', async (req: Request, res: Response) => {
  try {
    const { api_key, containers, docker_available, docker_reason } = req.body ?? {};
    if (!api_key) throw new ApiError(400, 'API key is required');
    if (!Array.isArray(containers)) throw new ApiError(400, 'containers must be an array');

    const shipper = await LogShipperModel.findByApiKey(api_key);
    if (!shipper) throw new ApiError(404, 'Invalid API key');

    // A shipper with no Docker socket still reports (containers: [],
    // docker_available: false) so the operator sees "this host can't see
    // Docker" instead of an unexplained gap in the inventory. Older shippers
    // omit the flag entirely; treat those as available, which is what they
    // meant before the field existed.
    const dockerAvailable = docker_available !== false;
    const dockerReason =
      dockerAvailable ? null : String(docker_reason ?? 'Docker not reachable from the shipper').slice(0, 500);

    // Map the shipper's {image,name,image_id,running} items to the Docker socket
    // shape, then reuse the exact grouping + scannable logic the local discovery
    // uses. Cap the count so a bad/huge report can't blow up the insert.
    const mapped: DockerContainer[] = containers.slice(0, 2000).map((c: any) => ({
      Image: (c?.image ?? '').toString(),
      Names: [(c?.name ?? '').toString()],
      ImageID: (c?.image_id ?? '').toString(),
      State:
        c?.running === true ||
        c?.running === 'true' ||
        (c?.state ?? '').toString().toLowerCase() === 'running'
          ? 'running'
          : 'exited',
    }));
    const images = groupContainers(mapped);
    await ShipperContainerModel.replaceForShipper(shipper.id, images);
    await LogShipperModel.recordContainerReport(shipper.id, dockerAvailable, dockerReason).catch(
      () => {}
    );

    // A report is also a sign of life.
    const ip_address = req.ip || req.socket.remoteAddress || 'unknown';
    await LogShipperModel.updateHeartbeat(api_key, ip_address).catch(() => {});

    res.json({ stored: images.length });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to store shipper containers');
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

    // Inject syslog settings at top level (not nested in config.config).
    // config is stripped of http_push_key_hash first — this is the shipper's
    // own record, but the hash still has no reason to leave the server.
    const fullConfig = {
      ...(config ? withHttpPushStatus(config) : config),
      ...syslogSettings,
    };

    res.json(fullConfig);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to fetch configuration');
  }
});

// ============================================================================
// HTTP LOG-PUSH INGESTION (shipper push-key authenticated — see
// middleware/shipperPushAuth.ts. NOT JWT, NOT the syslog api_key above.)
// ============================================================================

// Accepts a single log ({"message": "..."}) or a batch ({"logs": [...]}).
// message must be the bare extracted message, not a syslog-framed line (see
// CLAUDE.md: "Parsers match only the extracted message"). One bad entry in a
// batch is counted in `rejected`, not a whole-request failure.
router.post('/logs', authenticateShipperPush, async (req: Request, res: Response) => {
  try {
    const shipper = req.pushShipper!;
    const body = req.body ?? {};

    let rawEntries: unknown[];
    if (Array.isArray(body.logs)) {
      rawEntries = body.logs;
    } else if (typeof body.message === 'string') {
      rawEntries = [body];
    } else {
      throw new ApiError(400, 'Body must be a single log object with "message", or { "logs": [...] }');
    }
    if (rawEntries.length === 0) {
      throw new ApiError(400, 'logs array is empty');
    }
    if (rawEntries.length > MAX_LOG_PUSH_BATCH_SIZE) {
      throw new ApiError(400, `Too many entries in one request (max ${MAX_LOG_PUSH_BATCH_SIZE})`);
    }

    const sourceIp = req.ip || req.socket.remoteAddress || 'unknown';
    const result = await ingestPushedLogs(shipper, rawEntries, sourceIp);
    await LogShipperModel.touchHttpPush(shipper.id, sourceIp).catch(() => {});

    res.status(202).json(result);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(500, 'Failed to ingest logs');
  }
});

export default router;
