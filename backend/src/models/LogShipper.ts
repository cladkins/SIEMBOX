import pool from '../config/database';

export interface LogShipper {
  id: number;
  name: string;
  description: string | null;
  api_key: string;
  status: 'pending' | 'online' | 'offline' | 'error';
  version: string | null;
  last_seen: Date | null;
  ip_address: string | null;
  hostname: string | null;
  config: any;
  metadata: any;
  created_at: Date;
  updated_at: Date;
}

export interface ShipperSource {
  id: number;
  shipper_id: number;
  source_type: 'file' | 'docker' | 'journal';
  enabled: boolean;
  file_path: string | null;
  container_name: string | null;
  journal_unit: string | null;
  tag: string;
  facility: string;
  created_at: Date;
  updated_at: Date;
}

export interface ShipperVolume {
  id: number;
  shipper_id: number;
  host_path: string;
  container_path: string;
  mode: 'ro' | 'rw';
  created_at: Date;
}

export interface ShipperFullConfig extends LogShipper {
  sources: ShipperSource[];
  volumes: ShipperVolume[];
  siem_host?: string;
  siem_port?: number;
}

export class LogShipperModel {
  // Create a new shipper
  static async create(shipper: Partial<LogShipper>): Promise<LogShipper> {
    const { name, description, api_key, hostname } = shipper;
    const result = await pool.query(
      `INSERT INTO log_shippers (name, description, api_key, hostname)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [name, description, api_key, hostname]
    );
    return result.rows[0];
  }

  // Find all shippers with sources count
  static async findAll(): Promise<any[]> {
    const result = await pool.query(
      `SELECT
        ls.*,
        (SELECT COUNT(*) FROM shipper_sources WHERE shipper_id = ls.id) as sources_count
       FROM log_shippers ls
       ORDER BY ls.created_at DESC`
    );

    // Convert sources_count to sources array for consistency with frontend
    return result.rows.map(shipper => ({
      ...shipper,
      sources: Array(parseInt(shipper.sources_count, 10)).fill(null)
    }));
  }

  // Find shipper by ID
  static async findById(id: number): Promise<LogShipper | null> {
    const result = await pool.query(
      'SELECT * FROM log_shippers WHERE id = $1',
      [id]
    );
    return result.rows[0] || null;
  }

  // Find shipper by API key
  static async findByApiKey(apiKey: string): Promise<LogShipper | null> {
    const result = await pool.query(
      'SELECT * FROM log_shippers WHERE api_key = $1',
      [apiKey]
    );
    return result.rows[0] || null;
  }

  // Update shipper
  static async update(id: number, updates: Partial<LogShipper>): Promise<LogShipper | null> {
    const fields = [];
    const values = [];
    let paramCount = 1;

    for (const [key, value] of Object.entries(updates)) {
      if (key !== 'id' && key !== 'created_at') {
        fields.push(`${key} = $${paramCount}`);
        values.push(value);
        paramCount++;
      }
    }

    if (fields.length === 0) return null;

    fields.push('updated_at = NOW()');
    values.push(id);

    const result = await pool.query(
      `UPDATE log_shippers SET ${fields.join(', ')} WHERE id = $${paramCount} RETURNING *`,
      values
    );
    return result.rows[0] || null;
  }

  // Update last seen (heartbeat)
  static async updateHeartbeat(apiKey: string, ipAddress: string): Promise<void> {
    await pool.query(
      `UPDATE log_shippers
       SET last_seen = NOW(), status = 'online', ip_address = $2
       WHERE api_key = $1`,
      [apiKey, ipAddress]
    );
  }

  // Delete shipper
  static async delete(id: number): Promise<boolean> {
    const result = await pool.query(
      'DELETE FROM log_shippers WHERE id = $1',
      [id]
    );
    return result.rowCount! > 0;
  }

  // Get shipper with sources and volumes
  static async getFullConfig(id: number): Promise<ShipperFullConfig | null> {
    const shipper = await this.findById(id);
    if (!shipper) return null;

    const sources = await ShipperSourceModel.findByShipperId(id);
    const volumes = await ShipperVolumeModel.findByShipperId(id);

    return {
      ...shipper,
      sources,
      volumes,
    };
  }
}

export class ShipperSourceModel {
  // Create source
  static async create(source: Partial<ShipperSource>): Promise<ShipperSource> {
    const { shipper_id, source_type, enabled, file_path, container_name, journal_unit, tag, facility } = source;
    const result = await pool.query(
      `INSERT INTO shipper_sources
       (shipper_id, source_type, enabled, file_path, container_name, journal_unit, tag, facility)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING *`,
      [shipper_id, source_type, enabled, file_path, container_name, journal_unit, tag, facility]
    );
    return result.rows[0];
  }

  // Find sources by shipper ID
  static async findByShipperId(shipperId: number): Promise<ShipperSource[]> {
    const result = await pool.query(
      'SELECT * FROM shipper_sources WHERE shipper_id = $1 ORDER BY id',
      [shipperId]
    );
    return result.rows;
  }

  // Update source
  static async update(id: number, updates: Partial<ShipperSource>): Promise<ShipperSource | null> {
    const fields = [];
    const values = [];
    let paramCount = 1;

    for (const [key, value] of Object.entries(updates)) {
      if (key !== 'id' && key !== 'created_at') {
        fields.push(`${key} = $${paramCount}`);
        values.push(value);
        paramCount++;
      }
    }

    if (fields.length === 0) return null;

    fields.push('updated_at = NOW()');
    values.push(id);

    const result = await pool.query(
      `UPDATE shipper_sources SET ${fields.join(', ')} WHERE id = $${paramCount} RETURNING *`,
      values
    );
    return result.rows[0] || null;
  }

  // Delete source
  static async delete(id: number): Promise<boolean> {
    const result = await pool.query(
      'DELETE FROM shipper_sources WHERE id = $1',
      [id]
    );
    return result.rowCount! > 0;
  }

  // Delete all sources for a shipper
  static async deleteByShipperId(shipperId: number): Promise<void> {
    await pool.query(
      'DELETE FROM shipper_sources WHERE shipper_id = $1',
      [shipperId]
    );
  }
}

export class ShipperVolumeModel {
  // Create volume
  static async create(volume: Partial<ShipperVolume>): Promise<ShipperVolume> {
    const { shipper_id, host_path, container_path, mode } = volume;
    const result = await pool.query(
      `INSERT INTO shipper_volumes (shipper_id, host_path, container_path, mode)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [shipper_id, host_path, container_path, mode]
    );
    return result.rows[0];
  }

  // Find volumes by shipper ID
  static async findByShipperId(shipperId: number): Promise<any[]> {
    const result = await pool.query(
      'SELECT * FROM shipper_volumes WHERE shipper_id = $1 ORDER BY id',
      [shipperId]
    );
    // Convert mode to read_only for frontend compatibility
    return result.rows.map(volume => ({
      ...volume,
      read_only: volume.mode === 'ro'
    }));
  }

  // Delete volume
  static async delete(id: number): Promise<boolean> {
    const result = await pool.query(
      'DELETE FROM shipper_volumes WHERE id = $1',
      [id]
    );
    return result.rowCount! > 0;
  }

  // Delete all volumes for a shipper
  static async deleteByShipperId(shipperId: number): Promise<void> {
    await pool.query(
      'DELETE FROM shipper_volumes WHERE shipper_id = $1',
      [shipperId]
    );
  }
}

export class ShipperActivityModel {
  // Log activity
  static async log(shipperId: number, activityType: string, message: string, metadata: any = {}): Promise<void> {
    await pool.query(
      `INSERT INTO shipper_activity (shipper_id, activity_type, message, metadata)
       VALUES ($1, $2, $3, $4)`,
      [shipperId, activityType, message, JSON.stringify(metadata)]
    );
  }

  // Get recent activity for shipper
  static async getRecentActivity(shipperId: number, limit: number = 50): Promise<any[]> {
    const result = await pool.query(
      `SELECT * FROM shipper_activity
       WHERE shipper_id = $1
       ORDER BY created_at DESC
       LIMIT $2`,
      [shipperId, limit]
    );
    return result.rows;
  }
}
