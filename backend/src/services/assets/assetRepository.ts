/**
 * Asset Repository
 *
 * Database operations for asset discovery and management.
 * Handles CRUD operations for assets and their associated services.
 */

import pool from '../../config/database';
import { Asset, AssetService, AssetWithServices, AssetFilters, PaginatedAssets } from '../../models/Asset';

export class AssetRepository {
  /**
   * Get all assets with optional filtering and pagination
   */
  static async getAll(filters: AssetFilters = {}): Promise<PaginatedAssets> {
    try {
      const conditions: string[] = [];
      const params: any[] = [];
      let paramIndex = 1;

      // Build WHERE clause from filters
      if (filters.status) {
        conditions.push(`status = $${paramIndex++}`);
        params.push(filters.status);
      }

      if (filters.criticality) {
        conditions.push(`criticality = $${paramIndex++}`);
        params.push(filters.criticality);
      }

      if (filters.asset_type) {
        conditions.push(`asset_type = $${paramIndex++}`);
        params.push(filters.asset_type);
      }

      if (filters.search) {
        conditions.push(`(hostname ILIKE $${paramIndex} OR HOST(ip_address)::text LIKE $${paramIndex})`);
        params.push(`%${filters.search}%`);
        paramIndex++;
      }

      const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

      // Get total count
      const countQuery = `SELECT COUNT(*) as total FROM assets ${whereClause}`;
      const countResult = await pool.query(countQuery, params);
      const total = parseInt(countResult.rows[0].total, 10);

      // Get paginated results
      const limit = filters.limit || 50;
      const offset = filters.offset || 0;

      params.push(limit, offset);

      const query = `
        SELECT
          id,
          ip_address,
          hostname,
          mac_address,
          os_type,
          os_version,
          asset_type,
          criticality,
          status,
          discovery_method,
          first_seen,
          last_seen,
          last_scanned,
          metadata,
          tags,
          created_at,
          updated_at
        FROM assets
        ${whereClause}
        ORDER BY last_seen DESC
        LIMIT $${paramIndex++} OFFSET $${paramIndex++}
      `;

      const result = await pool.query(query, params);

      return {
        assets: result.rows,
        total,
        limit,
        offset,
        hasMore: offset + limit < total,
      };
    } catch (error) {
      console.error('Error fetching assets:', error);
      throw error;
    }
  }

  /**
   * Get asset by ID with its services
   */
  static async getById(id: number): Promise<AssetWithServices | null> {
    try {
      // Get asset
      const assetQuery = `
        SELECT
          id,
          ip_address,
          hostname,
          mac_address,
          os_type,
          os_version,
          asset_type,
          criticality,
          status,
          discovery_method,
          first_seen,
          last_seen,
          last_scanned,
          metadata,
          tags,
          created_at,
          updated_at
        FROM assets
        WHERE id = $1
      `;

      const assetResult = await pool.query(assetQuery, [id]);

      if (assetResult.rows.length === 0) {
        return null;
      }

      const asset = assetResult.rows[0];

      // Get services
      const services = await this.getServices(id);

      return {
        ...asset,
        services,
      };
    } catch (error) {
      console.error('Error fetching asset by ID:', error);
      throw error;
    }
  }

  /**
   * Get asset by IP address
   */
  static async getByIp(ipAddress: string): Promise<Asset | null> {
    try {
      const query = `
        SELECT
          id,
          ip_address,
          hostname,
          mac_address,
          os_type,
          os_version,
          asset_type,
          criticality,
          status,
          discovery_method,
          first_seen,
          last_seen,
          last_scanned,
          metadata,
          tags,
          created_at,
          updated_at
        FROM assets
        WHERE ip_address = $1
      `;

      const result = await pool.query(query, [ipAddress]);

      return result.rows.length > 0 ? result.rows[0] : null;
    } catch (error) {
      console.error('Error fetching asset by IP:', error);
      throw error;
    }
  }

  /**
   * Create or update asset (upsert on IP conflict)
   */
  static async create(asset: Partial<Asset>): Promise<Asset> {
    try {
      const query = `
        INSERT INTO assets (
          ip_address,
          hostname,
          mac_address,
          os_type,
          os_version,
          asset_type,
          criticality,
          status,
          discovery_method,
          first_seen,
          last_seen,
          metadata,
          tags
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW(), $10, $11)
        ON CONFLICT (ip_address) DO UPDATE SET
          hostname = COALESCE(EXCLUDED.hostname, assets.hostname),
          mac_address = COALESCE(EXCLUDED.mac_address, assets.mac_address),
          os_type = COALESCE(EXCLUDED.os_type, assets.os_type),
          os_version = COALESCE(EXCLUDED.os_version, assets.os_version),
          asset_type = COALESCE(EXCLUDED.asset_type, assets.asset_type),
          status = EXCLUDED.status,
          last_seen = NOW(),
          metadata = COALESCE(EXCLUDED.metadata, assets.metadata),
          tags = COALESCE(EXCLUDED.tags, assets.tags),
          updated_at = NOW()
        RETURNING
          id,
          ip_address,
          hostname,
          mac_address,
          os_type,
          os_version,
          asset_type,
          criticality,
          status,
          discovery_method,
          first_seen,
          last_seen,
          last_scanned,
          metadata,
          tags,
          created_at,
          updated_at
      `;

      const result = await pool.query(query, [
        asset.ip_address,
        asset.hostname || null,
        asset.mac_address || null,
        asset.os_type || null,
        asset.os_version || null,
        asset.asset_type || 'server',
        asset.criticality || 'medium',
        asset.status || 'active',
        asset.discovery_method || 'nmap',
        asset.metadata ? JSON.stringify(asset.metadata) : null,
        asset.tags || null,
      ]);

      return result.rows[0];
    } catch (error) {
      console.error('Error creating/updating asset:', error);
      throw error;
    }
  }

  /**
   * Update existing asset
   */
  static async update(id: number, updates: Partial<Asset>): Promise<Asset> {
    try {
      const fields: string[] = [];
      const params: any[] = [];
      let paramIndex = 1;

      // Build SET clause dynamically
      if (updates.hostname !== undefined) {
        fields.push(`hostname = $${paramIndex++}`);
        params.push(updates.hostname);
      }

      if (updates.mac_address !== undefined) {
        fields.push(`mac_address = $${paramIndex++}`);
        params.push(updates.mac_address);
      }

      if (updates.os_type !== undefined) {
        fields.push(`os_type = $${paramIndex++}`);
        params.push(updates.os_type);
      }

      if (updates.os_version !== undefined) {
        fields.push(`os_version = $${paramIndex++}`);
        params.push(updates.os_version);
      }

      if (updates.asset_type !== undefined) {
        fields.push(`asset_type = $${paramIndex++}`);
        params.push(updates.asset_type);
      }

      if (updates.criticality !== undefined) {
        fields.push(`criticality = $${paramIndex++}`);
        params.push(updates.criticality);
      }

      if (updates.status !== undefined) {
        fields.push(`status = $${paramIndex++}`);
        params.push(updates.status);
      }

      if (updates.metadata !== undefined) {
        fields.push(`metadata = $${paramIndex++}`);
        params.push(JSON.stringify(updates.metadata));
      }

      if (updates.tags !== undefined) {
        fields.push(`tags = $${paramIndex++}`);
        params.push(updates.tags);
      }

      if (fields.length === 0) {
        throw new Error('No fields to update');
      }

      fields.push(`updated_at = NOW()`);
      params.push(id);

      const query = `
        UPDATE assets
        SET ${fields.join(', ')}
        WHERE id = $${paramIndex}
        RETURNING
          id,
          ip_address,
          hostname,
          mac_address,
          os_type,
          os_version,
          asset_type,
          criticality,
          status,
          discovery_method,
          first_seen,
          last_seen,
          last_scanned,
          metadata,
          tags,
          created_at,
          updated_at
      `;

      const result = await pool.query(query, params);

      if (result.rows.length === 0) {
        throw new Error('Asset not found');
      }

      return result.rows[0];
    } catch (error) {
      console.error('Error updating asset:', error);
      throw error;
    }
  }

  /**
   * Delete asset (cascade to services)
   */
  static async delete(id: number): Promise<void> {
    try {
      const query = 'DELETE FROM assets WHERE id = $1';
      await pool.query(query, [id]);
    } catch (error) {
      console.error('Error deleting asset:', error);
      throw error;
    }
  }

  /**
   * Create or update service (upsert on asset_id, port, protocol)
   */
  static async upsertService(service: Partial<AssetService>): Promise<AssetService> {
    try {
      const query = `
        INSERT INTO asset_services (
          asset_id,
          port,
          protocol,
          service_name,
          service_version,
          state,
          banner,
          discovered_at,
          last_seen
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
        ON CONFLICT (asset_id, port, protocol) DO UPDATE SET
          service_name = COALESCE(EXCLUDED.service_name, asset_services.service_name),
          service_version = COALESCE(EXCLUDED.service_version, asset_services.service_version),
          state = EXCLUDED.state,
          banner = COALESCE(EXCLUDED.banner, asset_services.banner),
          last_seen = NOW()
        RETURNING
          id,
          asset_id,
          port,
          protocol,
          service_name,
          service_version,
          state,
          banner,
          discovered_at,
          last_seen,
          created_at
      `;

      const result = await pool.query(query, [
        service.asset_id,
        service.port,
        service.protocol || 'tcp',
        service.service_name || null,
        service.service_version || null,
        service.state || 'open',
        service.banner || null,
      ]);

      return result.rows[0];
    } catch (error) {
      console.error('Error upserting service:', error);
      throw error;
    }
  }

  /**
   * Get all services for an asset
   */
  static async getServices(assetId: number): Promise<AssetService[]> {
    try {
      const query = `
        SELECT
          id,
          asset_id,
          port,
          protocol,
          service_name,
          service_version,
          state,
          banner,
          discovered_at,
          last_seen,
          created_at
        FROM asset_services
        WHERE asset_id = $1
        ORDER BY port ASC
      `;

      const result = await pool.query(query, [assetId]);
      return result.rows;
    } catch (error) {
      console.error('Error fetching services:', error);
      throw error;
    }
  }

  /**
   * Update asset last_scanned timestamp
   */
  static async updateLastScanned(id: number): Promise<void> {
    try {
      const query = 'UPDATE assets SET last_scanned = NOW(), updated_at = NOW() WHERE id = $1';
      await pool.query(query, [id]);
    } catch (error) {
      console.error('Error updating last_scanned:', error);
      throw error;
    }
  }
}
