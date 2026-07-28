import pool from '../config/database';
import { query } from '../config/database';
import { DiscoveredImage } from '../services/scanner/dockerDiscovery';

/** A log-shipper host with the container images it reported. */
export interface ShipperHostInventory {
  shipper_id: number;
  name: string;
  hostname: string | null;
  version: string | null;
  last_seen: string | null;
  /** When this shipper last reported an inventory; null = never. */
  reported_at: string | null;
  /** Whether the shipper could reach Docker on its host; null = never reported. */
  docker_available: boolean | null;
  docker_reason: string | null;
  images: DiscoveredImage[];
}

export class ShipperContainerModel {
  /**
   * Replace a shipper's reported container inventory with `images` (a full
   * snapshot). Done in a transaction so a report is atomic.
   */
  static async replaceForShipper(shipperId: number, images: DiscoveredImage[]): Promise<void> {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('DELETE FROM shipper_containers WHERE shipper_id = $1', [shipperId]);
      for (const img of images) {
        await client.query(
          `INSERT INTO shipper_containers
             (shipper_id, image, image_id, container_names, running, scannable, reported_at)
           VALUES ($1, $2, $3, $4, $5, $6, NOW())
           ON CONFLICT (shipper_id, image) DO UPDATE SET
             image_id = EXCLUDED.image_id,
             container_names = EXCLUDED.container_names,
             running = EXCLUDED.running,
             scannable = EXCLUDED.scannable,
             reported_at = NOW()`,
          [
            shipperId,
            img.image.slice(0, 1024),
            (img.image_id || '').slice(0, 128),
            JSON.stringify(img.containers || []),
            img.running || 0,
            !!img.scannable,
          ]
        );
      }
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  }

  /**
   * All shipper-reported inventory, grouped by host (shipper).
   *
   * Starts from log_shippers, not shipper_containers: a shipper that reported
   * zero images still needs a row so the UI can explain WHY it contributed
   * nothing. Joining the other way round silently dropped exactly the hosts an
   * operator is trying to account for.
   */
  static async findGroupedByShipper(): Promise<ShipperHostInventory[]> {
    const result = await query(
      `SELECT ls.id AS shipper_id, ls.name, ls.hostname, ls.version, ls.last_seen,
              ls.containers_reported_at, ls.containers_available,
              ls.containers_unavailable_reason,
              sc.image, sc.image_id, sc.container_names, sc.running,
              sc.scannable, sc.reported_at
         FROM log_shippers ls
         LEFT JOIN shipper_containers sc ON sc.shipper_id = ls.id
        ORDER BY ls.name, sc.running DESC NULLS LAST, sc.image`
    );

    const byShipper = new Map<number, ShipperHostInventory>();
    for (const r of result.rows) {
      let host = byShipper.get(r.shipper_id);
      if (!host) {
        host = {
          shipper_id: r.shipper_id,
          name: r.name,
          hostname: r.hostname,
          version: r.version,
          last_seen: r.last_seen,
          reported_at: r.containers_reported_at,
          docker_available: r.containers_available,
          docker_reason: r.containers_unavailable_reason,
          images: [],
        };
        byShipper.set(r.shipper_id, host);
      }

      // LEFT JOIN: no shipper_containers row means this host reported nothing.
      if (!r.image) continue;
      // container_names is JSONB → already an array when read back.
      const names = Array.isArray(r.container_names) ? r.container_names : [];
      host.images.push({
        image: r.image,
        image_id: r.image_id || '',
        containers: names,
        running: r.running || 0,
        scannable: !!r.scannable,
      });
      // Track the most recent report time across the host's rows.
      if (r.reported_at && (!host.reported_at || r.reported_at > host.reported_at)) {
        host.reported_at = r.reported_at;
      }
    }
    return Array.from(byShipper.values());
  }
}
