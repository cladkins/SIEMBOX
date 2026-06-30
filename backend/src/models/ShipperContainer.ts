import pool from '../config/database';
import { query } from '../config/database';
import { DiscoveredImage } from '../services/scanner/dockerDiscovery';

/** A log-shipper host with the container images it reported. */
export interface ShipperHostInventory {
  shipper_id: number;
  name: string;
  hostname: string | null;
  reported_at: string | null;
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

  /** All shipper-reported inventory, grouped by host (shipper). */
  static async findGroupedByShipper(): Promise<ShipperHostInventory[]> {
    const result = await query(
      `SELECT sc.shipper_id, sc.image, sc.image_id, sc.container_names, sc.running,
              sc.scannable, sc.reported_at, ls.name, ls.hostname
         FROM shipper_containers sc
         JOIN log_shippers ls ON ls.id = sc.shipper_id
        ORDER BY ls.name, sc.running DESC, sc.image`
    );

    const byShipper = new Map<number, ShipperHostInventory>();
    for (const r of result.rows) {
      let host = byShipper.get(r.shipper_id);
      if (!host) {
        host = {
          shipper_id: r.shipper_id,
          name: r.name,
          hostname: r.hostname,
          reported_at: r.reported_at,
          images: [],
        };
        byShipper.set(r.shipper_id, host);
      }
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
