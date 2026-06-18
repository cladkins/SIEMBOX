import { query } from '../config/database';

export type NotificationChannelType = 'slack' | 'email' | 'ntfy';

export interface NotificationChannel {
  id: number;
  name: string;
  channel_type: NotificationChannelType;
  enabled: boolean;
  config: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface NotificationChannelInput {
  name: string;
  channel_type: NotificationChannelType;
  enabled?: boolean;
  config: Record<string, any>;
}

export const NotificationChannelModel = {
  async findAll(): Promise<NotificationChannel[]> {
    const result = await query(`SELECT * FROM notification_channels ORDER BY created_at DESC`);
    return result.rows;
  },

  async findEnabled(): Promise<NotificationChannel[]> {
    const result = await query(`SELECT * FROM notification_channels WHERE enabled = true`);
    return result.rows;
  },

  async findById(id: number): Promise<NotificationChannel | null> {
    const result = await query(`SELECT * FROM notification_channels WHERE id = $1`, [id]);
    return result.rows[0] || null;
  },

  async create(input: NotificationChannelInput): Promise<NotificationChannel> {
    const result = await query(
      `INSERT INTO notification_channels (name, channel_type, enabled, config)
       VALUES ($1, $2, COALESCE($3, true), $4)
       RETURNING *`,
      [input.name, input.channel_type, input.enabled ?? true, JSON.stringify(input.config || {})]
    );
    return result.rows[0];
  },

  async update(id: number, fields: Partial<NotificationChannelInput>): Promise<NotificationChannel | null> {
    const sets: string[] = [];
    const params: any[] = [];
    let i = 1;

    if (fields.name !== undefined) { sets.push(`name = $${i++}`); params.push(fields.name); }
    if (fields.channel_type !== undefined) { sets.push(`channel_type = $${i++}`); params.push(fields.channel_type); }
    if (fields.enabled !== undefined) { sets.push(`enabled = $${i++}`); params.push(fields.enabled); }
    if (fields.config !== undefined) { sets.push(`config = $${i++}`); params.push(JSON.stringify(fields.config)); }

    if (sets.length === 0) {
      return NotificationChannelModel.findById(id);
    }

    sets.push(`updated_at = NOW()`);
    params.push(id);

    const result = await query(
      `UPDATE notification_channels SET ${sets.join(', ')} WHERE id = $${i} RETURNING *`,
      params
    );
    return result.rows[0] || null;
  },

  async delete(id: number): Promise<boolean> {
    const result = await query(`DELETE FROM notification_channels WHERE id = $1`, [id]);
    return (result.rowCount || 0) > 0;
  },
};
