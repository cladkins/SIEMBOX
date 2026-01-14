import { query } from '../config/database';

export interface DetectionRule {
  id: number;
  name: string;
  description: string | null;
  enabled: boolean;
  severity: 'low' | 'medium' | 'high' | 'critical';
  rule_yaml: string;
  rule_logic: any;
  tags: string[];
  created_at: Date;
  updated_at: Date;
}

export interface CreateDetectionRuleParams {
  name: string;
  description?: string;
  enabled?: boolean;
  severity: 'low' | 'medium' | 'high' | 'critical';
  rule_yaml: string;
  rule_logic: any;
  tags?: string[];
}

export class DetectionRuleModel {
  static async create(params: CreateDetectionRuleParams): Promise<DetectionRule> {
    const result = await query(
      `INSERT INTO detection_rules (name, description, enabled, severity, rule_yaml, rule_logic, tags)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [
        params.name,
        params.description ?? null,
        params.enabled ?? true,
        params.severity,
        params.rule_yaml,
        JSON.stringify(params.rule_logic),
        params.tags ?? [],
      ]
    );

    return result.rows[0];
  }

  static async findById(id: number): Promise<DetectionRule | null> {
    const result = await query('SELECT * FROM detection_rules WHERE id = $1', [id]);
    return result.rows[0] || null;
  }

  static async findByName(name: string): Promise<DetectionRule | null> {
    const result = await query('SELECT * FROM detection_rules WHERE name = $1', [name]);
    return result.rows[0] || null;
  }

  static async findAll(): Promise<DetectionRule[]> {
    const result = await query('SELECT * FROM detection_rules ORDER BY id ASC');
    return result.rows;
  }

  static async findEnabled(): Promise<DetectionRule[]> {
    const result = await query('SELECT * FROM detection_rules WHERE enabled = true ORDER BY id ASC');
    return result.rows;
  }

  static async update(
    id: number,
    params: Partial<CreateDetectionRuleParams>
  ): Promise<DetectionRule | null> {
    const updates: string[] = [];
    const values: any[] = [];
    let paramIndex = 1;

    if (params.name !== undefined) {
      updates.push(`name = $${paramIndex++}`);
      values.push(params.name);
    }
    if (params.description !== undefined) {
      updates.push(`description = $${paramIndex++}`);
      values.push(params.description);
    }
    if (params.enabled !== undefined) {
      updates.push(`enabled = $${paramIndex++}`);
      values.push(params.enabled);
    }
    if (params.severity !== undefined) {
      updates.push(`severity = $${paramIndex++}`);
      values.push(params.severity);
    }
    if (params.rule_yaml !== undefined) {
      updates.push(`rule_yaml = $${paramIndex++}`);
      values.push(params.rule_yaml);
    }
    if (params.rule_logic !== undefined) {
      updates.push(`rule_logic = $${paramIndex++}`);
      values.push(JSON.stringify(params.rule_logic));
    }
    if (params.tags !== undefined) {
      updates.push(`tags = $${paramIndex++}`);
      values.push(params.tags);
    }

    if (updates.length === 0) {
      return this.findById(id);
    }

    updates.push(`updated_at = NOW()`);
    values.push(id);

    const result = await query(
      `UPDATE detection_rules SET ${updates.join(', ')} WHERE id = $${paramIndex} RETURNING *`,
      values
    );

    return result.rows[0] || null;
  }

  static async delete(id: number): Promise<boolean> {
    const result = await query('DELETE FROM detection_rules WHERE id = $1', [id]);
    return (result.rowCount || 0) > 0;
  }
}
