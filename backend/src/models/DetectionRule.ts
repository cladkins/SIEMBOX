import { query } from '../config/database';
import { invalidateAttackCoverage } from '../services/attack/coverageCache';

export interface DetectionRule {
  id: number;
  name: string;
  description: string | null;
  enabled: boolean;
  severity: 'low' | 'medium' | 'high' | 'critical';
  rule_yaml: string;
  rule_logic: any;
  tags: string[];
  /** SigmaHQ library provenance (migration 046); null for every other rule. */
  sigma_id?: string | null;
  sigma_release?: string | null;
  sigma_hash?: string | null;
  /** 1..N for the parts of a Sigma rule whose OR split into N rules. */
  sigma_part?: number | null;
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
  sigma_id?: string | null;
  sigma_release?: string | null;
  sigma_hash?: string | null;
  sigma_part?: number | null;
}

export class DetectionRuleModel {
  static async create(params: CreateDetectionRuleParams): Promise<DetectionRule> {
    const result = await query(
      `INSERT INTO detection_rules (name, description, enabled, severity, rule_yaml, rule_logic, tags,
                                    sigma_id, sigma_release, sigma_hash, sigma_part)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       RETURNING *`,
      [
        params.name,
        params.description ?? null,
        params.enabled ?? true,
        params.severity,
        params.rule_yaml,
        JSON.stringify(params.rule_logic),
        params.tags ?? [],
        params.sigma_id ?? null,
        params.sigma_release ?? null,
        params.sigma_hash ?? null,
        params.sigma_part ?? null,
      ]
    );
    invalidateAttackCoverage();
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

  /** The rules added from one SigmaHQ rule, in part order. */
  static async findBySigmaId(sigmaId: string): Promise<DetectionRule[]> {
    const result = await query('SELECT * FROM detection_rules WHERE sigma_id = $1 ORDER BY sigma_part ASC NULLS FIRST, id ASC', [
      sigmaId,
    ]);
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
    for (const key of ['sigma_id', 'sigma_release', 'sigma_hash', 'sigma_part'] as const) {
      if (params[key] !== undefined) {
        updates.push(`${key} = $${paramIndex++}`);
        values.push(params[key]);
      }
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
    // ATT&CK coverage depends on tags, conditions and enabled.
    invalidateAttackCoverage();
    return result.rows[0] || null;
  }

  static async delete(id: number): Promise<boolean> {
    const result = await query('DELETE FROM detection_rules WHERE id = $1', [id]);
    invalidateAttackCoverage();
    return (result.rowCount || 0) > 0;
  }
}
