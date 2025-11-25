import { query } from '../config/database';

export interface Parser {
  id: number;
  name: string;
  description: string | null;
  enabled: boolean;
  priority: number;
  parser_type: 'regex' | 'grok' | 'json';
  pattern: string;
  field_mappings: Record<string, string>;
  test_samples: any[] | null;
  created_at: Date;
  updated_at: Date;
}

export interface CreateParserParams {
  name: string;
  description?: string;
  enabled?: boolean;
  priority?: number;
  parser_type: 'regex' | 'grok' | 'json';
  pattern: string;
  field_mappings: Record<string, string>;
  test_samples?: any[];
}

export class ParserModel {
  static async create(params: CreateParserParams): Promise<Parser> {
    const result = await query(
      `INSERT INTO parsers (name, description, enabled, priority, parser_type, pattern, field_mappings, test_samples)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING *`,
      [
        params.name,
        params.description ?? null,
        params.enabled ?? true,
        params.priority ?? 100,
        params.parser_type,
        params.pattern,
        JSON.stringify(params.field_mappings),
        params.test_samples ? JSON.stringify(params.test_samples) : null,
      ]
    );

    return result.rows[0];
  }

  static async findById(id: number): Promise<Parser | null> {
    const result = await query('SELECT * FROM parsers WHERE id = $1', [id]);
    return result.rows[0] || null;
  }

  static async findByName(name: string): Promise<Parser | null> {
    const result = await query('SELECT * FROM parsers WHERE name = $1', [name]);
    return result.rows[0] || null;
  }

  static async findAll(): Promise<Parser[]> {
    const result = await query('SELECT * FROM parsers ORDER BY priority ASC, id ASC');
    return result.rows;
  }

  static async findEnabled(): Promise<Parser[]> {
    const result = await query(
      'SELECT * FROM parsers WHERE enabled = true ORDER BY priority ASC, id ASC'
    );
    return result.rows;
  }

  static async update(id: number, params: Partial<CreateParserParams>): Promise<Parser | null> {
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
    if (params.priority !== undefined) {
      updates.push(`priority = $${paramIndex++}`);
      values.push(params.priority);
    }
    if (params.parser_type !== undefined) {
      updates.push(`parser_type = $${paramIndex++}`);
      values.push(params.parser_type);
    }
    if (params.pattern !== undefined) {
      updates.push(`pattern = $${paramIndex++}`);
      values.push(params.pattern);
    }
    if (params.field_mappings !== undefined) {
      updates.push(`field_mappings = $${paramIndex++}`);
      values.push(JSON.stringify(params.field_mappings));
    }
    if (params.test_samples !== undefined) {
      updates.push(`test_samples = $${paramIndex++}`);
      values.push(JSON.stringify(params.test_samples));
    }

    if (updates.length === 0) {
      return this.findById(id);
    }

    updates.push(`updated_at = NOW()`);
    values.push(id);

    const result = await query(
      `UPDATE parsers SET ${updates.join(', ')} WHERE id = $${paramIndex} RETURNING *`,
      values
    );

    return result.rows[0] || null;
  }

  static async delete(id: number): Promise<boolean> {
    const result = await query('DELETE FROM parsers WHERE id = $1', [id]);
    return (result.rowCount || 0) > 0;
  }
}
