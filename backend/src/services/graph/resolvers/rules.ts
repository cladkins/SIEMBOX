/**
 * Detection rules. A rule's alerts are rule_alerts (alerts.ts, on
 * idx_graph_alerts_rule_created); an alert's rule is alert_rule.
 */
import type { Query } from '../budget';
import type { EntityRef } from '../entityKey';
import type { CenterInfo } from './common';

export async function loadRuleCenter(q: Query, ref: EntityRef): Promise<CenterInfo> {
  const [row] = await q(`SELECT r.id FROM detection_rules r WHERE r.id = $1`, [Number(ref.key)]);
  return { exists: Boolean(row), row: row ?? null };
}
