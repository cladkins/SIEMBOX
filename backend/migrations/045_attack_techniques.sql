-- 045_attack_techniques.sql — MITRE ATT&CK technique IDs on alerts.
--
-- alerts.attack_techniques   the raising rule's technique IDs at the time the
--                            alert was created, in canonical upper case
--                            (T1110, T1110.001), parsed from the rule's
--                            Sigma-style `attack.t…` tags. Copied rather than
--                            joined, so an alert keeps its techniques when the
--                            rule is re-tagged or deleted, and the alert list
--                            filters by the GIN index. Empty for non-rule
--                            alerts (EDR, exposure, auth) and untagged rules.
-- attack_technique_exclusions  techniques an operator marked "not applicable"
--                            for coverage (used by ATT&CK 2/4 and 3/4).
--
-- Idempotent (IF NOT EXISTS, guarded one-time backfill); runs on every startup.

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS attack_techniques TEXT[] NOT NULL DEFAULT '{}';
CREATE INDEX IF NOT EXISTS idx_attack_alerts_techniques ON alerts USING GIN (attack_techniques);

-- One-time backfill of the alerts that existed before this column, from their
-- rule's current tags. The guard row is inserted in the same statement, so the
-- update runs exactly once: later re-tags never rewrite alert history, and an
-- alert that legitimately has no technique is not revisited on every start.
-- The pattern is anchored and has no nested quantifiers (linear).
WITH guard AS (
  INSERT INTO system_settings (key, value, description)
  VALUES ('attack_alert_techniques_backfilled', 'true',
          'Migration 045 copied rule ATT&CK techniques onto existing alerts (do not remove)')
  ON CONFLICT (key) DO NOTHING
  RETURNING 1
),
rule_techniques AS (
  SELECT r.id AS rule_id,
         ARRAY(
           SELECT DISTINCT upper(substr(t, 8))
             FROM unnest(r.tags) AS t
            WHERE t ~* '^attack\.t[0-9]{4}(\.[0-9]{3})?$'
            ORDER BY 1
         ) AS techniques
    FROM detection_rules r
   WHERE r.tags IS NOT NULL
)
UPDATE alerts a
   SET attack_techniques = rt.techniques
  FROM rule_techniques rt
 WHERE EXISTS (SELECT 1 FROM guard)
   AND a.rule_id = rt.rule_id
   AND cardinality(rt.techniques) > 0
   AND a.attack_techniques = '{}';

CREATE TABLE IF NOT EXISTS attack_technique_exclusions (
    technique_id TEXT PRIMARY KEY,
    note         TEXT,
    created_by   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
