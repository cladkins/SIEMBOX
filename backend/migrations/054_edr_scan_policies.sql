-- Migration 054: endpoint scan policies.
--
-- Which scans an endpoint agent runs, and when, is now set on the server:
--
--   edr_scan_policies      named policies; exactly one row is the default
--                          (is_default), which every endpoint without a named
--                          policy follows. `scans` holds one entry per scan
--                          type (vuln, yara, packages, inventory):
--                            { "enabled": true,
--                              "schedule": { calendar timing, as scheduled_scans.schedule } | null,
--                              "interval_minutes": 1440 | null,      -- when schedule is null
--                              "window": { "start": "22:00", "end": "06:00",
--                                          "timezone": "UTC" } | null }
--                          (see src/services/edr/scanPolicies.ts).
--   edr_agents.scan_policy_id         the endpoint's named policy (NULL = default)
--   edr_agents.scan_policy_overrides  per-endpoint replacements for single scan
--                                     types, same entry shape ({ "vuln": {...} }), or NULL
--   edr_agent_policy_runs  per endpoint and scan type: when its policy next
--                          makes that scan due, and when it last issued it.
--
-- The server issues a due scan as a scan request in the agent's heartbeat
-- (edr_agent_scans row, trigger 'policy', named after the policy), so only
-- agents that report the 'policy_scans' capability follow policies; older
-- agents keep their own intervals.
--
-- The default policy starts with what agents did on their own: system
-- inventory hourly, packages every 6 hours, vulnerabilities and a full YARA
-- pass daily (fixed intervals, no window). Configuration, not catalog content.
--
-- Idempotent: re-runs on every start.

CREATE TABLE IF NOT EXISTS edr_scan_policies (
  id          SERIAL      PRIMARY KEY,
  name        TEXT        NOT NULL,
  description TEXT,
  is_default  BOOLEAN     NOT NULL DEFAULT FALSE,
  scans       JSONB       NOT NULL,
  created_by  INTEGER     REFERENCES users(id) ON DELETE SET NULL,
  updated_by  INTEGER     REFERENCES users(id) ON DELETE SET NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_edr_scan_policies_name ON edr_scan_policies (LOWER(name));
CREATE UNIQUE INDEX IF NOT EXISTS uq_edr_scan_policies_default ON edr_scan_policies (is_default) WHERE is_default;

INSERT INTO edr_scan_policies (name, description, is_default, scans)
SELECT 'Default',
       'Applies to every endpoint without a named policy.',
       TRUE,
       '{
          "vuln":      {"enabled": true, "schedule": null, "interval_minutes": 1440, "window": null},
          "yara":      {"enabled": true, "schedule": null, "interval_minutes": 1440, "window": null},
          "packages":  {"enabled": true, "schedule": null, "interval_minutes": 360,  "window": null},
          "inventory": {"enabled": true, "schedule": null, "interval_minutes": 60,   "window": null}
        }'::jsonb
 WHERE NOT EXISTS (SELECT 1 FROM edr_scan_policies WHERE is_default);

ALTER TABLE edr_agents ADD COLUMN IF NOT EXISTS scan_policy_id INTEGER
  REFERENCES edr_scan_policies(id) ON DELETE SET NULL;
ALTER TABLE edr_agents ADD COLUMN IF NOT EXISTS scan_policy_overrides JSONB;
CREATE INDEX IF NOT EXISTS idx_edr_agents_scan_policy ON edr_agents (scan_policy_id) WHERE scan_policy_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS edr_agent_policy_runs (
  agent_id       UUID        NOT NULL REFERENCES edr_agents(agent_id) ON DELETE CASCADE,
  scan_type      TEXT        NOT NULL CHECK (scan_type IN ('vuln', 'yara', 'packages', 'inventory')),
  -- The effective entry the times below were computed for; a different one
  -- (the policy, assignment or override changed) recomputes next_due_at.
  spec_key       TEXT        NOT NULL,
  next_due_at    TIMESTAMPTZ,
  last_issued_at TIMESTAMPTZ,
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (agent_id, scan_type)
);

-- Scan history: policy-issued runs, and which policy issued them.
ALTER TABLE edr_agent_scans DROP CONSTRAINT IF EXISTS edr_agent_scans_trigger_check;
ALTER TABLE edr_agent_scans
  ADD CONSTRAINT edr_agent_scans_trigger_check
  CHECK (trigger IN ('schedule', 'startup', 'console', 'policy'));
ALTER TABLE edr_agent_scans ADD COLUMN IF NOT EXISTS policy_id INTEGER
  REFERENCES edr_scan_policies(id) ON DELETE SET NULL;
-- The policy's name when the run was issued ('override' runs name the endpoint's override).
ALTER TABLE edr_agent_scans ADD COLUMN IF NOT EXISTS policy_name TEXT;
-- 'policy' or 'override': where the run's timing came from.
ALTER TABLE edr_agent_scans ADD COLUMN IF NOT EXISTS policy_source TEXT;
-- At most one outstanding policy run per agent and type.
CREATE UNIQUE INDEX IF NOT EXISTS uq_edr_agent_scans_policy_outstanding
  ON edr_agent_scans (agent_id, scan_type)
  WHERE trigger = 'policy' AND status IN ('pending', 'running');
