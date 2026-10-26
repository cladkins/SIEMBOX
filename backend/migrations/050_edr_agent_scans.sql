-- Migration 050: endpoint scan history and on-demand ("ad hoc") scans.
--
-- One row per scan an endpoint agent runs, whatever started it:
--   trigger 'console'  an analyst asked for it (POST /api/edr/agents/:id/scans);
--                      the row exists from the request on (status 'pending')
--                      and is served to the agent in its heartbeat response
--   trigger 'schedule' / 'startup'
--                      the agent's own cadence; the agent creates the row when
--                      it reports the run (POST /api/edr/scans)
-- scan_type: vuln (grype) | yara (file scan) | packages (installed software)
--            | inventory (host facts)
-- status:    pending -> running -> succeeded | failed, or cancelled (by a
--            user, while pending) / expired (never picked up, or never
--            finished). summary is per type (see services/edr/edrScans.ts);
--            the server fills what it can compute from the matching ingest.
--
-- At most one outstanding (pending or running) console request per agent and
-- type: the partial unique index makes a second click return the first.
-- Pruned by the edr-agent-release job (EDR_SCAN_HISTORY_* in edrScans.ts).
--
-- Idempotent: re-runs on every start.
CREATE TABLE IF NOT EXISTS edr_agent_scans (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id     UUID        NOT NULL REFERENCES edr_agents(agent_id) ON DELETE CASCADE,
  scan_type    TEXT        NOT NULL CHECK (scan_type IN ('vuln', 'yara', 'packages', 'inventory')),
  trigger      TEXT        NOT NULL CHECK (trigger IN ('schedule', 'startup', 'console')),
  requested_by INTEGER     REFERENCES users(id) ON DELETE SET NULL,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at   TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  status       TEXT        NOT NULL
               CHECK (status IN ('pending', 'running', 'succeeded', 'failed', 'cancelled', 'expired')),
  summary      JSONB,
  error        TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_edr_agent_scans_agent_requested
  ON edr_agent_scans (agent_id, requested_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS uq_edr_agent_scans_outstanding
  ON edr_agent_scans (agent_id, scan_type)
  WHERE trigger = 'console' AND status IN ('pending', 'running');
-- Expiry sweeps look only at outstanding rows.
CREATE INDEX IF NOT EXISTS idx_edr_agent_scans_open
  ON edr_agent_scans (status, requested_at)
  WHERE status IN ('pending', 'running');

-- What the agent says it can do (heartbeat `capabilities`); 'adhoc_scans'
-- means it runs console requests. NULL until a capable agent reports.
ALTER TABLE edr_agents ADD COLUMN IF NOT EXISTS capabilities TEXT[];
-- When the newest vulnerability report started being stored: the findings
-- last_detected at or after it are that report's, so the next report can
-- count how many it no longer holds (summary.resolved).
ALTER TABLE edr_agents ADD COLUMN IF NOT EXISTS last_vuln_ingest_at TIMESTAMPTZ;
-- Hash of the newest host inventory (minus its timestamp), for summary.changed.
ALTER TABLE edr_agents ADD COLUMN IF NOT EXISTS inventory_hash TEXT;
