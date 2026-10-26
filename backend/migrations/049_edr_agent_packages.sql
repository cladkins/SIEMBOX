-- Migration 049: endpoint software inventory. The endpoint agent reports the
-- full list of packages installed on its host (POST /api/edr/packages), not
-- only the vulnerable ones grype finds. Application Monitoring matches it
-- with the signatures' `package` matcher as the `endpoint_sbom` source.
--
-- A report is a full snapshot: it replaces the agent's rows, so a package
-- absent from the newest report is gone. Rows hang off the agent (not its
-- asset), so they follow the agent when its IP resolves to another asset and
-- go with it when it is deregistered.
-- Idempotent: re-runs on every start.
CREATE TABLE IF NOT EXISTS edr_agent_packages (
  agent_id   UUID        NOT NULL REFERENCES edr_agents(agent_id) ON DELETE CASCADE,
  type       TEXT        NOT NULL DEFAULT '',  -- ecosystem: deb|rpm|apk|msi|pkg|app|brew|npm|pypi|go|...
  name       TEXT        NOT NULL,
  version    TEXT        NOT NULL DEFAULT '',
  first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),  -- the last full report that held it
  PRIMARY KEY (agent_id, type, name, version)
);
-- The rollup reads only the packages a signature names (lower(name) = ANY(...)).
CREATE INDEX IF NOT EXISTS idx_edr_agent_packages_lname ON edr_agent_packages (lower(name));

-- One row per agent: the newest snapshot's hash (an unchanged report is
-- answered without touching the package rows), its size, and when it was
-- collected, last written, and last reported (changed or not).
CREATE TABLE IF NOT EXISTS edr_agent_package_snapshots (
  agent_id      UUID        PRIMARY KEY REFERENCES edr_agents(agent_id) ON DELETE CASCADE,
  snapshot_hash TEXT,
  package_count INTEGER     NOT NULL DEFAULT 0,
  collected_at  TIMESTAMPTZ,
  stored_at     TIMESTAMPTZ,
  reported_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
