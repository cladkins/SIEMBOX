-- 018_edr_agent_scan_times.sql — capture the agent-reported vuln scan window.
--
-- The agent's POST /api/edr/vulnerabilities payload carries scan_started_at /
-- scan_completed_at, which we previously discarded (the UI's "last scan" was
-- approximated from when findings were last ingested). Store the real reported
-- window on the agent row so the UI can show the actual last scan, its duration,
-- and derive the next scan (last completed + vuln_scan_interval).
--
-- Idempotent (ADD COLUMN IF NOT EXISTS).

ALTER TABLE edr_agents ADD COLUMN IF NOT EXISTS last_scan_started_at   TIMESTAMPTZ;
ALTER TABLE edr_agents ADD COLUMN IF NOT EXISTS last_scan_completed_at TIMESTAMPTZ;
