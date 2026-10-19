-- 044_edr_agent_updates.sql — console-triggered endpoint-agent updates.
--
-- The server only NAMES a target version (and a fresh request id); the agent
-- downloads the release from GitHub itself. Per-agent request/result state:
--   update_request_id    set while a request is outstanding (served as
--                        AgentConfig.agent_update); cleared on success/cancel,
--                        kept on failure so the agent keeps reporting it
--   update_target_version, update_state (pending | downloading | installing |
--   succeeded | failed), update_error, update_requested_at, update_updated_at
--                        survive after success/cancel for display
-- Fleet-wide state lives in system_settings (edr_agent_* keys, seeded below;
-- latest_* are written by the edr-agent-release job).
--
-- Idempotent (ADD COLUMN IF NOT EXISTS / ON CONFLICT DO NOTHING); runs on every startup.

ALTER TABLE edr_agents ADD COLUMN IF NOT EXISTS update_request_id uuid;
ALTER TABLE edr_agents ADD COLUMN IF NOT EXISTS update_target_version text;
ALTER TABLE edr_agents ADD COLUMN IF NOT EXISTS update_state text;
ALTER TABLE edr_agents ADD COLUMN IF NOT EXISTS update_error text;
ALTER TABLE edr_agents ADD COLUMN IF NOT EXISTS update_requested_at timestamptz;
ALTER TABLE edr_agents ADD COLUMN IF NOT EXISTS update_updated_at timestamptz;

-- Auto-update is opt-in. DO NOTHING keeps an admin's choice across restarts.
INSERT INTO system_settings (key, value) VALUES ('edr_agent_auto_update', 'false')
ON CONFLICT (key) DO NOTHING;
