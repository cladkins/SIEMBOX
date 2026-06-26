-- 016_edr_agents.sql — SIEMBox EDR server-side support.
--
-- Adds the two NEW tables the endpoint agent needs (edr_agents, edr_enrollment_tokens)
-- and extends the existing `alerts` table with nullable linkage columns so endpoint
-- detections flow into the SAME alert pipeline/UI as everything else. Endpoint
-- inventory reuses `assets` (asset_type='endpoint') and endpoint vulns reuse
-- `vulnerabilities` + `asset_vulnerabilities` — no new tables for those.
--
-- Idempotent (IF NOT EXISTS / ADD COLUMN IF NOT EXISTS); runs on every startup.

-- Enrolled endpoint agents. The api key is stored ONLY as a sha256 hash; the
-- plaintext is shown to the agent exactly once at enrollment.
CREATE TABLE IF NOT EXISTS edr_agents (
    agent_id        UUID PRIMARY KEY,
    api_key_hash    TEXT NOT NULL,                       -- sha256(agent_api_key)
    asset_id        INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    hostname        TEXT,
    os              TEXT,
    os_version      TEXT,
    arch            TEXT,
    agent_version   TEXT,
    ip              TEXT,
    status          TEXT DEFAULT 'enrolled',             -- enrolled | online | offline
    config_version  INTEGER DEFAULT 1,
    last_seen       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_edr_agents_asset_id ON edr_agents(asset_id);
CREATE INDEX IF NOT EXISTS idx_edr_agents_status   ON edr_agents(status);

-- One-time enrollment tokens (admin-generated, mirrors how shipper keys work).
-- Stored as a hash; the plaintext is shown once in the UI. Single-use: `used_at`
-- is stamped on enroll. Optional `expires_at` time-boxes the token.
CREATE TABLE IF NOT EXISTS edr_enrollment_tokens (
    token_hash   TEXT PRIMARY KEY,                       -- sha256(token)
    label        TEXT,
    created_by   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    expires_at   TIMESTAMPTZ,
    used_at      TIMESTAMPTZ,                            -- null until consumed
    created_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_edr_tokens_expires_at ON edr_enrollment_tokens(expires_at);

-- Extend alerts so endpoint detections reuse the existing pipeline:
--  * asset_id   — link the alert to the endpoint asset (drill-down / correlation)
--  * source     — where the alert came from (e.g. 'edr'); NULL = legacy rule alert
--  * event_id   — the agent's stable event UUID, for replay/dedup
-- rule_id is already nullable, so EDR alerts simply leave it NULL.
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS source   TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS event_id TEXT;

CREATE INDEX IF NOT EXISTS idx_alerts_asset_id ON alerts(asset_id);
-- Dedupe agent retries/replays: an event id may only become one alert.
CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_event_id ON alerts(event_id) WHERE event_id IS NOT NULL;
