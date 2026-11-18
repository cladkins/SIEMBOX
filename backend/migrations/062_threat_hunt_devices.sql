-- Migration 062: Threat Hunting, where a hunt's matches were seen.
--
-- threat_hunt_matches keeps up to 25 sample lines per term, so it can't say
-- how many devices matched or how many lines each had. A run now stores one
-- row per device with matching lines (services/hunting/huntService.ts):
--   device         the syslog header host, else the sender IP: the same key the
--                  Context Graph's host and ip nodes use (graph/entityKey.ts)
--   hostname, source_ip, app_names  as the logs gave them
--   lines, first_seen, last_seen    over every matching line the run read
--   indicators     [{ id, type, value, lines }] matched on this device
--   hypotheses     [{ id, title, lines }] whose search terms matched
--   last_raw_log_id  the newest matching line (no FK: retention deletes raw logs)
--   alert_id       the alert the run raised for this device, when it raised one
-- Replaced on every run, like the sample lines.
--
-- threat_hunts.devices_matched: how many devices the last run found.
--
-- Idempotent, like every migration here.

CREATE TABLE IF NOT EXISTS threat_hunt_devices (
    id BIGSERIAL PRIMARY KEY,
    hunt_id INTEGER NOT NULL REFERENCES threat_hunts(id) ON DELETE CASCADE,
    device TEXT NOT NULL,
    hostname TEXT,
    source_ip TEXT,
    app_names TEXT[] NOT NULL DEFAULT '{}',
    lines INTEGER NOT NULL DEFAULT 0,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    indicators JSONB NOT NULL DEFAULT '[]'::jsonb,
    hypotheses JSONB NOT NULL DEFAULT '[]'::jsonb,
    last_raw_log_id BIGINT,
    alert_id INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (hunt_id, device)
);

-- The FK's delete path (alert deletes set alert_id to NULL).
CREATE INDEX IF NOT EXISTS idx_threat_hunt_devices_alert_id ON threat_hunt_devices (alert_id) WHERE alert_id IS NOT NULL;

ALTER TABLE threat_hunts ADD COLUMN IF NOT EXISTS devices_matched INTEGER NOT NULL DEFAULT 0;
