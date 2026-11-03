-- Timezone of a syslog sender's zoneless header timestamps (RFC 3164
-- "Nov  3 12:17:04" carries no zone). Keyed by the source IP the listener sees.
-- A sender without a row uses the system setting syslog_default_timezone, else
-- UTC. Before this, zoneless timestamps were read in the backend's own local
-- time (UTC in the image), so a device logging in America/Chicago was stored
-- 6 hours early. See backend/src/services/syslog/sourceTimezone.ts.
-- Idempotent; re-runs on every startup like the other migrations.
CREATE TABLE IF NOT EXISTS syslog_source_timezones (
  source_ip TEXT PRIMARY KEY,
  timezone TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
