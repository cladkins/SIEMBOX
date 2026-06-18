-- Migration: Scheduled Scans
-- Adds recurring, user-defined vulnerability and asset scans.
-- NOTE: migrations are re-run on every boot, so everything here is idempotent.

CREATE TABLE IF NOT EXISTS scheduled_scans (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    scan_type VARCHAR(20) NOT NULL,            -- 'asset' | 'vulnerability'
    scan_options JSONB NOT NULL DEFAULT '{}',  -- scanner-specific config
    interval_minutes INTEGER NOT NULL,         -- run cadence in minutes
    enabled BOOLEAN DEFAULT true,
    last_run_at TIMESTAMP,
    last_scan_id INTEGER,                       -- id of the most recently triggered scan
    next_run_at TIMESTAMP NOT NULL DEFAULT NOW(),
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    CONSTRAINT scheduled_scans_type_chk CHECK (scan_type IN ('asset', 'vulnerability')),
    CONSTRAINT scheduled_scans_interval_chk CHECK (interval_minutes >= 5)
);

CREATE INDEX IF NOT EXISTS idx_scheduled_scans_due ON scheduled_scans (next_run_at) WHERE enabled;

COMMENT ON TABLE scheduled_scans IS 'Recurring scheduled vulnerability and asset scans';
COMMENT ON COLUMN scheduled_scans.scan_options IS 'Scanner config: asset -> {targets:[], scanType}; vulnerability -> {target, templateSelection, timeout, rateLimit}';
