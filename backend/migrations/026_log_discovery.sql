-- Log Discovery: find -> identify -> recommend -> onboard.
--
-- discovery_scans is the job-tracking table for a scan run (mirrors
-- vulnerability_scans' shape: options in, status + summary out). discovery_sources
-- is one row per detected host, upserted on ip_address across repeated scans so
-- re-scanning a homelab doesn't create duplicates (same pattern as assets).
--
-- Discovery is read-only by design (see CLAUDE.md / spec: "Onboarding is the only
-- module that writes config"), so these tables only ever record what a scan
-- observed and what the user decided about it -- never device config.
CREATE TABLE IF NOT EXISTS discovery_scans (
    id SERIAL PRIMARY KEY,
    mode VARCHAR(20) NOT NULL DEFAULT 'full', -- passive | active | full
    cidrs JSONB NOT NULL DEFAULT '[]',
    status VARCHAR(20) NOT NULL DEFAULT 'running', -- running | completed | failed
    started_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    error_message TEXT,
    results_summary JSONB,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS discovery_sources (
    id SERIAL PRIMARY KEY,
    ip_address INET NOT NULL,
    mac_address VARCHAR(17),
    hostname VARCHAR(255),
    open_ports INTEGER[] NOT NULL DEFAULT '{}',
    matched_fingerprint_id VARCHAR(100),
    confidence INTEGER NOT NULL DEFAULT 0,
    is_guess BOOLEAN NOT NULL DEFAULT true,
    security_value INTEGER,
    status VARCHAR(20) NOT NULL DEFAULT 'candidate', -- candidate | confirmed | onboarded | ignored
    selected_log_access JSONB,
    evidence JSONB NOT NULL DEFAULT '{}', -- raw passive/active signals the matcher scored against
    last_scan_id INTEGER REFERENCES discovery_scans(id) ON DELETE SET NULL,
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(ip_address)
);

CREATE INDEX IF NOT EXISTS idx_discovery_sources_status ON discovery_sources(status);
CREATE INDEX IF NOT EXISTS idx_discovery_sources_security_value ON discovery_sources(security_value DESC);
CREATE INDEX IF NOT EXISTS idx_discovery_scans_status ON discovery_scans(status);
