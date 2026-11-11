-- Migration 059: Threat Hunting.
--
-- A hunt starts from an article (a URL, pasted text, or an imported STIX
-- bundle). SIEMBox extracts its indicators of compromise and hunt hypotheses,
-- searches the stored logs for them, and records what it found. Every hunt is
-- exported as a STIX 2.1 bundle and served from the TAXII 2.1 collection at
-- /api/taxii2/ (backend/src/routes/taxii.ts). See docs/threat-hunting.md.
--
-- Tables:
--   hunt_sources            URLs SIEMBox watches (an RSS/Atom feed or a page);
--                           new items or new indicators create hunts.
--   hunt_source_items       feed items already seen, so each makes one hunt.
--   threat_hunts            one hunt: where it came from, its status, its last run.
--   threat_hunt_indicators  the hunt's IOCs (one STIX indicator each).
--   threat_hunt_hypotheses  the hunt's hypotheses (one STIX note each) and the
--                           log search terms that test them.
--   threat_hunt_matches     sample log lines the last run found (a snapshot:
--                           retention may delete the raw log later).
--   taxii_tokens            read-only TAXII client tokens (only a SHA-256 hash).
--
-- Idempotent: CREATE ... IF NOT EXISTS throughout, like every migration here.

CREATE TABLE IF NOT EXISTS hunt_sources (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    url TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL DEFAULT 'auto',            -- auto | feed | page
    enabled BOOLEAN NOT NULL DEFAULT true,
    check_interval_minutes INTEGER NOT NULL DEFAULT 360,
    lookback_days INTEGER NOT NULL DEFAULT 14,
    alert_on_match BOOLEAN NOT NULL DEFAULT true,
    use_ai BOOLEAN NOT NULL DEFAULT true,
    last_checked_at TIMESTAMPTZ,
    last_status TEXT,                             -- ok | error
    last_error TEXT,
    last_content_hash TEXT,                       -- page sources: hash of the last indicator set
    hunts_created INTEGER NOT NULL DEFAULT 0,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS threat_hunts (
    id SERIAL PRIMARY KEY,
    -- The STIX report id's UUID part: stable for the life of the hunt.
    stix_uuid UUID NOT NULL UNIQUE,
    title TEXT NOT NULL,
    title_locked BOOLEAN NOT NULL DEFAULT false,  -- the user named the hunt: extraction keeps the name
    origin TEXT NOT NULL DEFAULT 'url',           -- url | text | stix | source
    source_url TEXT,
    source_id INTEGER REFERENCES hunt_sources(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'pending',       -- pending | extracting | ready | running | completed | failed
    summary TEXT,
    -- The report's text as extracted (pasted text, the page's readable text, or
    -- a feed item's own content), kept so a hunt can be re-extracted.
    source_text TEXT,
    extraction_method TEXT,                       -- regex | ai | stix
    extraction_note TEXT,
    lookback_days INTEGER NOT NULL DEFAULT 14,
    alert_on_match BOOLEAN NOT NULL DEFAULT false,
    use_ai BOOLEAN NOT NULL DEFAULT true,
    error TEXT,
    match_count INTEGER NOT NULL DEFAULT 0,
    logs_matched INTEGER NOT NULL DEFAULT 0,
    results_truncated BOOLEAN NOT NULL DEFAULT false,
    last_run_at TIMESTAMPTZ,
    last_alert_id INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_threat_hunts_created_at ON threat_hunts (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_hunts_updated_at ON threat_hunts (updated_at);
CREATE INDEX IF NOT EXISTS idx_threat_hunts_source_id ON threat_hunts (source_id) WHERE source_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_threat_hunts_last_alert_id ON threat_hunts (last_alert_id) WHERE last_alert_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS hunt_source_items (
    id BIGSERIAL PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES hunt_sources(id) ON DELETE CASCADE,
    item_key TEXT NOT NULL,                       -- the item's guid, else its link
    item_url TEXT,
    title TEXT,
    published_at TIMESTAMPTZ,
    hunt_id INTEGER REFERENCES threat_hunts(id) ON DELETE SET NULL,
    seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (source_id, item_key)
);

CREATE INDEX IF NOT EXISTS idx_hunt_source_items_hunt_id ON hunt_source_items (hunt_id) WHERE hunt_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS threat_hunt_indicators (
    id SERIAL PRIMARY KEY,
    hunt_id INTEGER NOT NULL REFERENCES threat_hunts(id) ON DELETE CASCADE,
    stix_id TEXT NOT NULL,
    ioc_type TEXT NOT NULL,                       -- ipv4 | ipv6 | domain | url | email | md5 | sha1 | sha256 | cve
    value TEXT NOT NULL,
    context TEXT,
    found_by TEXT NOT NULL DEFAULT 'regex',       -- regex | ai | stix | user
    enabled BOOLEAN NOT NULL DEFAULT true,
    match_count INTEGER NOT NULL DEFAULT 0,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (hunt_id, ioc_type, value)
);

CREATE INDEX IF NOT EXISTS idx_threat_hunt_indicators_hunt ON threat_hunt_indicators (hunt_id);

CREATE TABLE IF NOT EXISTS threat_hunt_hypotheses (
    id SERIAL PRIMARY KEY,
    hunt_id INTEGER NOT NULL REFERENCES threat_hunts(id) ON DELETE CASCADE,
    stix_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    attack_techniques TEXT[] NOT NULL DEFAULT '{}',
    search_terms TEXT[] NOT NULL DEFAULT '{}',
    found_by TEXT NOT NULL DEFAULT 'regex',       -- regex | ai | stix | user
    enabled BOOLEAN NOT NULL DEFAULT true,
    match_count INTEGER NOT NULL DEFAULT 0,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_threat_hunt_hypotheses_hunt ON threat_hunt_hypotheses (hunt_id);

CREATE TABLE IF NOT EXISTS threat_hunt_matches (
    id BIGSERIAL PRIMARY KEY,
    hunt_id INTEGER NOT NULL REFERENCES threat_hunts(id) ON DELETE CASCADE,
    indicator_id INTEGER REFERENCES threat_hunt_indicators(id) ON DELETE CASCADE,
    hypothesis_id INTEGER REFERENCES threat_hunt_hypotheses(id) ON DELETE CASCADE,
    term TEXT NOT NULL,
    raw_log_id BIGINT,                            -- no FK: retention deletes raw logs
    log_timestamp TIMESTAMPTZ,
    source_ip TEXT,
    hostname TEXT,
    app_name TEXT,
    message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_threat_hunt_matches_hunt ON threat_hunt_matches (hunt_id, log_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_threat_hunt_matches_indicator ON threat_hunt_matches (indicator_id) WHERE indicator_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_threat_hunt_matches_hypothesis ON threat_hunt_matches (hypothesis_id) WHERE hypothesis_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS taxii_tokens (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,              -- SHA-256 hex of the token; the token itself is never stored
    token_prefix TEXT NOT NULL,                   -- first characters, to tell tokens apart in the UI
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);
