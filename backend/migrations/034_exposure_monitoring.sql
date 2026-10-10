-- Migration 034: exposure monitoring ("Digital Risk").
--
-- Three tables:
--   watched_domains       — domains to watch (own domains, and brand names to protect
--                           from lookalikes). The domain collectors (CT logs, lookalike
--                           generation, RDAP, DNS) ship in a later release; the table
--                           exists now so the UI and onboarding can collect domains.
--   monitored_identities  — email addresses and whole email domains checked against
--                           breach corpora (Have I Been Pwned today).
--   exposure_findings     — one row per distinct exposure, deduped on (source, fingerprint).
--                           A NEW row raises exactly one alert (alerts.source = the
--                           finding's source, alerts.event_id = sha256(source:fingerprint),
--                           deduped by the partial unique index from migration 016);
--                           seeing it again only moves last_seen.
--
-- Privacy: nothing here holds a password, a password hash or an API key. The HIBP
-- API key lives encrypted in system_settings (exposure_hibp_key), the same scheme as
-- the threat-intel provider keys, and is written by the app, never seeded.
--
-- Idempotent / re-runnable: CREATE ... IF NOT EXISTS, and the settings seed uses
-- ON CONFLICT (key) DO NOTHING so re-running never clobbers an operator's choice.

CREATE TABLE IF NOT EXISTS watched_domains (
    id SERIAL PRIMARY KEY,
    domain TEXT NOT NULL UNIQUE CHECK (domain = lower(domain)),
    scope TEXT NOT NULL CHECK (scope IN ('own', 'brand')),
    enabled BOOLEAN NOT NULL DEFAULT true,
    interval_minutes INTEGER NOT NULL DEFAULT 1440 CHECK (interval_minutes > 0),
    collectors JSONB NOT NULL DEFAULT '{"ct":true,"lookalike":true,"rdap":true,"dns":true}'::jsonb,
    expected_cas TEXT[] NOT NULL DEFAULT '{}',   -- CAs allowed to issue for this domain
    last_checked_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,
    last_status TEXT,                            -- ok | error
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS monitored_identities (
    id SERIAL PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('email', 'email_domain')),
    value TEXT NOT NULL CHECK (value = lower(value)),
    enabled BOOLEAN NOT NULL DEFAULT true,
    interval_minutes INTEGER NOT NULL DEFAULT 1440 CHECK (interval_minutes > 0),
    last_checked_at TIMESTAMPTZ,
    last_status TEXT,                            -- ok | error
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (kind, value)
);

CREATE TABLE IF NOT EXISTS exposure_findings (
    id BIGSERIAL PRIMARY KEY,
    source TEXT NOT NULL,                        -- 'leaked-creds' | 'domain-monitor'
    identity_id INTEGER REFERENCES monitored_identities(id) ON DELETE CASCADE,
    domain_id INTEGER REFERENCES watched_domains(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,                    -- e.g. 'breach'
    fingerprint TEXT NOT NULL,                   -- stable hash of what was found
    title TEXT,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    detail JSONB NOT NULL DEFAULT '{}'::jsonb,   -- sanitized: secret-like keys are stripped
    alert_id INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    UNIQUE (source, fingerprint)
);

-- The leaked-credential job's "what is due?" query only looks at enabled rows,
-- oldest check first; the domain collectors will do the same by next_run_at.
CREATE INDEX IF NOT EXISTS idx_monitored_identities_due
    ON monitored_identities (last_checked_at NULLS FIRST) WHERE enabled;
CREATE INDEX IF NOT EXISTS idx_watched_domains_due
    ON watched_domains (next_run_at NULLS FIRST) WHERE enabled;

-- Findings list (newest first, optionally per source) and open-findings counts.
CREATE INDEX IF NOT EXISTS idx_exposure_findings_source_first_seen
    ON exposure_findings (source, first_seen DESC);
CREATE INDEX IF NOT EXISTS idx_exposure_findings_open
    ON exposure_findings (first_seen DESC) WHERE resolved_at IS NULL;

-- FK columns that parent-row deletion must look up (see migration 025): deleting
-- an identity or domain cascades, and alert retention sets alert_id to NULL.
CREATE INDEX IF NOT EXISTS idx_exposure_findings_identity_id ON exposure_findings (identity_id);
CREATE INDEX IF NOT EXISTS idx_exposure_findings_domain_id ON exposure_findings (domain_id);
CREATE INDEX IF NOT EXISTS idx_exposure_findings_alert_id ON exposure_findings (alert_id);

-- Notifications are opt-in, like every other notification event (migration 006).
-- Leaked-credential checks are on, but do nothing until an HIBP key is saved and
-- the provider is enabled.
INSERT INTO system_settings (key, value) VALUES
    ('notify_exposure_enabled', 'false'),
    ('notify_exposure_min_severity', 'medium'),
    ('exposure_leaked_creds_enabled', 'true'),
    ('exposure_hibp_enabled', 'false')
ON CONFLICT (key) DO NOTHING;
