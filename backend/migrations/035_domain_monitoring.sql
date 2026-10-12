-- Migration 035: domain monitoring (Digital Risk, part 2).
--
-- domain_baselines holds each domain collector's last snapshot, one row per
-- (watched domain, collector): 'ct' (certificates seen in Certificate
-- Transparency), 'lookalike' (registered lookalike domains), 'rdap'
-- (registrar / nameservers / status / DNSSEC) and 'dns' (A/AAAA/MX/NS/TXT/DMARC).
-- A collector compares each run against its snapshot and only NEW changes
-- become exposure_findings (source = 'domain-monitor'); a missing row means
-- the collector has not run yet, so its first run records the baseline
-- silently. Snapshots hold public registry/DNS/CT data only — no secrets.
--
-- watched_domains.last_summary keeps the per-collector outcome of the last run
-- (ok / baseline / unsupported / error, with a one-line note), so the UI can tell
-- "nothing found" from "blocked" or "not supported for this TLD".
--
-- Idempotent / re-runnable: CREATE ... IF NOT EXISTS, ADD COLUMN IF NOT EXISTS,
-- and the settings seed uses ON CONFLICT (key) DO NOTHING so re-running never
-- clobbers an operator's choice.

CREATE TABLE IF NOT EXISTS domain_baselines (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES watched_domains(id) ON DELETE CASCADE,
    collector TEXT NOT NULL,                     -- 'ct' | 'lookalike' | 'rdap' | 'dns'
    snapshot JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (domain_id, collector)
);

-- FK column that parent-row deletion must look up (see migration 025).
CREATE INDEX IF NOT EXISTS idx_domain_baselines_domain_id ON domain_baselines (domain_id);

ALTER TABLE watched_domains ADD COLUMN IF NOT EXISTS last_summary JSONB;

-- Domain monitoring is on (it does nothing until a domain is watched). Expiry
-- warnings start 30 days out; each domain generates at most 300 lookalike
-- candidates; the optional second DNS resolver is off ('' = system resolver only).
INSERT INTO system_settings (key, value) VALUES
    ('exposure_domain_monitor_enabled', 'true'),
    ('exposure_domain_expiry_warning_days', '30'),
    ('exposure_lookalike_max_candidates', '300'),
    ('exposure_dns_secondary_resolver', '')
ON CONFLICT (key) DO NOTHING;
