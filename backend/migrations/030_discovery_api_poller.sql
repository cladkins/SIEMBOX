-- Generic API-pull poller for Log Discovery sources whose fingerprint declares
-- log_access: [{method: api_pull, ...}] (authentik, home-assistant, pihole,
-- adguard-home). Until now, onboarding one of these just handed the user a
-- copy-paste cron+curl+logger recipe (see onboarder.ts / templates/api_poller.j2)
-- -- nothing polled anything automatically. This adds real storage for a
-- per-source encrypted credential plus poll scheduling/status, mirroring
-- threat_feeds' shape (015_threat_intel_feeds.sql): per-item
-- poll_interval_minutes + last_status/last_error/last_polled_at.
--
-- Deliberately NOT modeled on log_shippers: a polled source has no agent, no
-- heartbeat, no host inventory -- SIEMBox reaches out to it, nothing reaches
-- in. Routing polled logs through log_shippers would also misattribute them
-- as an "unknown source" in the Shippers page, since shippers.ts's
-- unknown-sources query only recognizes log_shippers-derived hashes.
CREATE TABLE IF NOT EXISTS discovery_source_pollers (
    discovery_source_id INTEGER PRIMARY KEY REFERENCES discovery_sources(id) ON DELETE CASCADE,
    fingerprint_id VARCHAR(100) NOT NULL,
    log_access_method VARCHAR(50) NOT NULL DEFAULT 'api_pull',
    -- AES-256-GCM via CredentialEncryption (services/credentials/credentialEncryption.ts),
    -- same 3-column shape as scan_credentials (001_initial_schema.sql). Reversible --
    -- unlike log_shippers/EDR agent keys, this credential must be retrievable to
    -- present outbound on each poll, so it cannot be a one-way hash.
    encrypted_credential TEXT NOT NULL,
    encryption_iv TEXT NOT NULL,
    encryption_auth_tag TEXT NOT NULL,
    -- Only adguard-home (HTTP Basic) needs this; not secret on its own, so it stays
    -- out of the encrypted blob. NULL for every bearer/query-param-token adapter.
    credential_username VARCHAR(255),
    enabled BOOLEAN NOT NULL DEFAULT true,
    poll_interval_minutes INTEGER NOT NULL DEFAULT 5,
    -- Opaque, adapter-interpreted incremental-fetch position (an ISO timestamp for
    -- authentik/pihole/adguard-home; a rolling tail-hash marker for home-assistant,
    -- which has no server-side time filter). NULL means "never polled".
    poll_cursor TEXT,
    last_polled_at TIMESTAMPTZ,
    last_status VARCHAR(20), -- 'ok' | 'error'
    last_error TEXT,
    last_event_count INTEGER,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_discovery_source_pollers_due
    ON discovery_source_pollers(enabled, last_polled_at);

-- Real FK attribution for pulled logs, parallel to but independent of
-- raw_logs.shipper_id (a bare VARCHAR, not an FK -- see LogShipper.ts). A row
-- only ever sets one of the two; both NULL for syslog-ingested rows.
ALTER TABLE raw_logs ADD COLUMN IF NOT EXISTS discovery_source_id INTEGER REFERENCES discovery_sources(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_raw_logs_discovery_source_id ON raw_logs(discovery_source_id) WHERE discovery_source_id IS NOT NULL;

-- Dedup for retried/overlapping polls, parallel to 029's (shipper_id,
-- ingest_event_id) index but keyed to discovery_source_id. Postgres treats
-- NULL as distinct from NULL in unique indexes, so this never collides with
-- the existing shipper_id-keyed index (every row here has shipper_id NULL).
CREATE UNIQUE INDEX IF NOT EXISTS idx_raw_logs_discovery_ingest_event_id
    ON raw_logs (discovery_source_id, ingest_event_id)
    WHERE discovery_source_id IS NOT NULL AND ingest_event_id IS NOT NULL;
