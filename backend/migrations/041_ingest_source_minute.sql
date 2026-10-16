-- Migration 041: per-minute log counts per source, kept at ingest
-- (services/ingest/ingestCounter.ts, called from RawLogModel.create) the way
-- parser_match_hourly (024) keeps hourly parser counts, so the Big Display's
-- ingestion and sources panels never aggregate raw_logs. Buckets are server
-- ingest time. TIMESTAMPTZ (unlike 024) so bucket comparisons with NOW() don't
-- depend on the backend's and the database's time zones agreeing.
-- source_key: shipper_id (8 hex) | discovery_source_id | source_ip | '*' (overflow).
-- Rows older than 48 hours are pruned by the counter's own flush path.
-- Idempotent: migrations run on every start.
CREATE TABLE IF NOT EXISTS ingest_source_minute (
    minute      TIMESTAMPTZ NOT NULL,
    source_kind TEXT NOT NULL CHECK (source_kind IN ('shipper', 'poller', 'direct', 'overflow')),
    source_key  TEXT NOT NULL,
    logs        BIGINT NOT NULL DEFAULT 0 CHECK (logs >= 0),
    PRIMARY KEY (minute, source_kind, source_key)
);
