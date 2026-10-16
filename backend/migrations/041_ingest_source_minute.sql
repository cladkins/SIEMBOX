-- Migration 041: per-minute log counts per source, kept at ingest
-- (services/ingest/ingestCounter.ts, called from RawLogModel.create) the way
-- parser_match_hourly (024) keeps hourly parser counts, so the Big Display's
-- ingestion and sources panels never aggregate raw_logs. Buckets are server
-- ingest time. TIMESTAMPTZ (unlike 024) so bucket comparisons with NOW() don't
-- depend on the backend's and the database's time zones agreeing.
-- source_key: shipper_id (8 hex) | discovery_source_id | source_ip | '*' (overflow).
-- established: the source was one of the counter's established sources in
-- that minute (the ones it always counts one by one); a restart reads them
-- back from these rows.
-- Rows older than 48 hours are pruned by the counter's own flush path.
-- Idempotent: migrations run on every start.
CREATE TABLE IF NOT EXISTS ingest_source_minute (
    minute      TIMESTAMPTZ NOT NULL,
    source_kind TEXT NOT NULL CHECK (source_kind IN ('shipper', 'poller', 'direct', 'overflow')),
    source_key  TEXT NOT NULL,
    logs        BIGINT NOT NULL DEFAULT 0 CHECK (logs >= 0),
    established BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY (minute, source_kind, source_key)
);

-- For a database that created the table before the column was added.
ALTER TABLE ingest_source_minute ADD COLUMN IF NOT EXISTS established BOOLEAN NOT NULL DEFAULT false;
