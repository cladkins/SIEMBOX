-- HTTP log-push ingestion for log shippers (POST /api/shippers/logs).
--
-- Adds a distinct, separately-provisioned push key (hashed at rest, same
-- sha256 + timing-safe-compare pattern as EDR agents — see
-- backend/src/middleware/edrAgentAuth.ts) so a shipper can be enabled for
-- HTTP log push WITHOUT touching its existing syslog api_key (still
-- plaintext, still shown/regenerated exactly as before). http_push_key_hash
-- IS NULL means HTTP push is not provisioned/disabled; generating a key sets
-- it, revoking clears it back to NULL — no separate "enabled" column.
ALTER TABLE log_shippers ADD COLUMN IF NOT EXISTS http_push_key_hash TEXT;
ALTER TABLE log_shippers ADD COLUMN IF NOT EXISTS http_push_key_created_at TIMESTAMPTZ;
ALTER TABLE log_shippers ADD COLUMN IF NOT EXISTS http_push_last_seen TIMESTAMPTZ;

-- Optional client-supplied dedup key so a retried POST (timeout, at-least-once
-- delivery) doesn't create a second raw_logs row and re-fire detections.
-- NULL (every existing syslog row) never matches the partial index below, so
-- this is a no-op for every current caller of RawLogModel.create().
ALTER TABLE raw_logs ADD COLUMN IF NOT EXISTS ingest_event_id TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_raw_logs_ingest_event_id
    ON raw_logs (shipper_id, ingest_event_id)
    WHERE ingest_event_id IS NOT NULL;
