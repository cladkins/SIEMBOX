-- Indexes on FK columns that parent-row deletion must look up.
--
-- parsed_logs.raw_log_id is ON DELETE CASCADE from raw_logs, and
-- alerts.parsed_log_id is ON DELETE SET NULL from parsed_logs — but neither
-- column was indexed. Postgres resolves those referential actions with a
-- per-deleted-row child lookup, so every raw_logs row a retention purge
-- removed triggered a full sequential scan of parsed_logs (millions of rows).
-- A single 10k-row delete batch meant 10k seq scans: manual cleanup appeared
-- frozen while saturating the database. With these indexes each lookup is an
-- index probe and batched retention deletes run at the intended speed.
--
-- Note: on a large existing install the parsed_logs index build can take a few
-- minutes on first startup after upgrading — one-time cost, during boot,
-- before ingestion starts.
CREATE INDEX IF NOT EXISTS idx_parsed_logs_raw_log_id ON parsed_logs(raw_log_id);
CREATE INDEX IF NOT EXISTS idx_alerts_parsed_log_id ON alerts(parsed_log_id);
