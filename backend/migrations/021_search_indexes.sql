-- Trigram (pg_trgm) GIN indexes so the Alerts keyword/IP search (and similar
-- ILIKE '%term%' lookups) stay fast as the table grows, instead of sequential
-- scans. Idempotent: safe to re-run on every startup.
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX IF NOT EXISTS idx_alerts_title_trgm
  ON alerts USING gin (title gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_alerts_description_trgm
  ON alerts USING gin (description gin_trgm_ops);

-- matched_data is JSONB; index its text form so an IP/keyword stored inside it
-- (e.g. source_ip) is matched by the alerts `search` filter.
CREATE INDEX IF NOT EXISTS idx_alerts_matched_data_trgm
  ON alerts USING gin ((matched_data::text) gin_trgm_ops);
