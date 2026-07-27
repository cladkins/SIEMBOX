-- Hourly per-parser match counters, maintained incrementally by the parser
-- engine at ingest. The parse-coverage and parser match-stats endpoints read
-- these instead of aggregating parsed_logs (a multi-million-row scan per page
-- view on busy installs, which timed out the UI). parser_id 0 is the unparsed
-- fallback (no real parser ever has id 0 — SERIAL starts at 1); no FK so
-- deleting a parser keeps its historical counts. Buckets use server ingest
-- time, so sender clock skew cannot distort the stats. Rows older than 8 days
-- are pruned opportunistically by the engine's flush path.
CREATE TABLE IF NOT EXISTS parser_match_hourly (
  hour TIMESTAMP NOT NULL,
  parser_id INTEGER NOT NULL DEFAULT 0,
  matches BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (hour, parser_id)
);
