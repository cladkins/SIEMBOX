-- Migration 044: Context Graph, part 2: a daily rollup of the relationships
-- logs show (which IP signed in as which user, which device logged it, which
-- domains an IP queried, ...).
--
-- Filled off the ingest path by jobs/graphLogEdges.ts, an id cursor over
-- parsed_logs that runs every minute on the main pool and stays about two
-- minutes behind ingestion; pruned by the same job to the raw-log retention
-- (30 days by default). Nothing here touches raw_logs or parsed_logs: no new
-- index, trigger or column on the ingest path.
--
-- One row per (ingest day, relation, a, b). Days are parsed_logs.created_at
-- days, so a batch touches one or two days whatever the senders' clocks say.
-- Idempotent: re-runs on every start.
CREATE TABLE IF NOT EXISTS graph_log_edges (
  day        DATE      NOT NULL,
  rel        TEXT      NOT NULL,             -- signed_in_as|seen_on|user_on|connected_to|queried|sent_by|shipped_by
  a_type     TEXT      NOT NULL,
  a_value    TEXT      NOT NULL,
  b_type     TEXT      NOT NULL,
  b_value    TEXT      NOT NULL,
  events     INTEGER   NOT NULL,
  failures   INTEGER   NOT NULL DEFAULT 0,   -- parsed_data.auth_outcome = 'failure'
  successes  INTEGER   NOT NULL DEFAULT 0,   -- parsed_data.auth_outcome = 'success'
  first_seen TIMESTAMP NOT NULL,             -- parsed_logs.created_at of the first and last log
  last_seen  TIMESTAMP NOT NULL,
  PRIMARY KEY (a_type, a_value, day, rel, b_type, b_value)
);
-- The b-side lookups (who signed in as this user, who queried this domain).
CREATE INDEX IF NOT EXISTS idx_graph_log_edges_b ON graph_log_edges (b_type, b_value, day);
-- Pruning by day.
CREATE INDEX IF NOT EXISTS idx_graph_log_edges_day ON graph_log_edges (day);

-- The job's cursor and bookkeeping: one row. The cursor and the counts commit
-- with each batch's edges, so a crash replays a batch and counts nothing twice.
CREATE TABLE IF NOT EXISTS graph_log_edges_state (
  id                 SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  last_parsed_log_id BIGINT,                 -- NULL: not started; the job picks the backfill start
  covered_from       DATE,                   -- the first day relationships exist for
  covered_until      TIMESTAMP,              -- created_at of the last log consumed
  caught_up          BOOLEAN NOT NULL DEFAULT FALSE, -- the backfill has reached the live edge once
  new_rows_day       DATE,                   -- the day new_rows_count counts
  new_rows_count     INTEGER NOT NULL DEFAULT 0,
  truncated_days     DATE[]  NOT NULL DEFAULT '{}', -- days the daily cap cut short
  last_pruned_at     TIMESTAMPTZ,
  last_run_at        TIMESTAMPTZ
);
INSERT INTO graph_log_edges_state (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

-- Key rules for the values logs carry (attacker-controlled), the SQL twins of
-- services/graph/entityKey.ts: a parity test runs ENTITY_KEY_FIXTURES through
-- both. A control or bidi character anywhere makes a value no key at all;
-- btrim() trims spaces only, as trimSpaces() does.
CREATE OR REPLACE FUNCTION graph_user(v TEXT) RETURNS TEXT
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT CASE
    WHEN v IS NULL OR v ~ '[\u0001-\u001f\u007f-\u009f؜‎‏‪-‮⁦-⁩]' THEN NULL
    WHEN length(btrim(v)) = 0 OR length(btrim(v)) > 128 THEN NULL
    WHEN lower(btrim(v)) IN ('-', 'unknown', 'null', 'none', '(null)', 'n/a', 'nobody', '?') THEN NULL
    ELSE btrim(v) END $$;

-- A host a log names (the syslog header host): canonicalHost() and not one of
-- the "nobody" words (resolvers/alerts.ts logHost()).
CREATE OR REPLACE FUNCTION graph_log_host(v TEXT) RETURNS TEXT
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT CASE
    WHEN v IS NULL OR v ~ '[\u0001-\u001f\u007f-\u009f؜‎‏‪-‮⁦-⁩]' THEN NULL
    WHEN length(btrim(v)) = 0 OR length(btrim(v)) > 253 THEN NULL
    WHEN btrim(v) ~ '[    -     　﻿]' THEN NULL
    WHEN lower(btrim(v)) IN ('-', 'unknown', 'null', 'none', '(null)', 'n/a', 'nobody', '?') THEN NULL
    ELSE lower(btrim(v)) END $$;

CREATE OR REPLACE FUNCTION graph_domain(v TEXT) RETURNS TEXT
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT CASE
    WHEN d IS NULL OR length(d) = 0 OR length(d) > 253 OR position('.' IN d) = 0 OR left(d, 1) = '.' THEN NULL
    WHEN d ~ '[    -     　﻿]' THEN NULL
    ELSE d END
  FROM (SELECT CASE WHEN v ~ '[\u0001-\u001f\u007f-\u009f؜‎‏‪-‮⁦-⁩]' THEN NULL
                    ELSE rtrim(lower(btrim(v)), '.') END AS d) s $$;

-- IPv4 dotted (no leading zeros); ::ffff:a.b.c.d folds to IPv4; IPv6 in its
-- RFC 5952 form. Compared as written: no trimming.
CREATE OR REPLACE FUNCTION graph_ip(v TEXT) RETURNS TEXT
LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE AS $$
DECLARE
  v4 CONSTANT TEXT := '(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}';
  r TEXT;
  o INT[];
BEGIN
  IF v IS NULL OR length(v) = 0 OR length(v) > 45 THEN RETURN NULL; END IF;
  IF v ~ ('^' || v4 || '$') THEN RETURN v; END IF;
  IF v ~* ('^::ffff:' || v4 || '$') THEN RETURN substring(v FROM 8); END IF;
  -- IPv6 only (the rare path): no zone id, no prefix length.
  IF v !~* '^[0-9a-f:.]{2,45}$' OR position(':' IN v) = 0 THEN RETURN NULL; END IF;
  BEGIN
    r := lower(host(v::inet));
  EXCEPTION WHEN others THEN
    RETURN NULL;
  END;
  IF r ~ ('^::ffff:' || v4 || '$') THEN RETURN substring(r FROM 8); END IF;
  -- Postgres prints ::a.b.c.d (IPv4-compatible) dotted; the RFC 5952 form is hex.
  IF r ~ ('^::' || v4 || '$') THEN
    o := string_to_array(substring(r FROM 3), '.')::INT[];
    IF o[1] * 256 + o[2] = 0 THEN
      RETURN CASE WHEN o[3] * 256 + o[4] = 0 THEN '::' ELSE '::' || to_hex(o[3] * 256 + o[4]) END;
    END IF;
    RETURN '::' || to_hex(o[1] * 256 + o[2]) || ':' || to_hex(o[3] * 256 + o[4]);
  END IF;
  RETURN r;
END $$;

-- Settings (Settings -> Context Graph). The keys avoid the retention_%_days
-- pattern cleanupService reads.
INSERT INTO system_settings (key, value, description) VALUES
  ('graph_log_edges_enabled', 'true', 'Context Graph: build relationships seen in logs'),
  ('graph_log_edges_retention_days', '0', 'Context Graph: days of log relationships to keep (0 = same as raw logs)'),
  ('graph_log_edges_daily_new_cap', '500000', 'Context Graph: new relationship rows per day before the day is marked incomplete'),
  ('graph_log_edges_backfill_days', '7', 'Context Graph: days of existing logs to process after upgrading')
ON CONFLICT (key) DO NOTHING;
