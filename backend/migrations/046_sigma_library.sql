-- 046_sigma_library.sql — the SigmaHQ library (Detection Rules > SigmaHQ).
--
-- sigma_library_state   one row: which SigmaHQ release the cache holds, when it
--                       was fetched, and the last refresh failure (an
--                       air-gapped install keeps its last cache and shows why).
-- sigma_library_rules   the cached, parsed and converted rules of that release,
--                       one row per Sigma rule id, so a restart never refetches.
--                       `parts` holds the converted SIEMBox rules (one per OR
--                       alternative); `content_hash` is the sha256 of the rule
--                       file, which "update available" compares.
-- detection_rules       provenance of a rule added from the library: the Sigma
--                       id, the release and file hash it was installed from,
--                       and which part (1..N) of a split Sigma rule it is. NULL
--                       for every other rule.
--
-- Idempotent (IF NOT EXISTS throughout); runs on every startup. Fresh installs
-- ship no rules: the library is filled by its first refresh.

CREATE TABLE IF NOT EXISTS sigma_library_state (
  id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  release_tag TEXT,
  asset TEXT,
  release_date TEXT,
  commit_hash TEXT,
  archive_bytes INTEGER,
  archive_sha256 TEXT,
  rule_count INTEGER NOT NULL DEFAULT 0,
  convertible_count INTEGER NOT NULL DEFAULT 0,
  -- SIEMBox's converter version that built the cache: an upgrade that converts
  -- differently rebuilds it at the next refresh even when the release is the same.
  builder_version INTEGER,
  fetched_at TIMESTAMPTZ,
  last_attempt_at TIMESTAMPTZ,
  last_error TEXT,
  last_error_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS sigma_library_rules (
  sigma_id TEXT PRIMARY KEY,
  release_tag TEXT NOT NULL,
  path TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  level TEXT,
  status TEXT,
  product TEXT,
  category TEXT,
  service TEXT,
  tags TEXT[] NOT NULL DEFAULT '{}',
  author TEXT,
  rule_date TEXT,
  modified TEXT,
  refs TEXT[] NOT NULL DEFAULT '{}',
  content_hash TEXT NOT NULL,
  convertible BOOLEAN NOT NULL DEFAULT FALSE,
  errors JSONB NOT NULL DEFAULT '[]'::jsonb,
  warnings JSONB NOT NULL DEFAULT '[]'::jsonb,
  parts JSONB NOT NULL DEFAULT '[]'::jsonb,
  fields TEXT[] NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS sigma_library_rules_convertible_idx ON sigma_library_rules (convertible);

ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS sigma_id TEXT;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS sigma_release TEXT;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS sigma_hash TEXT;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS sigma_part INTEGER;

CREATE INDEX IF NOT EXISTS sigma_detection_rules_sigma_id_idx ON detection_rules (sigma_id) WHERE sigma_id IS NOT NULL;
