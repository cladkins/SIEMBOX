-- Migration 051: Application Monitoring authoring. Local application
-- signatures (written on the Application Monitoring page, in the catalog's
-- siembox.app/v1 format), a local ignore list for the "Not identified" list,
-- and the bookkeeping that lets a new signature match evidence the rollup's
-- cursor has already passed (a bounded look back over parsed_logs for just
-- the new or changed signatures).
-- Idempotent: re-runs on every start.

-- One row per local signature. `definition` is the signature as validated
-- (appFormat.validateApplication); `yaml` the text the author saved, for the
-- editor. A local id that is also a catalog id overrides the catalog's
-- signature while it is enabled.
CREATE TABLE IF NOT EXISTS custom_application_signatures (
  id          TEXT        PRIMARY KEY,          -- the signature id (kebab-case), unique
  definition  JSONB       NOT NULL,
  yaml        TEXT        NOT NULL,
  enabled     BOOLEAN     NOT NULL DEFAULT TRUE,
  created_by  TEXT,                             -- username
  updated_by  TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Values an analyst marked "not an application" in the Not identified list.
-- Hidden from the list (still collected), shown again with "Show ignored".
CREATE TABLE IF NOT EXISTS application_unmatched_ignores (
  source      TEXT        NOT NULL,
  value       TEXT        NOT NULL,
  created_by  TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (source, value)
);

-- The structured sample of an unmatched value (a service's name, version,
-- banner and port; a package's type and version), for the signature editor's
-- pre-filled matcher and the Test button.
ALTER TABLE application_unmatched ADD COLUMN IF NOT EXISTS detail JSONB;

-- Look back for new signatures. A row inserted while its application was
-- being looked back for carries that look-back's generation; the look-back
-- adds history only to rows of its own generation, so evidence counted
-- before the signature changed is never counted twice.
ALTER TABLE application_inventory ADD COLUMN IF NOT EXISTS rescan_gen BIGINT;

ALTER TABLE application_inventory_state ADD COLUMN IF NOT EXISTS rescan_pending TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE application_inventory_state ADD COLUMN IF NOT EXISTS rescan_apps TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE application_inventory_state ADD COLUMN IF NOT EXISTS rescan_gen BIGINT NOT NULL DEFAULT 0;
ALTER TABLE application_inventory_state ADD COLUMN IF NOT EXISTS rescan_from BIGINT;   -- the look-back's lower bound (exclusive)
ALTER TABLE application_inventory_state ADD COLUMN IF NOT EXISTS rescan_next BIGINT;   -- it walks down from here (inclusive)
ALTER TABLE application_inventory_state ADD COLUMN IF NOT EXISTS rescan_total BIGINT;  -- ids to look at, for the progress shown
ALTER TABLE application_inventory_state ADD COLUMN IF NOT EXISTS rescan_started_at TIMESTAMPTZ;
ALTER TABLE application_inventory_state ADD COLUMN IF NOT EXISTS unmatched_packages_at TIMESTAMPTZ;
