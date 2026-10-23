-- 047_content_pack_installs.sql — what each Content Pack install covered.
--
-- One row per installed pack: the pack version and the item list it held when
-- it was installed (parser names, catalog detection names, SigmaHQ rule ids).
-- The Content Packs page compares that snapshot with the pack as the catalog
-- has it now: items in the current pack that are not in the snapshot are
-- "What's new since you installed", and "Install what's new" installs only
-- those, then adds them to the snapshot. A full (re)install replaces the
-- snapshot with the pack's current item list.
--
-- `pending` holds the items the last install could not finish and why (a Sigma
-- rule while the SigmaHQ library is not loaded, a refused regex, a name the
-- catalog no longer has), for the page to show after a reload.
--
-- Idempotent (IF NOT EXISTS throughout); runs on every startup. Fresh installs
-- start with no rows: nothing is installed until an admin installs a pack.

CREATE TABLE IF NOT EXISTS content_pack_installs (
  pack_id TEXT PRIMARY KEY,
  version INTEGER NOT NULL,
  -- Where the pack definition came from: 'catalog' or 'bundled' (the built-in
  -- fallback used when the catalog has no packs/ or cannot be reached).
  source TEXT NOT NULL DEFAULT 'catalog',
  installed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  installed_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  installed_by_username TEXT,
  parsers TEXT[] NOT NULL DEFAULT '{}',
  detections TEXT[] NOT NULL DEFAULT '{}',
  sigma TEXT[] NOT NULL DEFAULT '{}',
  pending JSONB NOT NULL DEFAULT '[]'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
