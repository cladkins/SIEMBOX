-- Migration 061: Threat Hunting progress and coverage.
--
-- A hunt now searches its lookback window in time slices, newest first, so no
-- single statement has to scan the whole window (services/hunting/huntService.ts).
--   progress        while running: how far the search has got ("searched 6 of 30 days")
--   searched_from   the oldest log time the last run covered; earlier than the
--                   window start only when the run finished the whole window
--   search_complete false when the run stopped early (its time budget ran out
--                   or the row cap was reached), so the counts cover only part
--                   of the window
--
-- Idempotent, like every migration here.

ALTER TABLE threat_hunts ADD COLUMN IF NOT EXISTS progress TEXT;
ALTER TABLE threat_hunts ADD COLUMN IF NOT EXISTS searched_from TIMESTAMPTZ;
ALTER TABLE threat_hunts ADD COLUMN IF NOT EXISTS search_complete BOOLEAN NOT NULL DEFAULT true;
