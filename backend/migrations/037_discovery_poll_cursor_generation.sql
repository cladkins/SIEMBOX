-- Migration 037: which reset of an API poller's cursor a running poll started from.
--
-- A poll reads its source's poller row when it starts and writes the new
-- poll_cursor when it ends. An edit that clears the cursor while the poll runs
-- (a new address or endpoint, PATCH /api/log-discovery/sources/:id) must win:
-- that poll's cursor belongs to the old target. Every such reset now gives the
-- row a new cursor_generation, and a poll writes its cursor only while the row
-- still has the generation the poll started with. The other writes to the row
-- (polling on or off, the interval, a new token for the same address, a poll's
-- result) leave it as it is, so they never make a running poll drop its cursor
-- and store the same lines again on the next poll.
--
-- The values come from a sequence rather than a per-row counter, so a row that
-- is deleted (token revoked) and saved again never repeats a generation a poll
-- still running for the old row holds. Existing rows each get a value of their
-- own when the column is added.
--
-- Idempotent: CREATE SEQUENCE IF NOT EXISTS, ADD COLUMN IF NOT EXISTS, and
-- OWNED BY, which only ties the sequence to the column (dropped with it).
CREATE SEQUENCE IF NOT EXISTS discovery_poll_cursor_generation_seq;

ALTER TABLE discovery_source_pollers
  ADD COLUMN IF NOT EXISTS cursor_generation BIGINT NOT NULL DEFAULT nextval('discovery_poll_cursor_generation_seq');

ALTER SEQUENCE discovery_poll_cursor_generation_seq OWNED BY discovery_source_pollers.cursor_generation;
