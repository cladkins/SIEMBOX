-- Migration 053: calendar timing for scheduled scans.
--
-- Until now a schedule had only interval_minutes: it ran every N minutes from
-- when it was saved or last ran. A schedule can now instead name wall-clock
-- times in a time zone, stored in `schedule` (JSONB):
--
--   { "frequency": "hourly",  "minute": 15, "every_hours": 6, "timezone": "UTC" }
--   { "frequency": "daily",   "time": "02:00", "timezone": "America/Chicago" }
--   { "frequency": "weekly",  "time": "02:30", "days": [1,2,3,4,5], "timezone": "America/Chicago" }
--   { "frequency": "monthly", "time": "03:00", "day_of_month": 31, "timezone": "Europe/London" }
--
-- (days: 0 = Sunday ... 6 = Saturday; a month without day_of_month runs on its
-- last day.) The backend computes next_run_at from it
-- (src/utils/scheduleTiming.ts) on create, edit, re-enable and after each run.
--
-- schedule IS NULL is the original fixed-interval mode: every existing row
-- stays NULL here and keeps running every interval_minutes exactly as before.
-- A calendar schedule has no interval, so interval_minutes becomes nullable;
-- the CHECK below requires one of the two.
--
-- Idempotent: re-runnable on every startup.

ALTER TABLE scheduled_scans ADD COLUMN IF NOT EXISTS schedule JSONB;
ALTER TABLE scheduled_scans ALTER COLUMN interval_minutes DROP NOT NULL;

ALTER TABLE scheduled_scans DROP CONSTRAINT IF EXISTS scheduled_scans_timing_chk;
ALTER TABLE scheduled_scans
  ADD CONSTRAINT scheduled_scans_timing_chk
  CHECK (schedule IS NOT NULL OR interval_minutes IS NOT NULL);

COMMENT ON COLUMN scheduled_scans.schedule IS
  'Calendar timing {frequency, timezone, time|minute+every_hours, days, day_of_month}; NULL = fixed interval (interval_minutes)';
COMMENT ON COLUMN scheduled_scans.interval_minutes IS
  'Fixed-interval cadence in minutes (schedule IS NULL); NULL for a calendar schedule';
