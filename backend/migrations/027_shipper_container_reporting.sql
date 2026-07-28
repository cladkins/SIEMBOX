-- Track each shipper's container-inventory reporting state.
--
-- Container Scanning lists the SIEMBox host's images plus the images each log
-- shipper reports from its own host. When a shipper's images were missing there
-- was nothing to look at: shipper_containers simply had no rows, and an empty
-- table looks identical whether the shipper is too old to report, has no Docker
-- socket mounted, or has reporting switched off. These columns record what the
-- shipper actually told us so the UI can say which of those it is.
--
-- containers_reported_at is set on every report (including an empty one);
-- containers_available records whether the shipper could see a Docker daemon.
-- NULL on both means "this shipper has never reported" — i.e. it predates the
-- feature or has CONTAINER_REPORT_INTERVAL=0.
--
-- Idempotent: ADD COLUMN IF NOT EXISTS, re-runnable on every startup.
ALTER TABLE log_shippers
    ADD COLUMN IF NOT EXISTS containers_reported_at TIMESTAMPTZ;

ALTER TABLE log_shippers
    ADD COLUMN IF NOT EXISTS containers_available BOOLEAN;

ALTER TABLE log_shippers
    ADD COLUMN IF NOT EXISTS containers_unavailable_reason TEXT;
