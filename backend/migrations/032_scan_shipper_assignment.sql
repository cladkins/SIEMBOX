-- Let an asset/vuln scan be dispatched to a log shipper instead of running on
-- the SIEMBox backend itself.
--
-- The backend container is normally on the Docker bridge network, so its own
-- nmap can't see the real LAN (ARP host-discovery is link-local; auto-detected
-- "LAN" is just the bridge subnet). A log shipper already runs out on the LAN,
-- already authenticates and pulls config, and already feeds container-image
-- inventory to vuln scanning -- so it is the natural place to run a network
-- scan from. assigned_shipper_id records which shipper a scan was handed to.
--
--   NULL            -> run in-process on the backend, exactly as before.
--   <a shipper id>  -> the row stays 'queued' until that shipper claims it via
--                      GET /api/shippers/:api_key/scan-jobs (which stamps
--                      claimed_at and flips it to 'running'); the shipper runs
--                      nmap locally and posts results to
--                      POST /api/shippers/scan-results.
--
-- ON DELETE SET NULL: deleting a shipper must not delete its scan history; the
-- scan simply loses its assignment (a finished scan keeps its stored results).
--
-- Idempotent: ADD COLUMN IF NOT EXISTS + guarded index, re-runnable on startup.
ALTER TABLE vulnerability_scans
    ADD COLUMN IF NOT EXISTS assigned_shipper_id INTEGER REFERENCES log_shippers(id) ON DELETE SET NULL;

ALTER TABLE vulnerability_scans
    ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ;

-- The shipper job-pull looks up its own queued jobs: (assigned_shipper_id, status).
CREATE INDEX IF NOT EXISTS idx_scans_assigned_shipper
    ON vulnerability_scans(assigned_shipper_id, status)
    WHERE assigned_shipper_id IS NOT NULL;
