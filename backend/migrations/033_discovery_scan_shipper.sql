-- Let a log-discovery scan be dispatched to a log shipper, the same way
-- migration 032 did for asset (nmap) and vulnerability (nuclei) scans.
--
-- Active discovery sweeps the LAN (ARP/mDNS/SSDP + port/HTTP/TLS probes), which
-- the backend can't reach from inside the Docker bridge. A shipper runs on the
-- LAN, so it can run the full discovery probe and post the observed signals
-- back for the backend to fingerprint-match. Unlike the nmap/nuclei path this is
-- a SEPARATE table (discovery_scans), so the assignment columns live here too.
--
--   assigned_shipper_id NULL  -> run in-process on the backend, exactly as before.
--   assigned_shipper_id set    -> the row is created 'queued' and waits until that
--                                 shipper claims it via the job-pull (which stamps
--                                 claimed_at and flips it to 'running'); the shipper
--                                 runs the probe and posts results to
--                                 POST /api/shippers/discovery-results.
--
-- ON DELETE SET NULL: deleting a shipper must not delete scan history; the scan
-- simply loses its assignment.
--
-- Idempotent: ADD COLUMN IF NOT EXISTS + guarded index, re-runnable on startup.
-- (status is a plain VARCHAR with no CHECK, so the new 'queued' value needs no
-- constraint change -- see migration 026.)
ALTER TABLE discovery_scans
    ADD COLUMN IF NOT EXISTS assigned_shipper_id INTEGER REFERENCES log_shippers(id) ON DELETE SET NULL;

ALTER TABLE discovery_scans
    ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ;

-- The shipper job-pull looks up its own queued discovery jobs.
CREATE INDEX IF NOT EXISTS idx_discovery_scans_assigned_shipper
    ON discovery_scans(assigned_shipper_id, status)
    WHERE assigned_shipper_id IS NOT NULL;
