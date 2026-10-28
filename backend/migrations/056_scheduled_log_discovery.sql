-- Migration 056: allow 'log_discovery' scheduled scans.
--
-- A recurring Log Discovery sweep (passive, active or full) can now be
-- scheduled alongside the Nmap (asset), Nuclei (vulnerability) and Trivy
-- (container) ones. scan_options for it is
--   { mode: 'passive' | 'active' | 'full',
--     manual_cidrs?: [CIDR, ...],     -- omitted: the saved Log Discovery scope
--     assignedShipperId?: N }         -- run it from a log shipper
-- and last_scan_id names a discovery_scans row (see jobs/scheduledScans.ts).
-- Suggested scans from the catalog (routes/scanSuggestions.ts) add schedules
-- of every type, disabled until their targets are filled in.
--
-- Idempotent: drop-then-add the named constraint, re-runnable on every startup.

ALTER TABLE scheduled_scans DROP CONSTRAINT IF EXISTS scheduled_scans_type_chk;
ALTER TABLE scheduled_scans
  ADD CONSTRAINT scheduled_scans_type_chk
  CHECK (scan_type IN ('asset', 'vulnerability', 'container', 'log_discovery'));
