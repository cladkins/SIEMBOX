-- Migration 014: allow 'container' scheduled scans (Trivy image scans).
--
-- 005 constrained scheduled_scans.scan_type to ('asset','vulnerability'); add
-- 'container' so a recurring Trivy image scan can be scheduled alongside the
-- Nmap (asset) and Nuclei (vulnerability) ones. scan_options for a container
-- schedule is { image_ref }.
--
-- Idempotent: drop-then-add the named constraint, re-runnable on every startup.
-- Migrations re-run in order on every start, so this names the current full
-- list (056 added 'log_discovery'): a narrower list here would fail on rows of
-- a type added later, before 056 could widen it again.

ALTER TABLE scheduled_scans DROP CONSTRAINT IF EXISTS scheduled_scans_type_chk;
ALTER TABLE scheduled_scans
  ADD CONSTRAINT scheduled_scans_type_chk
  CHECK (scan_type IN ('asset', 'vulnerability', 'container', 'log_discovery'));
