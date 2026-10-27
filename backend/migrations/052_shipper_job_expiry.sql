-- Migration 052: shipper scan jobs expire, and remember where they came from.
--
-- A scan with "Run from" a log shipper is created 'queued' and waits for that
-- shipper to claim it (migrations 032/033). Queued jobs used to wait forever,
-- so a one-off scan queued while its shipper was offline ran whenever the
-- shipper came back, days later. Now a queued job its shipper doesn't claim
-- within shipper_job_expiry_hours (default 24) becomes status 'expired' and is
-- never run (services/scanner/shipperJobs.ts: a sweep every five minutes, and
-- every claim query refuses older rows).
--
-- Neither vulnerability_scans.status nor discovery_scans.status has a CHECK
-- constraint (plain VARCHAR, see 001 and 026), so 'expired' needs no
-- constraint change.
--
-- discovery_scans gains scan_options, like vulnerability_scans has: where the
-- scan was started from (origin) and, for a scan of public address space, who
-- confirmed it (publicTargetsConfirmation). NULL on older rows.
--
-- Idempotent: re-runs on every start.

ALTER TABLE discovery_scans ADD COLUMN IF NOT EXISTS scan_options JSONB;

-- The expiry sweep looks only at queued shipper jobs, by age.
CREATE INDEX IF NOT EXISTS idx_scans_shipper_queued_created
    ON vulnerability_scans (created_at)
    WHERE assigned_shipper_id IS NOT NULL AND status = 'queued';
CREATE INDEX IF NOT EXISTS idx_discovery_scans_shipper_queued_created
    ON discovery_scans (created_at)
    WHERE assigned_shipper_id IS NOT NULL AND status = 'queued';

-- The default window. An admin's own value is kept on re-run.
INSERT INTO system_settings (key, value)
VALUES ('shipper_job_expiry_hours', '24')
ON CONFLICT (key) DO NOTHING;

COMMENT ON COLUMN vulnerability_scans.status IS
    'Scan status: queued, running, completed, failed, cancelled, expired (a shipper job never claimed within shipper_job_expiry_hours)';
COMMENT ON COLUMN discovery_scans.scan_options IS
    'origin (the page or schedule that started the scan) and publicTargetsConfirmation (who confirmed public CIDRs); NULL on older rows';
