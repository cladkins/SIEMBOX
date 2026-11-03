-- Docker sources that tail every running container (blank container_name) can
-- now skip containers by name, and skip SIEMBox's own containers by default.
--
-- container_exclude: names or shell globs, separated by commas, spaces or
--   newlines ("redis, *-sidecar"). NULL or empty excludes nothing extra.
-- include_siembox_containers: FALSE (the default) skips siembox-backend,
--   siembox-postgres, siembox-frontend and siembox-log-shipper. Shipping
--   SIEMBox's own logs back into SIEMBox is a feedback loop: every ingested
--   line writes more log. Set TRUE to opt in.
--
-- Both are ignored when container_name names one container: naming it is the
-- opt-in. Idempotent; re-runs on every startup like the other migrations.
ALTER TABLE shipper_sources ADD COLUMN IF NOT EXISTS container_exclude TEXT;
ALTER TABLE shipper_sources ADD COLUMN IF NOT EXISTS include_siembox_containers BOOLEAN NOT NULL DEFAULT FALSE;
