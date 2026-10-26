-- Migration 048: Application Monitoring — which software runs where, from the
-- evidence SIEMBox already has (log program names, which parser matched,
-- nmap services, shipper-reported container images, EDR package findings and
-- OS, user agents and DNS queries in parsed logs), matched against the
-- catalog's application signatures (applications/<id>.app.yaml).
--
-- Filled off the ingest path by jobs/applicationInventory.ts: an id cursor
-- over parsed_logs (every raw log has one parsed_logs row, parsed or not; its
-- raw log is read through a bounded id range join, as the Context Graph
-- rollup does), plus a refresh of the small tables every run. Nothing here
-- touches raw_logs or parsed_logs: no new index, trigger or column on the
-- ingest path. Rows not seen for application_inventory_retention_days drop out.
-- Idempotent: re-runs on every start.

-- One row per (application, location, source, version). A location is
--   host     a logging host (syslog header hostname, else the sender IP)
--   asset    an asset id (nmap services, EDR findings and OS)
--   shipper  a log shipper id (its host's containers)
--   client   a client IP seen on the network (user agents, DNS queries)
-- version '' means none was seen. Log sources add up `events`; snapshot
-- sources (service_scan, container, edr_package, os) set it to what the
-- snapshot holds now.
CREATE TABLE IF NOT EXISTS application_inventory (
  app_id      TEXT        NOT NULL,
  loc_type    TEXT        NOT NULL,
  loc_key     TEXT        NOT NULL,
  source      TEXT        NOT NULL,             -- syslog_program|parser|service_scan|container|edr_package|os|user_agent|dns
  version     TEXT        NOT NULL DEFAULT '',
  events      BIGINT      NOT NULL DEFAULT 0,
  first_seen  TIMESTAMPTZ NOT NULL,
  last_seen   TIMESTAMPTZ NOT NULL,
  evidence    JSONB,                            -- the latest sample: the value matched, a raw log id, a port, an image
  PRIMARY KEY (app_id, loc_type, loc_key, source, version)
);
-- Retention pruning, and the host filter / detail lookups by location.
CREATE INDEX IF NOT EXISTS idx_application_inventory_last_seen ON application_inventory (last_seen);
CREATE INDEX IF NOT EXISTS idx_application_inventory_location ON application_inventory (loc_type, loc_key);

-- Which asset each inventory location is, where SIEMBox knows: an asset id;
-- a logging host or client by IP (assets.ip_address) or by host name; a log
-- shipper by its address. Equality joins only (each one a hash join over the
-- small assets table). A location can be no asset, or (duplicate host
-- names) more than one.
CREATE OR REPLACE VIEW application_location_assets AS
  SELECT i.app_id, i.loc_type, i.loc_key, i.source, a.id AS asset_id
    FROM application_inventory i JOIN assets a ON i.loc_type = 'asset' AND i.loc_key = a.id::text
  UNION ALL
  SELECT i.app_id, i.loc_type, i.loc_key, i.source, a.id
    FROM application_inventory i JOIN assets a ON i.loc_type IN ('host', 'client') AND i.loc_key = host(a.ip_address)
  UNION ALL
  SELECT i.app_id, i.loc_type, i.loc_key, i.source, a.id
    FROM application_inventory i JOIN assets a ON i.loc_type = 'host' AND a.hostname IS NOT NULL AND i.loc_key = lower(a.hostname)
  UNION ALL
  SELECT i.app_id, i.loc_type, i.loc_key, i.source, a.id
    FROM application_inventory i
    JOIN log_shippers s ON i.loc_type = 'shipper' AND i.loc_key = s.id::text
    JOIN assets a ON s.ip_address IS NOT NULL AND host(a.ip_address) = s.ip_address;

-- Values no signature matched, for the "not identified" list (and the
-- catalog's contributors): syslog program names, container image names, user
-- agent products. Capped per source by the job.
CREATE TABLE IF NOT EXISTS application_unmatched (
  source          TEXT        NOT NULL,         -- syslog_program|container|user_agent
  value           TEXT        NOT NULL,
  events          BIGINT      NOT NULL DEFAULT 0,
  locations       INTEGER     NOT NULL DEFAULT 1, -- distinct locations in the batch that last saw it (a lower bound)
  first_seen      TIMESTAMPTZ NOT NULL,
  last_seen       TIMESTAMPTZ NOT NULL,
  sample_location TEXT,
  sample          TEXT,                         -- a full value (a whole user agent, an image reference)
  PRIMARY KEY (source, value)
);
CREATE INDEX IF NOT EXISTS idx_application_unmatched_rank ON application_unmatched (source, events DESC);
CREATE INDEX IF NOT EXISTS idx_application_unmatched_last_seen ON application_unmatched (last_seen);

-- Open vulnerabilities linked to an application on an asset, rebuilt by every
-- run: match 'package' is exact (an EDR finding for one of the signature's
-- packages), 'product' is best effort (a finding on an asset where the
-- application was seen, whose title or template names the product).
CREATE TABLE IF NOT EXISTS application_vuln_links (
  app_id           TEXT    NOT NULL,
  asset_id         INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  vulnerability_id INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
  match            TEXT    NOT NULL,            -- package|product
  version          TEXT    NOT NULL DEFAULT '',
  PRIMARY KEY (app_id, asset_id, vulnerability_id)
);
CREATE INDEX IF NOT EXISTS idx_application_vuln_links_vuln ON application_vuln_links (vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_application_vuln_links_asset ON application_vuln_links (asset_id);

-- The signature set the inventory was last built with (names, categories and
-- matchers for the page, and the fallback while the catalog is unreachable).
CREATE TABLE IF NOT EXISTS application_signatures (
  id          TEXT        PRIMARY KEY,
  name        TEXT        NOT NULL,
  vendor      TEXT        NOT NULL,
  category    TEXT        NOT NULL,
  definition  JSONB       NOT NULL,
  source      TEXT        NOT NULL,             -- catalog|cache|stored|bundled
  fetched_at  TIMESTAMPTZ,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The job's cursor and bookkeeping: one row. The cursor commits with each
-- batch's rows, so a crash replays a batch and counts nothing twice.
CREATE TABLE IF NOT EXISTS application_inventory_state (
  id                 SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  last_parsed_log_id BIGINT,                    -- NULL: not started; the job picks the backfill start
  covered_from       TIMESTAMPTZ,
  covered_until      TIMESTAMPTZ,               -- created_at of the last log consumed
  caught_up          BOOLEAN     NOT NULL DEFAULT FALSE,
  signatures_hash    TEXT,
  signatures_source  TEXT,
  signatures_count   INTEGER     NOT NULL DEFAULT 0,
  signatures_error   TEXT,
  refused_regexes    JSONB       NOT NULL DEFAULT '[]'::jsonb,
  last_refresh_at    TIMESTAMPTZ,
  last_pruned_at     TIMESTAMPTZ,
  last_run_at        TIMESTAMPTZ,
  last_summary       TEXT
);
INSERT INTO application_inventory_state (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

-- Settings (Settings -> Application Monitoring). The keys avoid the
-- retention_%_days pattern cleanupService reads.
INSERT INTO system_settings (key, value, description) VALUES
  ('application_inventory_enabled', 'true', 'Application Monitoring: build the software inventory'),
  ('application_inventory_retention_days', '30', 'Application Monitoring: days an application stays listed after it was last seen'),
  ('application_inventory_backfill_days', '7', 'Application Monitoring: days of existing logs to process after upgrading')
ON CONFLICT (key) DO NOTHING;
