-- Migration 043: Context Graph, part 1: indexed entity lookups on alerts and audit_logs.
--
-- Alerts keep a copy of the parsed fields in matched_data. The Context Graph
-- (services/graph), Threat Intel's IP view (routes/threatIntel.ts) and Asset-360
-- (services/assets/assetContext.ts) look alerts up by them, which no index
-- served before (only trigram GINs), so each lookup read every alert.
-- created_at DESC serves the graph's "latest N in the window".
--
-- The expressions are the graph's key rules in SQL (btrim, lower, trailing
-- dots), so an alert is found by the key the graph shows for it. They are
-- written in services/graph/alertKeys.ts, which every lookup uses; a test
-- checks that this file holds exactly its statements.
--
-- Partial on octet_length(...) <= 2000: matched_data values come from logs and
-- can be any size, and a btree entry larger than about 2.7 kB would make the
-- alert INSERT fail (or this migration, on an existing database). Each lookup
-- states the same bound, so the planner can use these; no real key is that long.
-- Rows without the key aren't indexed either, which keeps them small.
--
-- Alerts are low-volume (cooldown-collapsed), so these build in seconds even at
-- about a million alerts. Plain CREATE INDEX: scripts/migrate.ts runs this file
-- as one multi-statement query, so CONCURRENTLY is impossible. Names carry the
-- feature (idx_graph_*), so they can't clash with another feature's indexes on
-- the same tables. Idempotent: re-runs on every start.
CREATE INDEX IF NOT EXISTS idx_graph_alerts_md_source_ip ON alerts ((matched_data->>'source_ip'), created_at DESC) WHERE octet_length(matched_data->>'source_ip') <= 2000;
CREATE INDEX IF NOT EXISTS idx_graph_alerts_md_client_ip ON alerts ((matched_data->>'client_ip'), created_at DESC) WHERE octet_length(matched_data->>'client_ip') <= 2000;
CREATE INDEX IF NOT EXISTS idx_graph_alerts_md_dest_ip ON alerts ((matched_data->>'dest_ip'), created_at DESC) WHERE octet_length(matched_data->>'dest_ip') <= 2000;
CREATE INDEX IF NOT EXISTS idx_graph_alerts_md_user ON alerts ((btrim(matched_data->>'user')), created_at DESC) WHERE octet_length(btrim(matched_data->>'user')) <= 2000;
CREATE INDEX IF NOT EXISTS idx_graph_alerts_md_target_user ON alerts ((btrim(matched_data->>'target_user')), created_at DESC) WHERE octet_length(btrim(matched_data->>'target_user')) <= 2000;
CREATE INDEX IF NOT EXISTS idx_graph_alerts_md_host ON alerts ((lower(btrim(matched_data->>'host'))), created_at DESC) WHERE octet_length(lower(btrim(matched_data->>'host'))) <= 2000;
CREATE INDEX IF NOT EXISTS idx_graph_alerts_md_domain ON alerts ((rtrim(lower(btrim(matched_data->>'domain')), '.')), created_at DESC) WHERE octet_length(rtrim(lower(btrim(matched_data->>'domain')), '.')) <= 2000;

-- Small populations, so also limited to their source: their lookups always say source = '...'.
CREATE INDEX IF NOT EXISTS idx_graph_alerts_auth_user_id ON alerts ((matched_data->>'user_id'), created_at DESC) WHERE source = 'siembox-auth' AND octet_length(matched_data->>'user_id') <= 2000;
CREATE INDEX IF NOT EXISTS idx_graph_alerts_edr_agent_id ON alerts ((lower(matched_data->>'agent_id')), created_at DESC) WHERE source = 'edr' AND octet_length(lower(matched_data->>'agent_id')) <= 2000;
-- Digital Risk lookalike alerts name the lookalike domain in matched_data.lookalike.
CREATE INDEX IF NOT EXISTS idx_graph_alerts_dm_lookalike ON alerts ((rtrim(lower(btrim(matched_data->>'lookalike')), '.')), created_at DESC) WHERE source = 'domain-monitor' AND octet_length(rtrim(lower(btrim(matched_data->>'lookalike')), '.')) <= 2000;

-- A rule's latest alerts, without sorting all of a noisy rule's alerts.
CREATE INDEX IF NOT EXISTS idx_graph_alerts_rule_created ON alerts (rule_id, created_at DESC) WHERE rule_id IS NOT NULL;

-- Admin-only pivot: SIEMBox sign-ins from an IP. (ip_address = $1 implies IS NOT NULL.)
CREATE INDEX IF NOT EXISTS idx_graph_audit_logs_ip_time ON audit_logs (ip_address, timestamp DESC) WHERE ip_address IS NOT NULL;
