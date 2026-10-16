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

-- The planner's statistics on the same expressions: Postgres keeps them for a
-- full index's expression but not a partial one's, and without them it takes
-- any value for 0.5% of alerts, rare or common alike. Lookups never OR these
-- keys (one ordered scan per key, alertKeys.ts latestAlerts()), so a bad guess
-- can't send them walking idx_alerts_created_at; with real frequencies a
-- common value's scan also stops at its limit instead of reading every alert
-- that names it. Expression statistics need PostgreSQL 14 or later; SIEMBox
-- runs on 15. Also written in alertKeys.ts (alertKeyStatsSql).
CREATE STATISTICS IF NOT EXISTS graph_alerts_md_source_ip_stats ON (matched_data->>'source_ip') FROM alerts;
CREATE STATISTICS IF NOT EXISTS graph_alerts_md_client_ip_stats ON (matched_data->>'client_ip') FROM alerts;
CREATE STATISTICS IF NOT EXISTS graph_alerts_md_dest_ip_stats ON (matched_data->>'dest_ip') FROM alerts;
CREATE STATISTICS IF NOT EXISTS graph_alerts_md_user_stats ON (btrim(matched_data->>'user')) FROM alerts;
CREATE STATISTICS IF NOT EXISTS graph_alerts_md_target_user_stats ON (btrim(matched_data->>'target_user')) FROM alerts;
CREATE STATISTICS IF NOT EXISTS graph_alerts_md_host_stats ON (lower(btrim(matched_data->>'host'))) FROM alerts;
CREATE STATISTICS IF NOT EXISTS graph_alerts_md_domain_stats ON (rtrim(lower(btrim(matched_data->>'domain')), '.')) FROM alerts;
CREATE STATISTICS IF NOT EXISTS graph_alerts_auth_user_id_stats ON (matched_data->>'user_id') FROM alerts;
CREATE STATISTICS IF NOT EXISTS graph_alerts_edr_agent_id_stats ON (lower(matched_data->>'agent_id')) FROM alerts;
CREATE STATISTICS IF NOT EXISTS graph_alerts_dm_lookalike_stats ON (rtrim(lower(btrim(matched_data->>'lookalike')), '.')) FROM alerts;

-- Fill them now rather than whenever autoanalyze next gets to alerts, and only
-- while one of them has no data yet: the first start after the upgrade (and
-- starts while alerts is empty, when there is nothing to read). Later starts
-- skip it. ANALYZE reads a sample of at most 30,000 rows: about 1.5 s on 1.6
-- million alerts, far less than building the indexes above. It reads
-- pg_stats_ext_exprs, not the catalog under it, which only a superuser may read.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_stats_ext_exprs e
     WHERE e.tablename = 'alerts' AND e.statistics_name LIKE 'graph\_alerts\_%' AND e.null_frac IS NULL
  ) THEN
    ANALYZE alerts;
  END IF;
END $$;

-- A rule's latest alerts, without sorting all of a noisy rule's alerts.
CREATE INDEX IF NOT EXISTS idx_graph_alerts_rule_created ON alerts (rule_id, created_at DESC) WHERE rule_id IS NOT NULL;

-- An asset's latest alerts (EDR detections set asset_id), read in order: the
-- graph's and Asset-360's asset_id arm is ordered by (asset_id, created_at
-- DESC), which only this index gives (alertKeys.ts AlertArm). Before it, for a
-- host whose alerts were mostly older than the window (one endpoint scan can
-- leave hundreds of thousands), the planner walked idx_alerts_created_at back
-- through every alert in the window. idx_alerts_asset_id (016) stays: it also
-- serves the asset_id foreign key.
CREATE INDEX IF NOT EXISTS idx_graph_alerts_asset_created ON alerts (asset_id, created_at DESC) WHERE asset_id IS NOT NULL;

-- Admin-only pivot: SIEMBox sign-ins from an IP. (ip_address = $1 implies IS NOT NULL.)
CREATE INDEX IF NOT EXISTS idx_graph_audit_logs_ip_time ON audit_logs (ip_address, timestamp DESC) WHERE ip_address IS NOT NULL;
