-- Context Graph bench: seed parsed logs shaped like an internet-facing home lab
-- (SSH sign-in spraying, Pi-hole DNS queries, firewall drops), for timing the
-- log-relationship rollup and the graph's queries on a SCRATCH database.
--
--   psql -v n=1000000 -d siembox_bench -f backend/scripts/graph-bench.sql
--
-- Then start the backend against that database: the graph-log-edges job
-- (Admin -> Background Jobs) backfills the last 7 days at up to 20 s of
-- database time a minute; graph_log_edges_state.last_parsed_log_id shows its
-- progress. The EXPLAIN ANALYZE statements at the end time the neighbourhood
-- reads once it has caught up (re-run just that part with -v explain_only=1).
--
-- Never run this against a production database: it inserts n raw and parsed
-- logs (tagged app_name 'graph-bench') and a disabled parser named
-- 'graph-bench'. Clean up with:
--   DELETE FROM raw_logs WHERE app_name = 'graph-bench';   -- parsed rows cascade
--   DELETE FROM parsers WHERE name = 'graph-bench';
\set ON_ERROR_STOP on
\if :{?n}
\else
  \set n 200000
\endif
\if :{?explain_only}
\else
\timing on
INSERT INTO parsers (name, parser_type, pattern, field_mappings, priority, enabled)
VALUES ('graph-bench', 'regex', '^$', '{}', 999, false)
ON CONFLICT (name) DO NOTHING;

-- 60 % SSH (one of 5,000 scanner IPs trying one of 300 users; 1 in 50 succeeds),
-- 30 % DNS (200 LAN clients, 20,000 domains), 10 % firewall (to 1,000 hosts).
-- Spread evenly over the last 7 days up to 5 minutes ago, ids in created_at
-- order as ingestion writes them (the rollup's id cursor relies on it);
-- 6 devices, 3 shipper tags.
WITH g AS (
  SELECT i, i % 10 AS kind, NOW() - make_interval(secs => 300 + 7 * 86400.0 * (:n - i) / :n) AS at
    FROM generate_series(1, :n) i
), raw AS (
  INSERT INTO raw_logs (timestamp, raw_message, source_ip, hostname, app_name, shipper_id, created_at)
  SELECT at, 'bench ' || i, '10.0.0.' || (1 + i % 6), (ARRAY['nas', 'pihole', 'fw01', 'web01', 'web02', NULL])[1 + i % 6],
         'graph-bench', (ARRAY['0a1b2c3d', '4e5f6a7b', NULL])[1 + i % 3], at
    FROM g ORDER BY i
  RETURNING id, created_at, source_ip
)
INSERT INTO parsed_logs (raw_log_id, parser_id, parsed_data, timestamp, source_ip, event_type, created_at)
SELECT r.id, (SELECT id FROM parsers WHERE name = 'graph-bench'),
       CASE
         WHEN r.id % 10 < 6 THEN jsonb_build_object(
           'source_ip', '198.18.' || (r.id % 5000 / 250) || '.' || (r.id % 250),
           'user', (ARRAY['root', 'admin', 'pi', 'ubuntu'])[1 + r.id % 4] || CASE WHEN r.id % 7 = 0 THEN (r.id % 300)::text ELSE '' END,
           'auth_outcome', CASE WHEN r.id % 50 = 0 THEN 'success' ELSE 'failure' END,
           'observer_ip', r.source_ip, 'service', 'sshd')
         WHEN r.id % 10 < 9 THEN jsonb_build_object(
           'source_ip', '192.168.1.' || (r.id % 200), 'domain', 'd' || (r.id % 20000) || '.example.com',
           'observer_ip', r.source_ip, 'service', 'pihole')
         ELSE jsonb_build_object(
           'source_ip', '203.0.113.' || (r.id % 250), 'dest_ip', '192.168.2.' || (r.id % 1000 / 4),
           'observer_ip', r.source_ip, 'service', 'netfilter')
       END,
       r.created_at, r.source_ip,
       CASE WHEN r.id % 10 < 6 THEN 'ssh_auth' WHEN r.id % 10 < 9 THEN 'dns_query' ELSE 'firewall_drop' END,
       r.created_at
  FROM raw r;
ANALYZE raw_logs;
ANALYZE parsed_logs;
\timing off
\endif

-- The neighbourhood's reads, once the rollup has caught up.
EXPLAIN (ANALYZE, BUFFERS)
SELECT b_type, b_value, sum(events), sum(failures), sum(successes)
  FROM (SELECT b_type, b_value, events, failures, successes FROM graph_log_edges
         WHERE a_type = 'ip' AND a_value = '198.18.0.7' AND rel = 'signed_in_as'
           AND day BETWEEN CURRENT_DATE - 8 AND CURRENT_DATE + 1
         ORDER BY day DESC LIMIT 20000) e
 GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 5;
EXPLAIN (ANALYZE, BUFFERS)
SELECT a_type, a_value, sum(events)
  FROM (SELECT a_type, a_value, events FROM graph_log_edges
         WHERE b_type = 'user' AND b_value = 'root' AND rel = 'signed_in_as'
           AND day BETWEEN CURRENT_DATE - 8 AND CURRENT_DATE + 1
         ORDER BY day DESC LIMIT 20000) e
 GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 5;
SELECT count(*) AS edge_rows, pg_size_pretty(pg_total_relation_size('graph_log_edges')) AS size FROM graph_log_edges;
