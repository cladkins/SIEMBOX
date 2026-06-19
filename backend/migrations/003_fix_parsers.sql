-- Migration 003: correct seeded parser patterns that never matched real logs.
--
-- Like the other migrations this file has no version table and re-runs on every
-- startup, so it is written to be idempotent: it UPDATEs by parser name, which
-- also brings EXISTING installs in line with the corrected definitions in
-- 002_seed_data.sql (002 only inserts, with ON CONFLICT DO NOTHING).
-- Note: because it re-applies on every boot, a manual UI edit to one of these
-- parsers would be reverted on restart.

-- Pi-hole / dnsmasq query logs look like "query[A] example.com from 1.2.3.4",
-- but the original pattern expected a space-separated "query_type domain" and so
-- never matched any query line -> query_type/domain/client_ip were always empty
-- and APP-003 (DNS anomaly) / EXFIL-003 (DNS tunneling) could not fire.
UPDATE parsers
SET pattern = 'dnsmasq\[\d+\]:\s+query\[(?<query_type>[^\]]+)\]\s+(?<domain>\S+)\s+from\s+(?<client_ip>[\d.]+)',
    field_mappings = '{"query_type": "query_type", "domain": "domain", "client_ip": "client_ip", "service": "pihole"}'
WHERE name = 'pihole-query';
