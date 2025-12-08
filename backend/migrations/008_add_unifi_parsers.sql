-- Migration: Add UniFi Firewall and IDS/IPS Parsers
-- Date: 2025-12-08
-- Purpose: Add missing Ubiquiti UniFi parsers that were documented but never migrated
-- Note: UniFi detection rules already exist in migration 002

-- Check if parsers already exist and delete if present (for re-runs)
DELETE FROM parsers WHERE name IN ('unifi-firewall', 'unifi-idsips');

-- Parser: UniFi Firewall
INSERT INTO parsers (
  name,
  description,
  enabled,
  priority,
  parser_type,
  pattern,
  field_mappings,
  test_samples,
  created_at,
  updated_at
)
VALUES (
  'unifi-firewall',
  'Parses Ubiquiti UniFi (UCG-Max) firewall rule logs for network security monitoring',
  true,
  50,
  'regex',
  '\[(?<rule_name>[^\]]+)\].*?DESCR="(?<rule_description>[^"]+)".*?IN=(?<in_interface>\S+).*?OUT=(?<out_interface>\S*).*?SRC=(?<source_ip>[\d\.]+).*?DST=(?<dest_ip>[\d\.]+).*?PROTO=(?<protocol>\w+)',
  '{
    "rule_name": "rule_name",
    "rule_description": "rule_description",
    "in_interface": "in_interface",
    "out_interface": "out_interface",
    "source_ip": "source_ip",
    "client_ip": "source_ip",
    "dest_ip": "dest_ip",
    "destination_ip": "dest_ip",
    "protocol": "protocol",
    "service": "unifi-firewall"
  }',
  '[
    {
      "raw_message": "<13>Nov 29 19:44:35 UCG-Max [LAN_LOCAL-RET-2147483647] DESCR=\"no rule description\" IN=br0 OUT= MAC=01:00:5e:00:00:fb:5e:07:7d:96:02:d7:08:00 SRC=192.168.1.158 DST=224.0.0.251 LEN=473 TOS=00 PREC=0x00 TTL=255 ID=62191 PROTO=UDP SPT=5353 DPT=5353 LEN=453 MARK=1a0000",
      "expected_fields": {
        "rule_name": "LAN_LOCAL-RET-2147483647",
        "rule_description": "no rule description",
        "in_interface": "br0",
        "out_interface": "",
        "source_ip": "192.168.1.158",
        "client_ip": "192.168.1.158",
        "dest_ip": "224.0.0.251",
        "destination_ip": "224.0.0.251",
        "protocol": "UDP",
        "service": "unifi-firewall"
      }
    },
    {
      "raw_message": "<12>Nov 29 20:15:42 UCG-Max [WAN_IN-DROP-4000] DESCR=\"Block external traffic\" IN=eth4 OUT=br0 SRC=203.0.113.50 DST=192.168.1.100 PROTO=TCP SPT=443 DPT=80",
      "expected_fields": {
        "rule_name": "WAN_IN-DROP-4000",
        "rule_description": "Block external traffic",
        "in_interface": "eth4",
        "out_interface": "br0",
        "source_ip": "203.0.113.50",
        "client_ip": "203.0.113.50",
        "dest_ip": "192.168.1.100",
        "destination_ip": "192.168.1.100",
        "protocol": "TCP",
        "service": "unifi-firewall"
      }
    }
  ]',
  NOW(),
  NOW()
);

-- Parser: UniFi IDS/IPS
INSERT INTO parsers (
  name,
  description,
  enabled,
  priority,
  parser_type,
  pattern,
  field_mappings,
  test_samples,
  created_at,
  updated_at
)
VALUES (
  'unifi-idsips',
  'Parses Ubiquiti UniFi IDS/IPS daemon event logs for intrusion detection and prevention',
  true,
  50,
  'regex',
  'ubnt-idsips-daemon\[\d+\]:\s+[\d-]+T[\d:.-]+\s+(?<severity>\w+):\s+(?<event_type>.+?):\s+ipset\[(?<action_type>\w+)\]\s+(?<action>\w+)\s+failed\s+ip1:(?<external_ip>[\d.]+),\s+port1:(?<external_port>\d+),\s+ip2:(?<internal_ip>[\d.]+),\s+port2:(?<internal_port>\d+),\s+proto:(?<protocol>\w+)',
  '{
    "severity": "severity",
    "log_level": "severity",
    "event_type": "event_type",
    "action_type": "action_type",
    "action": "action",
    "external_ip": "external_ip",
    "source_ip": "external_ip",
    "client_ip": "external_ip",
    "external_port": "external_port",
    "source_port": "external_port",
    "internal_ip": "internal_ip",
    "dest_ip": "internal_ip",
    "destination_ip": "internal_ip",
    "internal_port": "internal_port",
    "dest_port": "internal_port",
    "protocol": "protocol",
    "service": "unifi-idsips"
  }',
  '[
    {
      "raw_message": "<28>Nov 29 15:51:19 UCG-Max UCG-Max ubnt-idsips-daemon[2402]: 2025-11-29T15:51:19.543-0600 Warn: error handling event: ipset[ips] add failed ip1:156.218.17.179, port1:52686, ip2:192.168.1.194, port2:80, proto:tcp, err1:ipset v7.10: Element cannot be added to the set: it''s already added",
      "expected_fields": {
        "severity": "Warn",
        "log_level": "Warn",
        "event_type": "error handling event",
        "action_type": "ips",
        "action": "add",
        "external_ip": "156.218.17.179",
        "source_ip": "156.218.17.179",
        "client_ip": "156.218.17.179",
        "external_port": "52686",
        "source_port": "52686",
        "internal_ip": "192.168.1.194",
        "dest_ip": "192.168.1.194",
        "destination_ip": "192.168.1.194",
        "internal_port": "80",
        "dest_port": "80",
        "protocol": "tcp",
        "service": "unifi-idsips"
      }
    },
    {
      "raw_message": "<28>Nov 30 08:22:15 UCG-Max UCG-Max ubnt-idsips-daemon[2402]: 2025-11-30T08:22:15.123-0600 Error: attack detected: ipset[ids] add failed ip1:198.51.100.42, port1:443, ip2:192.168.1.50, port2:8080, proto:tcp",
      "expected_fields": {
        "severity": "Error",
        "log_level": "Error",
        "event_type": "attack detected",
        "action_type": "ids",
        "action": "add",
        "external_ip": "198.51.100.42",
        "source_ip": "198.51.100.42",
        "client_ip": "198.51.100.42",
        "external_port": "443",
        "source_port": "443",
        "internal_ip": "192.168.1.50",
        "dest_ip": "192.168.1.50",
        "destination_ip": "192.168.1.50",
        "internal_port": "8080",
        "dest_port": "8080",
        "protocol": "tcp",
        "service": "unifi-idsips"
      }
    }
  ]',
  NOW(),
  NOW()
);

-- Verify parsers were created
SELECT
  id,
  name,
  priority,
  enabled,
  parser_type,
  CASE
    WHEN jsonb_array_length(test_samples::jsonb) > 0
    THEN jsonb_array_length(test_samples::jsonb) || ' test samples'
    ELSE 'No test samples'
  END as test_samples_count
FROM parsers
WHERE name IN ('unifi-firewall', 'unifi-idsips')
ORDER BY name;

COMMENT ON COLUMN parsers.priority IS 'Parser priority (lower number = higher priority). UniFi parsers=50 (standard priority)';

-- Note: UniFi detection rules already exist in migration 002:
-- - UniFi IPS Repeated Attack Attempts (high severity)
-- - UniFi IPS Internal System Under Attack (critical severity)
-- - UniFi IDS/IPS Error Events (medium severity)
-- - UniFi IPS Port Scan Detection (high severity)
