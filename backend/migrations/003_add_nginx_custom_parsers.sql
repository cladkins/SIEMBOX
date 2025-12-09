-- Migration: Add Custom NGINX Parsers for Komodo System
-- Date: 2025-12-09
-- Purpose: Fix NGINX log parsing for custom log formats from komodo (192.168.1.194)
--
-- Background:
-- The system receives syslog messages in RFC 3164 format. After syslog parsing,
-- only the message portion (after the TAG) is stored in raw_logs.raw_message.
-- These parsers are designed to match the EXTRACTED message content, not the full
-- syslog message with headers.
--
-- Example Flow:
--   Received: <134>Dec 09 20:36:20 komodo NGINX: [09/Dec/2025:20:35:53 +0000] - 200 200 - GET
--   Extracted: [09/Dec/2025:20:35:53 +0000] - 200 200 - GET
--   Parser matches: ^^\[(?<timestamp>[^\]]+)\]...
--
-- Related Commit: 0f58032 - "fix(syslog): store extracted message instead of full syslog message"

-- ============================================================================
-- CUSTOM NGINX PARSERS FOR KOMODO SYSTEM
-- ============================================================================

-- Parser 1: NGINX Komodo - Timestamp-First Access Logs
-- Priority: 45 (higher than standard nginx parsers)
-- Matches logs that start with [timestamp] instead of client IP
-- This handles the custom NGINX log_format used on komodo
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, enabled)
VALUES (
    'nginx-komodo-timestamp-first',
    'Parses custom NGINX access logs from komodo that start with timestamp',
    'regex',
    45,
    '^\[(?<timestamp>[^\]]+)\]\s+(?:-\s+)?(?<status_code1>\d{3})?\s*(?<status_code2>\d{3})?\s*-?\s*(?<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)?\s*(?<protocol>https?|wss?)?\s*(?<request_uri>\S+)?',
    '{"timestamp": "timestamp", "status_code": "status_code1", "upstream_status": "status_code2", "method": "method", "protocol": "protocol", "request_uri": "request_uri", "service": "nginx-komodo"}',
    true
)
ON CONFLICT (name) DO NOTHING;

-- Parser 2: NGINX Komodo - Error Logs
-- Priority: 44 (higher than standard nginx error parser)
-- Matches NGINX error log format: 2025/12/08 19:37:36 [error] 1484#1484: *17597
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, enabled)
VALUES (
    'nginx-komodo-error',
    'Parses NGINX error logs from komodo system',
    'regex',
    44,
    '^(?<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?<log_level>\w+)\]\s+(?<pid>\d+)#(?<worker_id>\d+):\s+\*(?<connection_id>\d+)\s*(?<message>.*)?',
    '{"timestamp": "timestamp", "log_level": "log_level", "pid": "pid", "worker_id": "worker_id", "connection_id": "connection_id", "message": "error_message", "service": "nginx-komodo"}',
    true
)
ON CONFLICT (name) DO NOTHING;

-- Parser 3: NGINX Komodo - IP-Only Minimal Format
-- Priority: 43 (higher than standard parsers)
-- Matches truncated logs that only have IP address: 68.218.17.107 -
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, enabled)
VALUES (
    'nginx-komodo-ip-only',
    'Parses minimal NGINX access logs from komodo with only IP address',
    'regex',
    43,
    '^(?<client_ip>[\d.]+)\s+-\s*(?<message>.*)?',
    '{"client_ip": "client_ip", "message": "message", "service": "nginx-komodo"}',
    true
)
ON CONFLICT (name) DO NOTHING;

-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================

-- After applying this migration, verify the parsers were created:
-- SELECT name, priority, enabled FROM parsers WHERE name LIKE 'nginx-komodo%' ORDER BY priority DESC;

-- Test parsing against sample logs from komodo (192.168.1.194):
-- SELECT
--   id,
--   LEFT(raw_message, 80) as message_preview,
--   parser_id,
--   parsed_data
-- FROM raw_logs
-- WHERE source_ip = '192.168.1.194'
-- ORDER BY created_at DESC
-- LIMIT 10;

-- Check parser match statistics:
-- SELECT
--   p.name,
--   COUNT(*) as match_count
-- FROM parsed_logs pl
-- JOIN parsers p ON pl.parser_id = p.id
-- WHERE p.name LIKE 'nginx-komodo%'
-- GROUP BY p.name
-- ORDER BY match_count DESC;
