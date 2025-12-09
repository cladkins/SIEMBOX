-- Diagnostic queries to identify why parsed logs aren't showing up for source IP 192.168.1.194

-- 1. Check raw logs from this IP
SELECT 'Raw Logs from 192.168.1.194:' as query_description;
SELECT id, timestamp, source_ip, LEFT(raw_message, 100) as message_preview, facility, severity
FROM raw_logs
WHERE source_ip = '192.168.1.194'
ORDER BY timestamp DESC
LIMIT 10;

-- 2. Check parsed logs from this IP
SELECT 'Parsed Logs from 192.168.1.194:' as query_description;
SELECT id, timestamp, source_ip, event_type, raw_log_id, parser_id
FROM parsed_logs
WHERE source_ip = '192.168.1.194'
ORDER BY timestamp DESC
LIMIT 10;

-- 3. Check if any raw logs from this IP have corresponding parsed logs
SELECT 'Raw logs WITHOUT parsed logs for 192.168.1.194:' as query_description;
SELECT r.id, r.timestamp, r.source_ip, LEFT(r.raw_message, 100) as message_preview
FROM raw_logs r
LEFT JOIN parsed_logs p ON r.id = p.raw_log_id
WHERE r.source_ip = '192.168.1.194'
  AND p.id IS NULL
ORDER BY r.timestamp DESC
LIMIT 10;

-- 4. Check for any whitespace or formatting issues in source_ip
SELECT 'Source IP variations (showing length and any whitespace):' as query_description;
SELECT DISTINCT
    source_ip,
    LENGTH(source_ip) as ip_length,
    source_ip = '192.168.1.194' as exact_match,
    source_ip LIKE '%192.168.1.194%' as contains_match
FROM raw_logs
WHERE source_ip LIKE '%192.168.1.194%'
LIMIT 5;

-- 5. Count statistics
SELECT 'Count statistics for 192.168.1.194:' as query_description;
SELECT
    (SELECT COUNT(*) FROM raw_logs WHERE source_ip = '192.168.1.194') as raw_logs_count,
    (SELECT COUNT(*) FROM parsed_logs WHERE source_ip = '192.168.1.194') as parsed_logs_count,
    (SELECT COUNT(*) FROM raw_logs r LEFT JOIN parsed_logs p ON r.id = p.raw_log_id
     WHERE r.source_ip = '192.168.1.194' AND p.id IS NULL) as unparsed_raw_logs_count;
