-- SQL queries to check log shipper configuration
-- Run these in PostgreSQL to see what's configured

-- Find your shipper
SELECT
    id,
    name,
    api_key,
    status,
    last_seen,
    hostname,
    ip_address
FROM log_shippers
WHERE api_key = 'f25d8cc2a7994ab3626e677169b5a53e9c478327373c09302c7aab8cbc5c9031';

-- Check all sources for this shipper (replace {shipper_id} with the id from above)
-- SELECT * FROM shipper_sources WHERE shipper_id = {your_id};

-- Show all sources with their types
SELECT
    ss.id,
    ls.name as shipper_name,
    ss.source_type,
    ss.enabled,
    ss.file_path,
    ss.container_name,
    ss.journal_unit,
    ss.tag,
    ss.facility
FROM shipper_sources ss
JOIN log_shippers ls ON ss.shipper_id = ls.id
WHERE ls.api_key = 'f25d8cc2a7994ab3626e677169b5a53e9c478327373c09302c7aab8cbc5c9031'
ORDER BY ss.id;

-- Count sources by type
SELECT
    ss.source_type,
    COUNT(*) as count,
    COUNT(CASE WHEN ss.enabled THEN 1 END) as enabled_count
FROM shipper_sources ss
JOIN log_shippers ls ON ss.shipper_id = ls.id
WHERE ls.api_key = 'f25d8cc2a7994ab3626e677169b5a53e9c478327373c09302c7aab8cbc5c9031'
GROUP BY ss.source_type;
