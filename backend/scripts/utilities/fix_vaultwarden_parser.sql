-- Fix Script: Update Vaultwarden Parser with JavaScript-Compatible Regex
-- Date: 2025-12-08
-- Purpose: Fix existing vaultwarden-access parser with Python-style regex syntax
-- This script directly updates the database record created by migration 005

-- Update the vaultwarden-access parser with corrected JavaScript regex pattern
UPDATE parsers
SET
  pattern = '^\[(?<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\]\[(?<module>[^\]]+)\]\[(?<log_level>\w+)\]\s+(?<message>(?:(?!(?:\s+(?:for|from(?:\s+IP:)?|by)\s+|,\s+(?:Email|Device):)).)+?)(?:\s+for\s+(?<email>\S+))?(?:\s+by\s+(?<admin_email>\S+)\s+from\s+(?<admin_ip>[\d.]+)|(?:\s+from\s+(?:IP:\s+)?(?<client_ip>[\d.]+)(?:,\s+Email:\s+(?<email>\S+))?))(?:,\s+Device:\s+(?<device>[^,]+))?$',
  updated_at = NOW()
WHERE name = 'vaultwarden-access';

-- Verify the update was successful
SELECT
  id,
  name,
  enabled,
  priority,
  parser_type,
  substring(pattern, 1, 100) || '...' as pattern_preview,
  updated_at
FROM parsers
WHERE name = 'vaultwarden-access';

-- Check for any other parsers with Python-style regex syntax
SELECT
  id,
  name,
  parser_type,
  substring(pattern, 1, 100) || '...' as pattern_preview
FROM parsers
WHERE pattern LIKE '%(?P<%'
  AND parser_type IN ('regex', 'grok')
ORDER BY priority, name;
