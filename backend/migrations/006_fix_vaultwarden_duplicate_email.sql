-- Migration: Fix Vaultwarden Parser Duplicate Email Capture Group
-- Date: 2025-12-08
-- Purpose: Remove duplicate 'email' capture group that causes regex error
-- Issue: JavaScript regex doesn't allow duplicate capture group names

-- Update the vaultwarden-access parser with fixed pattern
UPDATE parsers
SET
  pattern = '^\[(?<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\]\[(?<module>[^\]]+)\]\[(?<log_level>\w+)\]\s+(?<message>(?:(?!(?:\s+(?:for|from(?:\s+IP:)?|by)\s+|,\s+(?:Email|Device):)).)+?)(?:\s+for\s+(?<user_email>\S+))?(?:\s+by\s+(?<admin_email>\S+)\s+from\s+(?<admin_ip>[\d.]+)|(?:\s+from\s+(?:IP:\s+)?(?<client_ip>[\d.]+)(?:,\s+Email:\s+(?<login_email>\S+))?))(?:,\s+Device:\s+(?<device>[^,]+))?$',
  field_mappings = '{
    "timestamp": "timestamp",
    "module": "module",
    "log_level": "log_level",
    "message": "message",
    "client_ip": "client_ip",
    "source_ip": "client_ip",
    "user_email": "email",
    "login_email": "email",
    "email": "email",
    "user": "email",
    "admin_email": "admin_email",
    "admin_ip": "admin_ip",
    "device": "device",
    "service": "vaultwarden",
    "action": "message",
    "event": "message"
  }',
  updated_at = NOW()
WHERE name = 'vaultwarden-access';

-- Verify the update
SELECT
  id,
  name,
  enabled,
  CASE
    WHEN pattern LIKE '%(?<email>%' AND pattern LIKE '%(?<email>%(?<email>%'
    THEN 'STILL HAS DUPLICATE EMAIL'
    ELSE 'FIXED - No duplicate email groups'
  END as status,
  LEFT(pattern, 100) as pattern_preview
FROM parsers
WHERE name = 'vaultwarden-access';

COMMENT ON COLUMN parsers.pattern IS 'Changed duplicate (?<email>) groups to (?<user_email>) and (?<login_email>) to fix JavaScript regex error';
