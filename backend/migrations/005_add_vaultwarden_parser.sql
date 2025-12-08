-- Migration: Add Vaultwarden Parser for Critical Password Manager Security
-- Date: 2025-12-03
-- Purpose: Implement CRITICAL priority parser for Vaultwarden password manager logs
-- Unblocks: AUTH-005, PWDMGR-001, PWDMGR-002, PWDMGR-003, PWDMGR-004 (5 rules)

-- Check if parser already exists and delete if present (for re-runs)
DELETE FROM parsers WHERE name = 'vaultwarden-access';

-- Insert Vaultwarden Parser
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
  'vaultwarden-access',
  'Parses Vaultwarden authentication and vault access logs for critical security monitoring',
  true,
  55, -- HIGHEST PRIORITY - Password manager is most critical system
  'regex',
  '^\[(?<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\]\[(?<module>[^\]]+)\]\[(?<log_level>\w+)\]\s+(?<message>(?:(?!(?:\s+(?:for|from(?:\s+IP:)?|by)\s+|,\s+(?:Email|Device):)).)+?)(?:\s+for\s+(?<email>\S+))?(?:\s+by\s+(?<admin_email>\S+)\s+from\s+(?<admin_ip>[\d.]+)|(?:\s+from\s+(?:IP:\s+)?(?<client_ip>[\d.]+)(?:,\s+Email:\s+(?<email>\S+))?))(?:,\s+Device:\s+(?<device>[^,]+))?$',
  '{
    "timestamp": "timestamp",
    "module": "module",
    "log_level": "log_level",
    "message": "message",
    "client_ip": "client_ip",
    "source_ip": "client_ip",
    "email": "email",
    "user": "email",
    "admin_email": "admin_email",
    "admin_ip": "admin_ip",
    "device": "device",
    "service": "vaultwarden",
    "action": "message",
    "event": "message"
  }',
  '[
    {
      "raw_message": "[2025-12-03 12:34:56.789][vaultwarden::api::identity][WARN] Failed login attempt from IP: 192.168.1.100, Email: admin@example.com",
      "expected_fields": {
        "timestamp": "2025-12-03 12:34:56.789",
        "module": "vaultwarden::api::identity",
        "log_level": "WARN",
        "message": "Failed login attempt",
        "client_ip": "192.168.1.100",
        "source_ip": "192.168.1.100",
        "email": "admin@example.com",
        "user": "admin@example.com",
        "service": "vaultwarden"
      }
    },
    {
      "raw_message": "[2025-12-03 12:35:10.123][vaultwarden::api::identity][INFO] Successful login from IP: 192.168.1.100, Email: admin@example.com",
      "expected_fields": {
        "timestamp": "2025-12-03 12:35:10.123",
        "module": "vaultwarden::api::identity",
        "log_level": "INFO",
        "message": "Successful login",
        "client_ip": "192.168.1.100",
        "source_ip": "192.168.1.100",
        "email": "admin@example.com",
        "user": "admin@example.com",
        "service": "vaultwarden"
      }
    },
    {
      "raw_message": "[2025-12-03 12:36:22.456][vaultwarden::api::core][INFO] Vault accessed by admin@example.com from 192.168.1.100",
      "expected_fields": {
        "timestamp": "2025-12-03 12:36:22.456",
        "module": "vaultwarden::api::core",
        "log_level": "INFO",
        "message": "Vault accessed",
        "admin_email": "admin@example.com",
        "admin_ip": "192.168.1.100",
        "service": "vaultwarden"
      }
    },
    {
      "raw_message": "[2025-12-03 12:37:45.789][vaultwarden::api::core][WARN] Vault export initiated by admin@example.com from 192.168.1.100",
      "expected_fields": {
        "timestamp": "2025-12-03 12:37:45.789",
        "module": "vaultwarden::api::core",
        "log_level": "WARN",
        "message": "Vault export initiated",
        "admin_email": "admin@example.com",
        "admin_ip": "192.168.1.100",
        "service": "vaultwarden",
        "action": "vault_export"
      }
    },
    {
      "raw_message": "[2025-12-03 12:38:30.012][vaultwarden::api::admin][INFO] Admin action: \"User deleted\" by admin@example.com from 192.168.1.10",
      "expected_fields": {
        "timestamp": "2025-12-03 12:38:30.012",
        "module": "vaultwarden::api::admin",
        "log_level": "INFO",
        "message": "Admin action: \"User deleted\"",
        "admin_email": "admin@example.com",
        "admin_ip": "192.168.1.10",
        "service": "vaultwarden"
      }
    },
    {
      "raw_message": "[2025-12-03 12:39:15.345][vaultwarden::api::core][WARN] API authentication failed from IP: 203.0.113.50",
      "expected_fields": {
        "timestamp": "2025-12-03 12:39:15.345",
        "module": "vaultwarden::api::core",
        "log_level": "WARN",
        "message": "API authentication failed",
        "client_ip": "203.0.113.50",
        "source_ip": "203.0.113.50",
        "service": "vaultwarden"
      }
    },
    {
      "raw_message": "[2025-12-03 12:40:00.678][vaultwarden::api::identity][INFO] New device registered for admin@example.com from 192.168.1.100, Device: Chrome/Desktop",
      "expected_fields": {
        "timestamp": "2025-12-03 12:40:00.678",
        "module": "vaultwarden::api::identity",
        "log_level": "INFO",
        "message": "New device registered",
        "client_ip": "192.168.1.100",
        "source_ip": "192.168.1.100",
        "email": "admin@example.com",
        "user": "admin@example.com",
        "device": "Chrome/Desktop",
        "service": "vaultwarden",
        "event": "device_registered"
      }
    }
  ]',
  NOW(),
  NOW()
);

-- Verify parser was created
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
WHERE name = 'vaultwarden-access';

COMMENT ON COLUMN parsers.priority IS 'Parser priority (lower number = higher priority). Vaultwarden=55 (HIGHEST PRIORITY)';
