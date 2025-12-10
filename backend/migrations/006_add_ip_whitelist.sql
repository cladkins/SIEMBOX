-- Migration: Add IP Whitelist Management System
-- Date: 2025-12-03
-- Purpose: Implement IP whitelist for admin interface access control
-- Unblocks: AUTH-011, ACCESS-002 (2 rules)

-- Create IP whitelist table with CIDR support
CREATE TABLE IF NOT EXISTS ip_whitelist (
  id SERIAL PRIMARY KEY,
  ip_address CIDR NOT NULL,
  description TEXT,
  rule_id VARCHAR(50),
  created_by INTEGER REFERENCES users(id),
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Create GiST index for efficient CIDR lookups
CREATE INDEX IF NOT EXISTS idx_ip_whitelist_cidr ON ip_whitelist USING GIST (ip_address inet_ops);

-- Add unique constraint to prevent duplicate IP entries
CREATE UNIQUE INDEX IF NOT EXISTS idx_ip_whitelist_unique ON ip_whitelist (ip_address);

-- Add comment to table
COMMENT ON TABLE ip_whitelist IS 'IP addresses whitelisted for admin interface access and rule exceptions';
COMMENT ON COLUMN ip_whitelist.ip_address IS 'IP address or CIDR block (e.g., 192.0.2.100 or 192.0.2.0/24)';
COMMENT ON COLUMN ip_whitelist.description IS 'Human-readable description of why this IP is whitelisted';
COMMENT ON COLUMN ip_whitelist.rule_id IS 'Optional: Associate whitelist entry with specific rule (e.g., AUTH-011)';
COMMENT ON COLUMN ip_whitelist.created_by IS 'User who added this whitelist entry';

-- Insert example entries (commented out - uncomment if needed)
-- INSERT INTO ip_whitelist (ip_address, description, rule_id) VALUES
--   ('192.168.1.0/24', 'Home network', NULL),
--   ('10.0.0.0/8', 'Internal network', NULL);

-- Verify table creation
SELECT
  tablename,
  schemaname
FROM pg_tables
WHERE tablename = 'ip_whitelist';

-- Show indexes
SELECT
  indexname,
  indexdef
FROM pg_indexes
WHERE tablename = 'ip_whitelist';
