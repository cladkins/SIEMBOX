-- Migration: Remove raw_logs table for Pattern B architecture
-- Created: 2025-01-11
-- Description: Remove raw_logs table and related components as log data is now stored in Cribl

-- Drop foreign key constraints first
ALTER TABLE parsed_logs DROP CONSTRAINT IF EXISTS parsed_logs_raw_log_id_fkey;

-- Drop indexes related to raw_logs
DROP INDEX IF EXISTS idx_raw_logs_timestamp;
DROP INDEX IF EXISTS idx_raw_logs_received_at;
DROP INDEX IF EXISTS idx_raw_logs_source_ip;
DROP INDEX IF EXISTS idx_raw_logs_protocol;
DROP INDEX IF EXISTS idx_raw_logs_hostname;
DROP INDEX IF EXISTS idx_raw_logs_app_name;
DROP INDEX IF EXISTS idx_raw_logs_is_parsed;

-- Drop the raw_logs table
DROP TABLE IF EXISTS raw_logs;

-- Update parsed_logs table to remove raw_log_id dependency
-- Note: We're keeping parsed_logs for now as it may still be used by detection rules and alerts
-- The raw_log_id column will be made nullable and eventually deprecated
ALTER TABLE parsed_logs ALTER COLUMN raw_log_id DROP NOT NULL;

-- Add a comment to indicate the change
COMMENT ON COLUMN parsed_logs.raw_log_id IS 'DEPRECATED: Raw log ID reference, no longer used in Pattern B architecture';