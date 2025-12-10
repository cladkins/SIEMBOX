-- Add app_name column to raw_logs table for source identification
-- This migration adds the syslog TAG field to enable distinguishing logs from different sources

-- Add app_name column if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'raw_logs' AND column_name = 'app_name'
    ) THEN
        ALTER TABLE raw_logs ADD COLUMN app_name VARCHAR(255);
        COMMENT ON COLUMN raw_logs.app_name IS 'Syslog TAG field (e.g., NGINX, docker-backend) - identifies log source';
    END IF;
END $$;

-- Create index for filtering by app_name
CREATE INDEX IF NOT EXISTS idx_raw_logs_app_name ON raw_logs(app_name);
