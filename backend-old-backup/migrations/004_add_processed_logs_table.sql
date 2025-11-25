-- Migration: Add processed_logs table for Pattern B architecture
-- This table stores processed logs received from Cribl Stream

-- Create processed_logs table
CREATE TABLE IF NOT EXISTS processed_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cribl_log_id VARCHAR(255),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    received_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    hostname VARCHAR(255),
    source_ip INET,
    app_name VARCHAR(100),
    raw_message TEXT,
    processed_fields JSONB,
    log_type VARCHAR(50),
    severity VARCHAR(20),
    category VARCHAR(50),
    source VARCHAR(100),
    cribl_pipeline VARCHAR(100)
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_processed_logs_timestamp ON processed_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_processed_logs_received_at ON processed_logs(received_at);
CREATE INDEX IF NOT EXISTS idx_processed_logs_hostname ON processed_logs(hostname);
CREATE INDEX IF NOT EXISTS idx_processed_logs_source_ip ON processed_logs(source_ip);
CREATE INDEX IF NOT EXISTS idx_processed_logs_app_name ON processed_logs(app_name);
CREATE INDEX IF NOT EXISTS idx_processed_logs_log_type ON processed_logs(log_type);
CREATE INDEX IF NOT EXISTS idx_processed_logs_severity ON processed_logs(severity);
CREATE INDEX IF NOT EXISTS idx_processed_logs_category ON processed_logs(category);
CREATE INDEX IF NOT EXISTS idx_processed_logs_source ON processed_logs(source);
CREATE INDEX IF NOT EXISTS idx_processed_logs_cribl_log_id ON processed_logs(cribl_log_id);

-- Create GIN index for JSONB field
CREATE INDEX IF NOT EXISTS idx_processed_logs_processed_fields ON processed_logs USING GIN(processed_fields);

-- Add new column to alerts table for processed log reference
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS processed_log_id UUID REFERENCES processed_logs(id);
CREATE INDEX IF NOT EXISTS idx_alerts_processed_log_id ON alerts(processed_log_id);

-- Make parsed_log_id nullable for backward compatibility
ALTER TABLE alerts ALTER COLUMN parsed_log_id DROP NOT NULL;

-- Update comments
COMMENT ON TABLE processed_logs IS 'Processed log entries received from Cribl Stream HTTP destination';
COMMENT ON COLUMN processed_logs.cribl_log_id IS 'Original log ID from Cribl';
COMMENT ON COLUMN processed_logs.timestamp IS 'Original log timestamp';
COMMENT ON COLUMN processed_logs.received_at IS 'When the log was received from Cribl';
COMMENT ON COLUMN processed_logs.processed_fields IS 'Processed fields from Cribl Stream';
COMMENT ON COLUMN alerts.processed_log_id IS 'Reference to processed log entry';