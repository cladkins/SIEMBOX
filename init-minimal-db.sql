-- SIEM BOX - Minimal Database Schema
-- Just logs. Nothing else.

-- Drop existing tables if doing a fresh rebuild
DROP TABLE IF EXISTS logs CASCADE;

-- Logs table - the only table we need
CREATE TABLE logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    hostname VARCHAR(255),
    source_ip VARCHAR(45) NOT NULL,
    message TEXT,
    raw_syslog TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_logs_timestamp ON logs(timestamp DESC);
CREATE INDEX idx_logs_source_ip ON logs(source_ip);
CREATE INDEX idx_logs_hostname ON logs(hostname);

-- Test insert to verify table works
INSERT INTO logs (timestamp, hostname, source_ip, message, raw_syslog)
VALUES (NOW(), 'test-host', '127.0.0.1', 'Database initialized', '<134>Test log');

-- Verify
SELECT COUNT(*) as total_logs FROM logs;
SELECT * FROM logs ORDER BY id DESC LIMIT 1;
