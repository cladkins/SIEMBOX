-- System Settings Table
CREATE TABLE IF NOT EXISTS system_settings (
    key VARCHAR(255) PRIMARY KEY,
    value TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

COMMENT ON TABLE system_settings IS 'System-wide configuration settings';
COMMENT ON COLUMN system_settings.key IS 'Setting key identifier';
COMMENT ON COLUMN system_settings.value IS 'Setting value (stored as text, parse as needed)';

-- Insert default retention settings
INSERT INTO system_settings (key, value) VALUES
    ('retention_raw_logs_days', '30'),
    ('retention_parsed_logs_days', '90'),
    ('retention_alerts_days', '365'),
    ('retention_auto_cleanup_enabled', 'true')
ON CONFLICT (key) DO NOTHING;
