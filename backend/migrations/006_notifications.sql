-- Migration: Notifications
-- Notification channels (Slack / Email / NTFY) and per-event preferences.
-- Re-run on every boot, so everything here is idempotent.

CREATE TABLE IF NOT EXISTS notification_channels (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    channel_type VARCHAR(20) NOT NULL,          -- 'slack' | 'email' | 'ntfy'
    enabled BOOLEAN DEFAULT true,
    config JSONB NOT NULL DEFAULT '{}',         -- type-specific: webhook_url / smtp settings / topic
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    CONSTRAINT notification_channels_type_chk CHECK (channel_type IN ('slack', 'email', 'ntfy'))
);

-- Per-event notification preferences live in system_settings (opt-in / disabled by default).
INSERT INTO system_settings (key, value) VALUES
    ('notify_alerts_enabled', 'false'),
    ('notify_alerts_min_severity', 'high'),
    ('notify_vuln_enabled', 'false'),
    ('notify_vuln_min_severity', 'high'),
    ('notify_ingestion_enabled', 'false'),
    ('notify_ingestion_stall_minutes', '15')
ON CONFLICT (key) DO NOTHING;

COMMENT ON TABLE notification_channels IS 'Configured notification destinations (Slack, Email, NTFY)';
