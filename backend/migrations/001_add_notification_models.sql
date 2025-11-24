-- Migration: Add notification models
-- Created: 2025-01-07
-- Description: Add notification channels, history, and templates tables

-- Create notification_channels table
CREATE TABLE IF NOT EXISTS notification_channels (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    type VARCHAR(50) NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    config JSONB NOT NULL DEFAULT '{}',
    min_severity VARCHAR(20) DEFAULT 'low',
    categories TEXT[] DEFAULT ARRAY[]::TEXT[],
    exclude_categories TEXT[] DEFAULT ARRAY[]::TEXT[],
    rate_limit_per_hour INTEGER DEFAULT 100,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create notification_history table
CREATE TABLE IF NOT EXISTS notification_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id UUID NOT NULL,
    channel_id UUID,
    channel_type VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    message TEXT,
    error_message TEXT,
    metadata JSONB DEFAULT '{}',
    sent_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE,
    FOREIGN KEY (channel_id) REFERENCES notification_channels(id) ON DELETE SET NULL
);

-- Create notification_templates table
CREATE TABLE IF NOT EXISTS notification_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    channel_type VARCHAR(50) NOT NULL,
    subject_template TEXT,
    body_template TEXT NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(name, channel_type)
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_notification_channels_type ON notification_channels(type);
CREATE INDEX IF NOT EXISTS idx_notification_channels_enabled ON notification_channels(enabled);
CREATE INDEX IF NOT EXISTS idx_notification_history_alert_id ON notification_history(alert_id);
CREATE INDEX IF NOT EXISTS idx_notification_history_channel_id ON notification_history(channel_id);
CREATE INDEX IF NOT EXISTS idx_notification_history_status ON notification_history(status);
CREATE INDEX IF NOT EXISTS idx_notification_history_created_at ON notification_history(created_at);
CREATE INDEX IF NOT EXISTS idx_notification_templates_channel_type ON notification_templates(channel_type);
CREATE INDEX IF NOT EXISTS idx_notification_templates_enabled ON notification_templates(enabled);

-- Add trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply triggers
CREATE TRIGGER update_notification_channels_updated_at 
    BEFORE UPDATE ON notification_channels 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_notification_templates_updated_at 
    BEFORE UPDATE ON notification_templates 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert default notification templates
INSERT INTO notification_templates (name, channel_type, subject_template, body_template) VALUES
('Default Email Alert', 'email', 
 'SIEM Alert: {{alert.severity}} - {{alert.rule_name}}',
 'Alert Details:\n\nSeverity: {{alert.severity}}\nRule: {{alert.rule_name}}\nDescription: {{alert.description}}\nTimestamp: {{alert.timestamp}}\nSource: {{alert.source_ip}}\nDestination: {{alert.destination_ip}}\n\nRaw Log:\n{{alert.raw_log}}'),

('Default Discord Alert', 'discord',
 NULL,
 '🚨 **SIEM Alert** 🚨\n**Severity:** {{alert.severity}}\n**Rule:** {{alert.rule_name}}\n**Description:** {{alert.description}}\n**Time:** {{alert.timestamp}}\n**Source:** {{alert.source_ip}}\n**Destination:** {{alert.destination_ip}}'),

('Default Slack Alert', 'slack',
 NULL,
 ':warning: *SIEM Alert*\n*Severity:* {{alert.severity}}\n*Rule:* {{alert.rule_name}}\n*Description:* {{alert.description}}\n*Time:* {{alert.timestamp}}\n*Source:* {{alert.source_ip}}\n*Destination:* {{alert.destination_ip}}'),

('Default SMS Alert', 'sms',
 NULL,
 'SIEM Alert: {{alert.severity}} - {{alert.rule_name}} at {{alert.timestamp}}. Source: {{alert.source_ip}}'),

('Default Webhook Alert', 'webhook',
 NULL,
 '{"alert_id": "{{alert.id}}", "severity": "{{alert.severity}}", "rule_name": "{{alert.rule_name}}", "description": "{{alert.description}}", "timestamp": "{{alert.timestamp}}", "source_ip": "{{alert.source_ip}}", "destination_ip": "{{alert.destination_ip}}"}')

ON CONFLICT (name, channel_type) DO NOTHING;