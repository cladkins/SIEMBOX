-- SIEM BOX - Database Initialization Script
-- This script sets up the initial database structure and configurations

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- Create indexes for better performance
-- Note: The tables will be created by SQLAlchemy, but we can add additional indexes here

-- Function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Grant necessary permissions
-- GRANT ALL PRIVILEGES ON DATABASE siembox TO siembox; -- This is handled by the Docker entrypoint
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO siembox;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO siembox;

-- Set default privileges for future tables
-- ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO siembox;
-- ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO siembox;

-- Additional indexes for Phase 2 tables (will be created after SQLAlchemy creates the tables)
-- These will be added via triggers after table creation

-- Create a function to add indexes after table creation
CREATE OR REPLACE FUNCTION create_phase2_indexes()
RETURNS void AS $$
BEGIN
    -- Indexes for parsed_logs table
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'parsed_logs') THEN
        CREATE INDEX IF NOT EXISTS idx_parsed_logs_log_type ON parsed_logs(log_type);
        CREATE INDEX IF NOT EXISTS idx_parsed_logs_severity ON parsed_logs(severity);
        CREATE INDEX IF NOT EXISTS idx_parsed_logs_category ON parsed_logs(category);
        CREATE INDEX IF NOT EXISTS idx_parsed_logs_parsed_at ON parsed_logs(parsed_at);
        CREATE INDEX IF NOT EXISTS idx_parsed_logs_parsed_fields_gin ON parsed_logs USING gin(parsed_fields);
    END IF;

    -- Indexes for detection_rules table
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'detection_rules') THEN
        CREATE INDEX IF NOT EXISTS idx_detection_rules_enabled ON detection_rules(is_enabled);
        CREATE INDEX IF NOT EXISTS idx_detection_rules_category ON detection_rules(category);
        CREATE INDEX IF NOT EXISTS idx_detection_rules_severity ON detection_rules(severity);
        CREATE INDEX IF NOT EXISTS idx_detection_rules_type ON detection_rules(rule_type);
    END IF;

    -- Indexes for alerts table
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'alerts') THEN
        CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
        CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
        CREATE INDEX IF NOT EXISTS idx_alerts_category ON alerts(category);
        CREATE INDEX IF NOT EXISTS idx_alerts_triggered_at ON alerts(triggered_at);
        CREATE INDEX IF NOT EXISTS idx_alerts_resolved_at ON alerts(resolved_at);
        CREATE INDEX IF NOT EXISTS idx_alerts_data_gin ON alerts USING gin(alert_data);
        CREATE INDEX IF NOT EXISTS idx_alerts_notifications_gin ON alerts USING gin(notifications_sent);
    END IF;

    -- Composite indexes for common queries
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'alerts') THEN
        CREATE INDEX IF NOT EXISTS idx_alerts_status_severity ON alerts(status, severity);
        CREATE INDEX IF NOT EXISTS idx_alerts_triggered_status ON alerts(triggered_at, status);
    END IF;

    -- Add triggers for updated_at columns
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'detection_rules') THEN
        DROP TRIGGER IF EXISTS update_detection_rules_updated_at ON detection_rules;
        CREATE TRIGGER update_detection_rules_updated_at
            BEFORE UPDATE ON detection_rules
            FOR EACH ROW
            EXECUTE FUNCTION update_updated_at_column();
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'alerts') THEN
        DROP TRIGGER IF EXISTS update_alerts_updated_at ON alerts;
        CREATE TRIGGER update_alerts_updated_at
            BEFORE UPDATE ON alerts
            FOR EACH ROW
            EXECUTE FUNCTION update_updated_at_column();
    END IF;
END;
$$ language 'plpgsql';

-- Log the initialization
SELECT pg_stat_statements_reset();

-- Note: Migration files will be executed by the backend application
-- after the base tables are created by SQLAlchemy