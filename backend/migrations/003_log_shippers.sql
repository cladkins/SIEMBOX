-- Migration: Log Shippers Management
-- Adds support for centralized log shipper management

-- Log shippers table - tracks all deployed shippers
CREATE TABLE IF NOT EXISTS log_shippers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    api_key VARCHAR(255) UNIQUE NOT NULL,
    status VARCHAR(20) DEFAULT 'pending', -- 'pending', 'online', 'offline', 'error'
    version VARCHAR(50),
    last_seen TIMESTAMP,
    ip_address VARCHAR(45), -- IPv4 or IPv6
    hostname VARCHAR(255),
    config JSONB DEFAULT '{}', -- Overall shipper configuration
    metadata JSONB DEFAULT '{}', -- Additional metadata (OS, etc.)
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Shipper log sources - individual log sources per shipper
CREATE TABLE IF NOT EXISTS shipper_sources (
    id SERIAL PRIMARY KEY,
    shipper_id INTEGER REFERENCES log_shippers(id) ON DELETE CASCADE,
    source_type VARCHAR(20) NOT NULL, -- 'file', 'docker', 'journal'
    enabled BOOLEAN DEFAULT true,

    -- File source config
    file_path TEXT,

    -- Docker source config
    container_name VARCHAR(255),

    -- Journal source config
    journal_unit VARCHAR(255),

    -- Common config
    tag VARCHAR(100) NOT NULL,
    facility VARCHAR(20) DEFAULT 'local0',

    -- Metadata
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Shipper volume mounts
CREATE TABLE IF NOT EXISTS shipper_volumes (
    id SERIAL PRIMARY KEY,
    shipper_id INTEGER REFERENCES log_shippers(id) ON DELETE CASCADE,
    host_path TEXT NOT NULL,
    container_path TEXT NOT NULL,
    mode VARCHAR(10) DEFAULT 'ro', -- 'ro' or 'rw'
    created_at TIMESTAMP DEFAULT NOW()
);

-- Shipper activity log
CREATE TABLE IF NOT EXISTS shipper_activity (
    id SERIAL PRIMARY KEY,
    shipper_id INTEGER REFERENCES log_shippers(id) ON DELETE CASCADE,
    activity_type VARCHAR(50) NOT NULL, -- 'registered', 'config_updated', 'status_changed', 'error'
    message TEXT,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_shippers_status ON log_shippers(status);
CREATE INDEX IF NOT EXISTS idx_shippers_api_key ON log_shippers(api_key);
CREATE INDEX IF NOT EXISTS idx_shippers_last_seen ON log_shippers(last_seen DESC);

CREATE INDEX IF NOT EXISTS idx_sources_shipper ON shipper_sources(shipper_id);
CREATE INDEX IF NOT EXISTS idx_sources_type ON shipper_sources(source_type);
CREATE INDEX IF NOT EXISTS idx_sources_enabled ON shipper_sources(enabled);

CREATE INDEX IF NOT EXISTS idx_volumes_shipper ON shipper_volumes(shipper_id);

CREATE INDEX IF NOT EXISTS idx_activity_shipper ON shipper_activity(shipper_id);
CREATE INDEX IF NOT EXISTS idx_activity_created ON shipper_activity(created_at DESC);
