-- Migration 013: container image vulnerability scanning (Trivy).
--
-- A second scanner alongside the Nuclei network scanner: Trivy scans a container
-- image by reference (it pulls the layers itself, no Docker daemon needed) and
-- reports vulnerable OS/library packages. These tables are image-centric, so they
-- live separately from the asset/IP-centric Nuclei tables.
--
-- Idempotent: CREATE TABLE/INDEX IF NOT EXISTS, re-runnable on every startup.

CREATE TABLE IF NOT EXISTS container_scans (
    id SERIAL PRIMARY KEY,
    image_ref VARCHAR(512) NOT NULL,
    status VARCHAR(20) DEFAULT 'queued', -- queued | running | completed | failed | cancelled
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_seconds INTEGER,
    vulnerabilities_found INTEGER DEFAULT 0,
    severity_counts JSONB,
    error_message TEXT,
    initiated_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS container_vulnerabilities (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES container_scans(id) ON DELETE CASCADE,
    target VARCHAR(512),                -- Trivy Result target, e.g. "nginx (debian 12.4)"
    vuln_id VARCHAR(255) NOT NULL,      -- CVE / advisory id
    pkg_name VARCHAR(255),
    installed_version VARCHAR(255),
    fixed_version VARCHAR(255),
    severity VARCHAR(20),               -- critical | high | medium | low | unknown
    title TEXT,
    description TEXT,
    primary_url TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_container_scans_status ON container_scans(status);
CREATE INDEX IF NOT EXISTS idx_container_scans_created ON container_scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_container_vulns_scan ON container_vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_container_vulns_severity ON container_vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_container_vulns_vuln_id ON container_vulnerabilities(vuln_id);
