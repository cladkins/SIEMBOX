-- Migration 042: read-only display links for wall screens (routes/display.ts,
-- routes/displayLinks.ts, middleware/displayAuth.ts, services/display/;
-- docs/architecture/BIG-DISPLAY.md).
--
-- display_links: one row per link. token_hash is the sha256 (hex) of the link
-- secret (sbd1_...), which is returned once at creation or rotation and never
-- stored; token_hint is its last 4 characters. config is validated by
-- services/display/config.ts. expires_at NULL = never (the default).
-- revoked_at: revoked links stay, without a usable secret, for the audit trail;
-- nothing accepts them, and their name is free again. Links belong to the
-- install: deleting the creator keeps them (created_by SET NULL), and nothing
-- about a user (password changes, sessions, deletion) touches them. One
-- mechanism for every board the product shows on a screen: a new kind of
-- panel or view is a config change, never a second token table.
--
-- display_link_clients: the addresses that used a link (at most 20 per link,
-- trimmed by the model), for the admin list. Informational only: nothing is
-- ever refused because of it.
--
-- idx_alerts_open_severity: the Open alerts panel as an index-only scan. A
-- plain CREATE INDEX: migrations finish before the API starts, so no alert
-- insert waits on it (seconds per million alerts), and scripts/migrate.ts runs
-- this file as one query, which rules out CONCURRENTLY. Distinct from the
-- Context Graph's idx_graph_* indexes on alerts (expressions on matched_data,
-- rule_id and asset_id), which serve lookups, not the open backlog.
--
-- Idempotent: migrations run on every start.
CREATE TABLE IF NOT EXISTS display_links (
    id               SERIAL PRIMARY KEY,
    name             TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
    token_hash       CHAR(64) NOT NULL UNIQUE,
    token_hint       CHAR(4) NOT NULL,
    config           JSONB NOT NULL,
    config_version   INTEGER NOT NULL DEFAULT 1,
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    allowed_cidrs    CIDR[] NOT NULL DEFAULT '{}',
    expires_at       TIMESTAMPTZ,
    revoked_at       TIMESTAMPTZ,
    created_by       INTEGER REFERENCES users(id) ON DELETE SET NULL,
    updated_by       INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    token_rotated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at     TIMESTAMPTZ
);
-- One live link per name, compared case-insensitively; a revoked link's name is free.
CREATE UNIQUE INDEX IF NOT EXISTS idx_display_links_live_name
    ON display_links (lower(name)) WHERE revoked_at IS NULL;
-- FK columns a user delete must look up (see 025).
CREATE INDEX IF NOT EXISTS idx_display_links_created_by ON display_links (created_by);
CREATE INDEX IF NOT EXISTS idx_display_links_updated_by ON display_links (updated_by);

CREATE TABLE IF NOT EXISTS display_link_clients (
    link_id    INTEGER NOT NULL REFERENCES display_links(id) ON DELETE CASCADE,
    ip         INET NOT NULL,
    user_agent TEXT,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (link_id, ip)
);

CREATE INDEX IF NOT EXISTS idx_alerts_open_severity
    ON alerts (severity, status, created_at) WHERE status IN ('new', 'investigating');
