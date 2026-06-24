-- Migration 015: external threat-intelligence feeds (Phase 4).
--
-- Two tables:
--   threat_feeds       — the configured blocklist sources (free, no-auth IP lists).
--   threat_indicators  — the individual IPs each feed currently contains.
--
-- A background job refreshes enabled feeds on an interval; lookups join an IP
-- against threat_indicators to see which feeds flag it. Keyed reputation
-- providers (AbuseIPDB / GreyNoise) are NOT stored here — their on-demand results
-- aren't persisted and their API keys live (encrypted) in system_settings.
--
-- Idempotent / re-runnable: CREATE ... IF NOT EXISTS, and the seed feeds use
-- ON CONFLICT (slug) DO NOTHING so re-running never duplicates or clobbers an
-- operator's enabled/disabled choice.

CREATE TABLE IF NOT EXISTS threat_feeds (
    id SERIAL PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT,
    category TEXT NOT NULL DEFAULT 'blocklist', -- c2 | tor | abuse | botnet | blocklist
    url TEXT NOT NULL,
    format TEXT NOT NULL DEFAULT 'plain',        -- 'plain' = one IP per line, # comments
    enabled BOOLEAN NOT NULL DEFAULT true,
    refresh_interval_minutes INTEGER NOT NULL DEFAULT 360,
    last_fetched_at TIMESTAMPTZ,
    last_status TEXT,                            -- ok | error
    last_error TEXT,
    indicator_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS threat_indicators (
    id BIGSERIAL PRIMARY KEY,
    feed_id INTEGER NOT NULL REFERENCES threat_feeds(id) ON DELETE CASCADE,
    indicator TEXT NOT NULL,                     -- the IP address
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (feed_id, indicator)
);

-- Fast "which feeds flag this IP?" lookups across all feeds.
CREATE INDEX IF NOT EXISTS idx_threat_indicators_indicator ON threat_indicators (indicator);
CREATE INDEX IF NOT EXISTS idx_threat_indicators_feed ON threat_indicators (feed_id);

-- Seed a small set of well-known, free, no-auth IP blocklists. Enabled by
-- default since the operator explicitly opted into external feeds; the refresh
-- job degrades gracefully if outbound egress is blocked (status -> error).
INSERT INTO threat_feeds (slug, name, description, category, url, format)
VALUES
    ('feodo-c2', 'Feodo Tracker (abuse.ch)',
     'Active botnet C2 server IPs (Dridex, Emotet, TrickBot, QakBot, BazarLoader) from abuse.ch Feodo Tracker.',
     'c2', 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt', 'plain'),
    ('sslbl-botnet', 'SSL Botnet C2 (abuse.ch SSLBL)',
     'IPs running botnet C2 with malicious SSL certificates, from abuse.ch SSLBL.',
     'botnet', 'https://sslbl.abuse.ch/blacklist/sslipblacklist.txt', 'plain'),
    ('tor-exit', 'Tor Exit Nodes',
     'Current Tor network exit-node IPs (from the Tor Project bulk exit list).',
     'tor', 'https://check.torproject.org/torbulkexitlist', 'plain'),
    ('blocklist-de', 'blocklist.de',
     'IPs reported in the last 48h for attacks against fail2ban-protected services (SSH, mail, web).',
     'abuse', 'https://lists.blocklist.de/lists/all.txt', 'plain')
ON CONFLICT (slug) DO NOTHING;
