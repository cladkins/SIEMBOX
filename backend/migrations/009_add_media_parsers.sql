-- Migration 009: add the Jellyfin and Plex media-server parsers for EXISTING
-- installs. 002_seed_data.sql only INSERTs (ON CONFLICT DO NOTHING), so installs
-- created before 009 won't have them; this adds them idempotently. House style
-- mirrors 008_add_home_assistant_parser.sql (no version table; safe to re-run).
--
-- Jellyfin (Serilog): "[<ts> +zz:zz] [<LVL>] [<thread>] <Category>: <message>"
--   auth fail:  Authentication request for "<user>" has been denied (IP: "<ip>").
--   playback:   ...SessionManager: Playback start reported by app "..." playing "...".
--   The [thread] segment is optional. event/user/client_ip derived in postProcessFields.
-- Plex: "MMM DD, YYYY HH:MM:SS.mmm [0x<hex>] LEVEL - <message>"
--   auth fail:  Completed: [<ip:port>] 401|403 GET ...   (Plex auth is via MyPlex)
--   playback:   Completed: [<ip:port>] 200 GET /:/timeline?...&state=playing ...
--   event/client_ip/status_code derived in postProcessFields.
-- Priorities 21 (jellyfin) / 19 (plex) do not collide with home-assistant
-- ('(thread) [logger]'), keycloak ('[logger]...type='), or nginx.
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, event_type, enabled)
VALUES (
    'jellyfin',
    'Parses the Jellyfin server log (log_*.log); surfaces denied-authentication and playback-start events',
    'regex',
    21,
    '^\[(?<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:\s*[+-]\d{2}:\d{2})?)\]\s+\[(?<log_level>[A-Z]{3})\]\s+(?:\[(?<thread>[^\]]*)\]\s+)?(?<category>[^:]+):\s+(?<msg>.*)$',
    '{"timestamp": "timestamp", "log_level": "log_level", "thread": "thread", "category": "category", "msg": "message", "service": "jellyfin"}',
    'jellyfin_event',
    true
)
ON CONFLICT (name) DO NOTHING;

INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, event_type, enabled)
VALUES (
    'plex',
    'Parses the Plex Media Server log (Plex Media Server.log); surfaces 401/403 auth failures and playback-start (timeline state=playing) events',
    'regex',
    19,
    '^(?<timestamp>[A-Z][a-z]{2}\s+\d{1,2},\s+\d{4}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+\[(?<thread>0x[0-9a-fA-F]+)\]\s+(?<log_level>[A-Z]+)\s+-\s+(?<msg>.*)$',
    '{"timestamp": "timestamp", "thread": "thread", "log_level": "log_level", "msg": "message", "service": "plex"}',
    'plex_event',
    true
)
ON CONFLICT (name) DO NOTHING;
