-- Migration 008: add the Home Assistant core-log parser for EXISTING installs.
-- 002_seed_data.sql only INSERTs (ON CONFLICT DO NOTHING), so installs created
-- before 008 won't have it; this adds it idempotently. House style mirrors
-- 003_fix_parsers.sql / 007_fix_vaultwarden_parser.sql (no version table; safe
-- to re-run every startup).
--
-- Real home-assistant.log line shape: "YYYY-MM-DD HH:MM:SS[.mmm] LEVEL (thread) [logger] message".
-- Actionable signal from logger homeassistant.components.http.ban:
--   "... Login attempt or request with invalid authentication from <host> (<ip>). ..."
--   "... Banned IP <ip> for too many login attempts"
-- client_ip and event ('login_failure'/'ip_banned') are derived in postProcessFields.
-- Priority 22 does not collide with keycloak (which needs '[logger]...type='): the
-- HA pattern requires '(thread) [logger]'.
INSERT INTO parsers (name, description, parser_type, priority, pattern, field_mappings, event_type, enabled)
VALUES (
    'home-assistant',
    'Parses the default Home Assistant core log (home-assistant.log); surfaces http.ban failed-login and IP-ban events',
    'regex',
    22,
    '^(?<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?)\s+(?<log_level>[A-Z]+)\s+\((?<thread>[^)]+)\)\s+\[(?<logger>[^\]]+)\]\s+(?<message>.*)$',
    '{"timestamp": "timestamp", "log_level": "log_level", "thread": "thread", "logger": "logger", "message": "message", "service": "home-assistant"}',
    'homeassistant_event',
    true
)
ON CONFLICT (name) DO NOTHING;
