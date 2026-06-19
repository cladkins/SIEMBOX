-- Migration 007: fix the vaultwarden-access parser, which never matched any real
-- Vaultwarden log line. The original pattern required the literal word "from"
-- before the IP and an ", Email:" suffix, but real lines (1.30+) look like:
--   [..][vaultwarden::api::identity][ERROR] Username or password is incorrect. Try again. IP: 1.2.3.4. Username: u@x.com.
-- i.e. "IP:" with no "from", "Username:" not "Email:", and trailing periods.
-- Because nothing matched, `service` was never set to "vaultwarden" and EVERY
-- vaultwarden rule (AUTH-005, PWDMGR-001..004) failed on its first condition.
-- Also drops the "action"/"event" -> "message" mappings that polluted those
-- fields with the full message string; postProcessFields derives them instead.
-- Idempotent (UPDATE by name); re-runs on every startup like the other migrations.
UPDATE parsers
SET pattern = '^\[(?<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?)\]\[(?<module>[^\]]+)\]\[(?<log_level>\w+)\]\s+(?<message>.*?)(?:\s+for\s+(?<user_email>[^\s,.]+))?(?:\s+by\s+(?<admin_email>\S+)\s+from\s+(?<admin_ip>\d{1,3}(?:\.\d{1,3}){3})|(?:[.,]?\s+(?:from\s+)?(?:IP:\s*)?(?<client_ip>\d{1,3}(?:\.\d{1,3}){3})))?(?:[.,]?\s+(?:Email|Username):\s*(?<login_email>[^\s,]+?)\.?)?(?:,\s+Device:\s+(?<device>[^,]+))?\.?\s*$',
    field_mappings = '{"timestamp": "timestamp", "module": "module", "log_level": "log_level", "message": "message", "client_ip": "client_ip", "source_ip": "client_ip", "user_email": "email", "login_email": "email", "admin_email": "admin_email", "admin_ip": "admin_ip", "device": "device", "service": "vaultwarden"}'
WHERE name = 'vaultwarden-access';
