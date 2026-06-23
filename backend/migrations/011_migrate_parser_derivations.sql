-- Migration 011: migrate the remaining hardcoded postProcessFields blocks to
-- declarative `derivations` data (the keystone of the parser platform — see
-- docs/parser-platform-plan.md). After this, parserEngine.postProcessFields no
-- longer contains ANY per-parser logic; every parser-specific derivation is data
-- carried by the parser and applied generically by services/parser/derive.ts.
--
-- Faithful translation of the deleted blocks (authelia/authentik/keycloak SSO
-- event markers; Home Assistant http.ban IP + event; Jellyfin auth-denied /
-- playback; Plex Completed-line IP/status/event + "[Now] User is" username).
-- Semantics (derive.ts): rules run in order; `set`/`extract` fill EMPTY fields
-- unless `overwrite: true`; `contains` and `matches` are case-INsensitive (the
-- old blocks all lower-cased first); `extract` pulls capture `group` (default 1)
-- of `pattern` from field `from`. source_ip is also mirrored from client_ip by
-- the normalizer, but we set both for parity with the old code.
--
-- Idempotent: UPDATE by name, re-runnable on every startup. Dollar-quoted so the
-- regex backslashes/quotes reach JSONB verbatim.

-- Authelia (regex, no `event` group): derive a uniform failure/success marker
-- from the message. Failure terms first so "unsuccessful" (which contains
-- "successful") resolves to failure via first-match-wins.
UPDATE parsers SET derivations = $json$[
  {"when": {"message": {"contains": "unsuccessful"}}, "set": {"event": "authentication failed"}},
  {"when": {"message": {"contains": "authentication failed"}}, "set": {"event": "authentication failed"}},
  {"when": {"message": {"contains": "invalid"}}, "set": {"event": "authentication failed"}},
  {"when": {"message": {"contains": "denied"}}, "set": {"event": "authentication failed"}},
  {"when": {"message": {"contains": "failed"}}, "set": {"event": "authentication failed"}},
  {"when": {"message": {"contains": "successful"}}, "set": {"event": "authentication success"}},
  {"when": {"message": {"contains": "authenticated"}}, "set": {"event": "authentication success"}}
]$json$::jsonb
WHERE name = 'authelia-access';

-- authentik (json, `event` + `success` already mapped): overwrite `event` with a
-- uniform failure marker when success=false OR the action says fail/denied/invalid.
-- All rules set the same value, so overwrite ordering is idempotent.
UPDATE parsers SET derivations = $json$[
  {"when": {"success": {"equals": "false"}}, "set": {"event": "authentication failed"}, "overwrite": true},
  {"when": {"event": {"contains": "fail"}}, "set": {"event": "authentication failed"}, "overwrite": true},
  {"when": {"event": {"contains": "denied"}}, "set": {"event": "authentication failed"}, "overwrite": true},
  {"when": {"event": {"contains": "invalid"}}, "set": {"event": "authentication failed"}, "overwrite": true}
]$json$::jsonb
WHERE name = 'authentik-audit';

-- Keycloak (regex, `event` = the `type=` token, e.g. LOGIN_ERROR): any *_ERROR
-- type is an auth failure. Overwrite the existing event with the uniform marker.
UPDATE parsers SET derivations = $json$[
  {"when": {"event": {"contains": "error"}}, "set": {"event": "authentication failed"}, "overwrite": true}
]$json$::jsonb
WHERE name = 'keycloak-event';

-- Home Assistant (regex, message from the http.ban logger): pull the client IP
-- (three message shapes, first match wins), derive the event, and pin `service`
-- explicitly so the normalizer does not treat the captured `logger` as service.
UPDATE parsers SET derivations = $json$[
  {"extract": {"client_ip": {"from": "message", "pattern": "Banned IP\\s+(\\d{1,3}(?:\\.\\d{1,3}){3})"}, "source_ip": {"from": "message", "pattern": "Banned IP\\s+(\\d{1,3}(?:\\.\\d{1,3}){3})"}}},
  {"extract": {"client_ip": {"from": "message", "pattern": "\\bfrom\\s+\\S+\\s+\\((\\d{1,3}(?:\\.\\d{1,3}){3})\\)"}, "source_ip": {"from": "message", "pattern": "\\bfrom\\s+\\S+\\s+\\((\\d{1,3}(?:\\.\\d{1,3}){3})\\)"}}},
  {"extract": {"client_ip": {"from": "message", "pattern": "\\bfrom\\s+(\\d{1,3}(?:\\.\\d{1,3}){3})\\b"}, "source_ip": {"from": "message", "pattern": "\\bfrom\\s+(\\d{1,3}(?:\\.\\d{1,3}){3})\\b"}}},
  {"when": {"message": {"matches": "banned ip.*too many login attempts"}}, "set": {"event": "ip_banned"}},
  {"when": {"message": {"contains": "invalid authentication"}}, "set": {"event": "login_failure"}},
  {"set": {"service": "home-assistant"}}
]$json$::jsonb
WHERE name = 'home-assistant';

-- Jellyfin (regex, message): auth-denied line carries user+IP (-> login_failure);
-- playback-start line carries the app + media title. `service` pinned (the
-- captured `category` would otherwise be misread).
UPDATE parsers SET derivations = $json$[
  {"when": {"message": {"matches": "Authentication request for\\s+\"?([^\"]+?)\"?\\s+has been denied\\s+\\(IP:\\s*\"?(\\d{1,3}(?:\\.\\d{1,3}){3})\"?\\)"}},
   "set": {"event": "login_failure"},
   "extract": {
     "user": {"from": "message", "pattern": "Authentication request for\\s+\"?([^\"]+?)\"?\\s+has been denied\\s+\\(IP:\\s*\"?(\\d{1,3}(?:\\.\\d{1,3}){3})\"?\\)", "group": 1},
     "client_ip": {"from": "message", "pattern": "Authentication request for\\s+\"?([^\"]+?)\"?\\s+has been denied\\s+\\(IP:\\s*\"?(\\d{1,3}(?:\\.\\d{1,3}){3})\"?\\)", "group": 2},
     "source_ip": {"from": "message", "pattern": "Authentication request for\\s+\"?([^\"]+?)\"?\\s+has been denied\\s+\\(IP:\\s*\"?(\\d{1,3}(?:\\.\\d{1,3}){3})\"?\\)", "group": 2}
   }},
  {"when": {"message": {"matches": "Playback start reported by app\\s+\"([^\"]*)\"\\s+\"([^\"]*)\"\\s+playing\\s+\"([^\"]*)\""}},
   "set": {"event": "playback_start"},
   "extract": {
     "client_app": {"from": "message", "pattern": "Playback start reported by app\\s+\"([^\"]*)\"\\s+\"([^\"]*)\"\\s+playing\\s+\"([^\"]*)\"", "group": 1},
     "media_item": {"from": "message", "pattern": "Playback start reported by app\\s+\"([^\"]*)\"\\s+\"([^\"]*)\"\\s+playing\\s+\"([^\"]*)\"", "group": 3}
   }},
  {"set": {"service": "jellyfin"}}
]$json$::jsonb
WHERE name = 'jellyfin';

-- Plex (regex, message): the "Completed: [ip:port] <status> <method> <uri>" line
-- yields client_ip/status_code/method/request_uri; a timeline+state=playing GET
-- is a playback start, a 401/403 is an auth failure (Plex delegates auth to
-- MyPlex, so login_failure wins over playback). The username is on a separate
-- "[Now] User is <name> (ID: <n>)" line. `service` pinned.
UPDATE parsers SET derivations = $json$[
  {"extract": {
     "client_ip": {"from": "message", "pattern": "Completed:\\s*\\[([0-9a-fA-F:.]+?):\\d+\\]\\s+(\\d{3})\\s+(GET|POST|PUT|DELETE|HEAD)\\s+(\\S+)", "group": 1},
     "source_ip": {"from": "message", "pattern": "Completed:\\s*\\[([0-9a-fA-F:.]+?):\\d+\\]\\s+(\\d{3})\\s+(GET|POST|PUT|DELETE|HEAD)\\s+(\\S+)", "group": 1},
     "status_code": {"from": "message", "pattern": "Completed:\\s*\\[([0-9a-fA-F:.]+?):\\d+\\]\\s+(\\d{3})\\s+(GET|POST|PUT|DELETE|HEAD)\\s+(\\S+)", "group": 2},
     "method": {"from": "message", "pattern": "Completed:\\s*\\[([0-9a-fA-F:.]+?):\\d+\\]\\s+(\\d{3})\\s+(GET|POST|PUT|DELETE|HEAD)\\s+(\\S+)", "group": 3},
     "request_uri": {"from": "message", "pattern": "Completed:\\s*\\[([0-9a-fA-F:.]+?):\\d+\\]\\s+(\\d{3})\\s+(GET|POST|PUT|DELETE|HEAD)\\s+(\\S+)", "group": 4}
   }},
  {"when": {"request_uri": {"matches": "/:/timeline\\b.*[?&]state=playing\\b"}}, "set": {"event": "playback_start"}},
  {"when": {"status_code": {"in": ["401", "403"]}}, "set": {"event": "login_failure"}, "overwrite": true},
  {"extract": {
     "user": {"from": "message", "pattern": "\\[Now\\]\\s+User is\\s+(.+?)\\s+\\(ID:\\s*(\\d+)\\)", "group": 1},
     "user_id": {"from": "message", "pattern": "\\[Now\\]\\s+User is\\s+(.+?)\\s+\\(ID:\\s*(\\d+)\\)", "group": 2}
   }},
  {"set": {"service": "plex"}}
]$json$::jsonb
WHERE name = 'plex';
