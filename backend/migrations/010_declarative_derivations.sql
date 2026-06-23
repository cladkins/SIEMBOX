-- Migration 010: declarative parser derivations.
--
-- Adds a `derivations` JSONB column to parsers — a data-driven replacement for
-- the hardcoded per-parser logic in parserEngine.postProcessFields. Each entry
-- is { when: { field: {contains|equals|in|matches|exists} }, set: {field: value} },
-- applied in order, first-match-wins (see services/parser/derive.ts).
--
-- Migrates the Vaultwarden parser to data as the first proof (its hardcoded block
-- is removed from the engine in the same change). Idempotent: ADD COLUMN IF NOT
-- EXISTS + UPDATE by name, re-runnable on every startup.
ALTER TABLE parsers ADD COLUMN IF NOT EXISTS derivations JSONB;

UPDATE parsers
SET derivations = '[
  {"when": {"message": {"contains": "vault export"}}, "set": {"action": "vault_export"}},
  {"when": {"message": {"contains": "vault import"}}, "set": {"action": "vault_import"}},
  {"when": {"message": {"contains": "vault sync"}}, "set": {"action": "vault_sync"}},
  {"when": {"message": {"contains": "vault accessed"}}, "set": {"action": "vault_access"}},
  {"when": {"message": {"contains": "username or password is incorrect"}}, "set": {"event": "login_failure"}},
  {"when": {"message": {"contains": "invalid totp code"}}, "set": {"event": "login_failure"}},
  {"when": {"message": {"contains": "invalid admin token"}}, "set": {"event": "login_failure"}},
  {"when": {"message": {"contains": "this user has been disabled"}}, "set": {"event": "login_failure"}},
  {"when": {"message": {"contains": "failed login"}}, "set": {"event": "login_failure"}},
  {"when": {"message": {"contains": "invalid password"}}, "set": {"event": "login_failure"}},
  {"when": {"message": {"contains": "logged in successfully"}}, "set": {"event": "login_success"}},
  {"when": {"message": {"contains": "successful login"}}, "set": {"event": "login_success"}},
  {"when": {"message": {"contains": "did not complete a 2fa login"}}, "set": {"event": "login_2fa_incomplete"}},
  {"when": {"module": {"contains": "::api::core"}}, "set": {"path": "/api/core"}},
  {"when": {"module": {"contains": "::api::identity"}}, "set": {"path": "/api/identity"}},
  {"when": {"module": {"contains": "::api::admin"}}, "set": {"path": "/admin"}},
  {"when": {"module": {"contains": "::api::"}}, "set": {"path": "/api"}}
]'::jsonb
WHERE name = 'vaultwarden-access';
