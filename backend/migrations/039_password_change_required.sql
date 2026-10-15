-- Migration 039: password changes an account must make before anything else
-- (middleware/auth.ts, services/auth/passwordChange.ts, defaultCredentials.ts).
--
-- users.must_change_password: while TRUE, every session of the account may only
-- read its profile (GET /api/auth/me), change its password (PUT
-- /api/auth/me/password) or sign out; every other route that takes a login
-- answers 403 PASSWORD_CHANGE_REQUIRED. Agent and shipper keys are not
-- sessions and are not affected.
-- must_change_password_reason: 'initial' (the admin account the first start
-- creates), 'default' (found using the shipped default password "changeme"),
-- 'admin' (an admin set the password), 'cli' (auth-admin reset-password).
-- must_change_password_since: when it was set (Users page; alert dedupe).
--
-- Only code sets or clears these. Existing accounts start FALSE; the migrate
-- runner then flags admin accounts still on "changeme" (a bcrypt check SQL
-- can't do). Idempotent: ADD COLUMN IF NOT EXISTS (an existing column keeps
-- its values and constraint).
ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password_reason VARCHAR(16)
  CHECK (must_change_password_reason IN ('initial', 'default', 'admin', 'cli'));
ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password_since TIMESTAMPTZ;
