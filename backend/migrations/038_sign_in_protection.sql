-- Migration 038: sign-in protection (routes/auth.ts, services/auth/signInPolicy.ts).
--
-- login_throttle holds one row per throttle key: an account from one network
-- (aip:<hash of the username>:<network>), a network (ip:<network>), an account
-- from every network (acct:<hash>), a recognized browser (br:<id>), a user's
-- MFA codes (mfa:<user id>) and a user's current-password checks on a
-- password change (pwc:<user id>). Usernames are only ever stored hashed, so
-- keys for usernames that don't exist look the same and hold nothing anyone
-- typed; user_id is filled in when the account exists, for listing and
-- unlocking. Counters live here rather than in memory so a restart doesn't
-- reset them and the recovery CLI (scripts/auth-admin.ts) can clear them.
--
-- recognized_browsers holds the sha256 of each browser token issued on a
-- successful sign-in (the token itself is only ever returned to the browser).
-- A recognized browser signs in through a bucket of its own, so an attack on
-- the account or the network doesn't lock its owner out.
--
-- users.mfa_last_totp_step is the last TOTP time step accepted for the user,
-- which makes each code single-use. users.password_changed_at is when the
-- user last changed their own password (Getting Started's "Secure your
-- account" step; a password change signs everyone out, so the browser can't
-- remember it).
--
-- Idempotent (CREATE ... IF NOT EXISTS, ADD COLUMN IF NOT EXISTS): migrations
-- run on every start. No backfill.
CREATE TABLE IF NOT EXISTS login_throttle (
  key TEXT PRIMARY KEY,
  scope VARCHAR(16) NOT NULL,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  network INET,
  failures INTEGER NOT NULL DEFAULT 0,
  pauses INTEGER NOT NULL DEFAULT 0,
  paused_until TIMESTAMPTZ,
  first_failure_at TIMESTAMPTZ,
  last_failure_at TIMESTAMPTZ,
  last_user_agent TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_login_throttle_user ON login_throttle (user_id) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_login_throttle_paused ON login_throttle (paused_until) WHERE paused_until IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_login_throttle_last_failure ON login_throttle (last_failure_at);

CREATE TABLE IF NOT EXISTS recognized_browsers (
  id BIGSERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash CHAR(64) NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_ip INET,
  user_agent TEXT
);

CREATE INDEX IF NOT EXISTS idx_recognized_browsers_user ON recognized_browsers (user_id, last_used_at DESC);

ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_last_totp_step BIGINT;

ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ;
