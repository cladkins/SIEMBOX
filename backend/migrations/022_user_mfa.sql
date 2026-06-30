-- Optional per-user TOTP MFA for local accounts. Additive and opt-in: every
-- column defaults to "no MFA", so existing accounts and the login flow are
-- unchanged until a user deliberately enrolls. Idempotent.
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE;

-- Encrypted TOTP secret: the JSON {encrypted, iv, authTag} produced by
-- CredentialEncryption (AES-256-GCM, keyed by CREDENTIAL_ENCRYPTION_KEY). Never
-- stored in plaintext.
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret TEXT;

-- One-time recovery codes as bcrypt hashes (array). Consumed on use.
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_recovery_codes JSONB;
