-- SIEMBox Seed Data — default admin user only.
--
-- Parsers and detection rules are NOT seeded here anymore: a fresh install
-- starts empty and the operator installs exactly what they want from the in-app
-- catalog (Parsers / Detection Rules → Browse Catalog → Install all). The large
-- block of hardcoded "built-in" parsers and sample rules that used to live in
-- this file was removed for that reason.
--
-- Non-destructive for existing installs: their previously-seeded parsers/rules
-- already exist in the database and are left untouched; this migration just
-- stops creating new ones. The migrate runner still substitutes the real admin
-- password hash for the placeholder below.

-- Create default admin user
-- Username: admin
-- Password: changeme (MUST be changed after first login)
INSERT INTO users (username, email, password_hash, role)
VALUES ('admin', 'admin@siembox.local', '$2b$10$placeholder', 'admin')
ON CONFLICT (username) DO NOTHING;
